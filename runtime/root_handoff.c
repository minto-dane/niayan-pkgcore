/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>
#include "root_handoff_wire.h"
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

/* One prepare request on a root-launched worker's private channel. The root
 * supervisor must independently admit the scope before acknowledging it.
 * 0 prepared, 1 denied, 2 uncertain, 3 expired, 4 already used/in use. */
struct handoff {
    int socket, pidfd, used;
    pid_t owner, supervisor;
    uid_t uid;
    uint64_t deadline;
};
static uint64_t clock_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int owned(struct handoff *s) {
    return s && s->owner == getpid() && getuid() == s->uid && geteuid() == s->uid && s->uid;
}
static int wait_for(struct handoff *s, short events) {
    while (owned(s)) {
        uint64_t now = clock_ms();
        if (now >= s->deadline) return -1;
        struct pollfd fds[2] = {{.fd=s->socket,.events=events},{.fd=s->pidfd,.events=POLLIN}};
        int delay = s->deadline - now > 1000 ? 1000 : (int)(s->deadline - now);
        int n = poll(fds, 2, delay);
        if (n < 0 && errno != EINTR) return -1;
        if (n > 0) {
            if (fds[1].revents || (fds[0].revents & (POLLERR|POLLNVAL|POLLHUP))) return -1;
            if (fds[0].revents & events) return 0;
        }
    }
    return -1;
}
void nia_root_handoff_close(void **handle) {
    if (!handle || !*handle) return;
    struct handoff *s = *handle;
    if (s->socket >= 0) close(s->socket);
    if (s->pidfd >= 0) close(s->pidfd);
    free(s); *handle = NULL;
}
int nia_root_handoff_open(void **handle, int peer, unsigned long long deadline) {
    if (!handle) return 1;
    if (*handle) return 4;
    if (!getuid() || getuid() != geteuid() || peer < 0) return 1;
    uint64_t now = clock_ms();
    if (deadline <= now || deadline > INT64_MAX || deadline - now > 600000) return 3;
    struct handoff *s = calloc(1, sizeof(*s));
    if (!s) return 1;
    s->socket = s->pidfd = -1; s->owner = getpid(); s->uid = getuid(); s->deadline = deadline;
    s->socket = fcntl(peer, F_DUPFD_CLOEXEC, 3);
    int value = 0; socklen_t length = sizeof(value);
    struct sockaddr_storage address;
    struct ucred credentials;
    if (s->socket < 0 || getsockopt(s->socket,SOL_SOCKET,SO_TYPE,&value,&length) || value != SOCK_SEQPACKET) goto fail;
    length = sizeof(value);
    if (getsockopt(s->socket,SOL_SOCKET,SO_PASSCRED,&value,&length) || value != 1) goto fail;
    length = sizeof(address);
    if (getpeername(s->socket,(struct sockaddr *)&address,&length) || address.ss_family != AF_UNIX) goto fail;
    length = sizeof(credentials);
    if (getsockopt(s->socket,SOL_SOCKET,SO_PEERCRED,&credentials,&length) || length != sizeof(credentials) ||
        credentials.uid || credentials.pid <= 0) goto fail;
    s->supervisor = credentials.pid; length = sizeof(s->pidfd);
    if (getsockopt(s->socket,SOL_SOCKET,SO_PEERPIDFD,&s->pidfd,&length) || length != sizeof(s->pidfd) ||
        fcntl(s->pidfd,F_SETFD,FD_CLOEXEC) || wait_for(s,POLLOUT)) goto fail;
    *handle = s; return 0;
fail:
    { void *temporary = s; nia_root_handoff_close(&temporary); }
    return clock_ms() >= deadline ? 3 : 1;
}
int nia_root_handoff_prepare(void *handle, const unsigned char *request, int archive, int reservation) {
    struct handoff *s = handle;
    if (!owned(s)) return 1;
    if (s->used) return 4;
    if (archive < 0 || reservation < 0 || !nia_handoff_wire_valid(request,192,s->deadline)) return 1;
    if (wait_for(s,POLLOUT)) return clock_ms() >= s->deadline ? 3 : 1;
    unsigned char expected[40]; memcpy(expected,"NIAHOK01",8);
    crypto_hash_sha256(expected+8,request,192);
    struct iovec vec = {.iov_base=(void *)request,.iov_len=192};
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(2*sizeof(int))]; } control = {0};
    struct msghdr message = {.msg_iov=&vec,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; c->cmsg_len=CMSG_LEN(2*sizeof(int));
    int descriptors[2]={archive,reservation}; memcpy(CMSG_DATA(c),descriptors,sizeof(descriptors));
    s->used=1;
    if (sendmsg(s->socket,&message,MSG_DONTWAIT|MSG_NOSIGNAL)!=192 || wait_for(s,POLLIN)) return 2;
    unsigned char reply[41]; vec.iov_base=reply; vec.iov_len=sizeof(reply);
    union { struct cmsghdr alignment; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(16*sizeof(int))]; } received = {0};
    message=(struct msghdr){.msg_iov=&vec,.msg_iovlen=1,.msg_control=received.bytes,.msg_controllen=sizeof(received.bytes)};
    ssize_t count=recvmsg(s->socket,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);
    if (count < 0) return 2;
    int invalid=!!(message.msg_flags & ~(MSG_CMSG_CLOEXEC|MSG_EOR)), credentials=0;
    for (c=CMSG_FIRSTHDR(&message); c; c=CMSG_NXTHDR(&message,c)) {
        if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_CREDENTIALS && c->cmsg_len==CMSG_LEN(sizeof(struct ucred))) {
            struct ucred sender; memcpy(&sender,CMSG_DATA(c),sizeof(sender)); ++credentials;
            invalid |= sender.uid!=0 || sender.pid!=s->supervisor;
        } else {
            invalid=1;
            if (c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS && c->cmsg_len>=CMSG_LEN(0))
                for (size_t i=0; i<(c->cmsg_len-CMSG_LEN(0))/sizeof(int); ++i) {
                    int fd; memcpy(&fd,(unsigned char *)CMSG_DATA(c)+i*sizeof(int),sizeof(fd)); close(fd);
                }
        }
    }
    struct pollfd life={.fd=s->pidfd,.events=POLLIN};
    return !invalid && credentials==1 && count==40 && !memcmp(reply,expected,40) &&
        clock_ms()<s->deadline && poll(&life,1,0)==0 ? 0 : 2;
}
