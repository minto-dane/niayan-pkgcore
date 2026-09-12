/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <systemd/sd-bus.h>
#include <time.h>
#include <unistd.h>

#define AUTHORITY "org.freedesktop.PolicyKit1"
#define AUTH_PATH "/org/freedesktop/PolicyKit1/Authority"
#define AUTH_INTERFACE "org.freedesktop.PolicyKit1.Authority"
#define ACTION "org.niaos.package.manage"
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

/* Operator authorization only. Native supply/plan/consent/effect guards remain
 * mandatory. This process-bound decision is never serialized as a permit. */
struct operator_authorization {
    sd_bus *bus;
    sd_bus_slot *slot;
    int pidfd, peer, changed, valid;
    pid_t owner;
    uid_t uid;
    uint64_t deadline;
    char plan[65], request[33], authority[256];
};
static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int digest(const char *s, size_t length) {
    if (!s || strnlen(s, length + 1) != length) return 0;
    int nonzero = 0;
    for (size_t i = 0; i < length; ++i) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
        nonzero |= s[i] != '0';
    }
    return nonzero;
}
static int live(struct operator_authorization *s) {
    if (!s || s->owner != getpid() || getuid() || geteuid() || now_ms() >= s->deadline) return 0;
    struct pollfd descriptors[2] = {{.fd=s->pidfd,.events=POLLIN},{.fd=s->peer,.events=POLLIN}};
    /* The caller consumed the accepted request. Any subsequent packet (including
     * cancellation), disconnect or peer death invalidates this decision. */
    return poll(descriptors, 2, 0) == 0;
}
static int changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
    (void)message; (void)error;
    struct operator_authorization *s = userdata;
    s->changed = 1; s->valid = 0;
    return 0;
}
static int drain(struct operator_authorization *s) {
    for (unsigned i = 0; i < 64; ++i) {
        int n = sd_bus_process(s->bus, NULL);
        if (n < 0 || s->changed || !live(s)) return -1;
        if (!n) return 0;
    }
    return -1;
}
static int call(struct operator_authorization *s, sd_bus_message *message, sd_bus_message **reply) {
    uint64_t now = now_ms();
    if (!live(s) || now >= s->deadline) return -1;
    return sd_bus_call(s->bus, message, (s->deadline - now) * 1000, NULL, reply);
}
static int current_owner(struct operator_authorization *s, int initial) {
    sd_bus_message *message=NULL,*reply=NULL;
    const char *owner=NULL; int result=-1;
    if (sd_bus_message_new_method_call(s->bus,&message,"org.freedesktop.DBus","/org/freedesktop/DBus",
        "org.freedesktop.DBus","GetNameOwner") < 0 || sd_bus_message_append(message,"s",AUTHORITY) < 0 ||
        call(s,message,&reply) < 0 || sd_bus_message_read(reply,"s",&owner) <= 0 ||
        !owner || owner[0]!=':' || strlen(owner)>=sizeof(s->authority) || !sd_bus_message_at_end(reply,1)) goto out;
    if (initial) memcpy(s->authority,owner,strlen(owner)+1);
    else if (strcmp(s->authority,owner)) goto out;
    result=0;
out:
    sd_bus_message_unref(reply);sd_bus_message_unref(message);return result;
}
static int barrier(struct operator_authorization *s) {
    sd_bus_message *message=NULL,*reply=NULL;int result=-1;
    if (current_owner(s,0) || sd_bus_message_new_method_call(s->bus,&message,s->authority,AUTH_PATH,
        "org.freedesktop.DBus.Peer","Ping") < 0 || call(s,message,&reply) < 0 ||
        strcmp(sd_bus_message_get_signature(reply,1),"") || drain(s) || current_owner(s,0) || drain(s)) goto out;
    result=0;
out:
    sd_bus_message_unref(reply);sd_bus_message_unref(message);return result;
}
static int protected_bus(void) {
    const char *directories[]={"/","/run","/run/dbus"};struct stat info;
    for (unsigned i=0;i<3;++i)
        if (lstat(directories[i],&info) || !S_ISDIR(info.st_mode) || info.st_uid || (info.st_mode&0022)) return 0;
    return !lstat("/run/dbus/system_bus_socket",&info) && S_ISSOCK(info.st_mode) && info.st_uid==0;
}
static int authenticate(struct operator_authorization *s, int interactive) {
    sd_bus_message *message=NULL,*reply=NULL;
    int authorized=0,challenge=0,result=-1; const char *key,*value;
    if (sd_bus_message_new_method_call(s->bus,&message,s->authority,AUTH_PATH,AUTH_INTERFACE,"CheckAuthorization") < 0 ||
        sd_bus_message_open_container(message,'r',"sa{sv}") < 0 || sd_bus_message_append(message,"s","unix-process") < 0 ||
        sd_bus_message_open_container(message,'a',"{sv}") < 0 ||
        sd_bus_message_append(message,"{sv}","pidfd","h",s->pidfd) < 0 ||
        sd_bus_message_append(message,"{sv}","uid","i",(int32_t)s->uid) < 0 ||
        sd_bus_message_close_container(message) < 0 || sd_bus_message_close_container(message) < 0 ||
        sd_bus_message_append(message,"s",ACTION) < 0 || sd_bus_message_open_container(message,'a',"{ss}") < 0 ||
        sd_bus_message_append(message,"{ss}","nia.plan",s->plan) < 0 ||
        sd_bus_message_append(message,"{ss}","nia.request",s->request) < 0 ||
        sd_bus_message_close_container(message) < 0 || sd_bus_message_append(message,"us",(uint32_t)interactive,s->request) < 0 ||
        call(s,message,&reply) < 0 || strcmp(sd_bus_message_get_signature(reply,1),"(bba{ss})") ||
        sd_bus_message_enter_container(reply,'r',"bba{ss}") <= 0 ||
        sd_bus_message_read(reply,"bb",&authorized,&challenge) <= 0 ||
        sd_bus_message_enter_container(reply,'a',"{ss}") <= 0) goto out;
    unsigned count=0;
    while (sd_bus_message_at_end(reply,0)==0) {
        if (++count>16 || sd_bus_message_read(reply,"{ss}",&key,&value)<=0 || strlen(key)>256 || strlen(value)>1024 ||
            !strcmp(key,"polkit.temporary_authorization_id")) goto out;
    }
    if (sd_bus_message_exit_container(reply)<0 || sd_bus_message_exit_container(reply)<0 ||
        !sd_bus_message_at_end(reply,1) || !authorized || challenge || barrier(s)) goto out;
    result=0;
out:
    sd_bus_message_unref(reply);sd_bus_message_unref(message);return result;
}
void nia_operator_close(void **handle) {
    if (!handle || !*handle) return;
    struct operator_authorization *s=*handle;
    sd_bus_slot_unref(s->slot);
    sd_bus_unref(s->bus);
    if (s->pidfd>=0) close(s->pidfd);
    if (s->peer>=0) close(s->peer);
    free(s);*handle=NULL;
}
int nia_operator_open(void **handle, int peer_fd, const char *plan, const char *request,
                      unsigned long long deadline, int interactive) {
    if (!handle) return 1;
    if (*handle) return 4;
    if (getuid() || geteuid() || !digest(plan,64) || !digest(request,32) || peer_fd<0 ||
        (interactive!=0 && interactive!=1)) return 1;
    uint64_t now=now_ms();
    if (deadline<=now || deadline-now>120000) return 3;
    if (!protected_bus()) return 1;
    struct operator_authorization *s=calloc(1,sizeof(*s));if (!s) return 1;
    s->pidfd=s->peer=-1;s->owner=getpid();s->deadline=deadline;
    memcpy(s->plan,plan,sizeof(s->plan));memcpy(s->request,request,sizeof(s->request));
    int kind=0; socklen_t length=sizeof(kind); struct sockaddr_storage address;
    struct ucred peer; socklen_t peer_length=sizeof(peer);int result=1;
    s->peer=fcntl(peer_fd,F_DUPFD_CLOEXEC,3);
    if (s->peer<0 || getsockopt(s->peer,SOL_SOCKET,SO_TYPE,&kind,&length) || kind!=SOCK_SEQPACKET) goto out;
    length=sizeof(address);
    if (getpeername(s->peer,(struct sockaddr*)&address,&length) || address.ss_family!=AF_UNIX ||
        getsockopt(s->peer,SOL_SOCKET,SO_PEERCRED,&peer,&peer_length) || peer_length!=sizeof(peer) ||
        peer.pid<=0 || peer.uid>INT_MAX) goto out;
    s->uid=peer.uid;length=sizeof(s->pidfd);
    if (getsockopt(s->peer,SOL_SOCKET,SO_PEERPIDFD,&s->pidfd,&length) || length!=sizeof(s->pidfd) ||
        fcntl(s->pidfd,F_SETFD,FD_CLOEXEC) || !live(s)) goto out;
    if (sd_bus_new(&s->bus)<0 || sd_bus_set_address(s->bus,"unix:path=/run/dbus/system_bus_socket")<0 ||
        sd_bus_set_bus_client(s->bus,1)<0 || sd_bus_negotiate_fds(s->bus,1)<0 || sd_bus_start(s->bus)<0 ||
        current_owner(s,1) || sd_bus_match_signal(s->bus,&s->slot,s->authority,AUTH_PATH,AUTH_INTERFACE,"Changed",changed,s)<0 ||
        authenticate(s,interactive)) goto out;
    s->valid=1;*handle=s;return 0;
out:
    if (now_ms()>=s->deadline) result=3;
    void *temporary=s;nia_operator_close(&temporary);return result;
}
int nia_operator_check(void *handle, const char *plan, const char *request) {
    struct operator_authorization *s=handle;
    if (!s || s->owner!=getpid() || getuid() || geteuid()) return 1;
    if (!s->valid || !digest(plan,64) || !digest(request,32) || strcmp(s->plan,plan) || strcmp(s->request,request)) {
        s->valid=0;return 1;
    }
    if (!live(s) || barrier(s)) { s->valid=0;return now_ms()>=s->deadline ? 3 : 1; }
    return 0;
}
