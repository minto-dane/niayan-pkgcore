/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* Private supervisor transport. No native admission, mount operation or CLI.
 * Return codes: 0 observed, 1 refused before delivery, 2 uncertain, 3 expired,
 * 4 handle in use. A response identity is evidence, not an independent pin. */
struct root_session {
    int socket, valid;
    pid_t owner, sender;
    uint64_t deadline, mount, major, minor, inode;
    char stage[33];
};
static uint64_t session_clock(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int wait_for(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = session_clock();
        if (now >= deadline) return -1;
        struct pollfd p = {.fd = fd, .events = events};
        int delay = deadline - now > 1000 ? 1000 : (int)(deadline - now);
        int n = poll(&p, 1, delay);
        if (n > 0) return p.revents & events ? 0 : -1;
        if (n < 0 && errno != EINTR) return -1;
    }
}
static int hex_value(const char *s, size_t size) {
    if (!s || strnlen(s, size + 1) != size) return 0;
    int nonzero = 0;
    for (size_t i = 0; i < size; ++i) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
        nonzero |= s[i] != '0';
    }
    return nonzero;
}
static int boot_value(const char *s) {
    if (!s || strnlen(s, 37) != 36) return 0;
    for (size_t i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) { if (s[i] != '-') return 0; }
        else if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    }
    return 1;
}
static int owned(const struct root_session *s) {
    return s && s->owner == getpid() && getuid() == 0 && geteuid() == 0;
}
static int packet_send(struct root_session *s, const char *packet, int length, int archive, int lease) {
    if (wait_for(s->socket, POLLOUT, s->deadline)) return 3;
    struct iovec vec = {.iov_base = (void *)packet, .iov_len = (size_t)length};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(2 * sizeof(int))]; } controls = {0};
    struct msghdr msg = {.msg_iov = &vec, .msg_iovlen = 1};
    if (archive >= 0) {
        msg.msg_control = controls.bytes; msg.msg_controllen = sizeof(controls.bytes);
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(2 * sizeof(int));
        int descriptors[2] = {archive, lease};
        memcpy(CMSG_DATA(c), descriptors, sizeof(descriptors));
    }
    /* Never retry: a failure from this point cannot establish non-execution. */
    return sendmsg(s->socket, &msg, MSG_NOSIGNAL) == length ? 0 : 2;
}
static int packet_receive(struct root_session *s, char *packet, size_t capacity, int eof) {
    if (wait_for(s->socket, POLLIN, s->deadline)) return 2;
    struct iovec vec = {.iov_base = packet, .iov_len = capacity - 1};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(16 * sizeof(int))]; } controls = {0};
    struct msghdr msg = {.msg_iov = &vec, .msg_iovlen = 1,
        .msg_control = controls.bytes, .msg_controllen = sizeof(controls.bytes)};
    ssize_t n = recvmsg(s->socket, &msg, MSG_CMSG_CLOEXEC);
    if (n < 0) return 2;
    int invalid = !!(msg.msg_flags & ~(MSG_CMSG_CLOEXEC | MSG_EOR)), credentials = 0;
    struct ucred sender = {0};
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS && c->cmsg_len == CMSG_LEN(sizeof(sender))) {
            memcpy(&sender, CMSG_DATA(c), sizeof(sender)); ++credentials;
        } else {
            invalid = 1;
            /* Even a truncated or rejected reply must release delivered FDs. */
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(0)) {
                size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; ++i) {
                    int fd; memcpy(&fd, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(fd)); close(fd);
                }
            }
        }
    }
    if (eof) return !invalid && !credentials && n == 0 && session_clock() < s->deadline ? 0 : 2;
    if (invalid || credentials != 1 || sender.uid != 0 || sender.pid <= 0 ||
        (s->sender && s->sender != sender.pid) || n == 0 || session_clock() >= s->deadline) return 2;
    s->sender = sender.pid;
    packet[n] = 0;
    /* No embedded NUL or noncanonical tail can be hidden from comparison. */
    return strlen(packet) == (size_t)n ? 0 : 2;
}
static int observation(struct root_session *s, int initial) {
    char response[4096], expected[1024];
    int result = packet_receive(s, response, sizeof(response), 0);
    if (result) return result;
    uint64_t inode = s->inode;
    if (initial) {
        const char *value = strstr(response, "\"inode\":");
        if (!value) return 2;
        value += strlen("\"inode\":");
        if (*value < '1' || *value > '9') return 2;
        errno = 0; char *end;
        unsigned long long parsed = strtoull(value, &end, 10);
        if (errno || !parsed || *end != ',') return 2;
        inode = parsed;
    }
    int n = snprintf(expected, sizeof(expected),
        "{\"deadline_ms\":%llu,\"observation\":{\"original_deadline_ms\":%llu,\"root\":{\"device_major\":%llu,\"device_minor\":%llu,\"inode\":%llu,\"mount_id\":%llu}},\"published\":false,\"stage\":\"%s\",\"state\":\"frozen\",\"version\":1}\n",
        (unsigned long long)s->deadline, (unsigned long long)s->deadline,
        (unsigned long long)s->major, (unsigned long long)s->minor, (unsigned long long)inode,
        (unsigned long long)s->mount, s->stage);
    if (n < 0 || (size_t)n >= sizeof(expected) || strcmp(response, expected)) return 2;
    s->inode = inode;
    return 0;
}
void nia_root_session_discard(void **handle) {
    if (!handle || !*handle) return;
    struct root_session *s = *handle;
    /* Closing a forked copy does not shutdown the parent's socket. */
    close(s->socket); free(s); *handle = NULL;
}
int nia_root_session_open(void **handle, const char *path, const char *generation, const char *root,
    const char *archive, const char *worker, const char *stage, const char *plan, const char *boot,
    unsigned long long size, unsigned long long entries, unsigned long long deadline,
    unsigned long long mount, unsigned long long bank_inode, unsigned long long major, unsigned long long minor,
    int archive_fd, int lease_fd, unsigned long long *root_inode) {
    if (!handle || !root_inode) return 1;
    *root_inode = 0;
    if (*handle) return 4;
    if (getuid() || geteuid() || !path || path[0] != '/' || strnlen(path, 108) >= 108 ||
        !hex_value(generation, 64) || !hex_value(root, 64) || !hex_value(archive, 64) ||
        !hex_value(worker, 64) || !hex_value(stage, 32) || !hex_value(plan, 64) || !boot_value(boot) ||
        size < 1024 || size > UINT64_C(8589934592) || size % 512 || !entries || entries > 524288 ||
        !mount || bank_inode != 2 || major > UINT32_MAX || minor > UINT32_MAX || archive_fd < 0 || lease_fd < 0) return 1;
    uint64_t now = session_clock();
    if (deadline <= now || deadline > INT64_MAX || deadline - now > 600000) return 3;
    char packet[2048];
    int length = snprintf(packet, sizeof(packet),
        "{\"bank\":{\"device_major\":%llu,\"device_minor\":%llu,\"inode\":%llu,\"mount_id\":%llu},\"boot_id\":\"%s\",\"device_plan_sha256\":\"%s\",\"operation\":\"prepare-freeze\",\"request\":{\"archive\":\"%s\",\"deadline_ms\":%llu,\"entries\":%llu,\"generation\":\"%s\",\"root_manifest\":\"%s\",\"size\":%llu,\"stage\":\"%s\",\"version\":1},\"version\":1,\"worker_sha256\":\"%s\"}\n",
        major, minor, bank_inode, mount, boot, plan, archive, deadline, entries, generation, root, size, stage, worker);
    if (length < 0 || (size_t)length >= sizeof(packet)) return 1;
    struct root_session *s = calloc(1, sizeof(*s));
    if (!s) return 1;
    s->socket = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s->socket < 0) { free(s); return 1; }
    int result = 1, enabled = 1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    struct ucred peer; socklen_t peer_size = sizeof(peer);
    if (setsockopt(s->socket, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) ||
        connect(s->socket, (struct sockaddr *)&address, sizeof(address)) ||
        getsockopt(s->socket, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) || peer_size != sizeof(peer) || peer.uid != 0) goto failed;
    s->owner = getpid(); s->deadline = deadline; s->mount = mount; s->major = major; s->minor = minor;
    memcpy(s->stage, stage, sizeof(s->stage));
    result = packet_send(s, packet, length, archive_fd, lease_fd);
    if (result) goto failed;
    result = observation(s, 1);
    if (result) goto failed;
    s->valid = 1; *root_inode = s->inode; *handle = s;
    return 0;
failed:
    close(s->socket); free(s);
    return result;
}
int nia_root_session_held(void *handle) {
    struct root_session *s = handle;
    if (!owned(s) || !s->valid || session_clock() >= s->deadline) return 0;
    struct pollfd p = {.fd = s->socket, .events = POLLIN};
    return poll(&p, 1, 0) == 0;
}
int nia_root_session_observe(void *handle, int archive_fd, int lease_fd) {
    struct root_session *s = handle;
    if (!owned(s) || !s->valid) return 1;
    if (archive_fd < 0 || lease_fd < 0) { s->valid = 0; return 1; }
    if (session_clock() >= s->deadline) { s->valid = 0; return 3; }
    char packet[128];
    int n = snprintf(packet, sizeof(packet), "{\"operation\":\"observe\",\"stage\":\"%s\",\"version\":1}\n", s->stage);
    int result = packet_send(s, packet, n, archive_fd, lease_fd);
    if (!result) result = observation(s, 0);
    if (result) s->valid = 0; /* Reservation lifetime still ends at explicit close. */
    return result;
}
int nia_root_session_close(void **handle) {
    if (!handle || !*handle) return 0;
    struct root_session *s = *handle;
    int result = 1;
    if (owned(s)) {
        char packet[128], response[4096];
        int n = snprintf(packet, sizeof(packet), "{\"operation\":\"close\",\"stage\":\"%s\",\"version\":1}\n", s->stage);
        result = packet_send(s, packet, n, -1, -1);
        if (!result) result = packet_receive(s, response, sizeof(response), 1);
    }
    nia_root_session_discard(handle);
    return result;
}
