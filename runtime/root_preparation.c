/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static uint64_t clock_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int ready(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = clock_ms();
        if (now >= deadline) return -1;
        struct pollfd p = {.fd = fd, .events = events};
        /* Reobserve boottime after suspend and every bounded wait. */
        int delay = deadline - now > 1000 ? 1000 : (int)(deadline - now);
        int result = poll(&p, 1, delay);
        if (result > 0) return p.revents & events ? 0 : -1;
        if (result < 0 && errno != EINTR) return -1;
    }
}
static int hex(const char *s, size_t size) {
    if (strlen(s) != size) return 0;
    int nonzero = 0;
    for (size_t i = 0; i < size; ++i) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
        nonzero |= s[i] != '0';
    }
    return nonzero;
}
static int exchange(const char *path, const char *packet, int length,
    const char *expected, int expected_length, uint64_t deadline, int archive_fd, int reservation_fd, int wait_close) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return 1;
    int result = 1;
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    memcpy(address.sun_path, path, strlen(path) + 1);
    /* A full accept backlog is refusal; never reconnect/retransmit implicitly. */
    if (connect(fd, (struct sockaddr *)&address, sizeof(address))) goto done;
    struct ucred peer; socklen_t peer_size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) || peer_size != sizeof(peer) || peer.uid != 0) goto done;
    if (ready(fd, POLLOUT, deadline)) { result = 3; goto done; }
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(2 * sizeof(int))]; } control = {0};
    struct iovec vec = {.iov_base = (void *)packet, .iov_len = (size_t)length};
    struct msghdr message = {.msg_iov = &vec, .msg_iovlen = 1, .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)};
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(2 * sizeof(int));
    int descriptors[2] = {archive_fd, reservation_fd};
    memcpy(CMSG_DATA(c), descriptors, sizeof(descriptors));
    result = 2; /* Every failure from attempted delivery is uncertain. */
    if (sendmsg(fd, &message, MSG_NOSIGNAL) != length || ready(fd, POLLIN, deadline)) goto done;
    char response[4096];
    vec.iov_base = response; vec.iov_len = sizeof(response);
    message.msg_controllen = sizeof(control.bytes); message.msg_flags = 0;
    ssize_t received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    int extra = 0;
    for (c = CMSG_FIRSTHDR(&message); received >= 0 && c; c = CMSG_NXTHDR(&message, c)) {
        extra = 1;
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(0)) {
            size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < count; ++i) { int owned; memcpy(&owned, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(owned)); close(owned); }
        }
    }
    int matched = !extra && !(message.msg_flags & ~(MSG_CMSG_CLOEXEC | MSG_EOR)) && received == expected_length && clock_ms() < deadline &&
        !memcmp(response, expected, (size_t)expected_length);
    if (!wait_close) { if (matched) result = 0; goto done; }
    if (received >= 0) {
        /* The bank closes its received archive/lease FDs before closing the
         * peer. Wait for that boundary: a response alone can race FD cleanup. */
        if (ready(fd, POLLIN, deadline)) goto done;
        message.msg_controllen = sizeof(control.bytes); message.msg_flags = 0;
        received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
        extra = 0;
        for (c = CMSG_FIRSTHDR(&message); received >= 0 && c; c = CMSG_NXTHDR(&message, c)) {
            extra = 1;
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(0)) {
                size_t count = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                for (size_t i = 0; i < count; ++i) { int owned; memcpy(&owned, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(owned)); close(owned); }
            }
        }
        if (matched && received == 0 && !extra && !(message.msg_flags & ~(MSG_CMSG_CLOEXEC | MSG_EOR)) && clock_ms() < deadline) result = 0;
    }
done:
    close(fd); /* Never close/unlock the caller's archive or reservation. */
    return result;
}
int nia_root_prepare(const char *path, const char *generation, const char *root,
    const char *archive, const char *worker, const char *stage,
    unsigned long long size, unsigned long long entries, unsigned long long deadline,
    int archive_fd, int reservation_fd) {
    uint64_t now = clock_ms();
    if (!getuid() || !geteuid() || !path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        !hex(generation, 64) || !hex(root, 64) || !hex(archive, 64) || !hex(worker, 64) || !hex(stage, 32) ||
        size < 1024 || size > UINT64_C(8589934592) || size % 512 || !entries || entries > 524288 ||
        archive_fd < 0 || reservation_fd < 0 || sodium_init() < 0) return 1;
    if (deadline <= now || deadline - now > 600000) return 3;
    char packet[1024], expected[512], intent[65];
    int length = snprintf(packet, sizeof(packet),
        "{\"archive\":\"%s\",\"deadline_ms\":%llu,\"entries\":%llu,\"generation\":\"%s\",\"root_manifest\":\"%s\",\"size\":%llu,\"stage\":\"%s\",\"version\":1}\n",
        archive, deadline, entries, generation, root, size, stage);
    if (length < 0 || (size_t)length >= sizeof(packet)) return 1;
    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, (const unsigned char *)packet, (unsigned long long)length);
    sodium_bin2hex(intent, sizeof(intent), digest, sizeof(digest));
    int expected_length = snprintf(expected, sizeof(expected),
        "{\"effects_applied\":false,\"intent_sha256\":\"%s\",\"published\":false,\"state\":\"extracted\",\"version\":1,\"worker_exit\":0,\"worker_sha256\":\"%s\"}\n",
        intent, worker);
    if (expected_length < 0 || (size_t)expected_length >= sizeof(expected)) return 1;
    return exchange(path, packet, length, expected, expected_length, deadline, archive_fd, reservation_fd, 0);
}
int nia_root_reinspect(const char *path, const char *generation, const char *root,
    const char *archive, const char *worker, const char *stage,
    unsigned long long size, unsigned long long entries, unsigned long long original_deadline,
    unsigned long long deadline, unsigned long long mount_id, unsigned long long inode,
    unsigned long long device_major, unsigned long long device_minor, int archive_fd, int reservation_fd) {
    uint64_t now = clock_ms();
    if (!getuid() || !geteuid() || !path || path[0] != '/' || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path) ||
        !hex(generation, 64) || !hex(root, 64) || !hex(archive, 64) || !hex(worker, 64) || !hex(stage, 32) ||
        size < 1024 || size > UINT64_C(8589934592) || size % 512 || !entries || entries > 524288 ||
        !original_deadline || original_deadline > INT64_MAX || !mount_id || !inode ||
        device_major > UINT32_MAX || device_minor > UINT32_MAX ||
        archive_fd < 0 || reservation_fd < 0 || sodium_init() < 0) return 1;
    if (deadline <= now || deadline > INT64_MAX || deadline - now > 600000) return 3;
    char request[1024], packet[1100], expected[1500], intent[65];
    int length = snprintf(request, sizeof(request),
        "{\"archive\":\"%s\",\"deadline_ms\":%llu,\"entries\":%llu,\"generation\":\"%s\",\"root_manifest\":\"%s\",\"size\":%llu,\"stage\":\"%s\",\"version\":1}\n",
        archive, original_deadline, entries, generation, root, size, stage);
    if (length < 0 || (size_t)length >= sizeof(request)) return 1;
    unsigned char digest[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(digest, (const unsigned char *)request, (unsigned long long)length);
    sodium_bin2hex(intent, sizeof(intent), digest, sizeof(digest));
    length = snprintf(packet, sizeof(packet),
        "{\"verify\":{\"archive\":\"%s\",\"deadline_ms\":%llu,\"entries\":%llu,\"generation\":\"%s\",\"root_manifest\":\"%s\",\"size\":%llu,\"stage\":\"%s\",\"version\":1}}\n",
        archive, deadline, entries, generation, root, size, stage);
    int expected_length = snprintf(expected, sizeof(expected),
        "{\"effects_applied\":false,\"intent_sha256\":\"%s\",\"observation\":{\"archive_sha256\":\"%s\",\"device_major\":%llu,\"device_minor\":%llu,\"entries\":%llu,\"inode\":%llu,\"mount_id\":%llu,\"profile\":\"linux-inode-v1\",\"published\":false,\"result\":\"verified\"},\"physical_revalidation\":true,\"published\":false,\"state\":\"extracted\",\"verification_deadline_ms\":%llu,\"version\":1,\"worker_exit\":0,\"worker_sha256\":\"%s\"}\n",
        intent, archive, device_major, device_minor, entries, inode, mount_id, deadline, worker);
    if (length < 0 || (size_t)length >= sizeof(packet) || expected_length < 0 || (size_t)expected_length >= sizeof(expected)) return 1;
    return exchange(path, packet, length, expected, expected_length, deadline, archive_fd, reservation_fd, 1);
}
