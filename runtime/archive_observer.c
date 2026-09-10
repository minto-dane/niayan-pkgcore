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
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define POLICY_LIMIT (5U * 1024U * 1024U)
#define PACKET_LIMIT 4096U

static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static int ready(int fd, short events, uint64_t deadline) {
    for (;;) {
        uint64_t now = now_ms();
        if (now >= deadline) return -1;
        struct pollfd p = {.fd = fd, .events = events};
        int result = poll(&p, 1, deadline - now > 1000 ? 1000 : (int)(deadline - now));
        if (result > 0) return p.revents & events ? 0 : -1;
        if (result < 0 && errno != EINTR) return -1;
    }
}
static int hex_digest(const char *s) {
    if (!s || strlen(s) != 64) return 0;
    int nonzero = 0;
    for (size_t i = 0; i < 64; ++i) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
        nonzero |= s[i] != '0';
    }
    return nonzero;
}
/* Match canonical ensure_ascii JSON without restricting valid UTF-8 filenames.
 * Input path elements are checked before escaping. No permissive JSON parser. */
static int path_json(const char *input, char output[PACKET_LIMIT]) {
    if (!input) return -1;
    size_t n = strnlen(input, 4097), out = 0, characters = 0, parts = 1, start = 0;
    if (!n || n > 4096 || input[0] == '/' || input[n-1] == '/') return -1;
    for (size_t i = 0; i <= n; ++i) {
        if (i == n || input[i] == '/') {
            size_t size = i - start;
            if (!size || (size == 1 && input[start] == '.') ||
                (size == 2 && input[start] == '.' && input[start+1] == '.')) return -1;
            start = i + 1;
            if (i < n && ++parts > 32) return -1;
        }
    }
    for (size_t i = 0; i < n;) {
        unsigned char first = (unsigned char)input[i++];
        uint32_t cp = first, minimum = 0; size_t extra = 0;
        if (first >= 0xc2 && first <= 0xdf) { cp &= 0x1f; extra = 1; minimum = 0x80; }
        else if (first >= 0xe0 && first <= 0xef) { cp &= 0x0f; extra = 2; minimum = 0x800; }
        else if (first >= 0xf0 && first <= 0xf4) { cp &= 7; extra = 3; minimum = 0x10000; }
        else if (first >= 0x80) return -1;
        if (extra > n-i) return -1;
        for (size_t j = 0; j < extra; ++j) {
            unsigned char next = (unsigned char)input[i++];
            if ((next & 0xc0) != 0x80) return -1;
            cp = (cp << 6) | (next & 0x3f);
        }
        if (cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ||
            cp < 32 || cp == 127 || cp == '\\' || ++characters > 1024) return -1;
        if (out + 13 >= PACKET_LIMIT) return -1;
        if (cp == '"') { output[out++] = '\\'; output[out++] = '"'; }
        else if (cp < 128) output[out++] = (char)cp;
        else if (cp <= 0xffff) { snprintf(output+out, 7, "\\u%04x", cp); out += 6; }
        else {
            cp -= 0x10000;
            snprintf(output+out, 13, "\\u%04x\\u%04x", 0xd800+(cp>>10), 0xdc00+(cp&1023)); out += 12;
        }
    }
    output[out] = 0;
    return 0;
}
static int read_result(int fd, uid_t uid, unsigned char *output, size_t limit,
                       size_t *size, uint64_t deadline) {
    struct stat s;
    int flags = fcntl(fd, F_GETFL), seals = fcntl(fd, F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (flags < 0 || seals < 0 || (flags & O_ACCMODE) != O_RDONLY ||
        (seals & required) != required || fstat(fd, &s) || !S_ISREG(s.st_mode) ||
        s.st_uid != uid || s.st_nlink != 0 || (s.st_mode & 07777) != 0400 ||
        s.st_size <= 0 || (uint64_t)s.st_size > limit) return -1;
    *size = (size_t)s.st_size;
    for (size_t offset = 0; offset < *size;) {
        if (now_ms() >= deadline) return -1;
        size_t count = *size-offset > 65536 ? 65536 : *size-offset;
        ssize_t got = pread(fd, output+offset, count, (off_t)offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return -1;
        offset += (size_t)got;
    }
    return 0;
}
int nia_archive_observe(const char *id, const char *scope, const char *index, const char *deb,
    unsigned int observer_uid, unsigned long long deadline, int release_fd, int index_fd, int deb_fd,
    unsigned char *wire, unsigned char *policy, unsigned int *policy_size) {
    if (!wire || !policy || !policy_size) return 1;
    memset(wire, 0, 320); memset(policy, 0, POLICY_LIMIT); *policy_size = 0;
    uint64_t now = now_ms();
    if (!getuid() || !geteuid() || !observer_uid || observer_uid == geteuid() ||
        !hex_digest(id) || !hex_digest(scope) || release_fd < 0 || index_fd < 0 || deb_fd < 0 || sodium_init() < 0) return 1;
    if (deadline <= now || deadline-now > 130000) return 3;
    char escaped_index[PACKET_LIMIT], escaped_deb[PACKET_LIMIT], packet[PACKET_LIMIT];
    if (path_json(index, escaped_index) || path_json(deb, escaped_deb)) return 1;
    int length = snprintf(packet, sizeof(packet),
        "{\"deb\":\"%s\",\"index\":\"%s\",\"request_id\":\"%s\",\"schema\":\"org.niaos.archive-observer-request/v1\",\"scope\":\"%s\"}",
        escaped_deb, escaped_index, id, scope);
    if (length < 0 || (size_t)length >= sizeof(packet)) return 1;
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return 1;
    int result = 1, enabled = 1, owned[8], owned_count = 0;
    struct sockaddr_un address = {.sun_family = AF_UNIX, .sun_path = "/run/niaos/archive-observer.sock"};
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) ||
        connect(fd, (struct sockaddr *)&address, sizeof(address))) goto done;
    struct ucred peer; socklen_t peer_size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) || peer_size != sizeof(peer) || peer.uid != 0) goto done;
    if (ready(fd, POLLOUT, deadline)) { result = 3; goto done; }
    union { struct cmsghdr align; char data[CMSG_SPACE(8*sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))]; } control = {0};
    struct iovec vec = {.iov_base = packet, .iov_len = (size_t)length};
    struct msghdr message = {.msg_iov = &vec, .msg_iovlen = 1,
                            .msg_control = control.data, .msg_controllen = CMSG_SPACE(3*sizeof(int))};
    struct cmsghdr *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS; c->cmsg_len = CMSG_LEN(3*sizeof(int));
    int originals[3] = {release_fd, index_fd, deb_fd}; memcpy(CMSG_DATA(c), originals, sizeof(originals));
    result = 2; /* Attempted delivery may have advanced the independent TUF cache. */
    if (sendmsg(fd, &message, MSG_NOSIGNAL) != length || ready(fd, POLLIN, deadline)) goto done;
    char response[PACKET_LIMIT]; vec.iov_base = response; vec.iov_len = sizeof(response);
    message.msg_controllen = sizeof(control.data); message.msg_flags = 0;
    ssize_t received = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    int credentials = 0, unexpected = 0;
    for (c = CMSG_FIRSTHDR(&message); received >= 0 && c; c = CMSG_NXTHDR(&message, c)) {
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= CMSG_LEN(0)) {
            size_t size = c->cmsg_len-CMSG_LEN(0);
            if (size % sizeof(int)) unexpected = 1;
            for (size_t i = 0; i < size/sizeof(int); ++i) {
                int descriptor; memcpy(&descriptor, (char *)CMSG_DATA(c)+i*sizeof(int), sizeof(int));
                if (owned_count < 8) owned[owned_count++] = descriptor;
                else { close(descriptor); unexpected = 1; }
            }
        } else if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_CREDENTIALS && c->cmsg_len == CMSG_LEN(sizeof(peer))) {
            memcpy(&peer, CMSG_DATA(c), sizeof(peer));
            if (++credentials != 1 || peer.uid != observer_uid || peer.pid <= 0) unexpected = 1;
        } else unexpected = 1;
    }
    if (received <= 0 || credentials != 1 || unexpected ||
        (message.msg_flags & ~(MSG_CMSG_CLOEXEC | MSG_EOR)) || now_ms() >= deadline) goto done;
    char expected[512];
    if (!owned_count) {
        const char *ids[2] = {id, "0000000000000000000000000000000000000000000000000000000000000000"};
        for (size_t i = 0; i < 2; ++i) {
            int n = snprintf(expected, sizeof(expected),
                "{\"execution_permit\":false,\"request_id\":\"%s\",\"schema\":\"org.niaos.archive-observer-result/v1\",\"status\":\"rejected\"}", ids[i]);
            if (n > 0 && received == n && !memcmp(response, expected, (size_t)n)) { result = 1; break; }
        }
        goto done;
    }
    size_t wire_size = 0, size = 0;
    if (owned_count != 2 || read_result(owned[0], observer_uid, wire, 320, &wire_size, deadline) || wire_size != 320 ||
        read_result(owned[1], observer_uid, policy, POLICY_LIMIT, &size, deadline)) goto done;
    unsigned char hash[32]; char policy_hash[65], wire_hash[65];
    crypto_hash_sha256(hash, policy, size); sodium_bin2hex(policy_hash, sizeof(policy_hash), hash, sizeof(hash));
    crypto_hash_sha256(hash, wire, 320); sodium_bin2hex(wire_hash, sizeof(wire_hash), hash, sizeof(hash));
    int n = snprintf(expected, sizeof(expected),
        "{\"execution_permit\":false,\"policy_sha256\":\"%s\",\"receipt_sha256\":\"%s\",\"request_id\":\"%s\",\"schema\":\"org.niaos.archive-observer-result/v1\",\"status\":\"authenticated\"}",
        policy_hash, wire_hash, id);
    if (n <= 0 || (size_t)n >= sizeof(expected) || received != n || memcmp(response, expected, (size_t)n) || now_ms() >= deadline) goto done;
    *policy_size = (unsigned int)size; result = 0;
done:
    for (int i = 0; i < owned_count; ++i) close(owned[i]);
    close(fd);
    if (result) { memset(wire, 0, 320); memset(policy, 0, POLICY_LIMIT); *policy_size = 0; }
    return result;
}
