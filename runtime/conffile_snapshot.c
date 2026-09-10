/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include "conffile_snapshot.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/openat2.h>
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define META_LIMIT 196608U
#define XATTR_LIMIT 131072U
#define REQUIRED (STATX_BASIC_STATS | STATX_MNT_ID)
struct observation {
    int root, fd;
    uint64_t size, limit;
    unsigned int used;
    char path[4097];
    unsigned char content[32], metadata[META_LIMIT];
};
static int error_code(void) {
    switch (errno) {
    case EACCES: case EPERM: return 3;
    case ENOSYS: case EOPNOTSUPP: case ENOTTY: return 2;
    case ENOMEM: case ENOSPC: case EMFILE: case ENFILE: case E2BIG: return 6;
    case ENOENT: case ESTALE: case ERANGE: return 5;
    case ELOOP: case EXDEV: case ENOTDIR: return 2;
    default: return 7;
    }
}
static int clock_check(uint64_t deadline) {
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now)) return 7;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 >= deadline ? 5 : 0;
}
static int append(struct observation *s, const void *p, size_t n) {
    if (n > META_LIMIT - s->used) return 6;
    memcpy(s->metadata + s->used, p, n); s->used += (unsigned int)n; return 0;
}
static int number(struct observation *s, uint64_t n) {
    unsigned char b[8];
    for (unsigned int i = 0; i < 8; ++i) { b[i] = n & 255; n >>= 8; }
    return append(s, b, sizeof(b));
}
#define TRY(x) do { int rc_ = (x); if (rc_) return rc_; } while (0)
static int stat_fd(int fd, struct statx *v) {
    memset(v, 0, sizeof(*v));
    if (statx(fd, "", AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_STATX_FORCE_SYNC,
              REQUIRED | STATX_BTIME, v)) return error_code();
    if ((v->stx_mask & REQUIRED) != REQUIRED) return 2;
    return 0;
}
static int identity(struct observation *s, const struct statx *v) {
    TRY(number(s, v->stx_mnt_id)); TRY(number(s, v->stx_dev_major));
    TRY(number(s, v->stx_dev_minor)); TRY(number(s, v->stx_ino));
    TRY(number(s, v->stx_mode)); TRY(number(s, v->stx_uid));
    return number(s, v->stx_gid);
}
static int directory(struct observation *s, int fd) {
    struct statx v; TRY(stat_fd(fd, &v));
    if (!S_ISDIR(v.stx_mode) || (v.stx_mode & 0022) ||
        (v.stx_uid != 0 && v.stx_uid != geteuid())) return 3;
    TRY(number(s, 2)); return identity(s, &v);
}
static int timestamp(struct observation *s, struct statx_timestamp t) {
    /* Signed seconds are preserved as 64-bit two's-complement, including pre-epoch. */
    TRY(number(s, (uint64_t)t.tv_sec)); return number(s, t.tv_nsec);
}
static int compare_names(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}
static int attributes(struct observation *s, uint64_t deadline) {
    char names[65536]; char *sorted[32768];
    unsigned char *value = NULL;
    ssize_t length = flistxattr(s->fd, names, sizeof(names));
    if (length < 0) return error_code();
    size_t count = 0, pos = 0, total = 0;
    while (pos < (size_t)length) {
        size_t n = strnlen(names + pos, (size_t)length - pos);
        if (!n || n == (size_t)length - pos || count == 32768) return 7;
        sorted[count++] = names + pos; pos += n + 1;
    }
    qsort(sorted, count, sizeof(*sorted), compare_names);
    TRY(number(s, count));
    value = malloc(XATTR_LIMIT);
    if (!value) return 6;
    int rc = 0;
    for (size_t i = 0; i < count; ++i) {
        if ((rc = clock_check(deadline))) break;
        if (i && !strcmp(sorted[i-1], sorted[i])) { rc = 7; break; }
        ssize_t n = fgetxattr(s->fd, sorted[i], value, XATTR_LIMIT);
        if (n < 0) { rc = error_code(); break; }
        size_t name_size = strlen(sorted[i]); total += name_size + (size_t)n;
        if (total > XATTR_LIMIT) { rc = 6; break; }
        if ((rc = number(s, name_size)) || (rc = append(s, sorted[i], name_size)) ||
            (rc = number(s, (uint64_t)n)) || (rc = append(s, value, (size_t)n))) break;
    }
    free(value); return rc;
}
static int file_metadata(struct observation *s, uint64_t deadline) {
    struct statx v; unsigned long flags = 0;
    TRY(stat_fd(s->fd, &v));
    if (!S_ISREG(v.stx_mode)) return 2;
    if (v.stx_size > s->limit) return 6;
    if (ioctl(s->fd, FS_IOC_GETFLAGS, &flags)) return error_code();
    s->size = v.stx_size;
    TRY(number(s, 1)); TRY(identity(s, &v));
    TRY(number(s, v.stx_nlink)); TRY(number(s, v.stx_size));
    TRY(number(s, v.stx_attributes)); TRY(number(s, v.stx_attributes_mask));
    TRY(timestamp(s, v.stx_atime)); TRY(timestamp(s, v.stx_mtime));
    TRY(timestamp(s, v.stx_ctime)); TRY(number(s, !!(v.stx_mask & STATX_BTIME)));
    if (v.stx_mask & STATX_BTIME) { TRY(timestamp(s, v.stx_btime)); }
    TRY(number(s, flags)); return attributes(s, deadline);
}
static int path_valid(const char *p) {
    if (!p || p[0] != '/' || strnlen(p, 4097) > 4096 || !p[1]) return 0;
    unsigned int depth = 0;
    for (const char *part = p + 1; *part;) {
        const char *end = strchrnul(part, '/'); size_t n = (size_t)(end - part);
        if (!n || n > 255 || (n == 1 && part[0] == '.') ||
            (n == 2 && part[0] == '.' && part[1] == '.') || ++depth > 128) return 0;
        if (!*end) return 1;
        part = end + 1;
    }
    return 0;
}
static int child(int parent, const char *name, uint64_t flags) {
    struct open_how how = {.flags = flags | O_CLOEXEC | O_NOFOLLOW,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV};
    return (int)syscall(SYS_openat2, parent, name, &how, sizeof(how));
}
static int hash_file(struct observation *s, uint64_t deadline) {
    crypto_hash_sha256_state hash; unsigned char buffer[65536];
    crypto_hash_sha256_init(&hash);
    uint64_t offset = 0;
    while (offset < s->size) {
        TRY(clock_check(deadline));
        size_t amount = s->size - offset < sizeof(buffer) ? (size_t)(s->size - offset) : sizeof(buffer);
        ssize_t n = pread(s->fd, buffer, amount, (off_t)offset);
        if (n < 0) { if (errno == EINTR) continue; return error_code(); }
        if (!n) return 5;
        crypto_hash_sha256_update(&hash, buffer, (unsigned long long)n); offset += (uint64_t)n;
    }
    crypto_hash_sha256_final(&hash, s->content); return clock_check(deadline);
}
/* Reopen from the pinned root each time. An absent ancestor records its exact
 * component position and preceding directory identities; it is not an IO error. */
static int scan(struct observation *s, uint64_t deadline) {
    TRY(clock_check(deadline));
    TRY(append(s, "NIACOBS1", 8)); TRY(number(s, strlen(s->path)));
    TRY(append(s, s->path, strlen(s->path)));
    /* Attribute visibility depends on credentials. This is an observation,
     * never an attestation that privileged namespaces were fully visible. */
    TRY(number(s, geteuid())); TRY(number(s, getegid()));
    int parent = fcntl(s->root, F_DUPFD_CLOEXEC, 3);
    if (parent < 0) return error_code();
    char path[4097]; strcpy(path, s->path + 1);
    char *part = path; int rc = 0;
    while (1) {
        if ((rc = clock_check(deadline)) || (rc = directory(s, parent))) break;
        char *end = strchr(part, '/'); if (end) *end = 0;
        int fd = child(parent, part, O_PATH);
        if (fd < 0) {
            if (errno == ENOENT) { rc = number(s, 0); if (!rc) rc = number(s, (uint64_t)(part - path)); }
            else rc = error_code();
            break;
        }
        struct statx probe;
        rc = stat_fd(fd, &probe);
        if (rc) { close(fd); break; }
        if (end) { close(parent); parent = fd; part = end + 1; continue; }
        if (!S_ISREG(probe.stx_mode)) { close(fd); rc = 2; break; }
        /* Reopen the already inspected regular inode through this process's
         * private FD table, never a pathname that could now name a device. */
        char reference[64];
        int printed = snprintf(reference, sizeof(reference), "/proc/self/fd/%d", fd);
        if (printed < 0 || (size_t)printed >= sizeof(reference)) { close(fd); rc = 7; break; }
        s->fd = open(reference, O_RDONLY | O_NONBLOCK | O_NOATIME | O_CLOEXEC);
        int open_error = errno;
        close(fd);
        if (s->fd < 0) { errno = open_error; rc = error_code(); break; }
        struct statx opened; rc = stat_fd(s->fd, &opened);
        if (rc) break;
        if (opened.stx_ino != probe.stx_ino || opened.stx_mnt_id != probe.stx_mnt_id ||
            opened.stx_dev_major != probe.stx_dev_major || opened.stx_dev_minor != probe.stx_dev_minor) { rc = 5; break; }
        unsigned int start = s->used;
        rc = file_metadata(s, deadline);
        if (!rc) rc = hash_file(s, deadline);
        if (!rc) {
            struct observation *after = calloc(1, sizeof(*after));
            if (!after) rc = 6;
            else {
                after->fd = s->fd; after->limit = s->limit;
                rc = file_metadata(after, deadline);
                if (!rc && (after->used != s->used - start ||
                            memcmp(after->metadata, s->metadata + start, after->used))) rc = 5;
                free(after);
            }
        }
        break;
    }
    close(parent); return rc;
}
void nia_conffile_close(void *handle) {
    struct observation *s = handle;
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    if (s->root >= 0) close(s->root);
    free(s);
}
static int observe(int root, const char *path, uint64_t limit, uint64_t deadline, struct observation **out) {
    *out = NULL;
    struct observation *s = calloc(1, sizeof(*s));
    if (!s) return 6;
    s->root = -1; s->fd = -1; s->limit = limit; strcpy(s->path, path);
    s->root = fcntl(root, F_DUPFD_CLOEXEC, 3);
    int rc = s->root < 0 ? error_code() : scan(s, deadline);
    if (!rc) rc = append(s, s->content, sizeof(s->content));
    if (rc) nia_conffile_close(s); else *out = s;
    return rc;
}
int nia_conffile_recheck(void *handle, uint64_t deadline) {
    struct observation *s = handle, *fresh = NULL;
    if (!s) return 1;
    int rc = observe(s->root, s->path, s->limit, deadline, &fresh);
    if (!rc && (s->used != fresh->used || memcmp(s->metadata, fresh->metadata, s->used) ||
                memcmp(s->content, fresh->content, 32))) rc = 5;
    nia_conffile_close(fresh); return rc;
}
int nia_conffile_capture(int root, const char *path, uint64_t limit, uint64_t deadline, void **result) {
    if (!result) return 1;
    *result = NULL;
    if (root < 0 || !path_valid(path) || limit > UINT64_C(8589934592)) return 1;
    struct observation *s = NULL;
    int rc = observe(root, path, limit, deadline, &s);
    if (!rc) rc = nia_conffile_recheck(s, deadline);
    if (rc) nia_conffile_close(s); else *result = s;
    return rc;
}
int nia_conffile_data(void *handle, int *fd, uint64_t *size,
                      const unsigned char **metadata, unsigned int *used, unsigned char content[32]) {
    if (fd) *fd = -1;
    if (size) *size = 0;
    if (metadata) *metadata = NULL;
    if (used) *used = 0;
    if (content) memset(content, 0, 32);
    struct observation *s = handle;
    if (!s || !fd || !size || !metadata || !used || !content) return 1;
    *fd = s->fd; *size = s->size; *metadata = s->metadata; *used = s->used;
    memcpy(content, s->content, 32); return 0;
}
