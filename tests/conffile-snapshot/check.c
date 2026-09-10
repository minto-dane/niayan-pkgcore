/* SPDX-License-Identifier: BSD-3-Clause */
#include "../../runtime/conffile_snapshot.c"
#include <assert.h>
#include <endian.h>
#include <linux/posix_acl_xattr.h>
static uint64_t deadline(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_BOOTTIME, &t));
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000 + 30000;
}
static void write_file(int root, const char *name, const char *data) {
    int fd = openat(root, name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    assert(fd >= 0); assert(write(fd, data, strlen(data)) == (ssize_t)strlen(data)); assert(!close(fd));
}
int main(int argc, char **argv) {
    assert(argc == 2 && geteuid() != 0);
    int root = open(argv[1], O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(root >= 0); assert(!mkdirat(root, "etc", 0700));
    void *s = NULL;
    const char *bad[] = {"", "/", "relative", "/a/", "/a//b", "/a/../b", "/./b"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        assert(nia_conffile_capture(root, bad[i], 1024, deadline(), &s) == 1 && !s);
    assert(!nia_conffile_capture(root, "/etc/missing/child", 1024, deadline(), &s));
    int fd; uint64_t size; const unsigned char *metadata; unsigned int used; unsigned char hash[32];
    assert(!nia_conffile_data(s, &fd, &size, &metadata, &used, hash));
    assert(fd == -1 && !size && used && !memcmp(hash, (unsigned char[32]){0}, 32));
    assert(!nia_conffile_recheck(s, deadline()));
    assert(!mkdirat(root, "etc/missing", 0700));
    assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!unlinkat(root, "etc/missing", AT_REMOVEDIR));
    const char *name = "etc/na me-\xff", *path = "/etc/na me-\xff";
    write_file(root, name, "local");
    fd = openat(root, name, O_RDWR | O_CLOEXEC); assert(fd >= 0);
    struct timespec times[2] = {{123,456}, {-42,123456789}};
    assert(!futimens(fd, times)); assert(!fsetxattr(fd, "user.fixture", "value", 5, 0));
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    int borrowed;
    assert(!nia_conffile_data(s, &borrowed, &size, &metadata, &used, hash));
    assert((fcntl(borrowed, F_GETFL) & O_ACCMODE) == O_RDONLY);
    /* Read canonical timestamps independently of the encoder. */
    size_t mtime = 16 + strlen(path) + 16 + 2 * 64 + 8 + 56 + 32 + 16;
    assert(used > mtime + 16 + 32);
    assert(!memcmp(metadata + mtime, (unsigned char[8]){214,255,255,255,255,255,255,255}, 8));
    assert(!memcmp(metadata + mtime + 8, (unsigned char[8]){21,205,91,7,0,0,0,0}, 8));
    assert(!memcmp(metadata + used - 32, hash, 32));
    struct stat after; assert(!fstat(fd, &after));
    assert(after.st_atim.tv_sec == 123 && after.st_atim.tv_nsec == 456);
    assert(after.st_mtim.tv_sec == -42 && after.st_mtim.tv_nsec == 123456789);
    assert(!nia_conffile_recheck(s, deadline()));
    assert(!fsetxattr(fd, "user.fixture", "other", 5, 0));
    assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    struct {
        struct posix_acl_xattr_header header;
        struct posix_acl_xattr_entry entries[5];
    } acl = {0};
    acl.header.a_version = htole32(POSIX_ACL_XATTR_VERSION);
    const uint16_t tags[5] = {1, 2, 4, 16, 32}, perms[5] = {6, 4, 0, 4, 0};
    for (size_t i = 0; i < 5; ++i) {
        acl.entries[i].e_tag = htole16(tags[i]); acl.entries[i].e_perm = htole16(perms[i]);
        acl.entries[i].e_id = htole32(i == 1 ? geteuid() + 1 : UINT32_MAX);
    }
    assert(!fsetxattr(fd, "system.posix_acl_access", &acl, sizeof(acl), 0));
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    assert(!nia_conffile_data(s, &borrowed, &size, &metadata, &used, hash));
    assert(memmem(metadata, used, &acl, sizeof(acl)));
    acl.entries[1].e_perm = htole16(0);
    assert(!fsetxattr(fd, "system.posix_acl_access", &acl, sizeof(acl), 0));
    assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!fremovexattr(fd, "system.posix_acl_access"));
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    assert(!fchmod(fd, 0600)); assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    assert(pwrite(fd, "other", 5, 0) == 5); assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    assert(!linkat(root, name, root, "etc/alias", 0));
    assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!unlinkat(root, "etc/alias", 0)); close(fd);
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    assert(!unlinkat(root, name, 0)); write_file(root, name, "other");
    assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!nia_conffile_capture(root, path, 1024, deadline(), &s));
    assert(!unlinkat(root, name, 0)); assert(nia_conffile_recheck(s, deadline()) == 5); nia_conffile_close(s);
    assert(!symlinkat("missing", root, "etc/link"));
    assert(nia_conffile_capture(root, "/etc/link", 1024, deadline(), &s) == 2 && !s);
    assert(nia_conffile_capture(root, "/etc/link/child", 1024, deadline(), &s) != 0 && !s);
    assert(!unlinkat(root, "etc/link", 0));
    assert(!mkfifoat(root, "etc/fifo", 0600));
    assert(nia_conffile_capture(root, "/etc/fifo", 1024, deadline(), &s) == 2 && !s);
    assert(!unlinkat(root, "etc/fifo", 0));
    write_file(root, "etc/config", "data");
    assert(nia_conffile_capture(root, "/etc/config", 3, deadline(), &s) == 6 && !s);
    assert(nia_conffile_capture(root, "/etc/config", 1024, 0, &s) == 5 && !s);
    int denied = openat(root, "etc/config", O_RDONLY | O_CLOEXEC); assert(denied >= 0);
    assert(!fchmod(denied, 0000));
    assert(nia_conffile_capture(root, "/etc/config", 1024, deadline(), &s) == 3 && !s);
    assert(!fchmod(denied, 0600)); close(denied);
    int dir = openat(root, "etc", O_RDONLY | O_DIRECTORY); assert(dir >= 0);
    assert(!fchmod(dir, 0770));
    assert(nia_conffile_capture(root, "/etc/config", 1024, deadline(), &s) == 3 && !s);
    assert(!fchmod(dir, 0700)); close(dir);
    assert(!unlinkat(root, "etc/config", 0)); assert(!unlinkat(root, "etc", AT_REMOVEDIR));
    assert(fcntl(root, F_GETFD) >= 0); close(root);
    puts("PASS raw paths, absence, contents, inode replacement, deletion, mode, xattrs, POSIX ACL, links, signed timestamps, atime, permission denial, bounds and deadline");
    return 0;
}
