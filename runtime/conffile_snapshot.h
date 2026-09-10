/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef NIA_CONFFILE_SNAPSHOT_H
#define NIA_CONFFILE_SNAPSHOT_H
#include <stdint.h>
/* Internal, process-local handles. Codes: 0 OK, 1 invalid, 2 unsupported,
 * 3 denied, 5 stale, 6 exhausted, 7 IO. No filesystem mutation or authority. */
int nia_conffile_capture(int root, const char *path, uint64_t limit,
                        uint64_t deadline, void **result);
int nia_conffile_recheck(void *handle, uint64_t deadline);
void nia_conffile_close(void *handle);
/* Borrowed data/FD, valid only until close. FD is -1 for observed absence. */
int nia_conffile_data(void *handle, int *fd, uint64_t *size,
                      const unsigned char **metadata, unsigned int *used,
                      unsigned char content[32]);
#endif
