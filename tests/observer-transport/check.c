/* SPDX-License-Identifier: BSD-3-Clause */
#include "../../runtime/archive_observer.c"
#include <assert.h>
#include <stdlib.h>
int main(void) {
    char output[PACKET_LIMIT];
    assert(path_json("pool/test.deb", output) == 0 && !strcmp(output, "pool/test.deb"));
    assert(path_json("pool/\xe6\x97\xa5\xf0\x9f\x98\x80\".deb", output) == 0 &&
           !strcmp(output, "pool/\\u65e5\\ud83d\\ude00\\\".deb"));
    const char *bad[] = {"", "/absolute", "a//b", "a/../b", "./a", "trailing/", "a\\b", "a\n", "a\x7f", "\xc0\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xf0\x9f"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) assert(path_json(bad[i], output) != 0);
    unsigned char *policy = malloc(POLICY_LIMIT), wire[320]; unsigned int used = 7;
    assert(policy);
    memset(policy, 1, POLICY_LIMIT); memset(wire, 1, sizeof(wire));
    assert(nia_archive_observe(NULL, NULL, NULL, NULL, 0, 0, -1, -1, -1, wire, policy, &used) == 1);
    assert(!used);
    for (size_t i = 0; i < POLICY_LIMIT; ++i) assert(policy[i] == 0);
    for (size_t i = 0; i < sizeof(wire); ++i) assert(wire[i] == 0);
    free(policy);
    puts("PASS UTF-8 paths, JSON escaping, malformed paths and cleared transport outputs");
    return 0;
}
