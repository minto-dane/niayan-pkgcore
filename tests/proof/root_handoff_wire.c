/* SPDX-License-Identifier: BSD-3-Clause */
/* Proof inputs are arbitrary initialized objects, with no input assumptions.
 * The packet is a real 192-byte object or NULL; length/deadline are arbitrary.
 * No external OS/library model is used by the implementation under proof. */
#include <assert.h>
#include <stdint.h>
#include "../../runtime/root_handoff_wire.h"
void __CPROVER_havoc_object(void *object);

static uint64_t reference_integer(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
        | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
        | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
        | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

void proof_handoff_wire(void)
{
    uint8_t packet[192];
    size_t length;
    uint64_t deadline;
    _Bool null_input;
    __CPROVER_havoc_object(packet);
    __CPROVER_havoc_object(&length);
    __CPROVER_havoc_object(&deadline);
    __CPROVER_havoc_object(&null_input);
    const uint64_t size = reference_integer(packet + 152);
    const uint64_t entries = reference_integer(packet + 160);
    int expected = !null_input && length == 192 && deadline > 0 && deadline <= INT64_MAX
        && packet[0] == 'N' && packet[1] == 'I' && packet[2] == 'A' && packet[3] == 'H'
        && packet[4] == 'N' && packet[5] == 'D' && packet[6] == '0' && packet[7] == '1'
        && reference_integer(packet + 168) == deadline
        && size >= 1024 && size <= UINT64_C(8589934592) && (size & 511) == 0
        && entries >= 1 && entries <= 524288;
    for (size_t index = 176; index < 192; ++index) {
        expected = expected && packet[index] == 0;
    }
    for (size_t block = 0; block < 5; ++block) {
        int present = 0;
        const size_t width = block == 4 ? 16 : 32;
        for (size_t index = 0; index < 32; ++index) {
            if (index < width) {
                present = present || packet[8 + 32 * block + index] != 0;
            }
        }
        expected = expected && present;
    }
    const int observed = nia_handoff_wire_valid(null_input ? NULL : packet, length, deadline);
    assert(observed == expected);
    assert(observed == 0 || observed == 1);
}
