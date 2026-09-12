/* SPDX-License-Identifier: BSD-3-Clause */
#include "root_handoff_wire.h"

static uint64_t read_u64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t index = 0; index < 8; ++index) {
        value = (value << 8) | bytes[index];
    }
    return value;
}

static int identity_present(const uint8_t *bytes, size_t length)
{
    unsigned int present = 0;
    if ((bytes == NULL) || (length == 0) || (length > 32)) {
        return 0;
    }
    for (size_t index = 0; index < 32; ++index) {
        if (index < length) {
            present |= bytes[index];
        }
    }
    return present != 0;
}

int nia_handoff_wire_valid(const uint8_t *packet, size_t length, uint64_t deadline)
{
    static const uint8_t magic[8] = {'N', 'I', 'A', 'H', 'N', 'D', '0', '1'};
    if ((packet == NULL) || (length != 192) || (deadline == 0) || (deadline > INT64_MAX)) {
        return 0;
    }
    for (size_t index = 0; index < 8; ++index) {
        if (packet[index] != magic[index]) {
            return 0;
        }
    }
    for (size_t index = 176; index < 192; ++index) {
        if (packet[index] != 0) {
            return 0;
        }
    }
    for (size_t block = 0; block < 4; ++block) {
        if (identity_present(packet + 8 + 32 * block, 32) == 0) {
            return 0;
        }
    }
    if ((identity_present(packet + 136, 16) == 0) || (read_u64(packet + 168) != deadline)) {
        return 0;
    }
    const uint64_t size = read_u64(packet + 152);
    const uint64_t entries = read_u64(packet + 160);
    return (size >= 1024) && (size <= UINT64_C(8589934592)) && (size % 512 == 0)
        && (entries >= 1) && (entries <= 524288);
}

int nia_handoff_reinspection_valid(const uint8_t *packet, size_t length, uint64_t deadline)
{
    static const uint8_t magic[8] = {'N', 'I', 'A', 'H', 'R', 'V', '0', '1'};
    uint8_t common[192] = {0};
    if ((packet == NULL) || (length != 224)) {
        return 0;
    }
    for (size_t index = 0; index < 8; ++index) {
        if (packet[index] != magic[index]) {
            return 0;
        }
    }
    for (size_t index = 208; index < 224; ++index) {
        if (packet[index] != 0) {
            return 0;
        }
    }
    /* Reuse the exact shared scope bounds without giving this operation the
     * preparation opcode on the actual channel. The local tail stays zero. */
    for (size_t index = 0; index < 176; ++index) {
        common[index] = packet[index];
    }
    common[4] = 'N';
    common[5] = 'D';
    const uint64_t original = read_u64(packet + 176);
    return nia_handoff_wire_valid(common, sizeof(common), deadline)
        && (original > 0) && (original <= INT64_MAX)
        && (read_u64(packet + 184) != 0) && (read_u64(packet + 192) != 0);
}
