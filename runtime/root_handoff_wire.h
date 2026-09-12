/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef NIA_ROOT_HANDOFF_WIRE_H
#define NIA_ROOT_HANDOFF_WIRE_H
#include <stddef.h>
#include <stdint.h>

/* The caller provides at least length readable bytes, or a null pointer.
 * No OS, allocation, cryptography, ownership or authorization is modeled here.
 * Acceptance is exactly the canonical 192-byte preparation scope, bound to
 * the supplied finite positive deadline. It is not an execution permit. */
int nia_handoff_wire_valid(const uint8_t *packet, size_t length, uint64_t deadline);
#endif
