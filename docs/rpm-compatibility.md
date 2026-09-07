> Edition note: this document describes inherited v2 components. For the current resilience extension, implementation limits and evidence, start with `assurance/docs/resilience.ja.md` in the source bundle. Earlier qualification counts do not apply to the new sources.

# RPM compatibility profile v2

Classic RPM lead/header parsing is extended by typed tag access, EVR comparison, bounded rich dependency expression evaluation,
file-map decoding, strict native rpmkeys authentication and bounded libarchive payload ingestion into CAS.
Payload entries are compared against authenticated RPM metadata for canonical path, type, mode, size and supported SHA-256 content.
Ghost entries are not materialized, unknown/duplicate archive paths and sparse/hard/special file constructs are rejected.

This is not complete RPM compatibility. Full SAT solving/transaction ordering, native RPMDB migration/write ownership, multilib/file colors,
all alternatives/config/noreplace semantics and arbitrary scriptlet/trigger execution are NOT implemented.
Header parsing/known hook flags are not enough to prove there are no additional installation effects.
All host effects must be expressed by a reviewed exact package/effect contract and a file plan within the supported profile.
A root-admin signature on an arbitrary file plan is administrative authorization, not a proof that it faithfully installs an RPM.

Source-package RPMs and unsupported digest/format semantics are denied. Archive filtering does not silently invoke an external decompressor.
Native parsers/crypto/TLS/rpmkeys are TCB dependencies and must be version-pinned, audited and isolated during staging.
Local source grant files authenticate approved artifacts; they do not implement a complete TUF repository or generate upstream build attestations.

A qualified compatibility corpus still needs real distribution RPMs, native librpm differential tests, malformed inputs,
file ownership conflicts, configuration migrations, SELinux labels/capabilities and all supported scripts/triggers.
Synthetic unsigned fixtures in tests are never installable distribution packages and must never be rpm-installed.
