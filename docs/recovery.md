> Edition note: this document describes inherited v2 components. For the current resilience extension, implementation limits and evidence, start with `assurance/docs/resilience.ja.md` in the source bundle. Earlier qualification counts do not apply to the new sources.

# Recovery v2

Two journal families exist: legacy pure transaction models/Pkg_Journal for regression testing,
and the new MC_Log + Pkg_File_Engine implementation for real file changes. Do not interchange their schemas.

The new executor retains exact content and canonical extended attributes in CAS, logs intent before effect,
creates a bounded temporary entry in the same target directory, verifies it, reauthorizes and checks the preimage before rename,
and records observed completion after the effect. Files, symlinks and newly created directories are supported; no recursive deletion.

Commit keeps active transaction state until the generation publication and commit receipt are durable. Terminal re-observation works
also after active state was cleared and the client response was lost. Restoration is reverse-ordered and only for uncommitted,
known pre/post images with qualified data-backward-compatible and quiescence witnesses.

Partial final log bytes may be preserved in CAS and truncated under authenticated repair; a separate repair audit is written.
Whole-frame corruption, unknown file state, absent recovery objects, stale policy/boot/fencing identity and invalid transitions stop progress.
Hash chains do not authenticate origin or prevent rollback of an entire old storage snapshot. Preserve independent trust/replay anchors.
CAS has no automatic GC; recovery pin/retention and archival must be qualified before adding collection.

The code provides real effects but has not been compiled, executed or crash-qualified here. Runtime SPARK_Mode=>Off boundaries and
filesystem/flush assumptions are explicit. Full operating-system/RPMDB/service/database atomicity is NOT claimed.
Business data, secrets, revocations and audit history are not part of generic package rollback.
See operations-v2.ja.md and assurance/docs/qualification-gap.md.
