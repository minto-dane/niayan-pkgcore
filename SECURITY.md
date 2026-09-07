# Security boundary and reporting

This source set is not a production certification. Report issues with version/source hash, affected trust boundary,
minimal isolated reproduction, expected vs actual status, and redacted evidence. Never include private signing keys,
real production credentials, full memory dumps or customer data in an issue.

Use least privilege, protected local policy, independent keys for request/reservation/health/isolation,
valid TLS, current signed binaries, explicit owner/HA authority, and isolated qualification environments.
Unknown state must be inspected, not normalized by deleting ledgers/CAS pins or disabling signature/MAC/fencing checks.

The package file engine cannot protect against unrestricted root or same-owner writes bypassing it.
Native libraries and commands are part of the TCB. Signed witnesses authenticate claims, not physical truth.
A health signer must not be co-resident with an untrusted workload or receive its answer as an unchecked Boolean.

See assurance/docs/qualification-gap.md and proof-boundary.md in the source set.

## Recovery engineering edition

The current security/failure boundary is documented in
`assurance/docs/engineering/specs/security.ja.md` and `failure-model.ja.md`
of the integration bundle. No all-failure recovery, malicious-root tolerance,
OS-wide serializability or completed formal proof is asserted. Report reproduction
against the exact source subject and do not attach production secrets.
