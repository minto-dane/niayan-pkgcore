# Development and review entry point

This repository remains independently buildable. Cross-repository integration review
requires the three exact sibling source sets. No production approval is implied by CI.

Canonical handbook: `assurance/docs/engineering/README.ja.md` in the integration bundle.
ADR / requirements / hazards / fault cases / test-main registry / owner roles live in
`assurance/engineering/` and `assurance/docs/engineering/`.

A change to persistence, authorization, protocol semantics, restart ownership, fencing
or recovery is not a cosmetic edit. Update the requirement, ADR, specification, negative
and interruption tests, source inventory and migration review together.
Run the registered tests, not only the Makefile's usual unit subset. Missing tools mean
NOT_RUN, never PASS. Independent reviewer and site evidence are required for release.

Never include real credentials, host logs containing secrets, or temporary IO test keys
in a source archive. Do not run build/tests under root on an operational machine.

