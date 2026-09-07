> **Nia OS product overlay**: 現行製品は [Nia構成](../distribution/docs/architecture.ja.md) と [所有権](../distribution/docs/ownership-and-effects.ja.md) を参照。以下は部品契約・継承SDKの説明です。旧RPM/SUSE製品前提はactive profileではありません。安全条件は維持し、未接続は完成扱いしません。

> Current edition: unified-management-2026-09-06. Four independent repositories; [current capabilities](../assurance/docs/engineering/specs/capability-matrix.ja.md) and [migration](../assurance/docs/engineering/specs/release-migration.ja.md) supersede inherited integration/initialization instructions below. Historical PASS counts do not qualify these sources.

> Current edition: **distro-foundation (2026-09-06)**. See packaging/README.ja.md and
> docs/system-composition.ja.md.
> Not a bootable distribution or a production-qualified build. Ada/GNATprove are NOT run here.

# Coordination-integrity edition

Current source release: `coordination-integrity-source-2026-09-06`. See the distribution-level `README.ja.md` and `assurance/docs/coordination-integrity.ja.md`.
The shared source profile and State_Etcd connection contract have changed. Missing pins/guards fail closed; the new package quiescence wrapper is opt-in, not automatically enabled for every worker.
Ada compilation/tests and GNATprove have not run. Native integration and site qualification remain necessary.

---

## 以前の版の説明（変更点は上記を優先）

> Current edition: assured-operations-source-2026-09-06. See the bundle's `README.ja.md` and `assurance/docs/assured-operations.ja.md`. New mandatory control authorities/state and source profile are required; missing state blocks dispatch. Ada/GNATprove have NOT been run. The text below retains earlier component details.

> Current edition: resilience-source-2026-09-06. Read the bundle's STATUS.ja.md and assurance/docs/resilience.ja.md for implemented paths, NOT-RUN tests and remaining site integration. Earlier counts refer to previous sources.

# pkgcore — expanded source v2

Independent Ada/SPARK source repository. MIT license. Wire contract 2.0 (v1 rejected).

Start with the archive-level README.ja.md and this repository's docs.

```sh
make check-contract
make compile-all
make build test
make flow prove
```

Ada compilation/tests/GNATprove were not run for this expanded source in the authoring environment.
Real effect workers are present; production qualification is not established.
Do not install into a production cluster until the documented compatibility and qualification gaps are addressed.

The vendor snapshot must remain pinned and audited across independent releases.
No install target, dependency download, native package installation or automatic service enable is performed by Make.
