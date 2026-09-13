# Nia OS pkgcore

Catalog and file change planning, bounded package semantics, execution and recovery support for Nia OS. The active product consumes DEB inputs; inherited RPM metadata support does not define the active distribution.

Independent Ada/SPARK repository with a small C codec boundary, BSD-3-Clause licensed. Native compilation, application linking and registered Ada tests now run in Debian 13 amd64. Strict SPARK flow has passed. Full formal proof and production integration remain incomplete; native success does not grant production qualification.

```sh
make compile-all build test
python3 ci/install-gnatprove.py
# Add the printed directory to PATH, then:
make flow prove
```

The build needs GNAT/GPRbuild, make, Python 3, libsodium, libarchive, zlib, liblzma, libzstd, libcurl, libxml2 and libsystemd development packages. Python reference tooling also uses python3-cryptography; dedicated bus tests use dbus. The pinned GitHub CI container installs these dependencies with `ci/setup-container.sh`; that script replaces apt sources and is intended only for its disposable CI container.

`make test` runs every Ada main registered for this component in the central test plan, including isolated I/O and read-only host observation. Tests run unprivileged with fresh private directories. `make compile-all` also checks SDK units not linked by an application main. `make flow prove` treats warnings and unproved obligations as failures.

Read [component integration](docs/system-composition.ja.md) and [packaging](packaging/README.ja.md). For the complete eight-repository source set, current verification evidence and fixed development environment, use the Nia OS integration workspace. Each repository builds independently; workspace tools verify the combined source profiles and generated snapshots.

The internal generation SDK assembles bounded inactive stages and binds a verified stage and catalog in one accepted descriptor. Publication retains both stage reservations and requires the full managed guard. `generation.next` is unpublished workspace; readers use the accepted plan in root.state. These APIs refuse UID 0 and do not activate a mount, boot image or installed package manager. Tests use disposable synthetic generations and test-only authorities.

Missing pins or guards fail closed. The build does not install services, enroll keys or enable live workers. Documented site integration, independent review and qualification gaps must be closed before production use. Imported edition notes remain in the initial Git commit and their historical evidence directories.

The archive supply SDK verifies a scoped observer signature against independent site policy, checks every referenced CAS object and reobserves the original DEB's control. It supplies a per-original binding, not publication authority. The integration workspace tests real archive authentication through this reader; production key provisioning, whole-plan coverage and generation retention remain required.

The supply map SDK binds a predecessor and candidate catalog to exactly the newly required original DEBs. It independently reobserves both catalogs and all retained inputs, verifies the scoped receipts, and separates fresh verification from historical retention. The v4 publisher binds its retained policy through the authenticated plan, revalidates inputs under the engine reservation, and permits historical receipt checks only after auditing an actual active or accepted transaction. Independent current trust policy remains mandatory during recovery; production providers and full DEB root effects remain incomplete.

The internal `pkg_store_bootstrap` installer executable calls the canonical `MC_Store.Initialize` only for an explicitly requested empty private store. Its `check` operation opens existing structure under the actual reservation; it neither repairs missing state nor verifies object contents. Both operations refuse UID 0. The component artifact installs it only under `/usr/libexec/nia/`; normal startup never calls initialization. Run `make bootstrap-check` to verify refusal and reservation boundaries with temporary state.

The independent site supply provider reads root-owned `supply.bin` and a separately protected `supply.floor`, rechecks their exact binding and samples current UTC on each publisher callback. It does not acquire the CAS reservation or grant execution. The internal `pkg_supply_observe` deployment probe is read-only. Site policy, rollback-resistant floor storage, a correct clock and the other managed authorization providers remain required; no production key or permissive default is shipped.

Configured v6 publication verifies the current independently reserved configuration source during stage inspection and again under the publication engine's CAS reservation. In-flight admission cannot waive that check. Only an exact already-accepted state and journal may use the distinct retained-stage evidence type for terminal metadata reconciliation; physical stage bytes, pins, receipts and current managed authorization remain mandatory. This selects a retained archive and does not qualify an extracted filesystem or boot switch. `tests/check_configured_publication.py` exercises the real conffile fixture, source changes, fresh-process recovery and missing retained evidence.

The private `pkg_supply_guard` retains a site supply session for ordered bounded
observations during root supervision. It checks the planner's exact policy/floor
hashes and UTC high water mark without reacquiring the store reservation. It
does not authorize the bound generation or replace managed publisher checks.
This integration is uncompiled and untested pending pre-release validation.

`Pkg_Generation_Reader` now owns consistent accepted-state reads without
instantiating a write-authority engine; publisher reads use the same code.
`Pkg_Update_Planner` prepares native transition intent and authenticated supply
against that actual predecessor under publication/root/store reservations.
`pkg_catalog_query` provides a bounded private catalog response for adopted
listing commands. These changes remain uncompiled and unqualified; a query or
prepared intent is not managed execution or boot authority.
