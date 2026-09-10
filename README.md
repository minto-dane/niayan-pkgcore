# Nia OS pkgcore

Catalog and file change planning, bounded package semantics, execution and recovery support for Nia OS. The active product consumes DEB inputs; inherited RPM metadata support does not define the active distribution.

Independent Ada/SPARK repository with a small C codec boundary, MIT licensed. Native compilation, application linking and registered Ada tests now run in Debian 13 amd64. Strict SPARK flow has passed. Full formal proof and production integration remain incomplete; native success does not grant production qualification.

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
