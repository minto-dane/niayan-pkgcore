# SPDX-License-Identifier: BSD-3-Clause
# SUSE/RPM integration source; rpmbuild and the resulting RPM are NOT qualified.
# Installation neither takes over native RPMDB nor provisions trust or starts services.
Name: mission-pkgcore
Version: 0.1.0
Release: 0.20260906.unified%{?dist}
Summary: Mission Core pkgcore independent tools and integration interfaces
License: MIT
Source0: %{name}-%{version}.tar.gz
ExclusiveArch: x86_64
%if 0%{?suse_version}
BuildRequires: gcc-ada
%else
BuildRequires: gcc-gnat
%endif
BuildRequires: gprbuild
BuildRequires: make
BuildRequires: libsodium-devel
BuildRequires: libarchive-devel
BuildRequires: libcurl-devel
BuildRequires: libxml2-devel
BuildRequires: systemd-devel

%description
Independent Mission Core pkgcore tools. Source-level contracts and qualification
interfaces are included in the project; this build is not a production qualification.
No automatic host ownership migration, network change, key enrollment or activation.

%prep
%autosetup -n %{name}-%{version}

%build
make compile-all
make build

%check
make test

%install
install -d -m0755 %{buildroot}%{_libexecdir}/mission-core/pkgcore
install -p -m0755 build/bin/pkgctl %{buildroot}%{_libexecdir}/mission-core/pkgcore/pkgctl
install -p -m0755 build/bin/pkg_worker %{buildroot}%{_libexecdir}/mission-core/pkgcore/pkg_worker
install -p -m0755 build/bin/pkg_scrubctl %{buildroot}%{_libexecdir}/mission-core/pkgcore/pkg_scrubctl
install -p -m0755 build/bin/pkg_recoveryctl %{buildroot}%{_libexecdir}/mission-core/pkgcore/pkg_recoveryctl

%files
%license LICENSE
%doc README.md SECURITY.md docs/
%{_libexecdir}/mission-core/pkgcore/

# Deliberately no %post, %preun, service presets, daemon reload or state removal.
# Opt-in unit activation must follow site review of identities, LSM policy and paths.
