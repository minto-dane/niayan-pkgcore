#!/bin/sh
# SPDX-License-Identifier: MIT
# Generated component CI dependency setup; use only in the pinned CI container.
set -eu
[ "$(id -u)" -eq 0 ] || exit 78
rm -f /etc/apt/sources.list.d/debian.sources
cat > /etc/apt/sources.list <<'SOURCES'
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260907T000000Z trixie main
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260907T000000Z trixie-updates main
deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260907T000000Z trixie-security main
SOURCES
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl dbus dpkg gcc git gettext gnat gpg gpg-agent gpgconf gpgv gprbuild libarchive-dev libc6-dev libcurl4-openssl-dev libsodium-dev libsystemd-dev libxml2-dev make pkg-config python3 python3-cryptography python3-tuf ripgrep xz-utils zstd
