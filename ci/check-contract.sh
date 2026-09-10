#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause
# Local source drift check, NOT an authenticated release/provenance check.
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BASE=vendor/contracts
test -d "$BASE" && test -d "$BASE/src" && test -d "$BASE/runtime" && test -f "$BASE/contracts.source.sha256" || exit 78
test ! -L "$BASE" && test ! -L "$BASE/src" && test ! -L "$BASE/runtime" && test ! -L "$BASE/contracts.source.sha256" || exit 78
cd "$BASE"
D=$(mktemp -d "${TMPDIR:-/tmp}/mc-source-check.XXXXXXXX")
cleanup() { rm -f -- "$D/expected" "$D/sorted" "$D/actual" "$D/links" "$D/special"; rmdir -- "$D"; }
trap cleanup EXIT HUP INT TERM
# No whitespace names, absolute paths, parent components, duplicates or unknown extensions.
awk 'NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || $2 !~ /^(src|runtime)\/[a-z0-9_]+\.(ads|adb)$/ { bad=1 } {print $2} END {if (NR==0 || bad) exit 1}' contracts.source.sha256 > "$D/expected"
LC_ALL=C sort -u "$D/expected" > "$D/sorted"
cmp "$D/expected" "$D/sorted"
find src runtime -type l -print > "$D/links"
test ! -s "$D/links" || { echo 'Shared source symlink refused' >&2; exit 78; }
# Reject special files BEFORE hashing: hashing a FIFO could block indefinitely.
find src runtime ! -type d ! -type f -print > "$D/special"
test ! -s "$D/special" || { echo 'Shared source special file refused' >&2; exit 78; }
# Reject unlisted regular files as well as extra Ada units.
find src runtime ! -type d -print | LC_ALL=C sort > "$D/actual"
cmp "$D/expected" "$D/actual"
sha256sum --check --strict contracts.source.sha256
