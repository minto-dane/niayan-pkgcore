#!/bin/sh
# SPDX-License-Identifier: MIT
# Only test-created paths. No installation, root filesystem, services or network.
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
D=$(mktemp -d "${TMPDIR:-/tmp}/mc-file-engine.XXXXXXXX")
# Intentionally retain the test tree for forensic comparison even on success.
printf 'Isolated test tree: %s\n' "$D"
mkdir "$D/root" "$D/root/usr" "$D/state" "$D/store"
./build/test-bin/run_file_engine_tests "$D/root" "$D/state" "$D/store"
printf 'No tree was automatically removed. Inspect this private test directory: %s\n' "$D"
