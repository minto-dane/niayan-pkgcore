#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
D=$(mktemp -d "${TMPDIR:-/tmp}/mc-journal.XXXXXXXX")
cleanup() {
    # Only the one known test file, never recursive deletion of a supplied path.
    rm -f -- "$D/journal.mcl"
    rmdir -- "$D"
}
trap cleanup EXIT HUP INT TERM
./build/test-bin/run_journal_io_tests "$D"
