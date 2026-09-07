#!/bin/sh
# SPDX-License-Identifier: MIT
# No credentials, network, host mutation or privilege escalation are needed.
set -eu
umask 077
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
command -v gprbuild >/dev/null || { echo 'gprbuild missing: NOT RUN' >&2; exit 78; }
command -v gnatprove >/dev/null || { echo 'GNATprove missing: NOT RUN' >&2; exit 78; }
# Exclusive directory: an old successful report cannot be confused with this run.
OUT=$(mktemp -d "${TMPDIR:-/tmp}/mc-evidence.XXXXXXXX")
printf '%s
' "$OUT" > evidence/latest-run-path.txt
record() {
    label=$1
    shift
    if "$@" > "$OUT/$label.log" 2>&1; then
        printf '%s
' "$label=PASS" >> "$OUT/results.txt"
    else
        code=$?
        printf '%s
' "$label=FAIL exit=$code" >> "$OUT/results.txt"
        cat "$OUT/$label.log" >&2
        printf 'Evidence retained at %s
' "$OUT" >&2
        exit "$code"
    fi
}
record compiler-version gprbuild --version
record prover-version gnatprove --version
record compile-all make compile-all
record build make build
record tests make test
record flow make flow
record proof make prove
printf '%s
' 'SOURCE CHECKS COMPLETED; PRODUCTION QUALIFICATION REMAINS BLOCKED' >> "$OUT/results.txt"
printf 'Evidence retained at %s
' "$OUT"
