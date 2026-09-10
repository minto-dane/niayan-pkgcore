#!/bin/sh
# SPDX-License-Identifier: MIT
# Valid synthetic manifests, only in a disposable container and private dirs.
set -eu
[ "$(id -u)" -eq 0 ] || exit 78
[ -f /.dockerenv ] || [ -f /run/.containerenv ] || exit 78
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
test -x build/test-bin/run_generation_stage_tests
test -x build/test-bin/run_generation_publication_tests
test -x build/test-bin/run_deb_payload_tests
test -x build/test-bin/run_payload_index_tests
test -x build/test-bin/run_selected_catalog_tests
test -x build/test-bin/run_deb_final_set_tests
test -x build/test-bin/run_deb_transition_tests
test -x build/test-bin/run_catalog_store_tests
test -x build/test-bin/run_archive_supply_tests
umask 077
nia_stage_test_dir=$(mktemp -d /tmp/nia-stage-root-test.XXXXXXXX)
trap 'rm -rf -- "$nia_stage_test_dir"' EXIT HUP INT TERM
mkdir "$nia_stage_test_dir/root" "$nia_stage_test_dir/state" "$nia_stage_test_dir/store"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_generation_stage_tests" \
  "$nia_stage_test_dir/root" "$nia_stage_test_dir/state" "$nia_stage_test_dir/store"
mkdir "$nia_stage_test_dir/pub-root" "$nia_stage_test_dir/pub-state" \
  "$nia_stage_test_dir/pub-store" "$nia_stage_test_dir/bank"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_generation_publication_tests" \
  "$nia_stage_test_dir/pub-root" "$nia_stage_test_dir/pub-state" \
  "$nia_stage_test_dir/pub-store" "$nia_stage_test_dir/bank"

timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_deb_payload_tests" "$nia_stage_test_dir/store" "$PWD/tests/fixtures/deb-payload"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_payload_index_tests" "$nia_stage_test_dir/store" \
  "$PWD/tests/fixtures/deb-payload" "$PWD/tests/fixtures/payload-index"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_selected_catalog_tests" "$nia_stage_test_dir/store" \
  "$PWD/tests/fixtures/selected-catalog"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_deb_final_set_tests" "$nia_stage_test_dir/store" \
  "$PWD/tests/fixtures/deb-final-set"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_deb_transition_tests" "$nia_stage_test_dir/store" \
  "$PWD/tests/fixtures/deb-transition"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_catalog_store_tests" "$nia_stage_test_dir/store" \
  "$PWD/tests/fixtures/selected-catalog"
timeout --kill-after=5s 600s env -i PATH=/usr/bin:/bin HOME="$nia_stage_test_dir" \
  TMPDIR="$nia_stage_test_dir" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
  "$PWD/build/test-bin/run_archive_supply_tests" "$nia_stage_test_dir/store" \
  "$PWD/tests/fixtures/selected-catalog"
