# SPDX-License-Identifier: MIT
# Run as an unprivileged user in an isolated build workspace. No install target.
SHELL := /bin/sh
GPRBUILD ?= gprbuild
GNATPROVE ?= gnatprove
.PHONY: compile-all all build check-tools check-contract test test-build flow prove evidence qualification
all: build
check-tools:
	@command -v $(GPRBUILD) >/dev/null || { echo 'gprbuild is required; NOT QUALIFIED' >&2; exit 78; }
check-contract:
	./ci/check-contract.sh
	python3 ci/check-resolver.py
build: check-tools check-contract
	$(GPRBUILD) -p -P pkgcore.gpr
test-build: check-tools check-contract
	$(GPRBUILD) -p -P tests.gpr
test: test-build
	./build/test-bin/run_deb_semantics_tests
	./build/test-bin/run_pkg_resolution_tests
	./build/test-bin/run_enterprise_pkg_tests
	./build/test-bin/run_file_replay_tests
	./build/test-bin/run_composition_tests
	./build/test-bin/run_pkg_tests
	./build/test-bin/run_rpm_tests
	./ci/journal-test.sh
	./build/test-bin/run_v2_pkg_tests
	./ci/file-engine-test.sh
	./build/test-bin/run_repair_tests
	./build/test-bin/run_retention_batch_tests
flow: check-contract
	@command -v $(GNATPROVE) >/dev/null || { echo 'GNATprove missing; proof NOT RUN' >&2; exit 78; }
	mkdir -p build/proof-obj
	$(GNATPROVE) -P proof.gpr -U --mode=flow --checks-as-errors=on --warnings=error
prove: check-contract
	@command -v $(GNATPROVE) >/dev/null || { echo 'GNATprove missing; proof NOT RUN' >&2; exit 78; }
	mkdir -p build/proof-obj
	$(GNATPROVE) -P proof.gpr -U --mode=all --level=4 --checks-as-errors=on --warnings=error --proof-warnings=on --report=statistics
evidence:
	./ci/verify.sh
qualification:
	@echo 'BLOCKED: production installation, adapters, proofs and qualification are incomplete.' >&2
	@exit 78

# Compile every source, including SDK adapters not linked by a CLI main.
compile-all: check-tools check-contract
	$(GPRBUILD) -p -c -u -P pkgcore.gpr

.PHONY: engineering-check
# Optional bundle-level integration check; the ordinary independent build is unchanged.
engineering-check:
	@test -f ../assurance/ci/engineering.py || { echo 'Seven sibling repositories required for this integration check' >&2; exit 78; }
	python3 ../assurance/ci/engineering.py check
