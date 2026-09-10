# SPDX-License-Identifier: BSD-3-Clause
# Run as an unprivileged user in an isolated build workspace. No install target.
SHELL := /bin/sh
GPRBUILD ?= gprbuild
GNATPROVE ?= gnatprove
JOBS ?= 1
.PHONY: compile-all all build check-tools check-contract test test-build bootstrap-check flow prove evidence qualification
all: build
check-tools:
	@command -v $(GPRBUILD) >/dev/null || { echo 'gprbuild is required; NOT QUALIFIED' >&2; exit 78; }
check-contract:
	./ci/check-contract.sh
	python3 ci/check-resolver.py
build: check-tools check-contract
	$(GPRBUILD) -s -j$(JOBS) -p -P pkgcore.gpr
test-build: check-tools check-contract
	$(GPRBUILD) -s -j$(JOBS) -p -P tests.gpr
test: test-build
	./ci/test-all.sh
bootstrap-check: check-tools check-contract
	$(GPRBUILD) -s -j$(JOBS) -p -P pkgcore.gpr pkg_store_bootstrap.adb
	python3 tests/check_store_bootstrap.py --driver build/bin/pkg_store_bootstrap
# Shared bounded proof runner, copied into each independent repository.
include ci/proof.mk
evidence:
	./ci/verify.sh
qualification:
	@echo 'BLOCKED: production installation, adapters, proofs and qualification are incomplete.' >&2
	@exit 78

# Compile every source, including SDK adapters not linked by a CLI main.
compile-all: check-tools check-contract
	$(GPRBUILD) -s -j$(JOBS) -p -c -u -P pkgcore.gpr

.PHONY: engineering-check
# Optional bundle-level integration check; the ordinary independent build is unchanged.
engineering-check:
	@test -f ../assurance/ci/engineering.py || { echo 'Seven sibling repositories required for this integration check' >&2; exit 78; }
	python3 ../assurance/ci/engineering.py check
