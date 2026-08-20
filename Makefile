# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Local rehearsal of every publish path. `make check-release` runs the same
# steps release:validate runs in CI, so a broken release setup fails on a
# workstation instead of halfway through a tag pipeline with some registries
# written and others not.
#
# TAG names the C library tarball. CI passes the release tag on tag
# pipelines and the short SHA otherwise; locally any label works.
TAG ?= dev

.PHONY: check-release
check-release: check-crate-publish check-python-dist check-npm-dist check-clib

# `cargo package`, not `cargo publish --dry-run`. Both verify the same way,
# and both leave the .crate tarballs the smoke jobs unpack and build against.
# `package` is preferred because it stays entirely local: it never enters the
# upload path, so this gate cannot fail on registry state. The release job
# runs the real publish.
#
# The stale tarballs are deleted first. Cargo leaves an existing .crate in
# place when it does not write one, so a leftover from an earlier version
# silently becomes the thing the smoke tests validate.
#
# --locked so packaging resolves the committed Cargo.lock. Without it a
# drifted lock file passes here and fails in the real publish.
#
# The three publishable crates are named explicitly. The four non-published
# crates carry publish = false: the abi runtime-dispatch layer, which no
# published crate needs, and the three foreign-ABI bindings. `cargo publish
# --workspace` skips those on its own, but `cargo package` does not, and
# each would fail on a missing Python or JavaScript toolchain long before the
# packaging question even came up.
.PHONY: check-crate-publish
check-crate-publish:
	rm -f target/package/*.crate
	cargo package --locked \
		-p pqhybridsign-core \
		-p pqhybridsign \
		-p pqhybridsign-shrincs

# Wheel and sdist into dist/python/, then the two guards. twine check
# validates the metadata is well formed; check-sdist-license-files.sh
# verifies the sdist actually contains every license file that metadata
# names, which twine cannot see (quip-solver-core shipped an sdist that
# passed twine and was rejected by PyPI with a bare 400 for exactly this).
#
# The venv lives under target/ so it is never committed and a `cargo clean`
# removes it. maturin needs the explicit -m path: unlike quip-solver-core,
# this repository's pyproject.toml is not at the root.
.PHONY: check-python-dist
check-python-dist:
	rm -rf dist/python
	mkdir -p dist/python
	python3 -m venv target/python-dist-venv
	target/python-dist-venv/bin/pip install --quiet --upgrade pip maturin twine
	target/python-dist-venv/bin/maturin build --release \
		-m crates/pqhybridsign-py/Cargo.toml -o dist/python
	target/python-dist-venv/bin/maturin sdist \
		-m crates/pqhybridsign-py/Cargo.toml -o dist/python
	target/python-dist-venv/bin/twine check dist/python/*
	bash scripts/check-sdist-license-files.sh dist/python/*.tar.gz

# Builds both wasm targets and the TypeScript wrapper, runs the Promise-API
# test suite, and packs the publishable tarball. Old tarballs are deleted
# first so the glob in release:npm can never publish a stale one.
.PHONY: check-npm-dist
check-npm-dist:
	bash crates/pqhybridsign-wasm/scripts/build-npm.sh
	cd crates/pqhybridsign-wasm/npm && npm test
	rm -f crates/pqhybridsign-wasm/npm/*.tgz
	cd crates/pqhybridsign-wasm/npm && npm pack
	@set -e; count=$$(ls crates/pqhybridsign-wasm/npm/*.tgz | wc -l); \
	if [ "$$count" -ne 1 ]; then \
		echo "expected exactly one packed tarball, found $$count" >&2; \
		exit 1; \
	fi

# The C library tarball plus its checksum, named by TAG.
.PHONY: check-clib
check-clib:
	bash scripts/build-clib.sh "$(TAG)"
