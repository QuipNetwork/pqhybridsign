# Agent Instructions

## Build and Test

The toolchain comes from `rust-toolchain.toml`. The minimum supported Rust
version is the `rust-version` field in the workspace `Cargo.toml`.

```bash
cargo fmt --all -- --check                                    # format
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked -p pqhybridsign --all-targets --features vrf -- -D warnings
cargo test --locked --workspace                               # 512 tests
cargo test --locked -p pqhybridsign --features vrf
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps
```

Run the two clippy commands, not one. The reason is in Feature Flags below.

The npm package builds and tests from its own directory:

```bash
cd crates/pqhybridsign-wasm/npm && npm run build && npm test
```

Before a release, `make check-release` packages every artifact and compiles
each one from the packaged form. `make check-crate-publish` is the part that a
version change can fail. It needs a clean working tree, because `cargo package`
builds the tarball from what git holds and refuses to package uncommitted
edits.

## Repository Layout

| Crate | Purpose | Published |
|---|---|---|
| `pqhybridsign` | The library: suites, composition, encoding | crates.io |
| `pqhybridsign-abi` | Byte-buffer API the bindings share | crates.io |
| `pqhybridsign-cffi` | C library and header | archive |
| `pqhybridsign-py` | Python extension | PyPI |
| `pqhybridsign-wasm` | WebAssembly and the npm package | npm |
| `pqhybridsign-test-support` | Test doubles shared by the tests | no |

The path dependencies between these crates carry a version alongside the path.
A local build resolves through the path and never reads that version, so a
stale pin builds green here and fails on crates.io. A version change must reach
every pin.

## Feature Flags

The four SHRINCS profiles, `profile-256s`, `profile-256s-sha2`,
`profile-128s-q18` and `profile-128s-q20`, are mutually exclusive. The
`hashsigs-rs` build script fails when more than one is on.

`--all-features` does not work in this workspace. Any command that needs the
`vrf` feature must name it in a second invocation, and that is why the clippy
gate runs twice.

The `128s` profiles are slow. Importing a stateful key at those profiles
re-derives the hypertree root, which costs about 47 seconds. Use
`StatefulKeyHandle` and its binding equivalents to pay that once per key
instead of once per signature.

## Testing Notes

The `pqhybridsign-abi` crate has no profile feature, so its stateful VRF tests
cannot be gated by `cfg`. They carry `#[ignore]` to keep a `128s` build of
`cargo test --workspace` inside the time budget, and CI runs them separately
under the default profile.

Tests that need a `StatelessBudgetStore` use
`pqhybridsign_test_support::MemoryBudget`. Two unit tests inside the
`pqhybridsign` library keep a local copy instead. A test double from a crate
that depends on `pqhybridsign` cannot serve a unit test inside `pqhybridsign`,
because cargo compiles the library a second time for the `--test` target and
the two trait definitions are then distinct types. Both sites say so in a
comment.

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Dependency Management

Never use a crates.io dependency less than seven days old. An attacker who hijacks a crate does the most damage in the hours after publishing the malicious version, before anyone reports it. The cooldown refuses that window.

Do not run a bare `cargo update`. It selects the newest version of every crate, regardless of publication date, which is how a fresh malicious release enters the tree. Update one crate at a time with `cargo update -p <crate> --precise <version>`, and only to a version at least seven days old.

Never treat a yanked-crate advisory as a reason to update. Yanking the prior good versions is how this attack forces a `cargo update` onto the malicious replacement. A yanked version already in `Cargo.lock` keeps working, because yanking blocks new selection only. Clear the advisory with a documented exception in `deny.toml`, not with an update.

A script enforces the rule. `scripts/check-dependency-cooldown.py` reads `Cargo.lock` and asks crates.io for each locked version's publication date. It fails on any version younger than seven days. The `cooldown` CI job runs it over the whole lockfile, and `release:validate` waits for that job, so no release can ship a fresh dependency. A pre-commit hook runs the same check against a staged `Cargo.lock`.

`scripts/cooldown-allowlist.toml` holds the reviewed exemptions. The only correct entry is a first-party crate this project controls, or a version a human has read and vetted. Each entry names an exact version and a reason. Remove it once the version ages past the cooldown.

This policy exists because of a real incident. An attacker published a malicious `arrayref 0.3.10` and yanked its prior versions in the same minutes. A reactive `cargo update` pulled it, and its build script ran a credential stealer. The malicious version was six minutes old.

## Releases

Every release job in `.gitlab-ci.yml` runs only when `$CI_COMMIT_TAG` matches
`/^v\d/`. Branch pipelines and merge-request pipelines never publish.

Pushing a `v*` tag publishes to npm, PyPI, the C library archive and
crates.io, in that order. **A crates.io version can never be replaced or
deleted.** Confirm with a human before pushing a release tag.

`scripts/check-release-version.py <tag>` asserts that the tag matches the
workspace `Cargo.toml`, the npm `package.json`, and that `pyproject.toml` still
declares `dynamic = ["version"]`. Run it before tagging. The Python wheel name
uses the PEP 440 spelling, so `v0.0.0-rc7` produces `0.0.0rc7`, and the two
never match byte for byte.

Tag the merge commit on `main`, not the branch head, and use an annotated tag
whose message is the bare version. That is what the existing `v0.0.0-rc*` tags
carry.
