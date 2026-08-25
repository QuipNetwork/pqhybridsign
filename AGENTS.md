# Agent Instructions

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
