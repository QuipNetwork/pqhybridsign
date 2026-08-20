#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail if any locked crates.io dependency was published too recently.

A supply-chain attack on a crate is loudest in the hours after it is
published: the malicious version is live, and the attacker often yanks the
prior good versions to force a `cargo update` onto the new one. A cooldown
turns that window into a wall. This script reads Cargo.lock, finds when each
locked version was published, and fails when any version is younger than the
cooldown. It reads the publish time from the local Cargo sparse-index cache
(Cargo 1.94 and later record it there), and falls back to the crates.io API
for any version the cache does not hold.

The attack this guards against, in full, is recorded in the incident notes:
`arrayref 0.3.9` was yanked and a malicious `arrayref 0.3.10` published in
the same minutes; a reactive `cargo update` pulled it, and its build script
ran a credential stealer. `0.3.10` was six minutes old. A seven-day
cooldown would have refused it.

Only crates.io dependencies are checked. Path and git dependencies have no
crates.io publication date and are skipped, which also skips this
workspace's own member crates.

An allowlist (scripts/cooldown-allowlist.toml) exempts specific
name-and-version pairs. Its only correct use is a first-party crate this
project controls, or a version a human has explicitly vetted. Each entry
carries a reason, the same way deny.toml carries its exceptions.

Usage:

    python3 scripts/check-dependency-cooldown.py               # full scan
    python3 scripts/check-dependency-cooldown.py --changed-only # vs git HEAD
    python3 scripts/check-dependency-cooldown.py --max-age-days 7

Exit codes: 0 all clear, 1 a version is too new, 2 usage error, 3 a version
could not be verified (network or API failure; fail closed).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
USER_AGENT = (
    "pqhybridsign-cooldown-check "
    "(https://gitlab.com/quip.network/pqhybridsign)"
)
API = "https://crates.io/api/v1/crates/{name}"
# crates.io asks crawlers for a descriptive User-Agent and modest request
# rates. Four workers over ~170 crates stays well inside that.
WORKERS = 4
RETRIES = 4


def crates_io_packages(lock_text: str) -> set[tuple[str, str]]:
    """Return the (name, version) pairs sourced from crates.io."""
    lock = tomllib.loads(lock_text)
    return {
        (pkg["name"], pkg["version"])
        for pkg in lock.get("package", [])
        if pkg.get("source") == CRATES_IO_SOURCE
    }


def load_allowlist(root: Path) -> dict[tuple[str, str], str]:
    """Return {(name, version): reason} for the reviewed exemptions."""
    path = root / "scripts" / "cooldown-allowlist.toml"
    if not path.exists():
        return {}
    data = tomllib.loads(path.read_text())
    out: dict[tuple[str, str], str] = {}
    for entry in data.get("allow", []):
        out[(entry["name"], entry["version"])] = entry.get("reason", "")
    return out


def _index_cache_files(name: str) -> list[Path]:
    """Return the sparse-index cache files for a crate, most likely first.

    Cargo 1.94 and later record each version's publish time in the local
    sparse-index cache. The cache shards a name into a path by length: one
    character is `1/<name>`, two is `2/<name>`, three is `3/<c>/<name>`, and
    four or more is `<first two>/<next two>/<name>`.
    """
    lowered = name.lower()
    if len(lowered) == 1:
        shard = Path("1") / lowered
    elif len(lowered) == 2:
        shard = Path("2") / lowered
    elif len(lowered) == 3:
        shard = Path("3") / lowered[0] / lowered
    else:
        shard = Path(lowered[0:2]) / lowered[2:4] / lowered
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    root = cargo_home / "registry" / "index"
    return [
        index / ".cache" / shard
        for index in sorted(root.glob("index.crates.io-*"))
    ]


def published_at_index(name: str, version: str) -> datetime.datetime | None:
    """Return the publish time from the local sparse-index cache, or None.

    None means the answer is not in the cache (the crate or version was never
    fetched, the cache predates Cargo 1.94, or the file could not be parsed).
    The caller then asks crates.io. This path never raises, so a cache miss
    can only fall back, never fail the check.
    """
    for path in _index_cache_files(name):
        if not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        for part in raw.split(b"\x00"):
            part = part.strip()
            if not part.startswith(b"{"):
                continue
            try:
                entry = json.loads(part)
            except json.JSONDecodeError:
                continue
            if entry.get("vers") == version and entry.get("pubtime"):
                stamp = entry["pubtime"].replace("Z", "+00:00")
                try:
                    return datetime.datetime.fromisoformat(stamp)
                except ValueError:
                    return None
    return None


def published_at_api(name: str, version: str) -> datetime.datetime:
    """Return the crates.io publication time of one version, over the API.

    Raises RuntimeError if the version cannot be found after retries, so the
    caller fails closed rather than treating an unknown as safe.
    """
    request = urllib.request.Request(
        API.format(name=name), headers={"User-Agent": USER_AGENT}
    )
    last_error = "unknown"
    for _ in range(RETRIES):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
            for entry in payload.get("versions", []):
                if entry["num"] == version:
                    stamp = entry["created_at"].replace("Z", "+00:00")
                    return datetime.datetime.fromisoformat(stamp)
            raise RuntimeError(
                f"{name} {version} is not listed on crates.io"
            )
        except RuntimeError:
            raise
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
            last_error = str(err)
    raise RuntimeError(
        f"could not reach crates.io for {name} {version}: {last_error}"
    )


def published_at(name: str, version: str) -> datetime.datetime:
    """Return the publish time, from the local index if possible, else the API."""
    from_index = published_at_index(name, version)
    if from_index is not None:
        return from_index
    return published_at_api(name, version)


def check(
    packages: set[tuple[str, str]],
    allow: dict[tuple[str, str], str],
    max_age: datetime.timedelta,
    now: datetime.datetime,
) -> int:
    to_check = sorted(p for p in packages if p not in allow)
    exempt = sorted(p for p in packages if p in allow)

    for name, version in exempt:
        print(f"  allowed   {name} {version}: {allow[(name, version)]}")

    too_new: list[tuple[str, str, datetime.datetime]] = []
    unverifiable: list[tuple[str, str, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {
            pool.submit(published_at, name, version): (name, version)
            for name, version in to_check
        }
        for future in concurrent.futures.as_completed(futures):
            name, version = futures[future]
            try:
                created = future.result()
            except RuntimeError as err:
                unverifiable.append((name, version, str(err)))
                continue
            if now - created < max_age:
                too_new.append((name, version, created))

    for name, version, created in sorted(too_new):
        age = (now - created).total_seconds() / 86400
        print(
            f"  TOO NEW   {name} {version}: published {created:%Y-%m-%d %H:%M} "
            f"UTC, {age:.1f} days old"
        )
    for name, version, err in sorted(unverifiable):
        print(f"  UNVERIFIED {name} {version}: {err}")

    days = max_age.days
    if too_new:
        print(
            f"\n{len(too_new)} dependency(ies) are younger than {days} days. "
            "Wait for the cooldown to pass, pin an older version, or add a "
            "reviewed entry to scripts/cooldown-allowlist.toml.",
            file=sys.stderr,
        )
        return 1
    if unverifiable:
        print(
            f"\n{len(unverifiable)} dependency(ies) could not be verified "
            "against crates.io. Failing closed.",
            file=sys.stderr,
        )
        return 3
    print(
        f"\nAll {len(to_check)} crates.io dependencies are at least {days} "
        f"days old ({len(exempt)} allowlisted)."
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-age-days", type=int, default=7)
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Only check versions not already present in git HEAD's Cargo.lock.",
    )
    parser.add_argument("--lockfile", default="Cargo.lock")
    args = parser.parse_args(argv[1:])

    root = Path(__file__).resolve().parent.parent
    lockfile = root / args.lockfile
    packages = crates_io_packages(lockfile.read_text())

    if args.changed_only:
        try:
            head = subprocess.run(
                ["git", "show", f"HEAD:{args.lockfile}"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            baseline = crates_io_packages(head)
            packages = packages - baseline
        except subprocess.CalledProcessError:
            # No committed Cargo.lock yet: check everything.
            pass
        if not packages:
            print("No new or changed crates.io dependencies since HEAD.")
            return 0

    allow = load_allowlist(root)
    now = datetime.datetime.now(datetime.timezone.utc)
    max_age = datetime.timedelta(days=args.max_age_days)
    return check(packages, allow, max_age, now)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
