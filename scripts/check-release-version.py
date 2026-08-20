#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Assert that a release tag matches the version in every manifest.

The four artifacts are versioned in two files plus one derivation, and
nothing else makes them agree. A tag pushed against a tree whose manifests
still carry the previous version publishes that previous version again:
crates.io rejects the duplicate, but only after npm and PyPI have already
accepted it, and a crates.io version can never be replaced.

Run from the repository root:

    python3 scripts/check-release-version.py v0.0.0-rc1

The tag is compared without its leading `v`.

The Python wheel is deliberately absent from the literal comparisons.
crates/pqhybridsign-py/pyproject.toml declares `dynamic = ["version"]`, so
maturin reads the version out of the crate manifest, which inherits the
workspace version this script already checks. What can silently break that
chain is the `dynamic` declaration itself disappearing, so that is what
this script asserts instead. PEP 440 spells the prerelease without the
hyphen (`0.0.0rc1`), which is why the wheel filename never matches the tag
byte for byte.
"""

import json
import sys
import tomllib
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <tag>", file=sys.stderr)
        return 2

    tag = argv[1]
    version = tag.removeprefix("v")
    root = Path(__file__).resolve().parent.parent

    cargo = tomllib.loads((root / "Cargo.toml").read_text())
    package_json = json.loads(
        (root / "crates/pqhybridsign-wasm/npm/package.json").read_text()
    )
    pyproject = tomllib.loads(
        (root / "crates/pqhybridsign-py/pyproject.toml").read_text()
    )

    expected = [
        ("Cargo.toml", cargo["workspace"]["package"]["version"], version),
        (
            "crates/pqhybridsign-wasm/npm/package.json",
            package_json["version"],
            version,
        ),
    ]

    mismatched = [
        (name, found, want) for name, found, want in expected if found != want
    ]

    for name, found, want in expected:
        status = "ok" if found == want else "MISMATCH"
        print(f"  {status:9} {name}: {found} (expected {want})")

    dynamic = pyproject.get("project", {}).get("dynamic", [])
    if "version" in dynamic:
        print("  ok        crates/pqhybridsign-py/pyproject.toml: version is dynamic")
    else:
        print(
            "  MISMATCH  crates/pqhybridsign-py/pyproject.toml: 'version' is not"
            " in [project].dynamic, so the wheel version no longer follows the"
            " workspace",
        )
        mismatched.append(("pyproject.toml", "static", "dynamic"))

    if mismatched:
        print(
            f"\nTag {tag} does not match every manifest. Bump the files listed"
            " above, or retag, before publishing.",
            file=sys.stderr,
        )
        return 1

    print(f"\nTag {tag} matches every manifest.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
