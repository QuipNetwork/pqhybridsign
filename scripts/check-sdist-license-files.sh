#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Verifies that every License-File named in an sdist's PKG-INFO is present in
# the tarball.
#
# PyPI enforces this and rejects the upload with `400 License-File <name>
# does not exist in distribution file`. twine check does not, because the
# metadata itself is well formed, so the failure only appears at upload
# time, after the wheel of the same version has already been accepted.
#
# Ported from quip-solver-core's script of the same name (fixed in that
# project's commit d5fce50, after that exact upload was rejected): maturin
# there declared LICENSE and NOTICE from the project config but packed
# neither, because both sat at the repository root rather than inside the
# crate. crates/pqhybridsign-py/pyproject.toml avoids that failure mode by
# construction, with a `license.file` entry maturin resolves and copies
# itself, but this check still runs so a future change to that file cannot
# reintroduce the gap unnoticed.
set -euo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: check-sdist-license-files.sh <sdist.tar.gz>..." >&2
    exit 1
fi

STATUS=0

check_one() {
    local sdist=$1

    if [ ! -f "$sdist" ]; then
        echo "No such sdist: $sdist" >&2
        return 1
    fi

    # Read the listing once. Deriving the root with `tar | head` instead
    # would kill tar with SIGPIPE, which pipefail then reports as a
    # failure of this function.
    local contents
    contents=$(tar tzf "$sdist")

    # Every path in the tarball is prefixed with the distribution
    # directory, and PKG-INFO names its license files relative to that
    # directory.
    local root=${contents%%/*}
    if [ -z "$root" ] || [ "$root" = "$contents" ]; then
        echo "Could not read the root directory of $sdist" >&2
        return 1
    fi
    local pkginfo
    pkginfo=$(tar xzOf "$sdist" "$root/PKG-INFO")

    local declared
    declared=$(printf '%s\n' "$pkginfo" | sed -n 's/^License-File: //p')
    if [ -z "$declared" ]; then
        echo "$sdist declares no License-File. Nothing to check."
        return 0
    fi

    local missing=0
    local name
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        if printf '%s\n' "$contents" | grep -Fxq "$root/$name"; then
            echo "  ok      $name"
        else
            echo "  MISSING $name" >&2
            missing=1
        fi
    done <<EOF
$declared
EOF

    if [ "$missing" -ne 0 ]; then
        cat >&2 <<'MSG'

The sdist declares a License-File it does not contain. PyPI rejects this
with 400 at upload time. Point pyproject.toml's `license` table at the
file with `license = { file = "<path>" }` so maturin copies the file it
names into the archive, instead of only declaring it.
MSG
        return 1
    fi

    echo "$sdist declares $(printf '%s\n' "$declared" | grep -c .) license file(s), all present."
}

for sdist in "$@"; do
    if ! check_one "$sdist"; then
        STATUS=1
    fi
done

exit "$STATUS"
