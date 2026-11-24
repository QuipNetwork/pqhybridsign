#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Sourced by check-types.sh, regenerate-types.sh and build-npm.sh. The
# generated .d.ts files are checked in and diffed in CI, and wasm-pack
# versions order generated lines differently (0.15.0 emits the
# `__wbg_set_*` exports of `InitOutput` before the `__wbg_get_*` ones;
# 0.13.1 the other way). One version must produce them, and that is CI's:
# the `wasm-npm` job installs 0.13.1 via the wasm-pack installer. Install it
# locally with `cargo install wasm-pack --version 0.13.1 --locked`.
PINNED_WASM_PACK_VERSION=0.13.1

require_pinned_wasm_pack() {
    local found
    found="$(wasm-pack --version 2>/dev/null | awk '{print $2}')"
    if [ "$found" != "$PINNED_WASM_PACK_VERSION" ]; then
        echo "wasm-pack ${found:-(not found)} is not the pinned ${PINNED_WASM_PACK_VERSION}:" \
            "generated .d.ts line order differs between versions." >&2
        echo "Install it with: cargo install wasm-pack --version ${PINNED_WASM_PACK_VERSION} --locked" >&2
        exit 1
    fi
}
