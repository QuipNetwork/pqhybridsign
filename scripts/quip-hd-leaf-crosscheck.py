#!/usr/bin/env python3
"""Independent cross-check for pqhybridsign `quip_hd::hybrid_leaf` (design v2 §1-§2).

Standard library only: BIP-39 seed = PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic" + NFKD(passphrase),
2048, 64); master = HMAC-SHA512("QUIP seed", seed); hardened CKD; path m/0x514E'/alg'/20049'/account'/index'.
The phrase is used as given (callers pass a canonical, single-spaced phrase); no wordlist check here.
"""
import hashlib
import hmac
import struct
import sys
import unicodedata

SUITES = {"H1": 0x100, "H2": 0x200, "H3": 0x300, "H4": 0x400}


def bip39_seed(phrase: str, passphrase: str) -> bytes:
    p = unicodedata.normalize("NFKD", phrase).encode()
    s = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode()
    return hashlib.pbkdf2_hmac("sha512", p, s, 2048, 64)


def leaf(seed: bytes, levels) -> bytes:
    i = hmac.new(b"QUIP seed", seed, hashlib.sha512).digest()
    k, c = i[:32], i[32:]
    for level in levels:
        assert 0 <= level < 2**31
        i = hmac.new(c, b"\x00" + k + struct.pack(">I", level + 2**31), hashlib.sha512).digest()
        k, c = i[:32], i[32:]
    return k


def hybrid_leaf(suite: str, phrase: str, passphrase: str, account: int, index: int) -> bytes:
    return leaf(bip39_seed(phrase, passphrase), [0x514E, SUITES[suite], 20049, account, index])


def hard_junction(parent: bytes, chain_code: bytes) -> bytes:
    """pqhybridsign derive::derive_hard_junction: HKDF-SHA256, salt "hybrid-sig",
    info "junction/hard/" || chain_code, 32 bytes."""
    prk = hmac.new(b"hybrid-sig", parent, hashlib.sha256).digest()
    return hmac.new(prk, b"junction/hard/" + chain_code + b"\x01", hashlib.sha256).digest()


DEV_PHRASE = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"


def scale_str(t: str) -> bytes:
    b = t.encode()
    n = len(b)
    prefix = bytes([n << 2]) if n < 64 else ((n << 2) | 1).to_bytes(2, "little")
    return prefix + b


def level_of(t: str) -> int:
    """Design §3 f(t): an all-digit t is itself; a name is the low 31 bits of
    blake2_256(SCALE(t)) read little-endian."""
    if t.isdigit():
        return int(t)
    h = hashlib.blake2b(scale_str(t), digest_size=32).digest()
    return int.from_bytes(h[:4], "little") & 0x7FFFFFFF


def chain_code(t: str) -> bytes:
    """sp-core DeriveJunction's chain code for a hard junction t."""
    if t.isdigit():
        return int(t).to_bytes(8, "little") + bytes(24)
    d = scale_str(t)
    return hashlib.blake2b(d, digest_size=32).digest() if len(d) > 32 else d + bytes(32 - len(d))


def check_suri_mapping(case: dict) -> None:
    """For an sdk-scope positive, re-derive the case's inputs from its SURI."""
    body, _, password = case["suri"].partition("///")
    has_password = "///" in case["suri"]
    head, *junctions = body.split("//")
    if head.startswith("0x"):
        assert head[2:].lower() == case["raw_seed"], case["name"]
        assert [chain_code(j).hex() for j in junctions] == case.get("junction_chain_codes", []), case["name"]
        return
    phrase = head.strip() or DEV_PHRASE
    assert " ".join(phrase.split()) == case["phrase"], case["name"]
    assert (password if has_password else "") == case["passphrase"], case["name"]
    levels = [level_of(j) for j in junctions] + [0, 0]
    assert levels[:2] == [case["account"], case["index"]], case["name"]


def check_parity_file(path: str) -> int:
    """Recompute every seed in tests/vectors/quip_hd_parity.json."""
    import json

    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    ids = {sid: info["algorithm"] for sid, info in data["suites"].items()}
    checked = 0
    for case in data["positive"]:
        if "sdk" in case["scope"]:
            check_suri_mapping(case)
        for sid, key in case["keys"].items():
            if case.get("raw_seed") is not None:
                seed = bytes.fromhex(case["raw_seed"])
                for cc in case.get("junction_chain_codes", []):
                    seed = hard_junction(seed, bytes.fromhex(cc))
            else:
                phrase = " ".join(case["phrase"].split())
                seed = leaf(
                    bip39_seed(phrase, case["passphrase"]),
                    [0x514E, ids[sid], 20049, case["account"], case["index"]],
                )
            assert seed.hex() == key["seed"], (case["name"], sid)
            checked += 1
    return checked


if __name__ == "__main__":
    if len(sys.argv) == 2:
        print(f"parity file: {check_parity_file(sys.argv[1])} seeds match")
        sys.exit(0)
    # Sanity: the hd.test.ts regression leaves (experimental algorithm).
    s = b"QUIP HD v1 regression vector seed"
    assert leaf(s, [0x514E, 0x7FFFFFFF, 20049, 0, 0]).hex().startswith("e384e035")
    assert bip39_seed("abandon " * 11 + "about", "TREZOR").hex().startswith("c55257c3")
    # Design v2.1: the phrase is NFKD-normalized, so the "fi" ligature (U+FB01) gives the ASCII leaf.
    dev = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"
    assert hybrid_leaf("H4", dev.replace("fit", "\ufb01t"), "", 0, 0) == hybrid_leaf("H4", dev, "", 0, 0)
    cases = [
        ("legal winner thank year wave sausage worth useful legal winner thank yellow", "", 0, 0),
        ("legal winner thank year wave sausage worth useful legal winner thank yellow", "", 1, 0),
        ("legal winner thank year wave sausage worth useful legal winner thank yellow", "", 0, 7),
        ("legal winner thank year wave sausage worth useful legal winner thank yellow", "café", 0, 0),
        ("bottom drive obey lake curtain smoke basket hold race lonely fit walk", "", 0, 0),
    ]
    for suite in SUITES:
        for phrase, pw, acct, idx in cases:
            print(f"{suite} acct={acct} idx={idx} pw={pw!r} phrase={phrase.split()[0]}... "
                  f"{hybrid_leaf(suite, phrase, pw, acct, idx).hex()}")
    sys.exit(0)
