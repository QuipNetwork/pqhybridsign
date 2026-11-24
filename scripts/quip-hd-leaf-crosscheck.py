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


if __name__ == "__main__":
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
