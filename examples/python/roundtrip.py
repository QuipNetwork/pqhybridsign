# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sign/verify roundtrip example for H1 through H4, built against the
installed pqhybridsign package.

For each suite: derive a keypair from a fixed seed, sign a message
deterministically, verify the signature, tamper one message byte, and
confirm verification then fails. Every seed and nonce is a fixed
constant, so the run needs no random number generator and is
byte-for-byte repeatable.

Prints one line per suite checked and exits 0. On the first failure it
prints a message to stderr and exits nonzero.
"""

import sys

import pqhybridsign as phs

# Application context bound into every signature.
CTX = b"pqhybridsign-example-ctx"
# Fixed nonce for deterministic signing. Not every component honours it
# (see pqhybridsign_core::composite::sign_deterministic's documentation),
# but it removes any dependency on a random number generator for this
# example.
NONCE = b"pqhybridsign-example-nonce"
# Message signed by every suite in this example.
MESSAGE = b"pqhybridsign roundtrip message"

SUITES = [
    ("H1", phs.Suite.H1, 1),
    ("H2", phs.Suite.H2, 2),
    ("H3", phs.Suite.H3, 3),
    ("H4", phs.Suite.H4, 4),
]


def tamper(msg: bytes) -> bytes:
    """Flip the first byte of `msg`, producing the tampered message this
    example verifies against."""
    return bytes([msg[0] ^ 0x01]) + msg[1:]


def check_suite(name: str, suite: "phs.Suite", seed_byte: int) -> None:
    """Roundtrip one suite: keygen, sign, verify true, tamper, verify
    false. Raises on the first failure."""
    # One fixed 32-byte master seed per suite, so a suite's keypair never
    # depends on another suite's.
    seed = bytes([seed_byte]) * 32
    sk, pk = phs.keygen_from_seed(suite, seed)

    sig = phs.sign_deterministic(suite, sk, MESSAGE, CTX, NONCE)

    if not phs.verify(suite, pk, MESSAGE, CTX, sig):
        raise RuntimeError(f"{name}: verify of the untampered signature returned false")

    if phs.verify(suite, pk, tamper(MESSAGE), CTX, sig):
        raise RuntimeError(f"{name}: verify of the tampered message returned true")

    print(f"{name}: keygen, sign, verify true, tamper, verify false -- OK")


def main() -> int:
    for name, suite, seed_byte in SUITES:
        try:
            check_suite(name, suite, seed_byte)
        except Exception as exc:  # noqa: BLE001 - first failure ends the run
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
