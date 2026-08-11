# SPDX-License-Identifier: AGPL-3.0-or-later
from enum import IntEnum
from typing import Any, Protocol, Union

ReadableBuffer = Union[bytes, bytearray]

class PqHybridSignError(Exception):
    """Base class for every exception this module raises."""

class BadLengthError(PqHybridSignError):
    """A byte string had the wrong length."""

class ContextTooLongError(PqHybridSignError):
    """The application context exceeded 255 bytes."""

class OutputBufferTooSmallError(PqHybridSignError):
    """An internal output buffer was too small for this signature."""

class SoftJunctionRejectedError(PqHybridSignError):
    """A soft derivation junction was supplied."""

class BadPathSelectorError(PqHybridSignError):
    """A path-selected signature (H5/H6) carried an unknown selector."""

class LeafCountOutOfRangeError(PqHybridSignError):
    """A stateful signature's declared leaf count was out of range."""

class TrailingBytesError(PqHybridSignError):
    """Bytes remained past the length an encoding implied."""

class ComponentFailureError(PqHybridSignError):
    """A component algorithm (the classical or post-quantum primitive) failed."""

class BadRotationKindError(PqHybridSignError):
    """A rotation payload carried an unknown rotation kind."""

class DeltaLengthOutOfRangeError(PqHybridSignError):
    """A delta-encoded (H2/H4) signature's length was out of range."""

class LeavesExhaustedError(PqHybridSignError):
    """The key's one-time leaf budget is spent; rotate the key."""

class GrindAbortError(PqHybridSignError):
    """The signature-randomizer grind bound was reached for this key and message."""

class JournalFailedError(PqHybridSignError):
    """The leaf journal could not durably commit; nothing was spent."""

class SigningFailedError(PqHybridSignError):
    """Signing failed."""

class InvalidSuiteError(PqHybridSignError):
    """The suite code or name is not one of H1-H6."""

class WrongEntryPointForSuiteError(PqHybridSignError):
    """This entry point does not accept this suite."""

class StatefulKeyNotCloneableError(PqHybridSignError):
    """A stateful (H5/H6) secret key cannot be copied, deep-copied or pickled."""

class Suite(IntEnum):
    """One of the six hybrid suites pqhybridsign ships."""

    H1 = 1
    H2 = 2
    H3 = 3
    H4 = 4
    H5 = 5
    H6 = 6

class LeafJournal(Protocol):
    """The interface `StatefulSecretKey.sign_stateful` requires of its
    `journal` argument. `commit` must not return until the write is
    durable."""

    def commit(self, leaf: int) -> None: ...
    def next_leaf(self) -> int: ...

class StatefulSecretKey:
    """A loaded H5 or H6 secret key.

    Not copyable, deep-copyable or picklable: `__copy__`, `__deepcopy__`
    and `__reduce__` all raise `StatefulKeyNotCloneableError`.
    """

    @property
    def suite(self) -> Suite: ...
    def sign_stateful(
        self, msg: ReadableBuffer, ctx: ReadableBuffer, journal: LeafJournal
    ) -> bytes: ...
    def sign_stateless(self, msg: ReadableBuffer, ctx: ReadableBuffer) -> bytes: ...
    def export(self) -> bytes: ...
    def __copy__(self) -> "StatefulSecretKey": ...
    def __deepcopy__(self, memo: Any) -> "StatefulSecretKey": ...
    def __reduce__(self) -> Any: ...

def keygen_from_seed(suite: Suite, seed: ReadableBuffer) -> tuple[bytes, bytes]:
    """Derive a keypair for `suite` (H1-H4) from a 32-byte master seed.
    Returns `(secret_key, public_key)`."""

def sign(
    suite: Suite, sk: ReadableBuffer, msg: ReadableBuffer, ctx: ReadableBuffer
) -> bytes:
    """Hedged (randomized) signing for `suite` (H1-H4)."""

def sign_deterministic(
    suite: Suite,
    sk: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    nonce: ReadableBuffer,
) -> bytes:
    """Deterministic signing for `suite` (H1-H4)."""

def verify(
    suite: Suite,
    pk: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    sig: ReadableBuffer,
) -> bool:
    """Verify `sig` over `msg` under `ctx` for `suite`, against `pk`.
    Covers all six suites. Returns `False`, never raises, for a malformed
    `pk` or `sig`."""

def keygen_stateful_from_seed(
    suite: Suite, seed: ReadableBuffer, max_stateful_signatures: int
) -> tuple[StatefulSecretKey, bytes]:
    """Derive a stateful keypair for `suite` (H5 or H6) from a 32-byte
    master seed, with a budget of `max_stateful_signatures` one-time
    leaves. Returns `(StatefulSecretKey, public_key)`."""

def load_stateful_secret_key(
    suite: Suite, blob: ReadableBuffer
) -> StatefulSecretKey:
    """Load a previously exported stateful secret key."""

def profile_name() -> str:
    """The SHRINCS profile this build links against, for example
    `"shrincs-256s"`. A key, signature or verify key produced by a build
    against one profile is not interchangeable with one from a build
    against another."""
