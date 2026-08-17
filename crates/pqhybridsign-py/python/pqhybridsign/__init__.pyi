# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any, Optional, Protocol, Union

ReadableBuffer = Union[bytes, bytearray]

class PqHybridSignError(Exception):
    """Base class for every exception this module raises."""

class BadLengthError(PqHybridSignError):
    """A byte string had the wrong length."""

class ContextTooLongError(PqHybridSignError):
    """The application context exceeded 255 bytes."""

class OutputBufferTooSmallError(PqHybridSignError):
    """An internal output buffer was too small for this signature."""

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

class JournalKeyMismatchError(PqHybridSignError):
    """This leaf journal does not belong to this key.

    It has never been bound to any key, or it is bound to a different one.
    Nothing was spent and the key is intact -- unlike
    `CountersDivergedError`, this is not a reason to rotate. Reopen the
    durable journal that belongs to this key, or, if there genuinely is
    none, bind one explicitly with `adopt_key`.
    """

class CountersDivergedError(PqHybridSignError):
    """The key counter and the leaf journal diverged; the key can sign no more.

    Rotate the key. Repairing the counters by hand reissues a spent leaf,
    which destroys the key's security. Distinct from SigningFailedError,
    which may be worth retrying.
    """

class StatelessBudgetExhaustedError(PqHybridSignError):
    """The few-time stateless budget for this key's stateless material is spent.

    Nothing was spent on the refused attempt. This is not the stateful
    path's leaf budget (`LeavesExhaustedError`): ordinary application
    signing spends leaves and never touches this bound, while
    `sign_stateless`, rotation authorization and recovery all draw on this
    one and never touch leaves.

    Not a quota to raise. Exceeding it degrades the security assumption of
    the underlying few-time scheme. It clears only when a rotation actually
    changes the stateless key material.
    """

class BudgetStoreFailedError(PqHybridSignError):
    """The stateless budget store could not durably record; nothing was spent.

    The stateless counterpart of `JournalFailedError`, and transient on the
    same terms: the same unit of budget is still available once the storage
    fault is repaired.
    """

class StatefulKeyNotCloneableError(PqHybridSignError):
    """A stateful (H5/H6) secret key cannot be copied, deep-copied or pickled."""

class Suite:
    """One of the six hybrid suites pqhybridsign ships.

    Frozen and hashable. Compares equal to the integer suite code
    (`Suite.H1 == 1`). Not an `IntEnum`: `isinstance(Suite.H1, int)` is
    False, `Suite(1)` does not construct, and the class is not iterable
    or subscriptable. Use `from_code` to recover a `Suite` from a stored
    integer code.
    """

    H1: Suite
    H2: Suite
    H3: Suite
    H4: Suite
    H5: Suite
    H6: Suite

    @property
    def value(self) -> int:
        """The integer suite code used on the wire and by the C ABI."""

    @staticmethod
    def from_code(code: int) -> Suite:
        """Recover a `Suite` from the integer code used on the wire."""

    def __int__(self) -> int: ...
    def __hash__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...

class LeafJournal(Protocol):
    """The interface `StatefulSecretKey.sign_stateful` requires of its
    `journal` argument.

    A journal records two facts, and both must be durable: how far the key
    has spent (`next_leaf`) and which key it is spending for
    (`bound_key`). `commit` and `bind_key` must not return until their
    write is durable.

    `bound_key` returns `None` only for a journal that has never been
    bound to a key. A journal that cannot read its own storage must not
    report `None`: that is the answer `adopt_key` treats as an invitation
    to write a binding, and writing one over a record that already exists
    forks the leaf budget.
    """

    def commit(self, leaf: int) -> None: ...
    def next_leaf(self) -> int: ...
    def bound_key(self) -> Optional[bytes]: ...
    def bind_key(self, identity: bytes) -> None: ...

class StatelessBudgetStore(Protocol):
    """A durable record of few-time stateless budget consumption.

    The stateless counterpart of `LeafJournal`. `sign_stateless` cannot be
    called without one, because the stateless bound of specification
    section 21 is a security assumption rather than a quota.

    Entries are keyed by a 32-byte value derived from the key's own
    stateless material, so one store serves every key a process holds and
    there is no adoption step: a store that has never seen a given material
    reports `None` for that material alone.

    `record` must not return until the write is durable. Returning early
    lets a restart hand the same unit of budget out again, and enough of
    those exceed the bound with nothing reporting it. `consumed` must
    return `None` only for material it has genuinely never tracked, never
    for a read it could not perform: `None` reads as a full budget.
    """

    def consumed(self, key: bytes) -> Optional[int]: ...
    def record(self, key: bytes, count: int) -> None: ...

class StatefulSecretKey:
    """A loaded H5 or H6 secret key.

    Bound to a `LeafJournal` at construction, by `keygen_stateful_from_seed`
    or `load_stateful_secret_key`: `sign_stateful` always spends leaves
    through that bound journal, never a fresh one, so it takes no `journal`
    argument itself.

    Bound to a `StatelessBudgetStore` at construction the same way, and for
    the same reason: `sign_stateless` always charges the few-time stateless
    budget through that bound store, so it takes no `budget` argument
    either. A caller who could pass a fresh store on each call would hold a
    bound that never advances.

    Not copyable, deep-copyable or picklable: `__copy__`, `__deepcopy__`
    and `__reduce__` all raise `StatefulKeyNotCloneableError`.
    """

    @property
    def suite(self) -> Suite: ...
    def sign_stateful(self, msg: ReadableBuffer, ctx: ReadableBuffer) -> bytes: ...
    def sign_stateless(self, msg: ReadableBuffer, ctx: ReadableBuffer) -> bytes: ...
    def export(self) -> bytes: ...
    def __copy__(self) -> "StatefulSecretKey": ...
    def __deepcopy__(self, memo: Any) -> "StatefulSecretKey": ...
    def __reduce__(self) -> Any: ...

def keygen_from_seed(suite: Suite, seed: ReadableBuffer) -> tuple[bytes, bytes]:
    """Derive a keypair for `suite` (H1-H4) from a 32-byte master seed.

    Returns `(secret_key, public_key)`. The returned secret key is a
    Python `bytes` object and cannot be zeroized. Callers that need
    that guarantee should use `StatefulSecretKey` or the C ABI.
    """

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
    suite: Suite,
    seed: ReadableBuffer,
    max_stateful_signatures: int,
    journal: LeafJournal,
    budget: StatelessBudgetStore,
) -> tuple[StatefulSecretKey, bytes]:
    """Derive a stateful keypair for `suite` (H5 or H6) from a 32-byte
    master seed, with a budget of `max_stateful_signatures` one-time
    leaves. `journal` is bound to the returned key for its whole lifetime,
    and is adopted for it -- the key is brand new, so there is no spending
    history a second journal could fork. A `journal` already bound to a
    different key raises `JournalKeyMismatchError`.

    `budget` is bound the same way and serves `sign_stateless`. It needs no
    adoption step, because its entries are keyed by the key's own stateless
    material.

    Returns `(StatefulSecretKey, public_key)`."""

def load_stateful_secret_key(
    suite: Suite,
    blob: ReadableBuffer,
    journal: LeafJournal,
    budget: StatelessBudgetStore,
) -> StatefulSecretKey:
    """Load a previously exported stateful secret key and bind it to
    `journal` for its whole lifetime.

    `journal` must already carry this key's identity, which is checked
    here rather than deferred to the first signature. A journal that has
    never been bound to any key, and one bound to a different key, both
    raise `JournalKeyMismatchError`. Adopting a new journal for an
    existing key is still possible, through an explicit `adopt_key` call.

    The counter is checked separately, as soon as the returned key is
    asked to sign: a stale blob loaded against an already-advanced
    journal, an advanced blob loaded against a journal that missed a
    commit, or a second key that shares its sibling's already-bound
    journal instance and tries to sign after the sibling has. Each raises
    `CountersDivergedError`.

    `budget` is bound for the returned key's whole lifetime and carries no
    identity check: its entries are keyed by the key's own stateless
    material, so a store holding another key's counts cannot be mistaken
    for this key's. What a wrong store loses is history, not attribution,
    so reopen the same durable store after a restart or the bound restarts
    at zero.
    """

def key_identity(suite: Suite, public_key: ReadableBuffer) -> bytes:
    """The identity a leaf journal records for the key `public_key` names.

    Public material only: this discloses nothing about the secret key, and
    anyone holding the public key can compute it. Pass it to `adopt_key`
    once, when the key's durable journal is created."""

def key_identity_from_secret_key(suite: Suite, blob: ReadableBuffer) -> bytes:
    """The identity a leaf journal records for the key an exported blob
    holds.

    The same value `key_identity` returns for the matching public key. It
    exists because the restart path has the blob in hand and may not have
    kept the public key."""

def adopt_key(journal: LeafJournal, identity: ReadableBuffer) -> None:
    """Bind `journal` to the key `identity` names, unless it already
    belongs to a different key.

    The explicit act performed once, when a key's durable journal is
    created. `load_stateful_secret_key` never does it implicitly. A
    journal already bound to `identity` is left as is, so a provisioning
    step is safe to re-run; one bound to another key raises
    `JournalKeyMismatchError`.

    Do not call this on a fresh journal at every process start: that mints
    a new binding each time and starts the leaf budget over, which is the
    defect the binding closes."""

def profile_name() -> str:
    """The SHRINCS profile this build links against, for example
    `"shrincs-256s"`. A key, signature or verify key produced by a build
    against one profile is not interchangeable with one from a build
    against another."""
