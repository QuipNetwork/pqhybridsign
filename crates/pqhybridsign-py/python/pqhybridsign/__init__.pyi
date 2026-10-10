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
    """A path-selected signature (ED_SH/SR_SH) carried an unknown selector."""

class LeafCountOutOfRangeError(PqHybridSignError):
    """A stateful signature's declared leaf count was out of range."""

class TrailingBytesError(PqHybridSignError):
    """Bytes remained past the length an encoding implied."""

class ComponentFailureError(PqHybridSignError):
    """A component algorithm (the classical or post-quantum primitive) failed."""

class BadRotationKindError(PqHybridSignError):
    """A rotation payload carried an unknown rotation kind."""

class DeltaLengthOutOfRangeError(PqHybridSignError):
    """A delta-encoded (ED_FN_512/SR_FN_512) signature's length was out of range."""

class LeavesExhaustedError(PqHybridSignError):
    """The key's one-time leaf budget is spent; rotate the key."""

class GrindAbortError(PqHybridSignError):
    """The signature-randomizer grind bound was reached for this key and message."""

class JournalFailedError(PqHybridSignError):
    """The leaf journal could not durably commit; nothing was spent."""

class SigningFailedError(PqHybridSignError):
    """Signing failed."""

class InvalidSuiteError(PqHybridSignError):
    """The suite code or name is not one of the six suites."""

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
    """A stateful (ED_SH/SR_SH) secret key cannot be copied, deep-copied or pickled."""

class InvalidMnemonicError(PqHybridSignError):
    """The recovery phrase is not a valid English BIP39 mnemonic."""

class InvalidProofError(PqHybridSignError):
    """The hybrid VRF proof did not verify; no output bytes were derived.

    One exception for both halves: which of the classical proof or the
    post-quantum binding failed is not reported.
    """

class Suite:
    """One of the six hybrid suites pqhybridsign ships.

    Frozen and hashable. Compares equal to the integer suite code
    (`Suite.ED_ML_44 == 1`). Not an `IntEnum`: `isinstance(Suite.ED_ML_44, int)` is
    False, `Suite(1)` does not construct, and the class is not iterable
    or subscriptable. Use `from_code` to recover a `Suite` from a stored
    integer code.
    """

    ED_ML_44: Suite
    ED_FN_512: Suite
    SR_ML_44: Suite
    SR_FN_512: Suite
    ED_SH: Suite
    SR_SH: Suite

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
    """A loaded ED_SH or SR_SH secret key.

    The durability contract is unchanged. After every sign_stateful call,
    including one that raised, call export() and persist the result
    before relying on the signature.

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
    def sign_stateful(self, msg: ReadableBuffer, ctx: ReadableBuffer) -> bytes:
        """Sign `msg` under `ctx`, spending one leaf from this key's bound
        journal.

        After this call, including one that raised, persist `export()`
        before relying on the signature."""

    def sign_stateless(self, msg: ReadableBuffer, ctx: ReadableBuffer) -> bytes: ...
    def export(self) -> bytes:
        """Export this key's current state as bytes.

        Persist this after every `sign_stateful` call, including one that
        raised. See `StatefulSecretKey`."""

    def __copy__(self) -> "StatefulSecretKey": ...
    def __deepcopy__(self, memo: Any) -> "StatefulSecretKey": ...
    def __reduce__(self) -> Any: ...

def keygen_from_seed(suite: Suite, seed: ReadableBuffer) -> tuple[bytes, bytes]:
    """Derive a keypair for `suite` (one of the four stateless suites) from a
    32-byte master seed.

    Returns `(secret_key, public_key)`. The returned secret key is a
    Python `bytes` object and cannot be zeroized. Callers that need
    that guarantee should use `StatefulSecretKey` or the C ABI.
    """

def sign(
    suite: Suite, sk: ReadableBuffer, msg: ReadableBuffer, ctx: ReadableBuffer
) -> bytes:
    """Hedged (randomized) signing for `suite` (one of the four stateless
    suites)."""

def sign_deterministic(
    suite: Suite,
    sk: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    nonce: ReadableBuffer,
) -> bytes:
    """Deterministic signing for `suite` (one of the four stateless
    suites)."""

def verify(
    suite: Suite,
    pk: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    sig: ReadableBuffer,
) -> bool:
    """Verify `sig` over `msg` under `ctx` for `suite`, against `pk`.
    Covers all six suites. For ED_SH and SR_SH this accepts only a signature
    produced by `StatefulSecretKey.sign_stateful`, the same behaviour
    `verify_stateful` gives directly; call `verify_stateless` for a message
    deliberately signed on the stateless path. Returns `False`, never
    raises, for a malformed `pk` or `sig`."""

def verify_stateful(
    suite: Suite,
    pk: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    sig: ReadableBuffer,
) -> bool:
    """Verify `sig` over `msg` under `ctx` for a stateful `suite` (ED_SH or
    SR_SH), accepting only a signature produced by `sign_stateful`, against one
    whole verify-form public key `pk`.

    `verify` is the total dispatcher across all six suites and, for ED_SH and
    SR_SH, behaves exactly as this function does. A signature whose wire
    `PathSelector` names the stateless path is refused before either
    component signature is checked. Raises `WrongEntryPointForSuiteError`
    for the four stateless suites."""

def verify_stateless(
    suite: Suite,
    pk: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    sig: ReadableBuffer,
) -> bool:
    """The mirror image of `verify_stateful`: accepts only a signature
    produced by `sign_stateless`. Use this for rotation and recovery
    authorizations, and for any other message deliberately signed on the
    few-time stateless path."""

def keygen_stateful_from_seed(
    suite: Suite,
    seed: ReadableBuffer,
    max_stateful_signatures: int,
    journal: LeafJournal,
    budget: StatelessBudgetStore,
) -> tuple[StatefulSecretKey, bytes]:
    """Derive a stateful keypair for `suite` (ED_SH or SR_SH) from a 32-byte
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

def stored_public_key(suite: Suite, public_key: ReadableBuffer) -> bytes:
    """Recompute the stored form of a verify-form public key.

    The stored form is the classical public key followed by the SHRINCS
    commitment, and the commitment is derived from the bundle's `pkSeed`
    and `hypertreeRoot` rather than copied out of it. Slicing the
    bundle's carried commitment field at a fixed offset gives the same
    bytes for a well-formed key and hides a divergence between the
    compute path and the verify path.

    Raises `WrongEntryPointForSuiteError` for the four stateless suites:
    they have no stored form. Raises `BadLengthError` if `public_key` is
    not the verify-form public key length for `suite`. Raises
    `ComponentFailureError` if the commitment computation itself fails."""

def stored_public_key_len(suite: Suite) -> int:
    """The stored public key length for `suite`, in bytes: the form a
    verifier keeps, which is what `verify_with_stored_public_key_stateful`
    and `verify_with_stored_public_key_stateless` take as
    `stored_public_key`.

    For ED_SH and SR_SH this is the classical public key and a 32-byte
    commitment to the post-quantum verify key, smaller than the
    verify-form length `keygen_stateful_from_seed`'s public key uses,
    because the verify key itself is supplied per signature rather than
    stored. For the four stateless suites the stored and verify forms are
    the same bytes, so this equals the public key length for `suite`;
    there is no error case for any suite."""

def verify_with_stored_public_key_stateful(
    suite: Suite,
    stored_public_key: ReadableBuffer,
    pq_verify_key: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    sig: ReadableBuffer,
) -> bool:
    """Verify `sig` over `msg` under `ctx` for a stateful `suite` (ED_SH or
    SR_SH), accepting only a signature produced by `sign_stateful`, against a
    signer-supplied verify key that must be the one `stored_public_key`
    commits to.

    `stored_public_key` is trusted (`stored_public_key_len(suite)` bytes,
    the small on-storage form a verifier installs); `pq_verify_key` is not
    (the larger commitment bundle the signer supplies alongside every
    signature). The commitment is recomputed from `pq_verify_key` and
    matched against the stored one before anything is verified, and the
    classical public key is taken from `stored_public_key`, so nothing the
    signer supplied can substitute a key of their own.

    `verify_stateful` is the other shape: it takes one whole verify-form
    public key and checks no commitment. Use it only where the verify key
    itself came from a trusted place.

    A signature whose wire `PathSelector` names the stateless path is
    refused before either component signature is checked. Call
    `verify_with_stored_public_key_stateless` for a message deliberately
    signed on that path.

    Returns `False`, never raises, for a commitment that does not match, a
    malformed key or a malformed signature."""

def verify_with_stored_public_key_stateless(
    suite: Suite,
    stored_public_key: ReadableBuffer,
    pq_verify_key: ReadableBuffer,
    msg: ReadableBuffer,
    ctx: ReadableBuffer,
    sig: ReadableBuffer,
) -> bool:
    """The mirror image of `verify_with_stored_public_key_stateful`:
    accepts only a signature produced by `sign_stateless`. Use this for
    rotation and recovery authorizations, and for any other message
    deliberately signed on the few-time stateless path."""

def master_seed_from_mnemonic(phrase: str, password: Optional[str] = None) -> bytes:
    """Turn an English BIP39 recovery phrase into a master seed.

    This is Substrate's seed derivation, not standard BIP39: PBKDF2-HMAC-
    SHA512 runs over the mnemonic's entropy, not over the phrase text,
    salted with `"mnemonic" || password`, for 2048 rounds. `password` is
    the empty string when `None`.

    Raises `InvalidMnemonicError` if `phrase` is not a valid English BIP39
    mnemonic: a wrong word count, an unknown word, or a bad checksum."""

def derive_hard_junction(
    parent_master: ReadableBuffer, chain_code: ReadableBuffer
) -> bytes:
    """Derive a hard-junction child master seed.

    Derivation is deterministic: the same parent and chain code reach the
    same child seed on every host that computes it, and therefore the same
    stateful tree starting at leaf 1. Deriving one child twice on two
    hosts is the same failure as importing one key twice -- both hosts
    spend leaf 1, and the post-quantum security of that key is gone. A
    derived child must be derived once, then persisted and restored
    through the validating import path.

    Raises `BadLengthError` if `parent_master` or `chain_code` is not 32
    bytes."""

def derive_hard_junction_path(
    parent_master: ReadableBuffer, chain_codes: list[ReadableBuffer]
) -> bytes:
    """Apply a sequence of chain codes in order, each child becoming the
    next parent. `[a, b]` means
    `derive_hard_junction(derive_hard_junction(parent, a), b)`.

    An empty `chain_codes` returns `parent_master` unchanged -- a caller
    that requires at least one junction must check for that itself. See
    `derive_hard_junction` for the re-keygen hazard, which applies to
    every seed this function returns.

    Raises `ValueError` naming the offending index if any element of
    `chain_codes` is not 32 bytes."""

def vrf_proof_len(suite: Suite) -> int:
    """Length in bytes of a hybrid VRF proof for `suite`.

    For ED_ML_44 and SR_ML_44 this is exact. For ED_FN_512 and SR_FN_512
    this is the maximum a delta-length binding can occupy. For ED_SH and
    SR_SH this is exact."""

def vrf_prove(suite: Suite, secret_key: ReadableBuffer, input: ReadableBuffer) -> bytes:
    """Evaluate the hybrid VRF for `suite`.

    The four stateless suites only: ED_SH and SR_SH spend one unit of a
    few-time stateless budget per evaluation and prove through
    `VrfStatelessKey.prove` instead.

    Raises `WrongEntryPointForSuiteError` for ED_SH and SR_SH."""

def vrf_prove_deterministic(
    suite: Suite, secret_key: ReadableBuffer, input: ReadableBuffer
) -> bytes:
    """Evaluate the hybrid VRF for `suite` with a reproducible classical
    proof. The same suite restriction and errors as `vrf_prove`."""

def vrf_verify(
    suite: Suite,
    public_key: ReadableBuffer,
    input: ReadableBuffer,
    proof: ReadableBuffer,
) -> bool:
    """Verify a hybrid VRF proof for `suite`. Covers all six suites.
    Returns `False`, never raises, for malformed `bytes`/`bytearray`
    `public_key` or `proof` input. A `public_key`, `input`, or `proof`
    argument that is neither `bytes` nor `bytearray` still raises
    `TypeError`, before verification runs."""

def vrf_make_bytes(
    suite: Suite,
    public_key: ReadableBuffer,
    input: ReadableBuffer,
    proof: ReadableBuffer,
    context: ReadableBuffer,
) -> bytes:
    """Verify a VRF proof for `suite` and derive 32 output bytes from it.

    The proof is verified first, the same check `vrf_verify` makes, and
    bytes are derived only on success. Raises `InvalidProofError` if the
    proof does not verify under `public_key` and `input`, `BadLengthError`
    if `public_key` or `proof` is not the suite's length.

    `context` separates two uses of one proof: the same proof under two
    different contexts gives unrelated bytes."""

class VrfStatelessKey:
    """A SHRINCS key dedicated to VRF evaluation, held across calls.

    ED_SH and SR_SH evaluate the VRF through their post-quantum half's few-time
    stateless path, which draws on a budget shared with rotation and
    recovery. The key that carries an identity's rotation and recovery
    authority must not also spend that budget on VRF evaluations, so this
    type holds a separate, dedicated key: `derive` gets one from the
    master seed under a label disjoint from the identity key's, so the
    two never collide.

    The key lives only in memory: there is no export."""

    @classmethod
    def derive(
        cls, suite: Suite, master: ReadableBuffer
    ) -> tuple["VrfStatelessKey", bytes]:
        """Derive a dedicated VRF key from `master` for `suite`. Returns
        `(key, public_key)`.

        Runs a real key generation: about 47 seconds at a 128s profile.
        Released from the GIL while it runs.

        Raises `WrongEntryPointForSuiteError` for the four stateless
        suites.
        Raises `BadLengthError` if `master` is not 32 bytes."""

    def prove(self, budget: StatelessBudgetStore, input: ReadableBuffer) -> bytes:
        """Evaluate the VRF on `input`, spending one unit of this key's
        few-time stateless budget through `budget`.

        Pass the same durable store on every call for this key. A fresh
        store on each call restarts the count from empty, so the few-time
        bound never advances and is exceeded with nothing reporting it.

        Raises `StatelessBudgetExhaustedError` if this key's stateless
        budget is spent. Raises `BudgetStoreFailedError` if `budget.record`
        raised or otherwise failed to run."""
