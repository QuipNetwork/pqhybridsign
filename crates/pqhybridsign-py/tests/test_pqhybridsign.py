# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
import pickle

import pytest

import pqhybridsign as phs

STATELESS_SUITES = [phs.Suite.H1, phs.Suite.H2, phs.Suite.H3, phs.Suite.H4]
STATEFUL_SUITES = [phs.Suite.H5, phs.Suite.H6]
ALL_SUITES = STATELESS_SUITES + STATEFUL_SUITES

# Integer codes pinned by pqhybridsign_abi::Suite. Changing any of these
# silently renumbers the Python-visible suite codes and the C ABI.
SUITE_CODES = (
    (phs.Suite.H1, 1),
    (phs.Suite.H2, 2),
    (phs.Suite.H3, 3),
    (phs.Suite.H4, 4),
    (phs.Suite.H5, 5),
    (phs.Suite.H6, 6),
)

MALFORMED_BLOBS = [
    pytest.param(b"", id="empty"),
    pytest.param(b"\x00", id="single-byte"),
    pytest.param(b"\x00" * 4096, id="4096-zero"),
    pytest.param(b"\xff" * 4096, id="4096-ff"),
]


class MemoryJournal:
    """A minimal, in-process `LeafJournal`: durable enough for a test, not
    for production use, since it holds no state past the Python process.

    It records both facts a journal owes: how far the key has spent, and
    which key it is spending for."""

    def __init__(self):
        self.committed = []
        self.bound = None

    def commit(self, leaf):
        self.committed.append(leaf)

    def next_leaf(self):
        return max(self.committed, default=-1) + 1

    def bound_key(self):
        return self.bound

    def bind_key(self, identity):
        self.bound = identity


class MemoryBudget:
    """A minimal, in-process `StatelessBudgetStore`: durable enough for a
    test, not for production, since it holds no state past the Python
    process. A real deployment that lost this record would restart the
    few-time bound of specification section 21 at zero.

    Entries are keyed by the 32-byte budget key the library derives from the
    key's own stateless material, so one store serves every key here."""

    def __init__(self):
        self.spent = {}

    def consumed(self, key):
        return self.spent.get(key)

    def record(self, key, count):
        self.spent[key] = count


def test_profile_name_reports_a_shrincs_profile():
    assert phs.profile_name().startswith("shrincs-")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_stateless_sign_and_verify_round_trips(suite):
    seed = bytes(range(32))
    sk, pk = phs.keygen_from_seed(suite, seed)

    sig = phs.sign(suite, sk, b"message", b"context")
    assert phs.verify(suite, pk, b"message", b"context", sig)
    assert not phs.verify(suite, pk, b"different message", b"context", sig)

    det_sig = phs.sign_deterministic(suite, sk, b"message", b"context", b"nonce")
    assert phs.verify(suite, pk, b"message", b"context", det_sig)
    # Determinism: the same nonce reproduces the same signature.
    det_sig_2 = phs.sign_deterministic(suite, sk, b"message", b"context", b"nonce")
    assert det_sig == det_sig_2


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_stateless_keygen_accepts_bytearray_input(suite):
    seed = bytearray(range(32))
    sk, pk = phs.keygen_from_seed(suite, seed)
    sig = phs.sign(suite, sk, bytearray(b"message"), b"")
    assert phs.verify(suite, pk, b"message", b"", sig)


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_keygen_rejects_a_seed_of_the_wrong_length(suite):
    with pytest.raises(phs.BadLengthError):
        phs.keygen_from_seed(suite, b"\x00" * 31)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_sign_and_verify_round_trips(suite):
    seed = bytes(range(32))
    journal = MemoryJournal()
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, MemoryBudget())
    assert sk.suite == suite

    sig = sk.sign_stateful(b"message", b"context")
    assert phs.verify(suite, pk, b"message", b"context", sig)
    assert journal.committed == [0]

    # A second signature spends the next leaf, through the same bound
    # journal -- sign_stateful takes no journal argument of its own.
    sig_2 = sk.sign_stateful(b"message two", b"context")
    assert phs.verify(suite, pk, b"message two", b"context", sig_2)
    assert journal.committed == [0, 1]


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateless_path_on_a_stateful_suite_spends_no_leaf(suite):
    seed = bytes(range(32))
    journal = MemoryJournal()
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, MemoryBudget())

    sig_a = sk.sign_stateless(b"message", b"context")
    sig_b = sk.sign_stateless(b"message", b"context")
    assert phs.verify(suite, pk, b"message", b"context", sig_a)
    assert phs.verify(suite, pk, b"message", b"context", sig_b)
    assert journal.committed == [], "the stateless path must spend no leaf"


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateless_signing_charges_the_few_time_budget(suite):
    """The stateless path spends no leaf, but it is not free: it draws on
    the separate few-time bound of specification section 21, shared with
    rotation and recovery."""
    budget = MemoryBudget()
    sk, _pk = phs.keygen_stateful_from_seed(
        suite, bytes(range(32)), 4, MemoryJournal(), budget
    )
    assert budget.spent == {}, "a fresh key has spent nothing"

    sk.sign_stateless(b"message", b"context")
    assert list(budget.spent.values()) == [1]
    key = next(iter(budget.spent))
    assert len(key) == 32, "entries are keyed by the 32-byte budget key"

    sk.sign_stateless(b"message", b"context")
    assert budget.spent[key] == 2, "every stateless signature decrements"


def test_stateful_signing_does_not_charge_the_stateless_budget():
    """The two bounds are separate. Ordinary application signing spends
    leaves and must leave the stateless budget exactly where it was."""
    budget = MemoryBudget()
    sk, _pk = phs.keygen_stateful_from_seed(
        phs.Suite.H5, bytes(range(32)), 4, MemoryJournal(), budget
    )

    sk.sign_stateful(b"message", b"context")
    sk.sign_stateful(b"message two", b"context")

    assert budget.spent == {}


def test_an_exhausted_stateless_budget_is_refused_and_spends_nothing():
    """A store already at the bound refuses, with its own error type, and
    the refused attempt records nothing -- a bound that charged for the
    calls it rejected would shrink under retries."""

    class ExhaustedBudget(MemoryBudget):
        """Reports the whole bound already spent for every material, which
        is the only way to reach the boundary without producing 2**20
        signatures."""

        def consumed(self, key):
            return 1 << 20

    budget = ExhaustedBudget()
    sk, _pk = phs.keygen_stateful_from_seed(
        phs.Suite.H5, bytes(range(32)), 4, MemoryJournal(), budget
    )

    with pytest.raises(phs.StatelessBudgetExhaustedError):
        sk.sign_stateless(b"message", b"context")
    assert budget.spent == {}, "a refused attempt must record nothing"


def test_a_budget_store_that_cannot_record_refuses_the_signature():
    """A store failure is its own transient error, not the permanent
    exhausted one: the two demand opposite responses."""

    class FailingBudget(MemoryBudget):
        def record(self, key, count):
            raise RuntimeError("disk full")

    sk, _pk = phs.keygen_stateful_from_seed(
        phs.Suite.H5, bytes(range(32)), 4, MemoryJournal(), FailingBudget()
    )

    # The store's own exception is re-raised in preference to the flat ABI
    # code, exactly as a raising journal's is.
    with pytest.raises(RuntimeError, match="disk full"):
        sk.sign_stateless(b"message", b"context")


# Offset of the 32-byte commitment inside a SHRINCS bundle
# (statefulPublicKey(68) || commitment(32) || pkSeed || hypertreeRoot),
# mirroring pqhybridsign_shrincs::bundle::BUNDLE_COMMITMENT_OFFSET and
# pqhybridsign_abi::stateful_suites::tests::COMMITMENT_AT. This is
# spec-fixed layout shared by every SHRINCS instance (H5 and H6 alike), not
# a per-profile detail.
#
# No binding exposes an accessor that derives the small stored form from a
# verify-form public key -- see the task-4 report for why -- so this test
# reconstructs it the same way the ABI crate's own unit test does. A real
# deployment installs the stored form once, at provisioning time, from
# whatever produced the key; it does not slice it out of the verify form
# the way this helper does for test setup.
_COMMITMENT_AT = 68


def _stored_form(suite, verify_public_key):
    """The small form a verifier installs: the classical public key and
    the commitment, lifted out of a verify-form public key its own keygen
    produced."""
    classical_len = phs.stored_public_key_len(suite) - 32
    commitment_at = classical_len + _COMMITMENT_AT
    return verify_public_key[:classical_len] + verify_public_key[commitment_at : commitment_at + 32]


def _bundle(suite, verify_public_key):
    """The signer-supplied half: everything after the classical public
    key."""
    classical_len = phs.stored_public_key_len(suite) - 32
    return verify_public_key[classical_len:]


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_verify_with_stored_public_key_rejects_a_foreign_bundle(suite):
    """The stored form binds a bundle to the key the verifier installed.

    An attacker's own freshly generated key verifies its own signatures
    perfectly well through the unchecked whole-key path (`phs.verify`).
    This entry point is what ties the key on the wire to the key on the
    account.
    """
    seed = bytes(range(32))
    journal, budget = MemoryJournal(), MemoryBudget()
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, budget)
    sig = sk.sign_stateless(b"message", b"ctx")
    stored = _stored_form(suite, pk)
    assert len(stored) == phs.stored_public_key_len(suite)

    # Whole-key verification accepts the honest signature: the key and the
    # signature agree with each other, and nothing else is consulted.
    assert phs.verify(suite, pk, b"message", b"ctx", sig)

    assert phs.verify_with_stored_public_key(
        suite, stored, _bundle(suite, pk), b"message", b"ctx", sig
    )

    other_journal, other_budget = MemoryJournal(), MemoryBudget()
    _, attacker_pk = phs.keygen_stateful_from_seed(
        suite, bytes(range(1, 33)), 4, other_journal, other_budget
    )
    assert phs.verify(suite, attacker_pk, b"message", b"ctx", sig) is False

    # Against the victim's installed commitment, the attacker's own bundle
    # is refused even though it is a perfectly well-formed key of its own.
    assert not phs.verify_with_stored_public_key(
        suite, stored, _bundle(suite, attacker_pk), b"message", b"ctx", sig
    )


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_verify_with_stored_public_key_rejects_stateless_suites(suite):
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.verify_with_stored_public_key(
            suite, b"\x00" * 64, b"\x00" * 164, b"m", b"", b"\x00"
        )


def test_sign_stateless_cannot_be_reached_without_a_budget_store():
    """The store is bound at construction and is required there, so there
    is no way to reach the stateless path with the bound unenforced."""
    with pytest.raises(TypeError):
        phs.keygen_stateful_from_seed(
            phs.Suite.H5, bytes(range(32)), 4, MemoryJournal()
        )
    with pytest.raises(TypeError):
        phs.load_stateful_secret_key(phs.Suite.H5, b"\x00" * 8, MemoryJournal())


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_export_and_load_round_trips(suite):
    """A correct reload -- the same journal that produced the exported
    blob -- round-trips and keeps signing from the right leaf."""
    seed = bytes(range(32))
    journal = MemoryJournal()
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, MemoryBudget())
    sk.sign_stateful(b"message", b"context")

    blob = sk.export()
    reloaded = phs.load_stateful_secret_key(suite, blob, journal, MemoryBudget())
    assert reloaded.export() == blob

    sig = reloaded.sign_stateless(b"message", b"context")
    assert phs.verify(suite, pk, b"message", b"context", sig)

    # Signing through the reload spends leaf 1, not leaf 0 again.
    sig_2 = reloaded.sign_stateful(b"message two", b"context")
    assert phs.verify(suite, pk, b"message two", b"context", sig_2)
    assert journal.committed == [0, 1]


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_two_loads_of_one_blob_sharing_a_journal_refuse_the_fork(suite):
    """The confirmed pqhs-aww hazard: export() + load_stateful_secret_key()
    handed a fresh caller a second holder of the same leaf budget, with no
    way to notice. Binding the journal at load time cannot stop a caller
    from constructing two Python objects over one blob -- Python has no
    such enforcement -- but with the sanctioned pattern of reusing one
    journal across every load of a key, the second key to attempt a
    signature after its sibling already has must fail closed rather than
    reissue leaf 0 under a different message."""
    seed = bytes(range(32))
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, MemoryJournal(), MemoryBudget())
    blob = sk.export()

    shared_journal = MemoryJournal()
    phs.adopt_key(shared_journal, phs.key_identity_from_secret_key(suite, blob))
    fork_a = phs.load_stateful_secret_key(suite, blob, shared_journal, MemoryBudget())
    fork_b = phs.load_stateful_secret_key(suite, blob, shared_journal, MemoryBudget())

    sig_a = fork_a.sign_stateful(b"message one", b"context")
    assert phs.verify(suite, pk, b"message one", b"context", sig_a)
    assert shared_journal.committed == [0]

    # fork_b's own key counter is still 0 (it never signed), but the
    # shared journal it is bound to now reports next_leaf() == 1: the
    # divergence this key and journal now disagree on is exactly the
    # signal that stops the fork.
    with pytest.raises(phs.CountersDivergedError):
        fork_b.sign_stateful(b"message two", b"context")


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_two_fresh_journals_cannot_fork_one_keys_leaf_budget(suite):
    """The pqhs-aww reproduction.

    One exported blob, two journals that have each recorded nothing. Both
    truthfully report that leaf 0 is next -- which is also what the key's
    own journal reports for a key that has spent nothing -- so no
    comparison of counters can separate a legitimate restart from a second
    holder claiming the same one-time leaf. Before identity binding, both
    loads succeeded and both keys signed a different message under leaf 0,
    and both signatures verified against the same public key.

    Every leaf index here is signer-side and zero-based (`next_leaf()`),
    not the one-based `LeafCount` a signature carries on the wire.
    """
    seed = bytes(range(32))
    journal_a = MemoryJournal()
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal_a, MemoryBudget())
    blob = sk.export()

    j1, j2 = MemoryJournal(), MemoryJournal()
    assert j1.next_leaf() == j2.next_leaf() == 0
    assert j1.bound_key() is None and j2.bound_key() is None

    with pytest.raises(phs.JournalKeyMismatchError):
        phs.load_stateful_secret_key(suite, blob, j1, MemoryBudget())
    with pytest.raises(phs.JournalKeyMismatchError):
        phs.load_stateful_secret_key(suite, blob, j2, MemoryBudget())
    assert j1.committed == [] and j2.committed == []

    # The sanctioned restart -- reopening the key's own journal -- still
    # works, so the refusals above are the binding and not the load path
    # refusing everything.
    resumed = phs.load_stateful_secret_key(suite, blob, journal_a, MemoryBudget())
    sig = resumed.sign_stateful(b"message one", b"ctx")
    assert phs.verify(suite, pk, b"message one", b"ctx", sig)
    assert journal_a.committed == [0]

    # Adoption is still available, and is now a line the caller has to
    # write: forking the budget became a decision somebody made, not the
    # default outcome of restarting a process.
    phs.adopt_key(j1, phs.key_identity(suite, pk))
    assert phs.load_stateful_secret_key(suite, blob, j1, MemoryBudget()) is not None


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_a_journal_belongs_to_one_key(suite):
    """A journal adopted by one key refuses the other, both ways round."""
    journal_a = MemoryJournal()
    journal_b = MemoryJournal()
    sk_a, pk_a = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4, journal_a, MemoryBudget())
    sk_b, pk_b = phs.keygen_stateful_from_seed(
        suite, bytes(range(32, 64)), 4, journal_b, MemoryBudget()
    )

    id_a = phs.key_identity(suite, pk_a)
    id_b = phs.key_identity(suite, pk_b)
    assert id_a != id_b
    assert id_a == phs.key_identity_from_secret_key(suite, sk_a.export())
    assert journal_a.bound_key() == id_a
    assert journal_b.bound_key() == id_b

    with pytest.raises(phs.JournalKeyMismatchError):
        phs.load_stateful_secret_key(suite, sk_a.export(), journal_b, MemoryBudget())
    with pytest.raises(phs.JournalKeyMismatchError):
        phs.load_stateful_secret_key(suite, sk_b.export(), journal_a, MemoryBudget())

    # A journal belongs to one key for its whole life, so re-adopting is
    # refused and the existing binding stands.
    with pytest.raises(phs.JournalKeyMismatchError):
        phs.adopt_key(journal_a, id_b)
    assert journal_a.bound_key() == id_a

    # Re-adopting the same key is a no-op, so a provisioning step is safe
    # to re-run.
    phs.adopt_key(journal_a, id_a)
    assert journal_a.bound_key() == id_a


def test_keygen_refuses_a_journal_that_already_belongs_to_another_key():
    journal = MemoryJournal()
    phs.keygen_stateful_from_seed(phs.Suite.H5, bytes(range(32)), 4, journal, MemoryBudget())
    with pytest.raises(phs.JournalKeyMismatchError):
        phs.keygen_stateful_from_seed(phs.Suite.H5, bytes(range(32, 64)), 4, journal, MemoryBudget())


def test_adopt_key_rejects_an_identity_of_the_wrong_length():
    journal = MemoryJournal()
    _sk, pk = phs.keygen_stateful_from_seed(
        phs.Suite.H5, bytes(range(32)), 4, MemoryJournal(), MemoryBudget()
    )
    identity = phs.key_identity(phs.Suite.H5, pk)
    with pytest.raises(phs.BadLengthError):
        phs.adopt_key(journal, identity[:-1])
    assert journal.bound_key() is None


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_identity_entry_points_reject_stateless_suites(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.key_identity(suite, pk)
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.key_identity_from_secret_key(suite, sk)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_a_stale_blob_against_an_advanced_journal_is_refused(suite):
    seed = bytes(range(32))
    journal = MemoryJournal()
    sk, _pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, MemoryBudget())
    stale_blob = sk.export()  # leaf counter still 0

    sk.sign_stateful(b"message", b"context")  # journal now reports 1

    stale = phs.load_stateful_secret_key(suite, stale_blob, journal, MemoryBudget())
    with pytest.raises(phs.CountersDivergedError):
        stale.sign_stateful(b"message two", b"context")


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_an_advanced_blob_against_a_stale_journal_is_refused(suite):
    """A journal that never saw this key is refused at load, by identity.

    Once it is adopted -- an explicit act the caller has to write -- the
    lockstep counter check is what refuses it, because the adopted journal
    reports leaf 0 while the blob has already spent leaf 0.
    """
    seed = bytes(range(32))
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, MemoryJournal(), MemoryBudget())
    sk.sign_stateful(b"message", b"context")
    advanced_blob = sk.export()  # leaf counter now 1

    stale_journal = MemoryJournal()  # next_leaf() == 0, never bound
    with pytest.raises(phs.JournalKeyMismatchError):
        phs.load_stateful_secret_key(suite, advanced_blob, stale_journal, MemoryBudget())

    phs.adopt_key(stale_journal, phs.key_identity(suite, pk))
    reloaded = phs.load_stateful_secret_key(suite, advanced_blob, stale_journal, MemoryBudget())
    with pytest.raises(phs.CountersDivergedError):
        reloaded.sign_stateful(b"message two", b"context")


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_exhausting_the_leaf_budget_raises(suite):
    seed = bytes(range(32))
    sk, _pk = phs.keygen_stateful_from_seed(suite, seed, 1, MemoryJournal(), MemoryBudget())
    sk.sign_stateful(b"message", b"context")

    with pytest.raises(phs.LeavesExhaustedError):
        sk.sign_stateful(b"message two", b"context")


def test_keygen_stateful_rejects_a_stateless_suite():
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.keygen_stateful_from_seed(phs.Suite.H1, b"\x00" * 32, 4, MemoryJournal(), MemoryBudget())


def test_keygen_rejects_a_stateful_suite():
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.keygen_from_seed(phs.Suite.H5, b"\x00" * 32)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_secret_key_refuses_copy(suite):
    sk, _pk = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4, MemoryJournal(), MemoryBudget())
    with pytest.raises(phs.StatefulKeyNotCloneableError):
        copy.copy(sk)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_secret_key_refuses_deepcopy(suite):
    sk, _pk = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4, MemoryJournal(), MemoryBudget())
    with pytest.raises(phs.StatefulKeyNotCloneableError):
        copy.deepcopy(sk)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_secret_key_refuses_pickle(suite):
    sk, _pk = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4, MemoryJournal(), MemoryBudget())
    with pytest.raises(phs.StatefulKeyNotCloneableError):
        pickle.dumps(sk)


def test_suite_round_trips_every_value():
    """Pin PySuite names, integer codes, and from_code against the ABI.

    This is the running replacement for suite::tests::suite_round_trips_every_value,
    which cargo test --workspace cannot execute while the crate lib target
    has test = false (the extension-module link does not provide libpython).
    """
    for suite, code in SUITE_CODES:
        assert suite.value == code
        assert int(suite) == code
        assert phs.Suite.from_code(code) == suite
        assert phs.Suite.from_code(code).value == code


def test_suite_runtime_matches_the_stub():
    """Behaviour table for Suite. Fail this if the stub and the class drift."""
    h1 = phs.Suite.H1

    assert isinstance(h1, phs.Suite)
    assert not isinstance(h1, int)
    assert h1 == 1
    assert h1 == phs.Suite.H1
    assert h1 != phs.Suite.H2
    assert int(h1) == 1
    assert h1.value == 1
    assert phs.Suite.from_code(1) == h1
    assert hash(h1) == hash(1)
    assert {h1: "ok"}[h1] == "ok"
    assert {h1: "ok"}[1] == "ok"

    with pytest.raises(TypeError):
        phs.Suite(1)
    with pytest.raises(TypeError):
        h1 + 1
    with pytest.raises(TypeError):
        list(phs.Suite)
    with pytest.raises(TypeError):
        phs.Suite["H1"]
    with pytest.raises(phs.InvalidSuiteError):
        phs.Suite.from_code(0)
    with pytest.raises(phs.InvalidSuiteError):
        phs.Suite.from_code(7)


@pytest.mark.parametrize("suite", ALL_SUITES)
@pytest.mark.parametrize("pk", MALFORMED_BLOBS)
@pytest.mark.parametrize("sig", MALFORMED_BLOBS)
def test_verify_returns_false_for_malformed_pk_and_sig(suite, pk, sig):
    """verify() returns False, and never raises, for a malformed pk or sig."""
    assert phs.verify(suite, pk, b"message", b"context", sig) is False


def test_a_journal_that_raises_on_commit_propagates_its_exception():
    class RaisingJournal(MemoryJournal):
        def commit(self, leaf):
            raise RuntimeError("disk full")

    sk, _pk = phs.keygen_stateful_from_seed(
        phs.Suite.H5, bytes(range(32)), 4, RaisingJournal(), MemoryBudget()
    )
    with pytest.raises(RuntimeError, match="disk full"):
        sk.sign_stateful(b"message", b"context")


def test_every_native_export_is_re_exported_by_the_package():
    """`__init__.py` must re-export every public name the extension defines.

    The package is a hand-written re-export layer over the
    `_pqhybridsign` extension, so a name added on the Rust side is
    registered in three places: the `sub_exception!` or `#[pyfunction]`
    declaration, `errors::register`, and this package's import list and
    `__all__`. Missing the third builds cleanly and passes every other
    test, while `import pqhybridsign` cannot reach the name.
    """
    import pqhybridsign._pqhybridsign as native

    native_names = {n for n in dir(native) if not n.startswith("_")}
    missing = native_names - set(phs.__all__)
    assert not missing, f"native exports absent from __all__: {sorted(missing)}"


def test_every_name_in_all_is_importable():
    """Every name `__all__` promises must actually resolve on the package."""
    unresolved = [n for n in phs.__all__ if not hasattr(phs, n)]
    assert not unresolved, f"__all__ names that do not resolve: {unresolved}"
