# SPDX-License-Identifier: AGPL-3.0-or-later
import ast
import copy
import pickle
from pathlib import Path

import pytest

import pqhybridsign as phs

STATELESS_SUITES = [
    phs.Suite.ED_ML_44,
    phs.Suite.ED_FN_512,
    phs.Suite.SR_ML_44,
    phs.Suite.SR_FN_512,
]
STATEFUL_SUITES = [phs.Suite.ED_SH, phs.Suite.SR_SH]
ALL_SUITES = STATELESS_SUITES + STATEFUL_SUITES

# Integer codes pinned by pqhybridsign_abi::Suite. Changing any of these
# silently renumbers the Python-visible suite codes and the C ABI.
SUITE_CODES = (
    (phs.Suite.ED_ML_44, 1),
    (phs.Suite.ED_FN_512, 2),
    (phs.Suite.SR_ML_44, 3),
    (phs.Suite.SR_FN_512, 4),
    (phs.Suite.ED_SH, 5),
    (phs.Suite.SR_SH, 6),
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
    # Plain `verify` accepts only the stateful path for ED_SH/SR_SH
    # (specification section 20.2): a stateless-path signature verifies
    # only through `verify_stateless`.
    assert phs.verify(suite, pk, b"message", b"context", sig_a) is False
    assert phs.verify_stateless(suite, pk, b"message", b"context", sig_a)
    assert phs.verify_stateless(suite, pk, b"message", b"context", sig_b)
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
        phs.Suite.ED_SH, bytes(range(32)), 4, MemoryJournal(), budget
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
        phs.Suite.ED_SH, bytes(range(32)), 4, MemoryJournal(), budget
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
        phs.Suite.ED_SH, bytes(range(32)), 4, MemoryJournal(), FailingBudget()
    )

    # The store's own exception is re-raised in preference to the flat ABI
    # code, exactly as a raising journal's is.
    with pytest.raises(RuntimeError, match="disk full"):
        sk.sign_stateless(b"message", b"context")


def _stored_form(suite, verify_public_key):
    """The small form a verifier installs: the classical public key and
    the commitment, recomputed from a verify-form public key its own
    keygen produced."""
    return phs.stored_public_key(suite, verify_public_key)


def _bundle(suite, verify_public_key):
    """The signer-supplied half: everything after the classical public
    key."""
    classical_len = phs.stored_public_key_len(suite) - 32
    return verify_public_key[classical_len:]


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_verify_with_stored_public_key_rejects_a_foreign_bundle(suite):
    """The stored form binds a bundle to the key the verifier installed.

    An attacker's own freshly generated key verifies its own signatures
    perfectly well through the unchecked whole-key path
    (`phs.verify_stateless`). This entry point is what ties the key on the
    wire to the key on the account.
    """
    seed = bytes(range(32))
    journal, budget = MemoryJournal(), MemoryBudget()
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, budget)
    sig = sk.sign_stateless(b"message", b"ctx")
    stored = _stored_form(suite, pk)
    assert len(stored) == phs.stored_public_key_len(suite)

    # Whole-key verification accepts the honest signature: the key and the
    # signature agree with each other, and nothing else is consulted. Plain
    # `phs.verify` accepts only the stateful path for ED_SH/SR_SH (specification
    # section 20.2), so a stateless-path signature verifies only through
    # `verify_stateless`.
    assert phs.verify(suite, pk, b"message", b"ctx", sig) is False
    assert phs.verify_stateless(suite, pk, b"message", b"ctx", sig)

    assert phs.verify_with_stored_public_key_stateless(
        suite, stored, _bundle(suite, pk), b"message", b"ctx", sig
    )
    # The stateful-path entry point must refuse this same stateless-path
    # signature, by selector, before either component signature is checked.
    assert not phs.verify_with_stored_public_key_stateful(
        suite, stored, _bundle(suite, pk), b"message", b"ctx", sig
    )

    # The mirror image: a stateful-path signature verifies only through the
    # stateful entry points, and is refused by the stateless ones.
    stateful_sig = sk.sign_stateful(b"stateful message", b"ctx")
    assert phs.verify(suite, pk, b"stateful message", b"ctx", stateful_sig)
    assert phs.verify_stateful(suite, pk, b"stateful message", b"ctx", stateful_sig)
    assert not phs.verify_stateless(
        suite, pk, b"stateful message", b"ctx", stateful_sig
    )
    assert phs.verify_with_stored_public_key_stateful(
        suite, stored, _bundle(suite, pk), b"stateful message", b"ctx", stateful_sig
    )
    assert not phs.verify_with_stored_public_key_stateless(
        suite, stored, _bundle(suite, pk), b"stateful message", b"ctx", stateful_sig
    )

    other_journal, other_budget = MemoryJournal(), MemoryBudget()
    _, attacker_pk = phs.keygen_stateful_from_seed(
        suite, bytes(range(1, 33)), 4, other_journal, other_budget
    )
    assert phs.verify_stateless(suite, attacker_pk, b"message", b"ctx", sig) is False

    # Against the victim's installed commitment, the attacker's own bundle
    # is refused even though it is a perfectly well-formed key of its own.
    assert not phs.verify_with_stored_public_key_stateless(
        suite, stored, _bundle(suite, attacker_pk), b"message", b"ctx", sig
    )


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_verify_with_stored_public_key_rejects_stateless_suites(suite):
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.verify_with_stored_public_key_stateful(
            suite, b"\x00" * 64, b"\x00" * 164, b"m", b"", b"\x00"
        )
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.verify_with_stored_public_key_stateless(
            suite, b"\x00" * 64, b"\x00" * 164, b"m", b"", b"\x00"
        )


def test_sign_stateless_cannot_be_reached_without_a_budget_store():
    """The store is bound at construction and is required there, so there
    is no way to reach the stateless path with the bound unenforced."""
    with pytest.raises(TypeError):
        phs.keygen_stateful_from_seed(
            phs.Suite.ED_SH, bytes(range(32)), 4, MemoryJournal()
        )
    with pytest.raises(TypeError):
        phs.load_stateful_secret_key(phs.Suite.ED_SH, b"\x00" * 8, MemoryJournal())


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
    assert phs.verify_stateless(suite, pk, b"message", b"context", sig)

    # Signing through the reload spends leaf 1, not leaf 0 again.
    sig_2 = reloaded.sign_stateful(b"message two", b"context")
    assert phs.verify(suite, pk, b"message two", b"context", sig_2)
    assert journal.committed == [0, 1]


def test_stateful_key_signs_repeatedly_without_reimporting():
    """A key object holds its imported form, so a second signature is cheap.

    This does not time anything: a timing assertion at profile-256s would
    measure nothing, and at a 128s profile it would take 94 seconds to fail.
    It asserts the observable consequence instead. Two signatures from one
    object both verify, the exported blob advances between them, and a fresh
    object built from that blob continues rather than restarting.
    """
    suite = phs.Suite.ED_SH
    seed = bytes(range(32))
    journal = MemoryJournal()
    budget = MemoryBudget()
    key, pk = phs.keygen_stateful_from_seed(suite, seed, 4, journal, budget)

    before = key.export()

    sig1 = key.sign_stateful(b"first", b"ctx")
    assert phs.verify(suite, pk, b"first", b"ctx", sig1)

    after = key.export()
    assert after != before, "the key did not advance"

    sig2 = key.sign_stateful(b"second", b"ctx")
    assert phs.verify(suite, pk, b"second", b"ctx", sig2)
    assert sig1 != sig2

    reopened = phs.load_stateful_secret_key(suite, key.export(), journal, budget)
    sig3 = reopened.sign_stateful(b"third", b"ctx")
    assert phs.verify(suite, pk, b"third", b"ctx", sig3)


def test_stateful_key_rejects_a_stateless_suite():
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.load_stateful_secret_key(
            phs.Suite.ED_ML_44, bytes(32), MemoryJournal(), MemoryBudget()
        )


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
    phs.keygen_stateful_from_seed(
        phs.Suite.ED_SH, bytes(range(32)), 4, journal, MemoryBudget()
    )
    with pytest.raises(phs.JournalKeyMismatchError):
        phs.keygen_stateful_from_seed(
            phs.Suite.ED_SH, bytes(range(32, 64)), 4, journal, MemoryBudget()
        )


def test_adopt_key_rejects_an_identity_of_the_wrong_length():
    journal = MemoryJournal()
    _sk, pk = phs.keygen_stateful_from_seed(
        phs.Suite.ED_SH, bytes(range(32)), 4, MemoryJournal(), MemoryBudget()
    )
    identity = phs.key_identity(phs.Suite.ED_SH, pk)
    with pytest.raises(phs.BadLengthError):
        phs.adopt_key(journal, identity[:-1])
    assert journal.bound_key() is None


def test_adopt_key_does_not_bind_when_bound_key_raises():
    """A read fault during adoption must not reach bind_key.

    The bridge reports a raising bound_key() to the abi as None, which reads
    as never-bound. If adopt_key proceeded on that, it would overwrite the
    binding of an already-bound journal and defeat the JournalKeyMismatch
    guard."""

    class FaultyJournal:
        def __init__(self):
            self.bind_calls = []

        def commit(self, leaf):
            return None

        def next_leaf(self):
            return 0

        def bound_key(self):
            raise OSError("transient read fault")

        def bind_key(self, identity):
            self.bind_calls.append(identity)

    journal = FaultyJournal()
    identity = bytes(32)

    with pytest.raises(OSError, match="transient read fault"):
        phs.adopt_key(journal, identity)

    assert journal.bind_calls == [], "bind_key must never be reached"


def test_adopt_key_does_not_overwrite_a_bound_journal_when_a_later_read_faults():
    """The always-raising fixture above only exercises the case where the
    very first read of an adoption fails. It cannot tell a guard that reads
    bound_key() once apart from one that reads it twice: if adopt_key read
    bound_key() a second time -- once for its own guard, once inside the
    abi -- a transient fault landing on that second read would still
    overwrite an already-bound journal, after the guard's first read had
    already reported it safely bound. This journal succeeds once and then
    raises, so it only fails the test if bound_key is read more than once.

    Which exception surfaces depends on how many reads happen: a fault on a
    second read raises the fixture's OSError; a single, cached read instead
    correctly reports the existing binding and adopt_key raises
    JournalKeyMismatchError. Either way, bind_key must never be reached and
    the existing binding must survive."""

    class SucceedsOnceThenFaultsJournal:
        def __init__(self, bound):
            self.bound = bound
            self.bind_calls = []
            self.bound_key_calls = 0

        def commit(self, leaf):
            return None

        def next_leaf(self):
            return 0

        def bound_key(self):
            self.bound_key_calls += 1
            if self.bound_key_calls >= 2:
                raise OSError("transient read fault")
            return self.bound

        def bind_key(self, identity):
            self.bind_calls.append(identity)

    other_identity = bytes(range(32))
    new_identity = bytes(32)
    journal = SucceedsOnceThenFaultsJournal(bound=other_identity)

    with pytest.raises((OSError, phs.JournalKeyMismatchError)):
        phs.adopt_key(journal, new_identity)

    assert journal.bind_calls == [], "bind_key must never be reached"
    assert journal.bound == other_identity, "the existing binding must survive"


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
        phs.keygen_stateful_from_seed(
            phs.Suite.ED_ML_44, b"\x00" * 32, 4, MemoryJournal(), MemoryBudget()
        )


def test_keygen_rejects_a_stateful_suite():
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.keygen_from_seed(phs.Suite.ED_SH, b"\x00" * 32)


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


def test_suite_members_are_named_for_their_algorithms():
    # The integer value is an ABI value and must survive the rename.
    assert int(phs.Suite.ED_ML_44) == 1
    assert int(phs.Suite.SR_SH) == 6
    assert not hasattr(phs.Suite, "H1")


def test_suite_runtime_matches_the_stub():
    """Behaviour table for Suite. Fail this if the stub and the class drift."""
    ed_ml_44 = phs.Suite.ED_ML_44

    assert isinstance(ed_ml_44, phs.Suite)
    assert not isinstance(ed_ml_44, int)
    assert ed_ml_44 == 1
    assert ed_ml_44 == phs.Suite.ED_ML_44
    assert ed_ml_44 != phs.Suite.ED_FN_512
    assert int(ed_ml_44) == 1
    assert ed_ml_44.value == 1
    assert phs.Suite.from_code(1) == ed_ml_44
    assert hash(ed_ml_44) == hash(1)
    assert {ed_ml_44: "ok"}[ed_ml_44] == "ok"
    assert {ed_ml_44: "ok"}[1] == "ok"

    with pytest.raises(TypeError):
        phs.Suite(1)
    with pytest.raises(TypeError):
        ed_ml_44 + 1
    with pytest.raises(TypeError):
        list(phs.Suite)
    with pytest.raises(TypeError):
        phs.Suite["ED_ML_44"]
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
        phs.Suite.ED_SH, bytes(range(32)), 4, RaisingJournal(), MemoryBudget()
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


# Names the `.pyi` stub legitimately declares without exporting them
# through the package namespace. A name earns a place here for one of two
# reasons: it is a typing helper a signature needs but nothing ever
# imports (there are none of those among the top-level `class`/`def`
# nodes the check below scans -- `ReadableBuffer` is a plain assignment,
# not a class or function, so it never reaches `stub_names` and needs no
# entry here), or it is a structural `Protocol` class callers implement
# against but never construct or import (`LeafJournal`,
# `StatelessBudgetStore`). Anything else added here would hide a stale
# stub entry a rename or removal left behind -- exactly the defect this
# test exists to catch.
ALLOWED_STUB_ONLY = frozenset({"LeafJournal", "StatelessBudgetStore"})


def test_every_name_in_all_appears_in_the_type_stub():
    """`__init__.pyi` is hand-maintained, so a name added to `__all__`
    without a matching stub entry silently loses editor completion and
    static type checking, with no other test in this file noticing. The
    reverse direction matters too: a stub entry a rename or removal left
    behind offers editor completion for a symbol that raises
    `AttributeError` at runtime.
    """
    package_file = phs.__file__
    assert package_file is not None, "pqhybridsign has no resolvable file location"
    stub_path = Path(package_file).with_name("__init__.pyi")
    tree = ast.parse(stub_path.read_text())
    stub_names = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = set(phs.__all__) - stub_names
    assert not missing, f"__all__ names missing from the .pyi stub: {sorted(missing)}"

    stale = stub_names - set(phs.__all__) - ALLOWED_STUB_ONLY
    assert not stale, f"stub names with no runtime counterpart: {sorted(stale)}"


# The standard all-zero-entropy BIP39 test vector, matching
# pqhybridsign_abi::seed's own tests.
BIP39_PHRASE = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)


def test_master_seed_from_mnemonic_is_stable():
    """The same phrase and password reach the same seed on every call: the
    property a recovery flow depends on."""
    seed = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    assert len(seed) == 32
    assert seed != b"\x00" * 32
    again = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    assert seed == again


# `crates/pqhybridsign/src/mnemonic.rs`'s own `PHRASE_12` golden-vector
# phrase, copied verbatim rather than retyped. The core crate pins that a
# derivation over this phrase's entropy (not its text) matches
# `quip-validator`'s own `master_seed_from_mnemonic`
# (crates/transaction-crypto-core/src/lib.rs, on top of substrate-bip39
# 0.6.1), generated 2026-08-21; this test pins that this binding's call
# reaches that same derivation rather than mangling an argument along the
# way (swapping `phrase`/`password`, truncating the result, or returning a
# different call's output all satisfy "32 bytes, not all zeros, stable"
# without this). Do not "fix" a failing assertion here by pasting in
# whatever the code currently returns -- that is exactly the failure mode
# a pinned vector exists to catch.
PHRASE_12 = "bottom drive obey lake curtain smoke basket hold race lonely fit walk"


def test_master_seed_from_mnemonic_matches_the_core_crates_golden_vector():
    seed = phs.master_seed_from_mnemonic(PHRASE_12)
    assert seed.hex() == "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e"


def test_master_seed_from_mnemonic_rejects_an_invalid_phrase():
    with pytest.raises(phs.InvalidMnemonicError):
        phs.master_seed_from_mnemonic("not a mnemonic at all")


def test_master_seed_from_mnemonic_password_changes_the_seed():
    without = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    with_password = phs.master_seed_from_mnemonic(BIP39_PHRASE, "pw")
    assert without != with_password


def test_a_junction_child_differs_from_its_parent_and_its_sibling():
    parent = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    a = phs.derive_hard_junction(parent, bytes([1]) * 32)
    b = phs.derive_hard_junction(parent, bytes([2]) * 32)
    assert a != parent
    assert b != parent
    assert a != b


def test_a_junction_path_equals_the_stepwise_derivation():
    parent = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    first = bytes([1]) * 32
    second = bytes([2]) * 32

    intermediate = phs.derive_hard_junction(parent, first)
    stepwise = phs.derive_hard_junction(intermediate, second)

    path = phs.derive_hard_junction_path(parent, [first, second])
    assert path == stepwise

    # Order is part of the derivation.
    reversed_path = phs.derive_hard_junction_path(parent, [second, first])
    assert reversed_path != path


def test_an_empty_junction_path_returns_the_parent():
    """Documented, not accidental: a caller that parsed an empty path gets
    the parent key back rather than an error, and must check for that
    itself."""
    parent = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    assert phs.derive_hard_junction_path(parent, []) == parent


def test_a_wrong_length_chain_code_raises_value_error_naming_the_index():
    parent = phs.master_seed_from_mnemonic(BIP39_PHRASE)
    good = bytes([1]) * 32
    short = bytes([2]) * 31
    with pytest.raises(ValueError, match="index 1"):
        phs.derive_hard_junction_path(parent, [good, short])


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_a_vrf_proof_verifies(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = phs.vrf_prove(suite, sk, b"input")
    assert len(proof) <= phs.vrf_proof_len(suite)
    assert phs.vrf_verify(suite, pk, b"input", proof)


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_a_tampered_vrf_proof_does_not_verify(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = bytearray(phs.vrf_prove(suite, sk, b"input"))
    proof[0] ^= 0x01
    assert phs.vrf_verify(suite, pk, b"input", bytes(proof)) is False


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_is_stable_across_two_proofs_of_one_input(suite):
    """Two evaluations of one input under one key give the same output, so
    a prover cannot re-roll for a better value -- the property the
    construction rests on, and it holds regardless of whether the suite
    hedges its classical proof's nonce."""
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof_a = phs.vrf_prove(suite, sk, b"input")
    proof_b = phs.vrf_prove(suite, sk, b"input")
    out_a = phs.vrf_make_bytes(suite, pk, b"input", proof_a, b"context")
    out_b = phs.vrf_make_bytes(suite, pk, b"input", proof_b, b"context")
    assert out_a == out_b


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_context_separates_two_uses_of_one_proof(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = phs.vrf_prove(suite, sk, b"input")
    score = phs.vrf_make_bytes(suite, pk, b"input", proof, b"leadership")
    randomness = phs.vrf_make_bytes(suite, pk, b"input", proof, b"randomness")
    assert score != randomness


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_refuses_a_proof_that_does_not_verify(suite):
    """make_bytes verifies before it derives. A proof with its last byte
    flipped still carries a decodable pre-output, so only a check over the
    whole proof refuses it."""
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = bytearray(phs.vrf_prove(suite, sk, b"input"))
    proof[-1] ^= 0x01
    with pytest.raises(phs.InvalidProofError):
        phs.vrf_make_bytes(suite, pk, b"input", bytes(proof), b"context")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_refuses_a_proof_whose_classical_field_is_altered(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = bytearray(phs.vrf_prove(suite, sk, b"input"))
    assert len(phs.vrf_make_bytes(suite, pk, b"input", bytes(proof), b"context")) == 32
    proof[32] ^= 0x01
    with pytest.raises(phs.InvalidProofError):
        phs.vrf_make_bytes(suite, pk, b"input", bytes(proof), b"context")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_refuses_a_valid_key_that_is_not_the_signer(suite):
    sk, _pk = phs.keygen_from_seed(suite, bytes(range(32)))
    _other_sk, other_pk = phs.keygen_from_seed(suite, bytes(range(32, 64)))
    proof = phs.vrf_prove(suite, sk, b"input")
    with pytest.raises(phs.InvalidProofError):
        phs.vrf_make_bytes(suite, other_pk, b"input", proof, b"context")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_refuses_a_public_key_that_does_not_decode(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = phs.vrf_prove(suite, sk, b"input")
    pk = b"\xff" * len(pk)
    with pytest.raises(phs.InvalidProofError):
        phs.vrf_make_bytes(suite, pk, b"input", proof, b"context")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_refuses_a_pre_output_that_does_not_decode(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = bytearray(phs.vrf_prove(suite, sk, b"input"))
    proof[:32] = b"\xff" * 32
    with pytest.raises(phs.InvalidProofError):
        phs.vrf_make_bytes(suite, pk, b"input", bytes(proof), b"context")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_make_bytes_refuses_a_proof_for_another_input(suite):
    sk, pk = phs.keygen_from_seed(suite, bytes(range(32)))
    proof = phs.vrf_prove(suite, sk, b"other input")
    with pytest.raises(phs.InvalidProofError):
        phs.vrf_make_bytes(suite, pk, b"input", proof, b"context")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_prove_deterministic_repeats_byte_for_byte(suite):
    sk, _pk = phs.keygen_from_seed(suite, bytes(range(32)))
    a = phs.vrf_prove_deterministic(suite, sk, b"input")
    b = phs.vrf_prove_deterministic(suite, sk, b"input")
    assert a == b


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_vrf_prove_rejects_the_stateful_suites(suite):
    """ED_SH and SR_SH spend a few-time budget unit per evaluation and prove
    through `VrfStatelessKey.prove` instead: a call that looked free and
    was not would be the worst failure mode this module could offer."""
    # The suite refusal happens before any length check, so this secret
    # key's length is irrelevant -- short and obviously a dummy on purpose.
    dummy_secret_key = b"\x00" * 8
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.vrf_prove(suite, dummy_secret_key, b"input")
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.vrf_prove_deterministic(suite, dummy_secret_key, b"input")


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_stateless_key_derive_rejects_the_stateless_suites(suite):
    """`VrfStatelessKey.derive` has no Python test that runs a real keygen:
    a successful call costs about 47 seconds at a 128s profile. This
    reject path returns before that work, so it is the cheap way to prove
    `suite` and `master` genuinely reach `pqhybridsign_abi::VrfStatelessKey::derive`
    and that the error is mapped correctly at this call site, rather than
    somewhere else in the module that happens to be tested. Do not delete
    this as redundant reject-path noise: it is the only coverage `derive`
    has."""
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.VrfStatelessKey.derive(suite, bytes(32))


def test_vrf_stateless_key_derive_rejects_a_wrong_length_master():
    """The companion to the suite-rejection test above: proves the 32-byte
    length check on `master` fires, and fires before the expensive keygen,
    for the same reason -- this is the only coverage `derive` has, and it
    is deliberately kept even though it looks like boilerplate."""
    with pytest.raises(phs.BadLengthError):
        phs.VrfStatelessKey.derive(phs.Suite.ED_SH, bytes(31))


@pytest.mark.parametrize("suite", STATELESS_SUITES)
def test_vrf_stateless_key_derive_rejects_the_suite_before_the_master_length(suite):
    """`master` is 31 bytes, not the required 32, and `suite` is one this
    entry point does not serve. Before this fix this call raised
    BadLengthError; it now raises WrongEntryPointForSuiteError."""
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.VrfStatelessKey.derive(suite, bytes(31))
