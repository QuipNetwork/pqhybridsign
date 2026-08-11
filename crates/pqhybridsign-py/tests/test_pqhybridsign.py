# SPDX-License-Identifier: AGPL-3.0-or-later
import copy
import pickle

import pytest

import pqhybridsign as phs

STATELESS_SUITES = [phs.Suite.H1, phs.Suite.H2, phs.Suite.H3, phs.Suite.H4]
STATEFUL_SUITES = [phs.Suite.H5, phs.Suite.H6]


class MemoryJournal:
    """A minimal, in-process `LeafJournal`: durable enough for a test, not
    for production use, since it holds no state past the Python process."""

    def __init__(self):
        self.committed = []

    def commit(self, leaf):
        self.committed.append(leaf)

    def next_leaf(self):
        return max(self.committed, default=-1) + 1


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
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4)
    assert sk.suite == suite

    journal = MemoryJournal()
    sig = sk.sign_stateful(b"message", b"context", journal)
    assert phs.verify(suite, pk, b"message", b"context", sig)
    assert journal.committed == [0]

    # A second signature spends the next leaf.
    sig_2 = sk.sign_stateful(b"message two", b"context", journal)
    assert phs.verify(suite, pk, b"message two", b"context", sig_2)
    assert journal.committed == [0, 1]


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateless_path_on_a_stateful_suite_spends_no_leaf(suite):
    seed = bytes(range(32))
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4)

    sig_a = sk.sign_stateless(b"message", b"context")
    sig_b = sk.sign_stateless(b"message", b"context")
    assert phs.verify(suite, pk, b"message", b"context", sig_a)
    assert phs.verify(suite, pk, b"message", b"context", sig_b)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_export_and_load_round_trips(suite):
    seed = bytes(range(32))
    sk, pk = phs.keygen_stateful_from_seed(suite, seed, 4)

    journal = MemoryJournal()
    sk.sign_stateful(b"message", b"context", journal)

    blob = sk.export()
    reloaded = phs.load_stateful_secret_key(suite, blob)
    assert reloaded.export() == blob

    sig = reloaded.sign_stateless(b"message", b"context")
    assert phs.verify(suite, pk, b"message", b"context", sig)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_exhausting_the_leaf_budget_raises(suite):
    seed = bytes(range(32))
    sk, _pk = phs.keygen_stateful_from_seed(suite, seed, 1)
    journal = MemoryJournal()
    sk.sign_stateful(b"message", b"context", journal)

    with pytest.raises(phs.LeavesExhaustedError):
        sk.sign_stateful(b"message two", b"context", journal)


def test_keygen_stateful_rejects_a_stateless_suite():
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.keygen_stateful_from_seed(phs.Suite.H1, b"\x00" * 32, 4)


def test_keygen_rejects_a_stateful_suite():
    with pytest.raises(phs.WrongEntryPointForSuiteError):
        phs.keygen_from_seed(phs.Suite.H5, b"\x00" * 32)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_secret_key_refuses_copy(suite):
    sk, _pk = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4)
    with pytest.raises(phs.StatefulKeyNotCloneableError):
        copy.copy(sk)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_secret_key_refuses_deepcopy(suite):
    sk, _pk = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4)
    with pytest.raises(phs.StatefulKeyNotCloneableError):
        copy.deepcopy(sk)


@pytest.mark.parametrize("suite", STATEFUL_SUITES)
def test_stateful_secret_key_refuses_pickle(suite):
    sk, _pk = phs.keygen_stateful_from_seed(suite, bytes(range(32)), 4)
    with pytest.raises(phs.StatefulKeyNotCloneableError):
        pickle.dumps(sk)


def test_a_journal_that_raises_on_commit_propagates_its_exception():
    class RaisingJournal:
        def commit(self, leaf):
            raise RuntimeError("disk full")

        def next_leaf(self):
            return 0

    sk, _pk = phs.keygen_stateful_from_seed(phs.Suite.H5, bytes(range(32)), 4)
    with pytest.raises(RuntimeError, match="disk full"):
        sk.sign_stateful(b"message", b"context", RaisingJournal())
