// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signing for the two stateful suites, H5 and H6.
//!
//! H5 and H6 pair a classical scheme with SHRINCS, whose post-quantum half
//! spends a one-time leaf per signature (see the crate documentation).
//! [`pqhs_sign_stateful`] and [`pqhs_stateful_key_sign`] are the entry
//! points that spend one, and they take a [`PqhsLeafJournal`] -- a durable
//! log of spent leaves the caller owns -- because losing track of which
//! leaves are spent is exactly the failure this suite exists to prevent.
//! [`pqhs_sign_stateless`] and [`pqhs_stateful_key_sign_stateless`] use
//! SHRINCS's separate few-time path instead and spend nothing.

use std::os::raw::{c_int, c_void};

use pqhybridsign_abi::{
    BudgetKey, KeyIdentity, LeafJournal, StatelessBudgetStore, KEY_IDENTITY_LEN,
};

use crate::error::{PQHS_ERR_ALIASED_BUFFERS, PQHS_ERR_BAD_LENGTH, PQHS_ERR_NULL_POINTER, PQHS_OK};
use crate::ffi::{borrow_slice, borrow_slice_mut, guard, ranges_overlap, write_out};
use crate::suite::suite_from_code;

/// Width in bytes of a key identity: the value
/// [`PqhsLeafJournal::bound_key`] reports, [`PqhsLeafJournal::bind_key`]
/// stores, and [`pqhs_key_identity`] writes.
///
/// Written as a literal rather than as an alias for
/// `pqhybridsign_abi::KEY_IDENTITY_LEN`, because cbindgen copies the
/// initialising expression into the header verbatim and a C compiler has no
/// `KEY_IDENTITY_LEN` to expand. The assertion below is what keeps the two in
/// step: a change upstream fails this build rather than shipping a header
/// that disagrees with the library.
pub const PQHS_KEY_IDENTITY_LEN: usize = 32;

const _: () = assert!(PQHS_KEY_IDENTITY_LEN == KEY_IDENTITY_LEN);

/// A caller-owned durable log of spent one-time leaves, passed to
/// [`pqhs_sign_stateful`].
///
/// `commit` MUST NOT return until the leaf is durably recorded -- on disk,
/// in a database, wherever the caller's integration keeps this state --
/// because a crash after `commit` returns `0` but before the write reaches
/// stable storage would let a later run replay an already-spent leaf, which
/// is a total loss of the key's post-quantum security. Returning nonzero
/// from `commit` MUST mean nothing was recorded.
///
/// A journal also records **which key** it belongs to, through `bound_key`
/// and `bind_key`. That binding is as durable as the counter and is what
/// separates a journal correctly reopened for its own key from a brand-new
/// one handed the same key by mistake: both report `0` from `next_leaf` for a
/// key that has spent nothing, and signing under the second reissues every
/// leaf the first spent. [`pqhs_sign_stateful`] refuses a journal that is not
/// bound to the key it was handed, with `PQHS_ERR_JOURNAL_KEY_MISMATCH`;
/// [`pqhs_adopt_key`] is the one call that creates a binding.
///
/// `ctx` is passed back unchanged to every callback and is never
/// dereferenced by this crate; it exists so a caller can close over its own
/// state without a second, language-specific registration mechanism.
///
/// # No callback may re-enter this library
///
/// `commit`, `next_leaf`, `bound_key` and `bind_key` MUST NOT call any
/// `pqhs_*` function, directly
/// or indirectly. All run while [`pqhs_sign_stateful`] holds live
/// references to the caller's `sk`, `sk_out` and `sig_out` buffers, so a
/// callback that re-enters with any of those buffers is the same aliasing
/// undefined behaviour `PQHS_ERR_ALIASED_BUFFERS` exists to catch on the
/// argument list -- and nothing detects it from inside a callback. A
/// callback that re-enters with the same journal is worse still: it spends
/// leaves in an order the outer call does not expect, which is exactly the
/// leaf reuse the journal exists to prevent. Do the work the callback needs
/// (the durable write) and return.
///
/// # Threading
///
/// Both callbacks are plain C calls made on whatever thread called
/// [`pqhs_sign_stateful`]; this library starts no threads and hands the
/// `ctx` pointer to nothing else.
///
/// Every buffer-based entry point in this library is stateless -- keys,
/// signatures and leaf state live only in the caller's own buffers, for the
/// duration of one call -- so calls on different threads over different
/// buffers do not interact. The one piece of process-wide state is the
/// cached string behind [`pqhs_profile_name`](crate::pqhs_profile_name),
/// which is initialised once and never mutated.
///
/// [`PqhsStatefulKey`] and [`crate::PqhsVrfKey`] break that isolation on
/// purpose: an open handle keeps its leaf or stateless-budget state inside
/// itself rather than in a caller buffer, for as long as it stays open, so
/// it belongs to one thread at a time. See [`PqhsStatefulKey`]'s own
/// documentation.
///
/// What is *not* thread-safe otherwise is the caller's own journal. Two
/// threads signing with the same journal, or with two copies of the same
/// stateful secret key, can be handed the same leaf. Serialising access to
/// a journal and to the key blob or handle it tracks is the caller's
/// responsibility, and it is not optional: a reused leaf is a total loss of
/// the key's post-quantum security.
#[repr(C)]
pub struct PqhsLeafJournal {
    /// Opaque caller state, passed unchanged to every callback.
    pub ctx: *mut c_void,
    /// Durably record that `leaf` is consumed. Returns `0` on success, or
    /// any nonzero value to report the leaf was not recorded.
    pub commit: Option<extern "C" fn(ctx: *mut c_void, leaf: u32) -> c_int>,
    /// The next unused leaf, as last committed. `0` for a fresh journal.
    pub next_leaf: Option<extern "C" fn(ctx: *mut c_void) -> u32>,
    /// Report the key this journal belongs to. Returns `0` and writes exactly
    /// `PQHS_KEY_IDENTITY_LEN` bytes to `out` if a binding exists, or any
    /// nonzero value -- writing nothing -- if the journal has never been
    /// bound.
    ///
    /// Nonzero MUST mean "never bound", never "could not read". A storage
    /// error reported as "never bound" invites [`pqhs_adopt_key`] to write a
    /// binding over one that already exists, which is what forks the leaf
    /// budget. Fail before constructing the journal instead.
    pub bound_key: Option<extern "C" fn(ctx: *mut c_void, out: *mut u8, out_len: usize) -> c_int>,
    /// Durably record that this journal belongs to the
    /// `PQHS_KEY_IDENTITY_LEN`-byte identity at `key`. Returns `0` once the
    /// write is durable, or any nonzero value to report that nothing was
    /// written. The same durability rule `commit` follows.
    pub bind_key: Option<extern "C" fn(ctx: *mut c_void, key: *const u8, key_len: usize) -> c_int>,
}

/// Wraps a caller's `&PqhsLeafJournal` as a
/// [`pqhybridsign_abi::LeafJournal`]. `ctx` is an opaque caller-owned
/// pointer that this crate never dereferences, and the callbacks it is
/// passed to are plain C function calls, so this type carries no
/// thread-safety obligation of its own beyond what the single call using it
/// already has.
struct FfiJournal<'a>(&'a PqhsLeafJournal);

impl LeafJournal for FfiJournal<'_> {
    /// The callback reported failure; no further detail crosses the FFI
    /// boundary for this path (see [`PqhsLeafJournal::commit`]).
    type Error = ();

    fn commit(&mut self, leaf: u32) -> Result<(), Self::Error> {
        let commit = self.0.commit.ok_or(())?;
        if commit(self.0.ctx, leaf) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn next_leaf(&self) -> u32 {
        self.0.next_leaf.map_or(0, |f| f(self.0.ctx))
    }

    fn bound_key(&self) -> Option<KeyIdentity> {
        let bound_key = self.0.bound_key?;
        let mut out = [0u8; KEY_IDENTITY_LEN];
        // A missing callback and a nonzero return both read as "never
        // bound", which is the fail-closed answer: signing refuses it, and
        // `adopt_key` is the only thing that acts on it, under a caller who
        // asked for exactly that.
        if bound_key(self.0.ctx, out.as_mut_ptr(), out.len()) != 0 {
            return None;
        }
        Some(KeyIdentity::from_bytes(out))
    }

    fn bind_key(&mut self, key: KeyIdentity) -> Result<(), Self::Error> {
        let bind_key = self.0.bind_key.ok_or(())?;
        let bytes = key.as_bytes();
        if bind_key(self.0.ctx, bytes.as_ptr(), bytes.len()) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Width in bytes of a budget key: the value a
/// [`PqhsStatelessBudget`] callback receives to identify which stateless
/// material a count belongs to.
///
/// Written as a literal for the same reason as [`PQHS_KEY_IDENTITY_LEN`]:
/// cbindgen copies the initialising expression into the header verbatim, and
/// a C compiler has no Rust constant to expand. The assertion below keeps it
/// in step with the library.
pub const PQHS_BUDGET_KEY_LEN: usize = 32;

const _: () = assert!(PQHS_BUDGET_KEY_LEN == 32);

/// A caller-owned durable record of how much of the few-time stateless
/// budget each stateless key material has consumed, passed to
/// [`pqhs_sign_stateless`].
///
/// The stateless counterpart of [`PqhsLeafJournal`], and required on the
/// same terms: [`pqhs_sign_stateless`] cannot be called without one. The
/// stateless path has a hard security bound of its own -- `2^20` signatures,
/// `2^18` under the low-budget profile -- shared with rotation and recovery,
/// and exceeding it degrades the security assumption of the underlying
/// few-time scheme. It is not a quota to enforce loosely.
///
/// `record` MUST NOT return until the count is durably stored, for the same
/// reason [`PqhsLeafJournal::commit`] must not: a crash after `record`
/// returns `0` but before the write reaches stable storage hands the same
/// unit of budget out again after a restart, and enough of those exceed the
/// bound with nothing reporting it. Returning nonzero from `record` MUST
/// mean nothing was stored.
///
/// Entries are keyed by a `PQHS_BUDGET_KEY_LEN`-byte value derived from the
/// key's stateless material (`pkSeed || hypertreeRoot`), so one store serves
/// every key an integrator holds and there is no separate binding step: two
/// keys sharing stateless material always produce the same budget key, and
/// two keys with different stateless material never do. A rotation that does
/// not change that material therefore continues the same count rather than
/// starting a new one, which is exactly what stops a rotation from refilling
/// the bound.
///
/// `ctx` is passed back unchanged to every callback and is never
/// dereferenced by this crate.
///
/// # No callback may re-enter this library
///
/// `consumed` and `record` MUST NOT call any `pqhs_*` function, directly or
/// indirectly, on the same terms as [`PqhsLeafJournal`]'s callbacks: they
/// run while [`pqhs_sign_stateless`] holds live references to the caller's
/// `sk` and `sig_out` buffers.
///
/// # Threading
///
/// As with [`PqhsLeafJournal`], the callbacks are plain C calls on the
/// calling thread, and serialising access to the store is the caller's
/// responsibility. Two threads signing against one unserialised store can
/// each read the same count and each write back the same increment, which
/// loses one spend per race and lets the bound be exceeded.
#[repr(C)]
pub struct PqhsStatelessBudget {
    /// Opaque caller state, passed unchanged to every callback.
    pub ctx: *mut c_void,
    /// Report how many stateless signatures have already been produced for
    /// the `PQHS_BUDGET_KEY_LEN`-byte budget key at `key`. Returns `0` and
    /// writes the count to `out_consumed` if this material is tracked, or
    /// any nonzero value -- writing nothing -- if it has never been tracked.
    ///
    /// Nonzero MUST mean "never tracked", never "could not read". A storage
    /// error reported as "never tracked" is read here as a count of zero,
    /// which hands the caller a full budget for material that may have spent
    /// most of it. Fail before constructing the store instead.
    pub consumed: Option<
        extern "C" fn(
            ctx: *mut c_void,
            key: *const u8,
            key_len: usize,
            out_consumed: *mut u64,
        ) -> c_int,
    >,
    /// Durably record that `count` stateless signatures have now been
    /// produced for the `PQHS_BUDGET_KEY_LEN`-byte budget key at `key`.
    /// Returns `0` once the write is durable, or any nonzero value to report
    /// that nothing was stored.
    pub record: Option<
        extern "C" fn(ctx: *mut c_void, key: *const u8, key_len: usize, count: u64) -> c_int,
    >,
}

/// Wraps a caller's `&PqhsStatelessBudget` as a
/// [`pqhybridsign_abi::StatelessBudgetStore`], on the same terms as
/// [`FfiJournal`].
///
/// `pub(crate)` rather than private: [`crate::vrf`] reuses this exact
/// wrapper for `pqhs_vrf_prove_stateless`, which spends the same few-time
/// budget through the same [`PqhsStatelessBudget`] vtable, so the callback
/// logic has one implementation rather than two that could drift apart.
pub(crate) struct FfiBudget<'a>(pub(crate) &'a PqhsStatelessBudget);

impl StatelessBudgetStore for FfiBudget<'_> {
    /// The callback reported failure; no further detail crosses the FFI
    /// boundary for this path (see [`PqhsStatelessBudget::record`]).
    type Error = ();

    fn consumed(&self, key: &BudgetKey) -> Option<u64> {
        let consumed = self.0.consumed?;
        let bytes = key.as_bytes();
        let mut out = 0u64;
        // A missing callback and a nonzero return both read as "never
        // tracked". That is the permissive answer rather than the
        // fail-closed one, which is why the callback's contract forbids
        // reporting a read failure this way: the store, not this crate, is
        // the only place that can tell a missing entry from an unreadable
        // one.
        if consumed(self.0.ctx, bytes.as_ptr(), bytes.len(), &mut out) != 0 {
            return None;
        }
        Some(out)
    }

    fn record(&mut self, key: &BudgetKey, count: u64) -> Result<(), Self::Error> {
        let record = self.0.record.ok_or(())?;
        let bytes = key.as_bytes();
        if record(self.0.ctx, bytes.as_ptr(), bytes.len(), count) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Bind `journal` to the key `key` names, unless it already belongs to a
/// different key.
///
/// This is the explicit act an integrator performs once, when a key's durable
/// journal is first created. [`pqhs_sign_stateful`] never does it: pairing a
/// key with a journal that has never seen it is how one key's one-time leaves
/// get spent twice, and it is refused with `PQHS_ERR_JOURNAL_KEY_MISMATCH`
/// rather than silently accepted.
///
/// `key` is the [`PQHS_KEY_IDENTITY_LEN`]-byte value
/// [`pqhs_key_identity`] or [`pqhs_key_identity_from_secret_key`] produced.
/// Calling this is idempotent for a journal already bound to `key`.
///
/// Do not call it on a fresh journal at every process start: that mints a new
/// binding each time and starts the leaf budget over, which is the defect the
/// binding exists to close.
///
/// # Errors
///
/// `PQHS_ERR_NULL_POINTER` if `journal` or `key` is null, or if
/// `journal->bound_key` or `journal->bind_key` is null.
/// `PQHS_ERR_BAD_LENGTH` if `key_len` is not [`PQHS_KEY_IDENTITY_LEN`].
/// `PQHS_ERR_JOURNAL_KEY_MISMATCH` if `journal` already belongs to another
/// key; nothing is written. `PQHS_ERR_JOURNAL_FAILED` if `bind_key` reported
/// the write did not become durable.
///
/// # Safety
///
/// `journal`, if non-null, must point to a valid `PqhsLeafJournal` whose
/// `ctx` is a pointer its own callbacks are prepared to receive, and whose
/// callbacks do not call back into this library (see [`PqhsLeafJournal`]).
/// `key`, if non-null, must be valid for reads for `key_len` bytes for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn pqhs_adopt_key(
    journal: *const PqhsLeafJournal,
    key: *const u8,
    key_len: usize,
) -> c_int {
    guard(move || {
        if journal.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // SAFETY: `journal` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let journal_ref = unsafe { &*journal };
        if journal_ref.bound_key.is_none() || journal_ref.bind_key.is_none() {
            return PQHS_ERR_NULL_POINTER;
        }
        let key = match unsafe { borrow_slice(key, key_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let Ok(bytes) = <[u8; KEY_IDENTITY_LEN]>::try_from(key) else {
            return PQHS_ERR_BAD_LENGTH;
        };
        let mut ffi_journal = FfiJournal(journal_ref);
        match pqhybridsign_abi::adopt_key(&mut ffi_journal, KeyIdentity::from_bytes(bytes)) {
            Ok(()) => PQHS_OK,
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Write the [`PQHS_KEY_IDENTITY_LEN`]-byte identity of the key `pk`
/// describes into `out`.
///
/// `pk` is the verify-form public key
/// [`pqhs_keygen_stateful_from_seed`](crate::pqhs_keygen_stateful_from_seed)
/// wrote, exactly [`pqhs_public_key_len`](crate::pqhs_public_key_len) bytes
/// for `suite`. It is public material, so this identity can be computed
/// without ever holding the secret key.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4, which have no journal
/// and so no identity. `PQHS_ERR_BAD_LENGTH` if `pk` is not the suite's
/// public key length or `out_len` is not [`PQHS_KEY_IDENTITY_LEN`].
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `pk`, writes for `out`) for exactly its paired length in
/// bytes, and must not be aliased by another live pointer for the duration of
/// this call. A null pointer is only valid when its paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_key_identity(
    suite: u8,
    pk: *const u8,
    pk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pk = match unsafe { borrow_slice(pk, pk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        write_identity(pqhybridsign_abi::key_identity(suite, pk), out)
    })
}

/// Write the [`PQHS_KEY_IDENTITY_LEN`]-byte identity of the key an exported
/// secret key blob holds into `out`.
///
/// The same value [`pqhs_key_identity`] writes for the matching public key:
/// it comes from the blob's cached post-quantum verify key, which is public,
/// and no secret byte reaches it. This exists because the restart path has
/// the blob in hand and may not have kept the public key.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4. `PQHS_ERR_BAD_LENGTH` if
/// `sk` is not [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes for
/// `suite` or `out_len` is not [`PQHS_KEY_IDENTITY_LEN`].
/// `PQHS_ERR_COMPONENT_FAILURE` if the blob does not import.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`, writes for `out`) for exactly its paired length in
/// bytes, and must not be aliased by another live pointer for the duration of
/// this call. A null pointer is only valid when its paired length is `0`.
#[no_mangle]
pub unsafe extern "C" fn pqhs_key_identity_from_secret_key(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        write_identity(
            pqhybridsign_abi::key_identity_from_secret_key(suite, sk),
            out,
        )
    })
}

/// Shared tail of the two identity entry points: check the output length,
/// then copy the identity out.
fn write_identity(
    identity: Result<KeyIdentity, pqhybridsign_abi::AbiError>,
    out: &mut [u8],
) -> c_int {
    if out.len() != KEY_IDENTITY_LEN {
        return PQHS_ERR_BAD_LENGTH;
    }
    match identity {
        Ok(identity) => {
            out.copy_from_slice(identity.as_bytes());
            PQHS_OK
        }
        Err(e) => crate::error::code_of(e),
    }
}

/// Sign `msg` under `ctx` for `suite`, spending one leaf recorded through
/// `journal`.
///
/// `sk` is the exported secret key blob from
/// [`pqhs_keygen_stateful_from_seed`](crate::pqhs_keygen_stateful_from_seed)
/// or a previous call to this function.
///
/// **`sk_out` is written on every outcome that reaches the component
/// signer, including a failed one** (`PQHS_ERR_GRIND_ABORT` in particular is
/// raised only after the leaf is already durably committed to `journal`).
/// Writing `sk_out` unconditionally in that case keeps the caller's copy of
/// the key in step with the journal; skipping it is exactly the
/// silent-leaf-drift failure mode this entry point exists to rule out.
/// `sk_out` is not written if `sk` fails to import, which happens before
/// any leaf is spent.
///
/// Every argument check -- the suite, the pointers, and the lengths of
/// `sk` and `sk_out` -- happens before the component signer runs, so a
/// rejected call has spent nothing and left `journal` untouched. That
/// ordering is what makes an error code safe to act on: an error raised
/// after a leaf had been committed but before the advanced key was handed
/// back would leave `journal` permanently ahead of every copy of the key
/// the caller holds, and the key unusable for the rest of its budget.
///
/// `sk` and `sk_out` must be separate buffers. Passing the same buffer for
/// both -- the natural way to write an in-place key update in C -- is
/// `PQHS_ERR_ALIASED_BUFFERS`, and so is any partial overlap between them.
/// Copy `sk` into `sk_out`'s buffer afterwards if that is the shape the
/// integration wants.
///
/// # Performance
///
/// This function calls `SecretKey::import`, which re-derives the hypertree
/// root. At `profile-128s-q18` and `profile-128s-q20` that is the same walk
/// as keygen: about 47 seconds, paid on every call. The in-process Rust API
/// keeps a `SecretKey` in memory and signs in under 0.01 seconds. A caller
/// on a 128s profile that signs more than occasionally wants the Rust API
/// or an opaque key handle, not this entry point.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4: use
/// [`pqhs_sign`](crate::pqhs_sign) or
/// [`pqhs_sign_deterministic`](crate::pqhs_sign_deterministic) instead.
/// `PQHS_ERR_BAD_LENGTH` if `sk` or `sk_out` is not exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes for `suite`,
/// checked before the journal is touched. `PQHS_ERR_LEAVES_EXHAUSTED` if
/// the key's leaf budget is spent, also checked before the journal is
/// touched. `PQHS_ERR_JOURNAL_FAILED` if `journal` could not durably
/// commit; nothing was spent. `PQHS_ERR_JOURNAL_KEY_MISMATCH` if `journal`
/// is not bound to this key; nothing was spent and the key is intact.
/// `PQHS_ERR_NULL_POINTER` if `journal` is null
/// or any of its four callbacks is null, if `sig_written` is null, or if any
/// buffer pointer paired with a nonzero length is null.
/// `PQHS_ERR_ALIASED_BUFFERS` if `sk` and `sk_out` overlap.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`/`journal`/`msg`/`ctx`, writes for
/// `sk_out`/`sig_out`/`sig_written`) for exactly its paired length in
/// bytes, and must not be aliased by another live pointer for the duration
/// of this call. The `sk`/`sk_out` pair is the one overlap this function
/// detects and refuses rather than leaving to the caller; every other pair
/// is still the caller's obligation. A null pointer is only valid when its
/// paired length is `0`; `journal`, if non-null, must point to a valid
/// `PqhsLeafJournal` whose `ctx` is a pointer its own callbacks are
/// prepared to receive, and whose callbacks do not call back into this
/// library (see [`PqhsLeafJournal`]).
#[no_mangle]
pub unsafe extern "C" fn pqhs_sign_stateful(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    journal: *const PqhsLeafJournal,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sk_out: *mut u8,
    sk_out_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    sig_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        if journal.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // Checked with the other pointers rather than at the `write_out`
        // that consumes it. Discovering it at the end of the success path
        // returns an error for a call that has already spent a leaf and
        // written a valid signature, and a caller reading that as a
        // rejection signs the same message again -- burning a second leaf.
        if sig_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // Refused before either slice exists. Manufacturing a `&[u8]` and a
        // `&mut [u8]` over the same bytes violates Rust's exclusivity rule
        // and reaches the optimizer with `noalias` on both, so it is
        // undefined behaviour rather than merely unspecified -- and the
        // corruption it would license is a wrong leaf counter in a stateful
        // secret key, which is silent, not a crash. Partial overlap is the
        // same defect as the exact `sk_out == sk` case and is caught too.
        //
        // Two null pointers both read as address zero, which would look
        // like an overlap. Skip them: the borrow helpers below report
        // `PQHS_ERR_NULL_POINTER` for a null buffer, which tells the caller
        // more than an aliasing complaint would.
        if !sk.is_null()
            && !sk_out.is_null()
            && ranges_overlap(sk, sk_len, sk_out.cast_const(), sk_out_len)
        {
            return PQHS_ERR_ALIASED_BUFFERS;
        }
        // SAFETY: `journal` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let journal_ref = unsafe { &*journal };
        // All four, not just the two the signing flow calls on the success
        // path: a journal with no `bound_key` reports "never bound" for every
        // key, which would come back as `PQHS_ERR_JOURNAL_KEY_MISMATCH` and
        // send an integrator hunting a binding problem that is really a
        // half-filled vtable.
        if journal_ref.commit.is_none()
            || journal_ref.next_leaf.is_none()
            || journal_ref.bound_key.is_none()
            || journal_ref.bind_key.is_none()
        {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk_out = match unsafe { borrow_slice_mut(sk_out, sk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut ffi_journal = FfiJournal(journal_ref);
        match pqhybridsign_abi::sign_stateful(
            suite,
            sk,
            &mut ffi_journal,
            msg,
            ctx,
            sk_out,
            sig_out,
        ) {
            Ok(n) => match unsafe { write_out(sig_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Sign `msg` under `ctx` for `suite` without spending any leaf state, using
/// SHRINCS's stateless few-time path (specification section 21), and
/// spending one unit of the few-time stateless budget.
///
/// `budget` is required. The stateless path has a hard bound of its own,
/// shared with rotation and recovery, and the spend is made durable through
/// `budget` before the signature is built -- the same order
/// [`pqhs_sign_stateful`] commits its leaf in. See [`PqhsStatelessBudget`]
/// for the durability contract the callbacks must honour.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4. `PQHS_ERR_BAD_LENGTH`
/// if `sk` is not exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes for `suite`.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null, if `sig_written` is null, if `budget` is null, or if either of
/// `budget`'s callbacks is null.
/// `PQHS_ERR_STATELESS_BUDGET_EXHAUSTED` if this key's stateless budget is
/// spent; nothing was recorded and no signature was built.
/// `PQHS_ERR_BUDGET_STORE_FAILED` if `record` reported the write did not
/// become durable; nothing was recorded either.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`/`msg`/`ctx`, writes for `sig_out`/`sig_written`)
/// for exactly its paired length in bytes, and must not be aliased by
/// another live pointer for the duration of this call. A null pointer is
/// only valid when its paired length is `0`; `sig_written` has no paired
/// length and must be a valid, non-null, writable `usize` pointer. `budget`
/// must point to a valid `PqhsStatelessBudget` whose `ctx` is a pointer its
/// own callbacks are prepared to receive, and whose callbacks do not call
/// back into this library.
#[no_mangle]
pub unsafe extern "C" fn pqhs_sign_stateless(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    budget: *const PqhsStatelessBudget,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    sig_written: *mut usize,
) -> c_int {
    guard(move || {
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        // See `pqhs_sign_stateful` for why this is checked here and not at
        // the `write_out` that consumes it.
        if sig_written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if budget.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // SAFETY: `budget` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let budget_ref = unsafe { &*budget };
        // Both callbacks are checked here rather than at the point of use.
        // A missing `record` would otherwise surface as
        // `PQHS_ERR_BUDGET_STORE_FAILED`, which tells a caller their storage
        // is broken when in fact their vtable is incomplete, and a missing
        // `consumed` would silently read as a full budget.
        if budget_ref.consumed.is_none() || budget_ref.record.is_none() {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut ffi_budget = FfiBudget(budget_ref);
        match pqhybridsign_abi::sign_stateless(suite, sk, &mut ffi_budget, msg, ctx, sig_out) {
            Ok(n) => match unsafe { write_out(sig_written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by [`pqhs_sign_stateful`], against one whole
/// verify-form public key `pk`.
///
/// [`pqhs_verify`](crate::sign::pqhs_verify) is the total dispatcher across
/// all six suites and, for H5 and H6, behaves exactly as this function
/// does; call this one directly only where the suite is already known to be
/// H5 or H6. Specification section 20.2 requires the behaviour both
/// enforce: the primary stateless path is reserved for rotation and
/// recovery, and a verifier for an ordinary application message MUST NOT
/// accept it. The wire `PathSelector` is checked, and a signature naming
/// the stateless path is refused, before either component signature is
/// checked. A caller that genuinely needs to verify a stateless-path H5 or
/// H6 signature calls [`pqhs_verify_stateless`] instead.
///
/// Writes `true` or `false` into `*valid_out` and returns `PQHS_OK` in both
/// cases, on the same terms as [`pqhs_verify`](crate::sign::pqhs_verify).
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4; use
/// [`pqhs_verify`](crate::sign::pqhs_verify) instead.
/// `PQHS_ERR_INVALID_SUITE` if `suite` is not `1..=6`.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null, or if `valid_out` is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `pk`/`msg`/`ctx`/`sig`, a write for `valid_out`) for
/// exactly its paired length in bytes, and must not be aliased by another
/// live pointer for the duration of this call. A null pointer is only
/// valid when its paired length is `0`; `valid_out` has no paired length
/// and must be a valid, non-null, writable `bool` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_verify_stateful(
    suite: u8,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
    valid_out: *mut bool,
) -> c_int {
    guard(move || {
        if valid_out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if let Err(e) = unsafe { write_out(valid_out, false) } {
            return e;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pk = match unsafe { borrow_slice(pk, pk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig = match unsafe { borrow_slice(sig, sig_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::verify_stateful(suite, pk, msg, ctx, sig) {
            Ok(valid) => match unsafe { write_out(valid_out, valid) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by [`pqhs_sign_stateless`], against one whole
/// verify-form public key `pk`.
///
/// The mirror image of [`pqhs_verify_stateful`]. Use this for rotation and
/// recovery authorizations, and for any other message an application has
/// deliberately chosen to sign on the few-time stateless path rather than
/// by spending a leaf.
///
/// # Errors
///
/// The same as [`pqhs_verify_stateful`].
///
/// # Safety
///
/// The same as [`pqhs_verify_stateful`].
#[no_mangle]
pub unsafe extern "C" fn pqhs_verify_stateless(
    suite: u8,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
    valid_out: *mut bool,
) -> c_int {
    guard(move || {
        if valid_out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if let Err(e) = unsafe { write_out(valid_out, false) } {
            return e;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let pk = match unsafe { borrow_slice(pk, pk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig = match unsafe { borrow_slice(sig, sig_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::verify_stateless(suite, pk, msg, ctx, sig) {
            Ok(valid) => match unsafe { write_out(valid_out, valid) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by [`pqhs_sign_stateful`], against a
/// signer-supplied verify key that must be the one `stored_public_key`
/// commits to.
///
/// This is the entry point for the deployment H5 and H6 are built for: the
/// verifier stores the small form (`ClassicalPK || commitment`,
/// [`pqhs_stored_public_key_len`](crate::pqhs_stored_public_key_len) bytes
/// -- 64 for both suites) and the signer supplies the full 164-byte
/// commitment bundle alongside every signature, because the bundle is too
/// large to keep on an account. `stored_public_key` is trusted;
/// `pq_verify_key` is not: the commitment is recomputed from
/// `pq_verify_key` and matched against the stored one before anything is
/// verified, and the classical public key is taken from `stored_public_key`,
/// so nothing the signer supplied can substitute a key of their own.
///
/// A signature whose wire `PathSelector` names the stateless path is
/// refused before either component signature is checked, on the same terms
/// [`pqhs_verify_stateful`] enforces. A caller that genuinely needs to
/// accept a stateless-path signature under a stored commitment calls
/// [`pqhs_verify_with_stored_public_key_stateless`] instead.
///
/// Writes `true` or `false` into `*valid_out` and returns `PQHS_OK` in both
/// cases: a commitment that does not match, a malformed key or a malformed
/// signature all fail to verify rather than error, on the same grounds as
/// [`pqhs_verify`](crate::pqhs_verify). `*valid_out` is set to `false`
/// before anything else happens, so it is `false` on every path that
/// returns a code other than `PQHS_OK` too.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4: their public key is a
/// single form with no commitment in it, so there is nothing for this
/// entry point to bind; use [`pqhs_verify`](crate::pqhs_verify).
/// `PQHS_ERR_INVALID_SUITE` if `suite` is not `1..=6`.
/// `PQHS_ERR_NULL_POINTER` if a pointer paired with a nonzero length is
/// null, or if `valid_out` is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for reads for
/// exactly its paired length in bytes (a write, for `valid_out`), and must
/// not be aliased by another live pointer for the duration of this call. A
/// null pointer is only valid when its paired length is `0`; `valid_out`
/// has no paired length and must be a valid, non-null, writable `bool`
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_verify_with_stored_public_key_stateful(
    suite: u8,
    stored_public_key: *const u8,
    stored_public_key_len: usize,
    pq_verify_key: *const u8,
    pq_verify_key_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
    valid_out: *mut bool,
) -> c_int {
    guard(move || {
        // See `pqhs_verify` for why `valid_out` is checked and set to
        // `false` ahead of every other check, including the suite code.
        if valid_out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if let Err(e) = unsafe { write_out(valid_out, false) } {
            return e;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let stored_public_key =
            match unsafe { borrow_slice(stored_public_key, stored_public_key_len) } {
                Ok(s) => s,
                Err(e) => return e,
            };
        let pq_verify_key = match unsafe { borrow_slice(pq_verify_key, pq_verify_key_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig = match unsafe { borrow_slice(sig, sig_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::verify_with_stored_public_key_stateful(
            suite,
            stored_public_key,
            pq_verify_key,
            msg,
            ctx,
            sig,
        ) {
            Ok(valid) => match unsafe { write_out(valid_out, valid) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Verify `sig` over `msg` under `ctx` for a stateful `suite`, accepting
/// only a signature produced by [`pqhs_sign_stateless`], against a
/// signer-supplied verify key that must be the one `stored_public_key`
/// commits to.
///
/// The mirror image of [`pqhs_verify_with_stored_public_key_stateful`]. Use
/// this for rotation and recovery authorizations, and for any other message
/// an application has deliberately chosen to sign on the few-time stateless
/// path.
///
/// # Errors
///
/// The same as [`pqhs_verify_with_stored_public_key_stateful`].
///
/// # Safety
///
/// The same as [`pqhs_verify_with_stored_public_key_stateful`].
#[no_mangle]
pub unsafe extern "C" fn pqhs_verify_with_stored_public_key_stateless(
    suite: u8,
    stored_public_key: *const u8,
    stored_public_key_len: usize,
    pq_verify_key: *const u8,
    pq_verify_key_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
    valid_out: *mut bool,
) -> c_int {
    guard(move || {
        if valid_out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if let Err(e) = unsafe { write_out(valid_out, false) } {
            return e;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let stored_public_key =
            match unsafe { borrow_slice(stored_public_key, stored_public_key_len) } {
                Ok(s) => s,
                Err(e) => return e,
            };
        let pq_verify_key = match unsafe { borrow_slice(pq_verify_key, pq_verify_key_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig = match unsafe { borrow_slice(sig, sig_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::verify_with_stored_public_key_stateless(
            suite,
            stored_public_key,
            pq_verify_key,
            msg,
            ctx,
            sig,
        ) {
            Ok(valid) => match unsafe { write_out(valid_out, valid) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// An imported stateful secret key, held across signing calls.
///
/// Opaque. Create one with [`pqhs_stateful_key_open`], release it with
/// [`pqhs_stateful_key_free`], and never copy or free the pointer any
/// other way.
///
/// # Why this exists
///
/// `pqhs_sign_stateful` imports the exported blob on every call.
/// `SecretKey::import` re-derives the hypertree root, which at
/// `profile-128s-q18` and `profile-128s-q20` costs about 47 seconds, the
/// same walk as keygen. A signer that takes more than one signature from a
/// key should open a handle once and sign through it: the import is paid
/// at `pqhs_stateful_key_open` and every later signature costs under 0.01
/// seconds.
///
/// # The durability contract is unchanged
///
/// A handle holds the key in memory and persists nothing. After every
/// `pqhs_stateful_key_sign` call, **including one that returned an
/// error**, call `pqhs_stateful_key_export` and persist the result before
/// relying on the signature. A leaf can be durably committed to the
/// journal and the signature still fail, and a stored key that did not
/// advance with the journal is refused for the rest of the key's life.
///
/// Not thread-safe. `pqhs_stateful_key_sign` takes a mutable pointer and
/// advances the key. One handle belongs to one thread at a time.
pub struct PqhsStatefulKey {
    inner: pqhybridsign_abi::StatefulKeyHandle,
}

/// Import `sk` once and return an opaque handle through `out`.
///
/// This is the call that costs about 47 seconds at the 128s profiles.
/// Every later [`pqhs_stateful_key_sign`] taken through the handle costs
/// under 0.01 seconds. See [`PqhsStatefulKey`].
///
/// `sk` is the exported secret key blob from
/// [`pqhs_keygen_stateful_from_seed`](crate::pqhs_keygen_stateful_from_seed)
/// or a previous [`pqhs_stateful_key_export`].
///
/// On success, `*out` is a pointer the caller must later pass to
/// [`pqhs_stateful_key_free`]. On failure, `*out` is left untouched.
///
/// # Errors
///
/// `PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE` for H1-H4.
/// `PQHS_ERR_BAD_LENGTH` if `sk` is not
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes for `suite`.
/// `PQHS_ERR_COMPONENT_FAILURE` if the blob does not import.
/// `PQHS_ERR_NULL_POINTER` if `out` is null, or if `sk` is null while
/// `sk_len` is nonzero. `PQHS_ERR_INVALID_SUITE` if `suite` is not
/// `1..=6`.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `sk`, a write of one `*mut PqhsStatefulKey` for
/// `out`) for exactly its paired length in bytes, and must not be aliased
/// by another live pointer for the duration of this call. A null pointer
/// is only valid when its paired length is `0`; `out` has no paired length
/// and must be a valid, non-null, writable `*mut PqhsStatefulKey` pointer.
#[no_mangle]
pub unsafe extern "C" fn pqhs_stateful_key_open(
    suite: u8,
    sk: *const u8,
    sk_len: usize,
    out: *mut *mut PqhsStatefulKey,
) -> c_int {
    guard(move || {
        if out.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let suite = match suite_from_code(suite) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sk = match unsafe { borrow_slice(sk, sk_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        match pqhybridsign_abi::StatefulKeyHandle::open(suite, sk) {
            Ok(inner) => {
                let raw = Box::into_raw(Box::new(PqhsStatefulKey { inner }));
                // SAFETY: `out` is non-null, checked above; the caller
                // guarantees it is valid for a write of one pointer.
                match unsafe { write_out(out, raw) } {
                    Ok(()) => PQHS_OK,
                    Err(e) => {
                        // Unreachable if the null check above holds;
                        // recover the box so a future change to
                        // `write_out` cannot leak the key.
                        // SAFETY: `raw` came from `Box::into_raw` on the
                        // line above and has not been handed out.
                        drop(unsafe { Box::from_raw(raw) });
                        e
                    }
                }
            }
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Release a handle previously returned by [`pqhs_stateful_key_open`].
///
/// A null `key` is a no-op. After this call returns, `key` must not be
/// used again.
///
/// # Safety
///
/// `key` must be a pointer previously returned by
/// [`pqhs_stateful_key_open`] that has not already been freed, or null.
/// The pointer must not be used after this call returns.
#[no_mangle]
pub unsafe extern "C" fn pqhs_stateful_key_free(key: *mut PqhsStatefulKey) {
    crate::ffi::guard_infallible(|| {
        if key.is_null() {
            return;
        }
        // SAFETY: `key` is non-null, checked above, and the caller
        // guarantees it is a pointer previously returned by
        // [`pqhs_stateful_key_open`] that has not already been freed.
        drop(unsafe { Box::from_raw(key) });
    });
}

/// Write the current exported blob of `key` into `sk_out`.
///
/// Writes the number of bytes written through `written`, which is
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) for this handle's
/// suite. Persist this after every [`pqhs_stateful_key_sign`] call,
/// including one that returned an error. See [`PqhsStatefulKey`].
///
/// # Errors
///
/// `PQHS_ERR_BAD_LENGTH` if `sk_out` is not exactly
/// [`pqhs_secret_key_len`](crate::pqhs_secret_key_len) bytes.
/// `PQHS_ERR_COMPONENT_FAILURE` if the key does not export.
/// `PQHS_ERR_NULL_POINTER` if `key` or `written` is null, or if `sk_out`
/// is null while `sk_out_len` is nonzero.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `key`, writes for `sk_out`/`written`) for exactly
/// its paired length in bytes, and must not be aliased by another live
/// pointer for the duration of this call. A null pointer is only valid
/// when its paired length is `0`; `written` has no paired length and must
/// be a valid, non-null, writable `usize` pointer. `key` must be a
/// pointer previously returned by [`pqhs_stateful_key_open`] that has not
/// been freed.
#[no_mangle]
pub unsafe extern "C" fn pqhs_stateful_key_export(
    key: *const PqhsStatefulKey,
    sk_out: *mut u8,
    sk_out_len: usize,
    written: *mut usize,
) -> c_int {
    guard(move || {
        if key.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let sk_out = match unsafe { borrow_slice_mut(sk_out, sk_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        // SAFETY: `key` is non-null, checked above; the caller guarantees
        // it is a live handle from [`pqhs_stateful_key_open`].
        let key_ref = unsafe { &*key };
        match key_ref.inner.export(sk_out) {
            Ok(n) => match unsafe { write_out(written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Write the [`PQHS_KEY_IDENTITY_LEN`]-byte identity of the key `key`
/// holds into `out`.
///
/// The same value [`pqhs_key_identity`] writes for the matching public
/// key. Derived from the cached post-quantum verify key, which is public;
/// no secret byte reaches it.
///
/// # Errors
///
/// `PQHS_ERR_BAD_LENGTH` if `out_len` is not [`PQHS_KEY_IDENTITY_LEN`].
/// `PQHS_ERR_NULL_POINTER` if `key` is null, or if `out` is null while
/// `out_len` is nonzero.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `key`, writes for `out`) for exactly its paired
/// length in bytes, and must not be aliased by another live pointer for
/// the duration of this call. A null pointer is only valid when its
/// paired length is `0`. `key` must be a pointer previously returned by
/// [`pqhs_stateful_key_open`] that has not been freed.
#[no_mangle]
pub unsafe extern "C" fn pqhs_stateful_key_identity(
    key: *const PqhsStatefulKey,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    guard(move || {
        if key.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        let out = match unsafe { borrow_slice_mut(out, out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        // SAFETY: `key` is non-null, checked above; the caller guarantees
        // it is a live handle from [`pqhs_stateful_key_open`].
        let key_ref = unsafe { &*key };
        write_identity(Ok(key_ref.inner.key_identity()), out)
    })
}

/// Sign `msg` under `ctx` with `key`, spending one leaf recorded through
/// `journal`.
///
/// The handle-held counterpart of [`pqhs_sign_stateful`]. Identical in
/// every respect except that the key is already imported and the advanced
/// key stays in `key` instead of being written to an `sk_out` buffer.
///
/// `journal` must already be bound to this key ([`pqhs_adopt_key`]). That
/// is checked before its counter is read and before anything is committed.
///
/// **The handle advances on every outcome that reaches the component
/// signer, including a failed one.** Export and persist it either way.
/// See [`PqhsStatefulKey`].
///
/// # Errors
///
/// `PQHS_ERR_JOURNAL_KEY_MISMATCH` if `journal` is not bound to this key;
/// nothing was spent and the key is intact. `PQHS_ERR_LEAVES_EXHAUSTED`
/// if the key's leaf budget is spent, checked before the journal is
/// touched. `PQHS_ERR_JOURNAL_FAILED` if `journal` could not durably
/// commit; nothing was spent. `PQHS_ERR_NULL_POINTER` if `key` is null,
/// if `journal` is null or any of its four callbacks is null, if
/// `written` is null, or if any buffer pointer paired with a nonzero
/// length is null.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `key`/`journal`/`msg`/`ctx`, writes for
/// `sig_out`/`written`) for exactly its paired length in bytes, and must
/// not be aliased by another live pointer for the duration of this call.
/// A null pointer is only valid when its paired length is `0`; `written`
/// has no paired length and must be a valid, non-null, writable `usize`
/// pointer. `key` must be a pointer previously returned by
/// [`pqhs_stateful_key_open`] that has not been freed. `journal`, if
/// non-null, must point to a valid `PqhsLeafJournal` whose `ctx` is a
/// pointer its own callbacks are prepared to receive, and whose callbacks
/// do not call back into this library (see [`PqhsLeafJournal`]).
#[no_mangle]
pub unsafe extern "C" fn pqhs_stateful_key_sign(
    key: *mut PqhsStatefulKey,
    journal: *const PqhsLeafJournal,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    written: *mut usize,
) -> c_int {
    guard(move || {
        if key.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if journal.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // Checked with the other pointers rather than at the `write_out`
        // that consumes it. Discovering it at the end of the success path
        // returns an error for a call that has already spent a leaf and
        // written a valid signature, and a caller reading that as a
        // rejection signs the same message again -- burning a second leaf.
        if written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // SAFETY: `journal` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let journal_ref = unsafe { &*journal };
        // All four, not just the two the signing flow calls on the success
        // path: a journal with no `bound_key` reports "never bound" for every
        // key, which would come back as `PQHS_ERR_JOURNAL_KEY_MISMATCH` and
        // send an integrator hunting a binding problem that is really a
        // half-filled vtable.
        if journal_ref.commit.is_none()
            || journal_ref.next_leaf.is_none()
            || journal_ref.bound_key.is_none()
            || journal_ref.bind_key.is_none()
        {
            return PQHS_ERR_NULL_POINTER;
        }
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut ffi_journal = FfiJournal(journal_ref);
        // SAFETY: `key` is non-null, checked above; the caller guarantees
        // it is a live handle from [`pqhs_stateful_key_open`].
        let key_ref = unsafe { &mut *key };
        match pqhybridsign_abi::sign_stateful_with_handle(
            &mut key_ref.inner,
            &mut ffi_journal,
            msg,
            ctx,
            sig_out,
        ) {
            Ok(n) => match unsafe { write_out(written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

/// Sign `msg` under `ctx` with `key` without spending any leaf, using
/// SHRINCS's stateless few-time path (specification section 21), and
/// spending one unit of the few-time stateless budget.
///
/// The handle-held counterpart of [`pqhs_sign_stateless`]. `budget` is
/// required and no leaf journal substitutes for it, on the same terms.
/// The stateless path does not advance the key, so there is nothing new
/// to export afterwards.
///
/// # Errors
///
/// `PQHS_ERR_NULL_POINTER` if `key` is null, if a pointer paired with a
/// nonzero length is null, if `written` is null, if `budget` is null, or
/// if either of `budget`'s callbacks is null.
/// `PQHS_ERR_STATELESS_BUDGET_EXHAUSTED` if this key's stateless budget is
/// spent; nothing was recorded and no signature was built.
/// `PQHS_ERR_BUDGET_STORE_FAILED` if `record` reported the write did not
/// become durable; nothing was recorded either.
///
/// # Safety
///
/// Every pointer parameter, if non-null, must be valid for the documented
/// access (reads for `key`/`budget`/`msg`/`ctx`, writes for
/// `sig_out`/`written`) for exactly its paired length in bytes, and must
/// not be aliased by another live pointer for the duration of this call.
/// A null pointer is only valid when its paired length is `0`; `written`
/// has no paired length and must be a valid, non-null, writable `usize`
/// pointer. `key` must be a pointer previously returned by
/// [`pqhs_stateful_key_open`] that has not been freed. `budget` must
/// point to a valid `PqhsStatelessBudget` whose `ctx` is a pointer its
/// own callbacks are prepared to receive, and whose callbacks do not call
/// back into this library.
#[no_mangle]
pub unsafe extern "C" fn pqhs_stateful_key_sign_stateless(
    key: *const PqhsStatefulKey,
    budget: *const PqhsStatelessBudget,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    written: *mut usize,
) -> c_int {
    guard(move || {
        if key.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // See `pqhs_sign_stateful` for why this is checked here and not at
        // the `write_out` that consumes it.
        if written.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        if budget.is_null() {
            return PQHS_ERR_NULL_POINTER;
        }
        // SAFETY: `budget` is non-null, checked above; the caller
        // guarantees it is valid for reads for the duration of this call.
        let budget_ref = unsafe { &*budget };
        // Both callbacks are checked here rather than at the point of use.
        // A missing `record` would otherwise surface as
        // `PQHS_ERR_BUDGET_STORE_FAILED`, which tells a caller their storage
        // is broken when in fact their vtable is incomplete, and a missing
        // `consumed` would silently read as a full budget.
        if budget_ref.consumed.is_none() || budget_ref.record.is_none() {
            return PQHS_ERR_NULL_POINTER;
        }
        let msg = match unsafe { borrow_slice(msg, msg_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let ctx = match unsafe { borrow_slice(ctx, ctx_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let sig_out = match unsafe { borrow_slice_mut(sig_out, sig_out_len) } {
            Ok(s) => s,
            Err(e) => return e,
        };
        let mut ffi_budget = FfiBudget(budget_ref);
        // SAFETY: `key` is non-null, checked above; the caller guarantees
        // it is a live handle from [`pqhs_stateful_key_open`].
        let key_ref = unsafe { &*key };
        match pqhybridsign_abi::sign_stateless_with_handle(
            &key_ref.inner,
            &mut ffi_budget,
            msg,
            ctx,
            sig_out,
        ) {
            Ok(n) => match unsafe { write_out(written, n) } {
                Ok(()) => PQHS_OK,
                Err(e) => e,
            },
            Err(e) => crate::error::code_of(e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::PQHS_ERR_JOURNAL_FAILED;
    use crate::keygen::pqhs_keygen_stateful_from_seed;
    use std::cell::RefCell;

    thread_local! {
        static COMMITTED: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
        /// The durable binding the test journal holds, alongside its
        /// counter. `None` is a journal that has never been bound to a key.
        static BOUND: RefCell<Option<[u8; PQHS_KEY_IDENTITY_LEN]>> =
            const { RefCell::new(None) };
        /// What the stateless budget store has on record, as
        /// `(budget key, count)` pairs. A linear scan is enough: the tests
        /// here use one or two keys at a time.
        static SPENT: RefCell<Vec<([u8; PQHS_BUDGET_KEY_LEN], u64)>> =
            const { RefCell::new(Vec::new()) };
    }

    extern "C" fn test_commit(_ctx: *mut c_void, leaf: u32) -> c_int {
        COMMITTED.with(|c| c.borrow_mut().push(leaf));
        0
    }

    extern "C" fn test_next_leaf(_ctx: *mut c_void) -> u32 {
        COMMITTED.with(|c| c.borrow().iter().copied().max().map_or(0, |m| m + 1))
    }

    extern "C" fn failing_commit(_ctx: *mut c_void, _leaf: u32) -> c_int {
        1
    }

    extern "C" fn test_bound_key(_ctx: *mut c_void, out: *mut u8, out_len: usize) -> c_int {
        BOUND.with(|b| match *b.borrow() {
            None => 1,
            Some(key) => {
                if out.is_null() || out_len != PQHS_KEY_IDENTITY_LEN {
                    return 1;
                }
                // SAFETY: `out` is non-null and the caller (this crate's own
                // `FfiJournal`) passes a buffer of exactly `out_len` bytes.
                unsafe { std::ptr::copy_nonoverlapping(key.as_ptr(), out, out_len) };
                0
            }
        })
    }

    extern "C" fn test_bind_key(_ctx: *mut c_void, key: *const u8, key_len: usize) -> c_int {
        if key.is_null() || key_len != PQHS_KEY_IDENTITY_LEN {
            return 1;
        }
        let mut bytes = [0u8; PQHS_KEY_IDENTITY_LEN];
        // SAFETY: `key` is non-null and valid for `key_len` bytes, which the
        // check above pins to the size of `bytes`.
        unsafe { std::ptr::copy_nonoverlapping(key, bytes.as_mut_ptr(), key_len) };
        BOUND.with(|b| *b.borrow_mut() = Some(bytes));
        0
    }

    extern "C" fn test_consumed(
        _ctx: *mut c_void,
        key: *const u8,
        key_len: usize,
        out_consumed: *mut u64,
    ) -> c_int {
        if key.is_null() || key_len != PQHS_BUDGET_KEY_LEN || out_consumed.is_null() {
            return 1;
        }
        // SAFETY: `key` is non-null and valid for `key_len` bytes, pinned to
        // the size of the array by the check above.
        let bytes: [u8; PQHS_BUDGET_KEY_LEN] = unsafe { std::slice::from_raw_parts(key, key_len) }
            .try_into()
            .unwrap_or([0u8; PQHS_BUDGET_KEY_LEN]);
        SPENT.with(
            |spent| match spent.borrow().iter().find(|(k, _)| *k == bytes) {
                // Never tracked: the store has nothing to report for this
                // material, which is a different answer from "zero spent".
                None => 1,
                Some((_, count)) => {
                    // SAFETY: `out_consumed` is non-null, checked above, and the
                    // caller passes a live `u64`.
                    unsafe { *out_consumed = *count };
                    0
                }
            },
        )
    }

    extern "C" fn test_record(
        _ctx: *mut c_void,
        key: *const u8,
        key_len: usize,
        count: u64,
    ) -> c_int {
        if key.is_null() || key_len != PQHS_BUDGET_KEY_LEN {
            return 1;
        }
        // SAFETY: as `test_consumed` above.
        let bytes: [u8; PQHS_BUDGET_KEY_LEN] = unsafe { std::slice::from_raw_parts(key, key_len) }
            .try_into()
            .unwrap_or([0u8; PQHS_BUDGET_KEY_LEN]);
        SPENT.with(|spent| {
            let mut spent = spent.borrow_mut();
            match spent.iter_mut().find(|(k, _)| *k == bytes) {
                Some(entry) => entry.1 = count,
                None => spent.push((bytes, count)),
            }
        });
        0
    }

    extern "C" fn failing_record(
        _ctx: *mut c_void,
        _key: *const u8,
        _key_len: usize,
        _count: u64,
    ) -> c_int {
        1
    }

    /// The stateless budget store every test below uses: a full vtable over
    /// the `SPENT` thread-local.
    fn test_budget() -> PqhsStatelessBudget {
        PqhsStatelessBudget {
            ctx: std::ptr::null_mut(),
            consumed: Some(test_consumed),
            record: Some(test_record),
        }
    }

    /// The journal every test below uses: a full vtable over the two
    /// thread-locals above.
    fn test_journal() -> PqhsLeafJournal {
        PqhsLeafJournal {
            ctx: std::ptr::null_mut(),
            commit: Some(test_commit),
            next_leaf: Some(test_next_leaf),
            bound_key: Some(test_bound_key),
            bind_key: Some(test_bind_key),
        }
    }

    /// The identity of the key `pk` names.
    fn identity_of(suite: u8, pk: &[u8]) -> [u8; PQHS_KEY_IDENTITY_LEN] {
        let mut out = [0u8; PQHS_KEY_IDENTITY_LEN];
        // SAFETY: both pointers are live local buffers of exactly the
        // lengths passed alongside them.
        let rc =
            unsafe { pqhs_key_identity(suite, pk.as_ptr(), pk.len(), out.as_mut_ptr(), out.len()) };
        assert_eq!(rc, PQHS_OK);
        out
    }

    /// Reset the shared test journal and bind it to the key `pk` names.
    ///
    /// Signing refuses a journal that is not the key's, so every test that
    /// signs starts from a journal provisioned for its key -- which is what
    /// an integrator does once, when the key's durable store is created.
    /// Resetting the binding first is a test convenience: the one store here
    /// stands in for a different durable journal per key.
    fn provision_journal(suite: u8, pk: &[u8]) {
        COMMITTED.with(|c| c.borrow_mut().clear());
        SPENT.with(|s| s.borrow_mut().clear());
        BOUND.with(|b| *b.borrow_mut() = None);
        let identity = identity_of(suite, pk);
        let journal = test_journal();
        // SAFETY: `journal` and `identity` are live locals for the duration
        // of the call.
        let rc = unsafe { pqhs_adopt_key(&journal, identity.as_ptr(), identity.len()) };
        assert_eq!(rc, PQHS_OK);
    }

    fn h5_keypair(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![0u8; pqhybridsign_abi::secret_key_len(pqhybridsign_abi::Suite::H5)];
        let mut pk = vec![0u8; pqhybridsign_abi::public_key_len(pqhybridsign_abi::Suite::H5)];
        let seed_bytes = [seed; 32];
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_keygen_stateful_from_seed(
                5,
                seed_bytes.as_ptr(),
                32,
                4,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);
        provision_journal(5, &pk);
        (sk, pk)
    }

    #[test]
    fn h5_stateful_sign_and_verify_round_trip() {
        COMMITTED.with(|c| c.borrow_mut().clear());
        let (sk, pk) = h5_keypair(11);
        let journal = test_journal();

        let msg = b"stateful message";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_ne!(
            sk_out, sk,
            "the exported key must advance past the spent leaf"
        );

        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            crate::sign::pqhs_verify(
                5,
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sig.as_ptr(),
                n,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);
    }

    /// The pqhs-aww reproduction across the C boundary: one key blob, a
    /// second journal that has never been bound to it. Both journals report
    /// leaf `0`, so nothing but the binding can separate them.
    ///
    /// Leaf indices here are signer-side and zero-based, not the one-based
    /// wire `LeafCount`.
    #[test]
    fn a_journal_that_never_adopted_this_key_is_refused_across_the_boundary() {
        let (sk, pk) = h5_keypair(21);
        let msg = b"message one";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        let journal = test_journal();

        // The key's own journal signs.
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_eq!(COMMITTED.with(|c| c.borrow().clone()), vec![0]);

        // A second store: never committed anything, never bound to any key.
        COMMITTED.with(|c| c.borrow_mut().clear());
        BOUND.with(|b| *b.borrow_mut() = None);
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                b"message two".as_ptr(),
                11,
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_JOURNAL_KEY_MISMATCH);
        assert!(
            COMMITTED.with(|c| c.borrow().is_empty()),
            "the refusal lands before any leaf is committed"
        );

        // A journal bound to another key is refused on the same terms.
        let (_other_sk, other_pk) = h5_keypair(22);
        assert_ne!(identity_of(5, &pk), identity_of(5, &other_pk));
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_JOURNAL_KEY_MISMATCH);
        assert!(COMMITTED.with(|c| c.borrow().is_empty()));
    }

    /// `pqhs_adopt_key` binds once, is idempotent for the same key, and
    /// refuses a second key. `pqhs_key_identity` and
    /// `pqhs_key_identity_from_secret_key` agree.
    #[test]
    fn adopting_binds_one_key_and_refuses_another() {
        let (sk, pk) = h5_keypair(23);
        let identity = identity_of(5, &pk);

        let mut from_sk = [0u8; PQHS_KEY_IDENTITY_LEN];
        // SAFETY: both pointers are live locals of exactly the lengths
        // passed alongside them.
        let rc = unsafe {
            pqhs_key_identity_from_secret_key(
                5,
                sk.as_ptr(),
                sk.len(),
                from_sk.as_mut_ptr(),
                from_sk.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_eq!(from_sk, identity, "public and secret name the same key");

        let journal = test_journal();
        // Already bound by `h5_keypair`; re-adopting the same key is a
        // no-op, so a provisioning step can be re-run.
        // SAFETY: as above.
        let rc = unsafe { pqhs_adopt_key(&journal, identity.as_ptr(), identity.len()) };
        assert_eq!(rc, PQHS_OK);

        // A different key is refused, and the existing binding stands.
        let mut other_pk = vec![0u8; pk.len()];
        let mut other_sk = vec![0u8; sk.len()];
        let seed = [24u8; 32];
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_keygen_stateful_from_seed(
                5,
                seed.as_ptr(),
                32,
                4,
                other_sk.as_mut_ptr(),
                other_sk.len(),
                other_pk.as_mut_ptr(),
                other_pk.len(),
            )
        };
        assert_eq!(rc, PQHS_OK);
        let other = identity_of(5, &other_pk);
        // SAFETY: as above.
        let rc = unsafe { pqhs_adopt_key(&journal, other.as_ptr(), other.len()) };
        assert_eq!(rc, crate::error::PQHS_ERR_JOURNAL_KEY_MISMATCH);
        assert_eq!(
            BOUND.with(|b| *b.borrow()),
            Some(identity),
            "a refused adoption must not overwrite the binding"
        );
    }

    #[test]
    fn the_identity_entry_points_check_their_pointers_and_lengths() {
        let (sk, pk) = h5_keypair(25);
        let mut out = [0u8; PQHS_KEY_IDENTITY_LEN];
        let identity = identity_of(5, &pk);

        // SAFETY: every pointer below is either the null under test, or a
        // live local of the length passed alongside it.
        unsafe {
            assert_eq!(
                pqhs_key_identity(9, pk.as_ptr(), pk.len(), out.as_mut_ptr(), out.len()),
                crate::error::PQHS_ERR_INVALID_SUITE
            );
            assert_eq!(
                pqhs_key_identity(1, pk.as_ptr(), pk.len(), out.as_mut_ptr(), out.len()),
                crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE
            );
            assert_eq!(
                pqhs_key_identity(5, pk.as_ptr(), pk.len() - 1, out.as_mut_ptr(), out.len()),
                PQHS_ERR_BAD_LENGTH
            );
            assert_eq!(
                pqhs_key_identity(5, pk.as_ptr(), pk.len(), out.as_mut_ptr(), out.len() - 1),
                PQHS_ERR_BAD_LENGTH
            );
            assert_eq!(
                pqhs_key_identity(5, std::ptr::null(), pk.len(), out.as_mut_ptr(), out.len()),
                PQHS_ERR_NULL_POINTER
            );
            assert_eq!(
                pqhs_key_identity_from_secret_key(
                    5,
                    sk.as_ptr(),
                    sk.len() - 1,
                    out.as_mut_ptr(),
                    out.len()
                ),
                PQHS_ERR_BAD_LENGTH
            );
            assert_eq!(
                pqhs_adopt_key(std::ptr::null(), identity.as_ptr(), identity.len()),
                PQHS_ERR_NULL_POINTER
            );
        }

        // A journal missing either binding callback is a half-filled vtable,
        // not a binding failure, so it is a null-pointer error rather than
        // `PQHS_ERR_JOURNAL_KEY_MISMATCH`.
        let no_bound_key = PqhsLeafJournal {
            bound_key: None,
            ..test_journal()
        };
        let no_bind_key = PqhsLeafJournal {
            bind_key: None,
            ..test_journal()
        };
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                pqhs_adopt_key(&no_bound_key, identity.as_ptr(), identity.len()),
                PQHS_ERR_NULL_POINTER
            );
            assert_eq!(
                pqhs_adopt_key(&no_bind_key, identity.as_ptr(), identity.len()),
                PQHS_ERR_NULL_POINTER
            );
            assert_eq!(
                pqhs_adopt_key(&test_journal(), identity.as_ptr(), identity.len() - 1),
                PQHS_ERR_BAD_LENGTH
            );
            assert_eq!(
                pqhs_sign_stateful(
                    5,
                    sk.as_ptr(),
                    sk.len(),
                    &no_bound_key,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sk_out.as_mut_ptr(),
                    sk_out.len(),
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut n,
                ),
                PQHS_ERR_NULL_POINTER
            );
        }
        assert!(COMMITTED.with(|c| c.borrow().is_empty()));
    }

    #[test]
    fn a_failing_journal_reports_journal_failed_and_spends_nothing() {
        let (sk, _pk) = h5_keypair(12);
        let journal = PqhsLeafJournal {
            commit: Some(failing_commit),
            ..test_journal()
        };
        let msg = b"m";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_JOURNAL_FAILED);
    }

    #[test]
    fn a_null_journal_or_null_callback_is_rejected_not_dereferenced() {
        let (sk, _pk) = h5_keypair(13);
        let msg = b"m";
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                std::ptr::null(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);

        let half_journal = PqhsLeafJournal {
            next_leaf: None,
            ..test_journal()
        };
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &half_journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);
    }

    /// The in-place idiom -- one buffer passed as both `sk` and `sk_out` --
    /// is undefined behaviour, so it is refused rather than left to appear
    /// to work. A partial overlap is the same defect and the likelier
    /// accident.
    #[test]
    fn aliased_sk_and_sk_out_are_refused_and_spend_nothing() {
        COMMITTED.with(|c| c.borrow_mut().clear());
        let (sk, _pk) = h5_keypair(15);
        let journal = test_journal();
        let mut buf = sk.clone();
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;

        // Exactly the same range for both.
        // SAFETY: `buf` is a live, correctly sized local buffer; passing it
        // twice is the condition under test, and the call rejects it before
        // constructing either slice.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                buf.as_ptr(),
                buf.len(),
                &journal,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                buf.as_mut_ptr(),
                buf.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_ALIASED_BUFFERS);

        // Partially overlapping ranges inside one allocation.
        let mut wide = vec![0u8; sk.len() * 2];
        wide[..sk.len()].copy_from_slice(&sk);
        // SAFETY: both ranges lie inside `wide`, which outlives the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                wide.as_ptr(),
                sk.len(),
                &journal,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                wide.as_mut_ptr().add(sk.len() / 2),
                sk.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_ALIASED_BUFFERS);

        assert!(
            COMMITTED.with(|c| c.borrow().is_empty()),
            "an aliased call must be refused before any leaf is spent"
        );
        assert_eq!(buf, sk, "an aliased call must not write through sk_out");
    }

    /// A null `sig_written` used to be discovered at the end of the success
    /// path, after the leaf was spent and the signature written -- so a
    /// caller reading `PQHS_ERR_NULL_POINTER` as a rejected call would sign
    /// again and burn a second leaf.
    #[test]
    fn a_null_sig_written_is_refused_before_any_leaf_is_spent() {
        COMMITTED.with(|c| c.borrow_mut().clear());
        let (sk, _pk) = h5_keypair(16);
        let journal = test_journal();
        let mut sk_out = vec![0u8; sk.len()];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        // SAFETY: every pointer below is either null with a zero length, the
        // null `sig_written` under test, or a live, correctly sized local
        // buffer for the duration of the call.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);
        assert!(
            COMMITTED.with(|c| c.borrow().is_empty()),
            "no leaf may be spent for a call that is refused"
        );
        assert!(sk_out.iter().all(|&b| b == 0), "sk_out must be untouched");
        assert!(sig.iter().all(|&b| b == 0), "sig_out must be untouched");

        // The stateless path takes the same check.
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateless(
                5,
                sk.as_ptr(),
                sk.len(),
                &test_budget(),
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                sig.as_mut_ptr(),
                sig.len(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);
        assert!(sig.iter().all(|&b| b == 0), "sig_out must be untouched");
    }

    /// A wrong-length `sk_out` must be caught before the signer runs. When
    /// it was caught afterwards, the leaf was already committed and the
    /// advanced key was never handed back, which left the key unusable for
    /// the whole of its remaining budget.
    #[test]
    fn a_wrong_length_sk_out_spends_nothing_and_leaves_the_key_usable() {
        COMMITTED.with(|c| c.borrow_mut().clear());
        let (sk, pk) = h5_keypair(17);
        let journal = test_journal();
        let msg = b"m";
        let mut short_sk_out = vec![0u8; sk.len() - 1];
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live buffer of the length passed alongside it.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                short_sk_out.as_mut_ptr(),
                short_sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_ERR_BAD_LENGTH);
        assert!(
            COMMITTED.with(|c| c.borrow().is_empty()),
            "a wrong-length sk_out must be refused before any leaf is spent"
        );

        // The original key still signs, and the signature verifies.
        let mut sk_out = vec![0u8; sk.len()];
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                sk.as_ptr(),
                sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        let mut valid = false;
        // SAFETY: as above.
        unsafe {
            crate::sign::pqhs_verify(
                5,
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sig.as_ptr(),
                n,
                &mut valid,
            );
        }
        assert!(valid);
    }

    #[test]
    fn h5_stateless_signing_spends_no_leaf_and_can_repeat() {
        let (sk, pk) = h5_keypair(14);
        let msg = b"few-time message";
        let mut sig_a = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut sig_b = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n_a = 0usize;
        let mut n_b = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        unsafe {
            assert_eq!(
                pqhs_sign_stateless(
                    5,
                    sk.as_ptr(),
                    sk.len(),
                    &test_budget(),
                    msg.as_ptr(),
                    msg.len(),
                    std::ptr::null(),
                    0,
                    sig_a.as_mut_ptr(),
                    sig_a.len(),
                    &mut n_a,
                ),
                PQHS_OK
            );
            assert_eq!(
                pqhs_sign_stateless(
                    5,
                    sk.as_ptr(),
                    sk.len(),
                    &test_budget(),
                    msg.as_ptr(),
                    msg.len(),
                    std::ptr::null(),
                    0,
                    sig_b.as_mut_ptr(),
                    sig_b.len(),
                    &mut n_b,
                ),
                PQHS_OK
            );
            let mut valid = false;
            pqhs_verify_stateless(
                5,
                pk.as_ptr(),
                pk.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sig_a.as_ptr(),
                n_a,
                &mut valid,
            );
            assert!(valid);
        }
    }

    fn keypair(suite: u8, seed: u8) -> (Vec<u8>, Vec<u8>) {
        let mut sk = vec![
            0u8;
            pqhybridsign_abi::secret_key_len(
                pqhybridsign_abi::Suite::from_code(suite).unwrap(),
            )
        ];
        let mut pk = vec![
            0u8;
            pqhybridsign_abi::public_key_len(
                pqhybridsign_abi::Suite::from_code(suite).unwrap(),
            )
        ];
        let seed_bytes = [seed; 32];
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_keygen_stateful_from_seed(
                suite,
                seed_bytes.as_ptr(),
                32,
                4,
                sk.as_mut_ptr(),
                sk.len(),
                pk.as_mut_ptr(),
                pk.len(),
            )
        };
        assert_eq!(rc, PQHS_OK, "suite {suite} keygen");
        provision_journal(suite, &pk);
        (sk, pk)
    }

    /// `sig_out` only needs to be *at least* what a call actually writes for
    /// H5 and H6 too, mirroring the contract `pqhs_sign`/
    /// `pqhs_sign_deterministic` pin for H1-H4 in `crate::sign::tests`.
    ///
    /// Unlike H1-H4, [`pqhybridsign_abi::signature_len`] for H5/H6 is a
    /// worst-case upper bound (the largest authentication path any leaf
    /// budget could need -- see that function's doc comment), not the exact
    /// length any one call writes, so `signature_len - 1` is not
    /// necessarily short enough to trigger the error. Each sub-case below
    /// first probes the real length with one call, then re-derives short
    /// (`probed - 1`), exact (`probed`) and oversized (`probed + 64`) from
    /// that. The stateful probe and the short/oversized sub-cases each use
    /// a fresh key at leaf 0, since a leaf-spending call cannot be
    /// undone -- the authentication path length depends on the key's fixed
    /// leaf capacity, not on which leaf is spent, so leaf 0 of a fresh key
    /// gives the same length the probe measured.
    ///
    /// Covers both the leaf-spending [`pqhs_sign_stateful`] and the
    /// few-time [`pqhs_sign_stateless`] entry points: short is
    /// `PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL` (and, for the stateful path,
    /// spends no leaf), exact and oversized both succeed with the same
    /// `sig_written`.
    #[test]
    fn sig_out_accepts_exact_or_larger_and_rejects_shorter_for_h5_and_h6() {
        for suite in [5u8, 6u8] {
            let max_len =
                pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::from_code(suite).unwrap());

            // --- pqhs_sign_stateless: no leaf state to manage, so the
            // probe key is reused for every sub-case. ---
            let (sk, pk) = keypair(suite, 100 + suite);
            let mut probe = vec![0u8; max_len];
            let mut needed = 0usize;
            // SAFETY: every pointer below is either null with a zero length
            // or points at a live, correctly sized local buffer for the
            // duration of the call.
            let rc = unsafe {
                pqhs_sign_stateless(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &test_budget(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    probe.as_mut_ptr(),
                    probe.len(),
                    &mut needed,
                )
            };
            assert_eq!(rc, PQHS_OK, "suite {suite} probe pqhs_sign_stateless");

            let mut short = vec![0u8; needed - 1];
            let mut n = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateless(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &test_budget(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    short.as_mut_ptr(),
                    short.len(),
                    &mut n,
                )
            };
            assert_eq!(
                rc,
                crate::error::PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL,
                "suite {suite} short pqhs_sign_stateless"
            );

            let mut exact = vec![0u8; needed];
            let mut n_exact = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateless(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &test_budget(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    exact.as_mut_ptr(),
                    exact.len(),
                    &mut n_exact,
                )
            };
            assert_eq!(rc, PQHS_OK, "suite {suite} exact pqhs_sign_stateless");
            assert_eq!(n_exact, needed);

            let mut oversized = vec![0xffu8; needed + 64];
            let mut n_oversized = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateless(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &test_budget(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    oversized.as_mut_ptr(),
                    oversized.len(),
                    &mut n_oversized,
                )
            };
            assert_eq!(rc, PQHS_OK, "suite {suite} oversized pqhs_sign_stateless");
            assert_eq!(n_oversized, needed, "suite {suite} sig_written");
            assert!(
                oversized[n_oversized..].iter().all(|&b| b == 0xff),
                "suite {suite} bytes past sig_written must be left untouched"
            );
            let mut valid = false;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_verify_stateless(
                    suite,
                    pk.as_ptr(),
                    pk.len(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    oversized.as_ptr(),
                    n_oversized,
                    &mut valid,
                )
            };
            assert_eq!(rc, PQHS_OK);
            assert!(
                valid,
                "suite {suite} oversized-buffer signature must verify"
            );

            // --- pqhs_sign_stateful: a fresh key per sub-case, since a
            // leaf that was spent to probe the length cannot be re-spent to
            // then test the short buffer. ---
            let journal = test_journal();

            let (probe_sk, _pk) = keypair(suite, 150 + suite);
            let mut probe_sk_out = vec![0u8; probe_sk.len()];
            let mut probe = vec![0u8; max_len];
            let mut needed = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateful(
                    suite,
                    probe_sk.as_ptr(),
                    probe_sk.len(),
                    &journal,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    probe_sk_out.as_mut_ptr(),
                    probe_sk_out.len(),
                    probe.as_mut_ptr(),
                    probe.len(),
                    &mut needed,
                )
            };
            assert_eq!(rc, PQHS_OK, "suite {suite} probe pqhs_sign_stateful");

            // Every sub-case below signs at leaf 0 of a fresh key, so the
            // shared `journal` must be reset to leaf 0 too, or its
            // `next_leaf` (built from `COMMITTED`) disagrees with the fresh
            // key's own counter and the call is rejected as diverged rather
            // than exercising the buffer-size check under test.
            COMMITTED.with(|c| c.borrow_mut().clear());
            let (sk, _pk) = keypair(suite, 160 + suite);
            let mut sk_out = vec![0u8; sk.len()];
            let mut short = vec![0u8; needed - 1];
            let mut n = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateful(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &journal,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sk_out.as_mut_ptr(),
                    sk_out.len(),
                    short.as_mut_ptr(),
                    short.len(),
                    &mut n,
                )
            };
            assert_eq!(
                rc,
                crate::error::PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL,
                "suite {suite} short pqhs_sign_stateful"
            );
            // Unlike H1-H4, a short `sig_out` here does not mean nothing
            // happened: the module doc (`PQHS_ERR_OUTPUT_BUFFER_TOO_SMALL`
            // from `pqhs_sign_stateful`, in `include/pqhybridsign.h`)
            // documents that the leaf is already spent and `sk_out` already
            // holds the advanced key by the time the buffer is found too
            // small, because that can only be discovered once the signature
            // exists. That pre-existing behaviour is unrelated to the
            // relaxed `sig_out` contract this test pins and is left as is.
            assert_ne!(
                sk_out, sk,
                "suite {suite} sk_out is documented to advance even when sig_out is too small"
            );
            assert!(
                COMMITTED.with(|c| !c.borrow().is_empty()),
                "suite {suite} the leaf is documented to be spent even when sig_out is too small"
            );

            // The next fresh key starts at leaf 0 too.
            COMMITTED.with(|c| c.borrow_mut().clear());
            let (sk, _pk) = keypair(suite, 170 + suite);
            let mut sk_out_exact = vec![0u8; sk.len()];
            let mut exact = vec![0u8; needed];
            let mut n_exact = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateful(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &journal,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sk_out_exact.as_mut_ptr(),
                    sk_out_exact.len(),
                    exact.as_mut_ptr(),
                    exact.len(),
                    &mut n_exact,
                )
            };
            assert_eq!(rc, PQHS_OK, "suite {suite} exact pqhs_sign_stateful");
            assert_eq!(n_exact, needed);

            // The exact-buffer call above spent leaf 0 of its own key; reset
            // for the next fresh key's leaf 0.
            COMMITTED.with(|c| c.borrow_mut().clear());
            let (sk, _pk) = keypair(suite, 180 + suite);
            let mut sk_out_over = vec![0u8; sk.len()];
            let mut oversized = vec![0xffu8; needed + 64];
            let mut n_oversized = 0usize;
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateful(
                    suite,
                    sk.as_ptr(),
                    sk.len(),
                    &journal,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sk_out_over.as_mut_ptr(),
                    sk_out_over.len(),
                    oversized.as_mut_ptr(),
                    oversized.len(),
                    &mut n_oversized,
                )
            };
            assert_eq!(rc, PQHS_OK, "suite {suite} oversized pqhs_sign_stateful");
            assert_eq!(n_oversized, needed, "suite {suite} sig_written");
            assert!(
                oversized[n_oversized..].iter().all(|&b| b == 0xff),
                "suite {suite} bytes past sig_written must be left untouched"
            );
        }
    }

    #[test]
    fn stateful_entry_points_reject_h1_through_h4() {
        let journal = test_journal();
        let mut buf = [0u8; 4096];
        let mut buf2 = [0u8; 4096];
        let mut n = 0usize;
        for code in 1u8..=4 {
            // SAFETY: every pointer below is either null with a zero length
            // or points at a live, correctly sized local buffer for the
            // duration of the call.
            let rc = unsafe {
                pqhs_sign_stateful(
                    code,
                    buf.as_ptr(),
                    4096,
                    &journal,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    buf2.as_mut_ptr(),
                    4096,
                    buf.as_mut_ptr(),
                    4096,
                    &mut n,
                )
            };
            assert_eq!(rc, crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
            // SAFETY: as above.
            let rc = unsafe {
                pqhs_sign_stateless(
                    code,
                    buf.as_ptr(),
                    4096,
                    &test_budget(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    buf2.as_mut_ptr(),
                    4096,
                    &mut n,
                )
            };
            assert_eq!(rc, crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
        }
    }

    /// The budget vtable is required and must be complete. A null store, and
    /// a store missing either callback, are all refused before anything is
    /// read or charged -- and refused as a null-pointer error rather than as
    /// a storage fault, which would send an integrator to inspect a disk for
    /// a vtable they never filled in.
    #[test]
    fn a_null_or_incomplete_budget_vtable_is_refused_before_anything_is_charged() {
        let (sk, pk) = h5_keypair(0x31);
        provision_journal(5, &pk);
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;

        let incomplete = [
            std::ptr::null(),
            &PqhsStatelessBudget {
                ctx: std::ptr::null_mut(),
                consumed: Some(test_consumed),
                record: None,
            },
            &PqhsStatelessBudget {
                ctx: std::ptr::null_mut(),
                consumed: None,
                record: Some(test_record),
            },
        ];
        for budget in incomplete {
            // SAFETY: every pointer below is either null with a zero length,
            // or points at a live, correctly sized local for the duration of
            // the call.
            let rc = unsafe {
                pqhs_sign_stateless(
                    5,
                    sk.as_ptr(),
                    sk.len(),
                    budget,
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut n,
                )
            };
            assert_eq!(rc, PQHS_ERR_NULL_POINTER);
        }
        assert!(
            SPENT.with(|spent| spent.borrow().is_empty()),
            "a refused vtable must never reach the store"
        );
    }

    /// A store that reports it could not make the spend durable must refuse
    /// the signature, and must be reported as its own transient failure --
    /// not folded into the permanent "budget exhausted" answer, which would
    /// tell an operator to rotate a key whose only problem was a disk.
    #[test]
    fn a_budget_store_that_cannot_record_refuses_the_signature() {
        let (sk, pk) = h5_keypair(0x32);
        provision_journal(5, &pk);
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;

        let failing = PqhsStatelessBudget {
            ctx: std::ptr::null_mut(),
            consumed: Some(test_consumed),
            record: Some(failing_record),
        };
        // SAFETY: as in the test above.
        let rc = unsafe {
            pqhs_sign_stateless(
                5,
                sk.as_ptr(),
                sk.len(),
                &failing,
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, crate::error::PQHS_ERR_BUDGET_STORE_FAILED);
        assert!(
            SPENT.with(|spent| spent.borrow().is_empty()),
            "a failed record must leave nothing on record"
        );

        // The working store then signs, proving the refusal above was the
        // store and not the key.
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateless(
                5,
                sk.as_ptr(),
                sk.len(),
                &test_budget(),
                b"m".as_ptr(),
                1,
                std::ptr::null(),
                0,
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert_eq!(
            SPENT.with(|spent| spent.borrow().first().map(|(_, count)| *count)),
            Some(1)
        );
    }

    /// The small form a verifier installs: the classical public key and the
    /// commitment, recomputed from a verify-form public key its own keygen
    /// produced through `pqhybridsign_abi::stored_public_key`, which derives
    /// the commitment from `pkSeed` and `hypertreeRoot` rather than reading
    /// the value the bundle carries. Test-only: nothing in this crate's
    /// public surface derives the stored form from a verify-form key today.
    fn stored_form(verify_public_key: &[u8]) -> Vec<u8> {
        let mut stored =
            vec![0u8; pqhybridsign_abi::stored_public_key_len(pqhybridsign_abi::Suite::H5)];
        pqhybridsign_abi::stored_public_key(
            pqhybridsign_abi::Suite::H5,
            verify_public_key,
            &mut stored,
        )
        .expect("test-supplied verify-form key must decode");
        stored
    }

    /// The signer-supplied half: everything after the classical public key.
    fn bundle_of(verify_public_key: &[u8]) -> &[u8] {
        let classical_len =
            pqhybridsign_abi::stored_public_key_len(pqhybridsign_abi::Suite::H5) - 32;
        &verify_public_key[classical_len..]
    }

    /// A bundle an attacker generated verifies their own signature perfectly
    /// well through `pqhs_verify`, which has no stored key to compare it
    /// against. Binding the two is what
    /// `pqhs_verify_with_stored_public_key_stateless` adds, across the C
    /// boundary. Every signature in this test is stateless-signed, so the
    /// stateful-path entry point must refuse all of them regardless of the
    /// commitment outcome -- covered separately in
    /// `verify_with_stored_public_key_stateful_refuses_a_stateless_path_signature`.
    #[test]
    fn verify_with_stored_public_key_refuses_a_bundle_the_stored_key_does_not_name() {
        let (victim_sk, victim_pk) = h5_keypair(31);
        let (attacker_sk, attacker_pk) = h5_keypair(32);
        let victim_stored = stored_form(&victim_pk);

        let msg = b"transfer everything";
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        let budget = test_budget();
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateless(
                5,
                attacker_sk.as_ptr(),
                attacker_sk.len(),
                &budget,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sig.as_mut_ptr(),
                sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        let forged = &sig[..n];

        // Whole-key verification accepts it. `forged` is stateless-signed,
        // and plain `pqhs_verify` accepts only the stateful path for H5/H6,
        // so this goes through `pqhs_verify_stateless`.
        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_stateless(
                5,
                attacker_pk.as_ptr(),
                attacker_pk.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                forged.as_ptr(),
                forged.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);

        // Against the victim's installed commitment it is refused.
        let attacker_bundle = bundle_of(&attacker_pk);
        let mut valid = true;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateless(
                5,
                victim_stored.as_ptr(),
                victim_stored.len(),
                attacker_bundle.as_ptr(),
                attacker_bundle.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                forged.as_ptr(),
                forged.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(!valid);

        // The victim's own signature and bundle pass, proving the refusal
        // above is the commitment check and not this entry point failing to
        // verify anything at all.
        let mut honest = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateless(
                5,
                victim_sk.as_ptr(),
                victim_sk.len(),
                &budget,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                honest.as_mut_ptr(),
                honest.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        let victim_bundle = bundle_of(&victim_pk);
        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateless(
                5,
                victim_stored.as_ptr(),
                victim_stored.len(),
                victim_bundle.as_ptr(),
                victim_bundle.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                honest.as_ptr(),
                n,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);
    }

    /// A stateless-path signature -- valid against the stored commitment --
    /// is refused by the stateful-path entry point, and a stateful-path
    /// signature is refused by the stateless-path entry point. The selector
    /// decides before either component signature is checked, so this must
    /// hold regardless of whether the commitment and the underlying
    /// signature would otherwise verify.
    #[test]
    fn the_stateful_and_stateless_stored_public_key_entry_points_each_refuse_the_others_path() {
        let (victim_sk, victim_pk) = h5_keypair(33);
        let victim_stored = stored_form(&victim_pk);
        let victim_bundle = bundle_of(&victim_pk);
        let msg = b"transfer everything";

        let mut stateless_sig =
            vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut n = 0usize;
        // SAFETY: every pointer below is either null with a zero length or
        // points at a live, correctly sized local buffer for the duration
        // of the call.
        let rc = unsafe {
            pqhs_sign_stateless(
                5,
                victim_sk.as_ptr(),
                victim_sk.len(),
                &test_budget(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                stateless_sig.as_mut_ptr(),
                stateless_sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        let stateless_sig = &stateless_sig[..n];

        provision_journal(5, &victim_pk);
        let journal = test_journal();
        let mut stateful_sig =
            vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut sk_out = victim_sk.clone();
        let mut n = 0usize;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_sign_stateful(
                5,
                victim_sk.as_ptr(),
                victim_sk.len(),
                &journal,
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                sk_out.as_mut_ptr(),
                sk_out.len(),
                stateful_sig.as_mut_ptr(),
                stateful_sig.len(),
                &mut n,
            )
        };
        assert_eq!(rc, PQHS_OK);
        let stateful_sig = &stateful_sig[..n];

        let mut valid = true;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateful(
                5,
                victim_stored.as_ptr(),
                victim_stored.len(),
                victim_bundle.as_ptr(),
                victim_bundle.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                stateless_sig.as_ptr(),
                stateless_sig.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(
            !valid,
            "the stateful entry point must refuse a stateless-path signature"
        );

        let mut valid = true;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateless(
                5,
                victim_stored.as_ptr(),
                victim_stored.len(),
                victim_bundle.as_ptr(),
                victim_bundle.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                stateful_sig.as_ptr(),
                stateful_sig.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(
            !valid,
            "the stateless entry point must refuse a stateful-path signature"
        );

        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateful(
                5,
                victim_stored.as_ptr(),
                victim_stored.len(),
                victim_bundle.as_ptr(),
                victim_bundle.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                stateful_sig.as_ptr(),
                stateful_sig.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid, "the stateful entry point accepts its own path");

        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateless(
                5,
                victim_stored.as_ptr(),
                victim_stored.len(),
                victim_bundle.as_ptr(),
                victim_bundle.len(),
                msg.as_ptr(),
                msg.len(),
                std::ptr::null(),
                0,
                stateless_sig.as_ptr(),
                stateless_sig.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid, "the stateless entry point accepts its own path");
    }

    #[test]
    fn verify_with_stored_public_key_rejects_h1_through_h4_and_writes_false_on_every_path() {
        let stored = [0u8; 64];
        let bundle = [0u8; 164];
        for code in [1u8, 2, 3, 4] {
            let mut valid = true;
            // SAFETY: every pointer below is a live local buffer of the
            // length passed alongside it.
            let rc = unsafe {
                pqhs_verify_with_stored_public_key_stateful(
                    code,
                    stored.as_ptr(),
                    stored.len(),
                    bundle.as_ptr(),
                    bundle.len(),
                    b"m".as_ptr(),
                    1,
                    std::ptr::null(),
                    0,
                    b"s".as_ptr(),
                    1,
                    &mut valid,
                )
            };
            assert_eq!(rc, crate::error::PQHS_ERR_WRONG_ENTRY_POINT_FOR_SUITE);
            assert!(!valid, "suite {code}");
        }

        // A null `valid_out` is refused outright; every other pointer null
        // with a zero length is read as an empty buffer.
        // SAFETY: `valid_out` is the null pointer under test.
        let rc = unsafe {
            pqhs_verify_with_stored_public_key_stateful(
                5,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, PQHS_ERR_NULL_POINTER);
    }

    #[test]
    fn an_opened_handle_signs_twice_and_both_signatures_verify() {
        let suite = 5u8; // H5
        let (sk, pk) = h5_keypair(41);

        let mut handle: *mut PqhsStatefulKey = std::ptr::null_mut();
        // SAFETY: `sk` is a live local of `sk.len()` bytes; `handle` is a
        // live local written through as the out-parameter.
        let status = unsafe { pqhs_stateful_key_open(suite, sk.as_ptr(), sk.len(), &mut handle) };
        assert_eq!(status, PQHS_OK);
        assert!(!handle.is_null());

        let mut identity = [0u8; PQHS_KEY_IDENTITY_LEN];
        assert_eq!(
            // SAFETY: `handle` was just opened; `identity` is a live local
            // of `PQHS_KEY_IDENTITY_LEN` bytes.
            unsafe { pqhs_stateful_key_identity(handle, identity.as_mut_ptr(), identity.len()) },
            PQHS_OK
        );

        COMMITTED.with(|c| c.borrow_mut().clear());
        BOUND.with(|b| *b.borrow_mut() = None);
        let journal = test_journal();
        // SAFETY: `journal` and `identity` are live locals for the duration
        // of the call.
        assert_eq!(
            unsafe { pqhs_adopt_key(&journal, identity.as_ptr(), identity.len()) },
            PQHS_OK
        );

        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];

        for msg in [b"first".as_slice(), b"second".as_slice()] {
            let mut written = 0usize;
            // SAFETY: `handle` is the opened pointer; `journal` and every
            // buffer are live locals of the lengths passed alongside them.
            let status = unsafe {
                pqhs_stateful_key_sign(
                    handle,
                    &journal,
                    msg.as_ptr(),
                    msg.len(),
                    b"ctx".as_ptr(),
                    3,
                    sig.as_mut_ptr(),
                    sig.len(),
                    &mut written,
                )
            };
            assert_eq!(status, PQHS_OK);
            let mut valid = false;
            // SAFETY: as above.
            let rc = unsafe {
                crate::sign::pqhs_verify(
                    suite,
                    pk.as_ptr(),
                    pk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    b"ctx".as_ptr(),
                    3,
                    sig.as_ptr(),
                    written,
                    &mut valid,
                )
            };
            assert_eq!(rc, PQHS_OK);
            assert!(valid);
        }

        // SAFETY: `handle` was opened above and has not been freed.
        unsafe { pqhs_stateful_key_free(handle) };
    }

    #[test]
    fn a_null_handle_out_pointer_is_rejected() {
        let (sk, _pk) = h5_keypair(42);
        // SAFETY: `sk` is a live local of `sk.len()` bytes; the out-pointer
        // is the null pointer under test.
        let status =
            unsafe { pqhs_stateful_key_open(5, sk.as_ptr(), sk.len(), std::ptr::null_mut()) };
        assert_eq!(status, PQHS_ERR_NULL_POINTER);
    }

    #[test]
    fn freeing_a_null_handle_is_a_no_op() {
        // SAFETY: a null handle is the documented no-op for this entry
        // point.
        unsafe { pqhs_stateful_key_free(std::ptr::null_mut()) };
    }

    #[test]
    fn the_exported_blob_reopens_and_continues() {
        let suite = 5u8;
        let (sk, pk) = h5_keypair(43);
        let mut handle: *mut PqhsStatefulKey = std::ptr::null_mut();
        // SAFETY: `sk` is a live local of `sk.len()` bytes; `handle` is a
        // live local written through as the out-parameter.
        unsafe {
            pqhs_stateful_key_open(suite, sk.as_ptr(), sk.len(), &mut handle);
        }

        let mut identity = [0u8; PQHS_KEY_IDENTITY_LEN];
        // SAFETY: `handle` was just opened; `identity` is a live local of
        // `PQHS_KEY_IDENTITY_LEN` bytes.
        unsafe {
            pqhs_stateful_key_identity(handle, identity.as_mut_ptr(), identity.len());
        }
        COMMITTED.with(|c| c.borrow_mut().clear());
        BOUND.with(|b| *b.borrow_mut() = None);
        let journal = test_journal();
        // SAFETY: `journal` and `identity` are live locals for the duration
        // of the call.
        unsafe {
            pqhs_adopt_key(&journal, identity.as_ptr(), identity.len());
        }
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut written = 0usize;
        // SAFETY: `handle` is the opened pointer; `journal` and every
        // buffer are live locals of the lengths passed alongside them.
        unsafe {
            pqhs_stateful_key_sign(
                handle,
                &journal,
                b"m1".as_ptr(),
                2,
                b"c".as_ptr(),
                1,
                sig.as_mut_ptr(),
                sig.len(),
                &mut written,
            );
        }

        let mut exported = vec![0u8; sk.len()];
        let mut export_written = 0usize;
        assert_eq!(
            // SAFETY: `handle` is still the opened pointer; `exported` is a
            // live local of `sk.len()` bytes.
            unsafe {
                pqhs_stateful_key_export(
                    handle,
                    exported.as_mut_ptr(),
                    exported.len(),
                    &mut export_written,
                )
            },
            PQHS_OK
        );
        assert_eq!(export_written, sk.len());
        assert_ne!(exported, sk, "the export did not advance");
        // SAFETY: `handle` was opened above and has not been freed.
        unsafe { pqhs_stateful_key_free(handle) };

        let mut reopened: *mut PqhsStatefulKey = std::ptr::null_mut();
        // SAFETY: `exported` is the blob just written; `reopened` is a live
        // local written through as the out-parameter.
        unsafe {
            pqhs_stateful_key_open(suite, exported.as_ptr(), exported.len(), &mut reopened);
        }
        let mut written2 = 0usize;
        // SAFETY: `reopened` was just opened; the journal still belongs to
        // this key and has recorded the first spend; every buffer is a live
        // local of the length passed alongside it.
        let status = unsafe {
            pqhs_stateful_key_sign(
                reopened,
                &journal,
                b"m2".as_ptr(),
                2,
                b"c".as_ptr(),
                1,
                sig.as_mut_ptr(),
                sig.len(),
                &mut written2,
            )
        };
        assert_eq!(status, PQHS_OK);
        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            crate::sign::pqhs_verify(
                suite,
                pk.as_ptr(),
                pk.len(),
                b"m2".as_ptr(),
                2,
                b"c".as_ptr(),
                1,
                sig.as_ptr(),
                written2,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);
        // SAFETY: `reopened` was opened above and has not been freed.
        unsafe { pqhs_stateful_key_free(reopened) };
    }

    /// First C-binding exercise of [`pqhybridsign_abi::sign_stateless_with_handle`],
    /// which has no ABI-level test of its own.
    #[test]
    fn an_opened_handle_signs_stateless_and_the_signature_verifies() {
        let suite = 5u8;
        let (sk, pk) = h5_keypair(44);
        let mut handle: *mut PqhsStatefulKey = std::ptr::null_mut();
        // SAFETY: `sk` is a live local of `sk.len()` bytes; `handle` is a
        // live local written through as the out-parameter.
        assert_eq!(
            unsafe { pqhs_stateful_key_open(suite, sk.as_ptr(), sk.len(), &mut handle) },
            PQHS_OK
        );
        let mut sig = vec![0u8; pqhybridsign_abi::signature_len(pqhybridsign_abi::Suite::H5)];
        let mut written = 0usize;
        let budget = test_budget();
        // SAFETY: `handle` is the opened pointer; `budget` and every buffer
        // are live locals of the lengths passed alongside them.
        let status = unsafe {
            pqhs_stateful_key_sign_stateless(
                handle,
                &budget,
                b"few".as_ptr(),
                3,
                b"c".as_ptr(),
                1,
                sig.as_mut_ptr(),
                sig.len(),
                &mut written,
            )
        };
        assert_eq!(status, PQHS_OK);
        let mut valid = false;
        // SAFETY: as above.
        let rc = unsafe {
            pqhs_verify_stateless(
                suite,
                pk.as_ptr(),
                pk.len(),
                b"few".as_ptr(),
                3,
                b"c".as_ptr(),
                1,
                sig.as_ptr(),
                written,
                &mut valid,
            )
        };
        assert_eq!(rc, PQHS_OK);
        assert!(valid);
        // SAFETY: `handle` was opened above and has not been freed.
        unsafe { pqhs_stateful_key_free(handle) };
    }
}
