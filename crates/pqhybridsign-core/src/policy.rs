// SPDX-License-Identifier: AGPL-3.0-or-later
//! Verifier-side leaf-tracking policy: the state machine that decides how a
//! stateful leaf is accepted for one key epoch.
//!
//! Section 20 ("Two-Path Acceptance Policy") of the spec requires a
//! conforming verifier to track stateful leaf consumption under exactly one
//! active policy per key epoch: [`MonotonicIndex`](Policy::MonotonicIndex),
//! [`LeafBitmap`](Policy::LeafBitmap), or
//! [`RecoveryRotation`](Policy::RecoveryRotation). The machine here is that
//! policy, held as [`LeafPolicyMachine`].
//!
//! Three demands drive the shape of the type:
//!
//! - **Total and fail closed.** Every `(policy, freeze, arming)` state this
//!   type can hold has an explicit, exhaustively-matched acceptance rule.
//!   `freeze` and `arming` are only representable inside the policy variant
//!   they describe, so there is no `bool` whose meaning depends on which
//!   policy happens to be active, and no state a future match arm could
//!   silently fall through to a catch-all accept.
//! - **Accept and mark-consumed are one atomic step**, the same discipline
//!   [`accept_monotonic_leaf`]
//!   already applies: nothing durable moves before the record succeeds, so a
//!   caller never observes an accepted leaf that a crash could still lose.
//! - **The freeze is per epoch, not per call.** Once any leaf is consumed
//!   under `MonotonicIndex` or `LeafBitmap`, this epoch's choice between the
//!   two locks; only a new epoch (spec 19.3, on a valid rotation) re-opens
//!   it. The owner-authorized move to `RecoveryRotation` is exempt from the
//!   freeze, or a key that had already signed once could never be rotated.

use core::fmt;

use crate::stateful::{accept_monotonic_leaf, LeafIndexStore, ReplayRejected};

/// Number of addressable leaves in [`LeafBitmap`]: 4096 bits, matching the
/// stateful scheme's leaf-budget ceiling (`MAX_STATEFUL_SIGNATURES_LIMIT` in
/// `pqhybridsign-shrincs`). Leaf indices are one-based (see
/// [`crate::stateful::ReplayRejected::ZeroLeaf`]), so the addressable range
/// is `1..LEAF_BITMAP_CAPACITY`; index `0` and any index at or above this
/// capacity are refused.
pub const LEAF_BITMAP_CAPACITY: u32 = 4096;

/// Bytes backing [`LeafBitmap`]: `LEAF_BITMAP_CAPACITY / 8`.
const LEAF_BITMAP_BYTES: usize = (LEAF_BITMAP_CAPACITY / 8) as usize;

/// A fixed-size, per-epoch record of which stateful leaves have been
/// consumed under the `LeafBitmap` policy.
///
/// `[u8; 512]` is 4096 bits, one per leaf in [`LEAF_BITMAP_CAPACITY`]. It is
/// not an allocation, so `pqhybridsign-core` stays usable without the
/// `alloc` feature. Namespacing a bitmap by key epoch is structural, not a
/// runtime check: [`LeafPolicyMachine::new_epoch_bitmap`] starts from a
/// fresh, all-zero bitmap, so a rotation frees every leaf at once instead of
/// clearing bits one at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafBitmap {
    bits: [u8; LEAF_BITMAP_BYTES],
}

impl Default for LeafBitmap {
    fn default() -> Self {
        Self {
            bits: [0u8; LEAF_BITMAP_BYTES],
        }
    }
}

impl LeafBitmap {
    /// An empty bitmap: no leaf consumed.
    pub fn new() -> Self {
        Self::default()
    }

    fn is_set(&self, leaf: u32) -> bool {
        let byte = (leaf / 8) as usize;
        let bit = leaf % 8;
        self.bits[byte] & (1 << bit) != 0
    }

    fn set(&mut self, leaf: u32) {
        let byte = (leaf / 8) as usize;
        let bit = leaf % 8;
        self.bits[byte] |= 1 << bit;
    }

    /// Accept `leaf` if it is in range and not already consumed, and mark it
    /// consumed in the same step.
    ///
    /// The range check runs before any indexing, so an out-of-range `leaf`
    /// is refused rather than panicking.
    fn accept(&mut self, leaf: u32) -> Result<(), BitmapRejected> {
        if leaf == 0 {
            return Err(BitmapRejected::ZeroLeaf);
        }
        if leaf >= LEAF_BITMAP_CAPACITY {
            return Err(BitmapRejected::OutOfRange {
                leaf,
                capacity: LEAF_BITMAP_CAPACITY,
            });
        }
        if self.is_set(leaf) {
            return Err(BitmapRejected::AlreadyConsumed { leaf });
        }
        self.set(leaf);
        Ok(())
    }
}

/// Why `LeafBitmap::accept` refused a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitmapRejected {
    /// Leaf indices are one-based; zero is never valid.
    ZeroLeaf,
    /// This exact leaf was already accepted this epoch.
    AlreadyConsumed {
        /// The offered leaf index.
        leaf: u32,
    },
    /// The leaf index is outside the bitmap's fixed capacity.
    OutOfRange {
        /// The offered leaf index.
        leaf: u32,
        /// The bitmap's capacity ([`LEAF_BITMAP_CAPACITY`]).
        capacity: u32,
    },
}

/// The public tag for which policy is active. Reading this never exposes
/// `freeze` or `arming`, which are only meaningful alongside the policy that
/// carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Accept only the next expected leaf index; advance on success.
    MonotonicIndex,
    /// Accept any leaf whose bit is clear in the per-epoch bitmap; set on
    /// success.
    LeafBitmap,
    /// Reject every stateful signature; accept only rotation, and only once
    /// armed.
    RecoveryRotation,
}

/// One of the two leaf-consuming policies: the subset of [`Policy`] that
/// [`LeafPolicyMachine::switch_consuming_policy`] can select. `RecoveryRotation`
/// is not a member, because switching into it needs owner authorization and
/// is exempt from the freeze rule; that is a separate operation
/// ([`LeafPolicyMachine::authorize_recovery`]), not a member of this choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsumingPolicy {
    /// See [`Policy::MonotonicIndex`].
    MonotonicIndex,
    /// See [`Policy::LeafBitmap`].
    LeafBitmap,
}

/// Whether this epoch's choice between the two leaf-consuming policies is
/// still open, or has frozen because a leaf was consumed.
///
/// This lives only inside [`PolicyState::MonotonicIndex`] and
/// [`PolicyState::LeafBitmap`]: `RecoveryRotation` has no freeze state,
/// because the choice this field tracks does not apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freeze {
    Open,
    Frozen,
}

/// Whether the account owner has armed recovery, authorizing the next
/// `RecoveryRotation` to accept a rotation.
///
/// This lives only inside [`PolicyState::RecoveryRotation`]: arming has no
/// meaning for the two leaf-consuming policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arming {
    Disarmed,
    Armed,
}

/// The private representation. Each variant carries exactly the state that
/// policy needs and no more, so an invalid combination -- an armed
/// `MonotonicIndex`, a frozen `RecoveryRotation` -- has no value that
/// constructs it.
///
/// `LeafBitmap`'s 512-byte payload makes this enum far larger than its other
/// variants. Boxing it would shrink the enum, but a box is an allocation,
/// and this type must stay usable without the `alloc` feature; the brief
/// requires `LeafBitmap` to be a fixed array precisely so it is not one. The
/// size cost is paid once per epoch's machine, not per leaf accepted.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyState {
    MonotonicIndex(Freeze),
    LeafBitmap(LeafBitmap, Freeze),
    RecoveryRotation(Arming),
}

/// The account owner's authorization for an operation that this module
/// cannot itself verify (see [`LeafPolicyMachine::authorize_recovery`] and
/// [`LeafPolicyMachine::arm_recovery`]).
///
/// An explicit enum, not a `bool`: the caller must name what "true" means at
/// the call site, and `Denied` reads as a decision rather than an absent
/// check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerAuthorization {
    /// The caller has verified the owner-authorized AND-gate (spec 19.2):
    /// both the classical co-signature and the stateless SHRINCS signature
    /// over the rotation payload.
    Granted,
    /// The AND-gate did not verify, or was not attempted.
    Denied,
}

/// Why a stateful leaf was refused before it reached `LeafBitmap::accept`
/// or [`accept_monotonic_leaf`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeafRejected {
    /// Refused by the monotonic-index rule.
    Monotonic(ReplayRejected),
    /// Refused by the bitmap rule.
    Bitmap(BitmapRejected),
    /// The active policy is the other leaf-consuming representation. Calling
    /// `accept_bitmap_leaf` while `MonotonicIndex` is active, or vice versa,
    /// is a caller bug, not a replay -- it is refused all the same, because a
    /// verifier that let the wrong call through would consume state under
    /// the representation the epoch never committed to.
    WrongPolicy,
    /// The active policy is `RecoveryRotation`, which accepts no stateful
    /// signatures.
    RecoveryPolicyActive,
}

/// Why [`LeafPolicyMachine::switch_consuming_policy`] refused a switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwitchRejected {
    /// A leaf has already been consumed this epoch; the choice between
    /// `MonotonicIndex` and `LeafBitmap` is frozen until the next epoch.
    Frozen,
    /// The active policy is `RecoveryRotation`. There is no path back to a
    /// leaf-consuming policy within an epoch that has moved to recovery;
    /// only a new epoch reopens the choice.
    RecoveryPolicyActive,
}

/// Why [`LeafPolicyMachine::authorize_recovery`] refused the transition into
/// `RecoveryRotation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryEntryRejected {
    /// The caller did not present a granted [`OwnerAuthorization`].
    NotOwnerAuthorized,
}

/// Why [`LeafPolicyMachine::arm_recovery`] refused to arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryArmRejected {
    /// The caller did not present a granted [`OwnerAuthorization`].
    NotOwnerAuthorized,
    /// The active policy is not `RecoveryRotation`; there is nothing to arm.
    NotInRecoveryRotation,
}

/// Why [`LeafPolicyMachine::accept_rotation`] refused a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RotationRejected {
    /// The active policy is not `RecoveryRotation`.
    NotInRecoveryRotation,
    /// `RecoveryRotation` is active but recovery has not been armed.
    NotArmed,
}

impl fmt::Display for RotationRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInRecoveryRotation => {
                write!(f, "active policy is not RecoveryRotation")
            }
            Self::NotArmed => write!(f, "recovery has not been armed"),
        }
    }
}

/// The verifier-side leaf-tracking state for one key epoch.
///
/// Construct one with [`new_epoch_monotonic`](Self::new_epoch_monotonic) or
/// [`new_epoch_bitmap`](Self::new_epoch_bitmap) when a key epoch opens (a
/// fresh key, or the epoch that follows a valid rotation -- spec 19.3).
/// Everything this type does is total: every public method matches every
/// state it can be in and returns an explicit rejection where the spec does
/// not grant acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafPolicyMachine {
    state: PolicyState,
}

impl LeafPolicyMachine {
    /// Start a new key epoch under `MonotonicIndex`, unfrozen. This is the
    /// rotation-install default (spec 19.3): a verifier resets to
    /// `MonotonicIndex` on every valid rotation unless it explicitly selects
    /// `LeafBitmap` afterward.
    pub fn new_epoch_monotonic() -> Self {
        Self {
            state: PolicyState::MonotonicIndex(Freeze::Open),
        }
    }

    /// Start a new key epoch under `LeafBitmap`, unfrozen, with a fresh
    /// (all-zero) bitmap.
    pub fn new_epoch_bitmap() -> Self {
        Self {
            state: PolicyState::LeafBitmap(LeafBitmap::default(), Freeze::Open),
        }
    }

    /// The active policy for this epoch.
    pub fn active_policy(&self) -> Policy {
        match self.state {
            PolicyState::MonotonicIndex(_) => Policy::MonotonicIndex,
            PolicyState::LeafBitmap(..) => Policy::LeafBitmap,
            PolicyState::RecoveryRotation(_) => Policy::RecoveryRotation,
        }
    }

    /// Whether this epoch's choice between `MonotonicIndex` and `LeafBitmap`
    /// has frozen. Always `false` once the policy has moved to
    /// `RecoveryRotation` -- freeze no longer applies there, and the answer
    /// would be misleading either way.
    pub fn is_frozen(&self) -> bool {
        matches!(
            self.state,
            PolicyState::MonotonicIndex(Freeze::Frozen)
                | PolicyState::LeafBitmap(_, Freeze::Frozen)
        )
    }

    /// Switch between `MonotonicIndex` and `LeafBitmap` for this epoch.
    ///
    /// Refused once any leaf has been consumed under either representation:
    /// switching after that point would either re-open leaves the old
    /// representation already marked consumed, or require reconciling two
    /// representations, which the spec forbids outright.
    pub fn switch_consuming_policy(&mut self, to: ConsumingPolicy) -> Result<(), SwitchRejected> {
        let freeze = match self.state {
            PolicyState::MonotonicIndex(freeze) => freeze,
            PolicyState::LeafBitmap(_, freeze) => freeze,
            PolicyState::RecoveryRotation(_) => return Err(SwitchRejected::RecoveryPolicyActive),
        };
        if freeze == Freeze::Frozen {
            return Err(SwitchRejected::Frozen);
        }
        self.state = match to {
            ConsumingPolicy::MonotonicIndex => PolicyState::MonotonicIndex(Freeze::Open),
            ConsumingPolicy::LeafBitmap => {
                PolicyState::LeafBitmap(LeafBitmap::default(), Freeze::Open)
            }
        };
        Ok(())
    }

    /// Accept a stateful leaf under `MonotonicIndex`, and mark it consumed
    /// in the same step.
    ///
    /// `store` is durable state the caller owns (see [`LeafIndexStore`]).
    /// Recording happens before this returns success, the same ordering
    /// [`accept_monotonic_leaf`] already enforces: a failed record means
    /// nothing was accepted.
    pub fn accept_monotonic_leaf<S: LeafIndexStore>(
        &mut self,
        store: &mut S,
        leaf: u32,
    ) -> Result<(), LeafRejected> {
        match &mut self.state {
            PolicyState::MonotonicIndex(freeze) => {
                accept_monotonic_leaf(store, leaf).map_err(LeafRejected::Monotonic)?;
                *freeze = Freeze::Frozen;
                Ok(())
            }
            PolicyState::LeafBitmap(..) => Err(LeafRejected::WrongPolicy),
            PolicyState::RecoveryRotation(_) => Err(LeafRejected::RecoveryPolicyActive),
        }
    }

    /// Accept a stateful leaf under `LeafBitmap`, and mark it consumed in
    /// the same step.
    pub fn accept_bitmap_leaf(&mut self, leaf: u32) -> Result<(), LeafRejected> {
        match &mut self.state {
            PolicyState::LeafBitmap(bitmap, freeze) => {
                bitmap.accept(leaf).map_err(LeafRejected::Bitmap)?;
                *freeze = Freeze::Frozen;
                Ok(())
            }
            PolicyState::MonotonicIndex(_) => Err(LeafRejected::WrongPolicy),
            PolicyState::RecoveryRotation(_) => Err(LeafRejected::RecoveryPolicyActive),
        }
    }

    /// Owner-authorized transition into `RecoveryRotation`, disarmed.
    ///
    /// Available regardless of freeze state: a key that has already signed
    /// once (and so is frozen into `MonotonicIndex` or `LeafBitmap`) must
    /// still be rotatable, or it could never be rotated at all.
    ///
    /// `authorization` is the caller's already-verified outcome of the
    /// owner-authorized AND-gate (spec 19.2). This function does not verify
    /// signatures; it only gates the state transition on the caller's
    /// verdict.
    pub fn authorize_recovery(
        &mut self,
        authorization: OwnerAuthorization,
    ) -> Result<(), RecoveryEntryRejected> {
        match authorization {
            OwnerAuthorization::Denied => Err(RecoveryEntryRejected::NotOwnerAuthorized),
            OwnerAuthorization::Granted => {
                self.state = PolicyState::RecoveryRotation(Arming::Disarmed);
                Ok(())
            }
        }
    }

    /// Owner-authorized arming of a `RecoveryRotation` already entered via
    /// [`authorize_recovery`](Self::authorize_recovery).
    ///
    /// Arming is a distinct authorization from entering `RecoveryRotation`:
    /// a verifier may recognize that recovery mode applies before the owner
    /// has actually confirmed the specific rotation, and only the confirmed
    /// rotation may spend the owner's authorization.
    pub fn arm_recovery(
        &mut self,
        authorization: OwnerAuthorization,
    ) -> Result<(), RecoveryArmRejected> {
        match &mut self.state {
            PolicyState::RecoveryRotation(arming) => match authorization {
                OwnerAuthorization::Denied => Err(RecoveryArmRejected::NotOwnerAuthorized),
                OwnerAuthorization::Granted => {
                    *arming = Arming::Armed;
                    Ok(())
                }
            },
            PolicyState::MonotonicIndex(_) | PolicyState::LeafBitmap(..) => {
                Err(RecoveryArmRejected::NotInRecoveryRotation)
            }
        }
    }

    /// Accept a rotation. Succeeds only when `RecoveryRotation` is active
    /// and armed.
    ///
    /// This gates whether the policy machine permits the rotation to
    /// proceed; installing the new commitment, advancing `keyVersion`, and
    /// opening the next epoch's policy (spec 19.3) is the caller's job --
    /// typically by constructing a fresh [`LeafPolicyMachine`] with
    /// [`new_epoch_monotonic`](Self::new_epoch_monotonic) once this returns
    /// `Ok`.
    pub fn accept_rotation(&self) -> Result<(), RotationRejected> {
        match self.state {
            PolicyState::RecoveryRotation(Arming::Armed) => Ok(()),
            PolicyState::RecoveryRotation(Arming::Disarmed) => Err(RotationRejected::NotArmed),
            PolicyState::MonotonicIndex(_) | PolicyState::LeafBitmap(..) => {
                Err(RotationRejected::NotInRecoveryRotation)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`LeafIndexStore`] that can be told to fail, so the atomicity and
    /// fail-closed paths are testable without I/O.
    #[derive(Default)]
    struct MemoryIndex {
        highest: Option<u32>,
        fail: bool,
    }

    impl LeafIndexStore for MemoryIndex {
        type Error = ();

        fn highest_accepted(&self) -> Option<u32> {
            self.highest
        }

        fn record(&mut self, leaf: u32) -> Result<(), Self::Error> {
            if self.fail {
                return Err(());
            }
            self.highest = Some(leaf);
            Ok(())
        }
    }

    // Demand 1: exactly one active policy per key epoch. Each accept method
    // works only for the policy it names; the other leaf-consuming
    // representation and `RecoveryRotation` both refuse it, so a caller can
    // never accept two leaves for one epoch under two different policies.
    #[test]
    fn exactly_one_policy_is_active_per_epoch() {
        let mut monotonic = LeafPolicyMachine::new_epoch_monotonic();
        assert_eq!(monotonic.active_policy(), Policy::MonotonicIndex);
        assert_eq!(
            monotonic.accept_bitmap_leaf(1),
            Err(LeafRejected::WrongPolicy)
        );

        let mut bitmap = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(bitmap.active_policy(), Policy::LeafBitmap);
        let mut store = MemoryIndex::default();
        assert_eq!(
            bitmap.accept_monotonic_leaf(&mut store, 1),
            Err(LeafRejected::WrongPolicy)
        );
    }

    // Demand 2: total and fail closed. A `RecoveryRotation` that has not
    // been armed grants nothing -- not a stateful leaf, not a rotation --
    // even though the policy is "active". There is no implicit accept.
    #[test]
    fn fail_closed_default_grants_nothing_until_explicitly_armed() {
        let mut machine = LeafPolicyMachine::new_epoch_monotonic();
        machine
            .authorize_recovery(OwnerAuthorization::Granted)
            .expect("owner authorization enters RecoveryRotation");
        assert_eq!(machine.active_policy(), Policy::RecoveryRotation);

        let mut store = MemoryIndex::default();
        assert_eq!(
            machine.accept_monotonic_leaf(&mut store, 1),
            Err(LeafRejected::RecoveryPolicyActive)
        );
        assert_eq!(
            machine.accept_bitmap_leaf(1),
            Err(LeafRejected::RecoveryPolicyActive)
        );
        assert_eq!(
            machine.accept_rotation(),
            Err(RotationRejected::NotArmed),
            "RecoveryRotation grants a rotation only once armed, never by default"
        );
    }

    // Demand 3: accept and mark-consumed are one atomic step. A store
    // failure must leave nothing recorded, the freeze untouched, and the
    // leaf still available once the store recovers.
    #[test]
    fn a_store_failure_leaves_nothing_recorded_and_accepts_nothing() {
        let mut machine = LeafPolicyMachine::new_epoch_monotonic();
        let mut store = MemoryIndex {
            fail: true,
            ..Default::default()
        };

        let outcome = machine.accept_monotonic_leaf(&mut store, 1);

        assert_eq!(
            outcome,
            Err(LeafRejected::Monotonic(ReplayRejected::StoreFailed))
        );
        assert_eq!(store.highest_accepted(), None);
        assert!(
            !machine.is_frozen(),
            "a failed record must not freeze the epoch's policy choice"
        );

        // Once the store recovers, the same leaf is still available, and
        // this time the epoch does freeze.
        store.fail = false;
        assert_eq!(machine.accept_monotonic_leaf(&mut store, 1), Ok(()));
        assert!(machine.is_frozen());
    }

    // Demand 4: once any stateful leaf is consumed in an epoch, the choice
    // between `MonotonicIndex` and `LeafBitmap` freezes.
    #[test]
    fn switching_policy_after_a_consumed_leaf_is_refused() {
        let mut machine = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(machine.accept_bitmap_leaf(1), Ok(()));

        assert_eq!(
            machine.switch_consuming_policy(ConsumingPolicy::MonotonicIndex),
            Err(SwitchRejected::Frozen)
        );
        assert_eq!(machine.active_policy(), Policy::LeafBitmap);

        // Before any leaf is consumed, the choice is still open.
        let mut fresh = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(
            fresh.switch_consuming_policy(ConsumingPolicy::MonotonicIndex),
            Ok(())
        );
        assert_eq!(fresh.active_policy(), Policy::MonotonicIndex);
    }

    // Demand 5: the owner-authorized transition to `RecoveryRotation` stays
    // available even when frozen.
    #[test]
    fn recovery_transition_is_available_on_a_frozen_epoch() {
        let mut machine = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(machine.accept_bitmap_leaf(1), Ok(()));
        assert!(machine.is_frozen());

        assert_eq!(
            machine.authorize_recovery(OwnerAuthorization::Granted),
            Ok(())
        );
        assert_eq!(machine.active_policy(), Policy::RecoveryRotation);

        assert_eq!(machine.arm_recovery(OwnerAuthorization::Granted), Ok(()));
        assert_eq!(machine.accept_rotation(), Ok(()));
    }

    // Demand 6, part one: `RecoveryRotation` rejects every stateful
    // signature.
    #[test]
    fn recovery_rotation_rejects_every_stateful_signature() {
        let mut machine = LeafPolicyMachine::new_epoch_monotonic();
        machine
            .authorize_recovery(OwnerAuthorization::Granted)
            .expect("owner authorization enters RecoveryRotation");
        machine
            .arm_recovery(OwnerAuthorization::Granted)
            .expect("owner authorization arms recovery");

        let mut store = MemoryIndex::default();
        assert_eq!(
            machine.accept_monotonic_leaf(&mut store, 1),
            Err(LeafRejected::RecoveryPolicyActive)
        );
        assert_eq!(
            machine.accept_bitmap_leaf(1),
            Err(LeafRejected::RecoveryPolicyActive)
        );
    }

    // Demand 6, part two: an unarmed `RecoveryRotation` rejects rotation.
    #[test]
    fn an_unarmed_recovery_rotation_rejects_rotation() {
        let mut machine = LeafPolicyMachine::new_epoch_monotonic();
        machine
            .authorize_recovery(OwnerAuthorization::Granted)
            .expect("owner authorization enters RecoveryRotation");

        assert_eq!(machine.accept_rotation(), Err(RotationRejected::NotArmed));
    }

    // Demand 7: a new key epoch re-opens the choice between the two
    // consuming policies, and a fresh bitmap frees every leaf at once.
    #[test]
    fn a_new_epoch_reopens_the_consuming_policy_choice() {
        let mut previous = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(previous.accept_bitmap_leaf(1), Ok(()));
        assert!(previous.is_frozen());
        assert_eq!(
            previous.switch_consuming_policy(ConsumingPolicy::MonotonicIndex),
            Err(SwitchRejected::Frozen)
        );

        // The next epoch, after a valid rotation, starts over: the default
        // is `MonotonicIndex` (spec 19.3), but the choice is open again.
        let mut next = LeafPolicyMachine::new_epoch_monotonic();
        assert!(!next.is_frozen());
        assert_eq!(
            next.switch_consuming_policy(ConsumingPolicy::LeafBitmap),
            Ok(())
        );

        // Leaf 1, refused a moment ago in the previous epoch's bitmap, is
        // free again in the new epoch's bitmap -- freed wholesale by
        // constructing a fresh bitmap, not by clearing bit 1 specifically.
        assert_eq!(next.accept_bitmap_leaf(1), Ok(()));
    }

    // Negative case named explicitly in the brief: a leaf accepted twice
    // under `LeafBitmap` is refused the second time.
    #[test]
    fn a_bitmap_leaf_accepted_twice_is_refused_the_second_time() {
        let mut machine = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(machine.accept_bitmap_leaf(5), Ok(()));
        assert_eq!(
            machine.accept_bitmap_leaf(5),
            Err(LeafRejected::Bitmap(BitmapRejected::AlreadyConsumed {
                leaf: 5
            }))
        );
    }

    // Negative case named explicitly in the brief: a leaf index of 0, and
    // one at or above the bitmap's capacity, are both refused -- never a
    // panic.
    #[test]
    fn bitmap_leaf_zero_and_over_capacity_are_both_refused() {
        let mut machine = LeafPolicyMachine::new_epoch_bitmap();
        assert_eq!(
            machine.accept_bitmap_leaf(0),
            Err(LeafRejected::Bitmap(BitmapRejected::ZeroLeaf))
        );
        assert_eq!(
            machine.accept_bitmap_leaf(LEAF_BITMAP_CAPACITY),
            Err(LeafRejected::Bitmap(BitmapRejected::OutOfRange {
                leaf: LEAF_BITMAP_CAPACITY,
                capacity: LEAF_BITMAP_CAPACITY,
            }))
        );
        assert_eq!(
            machine.accept_bitmap_leaf(LEAF_BITMAP_CAPACITY + 1000),
            Err(LeafRejected::Bitmap(BitmapRejected::OutOfRange {
                leaf: LEAF_BITMAP_CAPACITY + 1000,
                capacity: LEAF_BITMAP_CAPACITY,
            }))
        );
        // Neither refusal left the epoch frozen: nothing was consumed.
        assert!(!machine.is_frozen());
    }

    // Owner authorization is checked, not assumed: a denied authorization
    // neither enters nor arms `RecoveryRotation`.
    #[test]
    fn a_denied_authorization_grants_neither_entry_nor_arming() {
        let mut machine = LeafPolicyMachine::new_epoch_monotonic();
        assert_eq!(
            machine.authorize_recovery(OwnerAuthorization::Denied),
            Err(RecoveryEntryRejected::NotOwnerAuthorized)
        );
        assert_eq!(machine.active_policy(), Policy::MonotonicIndex);

        machine
            .authorize_recovery(OwnerAuthorization::Granted)
            .expect("owner authorization enters RecoveryRotation");
        assert_eq!(
            machine.arm_recovery(OwnerAuthorization::Denied),
            Err(RecoveryArmRejected::NotOwnerAuthorized)
        );
        assert_eq!(machine.accept_rotation(), Err(RotationRejected::NotArmed));
    }

    // Arming outside `RecoveryRotation` is refused with a distinct reason
    // from a denied authorization.
    #[test]
    fn arming_outside_recovery_rotation_is_refused() {
        let mut machine = LeafPolicyMachine::new_epoch_monotonic();
        assert_eq!(
            machine.arm_recovery(OwnerAuthorization::Granted),
            Err(RecoveryArmRejected::NotInRecoveryRotation)
        );
    }
}
