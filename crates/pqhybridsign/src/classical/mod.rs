// SPDX-License-Identifier: AGPL-3.0-or-later
//! Classical signature components: [`Ed25519`] and [`Sr25519`].

use zeroize::Zeroize;

mod ed25519;
mod sr25519;

pub use ed25519::Ed25519;
pub use sr25519::Sr25519;

/// Holds a secret value so that its wipe happens on drop.
///
/// Both components hold short-lived copies of real key material in locals of
/// types that have no destructor of their own. schnorrkel 0.11.5 implements
/// `Drop` only for `Keypair`; `MiniSecretKey` and `SecretKey` derive `Zeroize`
/// but have no destructor. `curve25519_dalek::Scalar` is the same: it derives
/// `Zeroize` under the `zeroize` feature and is `Copy`, so a plain local leaves
/// the secret scalar in the stack frame verbatim.
///
/// A bare `zeroize()` call at the end of each function would fix today's code
/// and quietly stop working the moment somebody adds an early return or a `?`
/// above it. Holding the value here makes the wipe structural instead: it runs
/// on every exit path, including a panic unwind.
pub(crate) struct Wiped<T: Zeroize>(pub(crate) T);

impl<T: Zeroize> Drop for Wiped<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
