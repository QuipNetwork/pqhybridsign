// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{ClassicalScheme, PqScheme, PqStatefulScheme};

/// One hybrid construction: a classical component, a post-quantum
/// component, and the label that separates it from every other suite.
///
/// Modelled on the Noise Protocol Framework, where the protocol name is
/// composed from its primitives and then bound cryptographically. Here the
/// composed name is the label prepended into `M'`.
pub trait Suite {
    type Classical: ClassicalScheme;
    type Pq: PqScheme;

    /// Null-terminated registry label from specification section 7.
    const LABEL: &'static [u8];

    const PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqScheme>::PUBLIC_KEY_LEN;
    const SECRET_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::SECRET_KEY_LEN
        + <Self::Pq as PqScheme>::SECRET_KEY_LEN;
    const SIGNATURE_LEN: usize =
        <Self::Classical as ClassicalScheme>::SIGNATURE_LEN + <Self::Pq as PqScheme>::SIGNATURE_LEN;
    /// Byte offset where the post-quantum half begins.
    const SPLIT: usize = <Self::Classical as ClassicalScheme>::SIGNATURE_LEN;
}

/// Declare a hybrid suite.
///
/// Composes the label as `"hybrid-" classical "-" pq "-v1"` plus a null
/// byte, then checks the result against the registry literal and its byte
/// count at compile time. A typo becomes a build failure, not a silently
/// incompatible signature.
#[macro_export]
macro_rules! hybrid_suite {
    (
        $(#[$meta:meta])*
        $name:ident,
        classical = $classical:ty as $ctok:literal,
        pq = $pq:ty as $ptok:literal,
        label = $label:literal,
        label_len = $len:literal $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl $crate::Suite for $name {
            type Classical = $classical;
            type Pq = $pq;
            const LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1", "\0").as_bytes();
        }

        const _: () = {
            // The composed name must equal the registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1"),
                    $label,
                ),
                "composed suite label does not match the registry literal",
            );
            // The byte count must equal the registry byte count, which
            // includes the trailing null byte.
            assert!(
                $label.len() + 1 == $len,
                "label length does not match the registry byte count",
            );
            // Each name token must equal its component's NAME constant.
            assert!(
                $crate::suite::const_str_eq(
                    <$classical as $crate::ClassicalScheme>::NAME, $ctok,
                ),
                "classical name token does not match ClassicalScheme::NAME",
            );
            assert!(
                $crate::suite::const_str_eq(
                    <$pq as $crate::PqScheme>::NAME, $ptok,
                ),
                "post-quantum name token does not match PqScheme::NAME",
            );
        };
    };
}

/// One stateful hybrid construction: a classical component, a stateful
/// post-quantum component, and the label that separates it from every other
/// suite.
///
/// Mirrors [`Suite`], but its post-quantum half is [`PqStatefulScheme`]
/// rather than [`PqScheme`]: a stateful signature spends a one-time leaf and
/// its encoded length varies with the leaf index, neither of which
/// [`PqScheme`]'s fixed-length, stateless shape can express.
///
/// `STORED_PUBLIC_KEY_LEN` is the small on-storage form (a classical public
/// key plus a commitment); `VERIFY_PUBLIC_KEY_LEN` is the larger form a
/// verifier needs at verification time (a classical public key plus the
/// full verify key). There is no single `SIGNATURE_LEN`: see
/// [`PqStatefulScheme::FIXED_STATEFUL_SIG_LEN`] and
/// [`PqStatefulScheme::STATELESS_SIG_LEN`].
pub trait StatefulSuite {
    type Classical: ClassicalScheme;
    type Pq: PqStatefulScheme;

    /// Null-terminated registry label from specification section 7.
    const LABEL: &'static [u8];

    /// Null-terminated registry label for the rotation domain, specification
    /// section 19.2. Distinct from [`LABEL`](Self::LABEL) so an ordinary
    /// classical signature can never be spliced in as a rotation
    /// co-signature.
    const ROTATE_LABEL: &'static [u8];

    const STORED_PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqStatefulScheme>::PUBLIC_KEY_LEN;
    const VERIFY_PUBLIC_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::PUBLIC_KEY_LEN
        + <Self::Pq as PqStatefulScheme>::VERIFY_KEY_LEN;
    const SECRET_KEY_LEN: usize = <Self::Classical as ClassicalScheme>::SECRET_KEY_LEN
        + <Self::Pq as PqStatefulScheme>::SECRET_KEY_LEN;
    /// Byte offset where the post-quantum half begins in the composite wire
    /// encoding (`pqhybridsign_core::encoding_path`).
    const SPLIT: usize = <Self::Classical as ClassicalScheme>::SIGNATURE_LEN;
}

/// Declare a stateful hybrid suite.
///
/// Same compile-time discipline as [`hybrid_suite!`]: composes the label as
/// `"hybrid-" classical "-" pq "-v1"` plus a null byte, then checks the
/// result against the registry literal and its byte count, and each name
/// token against its component's `NAME`, all at compile time. The rotation
/// label (specification section 19.2) gets the same treatment: composed as
/// `"hybrid-" classical "-" pq "-rotate-v1"` plus a null byte, checked
/// against its own registry literal and byte count.
#[macro_export]
macro_rules! hybrid_stateful_suite {
    (
        $(#[$meta:meta])*
        $name:ident,
        classical = $classical:ty as $ctok:literal,
        pq = $pq:ty as $ptok:literal,
        label = $label:literal,
        label_len = $len:literal,
        rotate_label = $rotate_label:literal,
        rotate_label_len = $rotate_len:literal $(,)?
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl $crate::StatefulSuite for $name {
            type Classical = $classical;
            type Pq = $pq;
            const LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1", "\0").as_bytes();
            const ROTATE_LABEL: &'static [u8] =
                ::core::concat!("hybrid-", $ctok, "-", $ptok, "-rotate-v1", "\0").as_bytes();
        }

        const _: () = {
            // The composed name must equal the registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-v1"),
                    $label,
                ),
                "composed suite label does not match the registry literal",
            );
            // The byte count must equal the registry byte count, which
            // includes the trailing null byte.
            assert!(
                $label.len() + 1 == $len,
                "label length does not match the registry byte count",
            );
            // The composed rotation name must equal its own registry literal.
            assert!(
                $crate::suite::const_str_eq(
                    ::core::concat!("hybrid-", $ctok, "-", $ptok, "-rotate-v1"),
                    $rotate_label,
                ),
                "composed rotate label does not match the registry literal",
            );
            // Same byte-count discipline as the label above.
            assert!(
                $rotate_label.len() + 1 == $rotate_len,
                "rotate label length does not match the registry byte count",
            );
            // Each name token must equal its component's NAME constant.
            assert!(
                $crate::suite::const_str_eq(
                    <$classical as $crate::ClassicalScheme>::NAME, $ctok,
                ),
                "classical name token does not match ClassicalScheme::NAME",
            );
            assert!(
                $crate::suite::const_str_eq(
                    <$pq as $crate::PqStatefulScheme>::NAME, $ptok,
                ),
                "post-quantum name token does not match PqStatefulScheme::NAME",
            );
        };
    };
}

/// Compare two string literals in a const context.
#[doc(hidden)]
pub const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
