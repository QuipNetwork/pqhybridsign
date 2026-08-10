// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{ClassicalScheme, PqScheme};

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
