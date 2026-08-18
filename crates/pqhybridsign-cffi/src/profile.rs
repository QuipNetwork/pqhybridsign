// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reporting the SHRINCS profile this build was compiled with.

use std::ffi::{c_char, CString};
use std::sync::OnceLock;

static PROFILE_NAME: OnceLock<CString> = OnceLock::new();

/// The SHRINCS profile this build links against, for example
/// `"shrincs-256s"`, as a `NUL`-terminated, `'static` string.
///
/// Exactly one `pqhybridsign-shrincs` profile feature is active in any one
/// build. A key, signature or verify key produced under one profile is
/// meaningless -- and in general the wrong length -- under another; an
/// integrator should confirm both sides of an integration report the same
/// string here before trusting anything on the wire. The returned pointer
/// is valid for the lifetime of the process and must not be freed or
/// written through.
///
/// This entry point has no error channel, so the panic guard every function
/// in this crate carries has nowhere to report a caught panic: it returns a
/// null pointer instead of unwinding into C. Check the result for null
/// before reading it. Nothing on this path is expected to panic -- the
/// profile name is a fixed ASCII literal cached on first call -- so a null
/// return means something is wrong underneath, not that the profile is
/// unknown.
#[no_mangle]
pub extern "C" fn pqhs_profile_name() -> *const c_char {
    crate::ffi::guard_infallible(|| {
        PROFILE_NAME
            .get_or_init(|| {
                #[expect(
                    clippy::expect_used,
                    reason = "see the doc comment above: the profile name is a fixed ASCII literal cached on first call, so this cannot fail"
                )]
                CString::new(pqhybridsign_abi::profile_name())
                    .expect("the profile name is a fixed ASCII literal with no interior NUL")
            })
            .as_ptr()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_name_is_a_valid_nul_terminated_string() {
        let ptr = pqhs_profile_name();
        assert!(!ptr.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) };
        assert!(s.to_str().unwrap().starts_with("shrincs-"));
    }
}
