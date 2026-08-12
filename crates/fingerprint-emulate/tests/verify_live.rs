#![cfg(feature = "emulation")]

//! Does the emulation actually reproduce the profile it was built from?
//!
//! Everything runs on loopback against fpd's own probe, so these are real
//! handshakes with no external network.

use fingerprint_emulate::verify::verify;
use fingerprint_probe::profile::{Profile, ProfileDb};

fn profile(label: &str) -> Profile {
    ProfileDb::shipped()
        .expect("db")
        .get(label)
        .expect("profile")
        .clone()
}

/// The headline property. If this passes, the emulation is demonstrated rather
/// than asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_chrome_profile_reproduces_itself() {
    let p = profile("chrome-macos");
    let d = verify(&p).await.expect("verify ran");
    assert!(d.is_clean(), "chrome-macos did not reproduce:\n{d}");
}

/// A permuted profile must hold across repeated draws, or the equivalence class
/// is not actually being exercised. Chrome shuffles extension order every
/// connection, so a single pass could succeed by luck.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permuted_profile_reproduces_across_repeated_draws() {
    let p = profile("chrome-macos");
    for i in 0..8 {
        let d = verify(&p).await.expect("verify ran");
        assert!(d.is_clean(), "draw {i} did not reproduce:\n{d}");
    }
}

/// Verification that cannot fail proves nothing. A deliberately corrupted profile
/// must be reported as not reproduced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_corrupted_profile_fails_verification() {
    let mut p = profile("chrome-macos");
    p.tls.ciphers.reverse();
    let d = verify(&p).await.expect("verify ran");
    assert!(!d.is_clean(), "a reversed cipher order must not verify");
}
