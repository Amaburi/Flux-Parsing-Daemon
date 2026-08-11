#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Terms embedding, acceptance records, and the invocation gate for fpd.

pub mod gate;
pub mod history;
pub mod record;
pub mod store;

/// The canonical terms text, compiled into the binary.
///
/// This is never read from the filesystem at runtime. Deleting or editing
/// `TERMS.md` on a user's disk cannot change what a built binary displays or
/// what an acceptance record is bound to.
pub const TERMS: &str = include_str!("../../../TERMS.md");

/// SHA-256 of [`TERMS`], computed by `build.rs`. Format: `sha256:<hex>`.
///
/// Published as the canonical value so any binary can be checked against a
/// genuine release with `fpd terms show --hash`.
pub const TERMS_HASH: &str = env!("FPD_TERMS_HASH");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_text_is_embedded_and_non_empty() {
        assert!(TERMS.contains("Responsibility for all use of fpd rests solely"));
        assert!(TERMS.len() > 500);
    }

    #[test]
    fn terms_hash_matches_the_embedded_text() {
        use sha2::{Digest, Sha256};
        let expected = format!("sha256:{:x}", Sha256::digest(TERMS.as_bytes()));
        assert_eq!(TERMS_HASH, expected);
    }
}
