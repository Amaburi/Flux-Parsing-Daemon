//! The acceptance record: what a user accepted, when, and a tamper-evidence tag.
//!
//! Pure logic, this module never touches the filesystem, which is what lets the
//! forgery tests below run with no I/O at all.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Key compiled into the binary.
///
/// This provides tamper-*evidence* against hand-editing the record file. It is
/// deliberately not claimed to be secret from anyone holding the binary, spec
/// §4.3 states that limit explicitly rather than overselling it.
const RECORD_KEY: &[u8] = b"fpd-acceptance-v1-9a3f2c7e41b8";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceRecord {
    /// Hash of the terms text this acceptance is bound to.
    pub terms_version: String,
    /// Version of fpd that recorded the acceptance.
    pub fpd_version: String,
    /// RFC 3339 UTC timestamp.
    pub accepted_at: String,
    /// HMAC over the fields above.
    pub sig: String,
}

impl AcceptanceRecord {
    pub fn new(fpd_version: &str) -> Self {
        let accepted_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

        let mut r = Self {
            terms_version: crate::TERMS_HASH.to_string(),
            fpd_version: fpd_version.to_string(),
            accepted_at,
            sig: String::new(),
        };
        r.sig = r.compute_sig();
        r
    }

    fn payload(&self) -> String {
        format!(
            "{}|{}|{}",
            self.terms_version, self.fpd_version, self.accepted_at
        )
    }

    fn compute_sig(&self) -> String {
        match Hmac::<Sha256>::new_from_slice(RECORD_KEY) {
            Ok(mut mac) => {
                mac.update(self.payload().as_bytes());
                format!("hmac-sha256:{:x}", mac.finalize().into_bytes())
            }
            Err(_) => String::new(),
        }
    }

    /// True only if the signature matches **and** the record is bound to the terms
    /// text compiled into this binary. Both conditions matter: the first catches
    /// hand-edited records, the second invalidates every prior acceptance when the
    /// terms change.
    pub fn verify(&self) -> bool {
        !self.sig.is_empty()
            && self.sig == self.compute_sig()
            && self.terms_version == crate::TERMS_HASH
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_record_verifies() {
        assert!(AcceptanceRecord::new("0.1.0").verify());
    }

    #[test]
    fn an_edited_terms_version_fails_verification() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.terms_version = "sha256:0000000000000000".into();
        assert!(!r.verify(), "hand-edited record must not verify");
    }

    #[test]
    fn an_edited_timestamp_fails_verification() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.accepted_at = "1999-01-01T00:00:00Z".into();
        assert!(!r.verify());
    }

    #[test]
    fn a_stripped_signature_fails_verification() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.sig = String::new();
        assert!(!r.verify());
    }

    /// Isolates the terms-version binding from the signature check. A record can be
    /// perfectly signed and still not verify, because it accepts a *different* terms
    /// text than the one compiled into this binary. This is the mechanism by which
    /// changing TERMS.md invalidates every prior acceptance.
    #[test]
    fn a_correctly_signed_record_for_other_terms_does_not_verify() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.terms_version = "sha256:deadbeefdeadbeef".into();
        r.sig = r.compute_sig(); // re-sign so the signature itself is valid
        assert_eq!(r.sig, r.compute_sig(), "precondition: signature is valid");
        assert!(
            !r.verify(),
            "a validly signed acceptance of different terms must still be rejected"
        );
    }
}
