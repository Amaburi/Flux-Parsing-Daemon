//! Cipher suite numbers to the names BoringSSL accepts.
//!
//! Derived from the profile's stored numeric list rather than hard-coded per
//! browser, so a newly captured profile works without touching this code.
//!
//! An unrecognised cipher is an error, never a silent omission. Dropping one
//! would produce a handshake that reproduces nothing, and the verification would
//! then be measuring the wrong thing while still reporting a difference.

/// OpenSSL name for a cipher suite number, or `None` if not known here.
pub fn cipher_name(id: u16) -> Option<&'static str> {
    Some(match id {
        // TLS 1.3
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",

        // TLS 1.2 ECDHE
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",

        // TLS 1.2 RSA
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0x000a => "DES-CBC3-SHA",

        _ => return None,
    })
}

/// True for the TLS 1.3 suites, which BoringSSL configures through a separate
/// call from the TLS 1.2 list.
pub fn is_tls13(id: u16) -> bool {
    (0x1301..=0x1303).contains(&id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ciphers_map_to_openssl_names() {
        assert_eq!(cipher_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(cipher_name(0xc02b), Some("ECDHE-ECDSA-AES128-GCM-SHA256"));
        assert_eq!(cipher_name(0x002f), Some("AES128-SHA"));
    }

    #[test]
    fn an_unknown_cipher_returns_none_rather_than_a_guess() {
        assert_eq!(cipher_name(0xffff), None);
        assert_eq!(cipher_name(0x0000), None);
    }

    #[test]
    fn tls13_suites_are_identified_separately() {
        for id in [0x1301, 0x1302, 0x1303] {
            assert!(is_tls13(id), "{id:#06x}");
        }
        for id in [0xc02b, 0x002f, 0x009c] {
            assert!(!is_tls13(id), "{id:#06x}");
        }
    }

    /// Every cipher in every **browser** profile must be known, or that browser
    /// cannot be emulated. This is what fails when a newly captured browser
    /// offers something unmapped.
    ///
    /// Non-browser profiles are excluded deliberately. curl offers 49 suites,
    /// 31 of them legacy (Camellia, SEED, RC4, 3DES, DHE variants) that no
    /// browser has proposed in years. Mapping them would be work in service of a
    /// use case that does not exist: nobody emulates curl, they run curl. curl's
    /// profile exists here as a contrast case for detection, not as a target.
    #[test]
    fn every_cipher_in_every_browser_profile_is_known() {
        let db = fingerprint_probe::profile::ProfileDb::shipped().expect("db");
        let browsers = ["chrome", "firefox", "safari", "edge"];

        for p in db.iter().filter(|p| browsers.contains(&p.family.as_str())) {
            for id in &p.tls.ciphers {
                assert!(
                    cipher_name(*id).is_some(),
                    "browser profile {} uses cipher {:#06x} which has no name mapping",
                    p.label,
                    id
                );
            }
        }
    }

    /// A profile that cannot be mapped must be rejected loudly at build time.
    /// Silently dropping a cipher would produce a handshake that reproduces
    /// nothing while the verification still reported a difference, which sends
    /// the reader looking in the wrong place.
    #[test]
    fn a_non_browser_profile_contains_ciphers_this_module_does_not_map() {
        let db = fingerprint_probe::profile::ProfileDb::shipped().expect("db");
        let curl = db.get("curl-8.7.1-macos").expect("curl profile");
        let unmapped = curl
            .tls
            .ciphers
            .iter()
            .filter(|id| cipher_name(**id).is_none())
            .count();
        assert!(
            unmapped > 0,
            "if this ever reaches zero the exclusion above can be removed"
        );
    }
}
