//! Building a BoringSSL client that reproduces a profile.
//!
//! rustls cannot do this. It deliberately does not expose cipher ordering,
//! arbitrary extension ordering, or GREASE injection, and that design is correct
//! for a TLS library whose job is to be secure rather than to impersonate. So
//! emulation builds on BoringSSL, which does expose them.
//!
//! The M0 S3 spike established the shape: `boring` reproduced the cipher list in
//! exact order and GREASE placement with no tuning, leaving five extensions to
//! add explicitly. Each of the five was checked against the crate rather than
//! assumed, and one of them has no safe wrapper.

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use fingerprint_probe::profile::{Order, Profile};

use crate::ciphers::{cipher_name, is_tls13};
use crate::EmulateError;

/// Extension numbers the S3 spike found missing from a default `boring` client.
pub const EXT_STATUS_REQUEST: u16 = 5;
pub const EXT_SCT: u16 = 18;
pub const EXT_COMPRESS_CERTIFICATE: u16 = 27;
pub const EXT_ALPS: u16 = 17613;
pub const EXT_ECH: u16 = 65037;

/// TLS 1.2 cipher list, in the profile's stored order.
///
/// TLS 1.3 suites are deliberately absent. **BoringSSL does not expose them for
/// configuration**: there is no `set_ciphersuites`, and the library fixes them at
/// AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305 in that order. That happens to be
/// exactly what Chrome sends, which is a large part of why the S3 spike matched
/// cipher order with no tuning. A profile whose 1.3 order differs from
/// BoringSSL's therefore cannot be reproduced, and `tls13_order_matches_boringssl`
/// fails rather than letting that pass silently.
pub fn cipher_list_for(profile: &Profile) -> Result<String, EmulateError> {
    names_for(profile, false)
}

/// The TLS 1.3 suites a profile expects, in its stored order. Reported so a
/// mismatch against BoringSSL's fixed order is visible, not to configure anything.
pub fn ciphersuites_for(profile: &Profile) -> Result<String, EmulateError> {
    names_for(profile, true)
}

/// BoringSSL's fixed TLS 1.3 order.
pub const BORINGSSL_TLS13_ORDER: [u16; 3] = [0x1301, 0x1302, 0x1303];

fn names_for(profile: &Profile, tls13: bool) -> Result<String, EmulateError> {
    let mut out = Vec::new();
    for id in &profile.tls.ciphers {
        let name = cipher_name(*id).ok_or(EmulateError::UnknownCipher(*id))?;
        if is_tls13(*id) == tls13 {
            out.push(name);
        }
    }
    Ok(out.join(":"))
}

/// Builds a connector configured to reproduce `profile`.
pub fn build(profile: &Profile) -> Result<SslConnector, EmulateError> {
    let mut b =
        SslConnector::builder(SslMethod::tls()).map_err(|e| EmulateError::Tls(e.to_string()))?;

    // The probe uses a self-signed certificate, and verification is not what is
    // being measured here. A caller emulating against a real server sets its own
    // verification.
    b.set_verify(SslVerifyMode::NONE);

    b.set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|e| EmulateError::Tls(e.to_string()))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|e| EmulateError::Tls(e.to_string()))?;

    let tls12 = cipher_list_for(profile)?;
    if !tls12.is_empty() {
        b.set_cipher_list(&tls12)
            .map_err(|e| EmulateError::Tls(e.to_string()))?;
    }

    // GREASE placement matched the baseline with no tuning in S3. Only enable it
    // when the profile actually recorded GREASE, or a client that legitimately
    // omits it would gain some.
    let wants_grease = !profile.tls.grease_cipher_positions.is_empty()
        || !profile.tls.grease_ext_positions.is_empty();
    b.set_grease_enabled(wants_grease);

    // M0 finding 1: Chrome shuffles extension order every connection. A profile
    // recording `permuted` must shuffle too, or it would be distinguishable by
    // being *too* consistent.
    b.set_permute_extensions(profile.equivalence.extension_order == Order::Permuted);

    if let Some(alpn) = &profile.tls.alpn {
        b.set_alpn_protos(&encode_alpn(alpn))
            .map_err(|e| EmulateError::Tls(e.to_string()))?;
    }

    // The five extensions S3 found missing. Each was verified to have an API
    // before this was written.
    let ext = &profile.tls.extensions;
    if ext.contains(&EXT_STATUS_REQUEST) {
        b.enable_ocsp_stapling();
    }
    if ext.contains(&EXT_SCT) {
        b.enable_signed_cert_timestamps();
    }
    if ext.contains(&EXT_COMPRESS_CERTIFICATE) {
        b.add_certificate_compression_algorithm(crate::extensions::AdvertiseOnlyBrotli)
            .map_err(|e| EmulateError::Tls(e.to_string()))?;
    }
    // ECH GREASE is per connection, not per context: `set_enable_ech_grease` lives
    // on `SslRef`. Applied in `configure` rather than here.

    Ok(b.build())
}

/// Applies the settings that BoringSSL only exposes per connection.
///
/// ECH GREASE is one of them. Discovering that cost a compile error, because the
/// S3 spike verified the method *name* existed in the crate without checking
/// which type it hangs off.
pub fn configure(
    connector: &SslConnector,
    profile: &Profile,
    domain: &str,
) -> Result<boring::ssl::ConnectConfiguration, EmulateError> {
    let mut cfg = connector
        .configure()
        .map_err(|e| EmulateError::Tls(e.to_string()))?;

    // `ConnectConfiguration` derefs to `SslRef`, which is where the per-connection
    // settings live.
    if profile.tls.extensions.contains(&EXT_ECH) {
        cfg.set_enable_ech_grease(true);
    }

    if profile.tls.extensions.contains(&EXT_ALPS) {
        if let Some(alpn) = &profile.tls.alpn {
            crate::extensions::enable_alps(&mut cfg, alpn.as_bytes())
                .map_err(|e| EmulateError::Tls(e.to_string()))?;
        }
    }

    // A profile captured without SNI must not gain one, since SNI presence flips
    // a JA4 character and is part of what is being reproduced.
    cfg.set_use_server_name_indication(profile.tls.has_sni);
    let _ = domain;

    Ok(cfg)
}

/// ALPN wire format: each protocol prefixed by its length.
fn encode_alpn(proto: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for p in [proto, "http/1.1"] {
        if p.len() <= u8::MAX as usize {
            out.push(p.len() as u8);
            out.extend_from_slice(p.as_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_probe::profile::ProfileDb;

    fn profile(label: &str) -> Profile {
        ProfileDb::shipped()
            .expect("db")
            .get(label)
            .expect("profile")
            .clone()
    }

    #[test]
    fn the_chrome_profile_yields_a_tls12_list_in_stored_order() {
        let p = profile("chrome-macos");
        let tls12 = cipher_list_for(&p).expect("tls12");
        assert!(tls12.starts_with("ECDHE-ECDSA-AES128-GCM-SHA256"));
        assert!(
            !tls12.contains("TLS_AES"),
            "1.3 suites must not leak into the 1.2 list"
        );
    }

    /// BoringSSL fixes the TLS 1.3 order and offers no way to change it. A
    /// profile expecting a different order cannot be reproduced, and that has to
    /// surface here rather than as a confusing diff during verification.
    #[test]
    fn tls13_order_matches_boringssl() {
        let p = profile("chrome-macos");
        let expected: Vec<u16> = p
            .tls
            .ciphers
            .iter()
            .copied()
            .filter(|id| is_tls13(*id))
            .collect();
        assert_eq!(
            expected,
            BORINGSSL_TLS13_ORDER.to_vec(),
            "this profile's TLS 1.3 order is not BoringSSL's, so it cannot be emulated"
        );
    }

    /// Silently dropping a cipher would produce a handshake reproducing nothing
    /// while the verification still reported a difference, sending the reader
    /// looking in the wrong place.
    #[test]
    fn an_unknown_cipher_is_an_error_not_a_silent_omission() {
        let mut p = profile("chrome-macos");
        p.tls.ciphers.push(0xffff);
        assert!(matches!(
            build(&p),
            Err(EmulateError::UnknownCipher(0xffff))
        ));
    }

    #[test]
    fn a_browser_profile_builds() {
        assert!(build(&profile("chrome-macos")).is_ok());
    }

    #[test]
    fn alpn_is_length_prefixed() {
        assert_eq!(encode_alpn("h2"), b"\x02h2\x08http/1.1");
    }
}
