//! Diff engine cases, one per M0 finding, each with its paired negative.
//!
//! Pure and fixture driven. A test asserting "a permuted profile accepts
//! reordering" is only meaningful next to one asserting "a fixed profile rejects
//! it", because an implementation that always returns clean passes the first.

use fingerprint_core::ja4;
use fingerprint_h2::akamai;
use fingerprint_probe::diff::diff;
use fingerprint_probe::probe::ClientReport;
use fingerprint_probe::profile::{Profile, ProfileDb};

fn read(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn report(which: &str) -> ClientReport {
    let (tls_fx, h2_fx) = match which {
        "curl" => (
            "../fingerprint-core/tests/fixtures/curl-8.7.1-macos.bin",
            "../fingerprint-h2/tests/fixtures/curl-8.7.1-h2.bin",
        ),
        _ => (
            "../fingerprint-core/tests/fixtures/chrome-macos.bin",
            "../fingerprint-h2/tests/fixtures/chrome-h2.bin",
        ),
    };
    ClientReport {
        tls: ja4::fingerprint(&read(tls_fx)).expect("tls"),
        h2: akamai::fingerprint(&read(h2_fx)).ok(),
        alpn: Some("h2".into()),
        handshake_failed: false,
    }
}

fn db() -> ProfileDb {
    ProfileDb::shipped().expect("shipped profiles")
}

fn profile(label: &str) -> Profile {
    db().get(label).expect("profile").clone()
}

// --- the baseline: a client must match its own profile -----------------------

#[test]
fn each_client_matches_its_own_profile() {
    assert!(diff(&report("curl"), &profile("curl-8.7.1-macos")).is_clean());
    assert!(diff(&report("chrome"), &profile("chrome-macos")).is_clean());
}

#[test]
fn a_clean_diff_lists_every_field_it_checked() {
    let d = diff(&report("chrome"), &profile("chrome-macos"));
    assert!(d.is_clean());
    assert!(d.fields.len() >= 6, "a silent pass proves nothing");
}

// --- M0 finding 1: extension order permutes for Chrome, not for curl ---------

#[test]
fn a_permuted_profile_accepts_a_reordered_extension_list() {
    let mut r = report("chrome");
    r.tls.extensions.reverse();
    assert!(diff(&r, &profile("chrome-macos")).is_clean());
}

/// Without this, "permuted accepts reordering" could be satisfied by an
/// implementation that never compares extensions at all.
#[test]
fn a_fixed_profile_rejects_a_reordered_extension_list() {
    let mut r = report("curl");
    r.tls.extensions.reverse();
    assert!(!diff(&r, &profile("curl-8.7.1-macos")).is_clean());
}

/// Permuted accepts reordering but not a different set.
#[test]
fn a_permuted_profile_still_rejects_a_missing_extension() {
    let mut r = report("chrome");
    r.tls.extensions.retain(|e| *e != 27); // compress_certificate
    assert!(!diff(&r, &profile("chrome-macos")).is_clean());
}

// --- M0 finding 2: GREASE values rotate, positions do not --------------------

#[test]
fn substituting_one_grease_value_for_another_is_not_a_difference() {
    let mut r = report("chrome");
    if let Some(first) = r.tls.ciphers.first_mut() {
        *first = 0xfafa;
    }
    assert!(diff(&r, &profile("chrome-macos")).is_clean());
}

/// The other direction, and the one that catches a naive emulation.
#[test]
fn removing_grease_entirely_is_a_difference() {
    let mut r = report("chrome");
    r.tls
        .ciphers
        .retain(|c| !fingerprint_core::grease::is_grease(*c));
    r.tls.grease_cipher_positions.clear();
    r.tls.grease_ext_positions.clear();
    let d = diff(&r, &profile("chrome-macos"));
    assert!(!d.is_clean());
    assert!(format!("{d}").contains("GREASE"));
}

// --- M0 finding 3: the two order axes are independent ------------------------

#[test]
fn reordering_ciphers_is_a_difference_even_for_a_permuted_profile() {
    let mut r = report("chrome");
    r.tls.ciphers.reverse();
    assert!(
        !diff(&r, &profile("chrome-macos")).is_clean(),
        "cipher order is fixed even when extension order permutes"
    );
}

// --- M0 finding 5: pre_shared_key is session dependent -----------------------

#[test]
fn absence_of_pre_shared_key_is_not_a_mismatch() {
    let mut r = report("chrome");
    r.tls.extensions.retain(|e| *e != 41);
    assert!(
        diff(&r, &profile("chrome-macos")).is_clean(),
        "a non-resuming session must not read as a different client"
    );
}

// --- the headline discriminator ----------------------------------------------

#[test]
fn curl_checked_against_the_chrome_profile_names_the_real_differences() {
    let d = diff(&report("curl"), &profile("chrome-macos"));
    assert!(!d.is_clean());

    let text = format!("{d}");
    assert!(
        text.contains("3:100"),
        "must name the SETTINGS tell:\n{text}"
    );
    assert!(text.contains("GREASE"), "must name GREASE:\n{text}");
    assert!(
        text.contains("m,s,a,p"),
        "must name the pseudo-header order:\n{text}"
    );
    assert!(text.contains("NOT chrome-macos"));
}

#[test]
fn the_settings_id_three_tell_is_called_out_explicitly() {
    let d = diff(&report("curl"), &profile("chrome-macos"));
    let settings = d
        .fields
        .iter()
        .find(|f| f.field == "SETTINGS")
        .expect("SETTINGS field");
    assert!(!settings.ok);
    assert!(
        settings
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("no browser"),
        "the id 3 tell deserves an explanation, not just a diff"
    );
}

#[test]
fn an_unknown_profile_name_reports_the_available_ones() {
    let err = db().get("netscape").expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("chrome-macos"));
    assert!(msg.contains("curl-8.7.1-macos"));
}

// --- the HTTP layer, fpd's own design rather than JA4H -----------------------

#[test]
fn the_http_layer_is_compared_and_named_in_the_diff() {
    let d = diff(&report("curl"), &profile("chrome-macos"));
    let text = format!("{d}");
    assert!(
        text.contains("header order"),
        "must compare header order:\n{text}"
    );
    assert!(
        text.contains("sec-ch-ua") || text.contains("missing:"),
        "must name what is missing rather than only that a hash differs:\n{text}"
    );
}

#[test]
fn accept_language_presence_discriminates_curl_from_chrome() {
    let d = diff(&report("curl"), &profile("chrome-macos"));
    let f = d
        .fields
        .iter()
        .find(|f| f.field == "accept-language")
        .expect("accept-language field");
    assert!(!f.ok, "curl sends none, Chrome does");
}

/// The reason request-scoped fields are excluded from a client profile. A site
/// setting cookies must not make a browser stop matching itself. Chrome's fixture
/// carries three cookie headers and still matches its own profile, which proves
/// the exclusion is real rather than incidental.
#[test]
fn cookie_headers_do_not_stop_chrome_matching_its_own_profile() {
    let r = report("chrome");
    let h2 = r.h2.as_ref().expect("h2");
    assert_eq!(
        h2.http.cookie_header_count, 3,
        "precondition: cookies present"
    );
    assert!(diff(&r, &profile("chrome-macos")).is_clean());
}

/// Cookie values are never read, so they can never reach a profile or a diff.
#[test]
fn no_cookie_value_appears_anywhere_in_the_diff_output() {
    let d = diff(&report("chrome"), &profile("chrome-macos"));
    let text = format!("{d}");
    assert!(
        !text.contains('='),
        "a cookie value would contain '=':\n{text}"
    );
}
