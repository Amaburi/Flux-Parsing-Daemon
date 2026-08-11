//! Identification and claim mismatch. Pure and fixture driven.

use fingerprint_core::ja4;
use fingerprint_h2::akamai;
use fingerprint_probe::probe::ClientReport;
use fingerprint_probe::profile::ProfileDb;
use fingerprint_probe::verdict::{identify, MATCH_FLOOR};

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

// --- identification ----------------------------------------------------------

#[test]
fn each_client_is_identified_as_its_own_profile() {
    for (which, label) in [("curl", "curl-8.7.1-macos"), ("chrome", "chrome-macos")] {
        let v = identify(&report(which), &db());
        let best = v
            .best
            .as_ref()
            .unwrap_or_else(|| panic!("{which}: no match"));
        assert_eq!(best.label, label);
        assert!(
            (best.score - 1.0).abs() < f32::EPSILON,
            "{which} should be exact"
        );
    }
}

#[test]
fn matches_are_ranked_best_first() {
    let v = identify(&report("curl"), &db());
    for pair in v.ranked.windows(2) {
        assert!(
            pair[0].score >= pair[1].score,
            "ranking out of order: {} then {}",
            pair[0].score,
            pair[1].score
        );
    }
}

/// The floor is calibrated from these numbers, so they are asserted rather than
/// left as a comment that can quietly go stale. If a growing database ever pushes
/// a wrong match above the floor, this fails and the floor gets re-measured.
#[test]
fn the_measured_scores_still_bracket_the_floor() {
    let v = identify(&report("curl"), &db());

    let own = v
        .ranked
        .iter()
        .find(|c| c.label == "curl-8.7.1-macos")
        .expect("own profile");
    let other = v
        .ranked
        .iter()
        .find(|c| c.label == "chrome-macos")
        .expect("other profile");

    assert!(own.score >= MATCH_FLOOR, "own profile scored {}", own.score);
    assert!(
        other.score < MATCH_FLOOR,
        "a wrong profile scored {} which is above the floor of {MATCH_FLOOR}; \
         re-measure and raise it",
        other.score
    );
}

/// A tool that always names a browser is useless. `None` has to be reachable.
#[test]
fn a_client_matching_nothing_reports_no_best_match() {
    let mut r = report("curl");
    r.tls.ciphers = vec![0x1301];
    r.tls.extensions = vec![0x0001];
    r.tls.grease_cipher_positions.clear();
    r.tls.grease_ext_positions.clear();
    r.h2 = None;

    let v = identify(&r, &db());
    assert!(v.best.is_none(), "should not name a profile");
    assert!(!v.ranked.is_empty(), "but ranking is still reported");
}

#[test]
fn an_altered_client_scores_below_an_exact_one() {
    let exact = identify(&report("curl"), &db())
        .best
        .map(|c| c.score)
        .unwrap_or(0.0);

    let mut altered = report("curl");
    altered.tls.extensions.reverse();
    let partial = identify(&altered, &db())
        .best
        .map(|c| c.score)
        .unwrap_or(0.0);

    assert!(
        exact > partial,
        "exact {exact} should beat altered {partial}"
    );
}

#[test]
fn every_profile_appears_in_the_ranking() {
    let v = identify(&report("curl"), &db());
    assert_eq!(v.ranked.len(), db().labels().len());
}

// --- claim mismatch ----------------------------------------------------------
//
// Three negative guards to one positive case, deliberately. A false flag costs
// more than a missed one: an operator who sees one wrong flag stops trusting all
// of them.

use fingerprint_probe::ua::Family;

fn set_header(r: &mut ClientReport, name: &str, value: &str) {
    if let Some(h2) = r.h2.as_mut() {
        h2.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        h2.headers.push((name.to_string(), value.to_string()));
    }
}

fn remove_header(r: &mut ClientReport, name: &str) {
    if let Some(h2) = r.h2.as_mut() {
        h2.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    }
}

const CHROME_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// The headline case. A curl fingerprint claiming to be Chrome.
#[test]
fn a_curl_fingerprint_claiming_chrome_is_a_mismatch() {
    let mut r = report("curl");
    set_header(&mut r, "user-agent", CHROME_UA);

    let m = identify(&r, &db()).mismatch.expect("mismatch expected");
    assert_eq!(m.claimed, Family::Chrome);
    assert_eq!(m.observed, Family::Curl);
}

/// Guard 1. An honest client is never flagged. This matters more than detection.
#[test]
fn an_honest_client_is_never_flagged() {
    for name in ["curl", "chrome"] {
        assert!(
            identify(&report(name), &db()).mismatch.is_none(),
            "{name} was flagged despite being honest"
        );
    }
}

/// Guard 2. No claim, no mismatch. Silence is not evidence.
#[test]
fn an_absent_or_unrecognised_user_agent_produces_no_mismatch() {
    let mut unknown_ua = report("curl");
    set_header(&mut unknown_ua, "user-agent", "SomeInternalTool/1.0");
    assert!(identify(&unknown_ua, &db()).mismatch.is_none());

    let mut no_ua = report("curl");
    remove_header(&mut no_ua, "user-agent");
    assert!(identify(&no_ua, &db()).mismatch.is_none());
}

/// Guard 3. If the fingerprint matches nothing, there is nothing to contradict
/// the claim. Without this, every client the database has not seen gets flagged.
#[test]
fn an_unidentified_fingerprint_produces_no_mismatch() {
    let mut r = report("curl");
    r.tls.ciphers = vec![0x1301];
    r.tls.extensions = vec![0x0001];
    r.tls.grease_cipher_positions.clear();
    r.tls.grease_ext_positions.clear();
    set_header(&mut r, "user-agent", CHROME_UA);

    let v = identify(&r, &db());
    assert!(v.best.is_none(), "precondition: unidentified");
    assert!(
        v.mismatch.is_none(),
        "must not flag what it cannot identify"
    );
}

/// The privacy promise, enforced rather than documented. `user-agent` is the one
/// value read. If anyone starts reading cookies, this fails loudly.
#[test]
fn no_header_value_other_than_user_agent_reaches_the_output() {
    let mut r = report("chrome");
    set_header(&mut r, "cookie", "session=SECRETVALUE");
    set_header(&mut r, "authorization", "Bearer SECRETTOKEN");

    let v = identify(&r, &db());
    let rendered = format!("{v:?}");
    assert!(!rendered.contains("SECRETVALUE"), "cookie value leaked");
    assert!(
        !rendered.contains("SECRETTOKEN"),
        "authorization value leaked"
    );
}

#[test]
fn every_shipped_profile_declares_a_family() {
    for p in db().iter() {
        assert!(!p.family.is_empty(), "{} has no family", p.label);
    }
}

/// Regression for the design fix that came out of `an_unidentified_fingerprint`.
///
/// Ten fields are compared and seven are HTTP/2 or HTTP, so equal weighting let a
/// client with an entirely wrong TLS fingerprint still score 0.70 and clear the
/// floor. TLS is the harder layer to forge, so it now gates identification
/// outright. Without this test the fix could be reverted and only one unrelated
/// test would notice.
#[test]
fn a_wrong_tls_layer_blocks_identification_even_when_http_matches() {
    let mut r = report("curl");
    // HTTP/2 and HTTP left completely intact.
    r.tls.ciphers = vec![0x1301, 0x1302];
    r.tls.extensions = vec![0x0001, 0x0002];
    r.tls.grease_cipher_positions.clear();
    r.tls.grease_ext_positions.clear();

    let v = identify(&r, &db());
    let top = v.ranked.first().expect("a ranking");
    assert!(
        top.score > 0.5,
        "precondition: the HTTP layer still scores well ({})",
        top.score
    );
    assert!(
        v.best.is_none(),
        "a wrong TLS layer must block identification regardless of score"
    );
}
