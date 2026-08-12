//! Live probe tests.
//!
//! These bind loopback on an ephemeral port and drive a real curl at it. That
//! breaks the socket-free rule the pure crates hold to, deliberately: a probe
//! that is never connected to has not been tested. Expected values still come
//! from the committed fixture oracles, so only the observed side is live.

use std::time::Duration;

use fingerprint_probe::probe::Probe;

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Drives curl at the probe and returns the report.
async fn capture_curl(args: &[&str]) -> fingerprint_probe::probe::ClientReport {
    let probe = Probe::bind().await.expect("bind");
    let url = probe.url();

    let mut cmd = std::process::Command::new("curl");
    cmd.args(args).arg(&url);
    std::thread::spawn(move || {
        let _ = cmd.output();
    });

    probe
        .accept_one(Duration::from_secs(10))
        .await
        .expect("accept")
}

#[tokio::test]
async fn a_real_curl_connection_yields_the_committed_ja4() {
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }
    let report = capture_curl(&["-sk", "--http2", "-o", "/dev/null", "--max-time", "5"]).await;

    // Oracle from crates/fingerprint-core/tests/fixtures/curl-8.7.1-macos.md
    assert_eq!(report.tls.ja4, "t13i4906h2_0d8feac7bc37_7395dae3b2f3");
    assert_eq!(report.alpn.as_deref(), Some("h2"));
    assert!(!report.handshake_failed);
}

#[tokio::test]
async fn a_real_curl_connection_yields_the_committed_akamai_fingerprint() {
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }
    let report = capture_curl(&["-sk", "--http2", "-o", "/dev/null", "--max-time", "5"]).await;

    let h2 = report.h2.expect("h2 fingerprint");
    // Oracle from crates/fingerprint-h2/tests/fixtures/curl-8.7.1-h2.md
    assert_eq!(h2.akamai, "3:100;4:10485760;2:0|1048510465|0|m,s,a,p");
}

/// The probe must not hang when nothing connects. Without this, `fpd check` with
/// a client that fails to start would wait forever.
#[tokio::test]
async fn a_probe_that_is_never_connected_to_times_out() {
    let probe = Probe::bind().await.expect("bind");
    let err = probe
        .accept_one(Duration::from_millis(300))
        .await
        .expect_err("must time out");
    assert!(matches!(
        err,
        fingerprint_probe::probe::ProbeError::NoConnection
    ));
}

#[tokio::test]
async fn each_probe_gets_its_own_ephemeral_port() {
    let a = Probe::bind().await.expect("bind");
    let b = Probe::bind().await.expect("bind");
    assert_ne!(a.port(), b.port());
    assert!(a.url().starts_with("https://127.0.0.1:"));
}

#[tokio::test]
async fn the_probe_exports_a_certificate_for_clients_that_want_to_trust_it() {
    let probe = Probe::bind().await.expect("bind");
    assert!(probe.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
}

/// The strongest available check that the retained bytes are the right bytes:
/// re-fingerprinting them must produce the fingerprint already reported. A
/// truncated or offset buffer cannot pass this.
#[tokio::test]
async fn the_retained_bytes_reproduce_the_reported_fingerprint() {
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }
    let report = capture_curl(&["-sk", "--http2"]).await;
    assert!(!report.raw_hello.is_empty(), "bytes must be retained");

    let again = fingerprint_core::ja4::fingerprint(&report.raw_hello).expect("re-parse");
    assert_eq!(again.ja4, report.tls.ja4);
    assert_eq!(again.ja4_r, report.tls.ja4_r);
}

/// The provenance spans must index the retained buffer, not some other buffer.
/// This is the exact operation the TUI performs, asserted here so that a renderer
/// panic becomes a test failure instead.
#[tokio::test]
async fn provenance_spans_index_the_retained_buffer() {
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }
    let report = capture_curl(&["-sk", "--http2"]).await;
    let s = report.tls.provenance.ciphers;
    assert!(
        s.start + s.len <= report.raw_hello.len(),
        "span outside retained bytes"
    );

    let from_span: Vec<u16> = report.raw_hello[s.start..s.start + s.len]
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();
    assert_eq!(from_span, report.tls.ciphers);
}
