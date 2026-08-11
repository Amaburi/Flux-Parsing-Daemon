//! End-to-end `fpd check` tests.
//!
//! These bind a loopback probe and drive a real curl at it. Expected values still
//! come from the committed profiles, so only the observed side is live.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A config dir with the terms already accepted.
fn accepted() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    Command::cargo_bin("fpd")
        .expect("binary")
        .env("FPD_CONFIG_DIR", dir.path())
        .args(["terms", "accept"])
        .assert()
        .success();
    dir
}

fn fpd(dir: &TempDir) -> Command {
    let mut c = Command::cargo_bin("fpd").expect("binary");
    c.env("FPD_CONFIG_DIR", dir.path())
        .env_remove("FPD_ACCEPT_TERMS")
        .timeout(std::time::Duration::from_secs(30));
    c
}

#[test]
fn checking_curl_against_the_curl_profile_matches() {
    if !curl_available() {
        return;
    }
    let dir = accepted();
    fpd(&dir)
        .args([
            "check",
            "--profile",
            "curl-8.7.1-macos",
            "--",
            "curl",
            "-sk",
            "--http2",
            "{url}",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("matches curl-8.7.1-macos"));
}

/// The headline case. curl checked against Chrome must fail and must name why.
#[test]
fn checking_curl_against_the_chrome_profile_fails_with_named_differences() {
    if !curl_available() {
        return;
    }
    let dir = accepted();
    fpd(&dir)
        .args([
            "check",
            "--profile",
            "chrome-macos",
            "--",
            "curl",
            "-sk",
            "--http2",
            "{url}",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("3:100"))
        .stdout(predicate::str::contains("m,s,a,p"))
        .stdout(predicate::str::contains("NOT chrome-macos"));
}

/// The gate covers the whole binary. `check` is not exempt.
#[test]
fn check_is_refused_without_terms_acceptance() {
    let dir = TempDir::new().expect("tempdir");
    let mut c = Command::cargo_bin("fpd").expect("binary");
    c.env("FPD_CONFIG_DIR", dir.path())
        .env_remove("FPD_ACCEPT_TERMS")
        .args(["check", "--profile", "chrome-macos", "--", "true"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("must accept the terms"));
}

/// A client that never connects must not hang the command forever.
#[test]
fn a_client_that_never_connects_fails_operationally_not_as_a_mismatch() {
    let dir = accepted();
    fpd(&dir)
        .args([
            "check",
            "--profile",
            "chrome-macos",
            "--timeout",
            "2",
            "--",
            "true",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("no connection"));
}

#[test]
fn an_unknown_profile_lists_the_available_ones() {
    let dir = accepted();
    fpd(&dir)
        .args(["check", "--profile", "netscape", "--", "true"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("chrome-macos"));
}

#[test]
fn the_output_states_that_the_http_layer_is_not_covered() {
    if !curl_available() {
        return;
    }
    let dir = accepted();
    fpd(&dir)
        .args([
            "check",
            "--profile",
            "curl-8.7.1-macos",
            "--",
            "curl",
            "-sk",
            "--http2",
            "{url}",
        ])
        .assert()
        .stdout(predicate::str::contains("HTTP layer is not yet covered"));
}

#[test]
fn the_probe_certificate_can_be_exported() {
    if !curl_available() {
        return;
    }
    let dir = accepted();
    let cert = dir.path().join("probe.pem");
    fpd(&dir)
        .args([
            "check",
            "--profile",
            "curl-8.7.1-macos",
            "--cacert-out",
            cert.to_str().unwrap_or_default(),
            "--",
            "curl",
            "-sk",
            "--http2",
            "{url}",
        ])
        .assert()
        .success();
    let pem = std::fs::read_to_string(&cert).expect("cert written");
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
}
