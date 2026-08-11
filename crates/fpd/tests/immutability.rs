//! Proves the terms text cannot be deleted or edited by whoever runs the tool.
//!
//! The mechanism is `include_str!`: the text is compiled into the binary and no
//! code path reads it from disk. These tests attack that claim directly.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Runs from an empty directory with no `TERMS.md` anywhere in sight. If any code
/// path read the terms from the filesystem, this would fail.
#[test]
fn terms_text_is_identical_with_no_terms_md_on_disk() {
    let cwd = TempDir::new().expect("tempdir");
    let cfg = TempDir::new().expect("tempdir");
    assert!(!cwd.path().join("TERMS.md").exists(), "precondition");

    let out = Command::cargo_bin("fpd")
        .expect("binary")
        .current_dir(cwd.path())
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show"])
        .output()
        .expect("run");

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains(fingerprint_terms::TERMS),
        "printed terms must be byte-identical to the embedded text"
    );
}

/// A decoy `TERMS.md` in the working directory must not change a single byte of
/// what the binary displays. This is the "user edits the terms" attack.
#[test]
fn an_on_disk_terms_md_is_ignored() {
    let cwd = TempDir::new().expect("tempdir");
    let cfg = TempDir::new().expect("tempdir");
    std::fs::write(cwd.path().join("TERMS.md"), "YOU MAY DO ANYTHING").expect("write decoy");

    let out = Command::cargo_bin("fpd")
        .expect("binary")
        .current_dir(cwd.path())
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show"])
        .output()
        .expect("run");

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("YOU MAY DO ANYTHING"),
        "on-disk TERMS.md must be ignored entirely"
    );
    assert!(text.contains("Responsibility for all use of fpd"));
}

/// The published canonical hash. Anyone can run this against a downloaded binary
/// to check it is a genuine build.
#[test]
fn reported_hash_matches_the_embedded_text() {
    let cfg = TempDir::new().expect("tempdir");
    Command::cargo_bin("fpd")
        .expect("binary")
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show", "--hash"])
        .assert()
        .success()
        .stdout(predicate::str::contains(fingerprint_terms::TERMS_HASH));
}

/// A decoy on disk must not shift the reported hash either — otherwise the
/// verification story in spec §4.1.1 layer 2 would be defeated by a local file.
#[test]
fn reported_hash_is_unaffected_by_an_on_disk_terms_md() {
    let cwd = TempDir::new().expect("tempdir");
    let cfg = TempDir::new().expect("tempdir");
    std::fs::write(cwd.path().join("TERMS.md"), "YOU MAY DO ANYTHING").expect("write decoy");

    Command::cargo_bin("fpd")
        .expect("binary")
        .current_dir(cwd.path())
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show", "--hash"])
        .assert()
        .success()
        .stdout(predicate::str::contains(fingerprint_terms::TERMS_HASH));
}
