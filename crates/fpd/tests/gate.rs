//! The gate, exercised end-to-end through the real binary.
//!
//! Each case is its own process, which is why `FPD_ACCEPT_TERMS` can be tested
//! here safely — unlike in the library's unit tests, where the environment is
//! process-global and shared with every other test thread.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Every real subcommand. Hand-written: deriving this from clap would require
/// exposing `Cli` from a library target, which is deliberate debt recorded in the
/// plan's self-review and paid down when M2 adds the first working subcommand.
const GATED: &[&str] = &["serve", "tui", "check", "capture", "emulate"];

fn fpd(dir: &TempDir) -> Command {
    let mut c = Command::cargo_bin("fpd").expect("binary");
    c.env("FPD_CONFIG_DIR", dir.path())
        .env_remove("FPD_ACCEPT_TERMS");
    c
}

#[test]
fn every_gated_subcommand_refuses_without_acceptance() {
    let dir = TempDir::new().expect("tempdir");
    for sub in GATED {
        fpd(&dir)
            .arg(sub)
            .assert()
            .code(1)
            .stderr(predicate::str::contains(
                "must accept the terms and conditions first",
            ));
    }
}

#[test]
fn bare_invocation_refuses() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir).assert().code(1).stderr(predicate::str::contains(
        "must accept the terms and conditions first",
    ));
}

#[test]
fn accepting_then_running_a_subcommand_passes_the_gate() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir).args(["terms", "accept"]).assert().success();
    fpd(&dir)
        .arg("serve")
        .assert()
        .stderr(predicate::str::contains("must accept").not());
}

#[test]
fn env_acceptance_satisfies_the_gate() {
    let dir = TempDir::new().expect("tempdir");
    Command::cargo_bin("fpd")
        .expect("binary")
        .env("FPD_CONFIG_DIR", dir.path())
        .env("FPD_ACCEPT_TERMS", "1")
        .arg("serve")
        .assert()
        .stderr(predicate::str::contains("must accept").not());
}

#[test]
fn terms_show_works_without_acceptance() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir)
        .args(["terms", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Responsibility for all use of fpd",
        ));
}

/// The gate runs on raw argv, before clap parses. A subcommand invoked with an
/// argument error must still be refused rather than reaching clap's validator,
/// so no code path at all executes before acceptance.
#[test]
fn a_subcommand_with_bad_arguments_is_refused_by_the_gate_not_by_clap() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir)
        .args(["serve", "--nonexistent-flag"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "must accept the terms and conditions first",
        ));
}
