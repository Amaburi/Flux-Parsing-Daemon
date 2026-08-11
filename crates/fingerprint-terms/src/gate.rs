//! The invocation gate: nothing runs until the terms have been accepted.
//!
//! The gate operates on raw `argv` rather than parsed arguments, so it runs
//! *before* argument validation. A subcommand invoked with bad flags still
//! executes nothing.

use std::path::Path;

/// Commands exempt from the gate. Without these the terms could not be read or
/// accepted at all. An allowlist, so anything new fails closed.
const CARVE_OUT_COMMANDS: &[&str] = &["terms"];

/// Flags exempt from the gate. All are inert — none opens a socket.
const CARVE_OUT_FLAGS: &[&str] = &["--help", "-h", "--version", "-V"];

/// True when this invocation must be blocked pending acceptance.
pub fn applies_to(argv: &[String]) -> bool {
    if argv.iter().any(|a| CARVE_OUT_FLAGS.contains(&a.as_str())) {
        return false;
    }
    match argv.first() {
        Some(first) => !CARVE_OUT_COMMANDS.contains(&first.as_str()),
        None => true,
    }
}

/// Refusal to run. Carries the message rather than a bare error so the wording
/// lives next to the rule it enforces.
#[derive(Debug)]
pub struct GateRefusal;

impl GateRefusal {
    pub fn message(&self) -> String {
        concat!(
            "fpd: you must accept the terms and conditions first.\n",
            "\n",
            "  This tool can both measure and reproduce TLS/HTTP-2 client identities.\n",
            "  Responsibility for how it is used rests solely with you, not the author.\n",
            "\n",
            "  Read them:    fpd terms show\n",
            "  Accept them:  fpd terms accept\n",
        )
        .to_string()
    }
}

/// Reads `FPD_ACCEPT_TERMS`. Split out so [`check_with`] stays pure and its tests
/// cannot race other tests through process-global environment state.
pub fn env_accepted() -> bool {
    std::env::var("FPD_ACCEPT_TERMS").as_deref() == Ok("1")
}

/// Gate check with the environment decision passed in explicitly.
///
/// `env_accepted` is an acceptance *mechanism* for CI, not an exemption — callers
/// record it to the history log exactly as they record an interactive acceptance.
pub fn check_with(dir: &Path, env_accepted: bool) -> Result<(), GateRefusal> {
    if env_accepted {
        return Ok(());
    }
    crate::store::load(dir).map(|_| ()).ok_or(GateRefusal)
}

/// Production entry point: [`check_with`], reading the environment.
pub fn check(dir: &Path) -> Result<(), GateRefusal> {
    check_with(dir, env_accepted())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn bare_invocation_is_gated() {
        assert!(applies_to(&argv(&[])));
    }

    #[test]
    fn ordinary_subcommands_are_gated() {
        for c in ["serve", "tui", "check", "capture", "emulate"] {
            assert!(applies_to(&argv(&[c])), "{c} must be gated");
        }
    }

    /// A subcommand added in a later milestone is gated by default — the carve-out
    /// list is an allowlist, so forgetting to add something fails closed.
    #[test]
    fn an_unknown_future_subcommand_is_gated_by_default() {
        assert!(applies_to(&argv(&["some-command-invented-in-m7"])));
    }

    #[test]
    fn only_terms_help_and_version_are_carved_out() {
        assert!(!applies_to(&argv(&["terms"])));
        assert!(!applies_to(&argv(&["terms", "accept"])));
        assert!(!applies_to(&argv(&["--help"])));
        assert!(!applies_to(&argv(&["-h"])));
        assert!(!applies_to(&argv(&["--version"])));
        assert!(!applies_to(&argv(&["-V"])));
    }

    #[test]
    fn help_flag_after_a_gated_subcommand_is_still_carved_out() {
        assert!(!applies_to(&argv(&["serve", "--help"])));
    }

    #[test]
    fn check_refuses_when_no_record_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(check_with(dir.path(), false).is_err());
    }

    #[test]
    fn check_passes_after_a_valid_record_is_saved() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::store::save(dir.path(), &crate::record::AcceptanceRecord::new("0.1.0"))
            .expect("save");
        assert!(check_with(dir.path(), false).is_ok());
    }

    /// `FPD_ACCEPT_TERMS=1` satisfies the gate for CI. Tested through the pure
    /// parameter here; the real environment variable is exercised end-to-end in the
    /// binary's integration tests, where each run is its own process and cannot
    /// race other tests.
    #[test]
    fn env_acceptance_satisfies_the_gate_without_a_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(check_with(dir.path(), false).is_err(), "precondition");
        assert!(check_with(dir.path(), true).is_ok());
    }

    #[test]
    fn the_refusal_message_names_the_accept_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let msg = check_with(dir.path(), false)
            .expect_err("must refuse")
            .message();
        assert!(msg.contains("must accept the terms and conditions first"));
        assert!(msg.contains("fpd terms accept"));
        assert!(msg.contains("fpd terms show"));
    }
}
