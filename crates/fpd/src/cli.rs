//! Command-line surface.
//!
//! Subcommands for later milestones are declared here from the start, so the gate
//! tests enumerate real commands rather than a list that grows later. None of them
//! contains gate logic — the check happens once, in `main`, before clap runs.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "fpd",
    version,
    about = "Flux Parsing Daemon — TLS/HTTP-2 fingerprint inspection and verified emulation"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show or accept the terms of use
    Terms {
        #[command(subcommand)]
        action: TermsAction,
    },
    /// Reverse proxy that annotates inbound traffic  (M4)
    Serve,
    /// Live fingerprint dashboard  (M6)
    Tui,
    /// Check a client against a browser profile  (M3)
    Check,
    /// Record a browser profile  (M3)
    Capture,
    /// Emulate a captured profile  (M5)
    Emulate,
}

#[derive(Subcommand)]
pub enum TermsAction {
    /// Print the terms text
    Show {
        /// Print only the terms hash
        #[arg(long)]
        hash: bool,
    },
    /// Record acceptance of the terms
    Accept,
}
