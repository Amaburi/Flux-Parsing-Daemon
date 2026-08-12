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
    /// Reverse proxy that annotates inbound traffic
    Serve {
        /// Address to listen on
        #[arg(long, default_value = "127.0.0.1:8443")]
        listen: String,
        /// Upstream application, plain HTTP
        #[arg(long, default_value = "127.0.0.1:8080")]
        upstream: String,
        /// How client IPs appear in logs: full, truncated or omitted
        #[arg(long, default_value = "truncated")]
        ip_mode: String,
        /// Write the TLS certificate here
        #[arg(long)]
        cacert_out: Option<String>,
    },
    /// Live fingerprint dashboard  (M6)
    Tui,
    /// Check a client against a browser profile
    Check {
        /// Profile to compare against. Omit to identify the client instead.
        #[arg(long)]
        profile: Option<String>,
        /// Seconds to wait for the client to connect
        #[arg(long, default_value_t = 10)]
        timeout: u64,
        /// Write the probe certificate here for clients that would rather trust it
        #[arg(long)]
        cacert_out: Option<String>,
        /// The client to run. `{url}` is replaced with the probe URL.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Record a browser profile
    Capture {
        /// Label for the new profile
        #[arg(long)]
        label: String,
        /// How many handshakes to observe. More than one is required to tell a
        /// fixed field order from a permuted one.
        #[arg(long, default_value_t = 1)]
        samples: usize,
        /// Directory to write the profile into
        #[arg(long, default_value = ".")]
        out: String,
        /// Seconds to wait for each connection
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
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
