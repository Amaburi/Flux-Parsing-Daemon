mod cli;
mod commands;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    // The gate runs on raw argv, BEFORE clap. A subcommand invoked with bad flags
    // is refused here rather than reaching clap's validator, so no code path at all
    // executes before acceptance. This is the only gate call site in the codebase;
    // subcommands added later inherit it without touching gate logic.
    let argv: Vec<String> = std::env::args().skip(1).collect();

    if fingerprint_terms::gate::applies_to(&argv) {
        let dir = match fingerprint_terms::store::config_dir() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("fpd: {e}");
                return ExitCode::FAILURE;
            }
        };

        let env_accepted = fingerprint_terms::gate::env_accepted();
        if let Err(refusal) = fingerprint_terms::gate::check_with(&dir, env_accepted) {
            eprint!("{}", refusal.message());
            return ExitCode::FAILURE;
        }

        // FPD_ACCEPT_TERMS is an acceptance mechanism, not an exemption: when it is
        // what granted access, it leaves the same audit trail an interactive
        // acceptance would. Best-effort — an unwritable config dir must not stop a
        // run that was already authorised.
        if env_accepted && fingerprint_terms::store::load(&dir).is_none() {
            let rec = fingerprint_terms::record::AcceptanceRecord::new(env!("CARGO_PKG_VERSION"));
            let _ = fingerprint_terms::history::append(&dir, &rec, "env");
        }
    }

    match cli::Cli::parse().command {
        Some(cli::Command::Terms { action }) => match action {
            cli::TermsAction::Show { hash } => commands::terms::show(hash),
            cli::TermsAction::Accept => {
                if let Err(e) = commands::terms::accept() {
                    eprintln!("fpd: {e}");
                    return ExitCode::FAILURE;
                }
            }
        },
        Some(cli::Command::Serve {
            listen,
            upstream,
            ip_mode,
            cacert_out,
        }) => {
            let code = commands::serve::run(commands::serve::Args {
                listen,
                upstream,
                ip_mode,
                cacert_out,
            });
            return ExitCode::from(code);
        }
        Some(cli::Command::Tui) => println!("tui: not yet implemented (M6)"),
        Some(cli::Command::Check {
            profile,
            timeout,
            cacert_out,
            command,
        }) => {
            let code = commands::check::run(commands::check::Args {
                profile,
                timeout_secs: timeout,
                cacert_out,
                command,
            });
            return ExitCode::from(code);
        }
        Some(cli::Command::Capture {
            label,
            samples,
            out,
            timeout,
        }) => {
            let code = commands::capture::run(commands::capture::Args {
                label,
                samples,
                out,
                timeout_secs: timeout,
            });
            return ExitCode::from(code);
        }
        Some(cli::Command::Emulate) => println!("emulate: not yet implemented (M5)"),
        None => {
            // Unreachable in practice: bare argv is gated above.
            eprintln!("fpd: no command given; try `fpd --help`");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}
