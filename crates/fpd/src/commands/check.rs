//! `fpd check`, run a client against a local probe and diff it against a profile.

use std::time::Duration;

use fingerprint_probe::diff::diff;
use fingerprint_probe::probe::Probe;
use fingerprint_probe::profile::ProfileDb;
use fingerprint_probe::verdict::identify;

/// Exit codes. A mismatch and a broken invocation must not look the same to CI.
pub const EXIT_MATCH: u8 = 0;
pub const EXIT_MISMATCH: u8 = 1;
pub const EXIT_OPERATIONAL: u8 = 2;

pub struct Args {
    pub profile: Option<String>,
    pub timeout_secs: u64,
    pub cacert_out: Option<String>,
    pub command: Vec<String>,
}

/// Substitutes `{url}` in each argument. Substitution goes into the argument
/// vector directly and never through a shell, so a URL cannot be reinterpreted as
/// shell syntax.
fn substitute(args: &[String], url: &str) -> Vec<String> {
    args.iter().map(|a| a.replace("{url}", url)).collect()
}

pub fn run(args: Args) -> u8 {
    let db = match ProfileDb::shipped() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("fpd: cannot load profiles: {e}");
            return EXIT_OPERATIONAL;
        }
    };

    // Resolved up front so an unknown name fails before a probe is started.
    let named = match &args.profile {
        Some(label) => match db.get(label) {
            Ok(p) => Some(p.clone()),
            Err(e) => {
                eprintln!("fpd: {e}");
                return EXIT_OPERATIONAL;
            }
        },
        None => None,
    };

    let Some((program, rest)) = args.command.split_first() else {
        eprintln!("fpd: no command given. try `fpd check --profile <name> -- curl -sk {{url}}`");
        return EXIT_OPERATIONAL;
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fpd: runtime: {e}");
            return EXIT_OPERATIONAL;
        }
    };

    rt.block_on(async move {
        let probe = match Probe::bind().await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fpd: cannot start probe: {e}");
                return EXIT_OPERATIONAL;
            }
        };
        let url = probe.url();

        if let Some(path) = &args.cacert_out {
            if let Err(e) = std::fs::write(path, probe.cert_pem()) {
                eprintln!("fpd: cannot write {path}: {e}");
                return EXIT_OPERATIONAL;
            }
        }

        let argv = substitute(rest, &url);
        let mut cmd = std::process::Command::new(program);
        cmd.args(&argv)
            .env("FPD_PROBE_URL", &url)
            .stdout(std::process::Stdio::null());

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("fpd: cannot run `{program}`: {e}");
                return EXIT_OPERATIONAL;
            }
        };

        let report = match probe
            .accept_one(Duration::from_secs(args.timeout_secs))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("fpd: {e}");
                eprintln!("     the client must connect to {url}");
                eprintln!("     put {{url}} in the command, or read $FPD_PROBE_URL");
                return EXIT_OPERATIONAL;
            }
        };

        // The client has served its purpose. Do not wait on it.
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();

        if report.h2.is_none() {
            eprintln!(
                "note: no HTTP/2 preamble captured. ALPN negotiated {:?}",
                report.alpn
            );
        }

        let clean = match &named {
            // Compare against the profile the user asked for.
            Some(profile) => {
                let d = diff(&report, profile);
                print!("{d}");
                d.is_clean()
            }
            // No profile named, so say what this client looks like instead.
            None => {
                let v = identify(&report, &db);
                match &v.best {
                    Some(best) => {
                        println!(
                            "  identified: {} ({:.0}% match)",
                            best.label,
                            best.score * 100.0
                        );
                        if let Some(runner) = v.ranked.get(1) {
                            println!(
                                "  runner-up:  {} ({:.0}%)",
                                runner.label,
                                runner.score * 100.0
                            );
                        }
                        println!();
                        print!("{}", best.diff);
                    }
                    None => {
                        println!("  identified: no profile matches this client");
                        if let Some(closest) = v.ranked.first() {
                            println!(
                                "  closest:    {} ({:.0}%)",
                                closest.label,
                                closest.score * 100.0
                            );
                        }
                    }
                }

                if let Some(m) = v.mismatch {
                    println!();
                    println!(
                        "  CLAIM MISMATCH: User-Agent says {}, fingerprint says {}",
                        m.claimed.as_str(),
                        m.observed.as_str()
                    );
                    println!("  no real browser produces this combination");
                }

                v.best.is_some() && v.mismatch.is_none()
            }
        };

        println!("  (checked TLS, HTTP/2 and HTTP headers)");

        if clean {
            EXIT_MATCH
        } else {
            EXIT_MISMATCH
        }
    })
}
