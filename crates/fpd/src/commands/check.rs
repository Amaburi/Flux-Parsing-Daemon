//! `fpd check` — run a client against a local probe and diff it against a profile.

use std::time::Duration;

use fingerprint_probe::diff::diff;
use fingerprint_probe::probe::Probe;
use fingerprint_probe::profile::ProfileDb;

/// Exit codes. A mismatch and a broken invocation must not look the same to CI.
pub const EXIT_MATCH: u8 = 0;
pub const EXIT_MISMATCH: u8 = 1;
pub const EXIT_OPERATIONAL: u8 = 2;

pub struct Args {
    pub profile: String,
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

    let profile = match db.get(&args.profile) {
        Ok(p) => p.clone(),
        Err(e) => {
            eprintln!("fpd: {e}");
            return EXIT_OPERATIONAL;
        }
    };

    let Some((program, rest)) = args.command.split_first() else {
        eprintln!("fpd: no command given; try `fpd check --profile <name> -- curl -sk {{url}}`");
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

        // The client has served its purpose; do not wait on it.
        let mut child = child;
        let _ = child.kill();
        let _ = child.wait();

        let d = diff(&report, &profile);
        print!("{d}");

        if report.h2.is_none() && profile.h2.is_some() {
            eprintln!(
                "note: no HTTP/2 preamble captured; ALPN negotiated {:?}",
                report.alpn
            );
        }
        println!("  (checked TLS, HTTP/2 and HTTP headers)");

        if d.is_clean() {
            EXIT_MATCH
        } else {
            EXIT_MISMATCH
        }
    })
}
