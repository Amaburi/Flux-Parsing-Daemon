//! `fpd emulate` — build a client that reproduces a profile, and prove it does.

#[cfg(feature = "emulation")]
use fingerprint_probe::profile::ProfileDb;

/// Fields are read only in the `emulation` build. Without the feature the command
/// exists purely to explain how to get one, so `dead_code` is expected here rather
/// than a sign of something unused.
#[cfg_attr(not(feature = "emulation"), allow(dead_code))]
pub struct Args {
    pub profile: String,
    pub verify: bool,
}

#[cfg_attr(not(feature = "emulation"), allow(dead_code))]
pub const EXIT_MATCH: u8 = 0;
#[cfg_attr(not(feature = "emulation"), allow(dead_code))]
pub const EXIT_MISMATCH: u8 = 1;
pub const EXIT_OPERATIONAL: u8 = 2;

#[cfg(not(feature = "emulation"))]
pub fn run(_args: Args) -> u8 {
    eprintln!("fpd: this build has no emulation support.");
    eprintln!("     Rebuild with --features emulation.");
    eprintln!();
    eprintln!("     It is off by default because it pulls in BoringSSL, a C");
    eprintln!("     dependency that inspection alone does not need.");
    EXIT_OPERATIONAL
}

#[cfg(feature = "emulation")]
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

    if !args.verify {
        println!("Built a client for {}.", profile.label);
        println!("Pass --verify to prove it reproduces the profile.");
        return EXIT_MATCH;
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fpd: runtime: {e}");
            return EXIT_OPERATIONAL;
        }
    };

    rt.block_on(async move {
        let d = match fingerprint_emulate::verify::verify(&profile).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!("fpd: {e}");
                return EXIT_OPERATIONAL;
            }
        };

        print!("{d}");
        println!("  (TLS layer only; HTTP/2 emulation is not implemented)");

        if d.is_clean() {
            EXIT_MATCH
        } else {
            EXIT_MISMATCH
        }
    })
}
