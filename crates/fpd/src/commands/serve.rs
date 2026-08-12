//! `fpd serve` — reverse proxy that annotates inbound traffic.

use std::net::SocketAddr;

use fingerprint_probe::profile::ProfileDb;
use fingerprint_probe::serve::{IpMode, ServeConfig, Server};

pub struct Args {
    pub listen: String,
    pub upstream: String,
    pub ip_mode: String,
    pub cacert_out: Option<String>,
}

pub fn run(args: Args) -> u8 {
    let listen: SocketAddr = match args.listen.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fpd: bad --listen `{}`: {e}", args.listen);
            return 2;
        }
    };
    let upstream: SocketAddr = match args.upstream.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("fpd: bad --upstream `{}`: {e}", args.upstream);
            return 2;
        }
    };

    let ip_mode = match args.ip_mode.as_str() {
        "full" => IpMode::Full,
        "truncated" => IpMode::Truncated,
        "omitted" => IpMode::Omitted,
        other => {
            eprintln!("fpd: bad --ip-mode `{other}`; use full, truncated or omitted");
            return 2;
        }
    };

    // Without a subscriber every tracing call is a no-op, so the connection log
    // that this command exists to produce would silently go nowhere. Found by
    // running serve and getting an empty log.
    // Logs go to stderr so stdout stays clean and pipeable, which matters for a
    // long-running process an operator may want to redirect separately.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let db = match ProfileDb::shipped() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("fpd: cannot load profiles: {e}");
            return 2;
        }
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fpd: runtime: {e}");
            return 2;
        }
    };

    rt.block_on(async move {
        let mut cfg = ServeConfig::new(listen, upstream);
        cfg.ip_mode = ip_mode;

        let server = match Server::bind(cfg, db).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("fpd: cannot bind {listen}: {e}");
                return 2;
            }
        };

        if let Some(path) = &args.cacert_out {
            if let Err(e) = std::fs::write(path, server.cert_pem()) {
                eprintln!("fpd: cannot write {path}: {e}");
                return 2;
            }
        }

        println!("fpd serve");
        println!("  listening  https://{}", server.local_addr());
        println!("  upstream   http://{upstream}");
        println!("  ip mode    {}", args.ip_mode);
        println!();
        println!("Injected headers: x-fp-ja4, x-fp-ja3, x-fp-h2, x-fp-http-headers,");
        println!("                  x-fp-verdict, x-fp-confidence, x-fp-mismatch");
        println!("Inbound x-fp-* headers from clients are stripped.");

        server.run().await;
        0
    })
}
