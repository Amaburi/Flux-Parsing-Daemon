//! `fpd tui`, the live view.

pub struct Args {
    pub attach: Option<String>,
    pub listen: Option<String>,
}

pub fn run(args: Args) -> u8 {
    let (attach, listen) = (args.attach, args.listen);

    if attach.is_some() && listen.is_some() {
        eprintln!("fpd: pass either --attach or --listen, not both");
        return 2;
    }

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fpd: runtime: {e}");
            return 2;
        }
    };

    rt.block_on(async move {
        let (rows, label) = match (&attach, &listen) {
            #[cfg(unix)]
            (Some(path), None) => {
                let p = std::path::PathBuf::from(path);
                if !p.exists() {
                    eprintln!("fpd: no socket at {path}");
                    eprintln!("     start one with `fpd serve --admin-socket {path}`");
                    return 2;
                }
                (crate::tui::source::attach(&p), path.clone())
            }
            #[cfg(not(unix))]
            (Some(_), None) => {
                eprintln!("fpd: --attach is Unix only");
                return 2;
            }
            (None, Some(addr)) => {
                let parsed: std::net::SocketAddr = match addr.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("fpd: bad --listen `{addr}`: {e}");
                        return 2;
                    }
                };
                eprintln!("fpd: listening on https://{parsed}");
                (crate::tui::source::listen(parsed), addr.clone())
            }
            _ => {
                eprintln!("fpd: pass --attach <socket> or --listen <addr>");
                eprintln!("     --attach watches a running `fpd serve`");
                eprintln!("     --listen binds its own listener, nothing else needed");
                return 2;
            }
        };

        match crate::tui::app::run(rows, label).await {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("fpd: {e}");
                2
            }
        }
    })
}
