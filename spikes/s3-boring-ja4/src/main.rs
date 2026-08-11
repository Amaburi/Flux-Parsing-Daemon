//! M0 spike S3 — can `boring` emit a ClientHello matching a captured Chrome?
//!
//! This is the spike that decides whether emulation (M5) is in v1 or moves to v2.
//! Self-contained: runs its own capture listener, drives a Chrome-configured
//! boring client at it, and diffs in-process.
//!
//! Throwaway. Nothing here is meant to survive into production.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Chrome baseline, captured live in spike S1 (docs/spikes/s1-capture-raw.txt).
// GREASE removed: its values rotate per connection, only positions are stable.
// ---------------------------------------------------------------------------

const CHROME_CIPHERS: &[u16] = &[
    4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53,
];

/// Sorted, GREASE removed. Chrome permutes extension order, so only the set matters.
const CHROME_EXTENSIONS_SORTED: &[u16] = &[
    5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 65037, 65281,
];

const CHROME_GREASE_CIPHERS: usize = 1;
const CHROME_GREASE_EXTENSIONS: usize = 2;

// ---------------------------------------------------------------------------
// Capture side (lifted from S1)
// ---------------------------------------------------------------------------

struct Recording<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let new = &buf.filled()[before..];
            if !new.is_empty() {
                if let Ok(mut g) = self.seen.lock() {
                    g.extend_from_slice(new);
                }
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

#[derive(Debug, Default, Clone)]
struct Hello {
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
}

fn parse_hello(raw: &[u8]) -> Option<Hello> {
    let mut p = 5usize + 4 + 2 + 32;
    let sid = *raw.get(p)? as usize;
    p += 1 + sid;

    let cs_len = u16::from_be_bytes([*raw.get(p)?, *raw.get(p + 1)?]) as usize;
    p += 2;
    let cs_end = p + cs_len;
    let mut ciphers = Vec::new();
    while p + 2 <= cs_end && p + 2 <= raw.len() {
        ciphers.push(u16::from_be_bytes([raw[p], raw[p + 1]]));
        p += 2;
    }
    p = cs_end;

    let comp = *raw.get(p)? as usize;
    p += 1 + comp;

    let ext_total = u16::from_be_bytes([*raw.get(p)?, *raw.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    let mut extensions = Vec::new();
    while p + 4 <= ext_end && p + 4 <= raw.len() {
        extensions.push(u16::from_be_bytes([raw[p], raw[p + 1]]));
        let len = u16::from_be_bytes([raw[p + 2], raw[p + 3]]) as usize;
        p += 4 + len;
    }

    Some(Hello {
        ciphers,
        extensions,
    })
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

fn compare(observed: &Hello) -> bool {
    let obs_ciphers: Vec<u16> = observed
        .ciphers
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .collect();
    let obs_grease_c = observed.ciphers.len() - obs_ciphers.len();

    let mut obs_exts: Vec<u16> = observed
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .collect();
    let obs_grease_e = observed.extensions.len() - obs_exts.len();
    obs_exts.sort_unstable();

    let mut ok = true;

    // 1. cipher order (fixed axis)
    if obs_ciphers == CHROME_CIPHERS {
        println!("  ✓ ciphers        {}/{} exact order", obs_ciphers.len(), CHROME_CIPHERS.len());
    } else {
        ok = false;
        println!("  ✗ ciphers        got {} want {}", obs_ciphers.len(), CHROME_CIPHERS.len());
        println!("      got:  {obs_ciphers:?}");
        println!("      want: {CHROME_CIPHERS:?}");
        let missing: Vec<_> = CHROME_CIPHERS.iter().filter(|c| !obs_ciphers.contains(c)).collect();
        let extra: Vec<_> = obs_ciphers.iter().filter(|c| !CHROME_CIPHERS.contains(c)).collect();
        if !missing.is_empty() {
            println!("      missing: {missing:?}");
        }
        if !extra.is_empty() {
            println!("      extra:   {extra:?}");
        }
    }

    // 2. extension set (permuted axis)
    if obs_exts == CHROME_EXTENSIONS_SORTED {
        println!("  ✓ extensions     {}/{} set matches", obs_exts.len(), CHROME_EXTENSIONS_SORTED.len());
    } else {
        ok = false;
        println!("  ✗ extensions     got {} want {}", obs_exts.len(), CHROME_EXTENSIONS_SORTED.len());
        println!("      got:  {obs_exts:?}");
        println!("      want: {CHROME_EXTENSIONS_SORTED:?}");
        let missing: Vec<_> = CHROME_EXTENSIONS_SORTED.iter().filter(|e| !obs_exts.contains(e)).collect();
        let extra: Vec<_> = obs_exts.iter().filter(|e| !CHROME_EXTENSIONS_SORTED.contains(e)).collect();
        if !missing.is_empty() {
            println!("      missing: {missing:?}");
        }
        if !extra.is_empty() {
            println!("      extra:   {extra:?}");
        }
    }

    // 3. GREASE counts
    if obs_grease_c == CHROME_GREASE_CIPHERS && obs_grease_e == CHROME_GREASE_EXTENSIONS {
        println!("  ✓ GREASE         {obs_grease_c} cipher, {obs_grease_e} extension");
    } else {
        ok = false;
        println!(
            "  ✗ GREASE         got {obs_grease_c}c/{obs_grease_e}e, want {CHROME_GREASE_CIPHERS}c/{CHROME_GREASE_EXTENSIONS}e"
        );
    }

    ok
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let issued = rcgen::generate_simple_self_signed(sans)?;
    let cert_der = issued.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(issued.signing_key.serialize_der())
        .map_err(|e| format!("key: {e}"))?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:8445").await?;
    println!("S3 capture listener on 127.0.0.1:8445\n");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Hello>(8);

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let seen = Arc::new(Mutex::new(Vec::new()));
            let rec = Recording {
                inner: tcp,
                seen: Arc::clone(&seen),
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = acceptor.accept(rec).await;
                let raw = seen.lock().map(|g| g.clone()).unwrap_or_default();
                if let Some(h) = parse_hello(&raw) {
                    let _ = tx.send(h).await;
                }
            });
        }
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // -- boring client, configured to look like Chrome --------------------
    use boring::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};

    let mut b = SslConnector::builder(SslMethod::tls_client())?;
    b.set_verify(SslVerifyMode::NONE);
    b.set_grease_enabled(true);
    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    b.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:\
         ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:\
         ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:\
         ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-RSA-AES128-SHA:\
         ECDHE-RSA-AES256-SHA:\
         AES128-GCM-SHA256:\
         AES256-GCM-SHA384:\
         AES128-SHA:\
         AES256-SHA",
    )?;
    b.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    let config = b.build().configure()?;
    let tcp = TcpStream::connect("127.0.0.1:8445").await?;
    match tokio_boring::connect(config, "localhost", tcp).await {
        Ok(_) => println!("boring client: handshake OK"),
        Err(e) => println!("boring client: handshake ended ({e}) — ClientHello still captured"),
    }

    let observed = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .map_err(|_| "timed out waiting for captured ClientHello")?
        .ok_or("capture channel closed")?;

    println!("\n=== boring output ===");
    println!("  ciphers ({}): {:?}", observed.ciphers.len(), observed.ciphers);
    println!(
        "  extensions ({}): {:?}",
        observed.extensions.len(),
        observed.extensions
    );

    println!("\n=== vs captured chrome ===");
    let ok = compare(&observed);
    println!(
        "\n  S3 VERDICT: {}",
        if ok {
            "PASS — boring reproduces the captured Chrome"
        } else {
            "PARTIAL — see field diffs above; this list is M5's work queue"
        }
    );

    Ok(())
}
