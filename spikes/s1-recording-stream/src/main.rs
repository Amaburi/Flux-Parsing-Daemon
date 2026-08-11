//! M0 spike S1 — can we tee raw bytes under tokio-rustls and still complete a
//! handshake, and is ClientHello extension ORDER recoverable from what we caught?
//!
//! Throwaway. Nothing here is meant to survive into production.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Tees every byte read from the inner stream into a shared buffer.
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

/// GREASE values are 0x0A0A, 0x1A1A, ... 0xFAFA: both bytes equal, low nibbles 0xA.
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

#[derive(Debug)]
struct Hello {
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
}

/// Minimal ClientHello walk over the raw record bytes.
/// record hdr(5) | hs hdr(4) | legacy_version(2) | random(32) | session_id
/// | cipher_suites | compression | extensions
fn parse_hello(raw: &[u8]) -> Option<Hello> {
    let mut p = 5usize + 4 + 2 + 32;
    let sid = *raw.get(p)? as usize;
    p += 1 + sid;

    let cs_len = u16::from_be_bytes([*raw.get(p)?, *raw.get(p + 1)?]) as usize;
    p += 2;
    let mut ciphers = Vec::new();
    let cs_end = p + cs_len;
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
        let id = u16::from_be_bytes([raw[p], raw[p + 1]]);
        let len = u16::from_be_bytes([raw[p + 2], raw[p + 3]]) as usize;
        extensions.push(id);
        p += 4 + len;
    }

    Some(Hello {
        ciphers,
        extensions,
    })
}

fn report(hello: &Hello) {
    let grease_ciphers = hello.ciphers.iter().filter(|c| is_grease(**c)).count();
    let grease_exts = hello.extensions.iter().filter(|e| is_grease(**e)).count();

    println!("  ciphers ({}): {:?}", hello.ciphers.len(), hello.ciphers);
    println!(
        "  extension order ({}): {:?}",
        hello.extensions.len(),
        hello.extensions
    );

    let mut sorted = hello.extensions.clone();
    sorted.sort_unstable();
    println!("  extensions sorted: {sorted:?}");
    println!("  GREASE: {grease_ciphers} in ciphers, {grease_exts} in extensions");
}

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
    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!("S1 listening on https://127.0.0.1:8443");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let rec = Recording {
            inner: tcp,
            seen: Arc::clone(&seen),
        };
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let outcome = acceptor.accept(rec).await;
            let raw = seen.lock().map(|g| g.clone()).unwrap_or_default();
            match outcome {
                Ok(_stream) => {
                    println!("--- {peer} handshake OK, {} bytes recorded", raw.len());
                    match parse_hello(&raw) {
                        Some(h) => report(&h),
                        None => println!("  PARSE FAILED"),
                    }
                }
                Err(e) => {
                    println!("--- {peer} handshake FAILED: {e} ({} bytes)", raw.len());
                    if let Some(h) = parse_hello(&raw) {
                        report(&h);
                    }
                }
            }
        });
    }
}
