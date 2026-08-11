//! Fixture recorder: captures one ClientHello record and writes the raw bytes.
//!
//! Used once to produce the byte fixtures that drive `fingerprint-core`'s tests.
//! Label the output with FPD_FIXTURE_LABEL.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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

/// Trim to exactly one handshake record: type(1) version(2) length(2) | payload.
fn client_hello_record(raw: &[u8]) -> Option<&[u8]> {
    if *raw.first()? != 0x16 {
        return None;
    }
    let len = u16::from_be_bytes([*raw.get(3)?, *raw.get(4)?]) as usize;
    raw.get(..5 + len)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let label = std::env::var("FPD_FIXTURE_LABEL").unwrap_or_else(|_| "unlabelled".into());
    let out_dir = std::env::var("FPD_FIXTURE_DIR")
        .unwrap_or_else(|_| "crates/fingerprint-core/tests/fixtures".into());
    std::fs::create_dir_all(&out_dir)?;

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
    println!("dump listening on 127.0.0.1:8443 -> {out_dir}/{label}.bin");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let rec = Recording {
            inner: tcp,
            seen: Arc::clone(&seen),
        };
        let _ = acceptor.accept(rec).await;

        let raw = seen.lock().map(|g| g.clone()).unwrap_or_default();
        match client_hello_record(&raw) {
            Some(record) => {
                let path = format!("{out_dir}/{label}.bin");
                std::fs::write(&path, record)?;
                println!("wrote {path} ({} bytes) from {peer}", record.len());
                return Ok(());
            }
            None => println!("{peer}: not a handshake record ({} bytes)", raw.len()),
        }
    }
}
