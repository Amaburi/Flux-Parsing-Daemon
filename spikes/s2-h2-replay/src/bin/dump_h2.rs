//! Fixture recorder: captures the DECRYPTED HTTP/2 preamble bytes.
//!
//! Unlike the TLS fixtures, these bytes only exist after TLS termination, so they
//! cannot be captured with tcpdump. Writes preface + frames up to and including
//! the first HEADERS frame.
//!
//! Label with FPD_FIXTURE_LABEL.

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

async fn capture_preamble<S: AsyncRead + Unpin>(
    stream: &mut S,
    captured: &mut Vec<u8>,
) -> std::io::Result<()> {
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface).await?;
    captured.extend_from_slice(&preface);

    loop {
        let mut hdr = [0u8; 9];
        stream.read_exact(&mut hdr).await?;
        captured.extend_from_slice(&hdr);

        let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
        let ftype = hdr[3];

        let mut payload = vec![0u8; len];
        if len > 0 {
            stream.read_exact(&mut payload).await?;
            captured.extend_from_slice(&payload);
        }

        // 0x1 = HEADERS: the request is complete, stop here.
        if ftype == 0x1 {
            return Ok(());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let label = std::env::var("FPD_FIXTURE_LABEL").unwrap_or_else(|_| "unlabelled-h2".into());
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
    cfg.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:8444").await?;
    println!("h2 dump listening on 127.0.0.1:8444 -> {out_dir}/{label}.bin");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let mut tls = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(e) => {
                println!("{peer}: TLS failed: {e}");
                continue;
            }
        };

        let mut captured = Vec::new();
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            capture_preamble(&mut tls, &mut captured),
        )
        .await
        {
            Ok(Ok(())) => {
                let path = format!("{out_dir}/{label}.bin");
                std::fs::write(&path, &captured)?;
                println!("wrote {path} ({} bytes) from {peer}", captured.len());
                return Ok(());
            }
            Ok(Err(e)) => println!("{peer}: io error: {e}"),
            Err(_) => println!("{peer}: timed out after {} bytes", captured.len()),
        }
    }
}
