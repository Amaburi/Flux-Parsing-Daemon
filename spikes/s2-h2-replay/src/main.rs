//! M0 spike S2 — after manually consuming the HTTP/2 preface, SETTINGS,
//! WINDOW_UPDATE and HEADERS, can the SAME connection still be served by hyper?
//!
//! This is the question that decides whether `fpd serve` can terminate with hyper
//! or has to become a frame-level proxy.
//!
//! Throwaway. Nothing here is meant to survive into production.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Yields `buf` first, then delegates to `inner`. This is what hands the already
/// consumed bytes back to hyper so it can drive the connection normally.
struct Replaying<S> {
    buf: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Replaying<S> {
    fn new(buf: Vec<u8>, inner: S) -> Self {
        Self { buf, pos: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replaying<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = std::cmp::min(out.remaining(), self.buf.len() - self.pos);
            let start = self.pos;
            let chunk = self.buf[start..start + n].to_vec();
            out.put_slice(&chunk);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replaying<S> {
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

fn frame_name(t: u8) -> &'static str {
    match t {
        0x0 => "DATA",
        0x1 => "HEADERS",
        0x2 => "PRIORITY",
        0x3 => "RST_STREAM",
        0x4 => "SETTINGS",
        0x5 => "PUSH_PROMISE",
        0x6 => "PING",
        0x7 => "GOAWAY",
        0x8 => "WINDOW_UPDATE",
        0x9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

/// Reads preface + frames until HEADERS, appending every byte to `captured`
/// and reporting the Akamai-fingerprint-relevant fields as it goes.
async fn capture_preamble<S: AsyncRead + Unpin>(
    stream: &mut S,
    captured: &mut Vec<u8>,
) -> std::io::Result<()> {
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface).await?;
    captured.extend_from_slice(&preface);
    println!(
        "  preface: {}",
        if preface == PREFACE { "OK" } else { "MISMATCH" }
    );

    let mut settings_pairs: Vec<(u16, u32)> = Vec::new();
    let mut window_update: Option<u32> = None;

    loop {
        let mut hdr = [0u8; 9];
        stream.read_exact(&mut hdr).await?;
        captured.extend_from_slice(&hdr);

        // Frame header: length(3) | type(1) | flags(1) | R+stream_id(4).
        // stream_id is bytes 5..9 — reading it at 4..8 swallows the flags byte
        // and yields nonsense like 0x05000000.
        let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
        let ftype = hdr[3];
        let flags = hdr[4];
        let stream_id = u32::from_be_bytes([hdr[5] & 0x7f, hdr[6], hdr[7], hdr[8]]);

        let mut payload = vec![0u8; len];
        if len > 0 {
            stream.read_exact(&mut payload).await?;
            captured.extend_from_slice(&payload);
        }

        println!(
            "  frame {:<13} len={:<5} flags=0x{:02x} stream={}",
            frame_name(ftype),
            len,
            flags,
            stream_id
        );

        match ftype {
            0x4 => {
                for c in payload.chunks_exact(6) {
                    let id = u16::from_be_bytes([c[0], c[1]]);
                    let v = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
                    settings_pairs.push((id, v));
                }
            }
            0x8 => {
                if payload.len() == 4 {
                    window_update = Some(u32::from_be_bytes([
                        payload[0] & 0x7f,
                        payload[1],
                        payload[2],
                        payload[3],
                    ]));
                }
            }
            0x1 => {
                let s = settings_pairs
                    .iter()
                    .map(|(i, v)| format!("{i}:{v}"))
                    .collect::<Vec<_>>()
                    .join(";");
                println!(
                    "  >> akamai-ish: {}|{}|0|<hpack not decoded in spike>",
                    s,
                    window_update.unwrap_or(0)
                );
                return Ok(());
            }
            _ => {}
        }
    }
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
    // h2 only, so the client is forced down the path we are testing.
    cfg.alpn_protocols = vec![b"h2".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:8444").await?;
    println!("S2 listening on https://127.0.0.1:8444 (h2 only)");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            let mut tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    println!("--- {peer} TLS failed: {e}");
                    return;
                }
            };
            println!("--- {peer} TLS OK");

            let mut captured = Vec::new();
            match tokio::time::timeout(
                Duration::from_secs(5),
                capture_preamble(&mut tls, &mut captured),
            )
            .await
            {
                Ok(Ok(())) => println!("  captured {} bytes of preamble", captured.len()),
                Ok(Err(e)) => {
                    println!("  capture io error: {e}");
                    return;
                }
                Err(_) => println!(
                    "  capture TIMED OUT after {} bytes — serving anyway",
                    captured.len()
                ),
            }

            // The question: can hyper still drive this connection?
            let replayed = Replaying::new(captured, tls);
            let svc = service_fn(|_req| async {
                Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(Bytes::from(
                    "ok\n",
                ))))
            });

            match hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(replayed), svc)
                .await
            {
                Ok(()) => println!("  >> SERVED OK after replay"),
                Err(e) => println!("  >> SERVE FAILED after replay: {e}"),
            }
        });
    }
}
