//! The capture probe.
//!
//! Binds loopback on an ephemeral port, accepts one connection, and reports what
//! the client looked like at the TLS and HTTP/2 layers. It never writes a
//! response, because nothing needs one and not responding keeps the surface
//! minimal.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fingerprint_core::ja4::TlsFingerprint;
use fingerprint_h2::akamai::H2Fingerprint;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::recording::RecordingStream;

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls setup: {0}")]
    Tls(String),
    #[error("certificate: {0}")]
    Cert(String),
    #[error("no connection arrived within the timeout")]
    NoConnection,
    #[error("connection produced no parseable ClientHello")]
    NoClientHello,
}

/// What one client looked like on the wire.
#[derive(Debug, Clone)]
pub struct ClientReport {
    pub tls: TlsFingerprint,
    /// `None` when ALPN did not negotiate h2, or when the client disconnected
    /// before sending a complete request.
    pub h2: Option<H2Fingerprint>,
    pub alpn: Option<String>,
    /// True when the TLS handshake did not complete, usually because the client
    /// rejected the self-signed certificate. The ClientHello is still captured,
    /// because the byte tee runs before the alert.
    pub handshake_failed: bool,
}

pub struct Probe {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    cert_pem: String,
    port: u16,
}

impl Probe {
    pub async fn bind() -> Result<Self, ProbeError> {
        Self::bind_on(0).await
    }

    pub async fn bind_on(port: u16) -> Result<Self, ProbeError> {
        let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let issued = rcgen::generate_simple_self_signed(sans)
            .map_err(|e| ProbeError::Cert(e.to_string()))?;
        let cert_pem = issued.cert.pem();
        let cert_der = issued.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(issued.signing_key.serialize_der())
                .map_err(|e| ProbeError::Cert(e.to_string()))?;

        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| ProbeError::Tls(e.to_string()))?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let port = listener.local_addr()?.port();

        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(cfg)),
            cert_pem,
            port,
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}/", self.port)
    }

    /// PEM for callers that would rather trust the certificate than disable
    /// verification.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Accepts exactly one connection and reports on it.
    ///
    /// A failed handshake still yields a report. The M0 S1 spike showed Chrome
    /// rejecting the self-signed certificate while its ClientHello was captured in
    /// full, and that is the common case for a browser, so treating it as an error
    /// would make the probe useless for the client that matters most.
    pub async fn accept_one(&self, timeout: Duration) -> Result<ClientReport, ProbeError> {
        let accepted = tokio::time::timeout(timeout, self.listener.accept())
            .await
            .map_err(|_| ProbeError::NoConnection)?;
        let (tcp, _peer) = accepted?;

        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = RecordingStream::new(tcp, Arc::clone(&seen));

        let handshake = tokio::time::timeout(timeout, self.acceptor.accept(recorded)).await;

        let raw = seen.lock().map(|g| g.clone()).unwrap_or_default();
        let tls =
            fingerprint_core::ja4::fingerprint(&raw).map_err(|_| ProbeError::NoClientHello)?;

        let (h2, alpn, handshake_failed) = match handshake {
            Ok(Ok(stream)) => {
                let alpn = stream
                    .get_ref()
                    .1
                    .alpn_protocol()
                    .map(|p| String::from_utf8_lossy(p).into_owned());
                let h2 = if alpn.as_deref() == Some("h2") {
                    capture_h2(stream, timeout).await
                } else {
                    None
                };
                (h2, alpn, false)
            }
            // Handshake refused or timed out. The ClientHello is still ours.
            Ok(Err(_)) | Err(_) => (None, None, true),
        };

        Ok(ClientReport {
            tls,
            h2,
            alpn,
            handshake_failed,
        })
    }
}

/// Reads the HTTP/2 preamble through the first HEADERS frame.
async fn capture_h2<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    timeout: Duration,
) -> Option<H2Fingerprint> {
    let mut captured = Vec::new();
    let read = tokio::time::timeout(timeout, async {
        let mut preface = [0u8; 24];
        stream.read_exact(&mut preface).await?;
        captured.extend_from_slice(&preface);

        loop {
            let mut hdr = [0u8; 9];
            stream.read_exact(&mut hdr).await?;
            captured.extend_from_slice(&hdr);

            let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
            let kind = hdr[3];

            // Bound the read so a client cannot make us buffer indefinitely.
            if len > 1 << 20 {
                return Err(std::io::Error::other("frame too large"));
            }
            let mut payload = vec![0u8; len];
            if len > 0 {
                stream.read_exact(&mut payload).await?;
                captured.extend_from_slice(&payload);
            }

            if kind == 0x1 {
                return Ok::<(), std::io::Error>(());
            }
        }
    })
    .await;

    // A partial capture is still worth parsing: settings and window update arrive
    // before headers do.
    let _ = read;
    fingerprint_h2::akamai::fingerprint(&captured).ok()
}
