//! The TLS acceptor that fingerprints as it accepts.
//!
//! **This cannot be HTTP middleware.** By the time a request reaches axum, rustls
//! has completed the handshake and dropped the ClientHello. Extension order and
//! GREASE placement, the two things a fingerprint needs most, are gone. The hook
//! therefore sits below HTTP entirely, which is why the API replaces the acceptor
//! rather than adding a layer to a router.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fingerprint_probe::probe::ClientReport;
use fingerprint_probe::profile::ProfileDb;
use fingerprint_probe::recording::RecordingStream;
use fingerprint_probe::replaying::Replaying;
use fingerprint_probe::ua::Family;
use fingerprint_probe::verdict::identify;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls handshake failed")]
    Handshake,
    #[error("timed out")]
    Timeout,
    #[error("no parseable ClientHello")]
    NoClientHello,
}

/// What a client looked like, cheap to clone.
///
/// Cloned into every request on the connection, so the expensive detail lives
/// behind an `Arc` and only callers who want it pay for it.
#[derive(Debug, Clone)]
pub struct ClientFingerprint {
    pub ja4: String,
    pub ja3: String,
    /// `None` when the connection is not HTTP/2.
    pub akamai: Option<String>,
    /// Matching profile label, or `unknown`.
    pub verdict: String,
    pub confidence: f32,
    /// Set when the User-Agent contradicts the fingerprint.
    pub claimed: Option<Family>,
    pub report: Arc<ClientReport>,
}

impl ClientFingerprint {
    pub fn mismatch(&self) -> bool {
        self.claimed.is_some()
    }
}

/// A finished accept: the connection, ready to serve, plus what the client is.
pub struct Accepted<S> {
    /// Hand this to hyper. For HTTP/2 it replays the preamble that was consumed
    /// during capture, so hyper sees the bytes it expects.
    pub stream: Replaying<TlsStream<RecordingStream<S>>>,
    pub fingerprint: ClientFingerprint,
    pub is_h2: bool,
}

#[derive(Clone)]
pub struct Acceptor {
    inner: TlsAcceptor,
    db: Arc<ProfileDb>,
    handshake_timeout: Duration,
    capture_timeout: Duration,
}

impl Acceptor {
    /// Drop-in for `TlsAcceptor::from`.
    pub fn new(config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            inner: TlsAcceptor::from(config),
            db: Arc::new(ProfileDb::shipped().unwrap_or_default()),
            handshake_timeout: Duration::from_secs(10),
            capture_timeout: Duration::from_secs(10),
        }
    }

    pub fn with_profiles(mut self, db: ProfileDb) -> Self {
        self.db = Arc::new(db);
        self
    }

    pub fn with_timeouts(mut self, handshake: Duration, capture: Duration) -> Self {
        self.handshake_timeout = handshake;
        self.capture_timeout = capture;
        self
    }

    /// Accepts one connection, fingerprinting it on the way through.
    ///
    /// A failed handshake is an error rather than a fingerprint. Unlike the
    /// standalone probe there is no connection left to serve, so a report would
    /// have nowhere to go.
    pub async fn accept<S>(&self, stream: S) -> Result<Accepted<S>, AcceptError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = RecordingStream::new(stream, Arc::clone(&seen));

        let tls =
            match tokio::time::timeout(self.handshake_timeout, self.inner.accept(recorded)).await {
                Ok(Ok(s)) => s,
                Ok(Err(_)) => return Err(AcceptError::Handshake),
                Err(_) => return Err(AcceptError::Timeout),
            };

        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let alpn = tls
            .get_ref()
            .1
            .alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned());

        let mut tls = tls;
        let preamble = if is_h2 {
            capture_preamble(&mut tls, self.capture_timeout).await
        } else {
            Vec::new()
        };

        let raw = seen.lock().map(|g| g.clone()).unwrap_or_default();
        let tls_fp =
            fingerprint_core::ja4::fingerprint(&raw).map_err(|_| AcceptError::NoClientHello)?;

        let report = ClientReport {
            tls: tls_fp,
            raw_hello: fingerprint_probe::probe::retain(&raw),
            h2: fingerprint_h2::akamai::fingerprint(&preamble).ok(),
            alpn,
            handshake_failed: false,
        };

        let id = identify(&report, &self.db);
        let fingerprint = ClientFingerprint {
            ja4: report.tls.ja4.clone(),
            ja3: report.tls.ja3.clone(),
            akamai: report.h2.as_ref().map(|h| h.akamai.clone()),
            verdict: id
                .best
                .as_ref()
                .map(|b| b.label.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            confidence: id.best.as_ref().map(|b| b.score).unwrap_or(0.0),
            claimed: id.mismatch.map(|m| m.claimed),
            report: Arc::new(report),
        };

        Ok(Accepted {
            stream: Replaying::new(preamble, tls),
            fingerprint,
            is_h2,
        })
    }
}

async fn capture_preamble<S: AsyncRead + Unpin>(stream: &mut S, timeout: Duration) -> Vec<u8> {
    let mut captured = Vec::new();
    let _ = tokio::time::timeout(timeout, async {
        let mut preface = [0u8; 24];
        stream.read_exact(&mut preface).await?;
        captured.extend_from_slice(&preface);

        loop {
            let mut hdr = [0u8; 9];
            stream.read_exact(&mut hdr).await?;
            captured.extend_from_slice(&hdr);

            let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
            let kind = hdr[3];
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
    captured
}
