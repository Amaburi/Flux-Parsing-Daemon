//! The reverse proxy.
//!
//! Terminates TLS, fingerprints the client, then forwards to an upstream over
//! plain HTTP with the result attached as headers. Any application in any
//! language reads those headers with its existing logger.
//!
//! **Fingerprinting must never break the site.** If parsing fails the request is
//! still proxied, annotated `unparsed`. A sidecar that can 500 the application it
//! sits in front of is worse than no sidecar, so every failure path here degrades
//! rather than rejects.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::inject::{fp_headers, strip_inbound};
use crate::probe::ClientReport;
use crate::profile::ProfileDb;
use crate::recording::RecordingStream;
use crate::replaying::Replaying;
use crate::verdict::identify;

pub type ProxyBody = Full<Bytes>;

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub handshake_timeout: Duration,
    pub capture_timeout: Duration,
    pub upstream_timeout: Duration,
    /// How an IP is recorded in logs.
    pub ip_mode: IpMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMode {
    Full,
    /// Final octet zeroed. The default, because a fingerprint together with a full
    /// address is close enough to personal data to treat as such.
    Truncated,
    Omitted,
}

impl ServeConfig {
    pub fn new(listen: SocketAddr, upstream: SocketAddr) -> Self {
        Self {
            listen,
            upstream,
            handshake_timeout: Duration::from_secs(10),
            capture_timeout: Duration::from_secs(10),
            upstream_timeout: Duration::from_secs(30),
            ip_mode: IpMode::Truncated,
        }
    }
}

pub fn render_ip(addr: &SocketAddr, mode: IpMode) -> String {
    match mode {
        IpMode::Omitted => "-".to_string(),
        IpMode::Full => addr.ip().to_string(),
        IpMode::Truncated => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                format!("{}.{}.{}.0", o[0], o[1], o[2])
            }
            std::net::IpAddr::V6(v6) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}::", s[0], s[1], s[2])
            }
        },
    }
}

/// Forwards one request upstream with the fingerprint headers attached.
///
/// An upstream that is down or slow yields 502 rather than propagating a failure
/// into the connection handler.
pub async fn forward(
    cfg: &ServeConfig,
    req: Request<Incoming>,
    fp: &[(String, String)],
) -> Response<ProxyBody> {
    let (mut parts, body) = req.into_parts();

    // Strip anything the client sent under our prefix, then attach the real values.
    let mut names: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(n, v)| {
            (
                n.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    strip_inbound(&mut names);

    parts.headers.clear();
    for (name, value) in names.iter().chain(fp.iter()) {
        if let (Ok(n), Ok(v)) = (
            name.parse::<hyper::header::HeaderName>(),
            value.parse::<hyper::header::HeaderValue>(),
        ) {
            parts.headers.append(n, v);
        }
    }

    let collected = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let upstream =
        match tokio::time::timeout(cfg.upstream_timeout, TcpStream::connect(cfg.upstream)).await {
            Ok(Ok(s)) => s,
            _ => return bad_gateway("upstream unreachable"),
        };

    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await;
    let (mut sender, conn) = match handshake {
        Ok(pair) => pair,
        Err(_) => return bad_gateway("upstream handshake failed"),
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let outbound = Request::from_parts(parts, Full::new(collected));
    let resp = match tokio::time::timeout(cfg.upstream_timeout, sender.send_request(outbound)).await
    {
        Ok(Ok(r)) => r,
        Ok(Err(_)) => return bad_gateway("upstream error"),
        Err(_) => return bad_gateway("upstream timed out"),
    };

    let (parts, body) = resp.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    Response::from_parts(parts, Full::new(bytes))
}

fn bad_gateway(why: &str) -> Response<ProxyBody> {
    let mut r = Response::new(Full::new(Bytes::from(format!("fpd: {why}\n"))));
    *r.status_mut() = StatusCode::BAD_GATEWAY;
    r
}

/// Reads the HTTP/2 preamble through the first HEADERS frame, returning the bytes
/// consumed so they can be replayed to hyper.
async fn capture_h2_preamble<S: AsyncRead + Unpin>(stream: &mut S, timeout: Duration) -> Vec<u8> {
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

/// Builds the report for one connection. Never fails the connection: a report
/// that cannot be parsed still lets the request through.
fn build_report(raw: &[u8], preamble: &[u8], alpn: Option<String>) -> Option<ClientReport> {
    let tls = fingerprint_core::ja4::fingerprint(raw).ok()?;
    Some(ClientReport {
        tls,
        raw_hello: crate::probe::retain(raw),
        h2: fingerprint_h2::akamai::fingerprint(preamble).ok(),
        alpn,
        handshake_failed: false,
    })
}

pub struct Server {
    cfg: ServeConfig,
    acceptor: TlsAcceptor,
    listener: TcpListener,
    db: Arc<ProfileDb>,
    cert_pem: String,
    local: SocketAddr,
}

impl Server {
    pub async fn bind(cfg: ServeConfig, db: ProfileDb) -> std::io::Result<Self> {
        let sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let issued = rcgen::generate_simple_self_signed(sans)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let cert_pem = issued.cert.pem();
        let cert_der = issued.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivateKeyDer::try_from(issued.signing_key.serialize_der())
                .map_err(std::io::Error::other)?;

        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let listener = TcpListener::bind(cfg.listen).await?;
        let local = listener.local_addr()?;

        Ok(Self {
            cfg,
            acceptor: TlsAcceptor::from(Arc::new(tls)),
            listener,
            db: Arc::new(db),
            cert_pem,
            local,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Serves until the task is dropped.
    pub async fn run(self) {
        loop {
            let Ok((tcp, peer)) = self.listener.accept().await else {
                continue;
            };
            let acceptor = self.acceptor.clone();
            let cfg = self.cfg.clone();
            let db = Arc::clone(&self.db);

            tokio::spawn(async move {
                handle(tcp, peer, acceptor, cfg, db).await;
            });
        }
    }
}

async fn handle(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    cfg: ServeConfig,
    db: Arc<ProfileDb>,
) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = RecordingStream::new(tcp, Arc::clone(&seen));

    let tls = match tokio::time::timeout(cfg.handshake_timeout, acceptor.accept(recorded)).await {
        Ok(Ok(s)) => s,
        // A failed handshake still recorded a ClientHello, but there is no
        // connection left to proxy, so there is nothing to do with it here.
        _ => return,
    };

    let alpn = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let is_h2 = alpn.as_deref() == Some("h2");

    let mut tls = tls;
    let preamble = if is_h2 {
        capture_h2_preamble(&mut tls, cfg.capture_timeout).await
    } else {
        Vec::new()
    };

    let raw = seen.lock().map(|g| g.clone()).unwrap_or_default();
    let report = build_report(&raw, &preamble, alpn);

    let fp = match &report {
        Some(r) => {
            let id = identify(r, &db);
            log_connection(&peer, r, &id, &cfg);
            fp_headers(r, &id)
        }
        None => {
            // Degrade, never reject. The site keeps working.
            tracing::info!(ip = %render_ip(&peer, cfg.ip_mode), verdict = "unparsed", "request");
            vec![
                ("x-fp-verdict".to_string(), "unparsed".to_string()),
                ("x-fp-confidence".to_string(), "0.00".to_string()),
                ("x-fp-mismatch".to_string(), "false".to_string()),
            ]
        }
    };

    let stream = Replaying::new(preamble, tls);
    serve_connection(stream, cfg, fp, is_h2).await;
}

async fn serve_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    cfg: ServeConfig,
    fp: Vec<(String, String)>,
    is_h2: bool,
) {
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let cfg = cfg.clone();
        let fp = fp.clone();
        async move { Ok::<_, std::convert::Infallible>(forward(&cfg, req, &fp).await) }
    });

    let io = TokioIo::new(stream);
    if is_h2 {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    } else {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, svc)
            .await;
    }
}

/// One line per connection.
///
/// A mismatch logs at WARN because that is the level an operator alerts on.
/// Header values never appear, with the documented `user-agent` exception, and
/// even that is reduced to a family name rather than logged verbatim.
fn log_connection(
    peer: &SocketAddr,
    report: &ClientReport,
    id: &crate::verdict::Identification,
    cfg: &ServeConfig,
) {
    let ip = render_ip(peer, cfg.ip_mode);
    let verdict = id
        .best
        .as_ref()
        .map(|b| b.label.as_str())
        .unwrap_or("unknown");

    match &id.mismatch {
        Some(m) => tracing::warn!(
            ip = %ip,
            ja4 = %report.tls.ja4,
            verdict = %verdict,
            ua_claims = %m.claimed.as_str(),
            mismatch = true,
            "request"
        ),
        None => tracing::info!(
            ip = %ip,
            ja4 = %report.tls.ja4,
            verdict = %verdict,
            mismatch = false,
            "request"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    /// A fingerprint together with a full address is close enough to personal
    /// data to treat as such, so truncation is the default.
    #[test]
    fn ip_truncation_zeroes_the_final_octet() {
        let a = addr("203.0.113.42:443");
        assert_eq!(render_ip(&a, IpMode::Truncated), "203.0.113.0");
        assert_eq!(render_ip(&a, IpMode::Full), "203.0.113.42");
        assert_eq!(render_ip(&a, IpMode::Omitted), "-");
    }

    #[test]
    fn ipv6_is_truncated_to_its_first_three_segments() {
        let a = addr("[2001:db8:1234:5678::1]:443");
        assert_eq!(render_ip(&a, IpMode::Truncated), "2001:db8:1234::");
    }

    #[test]
    fn the_default_config_truncates_and_bounds_every_phase() {
        let c = ServeConfig::new(addr("127.0.0.1:0"), addr("127.0.0.1:8080"));
        assert_eq!(c.ip_mode, IpMode::Truncated);
        assert!(c.handshake_timeout.as_secs() > 0);
        assert!(c.capture_timeout.as_secs() > 0);
        assert!(c.upstream_timeout.as_secs() > 0);
    }
}
