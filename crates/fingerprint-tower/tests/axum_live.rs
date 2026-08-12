//! The actual thing a user will write: an axum app that knows what its clients
//! are, with no proxy in front of it.
//!
//! axum is a dev-dependency only. The crate itself must not depend on it, but a
//! test that avoids the real framework would not prove the real use case.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::Extension;
use axum::routing::get;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tower::ServiceExt;

use fingerprint_tower::{Acceptor, ClientFingerprint, FingerprintLayer};

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// What a handler sees. Returned as the body so the test can assert on it.
async fn whoami(Extension(fp): Extension<ClientFingerprint>) -> String {
    format!(
        "{}|{}|{}|{}",
        fp.ja4,
        fp.verdict,
        fp.mismatch(),
        fp.claimed
            .map(|c| c.as_str().to_string())
            .unwrap_or_default()
    )
}

fn tls_config() -> Arc<rustls::ServerConfig> {
    let issued = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
        .expect("cert");
    let cert = issued.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::try_from(issued.signing_key.serialize_der())
        .expect("key");

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("tls config");
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Starts one axum app on one listener. No proxy, no second process.
async fn start_app() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let acceptor = Acceptor::new(tls_config());

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let Ok(accepted) = acceptor.accept(tcp).await else {
                    return;
                };

                // The one line a user adds to their existing router.
                let app = Router::new()
                    .route("/", get(whoami))
                    .layer(FingerprintLayer::new(accepted.fingerprint));

                let svc = hyper::service::service_fn(move |req| {
                    let app = app.clone();
                    async move { app.oneshot(req).await }
                });

                let io = TokioIo::new(accepted.stream);
                if accepted.is_h2 {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, svc)
                        .await;
                }
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    port
}

fn curl(port: u16, extra: &[&str]) -> String {
    let url = format!("https://127.0.0.1:{port}/");
    let out = std::process::Command::new("curl")
        .args(["-sk", "--http2", "--max-time", "8"])
        .args(extra)
        .arg(&url)
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The point of the whole crate: an application knows what its client is, with
/// nothing else deployed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handler_sees_the_client_fingerprint_with_no_proxy_in_front() {
    if !curl_available() {
        return;
    }
    let port = start_app().await;
    let body = curl(port, &[]);

    let fields: Vec<&str> = body.split('|').collect();
    // Oracle from crates/fingerprint-core/tests/fixtures/curl-8.7.1-macos.md
    assert_eq!(
        fields.first().copied(),
        Some("t13i4906h2_0d8feac7bc37_7395dae3b2f3"),
        "handler saw: {body}"
    );
    assert_eq!(fields.get(1).copied(), Some("curl-8.7.1-macos"));
    assert_eq!(fields.get(2).copied(), Some("false"), "honest client");
}

/// Claim mismatch reaches the handler, so an application can act on it directly
/// rather than reading a header a proxy set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lying_user_agent_reaches_the_handler_as_a_mismatch() {
    if !curl_available() {
        return;
    }
    let port = start_app().await;
    let body = curl(
        port,
        &[
            "-A",
            "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/131.0.0.0 Safari/537.36",
        ],
    );

    let fields: Vec<&str> = body.split('|').collect();
    assert_eq!(fields.get(2).copied(), Some("true"), "handler saw: {body}");
    assert_eq!(fields.get(3).copied(), Some("chrome"));
}

/// HTTP/2 multiplexes, so several requests share one connection and therefore one
/// fingerprint. That is correct, since a fingerprint describes the client rather
/// than the request, but it is surprising enough to pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_request_on_one_connection_sees_the_same_fingerprint() {
    if !curl_available() {
        return;
    }
    let port = start_app().await;
    let url = format!("https://127.0.0.1:{port}/");

    // One curl invocation, two requests, one connection.
    let out = std::process::Command::new("curl")
        .args(["-sk", "--http2", "--max-time", "8", &url, &url])
        .output()
        .expect("curl");
    let body = String::from_utf8_lossy(&out.stdout);

    let ja4 = "t13i4906h2_0d8feac7bc37_7395dae3b2f3";
    assert_eq!(body.matches(ja4).count(), 2, "both requests: {body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http1_client_is_also_fingerprinted() {
    if !curl_available() {
        return;
    }
    let port = start_app().await;
    let url = format!("https://127.0.0.1:{port}/");
    let out = std::process::Command::new("curl")
        .args(["-sk", "--http1.1", "--max-time", "8", &url])
        .output()
        .expect("curl");
    let body = String::from_utf8_lossy(&out.stdout);

    assert!(body.starts_with("t13"), "no TLS fingerprint: {body}");
}
