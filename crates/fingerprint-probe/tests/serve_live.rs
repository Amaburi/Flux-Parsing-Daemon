//! End-to-end `serve` tests.
//!
//! A stub upstream echoes the headers it received as its body, which makes "did
//! the injection actually reach the application" directly assertable. That is the
//! exit criterion for this milestone, and nothing short of it proves the sidecar
//! shape works.
//!
//! Every test here uses the multi-thread flavour. `#[tokio::test]` defaults to a
//! current-thread runtime, and these drive a blocking `std::process::Command`, so
//! on a single thread the spawned server never gets polled and the client
//! connects to a listener nobody is accepting on.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use fingerprint_probe::profile::ProfileDb;
use fingerprint_probe::serve::{ServeConfig, Server};

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Headers of one request, in arrival order.
type RequestHeaders = Vec<(String, String)>;

/// Records every header of every request the stub upstream receives.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<RequestHeaders>>>);

impl Seen {
    fn requests(&self) -> Vec<RequestHeaders> {
        self.0.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn header(&self, name: &str) -> Option<String> {
        self.requests()
            .first()?
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    }
}

/// Starts a stub upstream and returns its address.
async fn stub_upstream(seen: Seen) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let seen = seen.clone();
                    async move {
                        // The request target is recorded alongside the headers,
                        // under the HTTP/2 pseudo-header name. Recording only
                        // headers is what let an absolute-form target reach the
                        // upstream unnoticed through every test in this file.
                        let mut headers: RequestHeaders =
                            vec![(":path".to_string(), req.uri().to_string())];
                        headers.extend(req.headers().iter().map(|(n, v)| {
                            (
                                n.as_str().to_string(),
                                String::from_utf8_lossy(v.as_bytes()).into_owned(),
                            )
                        }));
                        if let Ok(mut g) = seen.0.lock() {
                            g.push(headers);
                        }
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from(
                            "upstream ok\n",
                        ))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });

    addr
}

/// Starts `serve` in front of a stub upstream and drives it with curl.
async fn through_serve(extra_curl_args: &[&str]) -> Seen {
    let seen = Seen::default();
    let upstream = stub_upstream(seen.clone()).await;

    let cfg = ServeConfig::new("127.0.0.1:0".parse().expect("addr"), upstream);
    let server = Server::bind(cfg, ProfileDb::shipped().expect("db"))
        .await
        .expect("serve bind");
    let url = format!("https://127.0.0.1:{}/", server.local_addr().port());

    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sk", "--http2", "-o", "/dev/null", "--max-time", "8"])
        .args(extra_curl_args)
        .arg(&url);
    let _ = cmd.output();

    tokio::time::sleep(Duration::from_millis(200)).await;
    seen
}

/// The milestone's exit criterion: a real client through `serve` lands correctly
/// annotated at the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_client_reaches_the_upstream_with_its_fingerprint_attached() {
    if !curl_available() {
        return;
    }
    let seen = through_serve(&[]).await;
    assert!(!seen.requests().is_empty(), "upstream saw no request");

    // Oracle from crates/fingerprint-core/tests/fixtures/curl-8.7.1-macos.md
    assert_eq!(
        seen.header("x-fp-ja4").as_deref(),
        Some("t13i4906h2_0d8feac7bc37_7395dae3b2f3")
    );
    assert_eq!(
        seen.header("x-fp-verdict").as_deref(),
        Some("curl-8.7.1-macos")
    );
    assert_eq!(seen.header("x-fp-mismatch").as_deref(), Some("false"));
    assert!(seen.header("x-fp-h2").is_some());
}

/// The security property. A client sending its own verdict must not have it
/// reach the upstream, or the whole mechanism becomes caller controlled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_cannot_forge_its_own_verdict() {
    if !curl_available() {
        return;
    }
    let seen = through_serve(&[
        "-H",
        "X-FP-Verdict: chrome-macos",
        "-H",
        "X-FP-Mismatch: false",
        "-H",
        "X-FP-JA4: forged",
    ])
    .await;

    assert_eq!(
        seen.header("x-fp-verdict").as_deref(),
        Some("curl-8.7.1-macos"),
        "the forged verdict survived"
    );
    assert_eq!(
        seen.header("x-fp-ja4").as_deref(),
        Some("t13i4906h2_0d8feac7bc37_7395dae3b2f3"),
        "the forged JA4 survived"
    );

    // Exactly one of each, so the real value did not merely get appended after
    // the forged one.
    let count = seen
        .requests()
        .first()
        .map(|h| {
            h.iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("x-fp-verdict"))
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        count, 1,
        "a forged header was appended rather than replaced"
    );
}

/// The headline detection, all the way through the proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lying_user_agent_is_flagged_at_the_upstream() {
    if !curl_available() {
        return;
    }
    let seen = through_serve(&[
        "-A",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    ])
    .await;

    assert_eq!(seen.header("x-fp-mismatch").as_deref(), Some("true"));
    assert_eq!(seen.header("x-fp-claimed").as_deref(), Some("chrome"));
}

/// Ordinary headers must survive the strip.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_client_headers_are_preserved() {
    if !curl_available() {
        return;
    }
    let seen = through_serve(&["-H", "X-Request-Id: abc123"]).await;
    assert_eq!(seen.header("x-request-id").as_deref(), Some("abc123"));
}

/// HTTP/1.1 clients have no HTTP/2 fingerprint, but must still be proxied and
/// still carry their TLS fingerprint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http1_client_is_still_proxied_and_still_fingerprinted() {
    if !curl_available() {
        return;
    }
    let seen = Seen::default();
    let upstream = stub_upstream(seen.clone()).await;
    let cfg = ServeConfig::new("127.0.0.1:0".parse().expect("addr"), upstream);
    let server = Server::bind(cfg, ProfileDb::shipped().expect("db"))
        .await
        .expect("bind");
    let url = format!("https://127.0.0.1:{}/", server.local_addr().port());

    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let _ = std::process::Command::new("curl")
        .args([
            "-sk",
            "--http1.1",
            "-o",
            "/dev/null",
            "--max-time",
            "8",
            &url,
        ])
        .output();
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !seen.requests().is_empty(),
        "http/1.1 request never arrived"
    );
    assert!(seen.header("x-fp-ja4").is_some(), "TLS fingerprint missing");
    assert_eq!(seen.header("x-fp-h2").as_deref(), Some("none"));
}

/// An upstream that is down must yield 502, not a panic and not a hang.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_upstream_yields_502() {
    if !curl_available() {
        return;
    }
    // Port 1 on loopback: nothing is listening.
    let cfg = ServeConfig::new(
        "127.0.0.1:0".parse().expect("addr"),
        "127.0.0.1:1".parse().expect("addr"),
    );
    let server = Server::bind(cfg, ProfileDb::shipped().expect("db"))
        .await
        .expect("bind");
    let url = format!("https://127.0.0.1:{}/", server.local_addr().port());

    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let out = std::process::Command::new("curl")
        .args([
            "-sk",
            "--http2",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "8",
            &url,
        ])
        .output()
        .expect("curl");
    let code = String::from_utf8_lossy(&out.stdout);
    assert_eq!(code.trim(), "502", "expected 502, got {code}");
}

// --- admin socket, end to end -----------------------------------------------

#[cfg(unix)]
async fn next_frame(
    lines: &mut tokio::io::Lines<tokio::io::BufReader<tokio::net::UnixStream>>,
) -> serde_json::Value {
    let line = tokio::time::timeout(Duration::from_secs(8), lines.next_line())
        .await
        .expect("a frame within 8s")
        .expect("read")
        .expect("a line, not EOF");
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad json {line:?}: {e}"))
}

/// M6a's exit criterion. Real curl through a real `serve` must appear on the
/// admin socket carrying the committed JA4 oracle, which exercises the whole
/// chain from wire bytes to socket frame.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_connection_appears_on_the_admin_socket() {
    use tokio::io::AsyncBufReadExt;
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }

    let dir = tempfile::TempDir::new().expect("tempdir");
    let sock = dir.path().join("fpd.sock");
    let seen = Seen::default();
    let upstream = stub_upstream(seen.clone()).await;

    let mut cfg = ServeConfig::new("127.0.0.1:0".parse().expect("addr"), upstream);
    cfg.admin_socket = Some(sock.clone());
    let server = Server::bind(cfg, ProfileDb::shipped().expect("db"))
        .await
        .expect("serve bind");
    let url = format!("https://127.0.0.1:{}/", server.local_addr().port());
    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stream = tokio::net::UnixStream::connect(&sock)
        .await
        .expect("connect to the admin socket");
    let mut lines = tokio::io::BufReader::new(stream).lines();

    // Nothing has connected yet, so the snapshot is empty.
    assert_eq!(next_frame(&mut lines).await["type"], "snapshot_end");

    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sk", "--http2", "-o", "/dev/null", "--max-time", "8"])
        .arg(&url);
    let _ = cmd.output();

    let v = next_frame(&mut lines).await;
    assert_eq!(v["type"], "record");
    assert_eq!(v["ja4"], "t13i4906h2_0d8feac7bc37_7395dae3b2f3");
    assert_eq!(v["verdict"], "curl-8.7.1-macos");
    assert_eq!(v["mismatch"], false);
    assert!(
        !v["raw_hello"].as_str().unwrap_or_default().is_empty(),
        "the frame must carry the bytes"
    );
}

/// Without the flag there must be no socket at all. An observability endpoint
/// that appears by default is an exposure nobody asked for.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_admin_socket_exists_unless_the_flag_is_given() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sock = dir.path().join("fpd.sock");
    let upstream = stub_upstream(Seen::default()).await;

    let cfg = ServeConfig::new("127.0.0.1:0".parse().expect("addr"), upstream);
    assert!(cfg.admin_socket.is_none(), "default must be off");

    let server = Server::bind(cfg, ProfileDb::shipped().expect("db"))
        .await
        .expect("serve bind");
    tokio::spawn(server.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        !sock.exists(),
        "a socket was created without --admin-socket"
    );
}

/// HTTP/2 carries the target as `:scheme` plus `:authority` plus `:path`, and
/// hyper reassembles those into an absolute URL. An HTTP/1.1 origin server
/// expects origin-form and treats an absolute URL as a literal path, so
/// forwarding it unchanged makes every request 404 at the upstream.
///
/// Found by running the proxy against `python3 -m http.server`, not by any test
/// here, because the stub upstream recorded only headers. nginx tolerates the
/// absolute form, which is exactly why this is worth pinning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upstream_receives_an_origin_form_target_not_an_absolute_url() {
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }
    let seen = through_serve(&[]).await;
    assert_eq!(
        seen.header(":path").as_deref(),
        Some("/"),
        "an origin server reads an absolute URL as a filename and 404s"
    );
}

/// The same for HTTP/1.1, where the client already sends origin-form. Rewriting
/// must not corrupt what was already correct.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_http1_request_target_reaches_the_upstream_unchanged() {
    if !curl_available() {
        eprintln!("curl not available, skipping");
        return;
    }
    let seen = through_serve(&["--http1.1"]).await;
    assert_eq!(seen.header(":path").as_deref(), Some("/"));
}
