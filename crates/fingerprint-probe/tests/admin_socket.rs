//! Admin socket behaviour, driven over a real Unix socket on a temp path.
//!
//! Unix only, matching the module.
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;

use fingerprint_core::ja4;
use fingerprint_h2::akamai;
use fingerprint_probe::admin::{AdminSocket, Publisher};
use fingerprint_probe::log::ConnectionRecord;
use fingerprint_probe::probe::ClientReport;
use fingerprint_probe::profile::ProfileDb;
use fingerprint_probe::verdict::identify;

fn read(rel: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn record(ip: &str) -> ConnectionRecord {
    let raw = read("../fingerprint-core/tests/fixtures/chrome-macos.bin");
    let preamble = read("../fingerprint-h2/tests/fixtures/chrome-h2.bin");
    let report = ClientReport {
        tls: ja4::fingerprint(&raw).expect("tls"),
        raw_hello: raw,
        h2: akamai::fingerprint(&preamble).ok(),
        alpn: Some("h2".into()),
        handshake_failed: false,
    };
    let db = ProfileDb::shipped().expect("shipped profiles");
    let id = identify(&report, &db);
    ConnectionRecord::new(&report, &id, ip.to_string())
}

fn publisher_with(n: usize) -> Arc<Publisher> {
    let p = Publisher::new(1000);
    for i in 0..n {
        p.push(record(&format!("10.0.0.{i}")));
    }
    p
}

/// Binds on a temp path and drives `serve` in the background. The returned
/// TempDir must stay alive for the socket path to exist.
async fn spawn_admin(publisher: Arc<Publisher>) -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("fpd.sock");
    let sock = AdminSocket::bind(&path, publisher).expect("bind");
    tokio::spawn(sock.serve());
    (path, dir)
}

struct Lines {
    inner: tokio::io::Lines<BufReader<UnixStream>>,
}

impl Lines {
    /// Times out rather than hanging, so a stalled server fails the suite instead
    /// of wedging it.
    async fn next_json(&mut self) -> serde_json::Value {
        let line = tokio::time::timeout(Duration::from_secs(5), self.inner.next_line())
            .await
            .expect("a frame within 5s")
            .expect("read")
            .expect("a line, not EOF");
        serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad json {line:?}: {e}"))
    }
}

async fn connect_lines(path: &std::path::Path) -> Lines {
    let stream = UnixStream::connect(path).await.expect("connect");
    Lines {
        inner: BufReader::new(stream).lines(),
    }
}

fn decode_base64(s: &str) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = A.iter().position(|a| *a == c).expect("base64 alphabet") as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Design §691. The socket carries client addresses and fingerprints, so it must
/// not be readable by other local users. A security property, not a nicety.
#[tokio::test(flavor = "multi_thread")]
async fn the_socket_is_not_accessible_to_other_users() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("fpd.sock");
    let _sock = AdminSocket::bind(&path, publisher_with(0)).expect("bind");

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(
        mode & 0o077,
        0,
        "mode {mode:o} is group or world accessible"
    );
}

/// A viewer attaching to a long-running serve must see the recent past, not only
/// what happens after it connected.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_receives_the_buffered_history_then_a_snapshot_marker() {
    let (path, _dir) = spawn_admin(publisher_with(3)).await;
    let mut lines = connect_lines(&path).await;

    for i in 0..3 {
        let v = lines.next_json().await;
        assert_eq!(v["type"], "record", "frame {i}");
        assert_eq!(v["ip"], format!("10.0.0.{i}"));
    }
    let end = lines.next_json().await;
    assert_eq!(end["type"], "snapshot_end");
    assert_eq!(end["seq"], 2, "the marker names the last record sent");
}

/// Records pushed after the snapshot must reach an attached client live.
#[tokio::test(flavor = "multi_thread")]
async fn records_pushed_after_connect_are_streamed() {
    let publisher = publisher_with(1);
    let (path, _dir) = spawn_admin(Arc::clone(&publisher)).await;
    let mut lines = connect_lines(&path).await;

    while lines.next_json().await["type"] != "snapshot_end" {}

    publisher.push(record("203.0.113.9"));
    let v = lines.next_json().await;
    assert_eq!(v["type"], "record");
    assert_eq!(v["ip"], "203.0.113.9");
}

/// The frame must carry everything the byte-provenance view needs, or a viewer
/// would have to reach back into the process it is attached to, which it cannot.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_frame_carries_the_bytes_and_the_spans() {
    let (path, _dir) = spawn_admin(publisher_with(1)).await;
    let mut lines = connect_lines(&path).await;
    let v = lines.next_json().await;

    let raw = decode_base64(v["raw_hello"].as_str().expect("raw_hello"));
    let fp = ja4::fingerprint(&raw).expect("re-parse the transmitted bytes");
    assert_eq!(fp.ja4, v["ja4"].as_str().expect("ja4"));

    let start = v["provenance"]["ciphers"]["start"].as_u64().expect("start") as usize;
    let len = v["provenance"]["ciphers"]["len"].as_u64().expect("len") as usize;
    assert!(
        start + len <= raw.len(),
        "span outside the transmitted bytes"
    );

    let from_span: Vec<u16> = raw[start..start + len]
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();
    assert_eq!(from_span, fp.ciphers, "the span must survive the wire");
}

/// A fingerprinting sidecar must never break the site. A viewer that stops
/// reading, or is suspended with ctrl-Z, must not block the handler that is
/// proxying real traffic.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stops_reading_does_not_block_the_server() {
    let publisher = publisher_with(1);
    let (path, _dir) = spawn_admin(Arc::clone(&publisher)).await;
    let _stalled = UnixStream::connect(&path).await.expect("connect");

    // Far more than any socket buffer will hold, and nothing ever reads it.
    let pushed = tokio::time::timeout(Duration::from_secs(10), async {
        for i in 0..10_000 {
            publisher.push(record(&format!("10.0.0.{}", i % 255)));
        }
    })
    .await;
    assert!(
        pushed.is_ok(),
        "pushing records blocked on a stalled reader"
    );
}
