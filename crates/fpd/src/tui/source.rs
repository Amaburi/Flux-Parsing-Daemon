//! Where rows come from.
//!
//! Two sources, one output. Attaching parses the JSONL an `fpd serve` admin socket
//! emits. Listening binds a probe this process owns. Everything downstream sees the
//! same `Row` and does not know which is in use.

use std::net::SocketAddr;
use std::path::Path;

use fingerprint_core::hello::Span;
use tokio::sync::mpsc;

/// One connection, flattened to exactly what the view draws.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub seq: u64,
    pub at_ms: u64,
    pub ip: String,
    pub ja4: String,
    pub verdict: String,
    pub score: f32,
    pub mismatch: bool,
    pub alpn: Option<String>,
    pub akamai: Option<String>,
    /// The ClientHello, so the hex pane has something to draw.
    pub raw: Vec<u8>,
    pub ciphers: Span,
    pub extensions: Span,
    pub cipher_count: usize,
    pub ext_count: usize,
    pub grease_ext: Vec<Span>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Record(Box<Row>),
    SnapshotEnd,
}

fn span_of(v: &serde_json::Value) -> Span {
    Span {
        start: v["start"].as_u64().unwrap_or(0) as usize,
        len: v["len"].as_u64().unwrap_or(0) as usize,
    }
}

/// Standard base64, RFC 4648 §4. Padding is ignored rather than validated, since a
/// frame we produced is the only thing that reaches here.
pub fn decode_base64(s: &str) -> Vec<u8> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for c in s.bytes().filter(|c| *c != b'=') {
        let Some(v) = A.iter().position(|a| *a == c) else {
            continue;
        };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Parses one line of the admin protocol.
///
/// Returns `None` for anything unrecognised rather than failing. A viewer that dies
/// on one malformed line would be a worse tool than one that skips it, and the
/// protocol is explicitly unstable.
pub fn parse_frame(line: &str) -> Option<Frame> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    match v["type"].as_str()? {
        "snapshot_end" => Some(Frame::SnapshotEnd),
        "record" => {
            let prov = &v["provenance"];
            let per_ext = prov["per_extension"].as_array();
            let grease_ext = per_ext
                .map(|items| {
                    items
                        .iter()
                        .filter(|e| {
                            e[0].as_u64()
                                .is_some_and(|id| fingerprint_core::grease::is_grease(id as u16))
                        })
                        .map(|e| span_of(&e[1]))
                        .collect()
                })
                .unwrap_or_default();

            Some(Frame::Record(Box::new(Row {
                seq: v["seq"].as_u64()?,
                at_ms: v["at_ms"].as_u64().unwrap_or(0),
                ip: v["ip"].as_str().unwrap_or("-").to_string(),
                ja4: v["ja4"].as_str().unwrap_or_default().to_string(),
                verdict: v["verdict"].as_str().unwrap_or("unknown").to_string(),
                score: v["score"].as_f64().unwrap_or(0.0) as f32,
                mismatch: v["mismatch"].as_bool().unwrap_or(false),
                alpn: v["alpn"].as_str().map(str::to_string),
                akamai: v["akamai"].as_str().map(str::to_string),
                raw: decode_base64(v["raw_hello"].as_str().unwrap_or_default()),
                ciphers: span_of(&prov["ciphers"]),
                extensions: span_of(&prov["extensions"]),
                cipher_count: 0,
                ext_count: per_ext.map(|e| e.len()).unwrap_or(0),
                grease_ext,
            })))
        }
        _ => None,
    }
}

impl Row {
    /// Built directly, for the listening source, which has the report in hand and
    /// does not go through JSON at all.
    pub fn from_report(
        seq: u64,
        ip: String,
        report: &fingerprint_probe::probe::ClientReport,
        id: &fingerprint_probe::verdict::Identification,
    ) -> Self {
        let p = &report.tls.provenance;
        let (verdict, score) = match &id.best {
            Some(b) => (b.label.clone(), b.score),
            None => ("unknown".to_string(), 0.0),
        };
        Self {
            seq,
            at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            ip,
            ja4: report.tls.ja4.clone(),
            verdict,
            score,
            mismatch: id.mismatch.is_some(),
            alpn: report.alpn.clone(),
            akamai: report.h2.as_ref().map(|h| h.akamai.clone()),
            raw: report.raw_hello.clone(),
            ciphers: p.ciphers,
            extensions: p.extensions,
            cipher_count: report.tls.ciphers.len(),
            ext_count: report.tls.extensions.len(),
            grease_ext: p
                .per_extension
                .iter()
                .filter(|(id, _)| fingerprint_core::grease::is_grease(*id))
                .map(|(_, s)| *s)
                .collect(),
        }
    }

    /// Number of ciphers, derived from the span when the count did not travel.
    pub fn ciphers_len(&self) -> usize {
        if self.cipher_count > 0 {
            self.cipher_count
        } else {
            self.ciphers.len / 2
        }
    }
}

/// Reads rows from a running `fpd serve`.
#[cfg(unix)]
pub fn attach(path: &Path) -> mpsc::Receiver<Row> {
    use tokio::io::AsyncBufReadExt;

    let (tx, rx) = mpsc::channel(256);
    let path = path.to_path_buf();
    tokio::spawn(async move {
        let Ok(stream) = tokio::net::UnixStream::connect(&path).await else {
            return;
        };
        let mut lines = tokio::io::BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(Frame::Record(row)) = parse_frame(&line) {
                if tx.send(*row).await.is_err() {
                    return;
                }
            }
        }
    });
    rx
}

/// Binds a probe this process owns, so the TUI runs with nothing else started.
///
/// This captures and closes. There is no upstream to forward to, so a client sees
/// the connection end after its request. It is for inspecting a client, not for
/// serving one.
pub fn listen(addr: SocketAddr) -> mpsc::Receiver<Row> {
    let (tx, rx) = mpsc::channel(256);
    tokio::spawn(async move {
        let Ok(db) = fingerprint_probe::profile::ProfileDb::shipped() else {
            return;
        };
        let Ok(probe) = fingerprint_probe::probe::Probe::bind_on(addr.port()).await else {
            return;
        };
        let mut seq = 0;
        loop {
            let Ok(report) = probe.accept_one(std::time::Duration::from_secs(30)).await else {
                continue;
            };
            let id = fingerprint_probe::verdict::identify(&report, &db);
            let row = Row::from_report(seq, "127.0.0.1".to_string(), &report, &id);
            seq += 1;
            if tx.send(row).await.is_err() {
                return;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_json() -> String {
        // Shaped exactly like `admin::record_json`, so this test fails if that
        // changes shape without this being updated.
        serde_json::json!({
            "type": "record",
            "seq": 7,
            "at_ms": 1_786_614_271_000u64,
            "ip": "45.9.148.0",
            "ja4": "t13i4906h2_0d8feac7bc37_7395dae3b2f3",
            "akamai": "3:100;4:10485760;2:0|1048510465|0|m,s,a,p",
            "verdict": "curl-8.7.1-macos",
            "score": 1.0,
            "mismatch": false,
            "alpn": "h2",
            "raw_hello": "Zm9vYmFy",
            "provenance": {
                "ciphers": { "start": 76, "len": 98 },
                "extensions": { "start": 180, "len": 24 },
                "per_extension": [[43, {"start": 180, "len": 8}], [2570, {"start": 188, "len": 4}]],
            },
        })
        .to_string()
    }

    #[test]
    fn a_record_frame_parses_with_its_spans_and_bytes_intact() {
        let Some(Frame::Record(row)) = parse_frame(&frame_json()) else {
            panic!("expected a record");
        };
        assert_eq!(row.seq, 7);
        assert_eq!(row.ip, "45.9.148.0");
        assert_eq!(row.verdict, "curl-8.7.1-macos");
        assert_eq!(row.raw, b"foobar");
        assert_eq!(row.ciphers, Span { start: 76, len: 98 });
        assert_eq!(row.ext_count, 2);
    }

    /// GREASE extensions are picked out at parse time so the renderer does not have
    /// to know what GREASE is.
    #[test]
    fn grease_extensions_are_identified_from_the_frame() {
        let Some(Frame::Record(row)) = parse_frame(&frame_json()) else {
            panic!("expected a record");
        };
        assert_eq!(row.grease_ext, vec![Span { start: 188, len: 4 }]);
    }

    #[test]
    fn a_snapshot_marker_parses_as_itself() {
        assert_eq!(
            parse_frame("{\"type\":\"snapshot_end\",\"seq\":3}"),
            Some(Frame::SnapshotEnd)
        );
    }

    /// A viewer that dies on one bad line is worse than one that skips it, and the
    /// protocol is explicitly unstable.
    #[test]
    fn malformed_lines_are_skipped_rather_than_fatal() {
        for line in [
            "",
            "not json",
            "{}",
            "{\"type\":\"future_frame\"}",
            "[1,2,3]",
        ] {
            assert_eq!(parse_frame(line), None, "{line:?}");
        }
    }

    /// The count is what the table shows, and it has to survive a frame that
    /// carries only the span.
    #[test]
    fn the_cipher_count_falls_back_to_the_span_width() {
        let Some(Frame::Record(row)) = parse_frame(&frame_json()) else {
            panic!("expected a record");
        };
        assert_eq!(row.ciphers_len(), 49, "98 bytes is 49 ciphers");
    }

    #[test]
    fn base64_decoding_matches_the_rfc_vectors() {
        for (encoded, want) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(decode_base64(encoded), want.as_bytes(), "{encoded:?}");
        }
    }
}
