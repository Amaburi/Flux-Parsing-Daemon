//! The admin socket, a read-only view of recent connections over a Unix socket.
//!
//! Newline-delimited JSON, one object per line, server to client only. Chosen over
//! a binary format because it can be read with `nc -U` while debugging, and a
//! socket whose entire purpose is observability should be observable itself.
//!
//! The socket carries client addresses and fingerprints, so it is created mode
//! 0600. Design §691.

#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use tokio::io::{AsyncWriteExt, BufWriter};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::log::{ConnectionLog, ConnectionRecord};

/// How many records a slow client may fall behind before it starts missing them.
const BROADCAST_DEPTH: usize = 256;

/// Owns the history and the live channel together.
///
/// Both happen under one call so a record cannot land in one and not the other.
/// Broadcasting drops for receivers that are not keeping up rather than blocking
/// the sender, which is the property that keeps a stalled viewer from stalling the
/// proxy it is watching.
pub struct Publisher {
    log: Mutex<ConnectionLog>,
    tx: broadcast::Sender<ConnectionRecord>,
}

impl Publisher {
    pub fn new(capacity: usize) -> Arc<Self> {
        let (tx, _) = broadcast::channel(BROADCAST_DEPTH);
        Arc::new(Self {
            log: Mutex::new(ConnectionLog::with_capacity(capacity)),
            tx,
        })
    }

    /// Records one connection. Never blocks, and never fails the caller: a
    /// poisoned lock or an absent subscriber must not affect traffic being served.
    pub fn push(&self, record: ConnectionRecord) {
        let stored = match self.log.lock() {
            Ok(mut log) => {
                let seq = log.push(record.clone());
                let mut stored = record;
                stored.seq = seq;
                stored
            }
            Err(_) => return,
        };
        let _ = self.tx.send(stored);
    }

    pub fn snapshot(&self) -> Vec<ConnectionRecord> {
        self.log.lock().map(|l| l.snapshot()).unwrap_or_default()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ConnectionRecord> {
        self.tx.subscribe()
    }
}

#[cfg(unix)]
pub struct AdminSocket {
    listener: UnixListener,
    path: PathBuf,
    publisher: Arc<Publisher>,
}

#[cfg(unix)]
impl AdminSocket {
    /// Binds the socket and restricts it to the owning user.
    ///
    /// A stale socket left by a crashed process is removed first, because `bind`
    /// fails on an existing path and refusing to start after an unclean shutdown
    /// would be worse than replacing a file we created.
    pub fn bind(path: &Path, publisher: Arc<Publisher>) -> io::Result<Self> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = UnixListener::bind(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self {
            listener,
            path: path.to_path_buf(),
            publisher,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts viewers until the process ends. One task per client, so a slow one
    /// cannot hold up another.
    pub async fn serve(self) {
        loop {
            let Ok((stream, _)) = self.listener.accept().await else {
                continue;
            };
            let publisher = Arc::clone(&self.publisher);
            tokio::spawn(async move {
                let _ = handle_client(stream, publisher).await;
            });
        }
    }
}

#[cfg(unix)]
impl Drop for AdminSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Sends the buffered history, then everything that arrives afterwards.
///
/// Subscribing happens **before** the snapshot is taken, so a record arriving
/// between the two is delivered rather than lost. That can duplicate one record,
/// which is why anything already covered by the snapshot is skipped by sequence
/// number. Losing a record silently would be the worse failure.
#[cfg(unix)]
async fn handle_client(stream: UnixStream, publisher: Arc<Publisher>) -> io::Result<()> {
    let mut rx = publisher.subscribe();
    let snapshot = publisher.snapshot();
    let mut out = BufWriter::new(stream);

    let mut highest = None;
    for record in &snapshot {
        write_line(&mut out, &record_json(record)).await?;
        highest = Some(record.seq);
    }
    write_line(
        &mut out,
        &format!(
            "{{\"type\":\"snapshot_end\",\"seq\":{}}}",
            highest.unwrap_or(0)
        ),
    )
    .await?;
    out.flush().await?;

    loop {
        match rx.recv().await {
            Ok(record) => {
                if highest.is_some_and(|h| record.seq <= h) {
                    continue;
                }
                highest = Some(record.seq);
                write_line(&mut out, &record_json(&record)).await?;
                out.flush().await?;
            }
            // The client fell behind and records were dropped for it. Keep going,
            // since the gap is visible in `seq` and a viewer can report it.
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

#[cfg(unix)]
async fn write_line(out: &mut BufWriter<UnixStream>, line: &str) -> io::Result<()> {
    out.write_all(line.as_bytes()).await?;
    out.write_all(b"\n").await
}

fn span_json(s: &fingerprint_core::hello::Span) -> serde_json::Value {
    serde_json::json!({ "start": s.start, "len": s.len })
}

/// Millisecond epoch rather than a formatted timestamp, so no date library is
/// pulled in for one field. A viewer formats it.
fn epoch_ms(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn record_json(r: &ConnectionRecord) -> String {
    let per_ext: Vec<serde_json::Value> = r
        .provenance
        .per_extension
        .iter()
        .map(|(id, span)| serde_json::json!([id, span_json(span)]))
        .collect();

    serde_json::json!({
        "type": "record",
        "seq": r.seq,
        "at_ms": epoch_ms(r.at),
        "ip": r.ip,
        "ja4": r.ja4,
        "akamai": r.akamai,
        "verdict": r.verdict,
        "score": r.score,
        "mismatch": r.mismatch,
        "alpn": r.alpn,
        "raw_hello": base64(&r.raw_hello),
        "provenance": {
            "ciphers": span_json(&r.provenance.ciphers),
            "extensions": span_json(&r.provenance.extensions),
            "per_extension": per_ext,
        },
    })
    .to_string()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, RFC 4648 §4.
///
/// Written here rather than taken as a dependency, for one call site. The same
/// reasoning removed `fluke-hpack` in M3.
pub fn base64(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let (b0, b1, b2) = (
            *chunk.first().unwrap_or(&0),
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        );
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let idx = |shift: u32| usize::try_from((n >> shift) & 0x3f).unwrap_or(0);

        out.push(char::from(B64[idx(18)]));
        out.push(char::from(B64[idx(12)]));
        out.push(if chunk.len() > 1 {
            char::from(B64[idx(6)])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(B64[idx(0)])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10. These seven cover every padding case, which is the only part
    /// of base64 that is easy to get wrong.
    #[test]
    fn base64_matches_the_rfc_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), want, "input {input:?}");
        }
    }

    /// Bytes above 0x7f exercise the high bits of the 24-bit group, which ASCII
    /// vectors alone never reach.
    #[test]
    fn base64_handles_non_ascii_bytes() {
        assert_eq!(base64(&[0xff, 0xff, 0xff]), "////");
        assert_eq!(base64(&[0x00, 0x00, 0x00]), "AAAA");
        assert_eq!(base64(&[0xfb, 0xff, 0xbf]), "+/+/");
    }
}
