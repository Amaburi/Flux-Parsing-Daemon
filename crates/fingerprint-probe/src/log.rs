//! A bounded, in-memory history of recent connections.
//!
//! `serve` runs indefinitely in front of a production application, so this buffer
//! is bounded rather than growing. Nothing here is written to disk. The design
//! calls for the TUI to attach to a live instance and see recent traffic, and a
//! ring buffer is the whole of that mechanism.

use std::collections::VecDeque;
use std::time::SystemTime;

use fingerprint_core::ja4::Provenance;

use crate::probe::ClientReport;
use crate::verdict::Identification;

/// One connection, reduced to what a viewer needs.
///
/// Carries no header values. The `user-agent` claim reaches this only after
/// `verdict` has turned it into a family name, so a cookie or an authorization
/// value has no path into a record and therefore none onto the admin socket.
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    /// Assigned by [`ConnectionLog::push`], monotonic and never reset. A viewer
    /// compares it across a reconnect to tell "I missed records" from "the server
    /// restarted", which a timestamp cannot do reliably.
    pub seq: u64,
    pub at: SystemTime,
    /// Already rendered under the configured [`crate::serve::IpMode`], so a record
    /// cannot carry an address the operator chose to truncate or omit.
    pub ip: String,
    pub ja4: String,
    pub akamai: Option<String>,
    /// Profile label, or `unknown` when nothing scored above the match floor.
    pub verdict: String,
    pub score: f32,
    pub mismatch: bool,
    pub alpn: Option<String>,
    pub raw_hello: Vec<u8>,
    pub provenance: Provenance,
}

impl ConnectionRecord {
    /// `seq` is left at zero here and assigned by [`ConnectionLog::push`], which
    /// owns the counter.
    pub fn new(report: &ClientReport, id: &Identification, ip: String) -> Self {
        let (verdict, score) = match &id.best {
            Some(best) => (best.label.clone(), best.score),
            None => ("unknown".to_string(), 0.0),
        };

        Self {
            seq: 0,
            at: SystemTime::now(),
            ip,
            ja4: report.tls.ja4.clone(),
            akamai: report.h2.as_ref().map(|h| h.akamai.clone()),
            verdict,
            score,
            mismatch: id.mismatch.is_some(),
            alpn: report.alpn.clone(),
            raw_hello: report.raw_hello.clone(),
            provenance: report.tls.provenance.clone(),
        }
    }
}

/// A fixed-size window over the most recent connections.
pub struct ConnectionLog {
    records: VecDeque<ConnectionRecord>,
    capacity: usize,
    next_seq: u64,
}

impl ConnectionLog {
    /// Clamps to at least one. A zero-capacity buffer would either retain
    /// everything or evict every push depending on how the bound is written, and
    /// neither is a reasonable reading of the argument.
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            records: VecDeque::with_capacity(capacity),
            capacity,
            next_seq: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Assigns the next sequence number and evicts from the front if full.
    pub fn push(&mut self, mut record: ConnectionRecord) -> u64 {
        let seq = self.next_seq;
        record.seq = seq;
        self.next_seq += 1;

        self.records.push_back(record);
        while self.records.len() > self.capacity {
            self.records.pop_front();
        }
        seq
    }

    /// Oldest first, so a viewer appending to a list does not have to reverse it
    /// and `seq` increases down the returned slice.
    pub fn snapshot(&self) -> Vec<ConnectionRecord> {
        self.records.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileDb;
    use crate::verdict::identify;
    use fingerprint_core::ja4;
    use fingerprint_h2::akamai;

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

    /// The buffer is bounded because `serve` runs indefinitely in front of a
    /// production application. Unbounded growth here is an outage, not a leak.
    #[test]
    fn the_buffer_evicts_the_oldest_once_full() {
        let mut log = ConnectionLog::with_capacity(3);
        for i in 0..5 {
            log.push(record(&format!("10.0.0.{i}")));
        }
        let snap = log.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].ip, "10.0.0.2", "oldest two must have been evicted");
        assert_eq!(snap[2].ip, "10.0.0.4");
    }

    /// Oldest first, so a renderer appending to a list does not have to reverse
    /// it, and so `seq` increases down the returned slice.
    #[test]
    fn a_snapshot_is_ordered_oldest_first() {
        let mut log = ConnectionLog::with_capacity(8);
        for i in 0..4 {
            log.push(record(&format!("10.0.0.{i}")));
        }
        let snap = log.snapshot();
        assert!(snap.windows(2).all(|w| w[0].seq < w[1].seq));
    }

    /// Sequence numbers keep increasing across eviction. If they reset, a client
    /// cannot tell "I missed 200 records" from "the server restarted".
    #[test]
    fn sequence_numbers_survive_eviction() {
        let mut log = ConnectionLog::with_capacity(2);
        for i in 0..6 {
            log.push(record(&format!("10.0.0.{i}")));
        }
        assert_eq!(log.snapshot().last().expect("a record").seq, 5);
    }

    /// A capacity of zero would divide by zero or silently retain everything
    /// depending on the implementation. Neither is acceptable, so it is clamped.
    #[test]
    fn a_zero_capacity_is_clamped_rather_than_accepted() {
        let mut log = ConnectionLog::with_capacity(0);
        log.push(record("10.0.0.1"));
        assert!(log.capacity() >= 1);
        assert_eq!(log.len(), 1);
    }

    /// The privacy rule from M4b, restated where records are built. A record that
    /// carried a cookie value would leak it to every socket client.
    #[test]
    fn a_record_carries_no_header_value_other_than_the_user_agent_verdict() {
        let rec = record("10.0.0.1");
        let rendered = format!("{rec:?}").to_lowercase();
        assert!(!rendered.contains("cookie"));
        assert!(!rendered.contains("authorization"));
    }
}
