# fpd M6a, Provenance, Ring Buffer and Admin Socket

> Execute task-by-task. Every task ends at a hard stop for review and commit.

**Goal:** Make available, and observable over a socket, the three things the M6b TUI renders: which bytes produced each fingerprint field, a bounded history of recent connections, and a live feed of them.

**Architecture:** Byte spans are recorded during the existing ClientHello walk and carried on `TlsFingerprint`. `ClientReport` retains the ClientHello bytes those spans index into. `serve` keeps a bounded ring buffer of connection records and publishes them over a Unix domain socket as newline-delimited JSON. Every part of this is headless and testable without a terminal.

**Tech Stack:** Existing `fingerprint-core`, `fingerprint-probe`. Adds `serde_json` to the probe crate and `tokio::net::UnixListener`, both already in the dependency tree.

## Why the TUI is not in this plan

The chosen M6b design shows the actual ClientHello bytes with the fingerprint
relevant spans bracketed underneath, and annotates the JA4 string segment by
segment. That view needs two things the codebase does not currently have.

`RawHello` records values, not positions. `RawExt.body` borrows from the input, so
offsets are recoverable by pointer arithmetic, but a view built on that would break
silently the first time the parser gains a nested reader. Positions have to be
explicit.

`ClientReport` discards the raw bytes after parsing. A hex pane has nothing to
render without them.

Both are parser and data concerns rather than interface concerns, both are fully
testable with no terminal involved, and getting them wrong makes the TUI show
confidently incorrect byte ranges. They come first. M6b is then rendering only.

## Global Constraints

- MSRV is 1.88, verified in CI. Do not use anything newer.
- Every crate denies `clippy::unwrap_used`, `clippy::panic`, `clippy::expect_used`
  outside tests. No exceptions, and no `#[allow]` added to make code fit.
- Prose in committed files uses plain punctuation. No em-dashes, no semicolons in
  sentences. Semicolons that are data, such as the Akamai fingerprint format, stay.
- The terms gate covers the whole binary, so any new subcommand or flag inherits it.
  No new gate logic.
- No test may reach a network beyond loopback.
- The admin socket is Unix only and sits behind `#[cfg(unix)]`. A Windows build must
  still compile, with the flag reporting that it is unavailable rather than vanishing.
- Header values are never logged, with the documented `user-agent` exception. Cookie
  and authorization values never reach a record or a socket frame.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Stop at each task, print the command, wait.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/fingerprint-core/src/reader.rs` | Gains `position()`. Still the only module touching raw offsets. |
| `crates/fingerprint-core/src/hello.rs` | Records spans during the walk it already performs. |
| `crates/fingerprint-core/src/ja4.rs` | Carries spans onto `TlsFingerprint` as `Provenance`. |
| `crates/fingerprint-probe/src/probe.rs` | `ClientReport` retains the ClientHello bytes. |
| `crates/fingerprint-probe/src/log.rs` | New. `ConnectionRecord` and the bounded ring buffer. |
| `crates/fingerprint-probe/src/admin.rs` | New. Unix socket server and the JSONL protocol. |
| `crates/fingerprint-probe/src/serve.rs` | Records into the buffer, optionally publishes. |
| `crates/fpd/src/commands/serve.rs` | `--admin-socket <path>`. |

---

### Task 1: Byte spans in the ClientHello walk

**Files:**
- Modify: `crates/fingerprint-core/src/reader.rs`
- Modify: `crates/fingerprint-core/src/hello.rs`

**Interfaces:**
- Consumes: `Reader::take`, `Reader::u8`, `Reader::u16`, `Reader::u24`, all existing.
- Produces: `Span { start: usize, len: usize }`, `Reader::position() -> usize`,
  `RawHello.cipher_span: Span`, `RawHello.extensions_span: Span`, `RawExt.span: Span`.
  All spans are absolute offsets into the `raw` slice passed to `parse_hello`.

**Why absolute offsets are the hard part.** `parse_hello` builds three nested
`Reader`s over successive sub-slices, so a position taken from the innermost reader
is relative to the handshake body, not to `raw`. The base offset of each nesting
level has to be carried forward. Do not hardcode 5 and 9. Derive both from
`position()` so that a change to the record header cannot silently shift every span.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-core/src/hello.rs`, in the existing `mod tests`:

```rust
/// The span must independently reproduce the value the parser returned. An
/// off-by-one span still slices cleanly and still yields u16s, so comparing
/// against `h.ciphers` is what actually catches it.
#[test]
fn the_cipher_span_reproduces_the_parsed_cipher_list() {
    for name in ["curl-8.7.1-macos", "chrome-macos"] {
        let raw = fixture(name);
        let h = parse_hello(&raw).expect("parse");
        let bytes = &raw[h.cipher_span.start..h.cipher_span.start + h.cipher_span.len];
        let from_span: Vec<u16> = bytes
            .chunks_exact(2)
            .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
            .collect();
        assert_eq!(from_span, h.ciphers, "{name}");
    }
}

/// Each extension span covers the whole extension record, its 4-byte header plus
/// its body, so the TUI can highlight one extension as a unit.
#[test]
fn each_extension_span_covers_its_own_header_and_body() {
    let raw = fixture("chrome-macos");
    let h = parse_hello(&raw).expect("parse");
    assert!(!h.extensions.is_empty(), "precondition");

    for e in &h.extensions {
        let b = &raw[e.span.start..e.span.start + e.span.len];
        assert_eq!(b.len(), 4 + e.body.len(), "ext {} length", e.id);
        assert_eq!(
            u16::from_be_bytes([b[0], b[1]]),
            e.id,
            "ext {} must start with its own id",
            e.id
        );
        assert_eq!(&b[4..], e.body, "ext {} body", e.id);
    }
}

/// The extensions block span must contain every individual extension span, or a
/// renderer drawing the block bracket would draw it in the wrong place.
#[test]
fn the_extensions_span_contains_every_extension() {
    let raw = fixture("chrome-macos");
    let h = parse_hello(&raw).expect("parse");
    let block_end = h.extensions_span.start + h.extensions_span.len;

    for e in &h.extensions {
        assert!(e.span.start >= h.extensions_span.start, "ext {}", e.id);
        assert!(e.span.start + e.span.len <= block_end, "ext {}", e.id);
    }
}

/// Every span must be in bounds for the buffer it indexes. A span past the end
/// would panic a renderer that slices with it, and the renderer is the one place
/// that cannot afford a panic.
#[test]
fn every_span_is_in_bounds() {
    for name in ["curl-8.7.1-macos", "chrome-macos"] {
        let raw = fixture(name);
        let h = parse_hello(&raw).expect("parse");
        let mut spans = vec![h.cipher_span, h.extensions_span];
        spans.extend(h.extensions.iter().map(|e| e.span));
        for s in spans {
            assert!(
                s.start + s.len <= raw.len(),
                "{name}: span {s:?} exceeds {} bytes",
                raw.len()
            );
        }
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fingerprint-core hello`
Expected: FAIL, no field `cipher_span` on `RawHello`.

- [ ] **Step 3: Implement**

In `reader.rs`, add next to `remaining`:

```rust
/// Offset of the next unread byte, relative to the slice this reader was built
/// over. Callers combine it with the base offset of that slice to get an
/// absolute position.
pub fn position(&self) -> usize {
    self.pos
}
```

In `hello.rs`:

```rust
/// A byte range within the buffer passed to `parse_hello`, absolute rather than
/// relative to any nested reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub len: usize,
}
```

Add `pub span: Span` to `RawExt`, and `pub cipher_span: Span` plus
`pub extensions_span: Span` to `RawHello`. Then thread the bases through the walk:

```rust
let record_len = r.u16()? as usize;
// Base of the record body within `raw`, derived rather than assumed, so a change
// to the record header cannot silently shift every span below.
let record_base = r.position();
let record_body = r.take(record_len)?;

let mut h = Reader::new(record_body);
if h.u8()? != 0x01 {
    return Err(ParseError::NotClientHello);
}
let hs_len = h.u24()? as usize;
let hs_base = record_base + h.position();
let mut c = Reader::new(h.take(hs_len)?);
```

At the cipher list:

```rust
let cs_len = c.u16()? as usize;
if !cs_len.is_multiple_of(2) {
    return Err(ParseError::Malformed("cipher_suites length"));
}
let cipher_span = Span { start: hs_base + c.position(), len: cs_len };
let cs_bytes = c.take(cs_len)?;
```

At the extensions block, noting that each extension's span starts 4 bytes before
its body because `e.position()` has already advanced past the id and length:

```rust
let mut extensions = Vec::new();
let mut extensions_span = Span { start: hs_base + c.position(), len: 0 };
if c.remaining() >= 2 {
    let ext_total = c.u16()? as usize;
    let ext_base = hs_base + c.position();
    extensions_span = Span { start: ext_base, len: ext_total };
    let mut e = Reader::new(c.take(ext_total)?);
    while e.remaining() >= 4 {
        let start = ext_base + e.position();
        let id = e.u16()?;
        let len = e.u16()? as usize;
        let body = e.take(len)?;
        extensions.push(RawExt { id, body, span: Span { start, len: len + 4 } });
    }
}
```

Return the two new fields alongside the existing three.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p fingerprint-core`
Expected: PASS, including the pre-existing hello, ja3, ja4 and property tests.

- [ ] **Step 5: Confirm the tests have teeth**

Temporarily change `let cipher_span = Span { start: hs_base + c.position(), ... }`
to `start: hs_base + c.position() + 1`. Re-run.
Expected: `the_cipher_span_reproduces_the_parsed_cipher_list` FAILS. Revert.

A span test that passes under a deliberate off-by-one is testing nothing, and
off-by-one is the specific failure this whole task exists to prevent. Recall that
M0 S2 lost an afternoon to reading the frame stream id at bytes 4..8 instead of
5..9, a bug that was silent because everything else still parsed.

- [ ] **Step 6: STOP, commit**

```bash
git add crates/fingerprint-core/src/reader.rs crates/fingerprint-core/src/hello.rs
git commit -m "feat(core): record byte spans for cipher and extension blocks"
```

---

### Task 2: Provenance on the fingerprint

**Files:**
- Modify: `crates/fingerprint-core/src/ja4.rs`

**Interfaces:**
- Consumes: `Span`, `RawHello.cipher_span`, `RawHello.extensions_span`, `RawExt.span`
  from Task 1.
- Produces: `Provenance { ciphers: Span, extensions: Span, per_extension: Vec<(u16, Span)> }`
  and `TlsFingerprint.provenance: Provenance`.

`TlsFingerprint` has no `Serialize` derive and profiles serialize the separate
`TlsProfile` type, so this does not change any profile JSON on disk. Confirm that
remains true rather than assuming it.

- [ ] **Step 1: Write the failing tests**

In `ja4.rs`, in the existing `mod tests`:

```rust
/// Provenance has to survive the trip through `fingerprint`, which is the only
/// entry point the probe uses.
#[test]
fn the_fingerprint_carries_provenance_for_every_extension_it_reports() {
    let raw = fixture("chrome-macos");
    let fp = fingerprint(&raw).expect("fingerprint");

    assert_eq!(
        fp.provenance.per_extension.len(),
        fp.extensions.len(),
        "one span per reported extension"
    );
    for (id, _) in &fp.provenance.per_extension {
        assert!(fp.extensions.contains(id), "ext {id} has a span but is not reported");
    }
}

/// The spans must still index the same bytes after passing through `fingerprint`,
/// not just after `parse_hello`.
#[test]
fn provenance_spans_still_index_the_right_bytes_after_fingerprinting() {
    let raw = fixture("curl-8.7.1-macos");
    let fp = fingerprint(&raw).expect("fingerprint");
    let s = fp.provenance.ciphers;
    let from_span: Vec<u16> = raw[s.start..s.start + s.len]
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();
    assert_eq!(from_span, fp.ciphers);
}

/// GREASE positions are reported as indices into the cipher list. The renderer
/// needs to turn one into a byte range, so the arithmetic is pinned here rather
/// than left for the TUI to invent.
#[test]
fn a_grease_cipher_position_maps_to_a_two_byte_range_inside_the_cipher_span() {
    let raw = fixture("chrome-macos");
    let fp = fingerprint(&raw).expect("fingerprint");
    let pos = *fp
        .grease_cipher_positions
        .first()
        .expect("chrome sends a GREASE cipher");

    let start = fp.provenance.ciphers.start + pos * 2;
    let value = u16::from_be_bytes([raw[start], raw[start + 1]]);
    assert!(
        crate::grease::is_grease(value),
        "byte range for GREASE position {pos} held {value:#06x}"
    );
}
```

`crate::grease::is_grease` already exists. Do not add a second predicate.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fingerprint-core ja4`
Expected: FAIL, no field `provenance`.

- [ ] **Step 3: Implement**

```rust
/// Where in the ClientHello each fingerprinted field came from.
///
/// Offsets are absolute within the buffer passed to `fingerprint`, and
/// `ClientReport` retains that buffer so a renderer can slice with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub ciphers: Span,
    pub extensions: Span,
    pub per_extension: Vec<(u16, Span)>,
}
```

Add `pub provenance: Provenance` to `TlsFingerprint` and populate it in
`fingerprint` from the `RawHello` already being walked. `per_extension` is built by
mapping the parsed extensions to `(e.id, e.span)`, in wire order, before any
GREASE stripping, so that a GREASE extension still has a span.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p fingerprint-core`
Expected: PASS.

- [ ] **Step 5: Confirm profile JSON did not change**

Run: `cargo test --workspace`
Expected: PASS, in particular the profile round-trip tests in `fingerprint-probe`.
If any profile fixture now differs, `Provenance` has leaked into a serialized type.
Move it rather than regenerating the fixture.

- [ ] **Step 6: STOP, commit**

```bash
git add crates/fingerprint-core/src/ja4.rs
git commit -m "feat(core): carry byte provenance on TlsFingerprint"
```

---

### Task 3: The report retains the bytes

**Files:**
- Modify: `crates/fingerprint-probe/src/probe.rs`
- Modify: `crates/fingerprint-probe/src/serve.rs:195-203` (`build_report`)
- Modify: `crates/fingerprint-tower/src/acceptor.rs:134`
- Modify: `crates/fingerprint-probe/tests/diff_cases.rs:29`, `tests/verdict_cases.rs:25`

**Interfaces:**
- Produces: `ClientReport.raw_hello: Vec<u8>`, and `pub const MAX_RETAINED_HELLO: usize = 8 * 1024;`

`ClientReport` is constructed in five places and all five must be updated. Adding
the field without updating them is a compile error, not a silent gap, which is why
they are listed rather than guarded by a test.

**Why 8 KB and not the 64 KB recording cap.** `RecordingStream::DEFAULT_CAP` bounds
what is captured from the wire. This is a second, tighter bound on what is retained
per connection, because the ring buffer in Task 4 holds many reports at once. A real
ClientHello is a few hundred bytes to about 2 KB with a large session ticket, so
8 KB retains every genuine handshake in full while capping a hostile one.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-probe/tests/probe_live.rs`:

```rust
/// The strongest available check that the retained bytes are the right bytes:
/// re-fingerprinting them must produce the fingerprint we already reported. A
/// truncated or offset buffer cannot pass this.
#[tokio::test(flavor = "multi_thread")]
async fn the_retained_bytes_reproduce_the_reported_fingerprint() {
    let report = capture_curl(&["-sk", "--http2"]).await;
    assert!(!report.raw_hello.is_empty(), "bytes must be retained");

    let again = fingerprint_core::ja4::fingerprint(&report.raw_hello).expect("re-parse");
    assert_eq!(again.ja4, report.tls.ja4);
    assert_eq!(again.ja4_r, report.tls.ja4_r);
}

/// The provenance spans must index the retained buffer, not some other buffer.
/// This is the exact operation the TUI performs, asserted here so a renderer
/// panic becomes a test failure instead.
#[tokio::test(flavor = "multi_thread")]
async fn provenance_spans_index_the_retained_buffer() {
    let report = capture_curl(&["-sk", "--http2"]).await;
    let s = report.tls.provenance.ciphers;
    assert!(s.start + s.len <= report.raw_hello.len(), "span outside retained bytes");

    let from_span: Vec<u16> = report.raw_hello[s.start..s.start + s.len]
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();
    assert_eq!(from_span, report.tls.ciphers);
}
```

`crates/fingerprint-probe/src/probe.rs`, in a `mod tests`:

```rust
/// A hostile client can send a large ClientHello. Retention is bounded
/// independently of the wire capture cap, because the ring buffer holds many of
/// these at once.
#[test]
fn retention_is_capped() {
    let big = vec![0u8; MAX_RETAINED_HELLO * 4];
    assert_eq!(retain(&big).len(), MAX_RETAINED_HELLO);
}

/// The paired negative. A cap that always truncates would pass the test above
/// while corrupting every real handshake.
#[test]
fn a_normal_hello_is_retained_whole() {
    let normal = vec![0u8; 1500];
    assert_eq!(retain(&normal).len(), 1500);
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fingerprint-probe`
Expected: FAIL, no field `raw_hello`, no function `retain`.

- [ ] **Step 3: Implement**

In `probe.rs`:

```rust
/// Upper bound on ClientHello bytes retained per connection.
///
/// Separate from, and tighter than, `RecordingStream::DEFAULT_CAP`, which bounds
/// what is read from the wire. This bounds what is kept afterwards, and the ring
/// buffer holds many reports at once.
pub const MAX_RETAINED_HELLO: usize = 8 * 1024;

pub(crate) fn retain(raw: &[u8]) -> Vec<u8> {
    raw[..raw.len().min(MAX_RETAINED_HELLO)].to_vec()
}
```

Add `pub raw_hello: Vec<u8>` to `ClientReport` and populate it with `retain(raw)`
at all five construction sites. In the two test helpers, populate it from the
fixture bytes already being read, not with `Vec::new()`, so the fixture-driven
tests exercise the same shape as live capture.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: STOP, commit**

```bash
git add crates/fingerprint-probe/src/probe.rs crates/fingerprint-probe/src/serve.rs \
        crates/fingerprint-tower/src/acceptor.rs crates/fingerprint-probe/tests/
git commit -m "feat(probe): retain the ClientHello bytes the spans index"
```

---

### Task 4: The connection ring buffer

**Files:**
- Create: `crates/fingerprint-probe/src/log.rs`
- Modify: `crates/fingerprint-probe/src/lib.rs` (add `pub mod log;`)

**Interfaces:**
- Consumes: `ClientReport`, `Identification` from `verdict.rs`, `render_ip` and
  `IpMode` from `serve.rs`.
- Produces:
  - `ConnectionRecord { seq: u64, at: SystemTime, ip: String, ja4: String, akamai: Option<String>, verdict: String, score: f32, mismatch: bool, alpn: Option<String>, raw_hello: Vec<u8>, provenance: Provenance }`
  - `ConnectionLog::with_capacity(n: usize) -> Self`
  - `ConnectionLog::push(&mut self, rec: ConnectionRecord)`
  - `ConnectionLog::snapshot(&self) -> Vec<ConnectionRecord>` (oldest first)
  - `ConnectionLog::len(&self)`, `ConnectionLog::capacity(&self)`

`seq` is a monotonic counter assigned on push. The TUI uses it to detect that it
missed records after a reconnect, which a timestamp cannot tell it reliably.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-probe/src/log.rs`, in `mod tests`:

```rust
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

/// Oldest first, so a renderer appending to a list does not have to reverse it,
/// and so `seq` increases down the returned slice.
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
    let rendered = format!("{rec:?}");
    assert!(!rendered.to_lowercase().contains("cookie"));
    assert!(!rendered.to_lowercase().contains("authorization"));
}
```

Write a `fn record(ip: &str) -> ConnectionRecord` helper in the test module that
builds one from the `chrome-macos` fixture, mirroring the `report` helper in
`tests/diff_cases.rs`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fingerprint-probe log`
Expected: FAIL, unresolved module `log`.

- [ ] **Step 3: Implement**

Back the buffer with `std::collections::VecDeque`. `with_capacity` clamps to at
least 1. `push` assigns `seq` from a counter that is never reset, then pops the
front while `len() > capacity`.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p fingerprint-probe log`
Expected: PASS, 5 tests.

- [ ] **Step 5: STOP, commit**

```bash
git add crates/fingerprint-probe/src/log.rs crates/fingerprint-probe/src/lib.rs
git commit -m "feat(probe): bounded ring buffer of connection records"
```

---

### Task 5: The admin socket

**Files:**
- Create: `crates/fingerprint-probe/src/admin.rs`
- Modify: `crates/fingerprint-probe/src/lib.rs` (add `#[cfg(unix)] pub mod admin;`)
- Modify: `crates/fingerprint-probe/Cargo.toml`

**Dependencies, already checked against the manifest.** `serde_json` 1.0.151 and
`tempfile` 3.27.0 are already dependencies of this crate, so do not add them.
`tokio` currently enables `net`, `io-util`, `rt`, `rt-multi-thread`, `macros` and
`time`, but **not `sync`**, which `tokio::sync::broadcast` requires. Add exactly
that one feature. `base64` is not in the tree, which is why the encoder below is
written by hand rather than pulled in for one call site.

**Interfaces:**
- Consumes: `ConnectionLog`, `ConnectionRecord` from Task 4.
- Produces: `AdminSocket::bind(path: &Path, log: Arc<Mutex<ConnectionLog>>) -> std::io::Result<AdminSocket>`,
  `AdminSocket::serve(self) -> impl Future<Output = ()>`, `AdminSocket::path(&self) -> &Path`.

**Protocol.** Newline-delimited JSON, one object per line, server to client only.
On connect the server writes every buffered record as a `record` frame, oldest
first, then a `snapshot_end` frame, then streams new records as they arrive. Chosen
over a binary format because it is inspectable with `nc` while debugging, which
matters for a socket whose whole purpose is observability.

```json
{"type":"record","seq":41,"at":"2026-08-12T12:04:31Z","ip":"45.9.148.99","ja4":"t13d3112h2_...","verdict":"python-requests","score":0.94,"mismatch":true,"alpn":"h2","raw_hello":"FgMBAgAB...","provenance":{"ciphers":{"start":50,"len":62},"extensions":{"start":116,"len":24},"per_extension":[[11,{"start":116,"len":8}]]}}
{"type":"snapshot_end","seq":41}
```

`raw_hello` is base64 because JSON has no byte string. Write a small standard
base64 encoder in `admin.rs` and unit test it against the RFC 4648 vectors
(`""`, `"f"`, `"fo"`, `"foo"`, `"foob"`, `"fooba"`, `"foobar"` encoding to `""`,
`"Zg=="`, `"Zm8="`, `"Zm9v"`, `"Zm9vYg=="`, `"Zm9vYmE="`, `"Zm9vYmFy"`), which
covers every padding case. A dependency for one call site is not worth the supply
chain, and the same reasoning already removed `fluke-hpack` in M3.

**Security.** Design §691 requires restrictive permissions. Create the socket with
mode `0o600` and verify it, because a socket carrying client IPs and fingerprints
readable by every local user would be worse than not shipping the feature.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-probe/tests/admin_socket.rs`:

```rust
/// Design §691. The socket carries client IPs and fingerprints, so it must not be
/// readable by other local users. This is a security property, not a nicety.
#[tokio::test(flavor = "multi_thread")]
async fn the_socket_is_not_accessible_to_other_users() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("fpd.sock");
    let _sock = AdminSocket::bind(&path, log_with(3)).expect("bind");

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(mode & 0o077, 0, "mode {mode:o} is group or world accessible");
}

/// A client attaching to a long-running serve must see the recent past, not only
/// what happens after it connected.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_receives_the_buffered_history_then_a_snapshot_marker() {
    let (path, _guard) = spawn_admin(log_with(3)).await;
    let mut lines = connect_lines(&path).await;

    for _ in 0..3 {
        let v = lines.next_json().await;
        assert_eq!(v["type"], "record");
    }
    assert_eq!(lines.next_json().await["type"], "snapshot_end");
}

/// Records pushed after the snapshot must reach an attached client live.
#[tokio::test(flavor = "multi_thread")]
async fn records_pushed_after_connect_are_streamed() {
    let log = log_with(1);
    let (path, _guard) = spawn_admin(log.clone()).await;
    let mut lines = connect_lines(&path).await;

    while lines.next_json().await["type"] != "snapshot_end" {}

    log.lock().expect("lock").push(record("203.0.113.9"));
    let v = lines.next_json().await;
    assert_eq!(v["type"], "record");
    assert_eq!(v["ip"], "203.0.113.9");
}

/// The frame must carry everything the byte-provenance view needs, or the TUI has
/// to reach back into the process it is attached to, which it cannot do.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_frame_carries_the_bytes_and_the_spans() {
    let (path, _guard) = spawn_admin(log_with(1)).await;
    let mut lines = connect_lines(&path).await;
    let v = lines.next_json().await;

    let raw = decode_base64(v["raw_hello"].as_str().expect("raw_hello"));
    let fp = fingerprint_core::ja4::fingerprint(&raw).expect("re-parse");
    assert_eq!(fp.ja4, v["ja4"].as_str().expect("ja4"));

    let start = v["provenance"]["ciphers"]["start"].as_u64().expect("start") as usize;
    let len = v["provenance"]["ciphers"]["len"].as_u64().expect("len") as usize;
    assert!(start + len <= raw.len(), "span outside the transmitted bytes");
}

/// A fingerprinting sidecar must never break the site. A TUI that stops reading,
/// or is suspended with ctrl-Z, must not block the connection handler that is
/// proxying real traffic.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_stops_reading_does_not_block_the_server() {
    let log = log_with(1);
    let (path, _guard) = spawn_admin(log.clone()).await;
    let _stalled = tokio::net::UnixStream::connect(&path).await.expect("connect");

    // Push far more than any socket buffer will hold, without ever reading.
    let pushed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for i in 0..10_000 {
            log.lock().expect("lock").push(record(&format!("10.0.0.{}", i % 255)));
        }
    })
    .await;
    assert!(pushed.is_ok(), "pushing records blocked on a stalled reader");
}
```

Write `log_with(n)`, `spawn_admin`, `connect_lines` and `decode_base64` as helpers
in the same file. `connect_lines` returns a wrapper over `BufReader::lines` with a
`next_json` method that parses one line, with a timeout so a hang fails rather
than stalling the suite.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p fingerprint-probe --test admin_socket`
Expected: FAIL, unresolved `AdminSocket`.

- [ ] **Step 3: Implement**

Bind with `tokio::net::UnixListener::bind`. Immediately
`std::fs::set_permissions(path, Permissions::from_mode(0o600))`. Unlink any stale
socket at the path first, since `bind` fails on an existing file, and a crashed
`serve` leaves one behind.

Broadcast to clients with `tokio::sync::broadcast`, which drops for slow receivers
rather than blocking the sender. That is what makes the stalled-reader test pass,
and it is the correct trade: a TUI missing records is acceptable, a stalled proxy
is not. Each client task writes the snapshot from the log under its lock, then
subscribes and forwards. Subscribe **before** taking the snapshot so a record
arriving between the two is not lost.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p fingerprint-probe --test admin_socket`
Expected: PASS, 5 tests.

- [ ] **Step 5: STOP, commit**

```bash
git add crates/fingerprint-probe/src/admin.rs crates/fingerprint-probe/src/lib.rs \
        crates/fingerprint-probe/Cargo.toml crates/fingerprint-probe/tests/admin_socket.rs
git commit -m "feat(probe): admin socket publishing connection records as JSONL"
```

---

### Task 6: Wire it into serve, and document it

**Files:**
- Modify: `crates/fingerprint-probe/src/serve.rs`
- Modify: `crates/fpd/src/commands/serve.rs`
- Modify: `crates/fpd/src/cli.rs`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything from Tasks 4 and 5.
- Produces: `ServeConfig.admin_socket: Option<PathBuf>`, `ServeConfig.log_capacity: usize`,
  and the `fpd serve --admin-socket <path>` flag.

- [ ] **Step 1: Write the failing test**

`crates/fingerprint-probe/tests/serve_live.rs`:

```rust
/// The milestone's exit criterion. Real curl through a real serve must appear on
/// the admin socket with the committed JA4 oracle, which proves the whole chain
/// from wire bytes to socket frame.
#[tokio::test(flavor = "multi_thread")]
async fn a_real_connection_appears_on_the_admin_socket() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sock = dir.path().join("fpd.sock");
    let (addr, _upstream) = start_stub_upstream().await;
    let server = start_serve_with_admin(addr, &sock).await;

    let mut lines = connect_lines(&sock).await;
    while lines.next_json().await["type"] != "snapshot_end" {}

    run_curl(&["-sk", "--http2", &server.url()]).await;

    let v = lines.next_json().await;
    assert_eq!(v["type"], "record");
    assert_eq!(v["ja4"], "t13i4906h2_0d8feac7bc37_7395dae3b2f3");
    assert_eq!(v["verdict"], "curl-8.7.1-macos");
}

/// Without the flag there must be no socket at all. An observability endpoint
/// that appears by default is an exposure someone did not ask for.
#[tokio::test(flavor = "multi_thread")]
async fn no_admin_socket_exists_unless_the_flag_is_given() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let sock = dir.path().join("fpd.sock");
    let (addr, _upstream) = start_stub_upstream().await;
    let _server = start_serve_without_admin(addr).await;

    run_curl(&["-sk", "--http2", "https://127.0.0.1:0/"]).await;
    assert!(!sock.exists(), "a socket was created without --admin-socket");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-probe --test serve_live`
Expected: FAIL, no field `admin_socket`.

- [ ] **Step 3: Implement**

Add both fields to `ServeConfig`, defaulting `admin_socket` to `None` and
`log_capacity` to 1000. The connection handler pushes a `ConnectionRecord` after
building the report and identification it already computes. Push unconditionally,
since the ring buffer is what `--admin-socket` publishes rather than what it
populates, so attaching a TUI to a running instance shows recent history.

Add `--admin-socket <PATH>` to the clap definition for `serve`. On a non-Unix
target the flag parses and reports that the admin socket is Unix only, rather than
not existing, so a script is not silently ignored.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: README**

Document `--admin-socket` under `fpd serve`, state the 0600 permission and what the
socket exposes, and state plainly that the buffer is in memory and bounded and that
nothing is persisted. Add a `nc -U` example, since a protocol described as
inspectable should be shown being inspected.

Do not describe the TUI. It does not exist yet, and the status table must keep
saying so.

- [ ] **Step 6: STOP, commit**

```bash
git add crates/fingerprint-probe/src/serve.rs crates/fpd/src/commands/serve.rs \
        crates/fpd/src/cli.rs crates/fingerprint-probe/tests/serve_live.rs README.md
git commit -m "feat(serve): optional admin socket and connection history"
```

---

## Visual specification, for M6b

Recorded now, while the direction is settled, so M6b implements a decision rather
than making one. M6b builds the interface. This section is what it builds.

### The chosen view

A live table on top, and below it the selected connection's ClientHello bytes with
the fingerprint relevant bytes brought forward and the inert ones pushed back, plus
the JA4 string annotated segment by segment. The spans come from `Provenance`, the
bytes from `raw_hello`.

### One ink

**The entire interface is a single colour: the terminal's own default foreground.**
No hues are assigned to anything. Hierarchy comes from weight and inversion, the
way it does in print, where one ink and three weights carry an entire newspaper.

| Level | Rendered as | Used for |
|---|---|---|
| Recede | dim | Chrome, labels, column headers, and bytes that do not feed the fingerprint |
| Normal | default | The data itself |
| Advance | bold | The field currently in focus |
| Demand | reverse video | The selected row, and a mismatch |

That is the whole system. There is no palette to get wrong because there is no
palette.

**Reverse video, not red, for a mismatch.** Inversion is louder than any hue while
staying in one tone, it survives every terminal theme, and it cannot clash with the
user's background. A red alert in an otherwise monochrome interface is the single
detail that would make this look assembled from a template.

Do not paint a background colour anywhere. Inherit the terminal's, the way `htop`
and `vim` do. A tool that repaints the background fights every theme its user
already chose.

**Consequences that follow for free.** It is identical under `NO_COLOR`, because
there was never colour to remove. It is unaffected by colour vision deficiency. It
looks correct on a light terminal and a dark one without a second code path. Those
are not features that were added. They are what is left when nothing is decorated.

### Provenance is shown by contrast, not by colour

This is the one idea the view rests on, so it is worth stating exactly.

In the hex pane, bytes that feed the fingerprint render at normal weight. Bytes
that do not, the random field and the session id, render dim and as `··` rather
than their value. The fingerprint's own shape then appears in the hex dump as
areas of contrast, with no hue and no bracket art required. Labels sit in the right
margin on the row where each span begins.

Bracketing every span with box-drawing runs underneath, which the first mockup did,
is the terminal equivalent of wrapping every division in a rounded card. It adds
strokes without adding information. The contrast already says it.

### What is banned, explicitly

These are the tells. None of them appear.

- No ASCII art banner, no figlet logo, no splash on startup.
- No emoji, anywhere, including in the status line and in log output.
- No rounded corners, and no box drawn around a region that whitespace can separate.
- No gradients, and no second hue for any reason.
- No spinner or progress animation for work that finishes instantly.
- No powerline separators or chevron dividers.
- No centred text and no decorative padding. Terminal layouts are dense and
  left aligned, and that density is the aesthetic rather than a compromise.
- No shouting. Labels are sentence case, not `=== SECTION ===`.

### Structure

No outer frame. A small left margin, thin dim horizontal rules between the three
zones, and strict column alignment doing the work a border would otherwise do.

```
  fpd   :8443                        1,284 conn   3 alerts   12:04:31

  12:04:31   103.28.14.2    t13d1516h2_8daaf6…   chrome-131-win
  12:04:31   45.9.148.99    t13d3112h2_e8f1e7…   python-requests    ✗
  12:04:29   198.51.100.7   t13d1715h2_5b5761…   firefox-133
  ──────────────────────────────────────────────────────────────────
  45.9.148.99                                  python-requests  94%

  clienthello   517 bytes

  0030   ·· ·· ·· ·· ·· ·· ·· ··   00 3e 13 02 13 03 c0 2b
  0040   c0 2f cc a9 cc a8 c0 0a   c0 09 00 9c 00 9d 00 2f   ciphers 31
  0050   00 35 ·· ·· 00 0a 00 0b   00 0d 00 10 00 17 ff 01   extensions 12

  ja4    t13d3112h2_e8f1e7e78f70_6bebaf5329ac
         tls 1.3, sni, alpn h2    31 ciphers, 12 ext    ext and sigalgs

  claims chrome 131, fingerprint says python-requests
  ──────────────────────────────────────────────────────────────────
  /  search       f  follow       e  export       q  quit
```

In that sketch the `··` bytes are dim, the hex values are normal weight, the row
for 45.9.148.99 and the mismatch line are reverse video, and every label is dim.
Nothing else is styled.

### Layout is responsive, with stated breakpoints

| Width | Layout |
|---|---|
| 100 columns or more | Full, 16 bytes per hex row |
| 72 to 99 | 8 bytes per hex row |
| Below 72 | Hex pane hidden, decoded fields only |
| Below 40 | Table only, one column of JA4 |

| Height | Layout |
|---|---|
| 20 rows or more | Full detail pane |
| Below 20 | Detail collapses to three lines, JA4 and the alert |

A TUI that corrupts its own frame below some width is not finished. Test the
narrow cases rather than assuming a wide terminal.

### Redraw only on change

Keep the last rendered state and skip the draw when nothing changed. Under a busy
`serve` the socket can deliver records faster than a terminal can usefully repaint,
so cap the repaint rate at about 30 per second and coalesce anything arriving in
between. A TUI that pegs a core to redraw identical frames is a bug.

---

## Self-Review

**Spec coverage.** §6.7's admin socket over a Unix domain socket maps to Task 5.
§6.7's bounded ring buffer that never persists traffic maps to Task 4 and Task 6.
§691's restrictive socket permissions maps to Task 5 Step 1. The byte provenance
the chosen view rests on is Tasks 1 to 3, which the spec did not anticipate because
it predates the visual direction. `fpd tui` itself is deliberately M6b.

**Deliberately excluded.** The TUI, its rendering and its key handling. The
standalone `fpd tui --listen` mode, which is M6b since it is a second source behind
the same interface. HTTP/3, per §3.

**Known risks.**

1. **Spans are only as correct as the fixtures exercise.** Two fixtures, curl and
   Chrome, both TLS 1.3. A TLS 1.2 ClientHello with no extensions block takes the
   `c.remaining() >= 2` false branch, where `extensions_span` has length zero. That
   path is real and the renderer must handle a zero-length span, so M6b should not
   assume every span is non-empty.

2. **The ring buffer holds retained bytes.** 1000 records at up to 8 KB each is a
   worst case of about 8 MB, and a realistic case of about 1.5 MB. That is
   acceptable for a sidecar but it is not free, and the capacity should be
   configurable before anyone runs it with a much larger buffer.

3. **`broadcast` drops for slow receivers.** That is the correct trade and it is
   what keeps a stalled TUI from blocking the proxy, but it means a client can
   silently miss records. The `seq` field exists so the TUI can detect the gap and
   say so rather than showing a quietly incomplete list. M6b must actually use it.

4. **JSONL is not a stable public API.** It is inspectable, which is why it was
   chosen, but shipping it invites people to script against it. The README should
   say it is unstable, or the first external consumer will freeze it.
