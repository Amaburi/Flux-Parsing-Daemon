# fpd M3a — `fingerprint-h2`: Frame Walk, HPACK, and the Akamai Fingerprint

> Execute task-by-task, in order. Steps use checkbox (`- [ ]`) syntax. Every task ends at a hard stop for review and commit — see the Commit Protocol.

**Goal:** Turn the decrypted HTTP/2 connection preamble into an `H2Fingerprint` carrying the Akamai fingerprint string, with every component validated against tshark and the parser hardened against malformed input.

**Architecture:** A new crate `crates/fingerprint-h2`, pure functions over `&[u8]`, mirroring `fingerprint-core`. Byte fixtures of the **decrypted** preamble drive every test. `Reader` is reused from `fingerprint-core` rather than duplicated.

**Tech Stack:** Rust 2021, `fingerprint-core` (for `Reader`), an HPACK decoder crate. Dev: `proptest`, `cargo-fuzz`.

## Global Constraints

- Same lint posture as `fingerprint-core`: `#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used, clippy::indexing_slicing)]`.
- No socket, clock, or randomness in any test. Fixtures only.
- Dependency versions via `cargo add`, never hand-written.
- Fixtures committed as `.bin` with a `.md` sidecar carrying the tshark oracle values.
- **Absence is signal.** `settings` is an ordered `Vec<(u16, u32)>` of what was literally on the wire. Never a map, never defaulted, never sorted — M0 S2 finding 2 measured curl sending `3,4,2` out of ascending order.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Every task ends at a STOP:
confirm tests pass, print the suggested commit command, wait. Inert git commands are fine.

---

## Scope decisions made before writing this plan

**JA4H is deliberately excluded.** Two independent reasons, either sufficient:

1. The JA4H specification could not be retrieved in full. Only one rule was confirmed:
   the segment-a header count is *"2 digit number of headers, not counting Cookie and
   Referer"*, capped at 99.
2. **tshark has no JA4H field at all** — `tshark -G fields | grep ja4` yields only
   `tls.handshake.ja4`, `tls.handshake.ja4_r` and the DTLS equivalents. There is no
   local oracle.

Implementing a fingerprint standard from an incomplete spec with no way to verify the
result is the worst available outcome: authoritative-looking and quietly wrong. JA4H
gets its own slot once the spec is obtained in full and an oracle exists (FoxIO's
reference implementation, or a newer Wireshark).

**The Akamai HTTP/2 fingerprint proceeds**, because its oracle is strong — see below.

## The oracle, verified before this plan was written

tshark dissects the decrypted preamble when it is wrapped by `scripts/bin2pcap.py` and
the HTTP/2 dissector is forced onto the port:

```bash
python3 scripts/bin2pcap.py <fixture>.bin /tmp/h2.pcap
tshark -r /tmp/h2.pcap -d tcp.port==443,http2 \
  -T fields -e http2.settings.id \
             -e http2.settings.max_concurrent_streams \
             -e http2.settings.initial_window_size \
             -e http2.settings.enable_push \
             -e http2.window_update.window_size_increment \
             -e http2.header.name
```

Confirmed working against a live curl 8.7.1 capture:

```
http2.settings.id                 3,4,2          ← wire order preserved
max_concurrent_streams            100
initial_window_size               10485760
enable_push                       0
window_update.window_size_increment  1048510465
http2.header.name                 :method,:scheme,:authority,:path,user-agent,accept
```

**tshark decodes HPACK independently.** That is the hardest part of this milestone and
the part most likely to be silently wrong, so having it externally validated is the
single most valuable property of this plan. The final Akamai string assembly is plain
concatenation of already-validated components and is checkable by eye.

---

## File Structure

```
crates/fingerprint-h2/
├── Cargo.toml
├── src/
│   ├── lib.rs          # H2Fingerprint, H2Error
│   ├── frame.rs        # preface + frame header walk
│   ├── settings.rs     # SETTINGS / WINDOW_UPDATE / PRIORITY extraction
│   ├── headers.rs      # HPACK decode → ordered header names
│   └── akamai.rs       # fingerprint string composition
├── tests/
│   ├── fixtures/
│   │   ├── curl-8.7.1-h2.bin  + .md
│   │   └── chrome-h2.bin      + .md
│   └── properties.rs
└── fuzz/fuzz_targets/parse_preamble.rs
```

**Boundaries.** `frame.rs` knows the 9-byte header layout and nothing about payloads.
`settings.rs` and `headers.rs` each interpret one payload kind. `akamai.rs` consumes
parsed structs and never sees bytes. A fuzz finding in `frame.rs` therefore cannot
silently alter a fingerprint.

---

### Task 1: Capture decrypted HTTP/2 preamble fixtures

The M0 S2 spike printed parsed output, not bytes — the same gap M2 Task 1 had to close.
A dumper already exists at `spikes/s2-h2-replay/src/bin/dump_h2.rs`, written and proven
during planning; it captures preface + frames through the first HEADERS frame.

Note these bytes only exist **after** TLS termination, so unlike the TLS fixtures they
cannot be obtained with `tcpdump`.

- [ ] **Step 1: Capture curl**

```bash
mkdir -p crates/fingerprint-h2/tests/fixtures
FPD_FIXTURE_LABEL=curl-8.7.1-h2 \
FPD_FIXTURE_DIR=crates/fingerprint-h2/tests/fixtures \
  ./spikes/s2-h2-replay/target/debug/dump_h2 &
sleep 2 && curl -sk --http2 https://127.0.0.1:8444/ --max-time 4 -o /dev/null
```

Expected: `wrote … (103 bytes)`, beginning `50 52 49 20 2a` (`PRI *`).

- [ ] **Step 2: Capture Chrome — requires a human**

Restart the dumper with `FPD_FIXTURE_LABEL=chrome-h2`, open `https://127.0.0.1:8444/`
in Chrome, accept the certificate warning. Chrome's SETTINGS differ materially from
curl's — per spec §6.1 it sends no id 3 at all, which is the contrast the whole
fingerprint rests on. **Do not skip this**; a curl-only fixture set cannot demonstrate
the discriminating case.

- [ ] **Step 3: Record oracle values in sidecars**

For each fixture write a `.md` recording client, date, byte length, and the full tshark
output from the oracle command above. These become the expected values in Task 5.

- [ ] **Step 4: STOP — hand off for commit**

```bash
git add spikes/s2-h2-replay/src/bin/dump_h2.rs crates/fingerprint-h2/tests/fixtures/
git commit -m "test(h2): capture decrypted HTTP/2 preamble fixtures with tshark oracle"
```

---

### Task 2: Crate skeleton and the frame walk

**Files:** `crates/fingerprint-h2/Cargo.toml`, `src/lib.rs`, `src/frame.rs`

**Interfaces:**
- Consumes: `fingerprint_core::reader::{Reader, ParseError}`.
- Produces: `Frame { kind: u8, flags: u8, stream_id: u32, payload: &[u8] }`, `parse_preamble(&[u8]) -> Result<Vec<Frame<'_>>, H2Error>`, `H2Error`.

- [ ] **Step 1: Create the crate**

```bash
cargo new --lib --vcs none crates/fingerprint-h2
# cargo new appends a duplicate workspace member line; remove it (M1 Task 1, M2 Task 2)
cd crates/fingerprint-h2
cargo add --path ../fingerprint-core
cargo add thiserror
cargo add --dev proptest
```

- [ ] **Step 2: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures").join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    #[test]
    fn rejects_input_without_the_connection_preface() {
        assert!(parse_preamble(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn curl_preamble_is_settings_then_window_update_then_headers() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        let kinds: Vec<u8> = frames.iter().map(|f| f.kind).collect();
        assert_eq!(kinds, vec![0x4, 0x8, 0x1], "SETTINGS, WINDOW_UPDATE, HEADERS");
    }

    /// M0 S2 finding 6: the stream identifier lives at bytes 5..9 of the frame
    /// header, not 4..8. Reading it one byte early swallows the flags byte and
    /// yields 0x05000000 for what is really stream 1. The bug is silent — frame
    /// boundaries stay correct — so it needs its own assertion.
    #[test]
    fn headers_frame_is_stream_one_with_end_stream_and_end_headers() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        let h = frames.iter().find(|f| f.kind == 0x1).expect("HEADERS");
        assert_eq!(h.stream_id, 1, "off-by-one in the frame header would give 83886080");
        assert_eq!(h.flags, 0x05, "END_STREAM | END_HEADERS");
    }

    #[test]
    fn connection_level_frames_are_stream_zero() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        for f in frames.iter().filter(|f| f.kind != 0x1) {
            assert_eq!(f.stream_id, 0);
        }
    }

    #[test]
    fn truncation_at_every_offset_never_panics() {
        let raw = fixture("curl-8.7.1-h2");
        for cut in 0..=raw.len() {
            let _ = parse_preamble(raw.get(..cut).unwrap_or_default());
        }
    }
}
```

- [ ] **Step 3: Run to verify it fails.** Expected: `cannot find function parse_preamble`.

- [ ] **Step 4: Implement**

```rust
use fingerprint_core::reader::{ParseError, Reader};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum H2Error {
    #[error("missing or malformed connection preface")]
    NoPreface,
    #[error("truncated frame")]
    Truncated,
}

impl From<ParseError> for H2Error {
    fn from(_: ParseError) -> Self { H2Error::Truncated }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: &'a [u8],
}

/// Frame header: length(3) | type(1) | flags(1) | R+stream_id(4).
pub fn parse_preamble(raw: &[u8]) -> Result<Vec<Frame<'_>>, H2Error> {
    let mut r = Reader::new(raw);
    if r.take(PREFACE.len())? != PREFACE {
        return Err(H2Error::NoPreface);
    }

    let mut frames = Vec::new();
    while r.remaining() >= 9 {
        let len = r.u24()? as usize;
        let kind = r.u8()?;
        let flags = r.u8()?;
        let sid_raw = r.take(4)?;
        let stream_id = u32::from_be_bytes([
            *sid_raw.first().ok_or(H2Error::Truncated)? & 0x7f,
            *sid_raw.get(1).ok_or(H2Error::Truncated)?,
            *sid_raw.get(2).ok_or(H2Error::Truncated)?,
            *sid_raw.get(3).ok_or(H2Error::Truncated)?,
        ]);
        let payload = r.take(len)?;
        let is_headers = kind == 0x1;
        frames.push(Frame { kind, flags, stream_id, payload });
        if is_headers {
            break; // the request is complete
        }
    }
    Ok(frames)
}
```

- [ ] **Step 5: Run to verify it passes.**
- [ ] **Step 6: STOP — commit**

```bash
git add crates/fingerprint-h2/ Cargo.lock
git commit -m "feat(h2): connection preface and frame header walk"
```

---

### Task 3: SETTINGS, WINDOW_UPDATE, PRIORITY

**Files:** `crates/fingerprint-h2/src/settings.rs`

**Interfaces:** `settings_pairs(&[Frame]) -> Vec<(u16, u32)>`, `window_update(&[Frame]) -> Option<u32>`, `priorities(&[Frame]) -> Vec<Priority>`.

- [ ] **Step 1: Write the failing tests against the oracle**

```rust
/// Oracle: tshark reports `http2.settings.id` as `3,4,2` — NOT ascending. Order is
/// signal, so this asserts the sequence, not a set.
#[test]
fn curl_settings_are_in_wire_order_not_sorted() {
    let raw = fixture("curl-8.7.1-h2");
    let frames = crate::frame::parse_preamble(&raw).expect("parse");
    assert_eq!(
        settings_pairs(&frames),
        vec![(3, 100), (4, 10_485_760), (2, 0)]
    );
}

#[test]
fn curl_window_update_matches_the_oracle() {
    let raw = fixture("curl-8.7.1-h2");
    let frames = crate::frame::parse_preamble(&raw).expect("parse");
    assert_eq!(window_update(&frames), Some(1_048_510_465));
}

/// The discriminating case: Chrome sends no SETTINGS id 3 at all, while curl
/// announces `3:100`. Presence alone separates the families.
#[test]
fn chrome_sends_no_max_concurrent_streams_setting() {
    let raw = fixture("chrome-h2");
    let frames = crate::frame::parse_preamble(&raw).expect("parse");
    let ids: Vec<u16> = settings_pairs(&frames).iter().map(|(id, _)| *id).collect();
    assert!(!ids.contains(&3), "no browser sends SETTINGS id 3");
}

/// Absence must be distinguishable from present-at-default.
#[test]
fn a_setting_absent_from_the_wire_is_absent_from_the_list() {
    let frames = vec![Frame { kind: 0x4, flags: 0, stream_id: 0, payload: &[0, 4, 0, 1, 0, 0] }];
    let pairs = settings_pairs(&frames);
    assert_eq!(pairs, vec![(4, 65536)]);
    assert!(!pairs.iter().any(|(id, _)| *id == 3));
}

#[test]
fn a_settings_payload_that_is_not_a_multiple_of_six_is_ignored_not_panicked_on() {
    let frames = vec![Frame { kind: 0x4, flags: 0, stream_id: 0, payload: &[0, 4, 0] }];
    assert!(settings_pairs(&frames).is_empty());
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement.** SETTINGS payload is repeated `id(2) value(4)`; WINDOW_UPDATE is `R+increment(4)`; PRIORITY is `stream_dep(4) weight(1)`.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-h2/
git commit -m "feat(h2): SETTINGS, WINDOW_UPDATE and PRIORITY extraction"
```

---

### Task 4: HPACK decoding

The hardest task in this milestone, and the one tshark validates most directly.

**Files:** `crates/fingerprint-h2/src/headers.rs`

**Interfaces:** `decode_headers(&Frame) -> Vec<(String, String)>`, `pseudo_header_order(&[(String, String)]) -> String`.

- [ ] **Step 1: Choose a decoder**

Use an existing HPACK crate (`cargo add hpack` or `fluke-hpack`) rather than hand-rolling
Huffman. Requirements, both of which must be verified before committing to the choice:
**it must preserve header order** (order is the fingerprint) and it must not panic on
malformed input — wrap it if it does. Record the chosen crate and version here.

- [ ] **Step 2: Write the failing tests**

```rust
/// Oracle: tshark `http2.header.name` reports exactly this order for the curl
/// fixture. Order is the whole point — a decoder that returns a map is unusable.
#[test]
fn curl_header_names_match_the_oracle_in_order() {
    let raw = fixture("curl-8.7.1-h2");
    let frames = crate::frame::parse_preamble(&raw).expect("parse");
    let h = frames.iter().find(|f| f.kind == 0x1).expect("HEADERS");
    let names: Vec<String> = decode_headers(h).into_iter().map(|(n, _)| n).collect();
    assert_eq!(
        names,
        vec![":method", ":scheme", ":authority", ":path", "user-agent", "accept"]
    );
}

#[test]
fn curl_pseudo_header_order_is_msap() {
    let raw = fixture("curl-8.7.1-h2");
    let frames = crate::frame::parse_preamble(&raw).expect("parse");
    let h = frames.iter().find(|f| f.kind == 0x1).expect("HEADERS");
    assert_eq!(pseudo_header_order(&decode_headers(h)), "m,s,a,p");
}

/// Chrome orders pseudo-headers m,a,s,p. Claiming to be Chrome with curl's
/// ordering is caught on the first request — this is the discriminator.
#[test]
fn chrome_pseudo_header_order_differs_from_curl() {
    let raw = fixture("chrome-h2");
    let frames = crate::frame::parse_preamble(&raw).expect("parse");
    let h = frames.iter().find(|f| f.kind == 0x1).expect("HEADERS");
    assert_eq!(pseudo_header_order(&decode_headers(h)), "m,a,s,p");
}

#[test]
fn a_malformed_headers_payload_yields_an_empty_list_not_a_panic() {
    let f = Frame { kind: 0x1, flags: 0, stream_id: 1, payload: &[0xff, 0xff, 0xff] };
    let _ = decode_headers(&f);
}
```

**If the Chrome assertion fails**, do not adjust it to match — capture what Chrome
actually sent, check it against tshark, and correct the expectation only if tshark
agrees. A test edited to match a buggy implementation is worse than no test.

- [ ] **Step 3: Run to verify it fails.**
- [ ] **Step 4: Implement.**
- [ ] **Step 5: Run to verify it passes.**
- [ ] **Step 6: STOP — commit**

```bash
git add crates/fingerprint-h2/ Cargo.lock
git commit -m "feat(h2): HPACK decoding with order preserved, validated against tshark"
```

---

### Task 5: The Akamai fingerprint

**Files:** `crates/fingerprint-h2/src/akamai.rs`, `src/lib.rs`

**Interfaces:** `H2Fingerprint { settings, window_update, priorities, pseudo_order, akamai: String }`, `fingerprint(&[u8]) -> Result<H2Fingerprint, H2Error>`.

Format: `SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header order`, where SETTINGS is
`id:value` joined by `;` in wire order, PRIORITY is `streamId:exclusive:dependsOn:weight`
joined by `,` or `0` when absent, and pseudo-order uses `m,a,s,p` letters.

- [ ] **Step 1: Write the failing tests**

```rust
/// Composed entirely from components already validated against tshark in Tasks
/// 3 and 4; this asserts only the assembly.
#[test]
fn curl_akamai_string_is_assembled_correctly() {
    let raw = fixture("curl-8.7.1-h2");
    assert_eq!(
        fingerprint(&raw).expect("fp").akamai,
        "3:100;4:10485760;2:0|1048510465|0|m,s,a,p"
    );
}

#[test]
fn chrome_akamai_string_differs_from_curl_in_settings_and_pseudo_order() {
    let curl_raw = fixture("curl-8.7.1-h2");
    let chrome_raw = fixture("chrome-h2");
    let c = fingerprint(&curl_raw).expect("fp");
    let g = fingerprint(&chrome_raw).expect("fp");
    assert_ne!(c.akamai, g.akamai);
    assert!(c.akamai.contains("3:100"), "curl announces id 3");
    assert!(!g.akamai.contains("3:100"), "Chrome does not");
}

#[test]
fn absent_priority_frames_render_as_zero() {
    let raw = fixture("curl-8.7.1-h2");
    let fp = fingerprint(&raw).expect("fp");
    assert!(fp.priorities.is_empty());
    assert!(fp.akamai.contains("|0|"));
}
```

- [ ] **Step 2–4:** red, implement, green.
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-h2/
git commit -m "feat(h2): Akamai fingerprint composition"
```

---

### Task 6: Hardening

**Files:** `crates/fingerprint-h2/tests/properties.rs`, `fuzz/fuzz_targets/parse_preamble.rs`, `.github/workflows/ci.yml`

- [ ] **Step 1: Property tests** — mirror `fingerprint-core`'s: arbitrary bytes never
  panic; preface-prefixed garbage never panics (this reaches far deeper than random
  noise); single-byte corruption of a real preamble never panics; lying frame lengths
  never over-read.
- [ ] **Step 2: Run.** If any fail, the input is a real bug — fix the parser, never the test.
- [ ] **Step 3: Fuzz target** seeded from the fixtures; run 90s locally; record executions.
- [ ] **Step 4: Add to the existing CI fuzz job** as a second target.
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-h2/ .github/
git commit -m "test(h2): property tests and fuzz target for the preamble parser"
```

---

## Self-Review

**Spec coverage.** §6.1 `H2Fingerprint` and the absence-is-signal / order-is-signal rules
→ Tasks 3 and 5. §6.2 minimal h2 read path → Tasks 2–4. §9.3 property tests, §9.4 fuzzing
→ Task 6. §10 bounds checking → `Reader` reuse plus truncation tests throughout.

**Deliberately excluded.** JA4H (see the scope decision above). `RecordingStream`,
profile database, diff engine, `fpd check`, `fpd capture` — those are M3b, which is the
first milestone with a user-facing command and needs its own plan.

**Known risks.**
1. **The Chrome h2 fixture needs a human** (Task 1 Step 2) and gates Tasks 3, 4 and 5's
   discriminating assertions. Without it the fixture set cannot show the case the whole
   fingerprint exists to detect.
2. **The HPACK crate is an unvetted dependency.** Task 4 Step 1 requires verifying order
   preservation and panic-freedom before adopting it. If neither holds, hand-rolling
   HPACK is a milestone of its own, not an afternoon.
3. **The Akamai format has no single normative specification** the way JA4 does — it is a
   de-facto format. The component values are oracle-validated; the assembly is asserted
   against the shape used consistently in the literature and in spec §6.1. If a
   discrepancy with another tool ever appears, the components are trustworthy and the
   separator convention is the thing to re-check.
4. **PRIORITY frames are near-extinct.** Modern Chrome uses RFC 9218 extensible
   priorities rather than PRIORITY frames, so the field will be `0` for most clients and
   the parsing path stays largely untested. Firefox still sends a priority tree and would
   exercise it — worth capturing when Firefox fixtures arrive.
