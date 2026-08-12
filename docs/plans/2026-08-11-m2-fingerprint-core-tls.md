# fpd M2, `fingerprint-core` TLS Parsing, JA3 and JA4, Implementation Plan

> Execute task-by-task, in order. Steps use checkbox (`- [ ]`) syntax for tracking. Every task ends at a hard stop for review and commit, see the Commit Protocol below.

**Status: COMPLETE.** 92 workspace tests pass, clippy `-D warnings` clean, fuzzer ran
672,344 executions with zero crashes. All three JA4 oracle values match tshark 4.4.9.
Deviations and remaining gaps are recorded at the bottom of this document.

**Goal:** Turn raw ClientHello bytes into a `TlsFingerprint` carrying JA3 and JA4, with every parser tested against byte fixtures captured from real clients and hardened against malformed input.

**Architecture:** A new crate `crates/fingerprint-core` containing only pure functions over `&[u8]` and structs, it never opens a socket. Byte fixtures recorded from real curl and Chrome handshakes live in-tree and drive every test, so the suite runs offline in milliseconds and each newly captured client becomes a permanent regression test.

**Tech Stack:** Rust 2021, sha2, md-5 (JA3), hex. Dev: `proptest`, `cargo-fuzz`. No async, no I/O, no network.

## Global Constraints

- `crates/fingerprint-core` carries `#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used, clippy::indexing_slicing)]`. Every parser returns `Result`. None may panic on any input.
- **`clippy::indexing_slicing` is new in this crate and is deliberate.** Every length field in a ClientHello is attacker-controlled. `raw[p]` on an attacker-supplied offset is a panic waiting to happen, so indexing must go through `.get()`.
- No test in this crate may open a socket, read the clock, or use randomness. Fixtures only.
- Dependency versions come from `cargo add`, never hand-written.
- Fixtures are committed as raw `.bin` files with a `.md` sidecar recording what produced them.
- `clippy.toml` at the repo root already relaxes unwrap/expect/panic inside `#[cfg(test)]`.

## Commit Protocol, read this before executing anything

**The implementer never runs `git commit` or `git push`.** The repository owner commits,
one commit per task. Every task ends at a **STOP**: confirm the task's tests pass, print
the suggested `git add` / `git commit` command, then wait. Inert git commands
(`git status`, `git diff`, `git log`) are fine.

---

## JA4 rules, verified against the specification and an independent oracle

These were confirmed before the plan was finalised, against
`github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md`, and then cross-checked
against **tshark 4.4.9** (`tls.handshake.ja4`) over the actual fixtures. Implement to
these, not to intuition.

**Segment (a)**, `t13i4906h2`

| Field | Rule |
|---|---|
| Protocol | `t` TLS-over-TCP, `q` QUIC, `d` DTLS |
| Version | Highest non-GREASE value in `supported_versions` (0x002b) if present, else `legacy_version`. `0x0304`→`13`, `0x0303`→`12`, `0x0302`→`11`, `0x0301`→`10` |
| SNI | `d` if extension `0x0000` present, `i` if absent |
| Cipher count | 2-digit decimal, GREASE excluded, capped at `99`. SCSV (`0x00ff`) and reserved values **are** counted |
| Extension count | 2-digit decimal, GREASE excluded, capped at `99`. **SNI and ALPN are counted here** |
| ALPN | First and last ASCII-alphanumeric characters of the *first* ALPN value, hex representation if non-alphanumeric, `00` if absent or empty |

**Segment (b)**, 12-char truncated SHA-256 of ciphers **sorted ascending**, formatted as
4-digit zero-padded **lowercase hex**, comma-delimited. GREASE excluded, other
non-cipher values retained. Literal `000000000000` if empty.

**Segment (c)**, 12-char truncated SHA-256 of extensions **sorted ascending** (same hex
format), **excluding SNI `0000` and ALPN `0010`** since segment (a) already carries them,
then `_`, then signature algorithms in **wire order, unsorted**. Literal
`000000000000` if empty.

### The oracle: tshark, locally, over the exact fixture bytes

`tshark` 4.4.9 exposes both `tls.handshake.ja4` and, critically,
`tls.handshake.ja4_r`, the **pre-hash strings**. A mismatch therefore says *which list*
is wrong rather than merely that a hash differs.

`scripts/bin2pcap.py` wraps a `.bin` fixture in a minimal Ethernet/IPv4/TCP pcap. The
payload is byte-identical to the fixture, so tshark and `fingerprint-core` consume
exactly the same bytes, the comparison has no confounder.

```bash
python3 scripts/bin2pcap.py crates/fingerprint-core/tests/fixtures/<name>.bin /tmp/f.pcap
tshark -r /tmp/f.pcap -T fields -e tls.handshake.ja4 -e tls.handshake.ja4_r
```

Three independent layers now agree on the curl fixture, and each is reproducible:

```
spec      → segment (a) predicted t13i4906h2
tshark    → t13i4906h2_0d8feac7bc37_7395dae3b2f3
shasum    → sha256(<cipher list>)[..12]  = 0d8feac7bc37   ✓
            sha256(<ext_sigalg>)[..12]   = 7395dae3b2f3   ✓
```

Oracle values are committed in each fixture's `.md` sidecar and asserted in Task 8, so
they keep working as regression tests rather than being a one-time check.

---

## File Structure

```
crates/fingerprint-core/
├── Cargo.toml
├── src/
│   ├── lib.rs           # re-exports, TlsFingerprint, ParseError
│   ├── grease.rs        # GREASE detection and normalisation
│   ├── reader.rs        # bounds-checked cursor over untrusted bytes
│   ├── hello.rs         # ClientHello walk → RawHello
│   ├── ext.rs           # extension bodies: SNI, ALPN, sig algs, groups, versions
│   ├── ja3.rs
│   └── ja4.rs
├── tests/
│   ├── fixtures/
│   │   ├── curl-8.7.1-macos.bin
│   │   ├── curl-8.7.1-macos.md
│   │   ├── chrome-macos.bin
│   │   └── chrome-macos.md
│   └── fixtures.rs      # fixture-driven end-to-end assertions
└── fuzz/
    └── fuzz_targets/parse_hello.rs
```

**Responsibility boundaries.** `reader.rs` is the only module that touches raw offsets,
everything above it works in terms of already-validated slices. `hello.rs` knows the
ClientHello layout but not what any extension *means*. `ext.rs` knows extension bodies
but not the outer layout. `ja3.rs` and `ja4.rs` consume the parsed structs and never see
bytes. That split is why a fuzz finding in `reader.rs` cannot silently change a JA4.

---

### Task 1: Record raw byte fixtures from real clients

S1 printed parsed summaries, not bytes. TDD against a parser needs the original bytes,
so they have to be captured before anything else can be written.

**Files:**
- Create: `spikes/s1-recording-stream/src/bin/dump.rs`
- Create: `crates/fingerprint-core/tests/fixtures/*.bin` and matching `*.md`

**Interfaces:**
- Consumes: the `Recording` adapter already in `spikes/s1-recording-stream`.
- Produces: `.bin` files containing exactly the bytes of one ClientHello record.

- [ ] **Step 1: Add a fixture-dumping binary to the existing S1 spike**

`spikes/s1-recording-stream/src/bin/dump.rs`, same listener as `main.rs`, but instead
of printing parsed lists it writes the recorded buffer to a file. Trim to the first TLS
record only: read the 5-byte record header, take `5 + length` bytes, discard the rest,
so a fixture is one ClientHello and nothing else.

```rust
fn client_hello_record(raw: &[u8]) -> Option<&[u8]> {
    // record: type(1) version(2) length(2) | payload
    let len = u16::from_be_bytes([*raw.get(3)?, *raw.get(4)?]) as usize;
    if *raw.first()? != 0x16 {
        return None; // not a handshake record
    }
    raw.get(..5 + len)
}
```

Name output files from an `FPD_FIXTURE_LABEL` environment variable so each run is
labelled at capture time:

```rust
let label = std::env::var("FPD_FIXTURE_LABEL").unwrap_or_else(|_| "unlabelled".into());
let path = format!("crates/fingerprint-core/tests/fixtures/{label}.bin");
std::fs::write(&path, record).expect("write fixture");
println!("wrote {} ({} bytes)", path, record.len());
```

- [ ] **Step 2: Capture curl**

```bash
mkdir -p crates/fingerprint-core/tests/fixtures
FPD_FIXTURE_LABEL=curl-8.7.1-macos \
  cargo run --manifest-path spikes/s1-recording-stream/Cargo.toml --bin dump &
sleep 2
curl -sk --http2 https://127.0.0.1:8443/ --max-time 5 || true
```

Expected: `wrote crates/fingerprint-core/tests/fixtures/curl-8.7.1-macos.bin (~360 bytes)`.

- [ ] **Step 3: Capture Chrome**

Restart the dumper with `FPD_FIXTURE_LABEL=chrome-macos`, open
`https://127.0.0.1:8443/` in Chrome, and accept the certificate warning.

Expected: `~1800 bytes`. Per M0 finding 2, GREASE values in this fixture are one
arbitrary draw and must never be asserted literally, only positions and counts.

**Capture a resuming Chrome separately if convenient** (`chrome-macos-psk`): M0 finding 5
showed Chrome sends 18 extensions with `pre_shared_key` on resumption versus 17 without.
Having both makes the session-dependence explicit in the fixture set rather than a
surprise later. Optional, do not block on it.

- [ ] **Step 4: Write the sidecars**

For each `.bin`, a `.md` with: capturing client and version, OS, date, target
(`127.0.0.1:8443`, so no SNI is present), byte length, and the parsed cipher and
extension lists from the S1 output for cross-reference.

- [ ] **Step 5: Verify the fixtures are well-formed**

```bash
for f in crates/fingerprint-core/tests/fixtures/*.bin; do
  printf "%s: " "$f"; xxd -l 6 -p "$f"
done
```
Expected: each begins `160301` or `160303` (handshake record, TLS 1.0/1.2 legacy
version), followed by the record length.

- [ ] **Step 6: STOP, hand off to the owner for commit**

```bash
git add spikes/s1-recording-stream/ crates/fingerprint-core/tests/fixtures/
git commit -m "test(core): record ClientHello byte fixtures from curl and Chrome"
```

Wait for the owner before starting Task 2.

---

### Task 2: Crate skeleton, bounds-checked reader, and the fixture harness

**Files:**
- Create: `crates/fingerprint-core/Cargo.toml`, `src/lib.rs`, `src/reader.rs`, `tests/fixtures.rs`

**Interfaces:**
- Produces: `ParseError`, `Reader::new(&[u8])`, `Reader::u8()`, `Reader::u16()`, `Reader::take(n) -> Result<&[u8], ParseError>`, `Reader::remaining()`, and `fixtures::load(name) -> Vec<u8>` for tests.

`Reader` exists so that no other module ever writes `raw[i]`. It is the single place
where an attacker-controlled length can go wrong, which makes it the single place worth
fuzzing hardest.

- [ ] **Step 1: Create the crate**

```bash
cargo new --lib --vcs none crates/fingerprint-core
# cargo new appends the crate to workspace.members even though `members = ["crates/*"]`
# already covers it, remove the duplicate line it adds, as in M1 Task 1.
cd crates/fingerprint-core && cargo add sha2 md-5 hex && cargo add --dev proptest
```

- [ ] **Step 2: Write the failing reader tests**

`crates/fingerprint-core/src/reader.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_values_in_order() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(r.u8().expect("u8"), 0x01);
        assert_eq!(r.u16().expect("u16"), 0x0203);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reading_past_the_end_errors_rather_than_panicking() {
        let mut r = Reader::new(&[0x01]);
        assert_eq!(r.u8().expect("u8"), 0x01);
        assert!(r.u8().is_err());
        assert!(r.u16().is_err());
        assert!(r.take(1).is_err());
    }

    #[test]
    fn an_oversized_length_errors_rather_than_panicking() {
        let mut r = Reader::new(&[0xff, 0xff, 0x00]);
        let n = r.u16().expect("u16") as usize; // 65535, far past the end
        assert!(r.take(n).is_err(), "must not panic or over-read");
    }

    #[test]
    fn take_returns_exactly_n_bytes() {
        let mut r = Reader::new(&[1, 2, 3, 4]);
        assert_eq!(r.take(3).expect("take"), &[1, 2, 3]);
        assert_eq!(r.remaining(), 1);
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p fingerprint-core reader`
Expected: FAIL, `cannot find type Reader in this scope`.

- [ ] **Step 4: Implement the reader**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("unexpected end of input")]
    Truncated,
    #[error("not a TLS handshake record")]
    NotHandshake,
    #[error("not a ClientHello")]
    NotClientHello,
    #[error("malformed {0}")]
    Malformed(&'static str),
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?.first().copied().ok_or(ParseError::Truncated)?)
    }

    pub fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([
            *b.first().ok_or(ParseError::Truncated)?,
            *b.get(1).ok_or(ParseError::Truncated)?,
        ]))
    }
}
```

Add `thiserror` with `cargo add thiserror`. Put `#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used, clippy::indexing_slicing)]` and `pub mod reader;` in `lib.rs`.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p fingerprint-core reader` maps to 4 passed.

- [ ] **Step 6: Add the fixture harness**

`crates/fingerprint-core/tests/fixtures.rs`:

```rust
pub fn load(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.bin"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

#[test]
fn every_fixture_is_a_handshake_record() {
    for name in ["curl-8.7.1-macos", "chrome-macos"] {
        let raw = load(name);
        assert_eq!(raw.first(), Some(&0x16), "{name} is not a handshake record");
        assert!(raw.len() > 100, "{name} is implausibly short");
    }
}
```

- [ ] **Step 7: Run and verify**

Run: `cargo test -p fingerprint-core` maps to reader tests plus the fixture sanity check pass.

- [ ] **Step 8: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/ Cargo.lock
git commit -m "feat(core): bounds-checked reader and fixture harness"
```

Wait for the owner before starting Task 3.

---

### Task 3: ClientHello walk, versions, session id, ciphers

**Files:**
- Create: `crates/fingerprint-core/src/hello.rs`
- Modify: `crates/fingerprint-core/src/lib.rs`

**Interfaces:**
- Consumes: `Reader`, `ParseError`.
- Produces: `RawHello { legacy_version: u16, session_id_len: usize, ciphers: Vec<u16>, extensions: Vec<RawExt> }`, `RawExt { id: u16, body: &[u8] }`, `parse_hello(&[u8]) -> Result<RawHello<'_>, ParseError>`.

- [ ] **Step 1: Write the failing tests, asserted against real fixtures**

`crates/fingerprint-core/src/hello.rs`, the expected values come from the S1 capture, so
these are assertions about real observed traffic rather than invented data:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    #[test]
    fn parses_curl_ciphers_in_wire_order() {
        let raw = fixture("curl-8.7.1-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(h.ciphers.len(), 49, "curl 8.7.1 offered 49 ciphers");
        assert_eq!(h.ciphers.first(), Some(&4867)); // TLS_CHACHA20_POLY1305_SHA256
    }

    #[test]
    fn parses_curl_extensions_in_wire_order() {
        let raw = fixture("curl-8.7.1-macos");
        let h = parse_hello(&raw).expect("parse");
        let ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![43, 51, 11, 10, 13, 16]);
    }

    #[test]
    fn parses_chrome_and_preserves_extension_order() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(h.ciphers.len(), 16, "15 real + 1 GREASE");
        assert!(
            h.extensions.len() == 17 || h.extensions.len() == 18,
            "17, or 18 when resuming with pre_shared_key; got {}",
            h.extensions.len()
        );
    }

    /// M0 finding 3: only extension order permutes. Cipher order is fixed, so this
    /// is safe to assert literally where the extension order is not.
    #[test]
    fn chrome_cipher_order_is_stable_after_removing_grease() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        let real: Vec<u16> = h.ciphers.iter().copied().filter(|c| !crate::grease::is_grease(*c)).collect();
        assert_eq!(
            real,
            vec![4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53]
        );
    }

    #[test]
    fn a_non_handshake_record_is_rejected() {
        assert_eq!(parse_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), Err(ParseError::NotHandshake));
    }

    #[test]
    fn truncation_at_every_offset_errors_and_never_panics() {
        let raw = fixture("chrome-macos");
        for cut in 0..raw.len() {
            let _ = parse_hello(raw.get(..cut).unwrap_or_default());
        }
    }
}
```

The last test is the important one: it truncates a real ClientHello at **every** byte
offset and requires that none of them panic. This is the cheapest possible substitute
for fuzzing and catches the majority of bounds bugs immediately.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-core hello`
Expected: FAIL, `cannot find function parse_hello`.

- [ ] **Step 3: Implement the walk**

```rust
use crate::reader::{ParseError, Reader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExt<'a> {
    pub id: u16,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHello<'a> {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<RawExt<'a>>,
}

pub fn parse_hello(raw: &[u8]) -> Result<RawHello<'_>, ParseError> {
    let mut r = Reader::new(raw);

    if r.u8()? != 0x16 {
        return Err(ParseError::NotHandshake);
    }
    let _record_version = r.u16()?;
    let record_len = r.u16()? as usize;
    let body = r.take(record_len)?;

    let mut h = Reader::new(body);
    if h.u8()? != 0x01 {
        return Err(ParseError::NotClientHello);
    }
    let hs_len = {
        let b = h.take(3)?;
        u32::from_be_bytes([
            0,
            *b.first().ok_or(ParseError::Truncated)?,
            *b.get(1).ok_or(ParseError::Truncated)?,
            *b.get(2).ok_or(ParseError::Truncated)?,
        ]) as usize
    };
    let mut c = Reader::new(h.take(hs_len)?);

    let legacy_version = c.u16()?;
    let _random = c.take(32)?;
    let sid_len = c.u8()? as usize;
    let _session_id = c.take(sid_len)?;

    let cs_len = c.u16()? as usize;
    let cs_bytes = c.take(cs_len)?;
    if cs_len % 2 != 0 {
        return Err(ParseError::Malformed("cipher_suites length"));
    }
    let ciphers: Vec<u16> = cs_bytes
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();

    let comp_len = c.u8()? as usize;
    let _comp = c.take(comp_len)?;

    let mut extensions = Vec::new();
    if c.remaining() >= 2 {
        let ext_total = c.u16()? as usize;
        let mut e = Reader::new(c.take(ext_total)?);
        while e.remaining() >= 4 {
            let id = e.u16()?;
            let len = e.u16()? as usize;
            let body = e.take(len)?;
            extensions.push(RawExt { id, body });
        }
    }

    Ok(RawHello {
        legacy_version,
        ciphers,
        extensions,
    })
}
```

Add `pub mod hello;` to `lib.rs`. Task 4 supplies `grease::is_grease`, so run Task 3's
cipher-order test after Task 4 if executing strictly in order, or add the two-line
`grease` module now and let Task 4 test it properly.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p fingerprint-core` maps to all hello tests pass, including the
truncate-at-every-offset test.

- [ ] **Step 5: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/
git commit -m "feat(core): bounds-checked ClientHello walk over real fixtures"
```

Wait for the owner before starting Task 4.

---

### Task 4: GREASE detection and normalisation

M0 finding 2: GREASE **values** rotate every connection. Only positions are stable.
Every comparison and hash in this crate must normalise them first, or every Chrome
result becomes non-deterministic.

**Files:**
- Create: `crates/fingerprint-core/src/grease.rs`

**Interfaces:**
- Produces: `is_grease(u16) -> bool`, `strip(&[u16]) -> Vec<u16>`, `positions(&[u16]) -> Vec<usize>`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// The 16 GREASE values from RFC 8701, spelled out rather than generated, so a
    /// wrong predicate cannot agree with a wrong generator.
    const ALL_GREASE: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];

    #[test]
    fn every_rfc8701_grease_value_is_recognised() {
        for v in ALL_GREASE {
            assert!(is_grease(v), "{v:#06x} is GREASE");
        }
    }

    #[test]
    fn real_values_are_not_mistaken_for_grease() {
        for v in [0x1301, 0x1302, 0x1303, 0xc02b, 0x002f, 0x0000, 0x0010, 0x002b, 0x0a0b, 0x1a2a] {
            assert!(!is_grease(v), "{v:#06x} is not GREASE");
        }
    }

    /// Values observed live in the S1 capture, in cipher[0] across successive
    /// Chrome handshakes.
    #[test]
    fn values_observed_in_the_s1_capture_are_recognised() {
        for v in [2570u16, 6682, 14906, 19018, 23130, 27242, 35466, 43690, 47802, 51914, 56026, 60138, 64250] {
            assert!(is_grease(v), "{v} was observed as Chrome cipher[0]");
        }
    }

    #[test]
    fn strip_removes_grease_and_preserves_order() {
        assert_eq!(strip(&[0x0a0a, 0x1301, 0x1a1a, 0x1302]), vec![0x1301, 0x1302]);
    }

    #[test]
    fn positions_reports_where_grease_sat() {
        assert_eq!(positions(&[0x0a0a, 0x1301, 0x1a1a]), vec![0, 2]);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-core grease`
Expected: FAIL, `cannot find function is_grease`.

- [ ] **Step 3: Implement**

```rust
/// RFC 8701 GREASE: both bytes equal, low nibble 0xA.
pub fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

pub fn strip(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

pub fn positions(values: &[u16]) -> Vec<usize> {
    values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| is_grease(*v).then_some(i))
        .collect()
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p fingerprint-core grease` maps to 5 passed.

- [ ] **Step 5: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/
git commit -m "feat(core): GREASE detection validated against RFC 8701 and live captures"
```

Wait for the owner before starting Task 5.

---

### Task 5: Extension bodies, SNI, ALPN, signature algorithms, groups, versions

**Files:**
- Create: `crates/fingerprint-core/src/ext.rs`

**Interfaces:**
- Consumes: `RawExt`, `Reader`.
- Produces: `has_sni(&[RawExt]) -> bool`, `first_alpn(&[RawExt]) -> Option<String>`, `sig_algs(&[RawExt]) -> Vec<u16>`, `supported_groups(&[RawExt]) -> Vec<u16>`, `negotiated_version(&[RawExt], legacy: u16) -> u16`.

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::parse_hello;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures").join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    /// Both fixtures were captured over a connection to a bare IP, where clients
    /// correctly omit SNI. This is the observed basis for JA4's `d`/`i` flag.
    #[test]
    fn no_sni_when_captured_over_an_ip_connection() {
        for name in ["curl-8.7.1-macos", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            assert!(!has_sni(&h.extensions), "{name} should have no SNI");
        }
    }

    #[test]
    fn first_alpn_is_h2_for_both_fixtures() {
        for name in ["curl-8.7.1-macos", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            assert_eq!(first_alpn(&h.extensions).as_deref(), Some("h2"), "{name}");
        }
    }

    #[test]
    fn signature_algorithms_are_present_and_even_length() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        let sa = sig_algs(&h.extensions);
        assert!(!sa.is_empty(), "Chrome always sends signature_algorithms");
    }

    #[test]
    fn negotiated_version_is_tls13_for_both_fixtures() {
        for name in ["curl-8.7.1-macos", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            assert_eq!(negotiated_version(&h.extensions, h.legacy_version), 0x0304, "{name}");
        }
    }

    /// supported_versions carries GREASE too; it must not win the "highest" contest.
    #[test]
    fn grease_in_supported_versions_is_ignored() {
        let ext = [RawExt { id: 43, body: &[0x04, 0x0a, 0x0a, 0x03, 0x04] }];
        assert_eq!(negotiated_version(&ext, 0x0303), 0x0304);
    }

    #[test]
    fn a_truncated_extension_body_yields_a_default_not_a_panic() {
        let ext = [RawExt { id: 16, body: &[0xff] }];
        assert_eq!(first_alpn(&ext), None);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-core ext`
Expected: FAIL, `cannot find function has_sni`.

- [ ] **Step 3: Implement**

```rust
use crate::grease::is_grease;
use crate::hello::RawExt;
use crate::reader::Reader;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIG_ALGS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

fn body_of<'a>(exts: &'a [RawExt<'a>], id: u16) -> Option<&'a [u8]> {
    exts.iter().find(|e| e.id == id).map(|e| e.body)
}

pub fn has_sni(exts: &[RawExt]) -> bool {
    exts.iter().any(|e| e.id == EXT_SERVER_NAME)
}

/// ALPN body: list_len(2) then repeated { len(1), bytes }.
pub fn first_alpn(exts: &[RawExt]) -> Option<String> {
    let body = body_of(exts, EXT_ALPN)?;
    let mut r = Reader::new(body);
    let list_len = r.u16().ok()? as usize;
    let mut list = Reader::new(r.take(list_len).ok()?);
    let n = list.u8().ok()? as usize;
    let bytes = list.take(n).ok()?;
    String::from_utf8(bytes.to_vec()).ok()
}

fn u16_list(body: Option<&[u8]>) -> Vec<u16> {
    let Some(body) = body else { return Vec::new() };
    let mut r = Reader::new(body);
    let Ok(len) = r.u16() else { return Vec::new() };
    let Ok(items) = r.take(len as usize) else { return Vec::new() };
    items
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect()
}

pub fn sig_algs(exts: &[RawExt]) -> Vec<u16> {
    u16_list(body_of(exts, EXT_SIG_ALGS))
}

pub fn supported_groups(exts: &[RawExt]) -> Vec<u16> {
    u16_list(body_of(exts, EXT_SUPPORTED_GROUPS))
}

/// supported_versions body: len(1) then repeated u16. GREASE entries are ignored.
pub fn negotiated_version(exts: &[RawExt], legacy: u16) -> u16 {
    let Some(body) = body_of(exts, EXT_SUPPORTED_VERSIONS) else {
        return legacy;
    };
    let mut r = Reader::new(body);
    let Ok(len) = r.u8() else { return legacy };
    let Ok(items) = r.take(len as usize) else { return legacy };
    items
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(legacy)
}
```

Note `unwrap_or` is permitted. `unwrap` is not.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p fingerprint-core ext` maps to 6 passed.

- [ ] **Step 5: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/
git commit -m "feat(core): extension body parsing for SNI, ALPN, sig algs, versions"
```

Wait for the owner before starting Task 6.

---

### Task 6: Verify the JA4 specification, then JA3

**Files:**
- Create: `crates/fingerprint-core/src/ja3.rs`
- Modify: this plan, if the specification differs from the rules recorded above.

- [ ] **Step 1: Read the official JA4 specification and correct this plan**

Open `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md` and check each
of the six numbered questions in the warning section near the top of this document.
Write the confirmed rules into this plan, replacing the from-memory versions, and note
any that differed. **Do not start Task 7 until this is done**, implementing JA4 from an
unverified recollection is how a fingerprint tool ends up authoritative and wrong.

- [ ] **Step 2: Write the failing JA3 tests**

JA3 = `MD5(TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)`, dash-joined
within each field, comma-joined between, GREASE removed, order **preserved**.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Verifiable by hand: an empty-ish hello has a known string form, and the MD5
    /// of that string can be checked with `md5` on the command line.
    #[test]
    fn ja3_string_shape_is_comma_separated_five_fields() {
        let s = ja3_string(0x0303, &[0x1301], &[0x000a], &[0x001d], &[0x00]);
        assert_eq!(s, "771,4865,10,29,0");
    }

    #[test]
    fn ja3_string_removes_grease_but_keeps_order() {
        let s = ja3_string(0x0303, &[0x0a0a, 0x1302, 0x1301], &[0x1a1a, 0x000a], &[], &[]);
        assert_eq!(s, "771,4866-4865,10,,");
    }

    #[test]
    fn ja3_hash_is_the_md5_of_the_string() {
        // Cross-check: `printf '771,4865,10,29,0' | md5`
        let s = ja3_string(0x0303, &[0x1301], &[0x000a], &[0x001d], &[0x00]);
        assert_eq!(ja3_hash(&s).len(), 32);
        assert!(ja3_hash(&s).chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn chrome_ja3_differs_between_two_captures_of_the_same_browser() {
        // Documents WHY JA3 is unreliable for browsers: it hashes extension order,
        // and Chrome permutes it. Uses the two Chrome fixtures if both exist.
    }
}
```

Note the last test is a documentation test of a known JA3 weakness, implement it only
if a second Chrome fixture was captured in Task 1. Otherwise delete it rather than
leaving it empty.

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p fingerprint-core ja3`
Expected: FAIL, `cannot find function ja3_string`.

- [ ] **Step 4: Implement**

```rust
use crate::grease::strip;

fn join(values: &[u16]) -> String {
    strip(values).iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-")
}

pub fn ja3_string(version: u16, ciphers: &[u16], exts: &[u16], curves: &[u16], point_fmts: &[u8]) -> String {
    let pf = point_fmts.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-");
    format!("{},{},{},{},{}", version, join(ciphers), join(exts), join(curves), pf)
}

pub fn ja3_hash(s: &str) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(s.as_bytes()))
}
```

- [ ] **Step 5: Run to verify it passes, and cross-check the MD5 externally**

```bash
cargo test -p fingerprint-core ja3
printf '771,4865,10,29,0' | md5
```
The second command's output must appear in the test's computed hash, an independent
check that the implementation is really MD5 over really that string.

- [ ] **Step 6: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/ docs/plans/
git commit -m "feat(core): JA3, and confirm JA4 rules against the specification"
```

Wait for the owner before starting Task 7.

---

### Task 7: JA4 segment (a)

Implement only after Task 6 Step 1 has confirmed the rules.

**Files:**
- Create: `crates/fingerprint-core/src/ja4.rs`

**Interfaces:**
- Produces: `ja4_a(&Ja4Input) -> String`, and `Ja4Input { transport, version, has_sni, cipher_count, ext_count, first_alpn }`.

- [ ] **Step 1: Write the failing tests**

Every field here is hand-checkable against the fixture, which is why (a) is split from
the hashed segments.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_fixture_segment_a() {
        // 49 ciphers, 6 extensions, TLS 1.3, no SNI (IP target), ALPN h2
        let a = ja4_a(&Ja4Input {
            transport: Transport::Tcp,
            version: 0x0304,
            has_sni: false,
            cipher_count: 49,
            ext_count: 6,
            first_alpn: Some("h2".into()),
        });
        assert_eq!(a, "t13i4906h2");
    }

    #[test]
    fn counts_are_capped_at_99() {
        let a = ja4_a(&Ja4Input { cipher_count: 250, ext_count: 100, ..chrome_like() });
        assert!(a.contains("9999"));
    }

    #[test]
    fn absent_alpn_is_reported_as_00() { /* ... */ }

    #[test]
    fn domain_target_uses_d_and_ip_target_uses_i() { /* ... */ }
}
```

**The expected string `t13i4906h2` is a prediction, not a known-good value.** If Task 6
Step 1 revealed different count or flag rules, correct it before implementing.

- [ ] **Step 2: Run to verify it fails.** Expected: `cannot find function ja4_a`.
- [ ] **Step 3: Implement segment (a) per the confirmed rules.**
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/
git commit -m "feat(core): JA4 segment (a)"
```

---

### Task 8: JA4 segments (b) and (c), and the composite

**Files:**
- Modify: `crates/fingerprint-core/src/ja4.rs`, `src/lib.rs`

**Interfaces:**
- Produces: `ja4_b(&[u16]) -> String`, `ja4_c(&[u16], &[u16]) -> String`, `TlsFingerprint { ja3, ja4, ciphers, extensions, grease_positions, alpn, has_sni }`, `fingerprint(&[u8]) -> Result<TlsFingerprint, ParseError>`.

- [ ] **Step 1: Write the failing tests, with externally checkable hashes**

```rust
#[test]
fn ja4_b_is_truncated_sha256_of_the_sorted_cipher_list() {
    // Cross-check: printf '1301,1302,1303' | shasum -a 256
    let b = ja4_b(&[0x1303, 0x1301, 0x1302]);
    assert_eq!(b.len(), 12);
    assert!(b.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn ja4_b_sorts_so_permutation_does_not_change_it() {
    assert_eq!(ja4_b(&[0x1301, 0x1302]), ja4_b(&[0x1302, 0x1301]));
}

/// The property that makes JA4 usable for Chrome at all (M0 finding 1).
#[test]
fn chrome_ja4_is_stable_across_extension_permutation() {
    let raw = fixture("chrome-macos");
    let mut h = parse_hello(&raw).expect("parse");
    let before = fingerprint(&raw).expect("fp").ja4;
    h.extensions.reverse();
    let after = ja4_from_parts(&h);
    assert_eq!(before, after, "JA4 must survive extension permutation");
}
```

The last test is the single most important assertion in M2: it encodes, as an executable
check, the reason JA4 replaced JA3.

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement (b), (c), the composite, and `fingerprint()`.**
- [ ] **Step 4: Run to verify it passes, and cross-check one hash externally**

```bash
printf '1301,1302,1303' | shasum -a 256 | cut -c1-12
```

- [ ] **Step 5: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/
git commit -m "feat(core): JA4 hashed segments and composite fingerprint"
```

---

### Task 9: Hardening, property tests and a fuzz target

**Files:**
- Create: `crates/fingerprint-core/fuzz/` (via `cargo fuzz init`), `fuzz/fuzz_targets/parse_hello.rs`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the property test**

```rust
proptest! {
    /// No byte string, however malformed, may panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(data: Vec<u8>) {
        let _ = crate::hello::parse_hello(&data);
    }

    /// Corrupting any single byte of a real ClientHello must yield an error or a
    /// parse, never a panic.
    #[test]
    fn single_byte_corruption_of_a_real_hello_never_panics(idx in 0usize..1800, byte: u8) {
        let mut raw = fixture("chrome-macos");
        if let Some(b) = raw.get_mut(idx) { *b = byte; }
        let _ = crate::hello::parse_hello(&raw);
    }
}
```

- [ ] **Step 2: Run, these should pass immediately if `Reader` did its job**

Run: `cargo test -p fingerprint-core proptest`
If either fails, the failing input is a genuine bug: fix `reader.rs` or `hello.rs`, do
not weaken the test.

- [ ] **Step 3: Add the fuzz target**

```bash
cargo install cargo-fuzz   # if not present
cd crates/fingerprint-core && cargo fuzz init
```

`fuzz/fuzz_targets/parse_hello.rs`:

```rust
#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = fingerprint_core::hello::parse_hello(data);
});
```

Seed the corpus from the fixtures:

```bash
mkdir -p fuzz/corpus/parse_hello
cp tests/fixtures/*.bin fuzz/corpus/parse_hello/
cargo fuzz run parse_hello -- -max_total_time=120
```

Expected: no crashes in 120 seconds. Record the executions-per-second in the commit
message so future runs have a baseline.

- [ ] **Step 4: Wire a short fuzz run into CI**

Add a job that runs `cargo fuzz run parse_hello -- -max_total_time=60` on a nightly
toolchain, allowed to fail on toolchain unavailability but not on a crash.

- [ ] **Step 5: STOP, hand off to the owner for commit**

```bash
git add crates/fingerprint-core/ .github/
git commit -m "test(core): property tests and fuzz target for the ClientHello parser"
```

---

## Self-Review

**Spec coverage.** §6.1 `TlsFingerprint` fields maps to Tasks 3, 5, 8. JA3 unreliability for
browsers maps to Task 6 Step 2. JA4 four-segment construction maps to Tasks 7-8. §6.9 GREASE
normalisation (M0 finding 2) maps to Task 4. §9.1 byte fixtures maps to Task 1. §9.3 property tests
maps to Task 9. §9.4 fuzzing maps to Task 9. §10 bounds checking on attacker-controlled lengths maps to
Task 2 `Reader` plus the truncate-at-every-offset test in Task 3.

**Not in this plan.** HTTP/2 parsing, JA4H, `serve`, `check`, `capture`, the verdict
engine, profiles. Those are M3 and M4 and get their own plans. `parse_h2_preamble` is
deliberately absent even though S2 proved it works, M2 is TLS only, and mixing the two
would make the crate hard to review in one sitting.

**Risks, all three from the first draft retired before finalising.**

1. ~~JA4 rules unverified~~, **retired.** Read from the FoxIO specification and recorded
   above. The prediction `t13i4906h2` turned out correct, but three details were missing
   from the first draft and would have produced wrong hashes: hex is **4-digit
   zero-padded lowercase** (`0004`, not `4`), empty lists emit literal
   `000000000000`, and DTLS uses protocol char `d`.
2. ~~No independent oracle~~, **retired.** tshark 4.4.9 supports `tls.handshake.ja4`
   and `tls.handshake.ja4_r`, and `scripts/bin2pcap.py` feeds it the exact fixture
   bytes. Oracle values are committed per fixture and asserted in Task 8.
3. ~~No domain-SNI fixture~~, **retired.** `curl --resolve example.com:8443:127.0.0.1`
   makes the client send SNI to a local listener, producing `curl-8.7.1-macos-sni`. It
   forms a controlled pair with the IP-target fixture that isolates the SNI rules
   exactly:

   ```
   no SNI  t13i4906h2_0d8feac7bc37_7395dae3b2f3
   SNI     t13d4907h2_0d8feac7bc37_7395dae3b2f3
              ↑  ↑↑
              |  06 → 07   SNI counted in (a)
              i → d
           (b) and (c) identical → SNI excluded from the (c) hash
   ```

**Remaining gaps, honestly.**

- **Only curl fixtures carry oracle values so far.** The Chrome fixture still has to be
  recaptured with the new dumper (Task 1) and run through tshark. Expect a wrinkle: per
  M0 finding 5, Chrome's extension count varies 17/18 with session resumption, so its
  JA4 segment (a) is **not** stable across captures. That is a property of JA4, not a
  bug, but it means the Chrome fixture must be asserted against its own recorded oracle
  value rather than a hand-predicted one.
- **Firefox and Safari are still absent.** M3's profile database needs them. Not
  blocking for M2.
- **`bin2pcap.py` writes zero IP/TCP checksums.** tshark dissects regardless, but if a
  future tool validates checksums the script needs to compute them.

**Type consistency.** `RawExt<'a> { id, body }` (Task 3) is consumed by every function in
Task 5, matches. `is_grease(u16) -> bool` (Task 4) is used in Task 3's cipher-order test
and Task 5's `negotiated_version`, matches. `ParseError` (Task 2) is returned by
`parse_hello` (Task 3) and `fingerprint` (Task 8), matches.

---

## Execution record

Red-phase output for each task is preserved in `m2-tdd-log.txt`.

### Deviations from the plan as written

1. **Task 4 (GREASE) was executed before Task 3 (hello walk).** Task 3's Chrome
   cipher-order test calls `grease::strip`, so the dependency ran first. The plan noted
   the ordering problem but left it unresolved. This is the resolution.
2. **`ec_point_formats` was added to `ext`**, which the plan did not anticipate. JA3's
   fifth field needs it. Driven out by the JA3 oracle test failing to compile.
3. **`ja4_r` was implemented and asserted**, which the plan treated only as a debugging
   aid. Once tshark turned out to expose it, matching the pre-hash strings became a
   far stronger check than matching hashes alone, a hash-only comparison can pass with
   two compensating errors in the input lists.
4. **`ja3_string` and `ja3` are both stored on `TlsFingerprint`.** Keeping the full
   string makes an oracle mismatch diagnosable without re-deriving it.
5. **Task 9's property tests passed on first run.** There was no red phase, because
   `Reader`'s bounds checks were written in Task 2 specifically to make these hold. That
   is a design result rather than a skipped step, and it is recorded as such in the log
   rather than presented as a passing TDD cycle.

### What is verified, and by what

| Claim | Evidence |
|---|---|
| JA4 for 3 fixtures | tshark 4.4.9 `tls.handshake.ja4`, exact match |
| JA4 pre-hash lists | tshark `tls.handshake.ja4_r`, exact match on 2 fixtures |
| JA3 for 2 fixtures | tshark `tls.handshake.ja3` + `ja3_full`, exact string and hash |
| JA4 (b)/(c) hash construction | `shasum -a 256 \| cut -c1-12` on the literal strings |
| SNI counted in (a), excluded from (c) | The `curl` / `curl-sni` controlled pair |
| JA4 survives extension permutation | `ja4_is_stable_across_extension_permutation` |
| JA3 does not survive permutation | `ja3_by_contrast_does_not_survive_permutation` |
| Parser never panics | Truncation at every offset x3 fixtures, 4 proptest properties, 672k fuzz executions |

### Remaining gaps

1. **The non-alphanumeric ALPN branch is unverified.** Every fixture negotiates `h2`, so
   `alpn_chars`'s hex fallback has no test against a reference implementation. The
   implementation is a reasonable reading of the spec, is marked `NOTE:` in the source,
   and should be checked before M5 depends on it. Capturing a client that negotiates a
   non-alphanumeric ALPN would close it.
2. **Chrome's JA4 is session-dependent.** The committed fixture is a *resuming*
   handshake (18 extensions including `pre_shared_key`), giving extension count `16`. A
   fresh handshake gives `15` and therefore a different JA4. This is a property of JA4,
   not a defect, but M3's profile database must model it, see `chrome-macos.md`.
3. **Firefox and Safari fixtures are still absent.** Needed for M3's profile database.
4. **`bin2pcap.py` writes zero IP/TCP checksums.** tshark dissects regardless. A
   checksum-validating tool would need them computed.
5. **`supported_groups` is parsed but unused outside JA3.** JA4 does not consume it. It
   is retained because M3's profile database will.
