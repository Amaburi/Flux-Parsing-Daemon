# fpd M0 + M1 — Risk Spikes and the Terms Gate — Implementation Plan

> Execute task-by-task, in order. Steps use checkbox (`- [ ]`) syntax for tracking. Every task ends at a hard stop for review and commit — see the Commit Protocol below.

**Goal:** Answer the three go/no-go risk questions from spec §11 M0, then build the terms-acceptance gate that every later feature will sit behind.

**Architecture:** A Cargo workspace at `~/fpd`. Throwaway spike crates live in `spikes/` and are excluded from the workspace so they never reach CI. The gate ships as `crates/fingerprint-terms` (embedded terms text, signed acceptance record, append-only history) consumed by the `fpd` binary in `crates/fpd`. The gate check runs on raw `argv` **before** clap parsing, so no subcommand — not even argument validation — executes without acceptance.

**Tech Stack:** Rust 2021, tokio, clap 4 (derive), serde/serde_json, sha2, hmac, directories, time. Spikes only: tokio-rustls, rustls, rcgen, hyper, h2, boring. Dev: assert_cmd, tempfile, predicates.

## Global Constraints

- Rust edition 2021. Toolchain `stable` (1.91.1 at time of writing). `rust-version` in `Cargo.toml` is a provisional floor, not a verified MSRV — do not pin the toolchain channel to it, because modern transitive dependencies require far newer compilers than the floor suggests.
- Dependency versions are resolved with `cargo add`, never hand-written. Version numbers appearing in this plan's code blocks are illustrative; the resolved `Cargo.toml` is the source of truth.
- Package name on crates.io is `flux-parsing-daemon`; the installed binary is `fpd`. The crates.io name `fpd` is taken (Fiberplane Daemon v2.7.2) and is not available.
- `crates/fingerprint-terms` carries `#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used)]`. Library code returns `Result`; it never panics.
- No test in the workspace may open a network socket. Spikes are exempt — they are excluded from the workspace.
- The terms text is **never read from the filesystem at runtime**. `include_str!` only. A test enforces this (Task 9).
- The acceptance record is HMAC-tagged with a key compiled into the binary. This is tamper-*evidence* against hand-editing, not cryptography against a determined attacker who has the binary — spec §4.3 states this limit and the plan does not overclaim it.
- Config directory is overridable via `FPD_CONFIG_DIR` so tests never touch the real user config.

## Commit Protocol — read this before executing anything

**The implementer never runs `git commit` or `git push`.** The repository owner commits,
and wants one commit per task so the history is readable rather than a single bulk
commit.

Every task ends with a **STOP**. At that stop: confirm the task's tests pass, print the
suggested `git add` / `git commit` command for the owner to run, and then wait. Do not
begin the next task until the owner says to continue.

Inert git commands (`git init`, `git status`, `git diff`, `git log`) are fine to run.

---

## File Structure

```
fpd/
├── Cargo.toml                         # workspace; excludes spikes/
├── TERMS.md                           # canonical terms text (Task 2)
├── LICENSE                            # Task 10 — blocked on licence decision
├── NOTICE                             # Task 10
├── README.md                          # Task 10
├── docs/
│   ├── design/2026-08-11-fpd-design.md
│   ├── plans/2026-08-11-m0-m1-foundation-and-terms-gate.md
│   └── spikes/2026-08-11-m0-findings.md          # Task 4
├── spikes/                            # throwaway, NOT in workspace
│   ├── s1-recording-stream/
│   ├── s2-h2-replay/
│   └── s3-boring-ja4/
└── crates/
    ├── fingerprint-terms/
    │   ├── build.rs                   # computes FPD_TERMS_HASH
    │   └── src/
    │       ├── lib.rs                 # TERMS, TERMS_HASH consts
    │       ├── record.rs              # AcceptanceRecord + HMAC
    │       ├── store.rs               # read/write config dir
    │       ├── history.rs             # append-only jsonl
    │       └── gate.rs                # applies_to(argv), check()
    └── fpd/
        ├── Cargo.toml                 # package flux-parsing-daemon, bin fpd
        ├── src/
        │   ├── main.rs                # gate before clap
        │   ├── cli.rs                 # clap definitions
        │   └── commands/terms.rs      # show / accept
        └── tests/
            ├── gate.rs                # every-subcommand-refused
            └── immutability.rs        # no TERMS.md on disk
```

**Responsibility boundaries.** `record.rs` knows the shape and signature of a record but nothing about the filesystem. `store.rs` knows paths and I/O but nothing about HMAC. `gate.rs` composes them and knows the argv carve-out rules. That split is what lets Task 5's forgery tests run with no filesystem and Task 6's path tests run with no crypto.

---

# PART A — M0 Risk Spikes

Spike code is throwaway. It is committed (so the findings are reproducible) but lives outside the workspace and is never refactored into production code. Each spike answers one question and stops.

### Task 1: Workspace skeleton and spike harness

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `rust-toolchain.toml`
- Create: `spikes/s1-recording-stream/Cargo.toml`, `spikes/s1-recording-stream/src/main.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace that builds; `spikes/*` excluded from it.

- [ ] **Step 1: Create the workspace manifest**

`Cargo.toml`:

Members use a glob so Task 1 does not have to declare crates that do not exist yet;
Tasks 5 and 9 are picked up automatically as they land.

Two things bite here and both were hit during execution:

1. **A workspace glob matching nothing is a hard error** — `manifest is virtual, and the
   workspace has no members`. Task 1 therefore creates a bare `crates/fingerprint-terms`
   stub (manifest plus an empty `lib.rs`, and **no `build.rs`**, which would panic
   without `TERMS.md`). Task 5 fills it in via TDD.
2. **`cargo new` inside the repo auto-appends the new crate to `workspace.members`**,
   and an explicit member overrides `exclude`. After creating any spike, delete the line
   it added. Spike manifests must also use literal values rather than
   `edition.workspace = true` — excluded crates have no workspace root to inherit from.

```toml
[workspace]
resolver = "2"
members = ["crates/*"]
exclude = ["spikes"]

[workspace.package]
edition = "2021"
rust-version = "1.82"
authors = ["Arsyad Maulana"]

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
hmac = "0.12"
directories = "5"
time = { version = "0.3", features = ["formatting", "parsing", "macros"] }
thiserror = "2"
clap = { version = "4", features = ["derive"] }
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["clippy", "rustfmt"]
```

`.gitignore`:

```
/target
/spikes/*/target
```

- [ ] **Step 2: Create the S1 spike crate**

`spikes/s1-recording-stream/Cargo.toml`:

```toml
[package]
name = "s1-recording-stream"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = "0.23"
rcgen = "0.13"
hex = "0.4"
```

- [ ] **Step 3: Verify the workspace builds and excludes spikes**

Run: `cargo build 2>&1 | tail -5`
Expected: builds with zero members compiled (no crates yet) and **no** mention of `s1-recording-stream`.

Run: `cargo build --manifest-path spikes/s1-recording-stream/Cargo.toml`
Expected: compiles (empty main is fine at this point).

- [ ] **Step 4: STOP — hand off to the owner for commit**

`git init` may be run by the implementer (inert). Then stop and give the owner:

```bash
git add Cargo.toml rust-toolchain.toml .gitignore spikes/ docs/
git commit -m "chore: workspace skeleton with excluded spike crates"
```

Wait for the owner before starting Task 2.

---

### Task 2: Spike S1 — recover raw ClientHello under tokio-rustls

**Question:** Can a recording wrapper tee raw bytes under `tokio-rustls` while the handshake still completes, and is extension *order* recoverable from what it captured?

**Files:**
- Modify: `spikes/s1-recording-stream/src/main.rs`

**Interfaces:**
- Produces: a printed, ordered list of TLS extension IDs from a live handshake. Later consumed as evidence in Task 4's findings doc.

- [ ] **Step 1: Write the recording stream and TLS listener**

`spikes/s1-recording-stream/src/main.rs`:

```rust
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Tees every byte read from the inner stream into a shared buffer.
struct Recording<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Recording<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let new = &buf.filled()[before..];
            if !new.is_empty() {
                self.seen.lock().unwrap().extend_from_slice(new);
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Recording<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8])
        -> Poll<std::io::Result<usize>> { Pin::new(&mut self.inner).poll_write(cx, b) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}

/// Minimal ClientHello walk. Returns extension IDs in wire order.
/// Layout: record hdr(5) | hs hdr(4) | ver(2) | random(32) | sid | ciphers | comp | exts
fn extension_ids(raw: &[u8]) -> Option<Vec<u16>> {
    let mut p = 5 + 4 + 2 + 32;
    let sid = *raw.get(p)? as usize;
    p += 1 + sid;
    let cs = u16::from_be_bytes([*raw.get(p)?, *raw.get(p + 1)?]) as usize;
    p += 2 + cs;
    let comp = *raw.get(p)? as usize;
    p += 1 + comp;
    let ext_total = u16::from_be_bytes([*raw.get(p)?, *raw.get(p + 1)?]) as usize;
    p += 2;
    let end = p + ext_total;
    let mut ids = Vec::new();
    while p + 4 <= end && p + 4 <= raw.len() {
        let id = u16::from_be_bytes([raw[p], raw[p + 1]]);
        let len = u16::from_be_bytes([raw[p + 2], raw[p + 3]]) as usize;
        ids.push(id);
        p += 4 + len;
    }
    Some(ids)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["fp.local".into()])?;
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )?;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!("listening on 127.0.0.1:8443");

    loop {
        let (tcp, peer) = listener.accept().await?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let rec = Recording { inner: tcp, seen: Arc::clone(&seen) };
        match acceptor.accept(rec).await {
            Ok(_stream) => {
                let raw = seen.lock().unwrap().clone();
                println!("--- {peer} handshake OK, {} bytes recorded", raw.len());
                match extension_ids(&raw) {
                    Some(ids) => println!("extension order: {ids:?}"),
                    None => println!("PARSE FAILED"),
                }
            }
            Err(e) => println!("--- {peer} handshake FAILED: {e}"),
        }
    }
}
```

- [ ] **Step 2: Run the listener**

Run: `cargo run --manifest-path spikes/s1-recording-stream/Cargo.toml`
Expected: `listening on 127.0.0.1:8443`

- [ ] **Step 3: Drive it with curl in a second terminal**

Run: `curl -k --http1.1 https://127.0.0.1:8443/ ; true`
Expected in the listener: `handshake OK`, a non-zero byte count, and a non-empty `extension order: [...]` list.

- [ ] **Step 4: Drive it with real Chrome and confirm order varies**

Open `https://127.0.0.1:8443/` in Chrome, accept the certificate warning, then reload three times.
Expected: three `extension order` lines that contain the **same set** of IDs in **different sequences** — direct confirmation of the Chrome permutation behaviour that spec §6.9 builds the equivalence classes on.

**S1 passes if** the handshake completes AND the extension list is non-empty. If the handshake fails, the fallback is a raw TCP pre-read of the first record before handing the socket to rustls — record that outcome and move on; do not spend more than half a day here.

- [ ] **Step 5: STOP — hand off to the owner for commit**

```bash
git add spikes/s1-recording-stream/
git commit -m "spike(s1): recover raw ClientHello and extension order under tokio-rustls"
```

Wait for the owner before starting Task 3.

---

### Task 3: Spike S2 — replay a consumed h2 preface into hyper

**Question:** After manually consuming the HTTP/2 preface, SETTINGS, and HEADERS, can the same connection still be served normally?

**Files:**
- Create: `spikes/s2-h2-replay/Cargo.toml`, `spikes/s2-h2-replay/src/main.rs`

**Interfaces:**
- Consumes: the `Recording` pattern from Task 2 (copy it; spikes do not share code).
- Produces: evidence that a `Replaying` adapter lets `hyper` serve a request whose opening bytes were already read.

- [ ] **Step 1: Create the crate manifest**

`spikes/s2-h2-replay/Cargo.toml`:

```toml
[package]
name = "s2-h2-replay"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
rustls = "0.23"
rcgen = "0.13"
hyper = { version = "1", features = ["http2", "server"] }
hyper-util = { version = "0.1", features = ["tokio", "server"] }
http-body-util = "0.1"
```

- [ ] **Step 2: Write the replaying adapter and the capture-then-serve flow**

`spikes/s2-h2-replay/src/main.rs` — the load-bearing part is `Replaying`, which yields buffered bytes before falling through to the live socket:

```rust
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Yields `buf` first, then delegates to `inner`.
pub struct Replaying<S> {
    buf: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Replaying<S> {
    pub fn new(buf: Vec<u8>, inner: S) -> Self { Self { buf, pos: 0, inner } }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replaying<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let n = std::cmp::min(out.remaining(), self.buf.len() - self.pos);
            let (pos, buf) = (self.pos, &self.buf);
            out.put_slice(&buf[pos..pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replaying<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8])
        -> Poll<std::io::Result<usize>> { Pin::new(&mut self.inner).poll_write(cx, b) }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>)
        -> Poll<std::io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}
```

The `main` follows the S1 shape, with ALPN set to `h2`, and after the TLS handshake:

1. `read_exact` the 24-byte preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` into `captured`.
2. Loop reading 9-byte frame headers plus payloads, appending each to `captured`, printing `type` and — for SETTINGS — the `(id, value)` pairs in wire order, until a HEADERS frame (type `0x1`) is seen.
3. Wrap: `let stream = Replaying::new(captured, tls_stream);`
4. Serve it: `hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(stream), service)` returning a 200 with body `ok`.

- [ ] **Step 3: Run and drive with curl over HTTP/2**

Run: `cargo run --manifest-path spikes/s2-h2-replay/Cargo.toml`
Then: `curl -k --http2 -v https://127.0.0.1:8443/`

Expected: the listener prints the captured SETTINGS pairs (curl should show `3:100`, the tell described in spec §6.1), **and** curl receives `HTTP/2 200` with body `ok`.

**S2 passes if** curl gets a 200 after the preface was consumed. If hyper rejects the replayed stream, the fallback is a frame-level proxy in `serve` instead of terminating with hyper — more work, still viable. Record the outcome either way.

- [ ] **Step 4: STOP — hand off to the owner for commit**

```bash
git add spikes/s2-h2-replay/
git commit -m "spike(s2): replay consumed h2 preface into hyper"
```

Wait for the owner before starting Task 4.

---

### Task 4: Spike S3 — BoringSSL against a captured Chrome ClientHello, and the findings doc

**Question:** Can `boring` emit a ClientHello whose cipher and extension sets match a real captured Chrome?

This is the spike that decides whether emulation (M5) is in v1 or moves to v2. It compares **sorted** cipher and extension lists plus GREASE counts — not literal order, because Chrome permutes (confirmed in Task 2 Step 4) and not the JA4 hash, because a correct JA4 implementation is M2's job and throwaway code must not depend on it.

**Files:**
- Create: `spikes/s3-boring-ja4/Cargo.toml`, `spikes/s3-boring-ja4/src/main.rs`
- Create: `docs/spikes/2026-08-11-m0-findings.md`

**Interfaces:**
- Consumes: the S1 listener (run it to capture both Chrome and the boring client).
- Produces: the M0 findings document, which gates whether M5 stays in scope.

- [ ] **Step 1: Capture a real Chrome baseline**

Run the S1 listener, open `https://127.0.0.1:8443/` in Chrome, and save the printed extension list and byte dump to `docs/spikes/chrome-baseline.txt`. Extend the S1 `main` to also print the cipher list (it is at the offset the parser already walks past) and the count of GREASE values — those matching the pattern `0x?A?A` where both bytes are equal and the low nibble is `A`.

- [ ] **Step 2: Write the boring client**

`spikes/s3-boring-ja4/Cargo.toml` depends on `boring = "4"` and `tokio-boring = "4"`. `src/main.rs` builds an `SslConnector` with Chrome-shaped settings — cipher list, `set_grease_enabled(true)`, ALPN `h2,http/1.1`, TLS 1.2–1.3 — connects to `127.0.0.1:8443`, and lets the S1 listener print what arrived.

- [ ] **Step 3: Compare**

Run the S1 listener; run the boring client against it; diff the sorted cipher list, the sorted extension list, and the GREASE count against `chrome-baseline.txt`.

**S3 passes if** all three match. Partial match is a partial pass — record exactly which fields differ, because that list becomes M5's work queue.

- [ ] **Step 4: Write the findings document**

`docs/spikes/2026-08-11-m0-findings.md` — one section per spike, each recording: the question, the command run, the literal output, PASS/FAIL, and the consequence for the plan. If S3 failed, state plainly that M5 moves to v2 and that M1–M4 + M6 still ship a complete inspection-only product (spec §11).

- [ ] **Step 5: STOP — hand off to the owner for commit**

```bash
git add spikes/s3-boring-ja4/ docs/spikes/
git commit -m "spike(s3): boring vs captured Chrome; record M0 findings"
```

Wait for the owner before starting Task 5.

---

# PART B — M1 The Terms Gate

Everything from here is production code. It is built before any feature exists, so no commit in the history ever contains working functionality without the gate in front of it (spec §11).

### Task 5: TERMS.md and the embedded-terms crate

**Files:**
- Create: `TERMS.md`
- Create: `crates/fingerprint-terms/Cargo.toml`, `crates/fingerprint-terms/build.rs`, `crates/fingerprint-terms/src/lib.rs`

**Interfaces:**
- Produces: `fingerprint_terms::TERMS: &'static str`, `fingerprint_terms::TERMS_HASH: &'static str` (format `sha256:<64 hex>`).

- [ ] **Step 1: Write TERMS.md**

```markdown
# fpd — Terms of Use

fpd (Flux Parsing Daemon) measures and reproduces the TLS and HTTP/2 identity of
network clients. These terms govern how you may use it. The software licence is a
separate document (`LICENSE`) and governs the code itself.

## 1. Responsibility

Responsibility for all use of fpd rests solely and entirely with you, the user.
The author provides fpd as-is, without warranty of any kind, and accepts no
liability for any consequence of its use, including consequences the author did
not foresee.

## 2. Permitted use

- Measuring, testing, and debugging clients and servers you own or are authorised
  to test.
- Detection engineering: building, tuning, and validating bot-detection and
  anti-fraud systems.
- Interoperability, research, education, and censorship circumvention.
- Regression-testing your own software's network identity.

## 3. Prohibited use

- Accessing any system without authorisation from the party entitled to grant it.
- Circumventing access controls, rate limits, or security measures you have no
  authorisation to circumvent.
- Fraud, credential stuffing, account takeover, or misrepresenting your identity
  to obtain something you are not entitled to.
- Any use unlawful in your jurisdiction or the jurisdiction of the system you
  interact with.

## 4. Acceptance

fpd will not perform any operation until you have accepted these terms via
`fpd terms accept`. Acceptance records the version of this document you accepted.
If this document changes, acceptance is required again for the new version.

## 5. No warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR ITS USE.
```

- [ ] **Step 2: Write the manifest and build script**

`crates/fingerprint-terms/Cargo.toml`:

```toml
[package]
name = "fingerprint-terms"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
sha2 = { workspace = true }
hmac = { workspace = true }
directories = { workspace = true }
time = { workspace = true }
thiserror = { workspace = true }

[build-dependencies]
sha2 = { workspace = true }

[dev-dependencies]
tempfile = "3"
```

`crates/fingerprint-terms/build.rs`:

```rust
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let terms = PathBuf::from(&manifest).join("../../TERMS.md");
    println!("cargo:rerun-if-changed={}", terms.display());
    let bytes = fs::read(&terms)
        .unwrap_or_else(|e| panic!("TERMS.md must exist at repo root: {e}"));
    println!("cargo:rustc-env=FPD_TERMS_HASH=sha256:{:x}", Sha256::digest(&bytes));
}
```

- [ ] **Step 3: Write the failing test**

`crates/fingerprint-terms/src/lib.rs`:

```rust
#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_text_is_embedded_and_non_empty() {
        assert!(TERMS.contains("Responsibility for all use of fpd rests solely"));
        assert!(TERMS.len() > 500);
    }

    #[test]
    fn terms_hash_matches_the_embedded_text() {
        use sha2::{Digest, Sha256};
        let expected = format!("sha256:{:x}", Sha256::digest(TERMS.as_bytes()));
        assert_eq!(TERMS_HASH, expected);
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cargo test -p fingerprint-terms`
Expected: FAIL — `cannot find value TERMS in this scope`.

- [ ] **Step 5: Add the constants**

At the top of `lib.rs`, above the test module:

```rust
/// The canonical terms text, compiled into the binary. Never read from disk.
pub const TERMS: &str = include_str!("../../../TERMS.md");

/// SHA-256 of `TERMS`, computed by build.rs. Format: `sha256:<hex>`.
pub const TERMS_HASH: &str = env!("FPD_TERMS_HASH");
```

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test -p fingerprint-terms`
Expected: 2 passed. The second test is the CI check that `build.rs` and the source can never drift apart.

- [ ] **Step 7: STOP — hand off to the owner for commit**

```bash
git add TERMS.md crates/fingerprint-terms/
git commit -m "feat(terms): embed canonical terms text with build-time hash"
```

Wait for the owner before starting Task 6.

---

### Task 6: The acceptance record and its HMAC tag

**Files:**
- Create: `crates/fingerprint-terms/src/record.rs`
- Modify: `crates/fingerprint-terms/src/lib.rs`

**Interfaces:**
- Consumes: `TERMS_HASH` from Task 5.
- Produces: `AcceptanceRecord { terms_version, fpd_version, accepted_at, sig }`, `AcceptanceRecord::new(fpd_version: &str) -> Self`, `AcceptanceRecord::verify(&self) -> bool`.

Pure logic only — no filesystem. That is what makes the forgery tests run without I/O.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-terms/src/record.rs`:

```rust
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_record_verifies() {
        assert!(AcceptanceRecord::new("0.1.0").verify());
    }

    #[test]
    fn an_edited_terms_version_fails_verification() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.terms_version = "sha256:0000000000000000".into();
        assert!(!r.verify(), "hand-edited record must not verify");
    }

    #[test]
    fn an_edited_timestamp_fails_verification() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.accepted_at = "1999-01-01T00:00:00Z".into();
        assert!(!r.verify());
    }

    #[test]
    fn a_stripped_signature_fails_verification() {
        let mut r = AcceptanceRecord::new("0.1.0");
        r.sig = String::new();
        assert!(!r.verify());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-terms record`
Expected: FAIL — `cannot find struct AcceptanceRecord`.

- [ ] **Step 3: Implement the record**

Above the test module in `record.rs`:

```rust
/// Compiled-in key. This provides tamper-EVIDENCE against hand-editing the
/// record file; it is not secret from anyone holding the binary, and spec §4.3
/// makes no claim that it is.
const RECORD_KEY: &[u8] = b"fpd-acceptance-v1-9a3f2c7e41b8";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptanceRecord {
    pub terms_version: String,
    pub fpd_version: String,
    pub accepted_at: String,
    pub sig: String,
}

impl AcceptanceRecord {
    pub fn new(fpd_version: &str) -> Self {
        let accepted_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
        let mut r = Self {
            terms_version: crate::TERMS_HASH.to_string(),
            fpd_version: fpd_version.to_string(),
            accepted_at,
            sig: String::new(),
        };
        r.sig = r.compute_sig();
        r
    }

    fn payload(&self) -> String {
        format!("{}|{}|{}", self.terms_version, self.fpd_version, self.accepted_at)
    }

    fn compute_sig(&self) -> String {
        match Hmac::<Sha256>::new_from_slice(RECORD_KEY) {
            Ok(mut m) => {
                m.update(self.payload().as_bytes());
                format!("hmac-sha256:{:x}", m.finalize().into_bytes())
            }
            Err(_) => String::new(),
        }
    }

    /// True only if the signature matches AND the record is for the terms text
    /// compiled into this binary.
    pub fn verify(&self) -> bool {
        !self.sig.is_empty()
            && self.sig == self.compute_sig()
            && self.terms_version == crate::TERMS_HASH
    }
}
```

Add `pub mod record;` to `lib.rs`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p fingerprint-terms record`
Expected: 4 passed.

- [ ] **Step 5: STOP — hand off to the owner for commit**

```bash
git add crates/fingerprint-terms/src/
git commit -m "feat(terms): HMAC-tagged acceptance record with forgery detection"
```

Wait for the owner before starting Task 7.

---

### Task 7: Record store and append-only history

**Files:**
- Create: `crates/fingerprint-terms/src/store.rs`, `crates/fingerprint-terms/src/history.rs`
- Modify: `crates/fingerprint-terms/src/lib.rs`

**Interfaces:**
- Consumes: `AcceptanceRecord` from Task 6.
- Produces: `config_dir() -> Result<PathBuf, TermsError>`, `load(&Path) -> Option<AcceptanceRecord>`, `save(&Path, &AcceptanceRecord) -> Result<(), TermsError>`, `history::append(&Path, &AcceptanceRecord, source: &str) -> Result<(), TermsError>`.

`load` returns `Option`, not `Result` — a missing file, an unreadable file, and malformed JSON are all simply "not accepted". This is the design point that makes deletion lock a user out rather than let them through.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-terms/src/store.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::AcceptanceRecord;

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = AcceptanceRecord::new("0.1.0");
        save(dir.path(), &r).expect("save");
        let back = load(dir.path()).expect("should load");
        assert_eq!(back.sig, r.sig);
        assert!(back.verify());
    }

    #[test]
    fn a_missing_file_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load(dir.path()).is_none());
    }

    #[test]
    fn deleting_the_record_locks_out_rather_than_admits() {
        let dir = tempfile::tempdir().expect("tempdir");
        save(dir.path(), &AcceptanceRecord::new("0.1.0")).expect("save");
        std::fs::remove_file(record_path(dir.path())).expect("remove");
        assert!(load(dir.path()).is_none(), "deletion must revoke, never grant");
    }

    #[test]
    fn malformed_json_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(record_path(dir.path()), b"{ not json").expect("write");
        assert!(load(dir.path()).is_none());
    }

    #[test]
    fn config_dir_honours_the_env_override() {
        std::env::set_var("FPD_CONFIG_DIR", "/tmp/fpd-test-override");
        assert_eq!(config_dir().expect("dir"), std::path::PathBuf::from("/tmp/fpd-test-override"));
        std::env::remove_var("FPD_CONFIG_DIR");
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-terms store`
Expected: FAIL — `cannot find function save`.

- [ ] **Step 3: Implement the store**

Above the tests in `store.rs`:

```rust
use crate::record::AcceptanceRecord;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum TermsError {
    #[error("cannot determine config directory")]
    NoConfigDir,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub fn config_dir() -> Result<PathBuf, TermsError> {
    if let Ok(p) = std::env::var("FPD_CONFIG_DIR") {
        return Ok(PathBuf::from(p));
    }
    directories::ProjectDirs::from("", "", "fpd")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or(TermsError::NoConfigDir)
}

pub fn record_path(dir: &Path) -> PathBuf { dir.join("terms-accepted") }

pub fn save(dir: &Path, r: &AcceptanceRecord) -> Result<(), TermsError> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(record_path(dir), serde_json::to_vec_pretty(r)?)?;
    Ok(())
}

/// Any failure — missing, unreadable, malformed, or unverifiable — reads as
/// "not accepted". There is no path by which removing a file grants access.
pub fn load(dir: &Path) -> Option<AcceptanceRecord> {
    let bytes = std::fs::read(record_path(dir)).ok()?;
    let r: AcceptanceRecord = serde_json::from_slice(&bytes).ok()?;
    r.verify().then_some(r)
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p fingerprint-terms store`
Expected: 5 passed.

- [ ] **Step 5: Write the failing history test**

`crates/fingerprint-terms/src/history.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::AcceptanceRecord;

    #[test]
    fn appending_never_truncates_prior_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        append(dir.path(), &AcceptanceRecord::new("0.1.0"), "interactive").expect("1");
        append(dir.path(), &AcceptanceRecord::new("0.2.0"), "env").expect("2");
        let text = std::fs::read_to_string(history_path(dir.path())).expect("read");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("0.1.0"));
        assert!(lines[1].contains("\"source\":\"env\""));
    }
}
```

- [ ] **Step 6: Implement history**

```rust
use crate::record::AcceptanceRecord;
use crate::store::TermsError;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn history_path(dir: &Path) -> PathBuf { dir.join("terms-history.jsonl") }

/// Opens in append mode only. Never truncates, never rewrites.
pub fn append(dir: &Path, r: &AcceptanceRecord, source: &str) -> Result<(), TermsError> {
    std::fs::create_dir_all(dir)?;
    let mut line = serde_json::to_value(r)?;
    if let Some(o) = line.as_object_mut() {
        o.insert("source".into(), serde_json::Value::String(source.into()));
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path(dir))?;
    writeln!(f, "{}", serde_json::to_string(&line)?)?;
    Ok(())
}
```

Add `pub mod store; pub mod history;` to `lib.rs`.

- [ ] **Step 7: Run the full crate suite**

Run: `cargo test -p fingerprint-terms`
Expected: all passed.

- [ ] **Step 8: STOP — hand off to the owner for commit**

```bash
git add crates/fingerprint-terms/src/
git commit -m "feat(terms): record store and append-only acceptance history"
```

Wait for the owner before starting Task 8.

---

### Task 8: The gate — argv carve-outs and the check

**Files:**
- Create: `crates/fingerprint-terms/src/gate.rs`
- Modify: `crates/fingerprint-terms/src/lib.rs`

**Interfaces:**
- Consumes: `store::load`, `store::config_dir`.
- Produces: `gate::applies_to(argv: &[String]) -> bool`, `gate::check(dir: &Path) -> Result<(), GateRefusal>`, `GateRefusal::message() -> String`.

The gate reads raw `argv` rather than parsed clap output, so it runs before argument validation. A subcommand with a usage error still cannot execute anything.

- [ ] **Step 1: Write the failing tests**

`crates/fingerprint-terms/src/gate.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> { a.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn bare_invocation_is_gated() {
        assert!(applies_to(&argv(&[])));
    }

    #[test]
    fn ordinary_subcommands_are_gated() {
        for c in ["serve", "tui", "check", "capture", "emulate"] {
            assert!(applies_to(&argv(&[c])), "{c} must be gated");
        }
    }

    #[test]
    fn only_terms_help_and_version_are_carved_out() {
        assert!(!applies_to(&argv(&["terms"])));
        assert!(!applies_to(&argv(&["terms", "accept"])));
        assert!(!applies_to(&argv(&["--help"])));
        assert!(!applies_to(&argv(&["-h"])));
        assert!(!applies_to(&argv(&["--version"])));
        assert!(!applies_to(&argv(&["-V"])));
    }

    #[test]
    fn help_flag_after_a_gated_subcommand_is_still_carved_out() {
        assert!(!applies_to(&argv(&["serve", "--help"])));
    }

    #[test]
    fn check_refuses_when_no_record_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(check(dir.path()).is_err());
    }

    #[test]
    fn check_passes_after_a_valid_record_is_saved() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::store::save(dir.path(), &crate::record::AcceptanceRecord::new("0.1.0"))
            .expect("save");
        assert!(check(dir.path()).is_ok());
    }

    #[test]
    fn the_refusal_message_names_the_accept_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let msg = check(dir.path()).expect_err("must refuse").message();
        assert!(msg.contains("must accept the terms and conditions first"));
        assert!(msg.contains("fpd terms accept"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p fingerprint-terms gate`
Expected: FAIL — `cannot find function applies_to`.

- [ ] **Step 3: Implement the gate**

```rust
use std::path::Path;

const CARVE_OUT_COMMANDS: &[&str] = &["terms"];
const CARVE_OUT_FLAGS: &[&str] = &["--help", "-h", "--version", "-V"];

/// True when this invocation must be blocked pending acceptance.
pub fn applies_to(argv: &[String]) -> bool {
    if argv.iter().any(|a| CARVE_OUT_FLAGS.contains(&a.as_str())) {
        return false;
    }
    match argv.first() {
        Some(first) => !CARVE_OUT_COMMANDS.contains(&first.as_str()),
        None => true,
    }
}

#[derive(Debug)]
pub struct GateRefusal;

impl GateRefusal {
    pub fn message(&self) -> String {
        "fpd: you must accept the terms and conditions first.\n\n  \
         This tool can both measure and reproduce TLS/HTTP-2 client identities.\n  \
         Responsibility for how it is used rests solely with you, not the author.\n\n  \
         Read them:    fpd terms show\n  \
         Accept them:  fpd terms accept\n"
            .to_string()
    }
}

/// `FPD_ACCEPT_TERMS=1` is an acceptance mechanism for CI, not an exemption —
/// callers record it to history exactly as an interactive acceptance.
pub fn check(dir: &Path) -> Result<(), GateRefusal> {
    if std::env::var("FPD_ACCEPT_TERMS").as_deref() == Ok("1") {
        return Ok(());
    }
    crate::store::load(dir).map(|_| ()).ok_or(GateRefusal)
}
```

Add `pub mod gate;` to `lib.rs`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p fingerprint-terms`
Expected: all passed.

- [ ] **Step 5: STOP — hand off to the owner for commit**

```bash
git add crates/fingerprint-terms/src/
git commit -m "feat(terms): argv-level gate with terms/help/version carve-outs"
```

Wait for the owner before starting Task 9.

---

### Task 9: The `fpd` binary — gate before clap, and `fpd terms`

**Files:**
- Create: `crates/fpd/Cargo.toml`, `crates/fpd/src/main.rs`, `crates/fpd/src/cli.rs`, `crates/fpd/src/commands/mod.rs`, `crates/fpd/src/commands/terms.rs`
- Create: `crates/fpd/tests/gate.rs`, `crates/fpd/tests/immutability.rs`

**Interfaces:**
- Consumes: `fingerprint_terms::{gate, store, history, record, TERMS, TERMS_HASH}`.
- Produces: the `fpd` binary. Every later milestone adds subcommands to `cli.rs`; none of them add gate code, because Task 8's check is applied once in `main`.

- [ ] **Step 1: Write the manifest**

`crates/fpd/Cargo.toml`:

```toml
[package]
name = "flux-parsing-daemon"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
description = "fpd — TLS/HTTP-2 fingerprint inspection and verified emulation"

[[bin]]
name = "fpd"
path = "src/main.rs"

[dependencies]
fingerprint-terms = { path = "../fingerprint-terms" }
clap = { workspace = true }

[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
```

- [ ] **Step 2: Write the failing integration tests**

`crates/fpd/tests/gate.rs`:

```rust
use assert_cmd::Command;
use tempfile::TempDir;

fn fpd(dir: &TempDir) -> Command {
    let mut c = Command::cargo_bin("fpd").expect("binary");
    c.env("FPD_CONFIG_DIR", dir.path()).env_remove("FPD_ACCEPT_TERMS");
    c
}

/// Enumerates real subcommands so a future one cannot silently escape the gate.
const GATED: &[&str] = &["serve", "tui", "check", "capture", "emulate"];

#[test]
fn every_gated_subcommand_refuses_without_acceptance() {
    let dir = TempDir::new().expect("tempdir");
    for sub in GATED {
        fpd(&dir).arg(sub).assert().code(1)
            .stderr(predicates::str::contains("must accept the terms and conditions first"));
    }
}

#[test]
fn bare_invocation_refuses() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir).assert().code(1)
        .stderr(predicates::str::contains("must accept the terms and conditions first"));
}

#[test]
fn accepting_then_running_a_subcommand_passes_the_gate() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir).args(["terms", "accept"]).assert().success();
    fpd(&dir).arg("serve").assert()
        .stderr(predicates::str::contains("must accept").not());
}

#[test]
fn env_acceptance_satisfies_the_gate() {
    let dir = TempDir::new().expect("tempdir");
    Command::cargo_bin("fpd").expect("binary")
        .env("FPD_CONFIG_DIR", dir.path())
        .env("FPD_ACCEPT_TERMS", "1")
        .arg("serve").assert()
        .stderr(predicates::str::contains("must accept").not());
}

#[test]
fn terms_show_works_without_acceptance() {
    let dir = TempDir::new().expect("tempdir");
    fpd(&dir).args(["terms", "show"]).assert().success()
        .stdout(predicates::str::contains("Responsibility for all use of fpd"));
}
```

`crates/fpd/tests/immutability.rs`:

```rust
use assert_cmd::Command;
use tempfile::TempDir;

/// Runs from an empty directory with no TERMS.md anywhere in sight. The text
/// must be identical, proving nothing is read from disk at runtime.
#[test]
fn terms_text_is_identical_with_no_terms_md_on_disk() {
    let cwd = TempDir::new().expect("tempdir");
    let cfg = TempDir::new().expect("tempdir");
    assert!(!cwd.path().join("TERMS.md").exists());

    let out = Command::cargo_bin("fpd").expect("binary")
        .current_dir(cwd.path())
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show"])
        .output().expect("run");

    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.trim_end(), fingerprint_terms::TERMS.trim_end());
}

/// A decoy TERMS.md in the working directory must not change the output.
#[test]
fn an_on_disk_terms_md_is_ignored() {
    let cwd = TempDir::new().expect("tempdir");
    let cfg = TempDir::new().expect("tempdir");
    std::fs::write(cwd.path().join("TERMS.md"), "YOU MAY DO ANYTHING").expect("write");

    let out = Command::cargo_bin("fpd").expect("binary")
        .current_dir(cwd.path())
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show"])
        .output().expect("run");

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("YOU MAY DO ANYTHING"));
    assert!(text.contains("Responsibility for all use of fpd"));
}

#[test]
fn reported_hash_matches_the_embedded_text() {
    let cfg = TempDir::new().expect("tempdir");
    Command::cargo_bin("fpd").expect("binary")
        .env("FPD_CONFIG_DIR", cfg.path())
        .args(["terms", "show", "--hash"])
        .assert().success()
        .stdout(predicates::str::contains(fingerprint_terms::TERMS_HASH));
}
```

Add `fingerprint-terms = { path = "../fingerprint-terms" }` to `[dev-dependencies]` as well so the tests can reference the constants.

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test -p flux-parsing-daemon`
Expected: FAIL — no binary target compiles yet.

- [ ] **Step 4: Write the CLI definitions**

`crates/fpd/src/cli.rs`:

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fpd", version, about = "Flux Parsing Daemon — TLS/HTTP-2 fingerprint inspection and verified emulation")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show or accept the terms of use
    Terms {
        #[command(subcommand)]
        action: TermsAction,
    },
    /// Reverse proxy that annotates inbound traffic  (M4)
    Serve,
    /// Live fingerprint dashboard  (M6)
    Tui,
    /// Check a client against a browser profile  (M3)
    Check,
    /// Record a browser profile  (M3)
    Capture,
    /// Emulate a captured profile  (M5)
    Emulate,
}

#[derive(Subcommand)]
pub enum TermsAction {
    /// Print the terms text
    Show {
        /// Print only the terms hash
        #[arg(long)]
        hash: bool,
    },
    /// Record acceptance of the terms
    Accept,
}
```

Subcommands other than `Terms` are declared now and print `not yet implemented (see milestone)` — they exist so the gate tests enumerate real commands from day one.

- [ ] **Step 5: Write the terms command**

`crates/fpd/src/commands/terms.rs`:

```rust
use fingerprint_terms::{history, record::AcceptanceRecord, store, TERMS, TERMS_HASH};

pub fn show(hash_only: bool) {
    if hash_only {
        println!("{TERMS_HASH}");
    } else {
        println!("{TERMS}");
        println!("\nterms hash: {TERMS_HASH}");
    }
}

pub fn accept() -> Result<(), Box<dyn std::error::Error>> {
    let dir = store::config_dir()?;
    let rec = AcceptanceRecord::new(env!("CARGO_PKG_VERSION"));
    store::save(&dir, &rec)?;
    history::append(&dir, &rec, "interactive")?;
    println!("Terms accepted.");
    println!("  version:  {}", rec.terms_version);
    println!("  recorded: {}", dir.join("terms-accepted").display());
    Ok(())
}
```

`crates/fpd/src/commands/mod.rs`: `pub mod terms;`

- [ ] **Step 6: Wire the gate into main, ahead of clap**

`crates/fpd/src/main.rs`:

```rust
mod cli;
mod commands;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    // The gate runs on raw argv, BEFORE clap. A subcommand with a usage error
    // still executes nothing. This is the only gate call site in the codebase.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if fingerprint_terms::gate::applies_to(&argv) {
        let dir = match fingerprint_terms::store::config_dir() {
            Ok(d) => d,
            Err(e) => { eprintln!("fpd: {e}"); return ExitCode::FAILURE; }
        };
        if let Err(refusal) = fingerprint_terms::gate::check(&dir) {
            eprint!("{}", refusal.message());
            return ExitCode::FAILURE;
        }
    }

    let parsed = cli::Cli::parse();
    match parsed.command {
        Some(cli::Command::Terms { action }) => match action {
            cli::TermsAction::Show { hash } => commands::terms::show(hash),
            cli::TermsAction::Accept => {
                if let Err(e) = commands::terms::accept() {
                    eprintln!("fpd: {e}");
                    return ExitCode::FAILURE;
                }
            }
        },
        Some(cli::Command::Serve) => println!("serve: not yet implemented (M4)"),
        Some(cli::Command::Tui) => println!("tui: not yet implemented (M6)"),
        Some(cli::Command::Check) => println!("check: not yet implemented (M3)"),
        Some(cli::Command::Capture) => println!("capture: not yet implemented (M3)"),
        Some(cli::Command::Emulate) => println!("emulate: not yet implemented (M5)"),
        None => {
            // Unreachable in practice: bare argv is gated above.
            eprintln!("fpd: no command given; try `fpd --help`");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}
```

- [ ] **Step 7: Run to verify all tests pass**

Run: `cargo test --workspace`
Expected: all `fingerprint-terms` unit tests plus 5 gate tests and 3 immutability tests pass.

- [ ] **Step 8: Manually confirm the exact refusal from the spec**

Run: `FPD_CONFIG_DIR=/tmp/fpd-manual cargo run -p flux-parsing-daemon --bin fpd -- serve`
Expected: the §4.2 message on stderr, exit code 1.

Run: `FPD_CONFIG_DIR=/tmp/fpd-manual cargo run -p flux-parsing-daemon --bin fpd -- terms accept`
Then re-run the `serve` command.
Expected: `serve: not yet implemented (M4)`.

- [ ] **Step 9: STOP — hand off to the owner for commit**

```bash
git add crates/fpd/
git commit -m "feat(fpd): gate every invocation on terms acceptance before clap parsing"
```

Wait for the owner before starting Task 10.

---

### Task 10: Licence, NOTICE, README, and CI

**Blocked on one decision:** which licence. Everything else in this task is independent of that choice — only the content of `LICENSE` and one paragraph of `NOTICE` change. Do the rest first if the decision is outstanding.

**Files:**
- Create: `LICENSE`, `NOTICE`, `README.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `TERMS_HASH` (published as the canonical value).
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write NOTICE**

```
fpd — Flux Parsing Daemon
Copyright (c) 2026 Arsyad Maulana

This software measures and reproduces the TLS and HTTP/2 identity of network
clients. Responsibility for all use rests solely with the user, not the author.
The author accepts no liability for any consequence of its use.

Use is governed by TERMS.md, which is compiled into every binary and is
displayed by `fpd terms show`.

This notice must be retained in all copies and derivative works.
```

- [ ] **Step 2: Write LICENSE**

Place the chosen licence text verbatim. If Elastic License 2.0: copy the canonical text from https://www.elastic.co/licensing/elastic-license, substituting `fpd` as the licensed work and the author's name as licensor. Do not paraphrase licence text.

- [ ] **Step 3: Write README.md**

Above the fold, in this order: the one-line description; the current `TERMS_HASH` labelled as the canonical value to verify a binary against; the licence position (source-available, readable and cloneable, redistribution and notice-removal forbidden); a link to `TERMS.md`; then build and run instructions. Include the §4.3 honest statement — that a determined user can rebuild without the gate, that this cannot be prevented, and that doing so is a deliberate, detectable licence breach.

- [ ] **Step 4: Write the CI workflow**

`.github/workflows/ci.yml` runs on push and PR: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`. Spikes are excluded from the workspace so they never run in CI.

- [ ] **Step 5: Verify CI passes locally**

Run: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: clean.

- [ ] **Step 6: STOP — hand off to the owner for commit**

```bash
git add LICENSE NOTICE README.md .github/
git commit -m "docs: licence, notice, readme, and CI"
```

This is the final task in the plan.

---

## Self-Review

**Spec coverage for M0 + M1.** §11 M0 S1 → Task 2. S2 → Task 3. S3 → Task 4. §4.1.1 layer 1 (`include_str!`, nothing read from disk) → Task 5 + Task 9 immutability tests. Layer 2 (build.rs hash, published canonical value) → Task 5 Step 2, Task 10 Step 3. Layer 3 (notice retention) → Task 10 Steps 1–2. §4.2 gate in `main()` before dispatch → Task 9 Step 6. Carve-outs → Task 8. HMAC record, forgery rejected → Task 6. Deletion locks out → Task 7. Append-only history → Task 7. `FPD_ACCEPT_TERMS` recorded not exempt → Task 8 + Task 9. §9.6 gate tests → Task 9. §9.7 immutability tests → Task 9.

**Not in this plan, by design:** M2–M6. Each gets its own plan. The next one is M2 (`fingerprint-core` TLS parsing, JA3/JA4, fixture harness), which should be written after the M0 findings land, because a failed S3 changes whether M5 stays in v1.

**Known gap, deliberate:** Task 9's `GATED` list in `tests/gate.rs` is written by hand rather than derived from clap introspection. Deriving it would require exposing `Cli` from a library target. When M2 adds the first real subcommand, convert `crates/fpd/src/cli.rs` into a `lib.rs` target and replace the constant with an enumeration over `Cli::command().get_subcommands()`. Until then, the hand-written list covers every declared subcommand and the plan records the debt rather than hiding it.

**Type consistency check:** `AcceptanceRecord::new(&str)` (Task 6) is called with `env!("CARGO_PKG_VERSION")` in Task 9 — matches. `store::load(&Path) -> Option<AcceptanceRecord>` (Task 7) is consumed by `gate::check` (Task 8) via `.map(|_| ()).ok_or(...)` — matches. `history::append(&Path, &AcceptanceRecord, &str)` (Task 7) is called with `"interactive"` in Task 9 — matches. `gate::applies_to(&[String])` (Task 8) is called with `Vec<String>` in Task 9 — matches via deref.
