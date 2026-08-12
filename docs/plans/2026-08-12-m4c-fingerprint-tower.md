# fpd M4c, `fingerprint-tower`

> Execute task-by-task. Every task ends at a hard stop for review and commit.

**Goal:** Fingerprinting inside a Rust application, with no separate process and no extra network hop.

**Why it exists separately from `serve`:** `serve` is a sidecar. It works with any language, but it costs a process, a localhost hop, and something extra to deploy and keep alive. A Rust application does not need any of that. One line changes at the TLS accept point and the fingerprint appears in request extensions.

**Architecture:** A new crate `crates/fingerprint-tower`. An `Acceptor` wraps `tokio_rustls::TlsAcceptor`, tees the handshake, captures the HTTP/2 preamble, and hands back both the stream and the fingerprint. A tower `Layer` then puts the fingerprint into every request on that connection.

## The constraint that forces this design

**This cannot be HTTP middleware.** By the time a request reaches axum, rustls has
finished the handshake and discarded the ClientHello. Extension order and GREASE
placement, the two things a fingerprint needs, are gone.

So the hook has to sit at the TLS accept layer, below HTTP entirely. That is why the API
is an `Acceptor` replacement rather than a `.layer(...)` call on the router, and why the
one line that changes is the one that builds the acceptor.

```rust
// before
let acceptor = TlsAcceptor::from(config);

// after
let acceptor = fingerprint_tower::Acceptor::new(config);
```

## Global Constraints

- Reuses `RecordingStream`, `Replaying`, and the whole probe pipeline. Nothing is reimplemented.
- `user-agent` remains the only header value read.
- No test may depend on a network beyond loopback.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Stop at each task, print the command, wait.

---

### Task 1: The acceptor

**Files:** `crates/fingerprint-tower/Cargo.toml`, `src/lib.rs`, `src/acceptor.rs`

**Interfaces:** `Acceptor::new(Arc<rustls::ServerConfig>)`, `Acceptor::with_profiles(ProfileDb)`, `Acceptor::accept(S) -> Result<Accepted<S>, Error>`, `Accepted { stream, fingerprint, is_h2 }`, `ClientFingerprint` (cheap to clone).

- [ ] Capture path identical to `serve`: tee, handshake, capture preamble when ALPN is h2, wrap in `Replaying` so hyper sees the bytes it expects.
- [ ] `ClientFingerprint` is `Clone` and cheap, because it is cloned into every request on the connection. The full `ClientReport` sits behind an `Arc` for callers who want the detail.
- [ ] **A handshake that fails must return an error, not a fingerprint.** Unlike the probe, there is no connection left to serve, so there is nothing useful to hand back.
- [ ] Tests: a real curl connection through the acceptor yields the committed JA4 oracle, an h2 connection is still fully serveable afterwards, a client that never completes the handshake errors rather than hanging.
- [ ] STOP, commit.

---

### Task 2: The tower layer

**Files:** `crates/fingerprint-tower/src/layer.rs`

**Interfaces:** `FingerprintLayer::new(ClientFingerprint)`, `FingerprintService<S>`.

- [ ] Inserts the fingerprint into `req.extensions_mut()` and calls the inner service.
- [ ] Tests: the extension is present in the handler. It survives across several requests on one connection, since HTTP/2 multiplexes and the fingerprint is per connection rather than per request.
- [ ] STOP, commit.

---

### Task 3: The real use case, end to end

**Files:** `crates/fingerprint-tower/tests/axum_live.rs`

axum as a dev-dependency only. The crate itself must not depend on axum, but the test
should prove the actual thing a user will write.

- [ ] An axum handler extracting `Extension<ClientFingerprint>` and returning the JA4.
- [ ] Drive it with real curl, assert the response body equals the committed oracle.
- [ ] Assert a lying User-Agent surfaces as a mismatch inside the handler.
- [ ] **Assert no extra process and no extra listener exist**, which is the whole point:
      one bind, one process.
- [ ] STOP, commit.

---

### Task 4: Docs

- [ ] README: the embedded option, next to `serve`, with the trade-off stated plainly.
      `serve` is any language and costs a hop. `tower` is Rust only and costs nothing.
- [ ] Status table.
- [ ] STOP, commit.

---

## Self-Review

**Spec coverage.** §6.6 `fingerprint-tower` and the one-line change maps to Tasks 1 and 2.

**Known risks.**
1. **A per-connection fingerprint on a multiplexed protocol.** HTTP/2 carries many
   requests on one connection, and they all share one fingerprint. That is correct, since
   the fingerprint describes the client rather than the request, but a reader may expect
   per-request values and should be told otherwise in the docs.
2. **The user still owns the accept loop.** This crate cannot enforce timeouts or
   connection limits the way `serve` does, because it does not own the listener. The docs
   must say so rather than let someone assume they inherit `serve`'s bounds.
3. **Rust only.** Nothing about this helps a Python or Go service, and the README should
   not let that be discovered late.
