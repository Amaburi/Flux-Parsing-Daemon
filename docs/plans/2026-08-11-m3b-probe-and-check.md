# fpd M3b — The Probe, the Profile Database, and `fpd check`

> Execute task-by-task, in order. Steps use checkbox (`- [ ]`) syntax. Every task ends at a hard stop for review and commit.

**Goal:** Ship the first command anyone would actually run. `fpd check` starts a local probe, runs the user's client against it, and prints a field-level diff against a stored browser profile, exiting non-zero on mismatch.

**Architecture:** A new crate `fingerprint-probe` holds everything that touches a socket, keeping `fingerprint-core` and `fingerprint-h2` pure. A `ClientReport` joins the TLS and HTTP/2 fingerprints for one connection. Profiles are JSON files carrying equivalence classes derived from the M0 findings, and the diff engine compares a report against a profile under those classes.

**Tech Stack:** tokio, tokio-rustls, rustls, rcgen, serde/serde_json, clap. Dev: assert_cmd, tempfile.

## Global Constraints

- `fingerprint-core` and `fingerprint-h2` stay pure. Nothing in this milestone adds I/O to them.
- `fingerprint-probe` may open sockets, but **only on loopback** and only on ephemeral ports unless explicitly configured.
- Dependency versions via `cargo add`.
- Every fingerprint value asserted in tests comes from a committed fixture or its recorded oracle, never from a fresh live capture at test time.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Every task ends at a STOP:
confirm tests pass, print the suggested commit command, wait.

---

## Assumptions from earlier milestones that stop holding here

Three constraints carried M1 through M3a. Each one has to be relaxed deliberately rather
than quietly.

**1. "No test may open a socket."** That was right for pure parsing crates and it kept
the suite at millisecond speed. `fingerprint-probe` exists to open sockets, so it cannot
hold. The replacement rule: **unit tests stay socket-free, integration tests may bind
loopback on an ephemeral port.** Integration tests live in `tests/` and are the only
place a listener appears. If a unit test needs a connection, the design is wrong and the
logic should move behind a trait instead.

**2. "No randomness or clock in tests."** The probe generates a self-signed certificate
at startup, which uses both. Certificate generation is confined to the probe's
constructor and is never part of a fingerprint comparison, so determinism is preserved
where it matters. Tests assert on fingerprints, never on certificates.

**3. "Fixtures are the only source of truth."** Still true for expected values. But
`check` must capture a *live* connection to work at all, so integration tests drive a
real curl against a real probe. The assertion is then made against the committed oracle
for that client, which keeps the expected side fixture-derived even though the observed
side is live.

## Carried forward, still unresolved

- **The `fluke-hpack` panic (M3a).** Contained by `catch_unwind`, not fixed. It is
  network-reachable through this milestone's probe for the first time. Task 8 revisits it.
- **JA4H remains unimplemented.** No specification in hand and no oracle. `check` will
  diff TLS and HTTP/2 only, and must not imply otherwise in its output.

---

## File Structure

```
crates/fingerprint-probe/
├── src/
│   ├── lib.rs         # ClientReport
│   ├── recording.rs   # RecordingStream, the byte tee
│   ├── probe.rs       # TLS listener, capture, one-shot and serve modes
│   ├── profile.rs     # Profile format, load and save, shipped set
│   └── diff.rs        # equivalence classes and field-level diff
├── profiles/          # shipped profile JSON, generated from M2/M3a fixtures
└── tests/
    ├── probe_live.rs  # binds loopback, drives real curl
    └── diff_cases.rs  # pure, fixture-driven

crates/fpd/src/commands/{check.rs,capture.rs}
```

**Boundaries.** `recording.rs` knows bytes and nothing else. `probe.rs` knows sockets and
produces a `ClientReport`. `profile.rs` and `diff.rs` are pure and never see a socket,
which is what lets the whole diff engine be tested from fixtures.

---

### Task 1: `RecordingStream` and the probe

**Files:** `crates/fingerprint-probe/Cargo.toml`, `src/lib.rs`, `src/recording.rs`, `src/probe.rs`

**Interfaces:**
- Produces: `RecordingStream<S>`, `Probe::bind() -> Result<Probe>`, `Probe::url() -> String`, `Probe::accept_one() -> Result<ClientReport>`, `ClientReport { tls: TlsFingerprint, h2: Option<H2Fingerprint>, alpn: Option<String> }`.

The M0 S1 and S2 spikes proved both halves of this. `RecordingStream` is the spike's tee
made production grade, and the h2 capture is the S2 flow minus the replay, since `check`
never needs to serve the connection.

- [ ] **Step 1: Create the crate**

```bash
cargo new --lib --vcs none crates/fingerprint-probe   # remove the workspace member line it adds
cd crates/fingerprint-probe
cargo add --path ../fingerprint-core
cargo add --path ../fingerprint-h2
cargo add tokio --features net,io-util,rt,macros,time
cargo add tokio-rustls rustls rcgen serde serde_json thiserror
cargo add --dev tempfile
```

- [ ] **Step 2: Write the failing `RecordingStream` tests**

These are pure. `tokio_test::io::Builder` supplies a scripted reader, so no socket is
involved.

```rust
#[tokio::test]
async fn records_every_byte_that_is_read() {
    let inner = tokio_test::io::Builder::new().read(b"hello").read(b" world").build();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut s = RecordingStream::new(inner, Arc::clone(&seen));
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.expect("read");
    assert_eq!(seen.lock().expect("lock").as_slice(), b"hello world");
}

#[tokio::test]
async fn recording_is_capped_and_stops_growing() {
    // A client that streams forever must not grow the buffer without bound.
    let big = vec![0u8; 1 << 20];
    let inner = tokio_test::io::Builder::new().read(&big).build();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut s = RecordingStream::with_cap(inner, Arc::clone(&seen), 4096);
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.expect("read");
    assert_eq!(seen.lock().expect("lock").len(), 4096, "must stop at the cap");
    assert_eq!(buf.len(), big.len(), "but must not truncate what the caller sees");
}
```

The cap is the difference between the spike and production code. A ClientHello is at most
a few kilobytes, so nothing beyond that is ever needed, and an unbounded buffer under a
hostile client is a memory exhaustion bug.

- [ ] **Step 3: Run to verify it fails.** Expected: `cannot find type RecordingStream`.
- [ ] **Step 4: Implement `RecordingStream`** from the S1 spike, adding `with_cap`.
- [ ] **Step 5: Implement `Probe`**

`bind()` generates a self-signed certificate for `localhost` and `127.0.0.1` with ALPN
`h2, http/1.1`, then binds `127.0.0.1:0`. `accept_one()` accepts one connection, tees the
handshake, parses the ClientHello, and if ALPN negotiated `h2`, reads the preamble
through the first HEADERS frame and parses that too.

Three behaviours the S1 spike proved are worth preserving deliberately:

- **Capture survives handshake failure.** A client that rejects the self-signed
  certificate still has its ClientHello recorded, because the tee runs before the alert.
  `accept_one()` must return a report in that case, not an error.
- **Timeout every phase.** A client that connects and stalls must not hold the probe
  forever.
- **Never write anything.** `check` has no reason to respond, and not responding keeps
  the surface minimal.

- [ ] **Step 6: Run to verify it passes.**
- [ ] **Step 7: STOP — commit**

```bash
git add crates/fingerprint-probe/ Cargo.toml Cargo.lock
git commit -m "feat(probe): recording stream with a cap, and the capture probe"
```

---

### Task 2: The profile format

**Files:** `crates/fingerprint-probe/src/profile.rs`, `crates/fingerprint-probe/profiles/*.json`

**Interfaces:** `Profile`, `Equivalence`, `ProfileDb::load()`, `ProfileDb::get(&str)`, `Profile::from_report(&ClientReport, label)`.

A profile stores **full ordered field lists**, not only derived hashes. A JA4 string is
sorted and therefore lossy, so it cannot be replayed. That matters for M5 and it is
cheaper to get right now than to migrate later.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_profile_round_trips_through_json() {
    let p = Profile::from_report(&report_fixture("chrome"), "chrome-macos");
    let text = serde_json::to_string_pretty(&p).expect("ser");
    let back: Profile = serde_json::from_str(&text).expect("de");
    assert_eq!(p, back);
}

/// GREASE values rotate per connection (M0 finding 2). A profile that stored them
/// literally would never match the same browser twice.
#[test]
fn a_profile_stores_grease_positions_and_never_grease_values() {
    let p = Profile::from_report(&report_fixture("chrome"), "chrome-macos");
    let text = serde_json::to_string(&p).expect("ser");
    for v in ["2570", "10794", "19018", "56026", "64250"] {
        assert!(!text.contains(v), "GREASE value {v} must not be stored");
    }
    assert_eq!(p.grease_cipher_positions, vec![0]);
    assert_eq!(p.grease_ext_positions.len(), 2);
}

#[test]
fn every_shipped_profile_parses_and_has_a_capture_date() {
    for p in ProfileDb::load().expect("db").iter() {
        assert!(!p.label.is_empty());
        assert!(p.captured.len() >= 10, "{} needs a capture date", p.label);
    }
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement the format**

```json
{
  "label": "chrome-macos",
  "captured": "2026-08-11",
  "source": "manual",
  "equivalence": { "cipher_order": "fixed", "extension_order": "permuted" },
  "tls": {
    "ja4": "t13i1516h2_8daaf6152771_a87ad97598a9",
    "ciphers": [4865, 4866, "..."],
    "extensions": [5, 10, 11, "..."],
    "grease_cipher_positions": [0],
    "grease_ext_positions": [0, 16],
    "sig_algs": [2308, 2309, "..."],
    "alpn": "h2",
    "has_sni": false
  },
  "h2": {
    "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "settings": [[1, 65536], [2, 0], [4, 6291456], [6, 262144]],
    "window_update": 15663105,
    "priorities": [],
    "pseudo_order": "m,a,s,p"
  }
}
```

- [ ] **Step 4: Generate the shipped profiles from existing fixtures**

No new captures needed. A small `xtask` or test-only helper reads
`crates/fingerprint-core/tests/fixtures/*.bin` and
`crates/fingerprint-h2/tests/fixtures/*.bin`, pairs them by client, and writes
`profiles/{curl-8.7.1-macos,chrome-macos}.json`.

**The Chrome profile must record that its capture was a resuming session.** Its TLS
extension count is 16 rather than 15 because `pre_shared_key` was present, so its JA4
differs from a fresh Chrome handshake. Add `"session": "resumed"` and make Task 3 treat
extension 41 as session-dependent.

- [ ] **Step 5: Run to verify it passes.**
- [ ] **Step 6: STOP — commit**

```bash
git add crates/fingerprint-probe/
git commit -m "feat(probe): profile format storing ordered fields and equivalence classes"
```

---

### Task 3: The diff engine

The intellectually hardest task in this milestone. Every M0 finding lands here, and each
one is a way to get a permanently flaky comparison if ignored.

**Files:** `crates/fingerprint-probe/src/diff.rs`

**Interfaces:** `Diff { fields: Vec<FieldDiff>, verdict: Verdict }`, `Diff::is_clean()`, `diff(&ClientReport, &Profile) -> Diff`, `Verdict::{Exact, Partial, Unknown}`.

- [ ] **Step 1: Write the failing tests, one per M0 finding**

```rust
/// M0 finding 1. Chrome permutes extension order every connection, so a profile
/// with equivalence extension_order=permuted must accept any ordering of the same
/// set.
#[test]
fn a_permuted_profile_accepts_a_reordered_extension_list() {
    let profile = db().get("chrome-macos").expect("profile");
    let mut report = report_fixture("chrome");
    report.tls.extensions.reverse();
    assert!(diff(&report, profile).is_clean());
}

/// The same reordering must FAIL against a profile declared fixed, or the
/// equivalence class means nothing.
#[test]
fn a_fixed_profile_rejects_a_reordered_extension_list() {
    let profile = db().get("curl-8.7.1-macos").expect("profile");
    let mut report = report_fixture("curl");
    report.tls.extensions.reverse();
    assert!(!diff(&report, profile).is_clean());
}

/// M0 finding 2. GREASE values rotate, so substituting one for another must not
/// register as a difference.
#[test]
fn substituting_one_grease_value_for_another_is_not_a_difference() {
    let profile = db().get("chrome-macos").expect("profile");
    let mut report = report_fixture("chrome");
    report.tls.ciphers[0] = 0xfafa; // was some other GREASE value
    assert!(diff(&report, profile).is_clean());
}

/// M0 finding 2, the other direction. Removing GREASE entirely IS a difference,
/// and it is exactly how a naive emulation gets caught.
#[test]
fn removing_grease_entirely_is_a_difference() {
    let profile = db().get("chrome-macos").expect("profile");
    let mut report = report_fixture("chrome");
    report.tls.ciphers.remove(0);
    assert!(!diff(&report, profile).is_clean());
}

/// M0 finding 3. Cipher order is fixed even for Chrome. Only extensions permute.
#[test]
fn reordering_ciphers_is_a_difference_even_for_a_permuted_profile() {
    let profile = db().get("chrome-macos").expect("profile");
    let mut report = report_fixture("chrome");
    report.tls.ciphers.reverse();
    assert!(!diff(&report, profile).is_clean());
}

/// M0 finding 5. pre_shared_key appears only when resuming, so its presence or
/// absence must not by itself count as a mismatch.
#[test]
fn presence_of_pre_shared_key_is_session_dependent_not_a_mismatch() {
    let profile = db().get("chrome-macos").expect("profile");
    let mut report = report_fixture("chrome");
    report.tls.extensions.retain(|e| *e != 41);
    let d = diff(&report, profile);
    assert!(d.is_clean(), "session resumption must not read as a different client");
}

/// The headline discriminator, end to end.
#[test]
fn curl_checked_against_the_chrome_profile_reports_the_real_differences() {
    let profile = db().get("chrome-macos").expect("profile");
    let d = diff(&report_fixture("curl"), profile);
    assert!(!d.is_clean());
    let text = format!("{d}");
    assert!(text.contains("3:100"), "must name the SETTINGS tell");
    assert!(text.contains("GREASE"), "must name the missing GREASE");
    assert!(text.contains("m,s,a,p"), "must name the pseudo-header order");
}

/// Output must be actionable, not just a boolean.
#[test]
fn a_clean_diff_lists_every_field_it_checked() {
    let profile = db().get("chrome-macos").expect("profile");
    let d = diff(&report_fixture("chrome"), profile);
    assert!(d.is_clean());
    assert!(d.fields.len() >= 6, "a silent pass proves nothing");
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement.** Normalise GREASE to a placeholder before any comparison.
  Apply `equivalence` per field. Treat extension 41 as session-dependent. Compare the
  Akamai components individually so the diff can name which one differs.
- [ ] **Step 4: Run to verify it passes.**
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fingerprint-probe/
git commit -m "feat(probe): diff engine encoding every M0 equivalence finding"
```

---

### Task 4: `fpd check`

**Files:** `crates/fpd/src/commands/check.rs`, `crates/fpd/src/cli.rs`

```console
$ fpd check --profile chrome-macos -- curl -k {url}
  ✗ SETTINGS       sends 3:100, chrome-macos sends no id 3
  ✗ pseudo-header  m,s,a,p  (chrome-macos: m,a,s,p)
  ✗ GREASE         absent from cipher list
  ✓ ALPN           h2
  ✓ TLS version    1.3
  verdict: NOT chrome-macos (61% match)
$ echo $?
1
```

- [ ] **Step 1: Decide how the child learns the URL, and write it down**

The probe binds an ephemeral port, so the URL is not known until runtime. `{url}` in the
command is substituted, and `FPD_PROBE_URL` is also set in the child's environment for
clients that cannot take a URL argument. Document both.

The probe uses a self-signed certificate, so clients need to be told to accept it
(`curl -k`). Provide `--cacert-out <path>` to write the certificate for tools that want
to trust it properly rather than disabling verification.

- [ ] **Step 2: Write the failing integration tests**

```rust
#[test]
fn checking_curl_against_the_curl_profile_succeeds() {
    let dir = accepted_config();
    fpd(&dir).args(["check", "--profile", "curl-8.7.1-macos", "--", "curl", "-sk", "{url}"])
        .assert().success().stdout(predicate::str::contains("verdict: matches"));
}

#[test]
fn checking_curl_against_the_chrome_profile_fails_with_named_differences() {
    let dir = accepted_config();
    fpd(&dir).args(["check", "--profile", "chrome-macos", "--", "curl", "-sk", "{url}"])
        .assert().code(1)
        .stdout(predicate::str::contains("3:100"))
        .stdout(predicate::str::contains("m,s,a,p"));
}

/// The gate still applies. `check` is not exempt.
#[test]
fn check_is_refused_without_terms_acceptance() {
    let dir = TempDir::new().expect("tempdir");
    fpd_unaccepted(&dir).args(["check", "--profile", "chrome-macos", "--", "true"])
        .assert().code(1)
        .stderr(predicate::str::contains("must accept the terms"));
}

#[test]
fn a_client_that_never_connects_times_out_rather_than_hanging() {
    let dir = accepted_config();
    fpd(&dir).args(["check", "--profile", "chrome-macos", "--timeout", "2", "--", "true"])
        .assert().code(2).stderr(predicate::str::contains("no connection"));
}

#[test]
fn an_unknown_profile_name_lists_the_available_ones() {
    let dir = accepted_config();
    fpd(&dir).args(["check", "--profile", "netscape", "--", "true"])
        .assert().code(2).stderr(predicate::str::contains("chrome-macos"));
}
```

Exit codes: `0` match, `1` mismatch, `2` operational failure. A mismatch and a broken
invocation must not look the same to CI.

- [ ] **Step 3: Run to verify it fails.**
- [ ] **Step 4: Implement.** Bind the probe, spawn the child with substitution and env,
  accept one connection, diff, render, exit.
- [ ] **Step 5: Run to verify it passes.**
- [ ] **Step 6: STOP — commit**

```bash
git add crates/fpd/ crates/fingerprint-probe/
git commit -m "feat(fpd): check command with field-level diff and CI exit codes"
```

---

### Task 5: `fpd capture`

**Files:** `crates/fpd/src/commands/capture.rs`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn capture_writes_a_profile_that_the_db_can_load_back() { /* … */ }

/// Repeat samples are what turn a guess about equivalence into an observation.
#[test]
fn capturing_multiple_samples_infers_permuted_extension_order() {
    // Drive the probe several times with the same client; if extension order
    // varies across samples, the inferred class must be "permuted".
}

#[test]
fn a_single_sample_records_equivalence_as_unknown_not_fixed() {
    // One sample cannot distinguish fixed from permuted. Claiming "fixed" from a
    // single observation is how a profile becomes silently wrong.
}
```

That last test matters more than it looks. One handshake is not evidence of stability,
and a profile that asserts `fixed` on one sample would reject the same browser on its
next connection.

- [ ] **Step 2–4:** red, implement `capture --label --samples N`, green.
- [ ] **Step 5: STOP — commit**

```bash
git add crates/fpd/ crates/fingerprint-probe/
git commit -m "feat(fpd): capture command inferring equivalence from repeat samples"
```

---

### Task 6: Resolve the `fluke-hpack` panic

Carried from M3a, where it was contained but not fixed. This milestone is the first time
it is reachable from a socket, so it should not carry further.

- [ ] **Step 1: Report it upstream.** File an issue against `fluke-hpack` with the
  minimal reproducer (`0x3f` as a header block) and the `decoder.rs:505` reference.
- [ ] **Step 2: Choose the local fix.** Either vendor a patched copy replacing
  `.ok().unwrap()` with proper error propagation, or evaluate an alternative decoder
  against the same two requirements: order preservation and panic freedom under the
  existing property tests.
- [ ] **Step 3: Once it no longer panics**, delete the `catch_unwind` in
  `headers::decode_fragment` and restore the fuzz target to cover the full path including
  HPACK, removing the split documented in the M3a plan.
- [ ] **Step 4: Verify** the pinned regression test still passes for the right reason,
  which is now that no panic occurs rather than that one is caught.
- [ ] **Step 5: STOP — commit**

---

### Task 7: Documentation and release polish

- [ ] Update the README status table, and add a `fpd check` usage example with real output.
- [ ] Document the profile format and how to contribute a profile.
- [ ] Note in the README that `check` covers TLS and HTTP/2 but not the HTTP layer, since JA4H is not implemented.
- [ ] STOP — commit.

---

## Self-Review

**Spec coverage.** §6.2 `RecordingStream` → Task 1. §6.3 profile database with full
ordered fields → Task 2. §6.9 equivalence classes → Tasks 2 and 3. §6.8 `fpd check` and
CI exit codes → Task 4. `fpd capture --samples` → Task 5. §10 resource bounds → Task 1's
recording cap and Task 4's timeouts.

**Deliberately excluded.** JA4H, still without a specification or an oracle. `serve`,
`tui` and `emulate`, which are M4 onward.

**Known risks.**
1. **The diff engine is where correctness is easiest to fake.** Every test in Task 3 has
   a paired negative case for exactly that reason. A permuted profile that accepts
   reordering is only meaningful if a fixed profile rejects it.
2. **Only two profiles ship**, both captured on one machine on one day. Firefox and
   Safari are still missing, and the shipped Chrome profile is a resuming session.
3. **`fpd check` spawns a user-supplied command.** It is the user's own command in their
   own shell, so this adds no privilege, but the substitution must not be quoted in a way
   that invites surprises. Substitute into an argument vector, never through a shell.
4. **Certificate trust is a usability wart.** Every client needs `-k` or the exported
   certificate. Worth revisiting if it becomes the main friction point in real use.