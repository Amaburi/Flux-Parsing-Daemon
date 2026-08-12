# fpd, Flux Parsing Daemon

**TLS/HTTP-2 fingerprint inspection and verified emulation**

**Status:** design
**Date:** 2026-08-11 (rev 3, name, licence, terms immutability)
**Name:** `fpd`, Flux Parsing Daemon. Settled.

**Naming constraint:** the crates.io name `fpd` is already taken (Fiberplane Daemon,
v2.7.2). Package and binary names are therefore decoupled:

```toml
[package]
name = "flux-parsing-daemon"

[[bin]]
name = "fpd"
```

`cargo install flux-parsing-daemon` installs a command called `fpd`. The GitHub repo may
be named `fpd` freely, repo names only need to be unique within an account. Under ELv2
(§4.1) crates.io is a secondary channel anyway. Signed GitHub Releases and the container
image are primary.

**To verify before first publish:** availability of the remaining package names
(`fingerprint-core`, `fingerprint-tower`, `fingerprint-emulate`) on crates.io, and
whether ELv2 is acceptable there via `license-file`.

---

## 1. Problem

When a request is blocked by a WAF or bot-management product, the response is a bare
403. No reason is given. The operator is left guessing across four independent layers:
IP reputation, TLS fingerprint, HTTP/2 framing, or an application-layer JS challenge.

The only way to narrow it down today is live experimentation against the real target,
slow, non-reproducible, and it burns the source IP's reputation as a side effect of the
debugging itself.

There is a second, sharper gap. Browser-emulation clients already exist,
`curl-impersonate`, `uTLS`, `curl_cffi`, `rquest`, and every one of them asks the user
to take its emulation on faith. None can answer *"is my ClientHello actually
byte-identical to Chrome 131 right now, after that dependency bump?"* The emulator and
the ground truth live in different projects, so the loop never closes.

The inverse problem exists too: an operator running a service has no built-in way to see
the TLS/H2 identity of clients hitting it. Cloudflare exposes `cf.tlsClientHelloJa3` to
its own customers. Self-hosted stacks get nothing.

All three are the same missing capability: **making a client's byte-level identity
visible and checkable**. `fpd` provides it, and because it holds both the parser and the
emitter in one codebase, it is the only tool in the category that can *verify* an
emulation rather than assert one.

## 2. Goals

- Compute JA3, JA4 and the Akamai HTTP/2 fingerprint for any TLS client, plus fpd's
  own HTTP-layer comparison (§6.1a).
- Passively annotate inbound traffic on a server the operator controls, surfacing
  fingerprints in that server's existing logs with no application code changes.
- Detect **claim/identity mismatch**: a request whose `User-Agent` asserts a browser
  that its TLS or H2 fingerprint contradicts.
- Verify an outgoing HTTP client against a real browser profile locally, in CI, with no
  external network traffic.
- **Emulate** a captured browser profile, and, the differentiating property,
  **prove the emulation is byte-exact** against the same profile database, as a test.
- Ship reusable Rust libraries so others can embed both halves.

## 3. Non-goals

- No IP reputation, geolocation, or threat-intel enrichment.
- No HTTP/3 or QUIC in v1 (roadmap, §12).
- No JS-challenge solving, CAPTCHA solving, or headless-browser orchestration. `fpd`
  operates at TLS and HTTP/2 only. When an application-layer challenge is the blocker,
  `fpd`'s job is to tell the operator that the transport layer is clean so they stop
  looking there.
- No hosted multi-tenant SaaS. Self-hosted, plus one public demo instance.
- No per-site presets and no "bypass" bundles of any kind. Profiles describe *browsers*,
  never *targets*. A profile named after a website would not be shipped.

## 4. Dual-use posture, terms, and the acceptance gate

`fpd` emits fingerprints as well as reading them. That is dual-use, in the same way
`uTLS`, `curl-impersonate`, and `nmap` are dual-use, and it is handled explicitly rather
than by omission.

**Legitimate uses this exists to serve:** validating that a client you own is not
misclassified, regression-testing your own emulation, interoperability work, censorship
circumvention. Detection engineering (building better detectors requires knowing what
evasion looks like), authorised security testing, accessing your own accounts and data
programmatically.

### 4.1 Licence and terms

**Elastic License 2.0 (ELv2)**, source-available, not OSI open source. The repository
is public and readable. Anyone may read, clone, build, and run it. ELv2 forbids three
things, and the third is why it was chosen:

1. providing the software as a managed service to third parties,
2. circumventing licence-key or functionality-limiting mechanisms,
3. **removing or obscuring licensing, copyright, or other notices.**

Point 3 makes stripping the terms a licence breach directly, which is stronger and
easier to point at than Apache-2.0's `NOTICE`-retention clause.

What this deliberately accepts: forking cannot be technically prevented on a public
repository, GitHub only allows disabling forks on private/internal repos, and `git
clone` is functionally a fork regardless. The button is not the threat. Republishing a
modified, terms-stripped build is the threat, and that is what the licence forbids.

- **`TERMS.md`**: an acceptable-use policy naming permitted and prohibited uses, and
  stating plainly that responsibility for any use rests solely with the user, not the
  author. Linked from the README above the fold. ELv2 governs the code. `TERMS.md`
  governs use.

### 4.1.1 The terms text is immutable to the user

The terms must not be deletable or editable by whoever runs the tool. Three layers, in
order of how much they actually achieve.

**Layer 1, the terms are not a file at runtime.** `TERMS.md` is compiled *into* the
binary with `include_str!`. `fpd` never reads terms from the filesystem, never fetches
them, and has no code path that could load an alternative copy:

```rust
pub const TERMS: &str = include_str!("../../TERMS.md");
pub const TERMS_HASH: &str = env!("FPD_TERMS_HASH"); // set by build.rs
```

Consequences, and these are the properties actually requested:

- **Deleting `TERMS.md` on the user's disk changes nothing.** There is no file to
  delete, the shipped artifact is one binary with the text inside it.
- **Editing `TERMS.md` on disk changes nothing.** Nothing reads it.
- `fpd terms show` always prints the exact text that was compiled in, byte for byte.
- The acceptance record (§4.2) binds to `TERMS_HASH`, so an acceptance is always an
  acceptance of one specific, identifiable terms text, never of "whatever is on disk
  today".

**Layer 2, tampering at build time is detectable by anyone.** A user who cannot edit
the terms in a released binary could still rebuild from edited source. That cannot be
prevented, but it can be made evident:

- `build.rs` computes the SHA-256 of `TERMS.md` and bakes it in as `FPD_TERMS_HASH`.
- `fpd --version` and `fpd terms show --hash` print it.
- The canonical hash is published in the README, in each GitHub release, and in the
  crates.io description. Releases are signed.
- Any binary whose terms hash differs from the published canonical value is, by
  inspection, not a genuine build. One command proves it.

**Layer 3, removal is a licence violation.** This is the layer with actual force
against modification, and it is legal rather than technical. ELv2 expressly forbids
removing or obscuring licensing, copyright, and other notices. The responsibility
disclaimer is therefore carried in `NOTICE` as well as `TERMS.md`, so stripping it is
not merely discouraged, it breaches the licence under which the copy was obtained at
all. ELv2 additionally forbids redistribution as a managed service, closing the other
route by which a stripped build would reach users.

**What remains possible, stated plainly.** Someone can fork, delete the terms, strip the
gate, and compile a private binary. No open-source project can prevent this, and this
document claims otherwise nowhere. What layers 1-3 accomplish is that doing so requires
deliberate modification of source, produces an artifact provably distinct from any
genuine release, and violates the licence. That is the complete set of what is
achievable, and it is the same set every serious dual-use tool operates within.

### 4.2 Runtime acceptance gate

The gate covers the **entire binary**, not only emulation. No subcommand does any work
until terms have been accepted:

```
$ fpd serve
fpd: you must accept the terms and conditions first.

  This tool can both measure and reproduce TLS/HTTP-2 client identities.
  Responsibility for how it is used rests solely with you, not the author.

  Read them:    fpd terms show
  Accept them:  fpd terms accept

$ echo $?
1
```

**Enforcement point.** The check runs in `main()` before subcommand dispatch, a single
call site, not a per-command opt-in that a new subcommand could forget to add. A test
asserts that every registered subcommand is refused when unaccepted, so the gate cannot
rot as commands are added.

**Carve-outs, and only these three:** `fpd terms *`, `fpd --help`, `fpd --version`.
Without them the terms could not be read or accepted at all. Each is inert, none
touches the network or emits a packet.

**Acceptance record.** `fpd terms accept` writes to the platform config directory
(`~/.config/fpd/terms-accepted` on Linux/macOS):

```json
{ "terms_version": "sha256:9f2c...", "fpd_version": "0.4.1",
  "accepted_at": "2026-08-11T09:22:31Z", "host": "sha256:1d4a...",
  "sig": "hmac-sha256:7bb1..." }
```

- `sig` is an HMAC over the other fields, keyed by a constant compiled into the binary.
  A hand-edited record, e.g. one forged to claim acceptance of a terms version the user
  never read, fails validation and is treated as **not accepted**.
- **Deleting the file does not grant access.** Absence is the unaccepted state, so
  removal locks the user out rather than freeing them. There is no file whose deletion
  disables the gate. This is the property that makes acceptance effectively permanent
  once granted.
- A separate append-only `terms-history.jsonl` records every acceptance event. `fpd`
  appends, never rewrites or truncates it.
- If the `TERMS.md` version hash changes, prior acceptance no longer validates and the
  gate re-triggers on the new version.

**Non-interactive use.** `FPD_ACCEPT_TERMS=1` satisfies the gate for CI and containers,
and is recorded in `terms-history.jsonl` and in every log line of that run. It is an
acceptance mechanism, not an exemption, the terms still bind.

**Library.** Emulation lives behind a **non-default** cargo feature, `emulation`,
requiring explicit opt-in in the consumer's `Cargo.toml`. `build.rs` emits the terms
notice at compile time, and the emulation constructor returns an error rather than a
client unless acceptance validates at runtime.

### 4.3 What this gate does and does not achieve

Stated honestly, because overstating it would be worse than not having it:

- It **does** make the terms unavoidable on every path through a released binary. No
  user reaches any functionality without an explicit, recorded, signed acceptance.
- It **does** resist tampering with the record itself: forging or editing it fails HMAC
  validation, and deleting it locks the user out rather than letting them through.
- It **does** establish and document intent, which is what matters to a reviewer, an
  employer, or a court.
- It **does not** make the tool tamper-proof against someone rebuilding it. The source
  is open. A determined user can fork, strip the check, and compile their own binary.
  That is true of every open-source tool and cannot be engineered away. What it costs
  them is deliberate, demonstrable circumvention, which is precisely the evidentiary
  line the terms exist to draw. No claim beyond this is made anywhere in the
  documentation, and the README says so in these words.

## 5. Users

| User | Mode | Question they are answering |
|---|---|---|
| Detection / anti-fraud engineer | `serve`, `tui` | Who is actually hitting my API, and does their TLS agree with their User-Agent? |
| HTTP client author | `check` | Does my client emit a fingerprint that will be misclassified? |
| SRE running synthetic monitoring | `check` in CI | Did a dependency bump silently change how my agent looks on the wire? |
| Interoperability / research engineer | `emulate` + `check` | Can I reproduce a browser's transport identity exactly, and prove it? |
| Rust service author | `fingerprint-tower` | Same as row 1, without an extra network hop. |

## 6. Architecture

```
                    fingerprint-core   (pure library, zero I/O)
        tls::parse_client_hello · h2::parse_preamble · http::ja4h
                    profiles · diff · verdict
                                │
     ┌──────────────┬───────────┼───────────┬──────────────┬──────────────┐
     │              │           │           │              │              │
 fpd serve      fpd tui     fpd check   fpd capture   fpd emulate   fingerprint-tower
 reverse proxy  dashboard   one-shot    record a      emulate a     Rust middleware
 injects X-FP-* attaches    CLI, exit   browser       profile       injects into
 headers        to serve    code, CI    profile       (gated §4.2)  request extensions
                                            │              │
                                            └──► profiles ◄┘
                                          one DB, both directions
```

Two invariants hold the design together:

1. **`fingerprint-core` never opens a socket.** Everything touching the network is a
   thin shell around it, with I/O reached through a trait so it can be substituted in
   tests. That is what makes the hard logic testable offline.
2. **One profile database feeds both directions.** `capture` writes it, `check` and
   `verdict` read it, `emulate` reproduces from it. Because emission and measurement
   share a single source of truth, an emulation can be tested against the very profile
   it was built from. This is the property no other tool in the category has.

### 6.1 `fingerprint-core`

```rust
pub fn parse_client_hello(raw: &[u8]) -> Result<TlsFingerprint, ParseError>;
pub fn parse_h2_preamble(frames: &[u8]) -> Result<H2Fingerprint, ParseError>;
pub fn ja4h(method: &Method, version: Version, headers: &HeaderMap) -> HttpFingerprint;
pub fn diff(observed: &Report, profile: &Profile) -> Diff;
pub fn verdict(observed: &Report, db: &ProfileDb) -> Verdict;
```

**`TlsFingerprint`**, TLS version, cipher suites in wire order, extensions in wire
order, GREASE positions, supported groups, signature algorithms, ALPN, SNI presence,
plus derived `ja3` and `ja4`.

JA4 is primary. JA3 is computed for compatibility but documented as unreliable for
browsers: Chrome has randomised its ClientHello extension order since v110, so a Chrome
JA3 changes per connection. JA4 sorts ciphers and extensions before hashing, which is
exactly why it survives that permutation.

```
t13d1516h2_8daaf6152771_02713d6af862
│││ ││ │   │              └─ sha256[..12] of sorted extensions + sig algs
│││ ││ │   └──────────────── sha256[..12] of sorted cipher list
│││ ││ └──────────────────── first ALPN value
│││ │└────────────────────── extension count
│││ └─────────────────────── cipher count
││└───────────────────────── SNI is a domain (i = raw IP)
│└────────────────────────── TLS 1.3
└─────────────────────────── TCP  (q = QUIC)
```

**`H2Fingerprint`**, the Akamai format
`SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header order`:

```
chrome-131    1:65536;2:0;4:6291456;6:262144 | 15663105   | 0            | m,a,s,p
firefox-133   1:65536;4:131072;5:16384       | 12517377   | 3:0:0:201,...  | m,p,a,s
curl 8.7.1    3:100;4:10485760;2:0           | 1048510465 | 0            | m,s,a,p   ← measured
```

The curl row is **measured**, captured in the M0 S2 spike
(`docs/spikes/s2-capture-raw.txt`). The browser rows are reference values pending
capture. Two things the measurement corrected:

- The SETTINGS arrive in the order `3, 4, 2`, *not* ascending. Any implementation that
  normalises or sorts settings destroys the fingerprint. This is the concrete reason
  `settings` is an ordered `Vec<(u16, u32)>`.
- The WINDOW_UPDATE increment 1048510465 is `1048576000 − 65535`: curl raising the
  connection window from the protocol default to 1000 MiB. The value is a client
  configuration artefact, which is exactly why it discriminates between clients.

Two details the model must preserve, and they matter twice over now, once for
measurement, once because emulation reproduces from the same structure:

- **Absence is signal.** Chrome sends no SETTINGS id 3 at all. Curl announces `3:100`.
  `settings` is an ordered `Vec<(u16, u32)>` of what was literally on the wire, never a
  map with defaults filled in.
- **Order is signal.** Pseudo-header order separates Chrome (`m,a,s,p`) from Firefox
  (`m,p,a,s`). Any structure that sorts or normalises destroys the measurement *and*
  makes faithful emulation impossible.

**`HttpProfile`** (§6.1a), the HTTP layer, as fpd's own design rather than JA4H.
Header names in wire order, a header count, and `Accept-Language` presence. Method,
referer and cookie-header count are recorded but never compared, because they are
properties of a request rather than of a client. Header **values are never read or
stored** (§10), which includes cookie values.

**JA4H is deliberately not implemented.** Three reasons, engineering first:

1. A hash cannot be diffed, and fpd's purpose is to report *which* field differs.
   `missing: sec-ch-ua, sec-fetch-site` is actionable where `hash a1b2...` is not.
2. JA4H hashes cookie fields together with their **values**, which contradicts the
   privacy position in §10. fpd records the count of `cookie` headers instead, which is
   real signal because HPACK splits them and requires reading nothing.
3. JA4H fingerprints a *request*. Fpd profiles a *client*. Comparing method or referer
   would make one browser fail to match its own profile across two page loads.

Separately, JA4 (TLS) is BSD 3-Clause with no patent claims, which is why it is
implemented here, while JA4H and the rest of the JA4+ suite are patent pending under
FoxIO License 1.1, which is not permissive for monetization. Anyone needing JA4H
specifically should approach FoxIO directly.

### 6.2 Capture path

Two hard constraints drive this design.

**rustls' ClientHello accessor is insufficient.** It surfaces SNI, cipher suites, and
signature schemes, but not raw extension order or GREASE placement, exactly the fields
that matter. So: wrap the `TcpStream` in a `RecordingStream` that tees every byte read
into a bounded buffer, let rustls perform the handshake normally on top of it, then
parse the buffered ClientHello independently.

**The `h2` crate is also insufficient.** It normalises settings and hides frame arrival
order, again, the measurement itself. So `fpd` implements a minimal HTTP/2 *read* path:
connection preface maps to SETTINGS maps to WINDOW_UPDATE maps to HEADERS (HPACK-decoded via
`fluke-hpack`) maps to capture complete. Afterwards the connection is handed to a normal
`hyper` server or proxied upstream.

```
TCP accept
 └─ RecordingStream (bounded tee)
      └─ tokio-rustls handshake ──► parse_client_hello(buffered bytes)
           └─ ALPN == h2 ?
                └─ minimal h2 reader ──► parse_h2_preamble(frames)
                     └─ HEADERS ──► ja4h(...)
                          └─ Report ──► serve / tui / check
```

### 6.3 Profile database

A profile is captured, versioned ground truth for one real browser build, and now also
the *input* to emulation:

```
profiles/chrome-131-win.json
{ "label": "chrome-131-win", "captured": "2026-08-11", "source": "manual",
  "ja4": "...", "ciphers": [...], "extensions": [...], "grease": [0, 5, 11],
  "groups": [...], "sig_algs": [...], "alpn": ["h2","http/1.1"],
  "h2": { "settings": [[1,65536],[2,0],[4,6291456],[6,262144]],
          "window_update": 15663105, "priority": [], "pseudo_order": "masp" },
  "header_order": ["sec-ch-ua", "sec-ch-ua-mobile", ...] }
```

Because emulation replays this structure, profiles must store the **full ordered field
lists**, not only the derived hashes. A JA4 string alone is lossy, it is sorted, and
cannot be replayed.

Produced by `fpd capture --label <name>`, which runs a probe listener and records the
next handshake. Browsers ship roughly every four weeks, so profiles carry a capture date
and the verdict engine reports profile age alongside its match.

Shipped set for v1: current and previous stable Chrome (Win/macOS), Firefox, Safari,
plus curl, `python-requests`, Go `net/http`, and Node `undici` as negative references.

### 6.4 Verdict engine

`verdict()` scores an observed report against every profile and returns the best match
with a confidence value, plus the mismatch flag:

- **exact**, JA4 and H2 fingerprint both equal a profile.
- **partial**, one layer matches, the other does not. Differing fields are listed.
- **unknown**, no profile within threshold. Nearest neighbour reported.
- **ua_mismatch**, the `User-Agent` claims a browser family the best fingerprint match
  contradicts. Highest-value output of the system: no real browser produces
  `UA: Chrome/131` with a `python-requests` JA4, so the signal has near-zero
  false-positive rate and needs no operator tuning.

### 6.5 `fpd serve`, passive mode

Terminates TLS, captures, then reverse-proxies to the application over plain HTTP on
localhost, injecting:

```
X-FP-JA4:        t13d1516h2_8daaf6152771_02713d6af862
X-FP-H2:         1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
X-FP-HTTP-Headers: cache-control,sec-ch-ua,sec-fetch-site,...
X-FP-Verdict:    chrome-131-win
X-FP-Confidence: 1.00
X-FP-Mismatch:   false
```

Any upstream in any language reads those headers and logs them with its existing logger.
`fpd` also emits its own structured log line per connection.

Inbound `X-FP-*` headers from the client are **stripped before injection**, without
exception. Otherwise a client could forge its own verdict.

### 6.6 `fingerprint-tower`, passive mode, embedded

For Rust services, the same capability with no extra hop:

```rust
// before
let acceptor = TlsAcceptor::from(config);
// after
let acceptor = fingerprint_tower::Acceptor::new(config);
```

```rust
async fn handler(Extension(fp): Extension<ClientFingerprint>) {
    tracing::info!(ja4 = %fp.ja4, verdict = %fp.verdict, mismatch = fp.ua_mismatch, "request");
}
```

### 6.7 `fpd tui`, interactive mode

`ratatui` + `crossterm`. Attaches to a running `fpd serve` over a Unix domain socket, so
it can be opened against a live production instance, not only a local lab.

```
┌─ fpd ─ live ──────────────────────────────────── :443 ─ 1,284 conn ─ 3 alerts ─┐
│ TIME      IP               JA4                    VERDICT           UA         │
│ 12:04:31  103.28.14.2      t13d1516h2_8daaf6...     chrome-131-win    ✓          │
│ 12:04:31  45.9.148.99      t13d3112h2_e8f1e7...     python-requests   ✗ MISMATCH │
│ 12:04:29  198.51.100.7     t13d1715h2_5b5761...     firefox-133       ✓          │
├─ detail ─ 45.9.148.99 ─────────────────────────────────────────────────────────┤
│ TLS 1.3    ciphers 31    ext 12    GREASE absent    ALPN h2                     │
│ JA4   t13d3112h2_e8f1e7e78f70_6bebaf5329ac                                     │
│ H2    3:100;4:1048576|1048576|0|m,s,a,p                                        │
│ ⚠  claims Chrome 131, fingerprint says python-requests                         │
│ ⚠  sends SETTINGS 3:100, no browser sends this                                │
└─ [tab] filter  [/] search  [f] follow  [e] export  [d] diff  [q] quit ─────────┘
```

Bounded ring buffer in memory. The TUI never persists traffic itself.

### 6.8 `fpd check`, active mode

Starts a local probe listener, runs the user's command against it, captures the single
resulting handshake, prints a field-level diff, and exits non-zero on mismatch.

```bash
$ fpd check --profile chrome-131-win -- curl https://fp.local:8443
  ✗ SETTINGS       sends 3:100, Chrome sends no id 3
  ✗ pseudo-header  m,s,a,p  (chrome-131-win: m,a,s,p)
  ✗ GREASE         absent from cipher list
  ✓ ALPN           h2
  verdict: NOT chrome-131-win (61% match)
$ echo $?
1
```

The CI form. A scraper or monitoring agent gets a test that fails the moment a
dependency bump changes its wire identity, locally, in milliseconds, without sending a
packet to the real target and without exposing the source IP.

### 6.9 `fpd emulate` / `fingerprint-emulate`, emission

Subject to the acceptance gate in §4.2. Builds a TLS+H2 client that reproduces a stored
profile field-for-field.

**Why rustls cannot be used here.** rustls deliberately does not expose cipher ordering,
arbitrary extension ordering, or GREASE injection, by design, and that design is
correct for a TLS library. Emulation therefore builds on **BoringSSL** via the `boring`
crate, which does expose the necessary controls (cipher list ordering, extension
permutation, GREASE, ALPS). This is the same foundation `rquest` uses.

**Validated in the M0 S3 spike** (`docs/spikes/2026-08-11-m0-findings.md`). Against a
live-captured Chrome baseline, `boring` 4.22.0 reproduced the cipher list in exact order
and GREASE placement exactly, with no tuning. Five extensions remained missing, each
with a confirmed API: `enable_ocsp_stapling` (5), `enable_signed_cert_timestamps` (18),
`add_certificate_compression_algorithm` (27), `set_enable_ech_grease` (65037), and,
the only one needing unsafe FFI, since `boring` ships no wrapper,
`SSL_add_application_settings` for ALPS (17613). Extension permutation per S1 finding 1
is covered by `set_permute_extensions`.

**The H2 write path needs the same treatment** as the read path: SETTINGS values *and
order*, WINDOW_UPDATE increment, and pseudo-header order must be controllable, none of
which stock `h2` permits.

This originally said a vendored and patched `h2` was therefore required. **That turned
out to be wrong**, and M5b replaced it. fpd does not need an HTTP/2 client, it needs to
emit a preamble: preface, SETTINGS, WINDOW_UPDATE and one HEADERS frame, then stop. That
is a few hundred bytes of writing against roughly fifteen thousand lines of vendored `h2`
to maintain and re-patch on every upstream release. See
`crates/fingerprint-emulate/src/h2.rs`.

```rust
let client = fingerprint_emulate::build(&ProfileDb::load()?.get("chrome-131-win")?)?;
let resp = client.get("https://example.com").send().await?;
```

**Equivalence is defined per profile, not globally.** Chrome has randomised its
ClientHello extension order since v110, so "byte-identical to Chrome" is not a
well-defined target, two consecutive real Chrome handshakes are not byte-identical to
each other. Each profile therefore carries an explicit equivalence class:

```json
"equivalence": { "extension_order": "permuted", "cipher_order": "fixed" }
```

- `"fixed"`, literal wire order must match exactly (Firefox, Safari, curl).
- `"permuted"`, the extension *multiset* must match exactly and the derived JA4 must
  match (JA4 sorts, so it is permutation-invariant), but literal order is free (Chrome
  and Chromium derivatives).

Getting this wrong in either direction is fatal: compare literally and every Chrome test
flakes. Compare only by JA4 and a genuinely wrong extension set passes. The equivalence
class is captured as observed evidence, not assumed, `fpd capture --samples 20` records
repeated handshakes from the same browser and infers whether a field varies.

**Three rules below were derived from ~30 live Chrome handshakes captured during the M0
S1 spike (`docs/spikes/s1-capture-raw.txt`), not from documentation. Each one would
otherwise have produced a permanently flaky comparison.**

1. **GREASE *values* rotate every connection. Only positions are stable.** Observed
   cipher[0] taking 2570, 6682, 14906, 19018, 23130, 27242, 35466, 43690, 47802, 51914,
   56026, 60138, 64250 across successive handshakes. A profile therefore stores GREASE
   as a **position set plus a count**, never as literal values, and comparison
   normalises every GREASE value to a single placeholder before matching. Chrome's
   observed placement is cipher[0], extension[0], and the last non-PSK extension.
2. **Extension 41 (`pre_shared_key`) is exempt from permutation.** RFC 8446 requires it
   to be the final extension, and every observed 18-extension handshake ended with it
   while the other 17 were freely shuffled. A `"permuted"` class must therefore pin 41
   last rather than treating it as just another member of the multiset.
3. **Cipher order is `"fixed"` even for Chrome.** Only extension order permutes. Across
   every sample the 15 non-GREASE ciphers held identical order
   (`4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157,
   47, 53`). The two axes are independent and must be modelled separately.

**Extension count varies legitimately between sessions.** The same browser produced both
17- and 18-extension handshakes, the 18th being `pre_shared_key` on resumption. A
profile must record which extensions are *session-dependent* or `--samples` will
oscillate between two "correct" answers. This also means JA4's extension-count digit is
not stable for a resuming browser, which is a property of JA4 rather than a bug here.

**The verification loop, the headline feature.** Because emitter and parser share the
profile database, an emulation can be proven rather than assumed:

```bash
$ fpd emulate --profile chrome-131-win --verify
  ✓ JA4            t13d1516h2_8daaf6152771_02713d6af862
  ✓ ciphers        31/31, order exact
  ✓ extensions     16/16 present, GREASE ×3   (order: permuted, allowed)
  ✓ SETTINGS       1:65536;2:0;4:6291456;6:262144
  ✓ pseudo-header  m,a,s,p
  verdict: equivalent to chrome-131-win under its stated class  (profile age 3d)
```

`--verify` spawns an in-process probe listener, drives one request through the emulated
client, and diffs the observed handshake against the source profile. No external
network. This is a `#[test]`, not a manual step:

```rust
#[test]
fn emulation_matches_every_shipped_profile() {
    for profile in ProfileDb::load().unwrap().iter() {
        let client = fingerprint_emulate::build(profile).unwrap();
        // repeated, because a permuted profile must hold across draws
        for _ in 0..16 {
            assert_eq!(probe_locally(&client).diff(profile), Diff::CLEAN, "{}", profile.label);
        }
    }
}
```

Every shipped profile is continuously proven equivalent in CI. When a `boring` bump
breaks emulation, CI fails that day instead of a 403 appearing three weeks later. That
guarantee is the reason this project exists in the form it does.

## 7. Data flow summary

Every row is gated by §4.2, the check sits in `main()` ahead of dispatch, so the column
is uniform by construction rather than by remembering to add it.

| Mode | Direction | Trigger | Gated | Output |
|---|---|---|---|---|
| `serve` | inbound | every connection | yes | injected headers + structured log |
| `tower` | inbound | every connection | yes (lib runtime check) | request extension + tracing event |
| `tui` | inbound | attach to `serve` | yes | live table + detail pane |
| `check` | outbound | manual / CI | yes | diff to stdout + exit code |
| `capture` | outbound | manual | yes | profile JSON on disk |
| `emulate` | outbound | manual / library | yes + `emulation` feature | emulated client. `--verify` diff |
| `terms` | none | manual | carve-out | terms text, acceptance record |

## 8. Error handling

Malformed input is expected traffic, not an exceptional case, a scanner will send
garbage on day one.

- Parsers return `Result`, never panic. `#![deny(clippy::unwrap_used, clippy::panic)]`
  in `fingerprint-core`.
- A parse failure in `serve` degrades gracefully: the connection is still proxied, with
  `X-FP-Verdict: unparsed`. Fingerprinting must never be able to take the site down.
- Upstream connection failure returns 502 from `fpd`, fingerprint still logged.
- Truncated or absent H2 preamble yields a TLS-only report rather than an error.
- `emulate` fails **loudly** on a profile it cannot reproduce faithfully, rather than
  silently degrading to an approximation. A silently-wrong emulation is the exact
  failure mode this project exists to eliminate.

## 9. Testing

The pure-core split makes the system testable offline.

1. **Byte fixtures.** Real handshakes captured once, committed as raw bytes. Every
   parser test is `parse(fixture) == expected`, no network, no timing. Each newly
   captured browser becomes a permanent regression test.
2. **Round-trip tests.** `emulate(profile)` maps to `parse` maps to equals `profile`. Closes the
   loop across both halves of the codebase and is the strongest correctness signal
   available.
3. **Property tests.** `proptest` over frame and extension structures for the
   ordering and absence-vs-default invariants in §6.1.
4. **Fuzzing.** `cargo-fuzz` on `parse_client_hello` and `parse_h2_preamble`, seeded
   from the fixture corpus, in CI. These parsers consume attacker-controlled length
   fields. Not optional.
5. **Integration.** `fpd serve` in front of a stub upstream, driven by real curl and
   headless Chrome, asserting injected headers.
6. **Gate tests.** Enumerate every registered subcommand and assert each is refused
   when unaccepted (so a future subcommand cannot silently escape the gate). A forged or
   hand-edited record fails HMAC validation and reads as unaccepted. Deleting the record
   locks out rather than admits, acceptance invalidates on terms-hash change,
   `terms-history.jsonl` is append-only. The `emulation` feature is genuinely off by
   default.
7. **Terms immutability tests.** `fpd terms show` output equals `TERMS` byte for byte
   with no `TERMS.md` present anywhere on disk (run in an empty temp cwd). Deleting or
   rewriting an on-disk `TERMS.md` does not alter the printed text or the reported hash,
   `TERMS_HASH` equals the SHA-256 of the committed `TERMS.md` (a CI check that fails if
   `build.rs` and the source ever drift apart). No source file other than `terms.rs`
   references the terms path.
8. **Golden diffs.** `fpd check` and `emulate --verify` output snapshot-tested.

## 10. Security and privacy

**Attack surface.** `fpd serve` terminates TLS in front of a production application,
making it a security-critical component parsing untrusted bytes from the internet.

- Every length field in a ClientHello is attacker-controlled. Bounds are checked
  explicitly, `RecordingStream` buffers are hard-capped, and the parsers are fuzzed
  (§9.4).
- Per-connection handshake timeout and a maximum frame count before capture is
  abandoned, bounding slowloris-style resource use.
- The `tui` admin socket is a Unix domain socket with restrictive file permissions. No
  TCP admin port.
- Client-supplied `X-FP-*` headers are stripped before injection (§6.5).
- BoringSSL is an additional C dependency reachable only from the `emulation` feature,
  it is absent from the default build, so a `serve`-only deployment does not carry it.

**Privacy.** A fingerprint is a tracking vector, and fingerprint-plus-IP is
PII-adjacent under GDPR.

- Header **values are never read, logged, or stored**, only names, order, and counts.
  Cookie and authorization values never enter the fingerprint path.
- IP handling is configurable: full, truncated, hashed with a rotating salt, or omitted.
- Log retention is configurable with a documented default. The privacy posture is stated
  in the README, not buried in this document.

**Dual-use.** Fully covered in §4, including an honest statement of the acceptance
gate's limits.

## 11. Milestones

### M0, Risk spike (~3 days, throwaway code, before anything else)

Three assumptions carry the entire design. If any is false, the plan changes shape, and
it is far cheaper to learn that in three days than in week five. M0 exists to get a
yes/no on each, with scrappy code that is thrown away afterwards.

| # | Question | Pass looks like | If it fails |
|---|---|---|---|
| S1 | Can a `RecordingStream` tee raw bytes under `tokio-rustls` and still complete a handshake? | Raw ClientHello recovered. Extension order readable | Fall back to a raw TCP pre-read of the first record before handing to rustls |
| S2 | After manually consuming preface + SETTINGS + HEADERS, can the connection still be served or proxied? | A replaying stream re-emits consumed bytes. `hyper` serves the request normally | `serve` becomes a frame-level proxy instead of terminating with `hyper`, more work, still viable |
| S3 | Can `boring` emit a ClientHello whose JA4 equals a captured Chrome JA4? | JA4 strings match | **Emulation descopes to v2.** Inspection-only v1 still ships intact |

**M0 is complete. All three passed**, see `docs/spikes/2026-08-11-m0-findings.md`.
S1 needed no fallback, S2 confirmed hyper can serve a replayed connection so no
frame-level proxy is required, and S3 matched cipher order and GREASE placement on the
first attempt with an enumerable five-extension gap, every item API-addressable.
**M5 stays in v1** and the descope contingency is not exercised.

S3 is the real risk and the reason it is spiked first rather than trusted. `rquest`
demonstrates that browser-grade emulation on BoringSSL is achievable, but "achievable"
and "reproducible from an arbitrary captured profile" are different claims, and only the
second one is what this spec promises.

### Delivery milestones

| # | Scope | Exit criterion |
|---|---|---|
| M1 | `TERMS.md` + `NOTICE`, Apache-2.0, `include_str!` embedding + `build.rs` hash, acceptance gate, `fpd terms`, gate + immutability tests | Every subcommand refused when unaccepted, forged record rejected, terms text identical with no `TERMS.md` on disk |
| M2 | `fingerprint-core` TLS: ClientHello parser, JA3, JA4, fixture harness | JA4 for curl/Chrome/Firefox fixtures matches known-good values |
| M3 | H2 read path, own HPACK decoder, HTTP layer, `RecordingStream`, `fpd check` + `fpd capture --samples` | Correct diff for curl vs. a captured Chrome. Equivalence class inferred from repeat samples |
| M4 | `fpd serve` proxy, header injection, verdict engine, structured logs, `fingerprint-tower` | Real Chrome and curl through `serve` land correctly annotated in an upstream's logs |
| M5 | `fingerprint-emulate`: BoringSSL ClientHello control, own h2 preamble writer, `--verify` | Every shipped profile passes 16 repeat draws under its equivalence class in CI |
| M6 | `fpd tui`, admin socket, fuzzing in CI, docs, crates.io release | Demo GIF, published crates, deployed public instance |

**Estimate: 6-8 weeks** at a steady pace, plus M0. M3 and M5 are the technically hard
parts. M4 and M6 are assembly and polish.

**M1 comes first on purpose.** The gate is built before anything it gates, so no
intermediate commit in the history ever contains working functionality without it. That
ordering is visible in the git log and is itself part of the argument that the terms were
a design constraint rather than a label applied at the end.

**Release strategy option.** M1-M4 + M6 form a complete, shippable inspection-only v1.
Releasing there first and shipping emulation (M5) as v2 yields two launch moments
instead of one, and gets the project public roughly three weeks earlier. It also means a
failed S3 spike costs nothing but a roadmap line. Recommended, not required.

## 12. Roadmap (explicitly out of v1)

- **HTTP/3 and QUIC**, the JA4 `q` variant, on both the parse and emulate sides.
- **Encrypted ClientHello (ECH)**, once ECH is widely deployed, the outer ClientHello
  carries no distinguishing signal and this whole technique degrades. Documenting how
  and why is a stronger contribution than pretending otherwise.
- Prometheus metrics export.
- Community-submitted profiles, with provenance metadata.

## 13. Deliverables

**Primary distribution** (ELv2 makes these the real channels):

- Signed binaries on GitHub Releases, each published alongside its canonical
  `TERMS_HASH` (§4.1.1 layer 2)
- Container image
- Public demo instance

**Secondary:**

- `flux-parsing-daemon` on crates.io, installing the `fpd` binary
- `fingerprint-core`, `fingerprint-tower`, `fingerprint-emulate`, library crates,
  `emulation` feature off by default (names pending availability check)

**Repository:**

- `LICENSE` (Elastic License 2.0), `NOTICE`, `TERMS.md`
- README leading with the verification loop, then the licence and terms position, the
  non-goals, and the privacy posture
- Fixture corpus and profile DB, versioned in-repo
