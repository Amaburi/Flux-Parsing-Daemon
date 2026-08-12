# FPD (Flux Parsing Daemon)

**TLS/HTTP-2 fingerprint inspection and verified emulation.**

When a WAF blocks a request you get a bare 403 and no reason. Was it your IP, your TLS
fingerprint, your HTTP/2 framing, or a JavaScript challenge? The only way to find out
today is live experimentation against the real target. That is slow, it cannot be
reproduced, and it burns the source IP's reputation as a side effect of the debugging.

fpd makes the byte-level identity of a client visible, in both directions.

## Status

In development. What works today:

| Component | State |
|---|---|
| `fingerprint-terms` | Done. Terms gate on every invocation, HMAC acceptance record. |
| `fingerprint-core` | Done. ClientHello parsing, JA3, JA4, GREASE handling. |
| `fingerprint-h2` | Done. Frame walk, HPACK, Akamai fingerprint. |
| `fingerprint-probe` | Done. Capture probe, profile database, diff engine. |
| `fpd check` | **Working.** Compares against a profile, or identifies the client. |
| `fpd capture` | Working. Infers field ordering from repeat samples. |
| Claim mismatch | **Working.** Flags a client whose User-Agent contradicts its fingerprint. |
| `fpd serve` | **Working.** Reverse proxy that annotates traffic for any upstream. |
| `fingerprint-tower` | **Working.** Embedded in a Rust app, no proxy and no extra hop. |
| `fpd emulate --verify` | **Working.** Reproduces a profile across TLS and HTTP/2, and proves it. |
| `tui` | Not implemented. Stub. |

Every fingerprint value is checked against tshark rather than against itself. See
[the design](docs/design/2026-08-11-fpd-design.md) and [the plans](docs/plans/).

## Try it

```console
$ fpd terms accept
$ fpd check --profile chrome-macos -- curl -sk --http2 '{url}'
```

```
  ✗ ciphers         4867,4866,4865,52393,52392 +44 more  (chrome-macos: 4865,4866,4867,49195,49199 +10 more)
                    order rule: Fixed
  ✗ extensions      43,51,11,10,13,16  (chrome-macos: 23,27,45,13,16,18,11,65281,35 +6 more)
                    order rule: Permuted
  ✗ GREASE          0 cipher, 0 extension  (chrome-macos: 1 cipher, 2 extension)
                    absent entirely, no browser omits GREASE
  ✓ ALPN            h2
  ✓ SNI             absent
  ✗ SETTINGS        3:100;4:10485760;2:0  (chrome-macos: 1:65536;2:0;4:6291456;6:262144)
                    sends id 3, which no browser does
  ✗ WINDOW_UPDATE   1048510465  (chrome-macos: 15663105)
  ✗ pseudo-header   m,s,a,p  (chrome-macos: m,a,s,p)
  ✗ header order    user-agent,accept  (chrome-macos: cache-control,sec-ch-ua +12 more)
                    missing: cache-control,sec-ch-ua +10 more
  ✗ accept-language absent  (chrome-macos: present)
  verdict: NOT chrome-macos (20% match)
```

Without `--profile` it identifies the client instead of comparing it:

```console
$ fpd check -- curl -sk --http2 '{url}'
  identified: curl-8.7.1-macos (100% match)
  runner-up:  chrome-macos (20%)
```

And it catches a client whose claim contradicts its fingerprint:

```console
$ fpd check -- curl -sk --http2 -A 'Mozilla/5.0 ... Chrome/131.0.0.0 Safari/537.36' '{url}'
  identified: curl-8.7.1-macos (100% match)

  CLAIM MISMATCH: User-Agent says chrome, fingerprint says curl
  no real browser produces this combination
```

Mismatch detection declines to report whenever either side is uncertain. No User-Agent,
an unrecognised one, or a fingerprint matching no profile all produce silence rather than
a guess. A false flag costs more than a missed one, because an operator who sees one
wrong flag stops trusting all of them.

`fpd check` starts a probe on loopback, runs your client against it, and diffs what
arrived against a stored profile. `{url}` is replaced with the probe URL, and
`$FPD_PROBE_URL` is set in the client's environment. Exit codes are 0 for a match, 1 for
a mismatch and 2 for an operational failure, so a broken invocation cannot be mistaken
for a clean result in CI.

Comparison respects per-profile equivalence rules. Chrome permutes its extension order on
every connection, so a reordering is not a difference, while a reordering of ciphers is,
because that order is fixed even for Chrome. GREASE values rotate per connection and are
normalised away, but GREASE going missing entirely is reported, since no browser omits
it.

## What makes it different

Browser emulation clients already exist. `curl-impersonate`, `uTLS`, `curl_cffi` and
`rquest` all ask you to take their emulation on faith. None of them can answer whether
your ClientHello is still equivalent to Chrome 131 after a dependency bump, because the
emulator and the ground truth live in different projects.

fpd holds the parser and the emitter in one codebase over one profile database. That
means an emulation can be proven instead of asserted:

```rust
#[test]
fn emulation_matches_every_shipped_profile() {
    for profile in ProfileDb::load()?.iter() {
        let client = fingerprint_emulate::build(profile)?;
        assert_eq!(probe_locally(&client).diff(profile), Diff::CLEAN);
    }
}
```

No network. Runs in CI. A dependency bump that breaks emulation fails the build that
day instead of producing a mysterious 403 three weeks later.

This works today:

```console
$ fpd emulate --profile chrome-macos --verify
  ✓ ciphers         15 ciphers
  ✓ extensions      15 extensions
  ✓ GREASE          1 cipher, 2 extension
  ✓ ALPN            h2
  ✓ SNI             absent
  ✓ SETTINGS        1:65536;2:0;4:6291456;6:262144
  ✓ WINDOW_UPDATE   15663105
  ✓ pseudo-header   m,a,s,p
  ✓ header order    14 headers
  ✓ accept-language present
  verdict: matches chrome-macos
```

The comparison uses the profile's own equivalence class, not byte equality. Two
consecutive real Chrome handshakes are not identical to each other, since Chrome permutes
its extension order every connection and its GREASE values rotate, so byte comparison
would fail against the real browser too. A test runs eight draws to confirm the
permutation is genuinely being exercised, and a deliberately corrupted profile is checked
to fail, because a verification that cannot fail proves nothing.

Emulation is behind a non-default feature, since it pulls in BoringSSL:

```console
$ cargo build --features emulation
```

What it does not do, stated so nobody discovers it late:

- **Profiles carry the shape of a request, never its values.** That follows directly from
  the privacy position below: fpd records header names, order and counts and nothing else.
  So emulation reproduces which headers are sent and in what order, and the caller supplies
  what goes in them. Empty values reproduce the fingerprint but would not survive anything
  that inspects content.
- **Certificate compression is advertised but not implemented.** The extension appears in
  the ClientHello, which is what a fingerprint is made of, but a live server that actually
  compresses its certificate chain will fail the connection. Fine for verifying a profile,
  not fine for a general-purpose client.
- **HPACK encoding shape is not part of the fingerprint.** Two encoders can produce the
  same decoded headers from different bytes. Static-table hits use the indexed form, as
  browsers do, which narrows the gap without closing it.
- **Only browsers can be emulated.** curl offers 31 legacy cipher suites this does not map,
  and emulating curl is not a use case: you would run curl. Attempting it errors rather
  than producing a handshake that reproduces nothing.

## Two directions

| Mode | Commands | Question it answers |
|---|---|---|
| Inbound | `serve`, `tui` | Who is hitting my API, and does their TLS agree with their User-Agent? |
| Outbound | `check`, `emulate` | What does my own client look like on the wire? |

The most useful output is a claim mismatch. A request whose `User-Agent` says Chrome 131
while its TLS fingerprint says `python-requests` cannot come from a real browser, so the
signal needs no tuning by the operator.

## How correctness is established

Fingerprint tools fail quietly. A wrong JA4 still looks like a JA4. fpd is built so that
cannot happen silently.

Every fingerprint value in the test suite is checked three ways:

1. Against the published specification.
2. Against tshark 4.4.9, which computes JA3 and JA4 independently over the same bytes.
3. Against `shasum` on the literal pre-hash strings.

Byte fixtures are captured from real clients and committed. `scripts/bin2pcap.py` wraps
a fixture in a pcap so tshark reads exactly the bytes the parser reads, which leaves no
room for the two implementations to differ on input.

```
curl 8.7.1     t13i4906h2_0d8feac7bc37_7395dae3b2f3
curl with SNI  t13d4907h2_0d8feac7bc37_7395dae3b2f3
Chrome         t13i1516h2_8daaf6152771_a87ad97598a9
```

The first two are the same client differing only by SNI. That isolates two JA4 rules at
once. SNI flips the third character and raises the extension count, while the two hashes
stay identical because SNI is excluded from them.

The parser is fuzzed and property tested. 672,344 fuzz executions with no crashes, plus
truncation of every fixture at every byte offset.

## Annotating your own traffic

`fpd serve` sits in front of an application, terminates TLS, fingerprints each client,
and forwards the request with the result attached as headers. No application code
changes. Any language, any framework, read the headers with your existing logger.

```console
$ fpd serve --listen 127.0.0.1:8443 --upstream 127.0.0.1:8080
```

```
Internet ──TLS──> fpd :8443 ──HTTP──> your app :8080
                    |
                    +-- x-fp-ja4:           t13i1516h2_8daaf6152771_a87ad97598a9
                        x-fp-h2:            1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
                        x-fp-http-headers:  cache-control,sec-ch-ua,sec-fetch-site,...
                        x-fp-verdict:       chrome-macos
                        x-fp-confidence:    1.00
                        x-fp-mismatch:      false
```

**Inbound `x-fp-*` headers from clients are stripped before injection**, without
exception. Otherwise a caller sends its own `x-fp-verdict` and your application believes
it, which would turn the whole mechanism into something the caller controls. There is a
test that sends forged headers through a live proxy and asserts they never arrive.

Values are always present, never omitted on failure. `x-fp-verdict: unknown` means fpd
looked and found no match, and `unparsed` means the handshake could not be read. An
absent header would be indistinguishable from fpd not being in the path at all.

**Fingerprinting never breaks the site.** If a handshake cannot be parsed the request is
still proxied, annotated `unparsed`. An unreachable upstream returns 502. A sidecar that
can 500 the application it protects is worse than no sidecar.

Upstream is HTTP/1.1 only in this version, which is the usual sidecar shape where the
upstream is a local application. Client-facing HTTP/2 and HTTP/1.1 are both supported.

Logging is one line per connection, at WARN when a claim mismatch is detected and INFO
otherwise, so the level is the thing to alert on. Client IPs are truncated by default,
and `--ip-mode` takes `full`, `truncated` or `omitted`.

### Watching a running instance

`serve` keeps the last 1000 connections in memory and can expose them on a read-only
Unix socket:

```console
$ fpd serve --listen 127.0.0.1:8443 --upstream 127.0.0.1:8080 \
            --admin-socket /run/fpd.sock
```

Newline-delimited JSON, one object per connection, server to client only. A viewer
receives the buffered history, then a `snapshot_end` marker, then everything that
arrives afterwards. That format was chosen so it can be read without a client:

```console
$ nc -U /run/fpd.sock
{"type":"record","seq":0,"at_ms":1786614271000,"ip":"45.9.148.0",
 "ja4":"t13i4906h2_0d8feac7bc37_7395dae3b2f3","verdict":"curl-8.7.1-macos",
 "score":1.0,"mismatch":false,"alpn":"h2","raw_hello":"FgMBAgAB...",
 "provenance":{"ciphers":{"start":76,"len":98},...}}
{"type":"snapshot_end","seq":0}
```

Each frame carries the ClientHello bytes and the byte ranges each fingerprinted field
came from, so a viewer can show which bytes produced a fingerprint without asking the
server again.

Four things worth knowing before relying on it:

- **The socket is created mode 0600.** It carries client addresses and fingerprints, so
  it is restricted to the user running `fpd`. There is a test asserting the mode.
- **No socket exists unless you pass the flag.** An observability endpoint that appears
  by default is an exposure nobody asked for.
- **Nothing is persisted.** The buffer is in memory, bounded, and gone when the process
  ends. `fpd` never writes traffic to disk.
- **A viewer that stops reading is dropped, not queued.** Records are discarded for that
  client rather than blocking the proxy, and the gap is visible as a jump in `seq`. A
  monitoring socket must never be able to stall the traffic it monitors.

The JSON shape is **not a stable interface** yet. It exists to be inspected and to feed
`fpd tui`, and it may change without notice until that lands.

Unix only. On other platforms the flag is accepted and reported as unsupported rather
than silently doing nothing.

### Rust applications need no proxy at all

`serve` costs a process, a localhost hop, and something extra to deploy and keep alive.
A Rust application needs none of that. One line changes, at the TLS accept point:

```rust
// before
let acceptor = TlsAcceptor::from(config);
// after
let acceptor = fingerprint_tower::Acceptor::new(config);
```

Then per connection, add one layer to the router you already have:

```rust
let accepted = acceptor.accept(tcp).await?;
let app = Router::new()
    .route("/", get(handler))
    .layer(FingerprintLayer::new(accepted.fingerprint));
```

And every handler knows what its caller is:

```rust
async fn handler(Extension(fp): Extension<ClientFingerprint>) -> String {
    if fp.mismatch() {
        // User-Agent says one thing, the TLS handshake says another.
    }
    fp.ja4.clone()
}
```

This cannot be written as ordinary HTTP middleware. By the time a request reaches axum,
rustls has finished the handshake and dropped the ClientHello, taking extension order and
GREASE placement with it. The hook has to sit below HTTP, which is why it replaces the
acceptor rather than adding a layer to the router alone.

Two things to know before choosing this over `serve`:

- **The fingerprint is per connection, not per request.** HTTP/2 multiplexes, so every
  request on one connection shares one fingerprint. That is correct, because a
  fingerprint describes the client rather than the request, but it surprises people.
- **You still own the accept loop**, so connection limits and timeouts stay your
  responsibility. `serve` bounds those itself. This does not, because it does not own
  the listener.

And the obvious one: this is Rust only. Anything else uses `serve`.

## The HTTP layer is fpd's own, not JA4H

fpd compares HTTP headers as a list of named fields rather than as a hash. There is a
licensing reason and two engineering reasons, and the engineering ones came first.

A hash cannot be diffed. `hash 974ebe531c03, expected a1b2c3d4e5f6` tells you something
differs. `missing: sec-ch-ua, sec-fetch-site, accept-language` tells you what. Since
fpd's whole purpose is answering the second question, hashing the HTTP layer would work
against the tool.

Header values are also never read. JA4H hashes cookie fields together with their values,
which contradicts the privacy position below. fpd records the number of `cookie` headers
instead, which is real signal because HPACK splits them, and requires reading nothing.

Finally, JA4H fingerprints a **request** while fpd profiles a **client**. Method and
referer change between requests from the same browser, so comparing them would make
Chrome fail to match its own profile. Those fields are reported but never compared.

On licensing: JA4 (TLS) is BSD 3-Clause with no patent claims, which is why it is
implemented here. The rest of the JA4+ suite, including JA4H, is patent pending and
licensed under FoxIO License 1.1, which is not permissive for monetization. Rather than
take on that question, fpd uses its own design. Anyone wanting JA4H specifically should
talk to FoxIO.

## Terms and licence

fpd can measure client identities and also reproduce them. That is dual use, in the same
way `uTLS`, `curl-impersonate` and `nmap` are dual use. It is handled explicitly.

Every invocation is gated on accepting [`TERMS.md`](TERMS.md). Not only emulation. The
whole binary.

```console
$ fpd serve
fpd: you must accept the terms and conditions first.

  This tool can both measure and reproduce TLS/HTTP-2 client identities.
  Responsibility for how it is used rests solely with you, not the author.

  Read them:    fpd terms show
  Accept them:  fpd terms accept
```

The terms text is compiled into the binary with `include_str!`. Nothing reads it from
disk at runtime, so deleting or editing a `TERMS.md` on your filesystem changes nothing
about what a built binary shows or what an acceptance is bound to.

Canonical terms hash, for verifying that a binary is a genuine build:

```
sha256:143e8d871d94cb826596e0d5a70cf0666662065ac3faa9648c2fa16795b1b0ac
```

```console
$ fpd terms show --hash
```

A binary reporting anything else is not a genuine release.

### What the gate does and does not achieve

- It makes the terms unavoidable on every path through a released binary. No user
  reaches any functionality without an explicit, recorded acceptance.
- It resists tampering with the acceptance record. Editing it fails HMAC validation.
  Deleting it locks you out rather than letting you through. No file exists whose
  removal disables the gate.
- It does not make the tool tamper proof against someone rebuilding it. The source is
  available, so a determined user can fork it, strip the check and compile their own
  binary. That is true of every open and source available tool and cannot be engineered
  away. What it costs them is deliberate and demonstrable circumvention, which is the
  line the terms exist to draw.

### Permanent non-goals

- No per-site presets and no bypass bundles. Profiles describe browsers, never targets.
  A profile named after a website will not be shipped.
- No JavaScript challenge or CAPTCHA solving. fpd works at TLS and HTTP/2 only.
- No IP reputation, geolocation or threat intel enrichment.

## Privacy

A fingerprint is a tracking vector, and a fingerprint together with an IP is close
enough to personal data to be treated as such.

- Header values are not read, with **one documented exception**. `user-agent` is read,
  because claim mismatch detection compares what a client says it is against what its
  fingerprint shows it to be, and the claim lives in that value. Cookie, authorization
  and every other header value never enter the fingerprint path, and a test enforces
  that by planting fake secrets and asserting they never reach any output.
- Cookies are counted, never parsed. HPACK splits a cookie header into several, and the
  count alone is signal, so no cookie value is ever read.
- IP handling is configurable. Full, truncated, hashed with a rotating salt, or omitted.
- Log retention is configurable. fpd requires no database.

## Build

```console
$ cargo build --release
$ ./target/release/fpd terms show
$ ./target/release/fpd terms accept
```

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --check
```

## Credits

JA4 (TLS Client Fingerprinting) was created by FoxIO and released under BSD 3-Clause
with no patent claims. fpd implements it from the published specification. JA4 and JA4+
are trademarks of FoxIO. See <https://github.com/FoxIO-LLC/ja4>.

The HPACK implementation follows RFC 7541. Its Huffman code and static table are
normative data from the RFC.

## Repository layout

```
crates/fingerprint-terms/   embedded terms, signed acceptance record, the gate
crates/fingerprint-core/    ClientHello parsing, JA3, JA4
crates/fingerprint-h2/      HTTP/2 frame walk, HPACK, Akamai fingerprint
crates/fingerprint-probe/   capture probe, profile database, diff engine
crates/fingerprint-tower/   embedded acceptor and tower layer for Rust apps
crates/fpd/                 the fpd binary (package: flux-parsing-daemon)
scripts/bin2pcap.py         wraps a byte fixture in a pcap for tshark
spikes/                     throwaway risk spikes, excluded from the workspace
docs/design/                the design specification
docs/plans/                 implementation plans
docs/spikes/                spike findings and raw capture output
```

The crates.io package is `flux-parsing-daemon` and the installed binary is `fpd`. The
name `fpd` was already taken on crates.io.
