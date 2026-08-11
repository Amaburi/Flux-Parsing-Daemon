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
| `fpd check` | **Working.** |
| `fpd capture` | Working. Infers field ordering from repeat samples. |
| `serve` `tui` `emulate` | Not implemented. Stubs. |

Every fingerprint value is checked against tshark rather than against itself. See
[the design](docs/design/2026-08-11-fpd-design.md) and [the plans](docs/plans/).

## Try it

```console
$ fpd terms accept
$ fpd check --profile chrome-macos -- curl -sk --http2 '{url}'
```

```
  ✗ ciphers         4867,4866,4865,…  (chrome-macos: 4865,4866,4867,…)  order rule: Fixed
  ✗ extensions      43,51,11,10,13,16  (chrome-macos: 23,27,45,…)  order rule: Permuted
  ✗ GREASE          0 cipher, 0 extension  (chrome-macos: 1 cipher, 2 extension)
                    absent entirely; no browser omits GREASE
  ✓ ALPN            h2
  ✓ SNI             absent
  ✗ SETTINGS        3:100;4:10485760;2:0  (chrome-macos: 1:65536;2:0;4:6291456;6:262144)
                    sends id 3, which no browser does
  ✗ WINDOW_UPDATE   1048510465  (chrome-macos: 15663105)
  ✗ pseudo-header   m,s,a,p  (chrome-macos: m,a,s,p)
  ✗ header order    user-agent,accept  (chrome-macos: cache-control,sec-ch-ua,…)
                    missing: sec-ch-ua, sec-fetch-site, accept-language, priority, …
  ✗ accept-language absent  (chrome-macos: present)
  verdict: NOT chrome-macos (20% match)
```

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
sha256:7084b58c32452f36777b71b33a5fd34ee123e6043fa4cd4ca582b27286c2cb8a
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

- Header values are never read, logged or stored. Only names, order and counts. Cookie
  and authorization values never enter the fingerprint path.
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
crates/fpd/                 the fpd binary (package: flux-parsing-daemon)
scripts/bin2pcap.py         wraps a byte fixture in a pcap for tshark
spikes/                     throwaway risk spikes, excluded from the workspace
docs/design/                the design specification
docs/plans/                 implementation plans
docs/spikes/                spike findings and raw capture output
```

The crates.io package is `flux-parsing-daemon` and the installed binary is `fpd`. The
name `fpd` was already taken on crates.io.
