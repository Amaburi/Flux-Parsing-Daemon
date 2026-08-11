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
| `fingerprint-h2` | In progress. HTTP/2 frame walk, HPACK, Akamai fingerprint. |
| `serve` `tui` `check` `capture` `emulate` | Not implemented. Stubs. |

92 tests pass. Every fingerprint value is checked against tshark rather than against
itself. See [the design](docs/design/2026-08-11-fpd-design.md) and
[the plans](docs/plans/).

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

## Repository layout

```
crates/fingerprint-terms/   embedded terms, signed acceptance record, the gate
crates/fingerprint-core/    ClientHello parsing, JA3, JA4
crates/fingerprint-h2/      HTTP/2 frame walk, HPACK, Akamai fingerprint
crates/fpd/                 the fpd binary (package: flux-parsing-daemon)
scripts/bin2pcap.py         wraps a byte fixture in a pcap for tshark
spikes/                     throwaway risk spikes, excluded from the workspace
docs/design/                the design specification
docs/plans/                 implementation plans
docs/spikes/                spike findings and raw capture output
```

The crates.io package is `flux-parsing-daemon` and the installed binary is `fpd`. The
name `fpd` was already taken on crates.io.
