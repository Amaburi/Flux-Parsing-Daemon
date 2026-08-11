# fpd — Flux Parsing Daemon

**TLS/HTTP-2 fingerprint inspection and verified emulation.**

When a request is blocked by a WAF, you get a bare 403 and no reason. Was it your IP,
your TLS fingerprint, your HTTP/2 framing, or a JavaScript challenge? Today the only way
to find out is live experimentation against the real target — slow, unreproducible, and
it burns the source IP's reputation as a side effect of the debugging itself.

fpd makes the byte-level identity of a client visible, in both directions.

> **Status: in development.** The terms gate (M1) is complete and tested. Fingerprint
> parsing, `serve`, `check`, `emulate`, and the TUI are not yet implemented — every
> subcommand below other than `terms` is currently a stub. See
> [the design](docs/design/2026-08-11-fpd-design.md) and
> [the current plan](docs/plans/2026-08-11-m0-m1-foundation-and-terms-gate.md).

---

## What makes it different

Browser-emulation clients already exist — `curl-impersonate`, `uTLS`, `curl_cffi`,
`rquest` — and every one of them asks you to take its emulation on faith. None can
answer *"is my ClientHello actually equivalent to Chrome 131 right now, after that
dependency bump?"*, because the emulator and the ground truth live in different
projects.

fpd holds both the parser and the emitter in one codebase, over one profile database. So
an emulation can be **proven** rather than asserted:

```rust
#[test]
fn emulation_matches_every_shipped_profile() {
    for profile in ProfileDb::load()?.iter() {
        let client = fingerprint_emulate::build(profile)?;
        assert_eq!(probe_locally(&client).diff(profile), Diff::CLEAN);
    }
}
```

No network. Runs in CI. When a dependency bump breaks emulation, the build fails that
day instead of a 403 appearing three weeks later.

## Two directions

| | Mode | Question it answers |
|---|---|---|
| **Inbound** | `serve`, `tui` | Who is hitting my API, and does their TLS agree with their User-Agent? |
| **Outbound** | `check`, `emulate` | What does my own client look like on the wire? |

The highest-value output is **claim/identity mismatch**: a request whose `User-Agent`
says Chrome 131 while its TLS fingerprint says `python-requests`. No real browser can
produce that combination, so the signal needs no tuning by the operator.

## Terms and licence

fpd can both measure *and* reproduce client identities. That is dual-use, in the same
way `uTLS`, `curl-impersonate`, and `nmap` are dual-use, and it is handled explicitly.

**Every invocation is gated on accepting [`TERMS.md`](TERMS.md).** Not just emulation —
the whole binary:

```console
$ fpd serve
fpd: you must accept the terms and conditions first.

  This tool can both measure and reproduce TLS/HTTP-2 client identities.
  Responsibility for how it is used rests solely with you, not the author.

  Read them:    fpd terms show
  Accept them:  fpd terms accept
```

The terms text is compiled into the binary with `include_str!`. It is never read from
disk at runtime, so deleting or editing a `TERMS.md` on your filesystem changes nothing
about what a built binary displays or what an acceptance is bound to.

**Canonical terms hash** — verify any binary against a genuine build:

```
sha256:7084b58c32452f36777b71b33a5fd34ee123e6043fa4cd4ca582b27286c2cb8a
```

```console
$ fpd terms show --hash
```

If that differs from the value above, the binary is not a genuine release.

### What the gate does and does not achieve

Stated plainly, because overstating it would be worse than not having it:

- It **does** make the terms unavoidable on every path through a released binary. No
  user reaches any functionality without an explicit, recorded acceptance.
- It **does** resist tampering with the acceptance record: editing it fails HMAC
  validation, and deleting it locks you out rather than letting you through. There is no
  file whose removal disables the gate.
- It **does not** make the tool tamper-proof against someone rebuilding it. The source
  is available; a determined user can fork, strip the check, and compile their own
  binary. That is true of every open-source and source-available tool and cannot be
  engineered away. What it costs them is deliberate, demonstrable circumvention — which
  is precisely the line the terms exist to draw.

### Non-goals, permanently

- No per-site presets and no "bypass" bundles. Profiles describe *browsers*, never
  *targets*. A profile named after a website will not be shipped.
- No JavaScript-challenge or CAPTCHA solving. fpd operates at TLS and HTTP/2 only.
- No IP reputation, geolocation, or threat-intel enrichment.

## Privacy

A fingerprint is a tracking vector, and fingerprint-plus-IP is PII-adjacent under GDPR.

- Header **values** are never read, logged, or stored — only names, order, and counts.
  Cookie and authorization values never enter the fingerprint path.
- IP handling is configurable: full, truncated, hashed with a rotating salt, or omitted.
- Log retention is configurable, and fpd requires no database.

## Build

```console
$ cargo build --release
$ ./target/release/fpd terms show
$ ./target/release/fpd terms accept
```

Tests, lints, and formatting:

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --check
```

## Repository layout

```
crates/fingerprint-terms/   embedded terms, signed acceptance record, the gate
crates/fpd/                 the fpd binary  (package: flux-parsing-daemon)
spikes/                     throwaway M0 risk spikes, excluded from the workspace
docs/design/                the design specification
docs/plans/                 implementation plans
docs/spikes/                M0 findings and raw capture output
```

Note the crates.io package is `flux-parsing-daemon`; the installed binary is `fpd`. The
name `fpd` was already taken on crates.io.
