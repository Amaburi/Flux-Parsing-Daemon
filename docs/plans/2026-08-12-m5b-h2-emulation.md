# fpd M5b — HTTP/2 Emulation

> Execute task-by-task. Every task ends at a hard stop for review and commit.

**Goal:** Emit an HTTP/2 preamble that reproduces a profile's Akamai fingerprint, and extend verification to cover it.

## Why not patch the `h2` crate

The design document assumed a vendored and patched `h2` would be needed, because
stock `h2` normalises SETTINGS and hides frame order, which is the measurement
itself. That assumption is worth revisiting now that the shape of the work is clear.

**We do not need an HTTP/2 client. We need to emit a preamble.** Preface, SETTINGS,
WINDOW_UPDATE and one HEADERS frame, then stop. That is a few hundred bytes of
writing, against roughly 15,000 lines of vendored `h2` to maintain and re-patch on
every upstream release.

The same reasoning that replaced the HPACK decoder applies: the narrow thing we
actually need is small, and owning it removes a dependency we would otherwise have
to track forever.

## What already exists to build on

- `fingerprint_h2::hpack` decodes HPACK, including the static table and the RFC 7541
  Huffman code, both already validated. Encoding reuses the same tables.
- `H2Profile` stores `settings` as an ordered `Vec<(u16, u32)>`, `window_update`, and
  `pseudo_order`. Everything the emitter needs is already recorded.
- The probe already parses what we emit, so verification is a matter of connecting
  the two.

## Global Constraints

- Behind the same non-default `emulation` feature.
- Reuses the existing Huffman and static tables. No second copy.
- Emission order comes from the profile, never from a default.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Stop at each task, print the command, wait.

---

### Task 1: HPACK encoding

**Files:** `crates/fingerprint-h2/src/hpack/encode.rs`

**Interfaces:** `encode_integer(value, prefix_bits, prefix_value) -> Vec<u8>`, `encode_huffman(&[u8]) -> Vec<u8>`, `encode_headers(&[(String, String)]) -> Vec<u8>`.

- [ ] **Step 1: Write the failing tests, round-tripping against the decoder we already trust**

```rust
/// The decoder is already validated against RFC vectors and tshark, so
/// round-tripping through it is a real check rather than a tautology.
#[test]
fn encoding_then_decoding_returns_the_original_headers() {
    let h = vec![
        (":method".to_string(), "GET".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];
    assert_eq!(decode(&encode_headers(&h)).expect("decode"), h);
}

/// RFC 7541 C.1 in reverse.
#[test]
fn integer_encoding_matches_the_rfc_examples() {
    assert_eq!(encode_integer(10, 5, 0x00), vec![0x0a]);
    assert_eq!(encode_integer(1337, 5, 0x00), vec![0x1f, 0x9a, 0x0a]);
    assert_eq!(encode_integer(42, 8, 0x00), vec![0x2a]);
}

/// RFC 7541 C.4.1 in reverse.
#[test]
fn huffman_encoding_matches_the_rfc_example() {
    assert_eq!(
        encode_huffman(b"www.example.com"),
        vec![0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
    );
}

/// Static table hits must use the indexed form, as real clients do. Encoding
/// `:method GET` as a literal would decode identically but look nothing like a
/// browser on the wire.
#[test]
fn static_table_entries_use_the_indexed_representation() {
    let h = vec![(":method".to_string(), "GET".to_string())];
    assert_eq!(encode_headers(&h), vec![0x82]);
}
```

- [ ] **Step 2–4:** red, implement, green.
- [ ] STOP — commit.

---

### Task 2: The preamble writer

**Files:** `crates/fingerprint-emulate/src/h2.rs`

**Interfaces:** `preamble_for(&Profile, authority: &str) -> Result<Vec<u8>, EmulateError>`.

- [ ] **Step 1: Write the failing tests**

```rust
/// The whole point. What we emit must parse back to the profile's own Akamai
/// string, using the parser that reads real browsers.
#[test]
fn the_emitted_preamble_reproduces_the_profile_akamai_string() {
    let p = profile("chrome-macos");
    let bytes = preamble_for(&p, "example.com").expect("preamble");
    let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");
    assert_eq!(Some(fp.akamai), p.h2.map(|h| h.akamai));
}

/// M0 S2 finding: curl sends settings as 3, 4, 2, not ascending. Emission must
/// preserve the profile's order or the fingerprint changes.
#[test]
fn settings_are_emitted_in_the_profile_order_not_sorted() {
    let p = profile("curl-8.7.1-macos");
    let bytes = preamble_for(&p, "example.com").expect("preamble");
    let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");
    assert_eq!(fp.settings, p.h2.expect("h2").settings);
}

/// Pseudo-header order is one of the two discriminators the Akamai fingerprint
/// rests on, so it must come from the profile rather than a fixed order.
#[test]
fn pseudo_header_order_follows_the_profile() {
    for (label, want) in [("chrome-macos", "m,a,s,p"), ("curl-8.7.1-macos", "m,s,a,p")] {
        let bytes = preamble_for(&profile(label), "example.com").expect("preamble");
        let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");
        assert_eq!(fp.pseudo_order, want, "{label}");
    }
}
```

- [ ] **Step 2–4:** red, implement, green.
- [ ] STOP — commit.

---

### Task 3: Verification covers HTTP/2

- [ ] After the TLS handshake, the emulated client writes the preamble.
- [ ] `verify` stops filtering HTTP/2 out of the diff, since there is now something
      to compare.
- [ ] Test: the full diff is clean for the Chrome profile, TLS and HTTP/2 together.
- [ ] Remove the "TLS layer only" note from `fpd emulate` output, which becomes
      false at this point.
- [ ] STOP — commit.

---

### Task 4: Docs

- [ ] README: the verification loop now covers both layers. Remove the HTTP/2
      limitation, and state whatever remains instead of leaving the old text.
- [ ] STOP — commit.

---

## Self-Review

**Spec coverage.** §6.9's H2 write path → Tasks 1 and 2. The full closed loop → Task 3.

**Known risks.**
1. **HPACK encoding shape is not part of our fingerprint.** Two encoders can produce
   the same decoded headers from different bytes. Our Akamai fingerprint captures
   pseudo-header *order*, not the representations chosen, so a verification can pass
   while the byte pattern still differs from a real browser. Using indexed forms for
   static-table hits narrows this considerably, and the residual gap should be stated
   rather than hidden.
2. **The emitted request is minimal.** A real Chrome request carries the
   `sec-ch-ua` and `sec-fetch-` block. Reproducing the HTTP-layer header list is a
   further step beyond reproducing the Akamai fingerprint.
3. **No PRIORITY frames.** Modern clients do not send them, so the field stays `0`.
   A Firefox profile would need the priority tree emitted.
