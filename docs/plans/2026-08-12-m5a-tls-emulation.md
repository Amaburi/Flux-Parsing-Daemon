# fpd M5a — Verified TLS Emulation

> Execute task-by-task. Every task ends at a hard stop for review and commit.

**Goal:** Build a TLS client that reproduces a stored profile, and prove it does, in a test, with no external network.

**Why this is the point of the project:** `curl-impersonate`, `uTLS`, `curl_cffi` and `rquest` all emit browser-shaped handshakes and all ask you to believe they still work. None can answer whether their output still matches Chrome after a dependency bump, because the emitter and the ground truth live in different projects. fpd already holds the parser, the profile database and a capture probe. Adding the emitter closes the loop.

**Architecture:** New crate `crates/fingerprint-emulate`, behind a non-default cargo feature. Builds a BoringSSL client from a `Profile`. Verification binds the existing `Probe` in-process, drives the emulated client at it, and diffs the captured result against the profile it was built from.

## Scope split

**M5a, this plan: the TLS layer.** Ciphers, extensions, GREASE, ALPN, and the
verification loop.

**M5b, later: the HTTP/2 layer.** SETTINGS order, WINDOW_UPDATE and pseudo-header order
cannot be controlled through the stock `h2` crate, so that needs a patched or hand-written
writer. It is a separate hard problem and bundling it here would make neither reviewable.

M5a alone is shippable and demonstrates the headline property.

## What the M0 S3 spike already established

Against a live-captured Chrome baseline, `boring` 4.22.0 reproduced the cipher list in
exact order and GREASE placement exactly, **with no tuning**. Five extensions were
missing, and each was checked against the crate rather than assumed:

| Ext | Name | How | Verified |
|---|---|---|---|
| 5 | `status_request` | `enable_ocsp_stapling()` | safe API |
| 18 | `signed_certificate_timestamp` | `enable_signed_cert_timestamps()` | safe API |
| 27 | `compress_certificate` | `add_certificate_compression_algorithm()` | safe API |
| 65037 | `encrypted_client_hello` | `set_enable_ech_grease()` | safe API |
| 17613 | `application_settings` (ALPS) | `SSL_add_application_settings` | **unsafe FFI only** |

Plus `set_permute_extensions()` for Chrome's per-connection shuffling.

Two extensions appeared that the baseline lacked, and neither is a real gap. SNI (`0`) was
a test artefact, since the spike passed a hostname while the baseline was captured against
a bare IP. Padding (`21`) is size-dependent and may disappear once the five missing
extensions add bytes, so it should be re-measured rather than fixed directly.

## Global Constraints

- **Behind a non-default cargo feature, `emulation`.** Enabling it is an explicit opt-in
  in the consumer's `Cargo.toml`, per design §4.2.
- The terms gate already covers the whole binary, so `fpd emulate` inherits it. No new
  gate logic.
- BoringSSL compiles from source, roughly 50 seconds cold on this machine. CI must build
  the feature explicitly or it will never be exercised.
- No test reaches a network beyond loopback.

## Commit Protocol

**The implementer never runs `git commit` or `git push`.** Stop at each task, print the command, wait.

---

## Equivalence is what makes verification meaningful

A naive implementation compares emitted bytes to captured bytes and fails immediately,
because **two consecutive real Chrome handshakes are not identical to each other**.
Chrome permutes its extension order every connection and its GREASE values rotate.

The profile already records how to compare, from M0 findings 1 through 3:

```json
"equivalence": { "cipher_order": "fixed", "extension_order": "permuted" }
```

Verification therefore asserts equivalence **under the profile's own stated class**, not
byte equality. Getting this backwards in either direction is fatal: compare literally and
every Chrome verification flakes, compare too loosely and a genuinely wrong handshake
passes. The diff engine already encodes both rules and is reused rather than reimplemented.

---

### Task 1: The crate, behind a feature

**Files:** `crates/fingerprint-emulate/Cargo.toml`, `src/lib.rs`

- [ ] `cargo new`, add `boring`, `tokio-boring`, and the local crates.
- [ ] The whole crate body sits behind `#[cfg(feature = "emulation")]`, and the feature is
      **not** in `default`.
- [ ] Test: the crate builds with the feature off and exposes nothing.
- [ ] Test: it builds with the feature on.
- [ ] STOP — commit.

---

### Task 2: Building a client from a profile

**Files:** `crates/fingerprint-emulate/src/build.rs`

**Interfaces:** `build(&Profile) -> Result<ConnectConfiguration, EmulateError>`, `cipher_list_for(&Profile) -> String`.

- [ ] **Step 1: Write the failing tests**

```rust
/// Cipher names are derived from the profile's numeric list, so a new profile
/// works without code changes. An unknown cipher is an error, not a silent skip:
/// dropping one would produce a handshake that verifies against nothing.
#[test]
fn cipher_ids_map_to_openssl_names() {
    assert_eq!(cipher_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
    assert_eq!(cipher_name(0xc02b), Some("ECDHE-ECDSA-AES128-GCM-SHA256"));
    assert_eq!(cipher_name(0xffff), None);
}

#[test]
fn an_unknown_cipher_in_a_profile_is_an_error_not_a_silent_omission() {
    let mut p = profile("chrome-macos");
    p.tls.ciphers.push(0xffff);
    assert!(build(&p).is_err());
}

#[test]
fn the_chrome_profile_produces_a_cipher_list_in_its_stored_order() {
    let list = cipher_list_for(&profile("chrome-macos")).expect("list");
    assert!(list.starts_with("TLS_AES_128_GCM_SHA256"));
}
```

- [ ] **Step 2–4:** red, implement, green. Apply the five extension calls from the table
      above, plus `set_grease_enabled` and `set_permute_extensions` when the profile's
      extension order is `permuted`.
- [ ] **ALPS needs unsafe FFI.** Isolate it in one function with a comment naming why, so
      the unsafe block is auditable rather than scattered.
- [ ] STOP — commit.

---

### Task 3: The verification loop

**Files:** `crates/fingerprint-emulate/src/verify.rs`

**Interfaces:** `verify(&Profile) -> Result<Diff, EmulateError>`.

Binds the existing `Probe` in-process, connects the emulated client to it, captures, and
diffs against the source profile. No external network, so this runs in CI.

- [ ] **Step 1: Write the failing tests**

```rust
/// The headline property. If this passes, the emulation is not asserted, it is
/// demonstrated.
#[tokio::test]
async fn every_shipped_profile_verifies_against_itself() {
    for p in ProfileDb::shipped().expect("db").iter() {
        let d = verify(p).await.expect("verify");
        assert!(d.is_clean(), "{} did not reproduce:\n{d}", p.label);
    }
}

/// A permuted profile must hold across repeated draws, or the equivalence class
/// is not actually being exercised.
#[tokio::test]
async fn a_permuted_profile_verifies_repeatedly() {
    let p = profile("chrome-macos");
    for i in 0..8 {
        assert!(verify(&p).await.expect("verify").is_clean(), "draw {i}");
    }
}

/// The negative case. Verification that cannot fail proves nothing, so a
/// deliberately corrupted profile must be reported as not reproduced.
#[tokio::test]
async fn a_profile_the_client_cannot_reproduce_fails_verification() {
    let mut p = profile("chrome-macos");
    p.tls.ciphers.reverse();
    let d = verify(&p).await.expect("verify ran");
    assert!(!d.is_clean(), "a wrong cipher order must not verify");
}
```

**If a shipped profile does not verify, do not relax the profile.** Record which fields
differ, since that list is the honest state of the emulation, and the S3 spike predicted
exactly five. A verification loosened until it passes is worse than none.

- [ ] **Step 2–4:** red, implement, green.
- [ ] STOP — commit.

---

### Task 4: `fpd emulate --verify`

- [ ] Wire the existing stub subcommand. `--profile`, `--verify`.
- [ ] Output names each field and whether it matched, in the shape design §6.9 specifies.
- [ ] Exit 0 on equivalence, 1 on difference, 2 on operational failure, matching `check`.
- [ ] Integration test through the real binary, including that the terms gate still
      refuses it without acceptance.
- [ ] STOP — commit.

---

### Task 5: CI and docs

- [ ] CI builds and tests with `--features emulation`, or the whole crate is never
      exercised.
- [ ] README: the verification loop, with real output, and the honest state of which
      fields reproduce.
- [ ] STOP — commit.

---

## Self-Review

**Spec coverage.** §6.9 emulation, the equivalence classes, and `--verify` → Tasks 2 to 4.
§4.2's non-default feature → Task 1.

**Known risks.**
1. **The five extensions may not all land.** S3 confirmed each has an API but did not
   exercise them together. If ALPS in particular resists, the honest outcome is a
   verification that reports four of five reproduced, not a loosened comparison.
2. **Padding (extension 21) may still differ.** It is size-dependent and was present in
   the spike's output but not the baseline. Re-measure after the five are added rather
   than special-casing it.
3. **Only two profiles exist**, and one is a resuming Chrome session whose extension count
   differs from a fresh handshake. Verification against it exercises the resumed shape only.
4. **BoringSSL is a C dependency** reachable only through the non-default feature, so a
   default build does not carry it. That is deliberate and worth keeping.
