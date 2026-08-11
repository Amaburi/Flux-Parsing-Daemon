#![no_main]

//! Fuzzes the whole preamble path: preface, frame headers, SETTINGS,
//! WINDOW_UPDATE, PRIORITY, and HPACK.
//!
//! HPACK used to be excluded here. The decoder was `fluke-hpack` 0.3.1, which
//! panics on malformed input, and the containment wrapper relied on
//! `catch_unwind`, which cannot function under the `panic = "abort"` that
//! cargo-fuzz forces. Fuzzing through it would only have rediscovered the
//! upstream bug in a configuration that never ships.
//!
//! `crate::hpack` returns errors instead of panicking, so the split is gone and
//! this target covers everything again.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = fingerprint_h2::frame::parse_preamble(data);
    let _ = fingerprint_h2::akamai::fingerprint(data);
    let _ = fingerprint_h2::hpack::decoder::decode(data);
});
