#![no_main]

//! Fuzzes the full parse path. Every length field in a ClientHello is
//! attacker-controlled, so the contract under test is simply: never panic.
//!
//! Seeded from the committed fixtures, which puts the fuzzer straight into
//! structurally valid territory instead of making it discover the record header
//! by chance.

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = fingerprint_core::hello::parse_hello(data);
    let _ = fingerprint_core::ja4::fingerprint(data);
});
