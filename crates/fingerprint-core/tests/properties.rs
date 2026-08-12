//! Property and robustness tests over the public API.
//!
//! The parser consumes attacker-controlled length fields. The contract is that no
//! input, however malformed, may panic.

use fingerprint_core::{hello::parse_hello, ja4};
use proptest::prelude::*;

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.bin"));
    std::fs::read(p).expect("fixture")
}

const FIXTURES: &[&str] = &["curl-8.7.1-macos", "curl-8.7.1-macos-sni", "chrome-macos"];

// --- ja4_r: the pre-hash strings, checked against tshark ---------------------

/// tshark's `tls.handshake.ja4_r` for these exact bytes. Matching this means our
/// intermediate lists, not merely the final hash, agree with an independent
/// implementation. A hash-only check could pass with two compensating errors.
#[test]
fn ja4_r_matches_the_tshark_oracle() {
    let expected: &[(&str, &str)] = &[
        (
            "curl-8.7.1-macos",
            "t13i4906h2_0004,0005,000a,0016,002f,0033,0035,0039,003c,003d,0041,0045,0067,006b,0081,0084,0088,009c,009d,009e,009f,00ba,00be,00c0,00c4,00ff,1301,1302,1303,c007,c008,c009,c00a,c011,c012,c013,c014,c023,c024,c027,c028,c02b,c02c,c02f,c030,cca8,cca9,ccaa,ff85_000a,000b,000d,002b,0033_0806,0601,0603,0805,0501,0503,0804,0401,0403,0201,0203",
        ),
        (
            "chrome-macos",
            "t13i1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,0029,002b,002d,0033,44cd,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601",
        ),
    ];

    for (name, want) in expected {
        let raw = fixture(name);
        let got = ja4::fingerprint(&raw).expect("fingerprint").ja4_r;
        assert_eq!(&got, want, "{name}");
    }
}

// --- robustness --------------------------------------------------------------

#[test]
fn truncating_every_fixture_at_every_offset_never_panics() {
    for name in FIXTURES {
        let raw = fixture(name);
        for cut in 0..=raw.len() {
            let slice = raw.get(..cut).unwrap_or_default();
            let _ = parse_hello(slice);
            let _ = ja4::fingerprint(slice);
        }
    }
}

proptest! {
    /// No byte string, however malformed, may panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(data: Vec<u8>) {
        let _ = parse_hello(&data);
        let _ = ja4::fingerprint(&data);
    }

    /// Bytes that start like a handshake record reach far deeper into the parser
    /// than random noise, which mostly bounces off the first byte check.
    #[test]
    fn handshake_shaped_garbage_never_panics(body in prop::collection::vec(any::<u8>(), 0..600)) {
        let mut data = vec![0x16, 0x03, 0x01];
        data.extend_from_slice(&(body.len() as u16).to_be_bytes());
        data.extend_from_slice(&body);
        let _ = parse_hello(&data);
        let _ = ja4::fingerprint(&data);
    }

    /// Corrupting any single byte of a real ClientHello must error or parse,
    /// never panic. This walks the structured paths a random generator rarely
    /// reaches.
    #[test]
    fn single_byte_corruption_of_a_real_hello_never_panics(
        idx in 0usize..1818,
        byte: u8,
    ) {
        let mut raw = fixture("chrome-macos");
        if let Some(b) = raw.get_mut(idx) {
            *b = byte;
        }
        let _ = parse_hello(&raw);
        let _ = ja4::fingerprint(&raw);
    }

    /// A declared length that lies about the real one must not over-read.
    #[test]
    fn lying_record_lengths_never_panic(declared: u16) {
        let mut raw = fixture("curl-8.7.1-macos");
        if raw.len() > 5 {
            let bytes = declared.to_be_bytes();
            if let Some(slot) = raw.get_mut(3..5) {
                slot.copy_from_slice(&bytes);
            }
        }
        let _ = parse_hello(&raw);
    }
}
