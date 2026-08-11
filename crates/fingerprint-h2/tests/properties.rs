//! Property and robustness tests over the public API.
//!
//! HPACK is decoded by an external crate, so these also serve as the panic-freedom
//! contract for that dependency, not only for our own code.

use fingerprint_h2::{akamai, frame::parse_preamble};
use proptest::prelude::*;

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.bin"));
    std::fs::read(p).expect("fixture")
}

const FIXTURES: &[&str] = &["curl-8.7.1-h2", "chrome-h2"];
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[test]
fn truncating_every_fixture_at_every_offset_never_panics() {
    for name in FIXTURES {
        let raw = fixture(name);
        for cut in 0..=raw.len() {
            let slice = raw.get(..cut).unwrap_or_default();
            let _ = parse_preamble(slice);
            let _ = akamai::fingerprint(slice);
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(data: Vec<u8>) {
        let _ = parse_preamble(&data);
        let _ = akamai::fingerprint(&data);
    }

    /// Preface-prefixed garbage reaches far deeper into the parser than random
    /// noise, which mostly bounces off the preface check.
    #[test]
    fn preface_prefixed_garbage_never_panics(body in prop::collection::vec(any::<u8>(), 0..800)) {
        let mut data = PREFACE.to_vec();
        data.extend_from_slice(&body);
        let _ = parse_preamble(&data);
        let _ = akamai::fingerprint(&data);
    }

    /// Drives the HPACK decoder with a well-formed frame header wrapping arbitrary
    /// payload bytes, including the PRIORITY and PADDED flag combinations that
    /// shift where the header block starts.
    #[test]
    fn arbitrary_headers_payloads_never_panic(
        flags: u8,
        body in prop::collection::vec(any::<u8>(), 0..300),
    ) {
        let mut data = PREFACE.to_vec();
        let len = body.len() as u32;
        data.extend_from_slice(&len.to_be_bytes()[1..]);
        data.push(0x1);              // HEADERS
        data.push(flags);
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&body);
        let _ = akamai::fingerprint(&data);
    }

    #[test]
    fn single_byte_corruption_of_a_real_preamble_never_panics(idx in 0usize..679, byte: u8) {
        let mut raw = fixture("chrome-h2");
        if let Some(b) = raw.get_mut(idx) {
            *b = byte;
        }
        let _ = akamai::fingerprint(&raw);
    }

    /// A frame length that lies about the real one must not over-read.
    #[test]
    fn lying_frame_lengths_never_panic(declared in 0u32..0xff_ffff) {
        let mut raw = fixture("curl-8.7.1-h2");
        let at = PREFACE.len();
        if let Some(slot) = raw.get_mut(at..at + 3) {
            slot.copy_from_slice(&declared.to_be_bytes()[1..]);
        }
        let _ = parse_preamble(&raw);
    }
}
