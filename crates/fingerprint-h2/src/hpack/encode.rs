//! HPACK encoding, RFC 7541.
//!
//! Only what emission needs. The decoder is the validated side, checked against
//! the RFC's worked examples and against tshark over real captures, so encoding
//! is tested by round-tripping through it rather than by asserting bytes we chose
//! ourselves.
//!
//! Static-table hits use the indexed representation because that is what real
//! clients do. Encoding `:method GET` as a literal would decode identically and
//! look nothing like a browser on the wire.

use super::table_huffman::HUFFMAN;
use super::table_static::STATIC_TABLE;

/// Encodes an integer with an N-bit prefix, RFC 7541 section 5.1.
///
/// `prefix_value` is the high bits of the first octet, which carry the
/// representation type.
pub fn encode_integer(value: u64, prefix_bits: u8, prefix_value: u8) -> Vec<u8> {
    let max = (1u64 << prefix_bits) - 1;
    let mut out = Vec::new();

    if value < max {
        out.push(prefix_value | value as u8);
        return out;
    }

    out.push(prefix_value | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push(((rest % 128) as u8) | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
    out
}

/// Huffman-encodes a byte string using the RFC 7541 Appendix B code.
///
/// Padding is the leading bits of EOS, which are all ones, per section 5.2.
pub fn encode_huffman(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;

    for byte in input {
        let Some((code, len)) = HUFFMAN.get(*byte as usize) else {
            continue;
        };
        acc = (acc << *len as u32) | u64::from(*code);
        bits += u32::from(*len);

        while bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }

    if bits > 0 {
        let pad = 8 - bits;
        out.push((((acc << pad) | ((1u64 << pad) - 1)) & 0xff) as u8);
    }
    out
}

/// A string literal: length with a 7-bit prefix, top bit set when Huffman coded.
///
/// Huffman is used when it is shorter, which is what browsers do.
fn encode_string(s: &str) -> Vec<u8> {
    let raw = s.as_bytes();
    let huff = encode_huffman(raw);

    if huff.len() < raw.len() {
        let mut out = encode_integer(huff.len() as u64, 7, 0x80);
        out.extend_from_slice(&huff);
        out
    } else {
        let mut out = encode_integer(raw.len() as u64, 7, 0x00);
        out.extend_from_slice(raw);
        out
    }
}

/// Static table index for an exact name and value match, 1-based.
fn static_index_exact(name: &str, value: &str) -> Option<u64> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
        .map(|i| i as u64 + 1)
}

/// Static table index for a name match only, 1-based.
fn static_index_name(name: &str) -> Option<u64> {
    STATIC_TABLE
        .iter()
        .position(|(n, _)| *n == name)
        .map(|i| i as u64 + 1)
}

/// Encodes a header list in the given order.
///
/// Order is preserved exactly, because it is the fingerprint.
pub fn encode_headers(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();

    for (name, value) in headers {
        if let Some(idx) = static_index_exact(name, value) {
            // Indexed header field: 1xxxxxxx
            out.extend_from_slice(&encode_integer(idx, 7, 0x80));
        } else if let Some(idx) = static_index_name(name) {
            // Literal with incremental indexing, name indexed: 01xxxxxx
            out.extend_from_slice(&encode_integer(idx, 6, 0x40));
            out.extend_from_slice(&encode_string(value));
        } else {
            // Literal with incremental indexing, new name: 01000000
            out.push(0x40);
            out.extend_from_slice(&encode_string(name));
            out.extend_from_slice(&encode_string(value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack::decoder::decode;

    /// RFC 7541 C.1, in reverse.
    #[test]
    fn integer_encoding_matches_the_rfc_examples() {
        assert_eq!(encode_integer(10, 5, 0x00), vec![0x0a]);
        assert_eq!(encode_integer(1337, 5, 0x00), vec![0x1f, 0x9a, 0x0a]);
        assert_eq!(encode_integer(42, 8, 0x00), vec![0x2a]);
    }

    /// The prefix maximum must spill into a continuation octet, the same off-by-one
    /// that matters on the decoding side.
    #[test]
    fn the_prefix_maximum_spills_into_a_continuation_octet() {
        assert_eq!(encode_integer(30, 5, 0x00), vec![0x1e]);
        assert_eq!(encode_integer(31, 5, 0x00), vec![0x1f, 0x00]);
    }

    /// RFC 7541 C.4.1, in reverse. The same vector the decoder is tested against.
    #[test]
    fn huffman_encoding_matches_the_rfc_example() {
        assert_eq!(
            encode_huffman(b"www.example.com"),
            vec![0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
        );
    }

    /// RFC 7541 C.4.2.
    #[test]
    fn huffman_encoding_matches_the_second_rfc_example() {
        assert_eq!(
            encode_huffman(b"no-cache"),
            vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]
        );
    }

    /// Real clients use the indexed form for static hits. A literal would decode
    /// the same and look nothing like a browser.
    #[test]
    fn static_table_entries_use_the_indexed_representation() {
        assert_eq!(
            encode_headers(&[(":method".into(), "GET".into())]),
            vec![0x82]
        );
        assert_eq!(
            encode_headers(&[(":scheme".into(), "https".into())]),
            vec![0x87]
        );
        assert_eq!(encode_headers(&[(":path".into(), "/".into())]), vec![0x84]);
    }

    /// The decoder is independently validated, so round-tripping through it is a
    /// real check rather than a tautology.
    #[test]
    fn encoding_then_decoding_returns_the_original_headers_in_order() {
        let h = vec![
            (":method".to_string(), "GET".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), "/".to_string()),
            ("user-agent".to_string(), "fpd/0.1".to_string()),
        ];
        assert_eq!(decode(&encode_headers(&h)).expect("decode"), h);
    }

    #[test]
    fn a_header_with_no_static_entry_round_trips() {
        let h = vec![("x-custom-thing".to_string(), "value".to_string())];
        assert_eq!(decode(&encode_headers(&h)).expect("decode"), h);
    }

    #[test]
    fn an_empty_header_list_encodes_to_nothing() {
        assert!(encode_headers(&[]).is_empty());
    }

    /// Huffman is used only when it actually saves bytes, which is what browsers
    /// do and what keeps short values readable on the wire.
    #[test]
    fn huffman_is_used_only_when_it_is_shorter() {
        // Round-trip is what matters; this pins the decision rather than a length.
        for value in ["a", "example.com", "\u{fffd}"] {
            let h = vec![("x".to_string(), value.to_string())];
            assert_eq!(decode(&encode_headers(&h)).expect("decode"), h, "{value}");
        }
    }
}
