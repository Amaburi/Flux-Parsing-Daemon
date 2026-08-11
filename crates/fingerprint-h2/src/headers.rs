//! HPACK decoding.
//!
//! Header **order** is the fingerprint, so the decoder must preserve it. A decoder
//! that returned a map would be unusable here. `fluke-hpack` returns a `Vec` of
//! pairs in wire order, which is the property this module depends on.
//!
//! Independently validated: tshark's `http2.header.name` reports the same names in
//! the same order for both fixtures.

use crate::frame::Frame;

const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

/// Extracts the header block fragment from a HEADERS payload.
///
/// The fragment is not at offset 0 when flags are set. Per RFC 7540 §6.2 the
/// payload is laid out as
///
/// ```text
/// Pad Length (1)          if PADDED
/// E + Stream Dependency (4) + Weight (1)   if PRIORITY
/// Header Block Fragment (*)
/// Padding (Pad Length)    if PADDED
/// ```
///
/// Chrome sends `flags=0x25`, which includes PRIORITY, so its fragment starts five
/// bytes in. curl sends `0x05` with no prefix. Handing the raw payload straight to
/// HPACK therefore works for curl and fails for Chrome, which is exactly the bug
/// tshark caught.
pub fn header_block_fragment<'a>(frame: &Frame<'a>) -> &'a [u8] {
    let mut body = frame.payload;

    let pad_len = if frame.flags & FLAG_PADDED != 0 {
        let Some((&n, rest)) = body.split_first() else {
            return &[];
        };
        body = rest;
        usize::from(n)
    } else {
        0
    };

    if frame.flags & FLAG_PRIORITY != 0 {
        let Some(rest) = body.get(5..) else {
            return &[];
        };
        body = rest;
    }

    match body.len().checked_sub(pad_len) {
        Some(end) => body.get(..end).unwrap_or_default(),
        None => &[],
    }
}

/// Decodes one HEADERS frame into `(name, value)` pairs in wire order.
///
/// A malformed payload yields an empty list rather than an error. To a fingerprint
/// an undecodable header block and an absent one mean the same thing, and the
/// caller has no useful recovery either way.
pub fn decode_headers(frame: &Frame) -> Vec<(String, String)> {
    if frame.flags & FLAG_END_HEADERS == 0 {
        // A CONTINUATION frame follows and we do not have it. Decoding a partial
        // block would corrupt the HPACK dynamic table for no benefit.
        return Vec::new();
    }

    decode_fragment(header_block_fragment(frame))
}

/// Runs the HPACK decoder with panics contained.
///
/// **This wrapper exists because of an upstream bug, not out of caution.**
/// `fluke-hpack` 0.3.1 `decoder.rs:505` reads
///
/// ```text
/// let (new_size, consumed) = decode_integer(buf, 5).ok().unwrap();
/// ```
///
/// inside `update_max_dynamic_size`, which returns `Result`. A header block that
/// begins with a dynamic-table-size-update byte followed by a malformed varint
/// therefore panics instead of returning the error the signature promises. Found
/// by the `arbitrary_headers_payloads_never_panic` property test.
///
/// The input is attacker controlled and reaches this code from the network, so an
/// uncontained panic would be a per-connection denial of service once `serve`
/// exists. `catch_unwind` is sound here because the decoder is created inside the
/// closure and dropped on unwind, so no partially mutated state escapes.
///
/// Two limitations, stated rather than glossed over. It does not help under
/// `panic = "abort"`, and the panic message still reaches stderr, so a flood of
/// malformed requests becomes log noise. The real fix is upstream or a vendored
/// patch replacing that `unwrap`.
fn decode_fragment(fragment: &[u8]) -> Vec<(String, String)> {
    let decoded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fluke_hpack::Decoder::new().decode(fragment).ok()
    }));

    match decoded {
        Ok(Some(pairs)) => pairs
            .into_iter()
            .map(|(n, v)| {
                (
                    String::from_utf8_lossy(&n).into_owned(),
                    String::from_utf8_lossy(&v).into_owned(),
                )
            })
            .collect(),
        Ok(None) | Err(_) => Vec::new(),
    }
}

/// Pseudo-header order as single letters, comma joined. Chrome emits `m,a,s,p`
/// and curl emits `m,s,a,p`, which is one of the two discriminators the Akamai
/// fingerprint rests on.
///
/// Only the four request pseudo-headers are mapped. Anything else, including
/// `:protocol`, is skipped rather than guessed at.
pub fn pseudo_header_order(headers: &[(String, String)]) -> String {
    headers
        .iter()
        .filter_map(|(name, _)| match name.as_str() {
            ":method" => Some("m"),
            ":authority" => Some("a"),
            ":scheme" => Some("s"),
            ":path" => Some("p"),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{parse_preamble, Frame, FRAME_HEADERS};

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    fn headers_of(name: &str) -> Vec<(String, String)> {
        let raw = fixture(name);
        let frames = parse_preamble(&raw).expect("parse");
        let h = frames
            .iter()
            .find(|f| f.kind == FRAME_HEADERS)
            .expect("HEADERS")
            .clone();
        decode_headers(&h)
    }

    /// Oracle: tshark `http2.header.name` reports exactly this sequence.
    #[test]
    fn curl_header_names_match_the_oracle_in_order() {
        let names: Vec<String> = headers_of("curl-8.7.1-h2")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            names,
            vec![
                ":method",
                ":scheme",
                ":authority",
                ":path",
                "user-agent",
                "accept"
            ]
        );
    }

    /// Oracle: tshark reports 21 headers for Chrome, including three separate
    /// `cookie` entries because HPACK splits them, and a trailing `priority`
    /// header from RFC 9218 extensible priorities.
    #[test]
    fn chrome_header_names_match_the_oracle_in_order() {
        let names: Vec<String> = headers_of("chrome-h2")
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(
            names,
            vec![
                ":method",
                ":authority",
                ":scheme",
                ":path",
                "cache-control",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "accept-encoding",
                "accept-language",
                "cookie",
                "cookie",
                "cookie",
                "priority",
            ]
        );
    }

    #[test]
    fn curl_pseudo_header_order_is_msap() {
        assert_eq!(pseudo_header_order(&headers_of("curl-8.7.1-h2")), "m,s,a,p");
    }

    /// The discriminator. Chrome orders pseudo-headers m,a,s,p. A client claiming
    /// to be Chrome while ordering them like curl is caught on the first request.
    #[test]
    fn chrome_pseudo_header_order_is_masp_and_differs_from_curl() {
        assert_eq!(pseudo_header_order(&headers_of("chrome-h2")), "m,a,s,p");
        assert_ne!(
            pseudo_header_order(&headers_of("chrome-h2")),
            pseudo_header_order(&headers_of("curl-8.7.1-h2"))
        );
    }

    #[test]
    fn regular_headers_do_not_appear_in_the_pseudo_header_order() {
        let h = vec![
            (":method".to_string(), "GET".to_string()),
            ("user-agent".to_string(), "x".to_string()),
            (":path".to_string(), "/".to_string()),
        ];
        assert_eq!(pseudo_header_order(&h), "m,p");
    }

    #[test]
    fn an_unknown_pseudo_header_is_skipped_rather_than_guessed() {
        let h = vec![
            (":method".to_string(), "GET".to_string()),
            (":protocol".to_string(), "websocket".to_string()),
        ];
        assert_eq!(pseudo_header_order(&h), "m");
    }

    // --- the panic-freedom contract the plan required verifying ---------------

    /// Regression for the upstream panic documented on `decode_fragment`.
    ///
    /// `0x3f` is `001_11111`: a dynamic table size update whose 5-bit prefix is
    /// saturated, so the value continues into following octets. With none
    /// present, `decode_integer` fails and fluke-hpack 0.3.1 calls
    /// `.ok().unwrap()` on the result. Uncontained, this is a remotely triggerable
    /// panic. If this test ever starts failing, the `catch_unwind` in
    /// `decode_fragment` has been removed or defeated.
    #[test]
    fn the_upstream_hpack_size_update_panic_stays_contained() {
        for payload in [
            &[0x3f][..],
            &[0x3f, 0xff][..],
            &[0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff][..],
            &[0x20][..],
            &[0x3e][..],
        ] {
            let f = Frame {
                kind: 0x1,
                flags: 0x04,
                stream_id: 1,
                payload,
            };
            assert!(
                decode_headers(&f).is_empty(),
                "must degrade to empty, not panic, for {payload:02x?}"
            );
        }
    }

    #[test]
    fn a_malformed_headers_payload_yields_an_empty_list_not_a_panic() {
        for payload in [
            &[0xff, 0xff, 0xff][..],
            &[0x00][..],
            &[0x80][..],
            &[0xff, 0x00][..],
            &[0x40, 0x7f, 0xff, 0xff, 0xff][..],
        ] {
            let f = Frame {
                kind: 0x1,
                flags: 0,
                stream_id: 1,
                payload,
            };
            let _ = decode_headers(&f);
        }
    }

    #[test]
    fn every_single_byte_truncation_of_a_real_headers_frame_is_safe() {
        let raw = fixture("chrome-h2");
        let frames = parse_preamble(&raw).expect("parse");
        let h = frames
            .iter()
            .find(|f| f.kind == FRAME_HEADERS)
            .expect("HEADERS");
        for cut in 0..=h.payload.len() {
            let f = Frame {
                kind: 0x1,
                flags: 0,
                stream_id: 1,
                payload: h.payload.get(..cut).unwrap_or_default(),
            };
            let _ = decode_headers(&f);
        }
    }
}
