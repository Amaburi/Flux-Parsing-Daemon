//! The ClientHello walk. Knows the message layout. Knows nothing about what any
//! individual extension means, that is `ext`'s job.

use crate::reader::{ParseError, Reader};

/// A byte range within the buffer passed to `parse_hello`.
///
/// Absolute, not relative to any of the nested readers the walk builds, so a
/// caller holding the original bytes can slice with it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExt<'a> {
    pub id: u16,
    pub body: &'a [u8],
    /// Covers the whole extension record, its 4-byte header and its body.
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHello<'a> {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<RawExt<'a>>,
    pub cipher_span: Span,
    /// The extensions block, excluding its own 2-byte length prefix. Zero length
    /// when the ClientHello carries no extensions block at all, which TLS 1.2 and
    /// earlier are allowed to do.
    pub extensions_span: Span,
}

/// Walks one TLS handshake record containing a ClientHello.
///
/// Layout: record `type(1) version(2) length(2)` | handshake `type(1) length(3)` |
/// `legacy_version(2) random(32) session_id cipher_suites compression extensions`.
pub fn parse_hello(raw: &[u8]) -> Result<RawHello<'_>, ParseError> {
    let mut r = Reader::new(raw);

    if r.u8()? != 0x16 {
        return Err(ParseError::NotHandshake);
    }
    let _record_version = r.u16()?;
    let record_len = r.u16()? as usize;
    // Base of each nesting level within `raw`, derived from the reader rather than
    // hardcoded, so a change to either header cannot silently shift every span.
    let record_base = r.position();
    let record_body = r.take(record_len)?;

    let mut h = Reader::new(record_body);
    if h.u8()? != 0x01 {
        return Err(ParseError::NotClientHello);
    }
    let hs_len = h.u24()? as usize;
    let hs_base = record_base + h.position();
    let mut c = Reader::new(h.take(hs_len)?);

    let legacy_version = c.u16()?;
    let _random = c.take(32)?;
    let sid_len = c.u8()? as usize;
    let _session_id = c.take(sid_len)?;

    let cs_len = c.u16()? as usize;
    if !cs_len.is_multiple_of(2) {
        return Err(ParseError::Malformed("cipher_suites length"));
    }
    let cipher_span = Span {
        start: hs_base + c.position(),
        len: cs_len,
    };
    let cs_bytes = c.take(cs_len)?;
    let ciphers: Vec<u16> = cs_bytes
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();

    let comp_len = c.u8()? as usize;
    let _compression = c.take(comp_len)?;

    // TLS 1.2 and earlier may omit the extensions block entirely.
    let mut extensions = Vec::new();
    let mut extensions_span = Span {
        start: hs_base + c.position(),
        len: 0,
    };
    if c.remaining() >= 2 {
        let ext_total = c.u16()? as usize;
        let ext_base = hs_base + c.position();
        extensions_span = Span {
            start: ext_base,
            len: ext_total,
        };
        let mut e = Reader::new(c.take(ext_total)?);
        while e.remaining() >= 4 {
            // Taken before the id and length are read, so the span covers the
            // whole record rather than only its body.
            let start = ext_base + e.position();
            let id = e.u16()?;
            let len = e.u16()? as usize;
            let body = e.take(len)?;
            extensions.push(RawExt {
                id,
                body,
                span: Span {
                    start,
                    len: len + 4,
                },
            });
        }
    }

    Ok(RawHello {
        legacy_version,
        ciphers,
        extensions,
        cipher_span,
        extensions_span,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    #[test]
    fn parses_curl_ciphers_in_wire_order() {
        let raw = fixture("curl-8.7.1-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(h.ciphers.len(), 49, "curl 8.7.1 offered 49 ciphers");
        assert_eq!(h.ciphers.first(), Some(&4867)); // TLS_CHACHA20_POLY1305_SHA256
    }

    #[test]
    fn parses_curl_extensions_in_wire_order() {
        let raw = fixture("curl-8.7.1-macos");
        let h = parse_hello(&raw).expect("parse");
        let ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![43, 51, 11, 10, 13, 16]);
    }

    /// The SNI fixture is the same client with one extension added. Comparing the
    /// two isolates that difference and nothing else.
    #[test]
    fn the_sni_fixture_differs_from_its_pair_by_exactly_one_extension() {
        let plain_raw = fixture("curl-8.7.1-macos");
        let sni_raw = fixture("curl-8.7.1-macos-sni");
        let plain = parse_hello(&plain_raw).expect("parse");
        let sni = parse_hello(&sni_raw).expect("parse");

        assert_eq!(plain.ciphers, sni.ciphers, "ciphers must be identical");
        assert_eq!(sni.extensions.len(), plain.extensions.len() + 1);

        let plain_ids: Vec<u16> = plain.extensions.iter().map(|e| e.id).collect();
        let sni_ids: Vec<u16> = sni.extensions.iter().map(|e| e.id).collect();
        assert!(!plain_ids.contains(&0), "plain fixture must have no SNI");
        assert!(sni_ids.contains(&0), "sni fixture must have SNI");
    }

    #[test]
    fn parses_chrome() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(h.ciphers.len(), 16, "15 real + 1 GREASE");
        assert_eq!(
            h.extensions.len(),
            18,
            "this capture is a resuming session: 16 non-GREASE + 2 GREASE"
        );
    }

    /// M0 finding 3: only extension order permutes. Cipher order is fixed, so it
    /// is safe to assert literally where extension order is not.
    #[test]
    fn chrome_cipher_order_is_stable_after_removing_grease() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(
            crate::grease::strip(&h.ciphers),
            vec![
                4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157,
                47, 53
            ]
        );
    }

    /// M0 finding 2: GREASE sits at cipher[0] and at the first and last non-PSK
    /// extension slots. Positions are asserted. Values deliberately are not.
    #[test]
    fn chrome_grease_positions_are_recorded_but_values_are_not_asserted() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(crate::grease::positions(&h.ciphers), vec![0]);

        let ext_ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
        assert_eq!(crate::grease::positions(&ext_ids).len(), 2);
    }

    #[test]
    fn a_non_handshake_record_is_rejected() {
        assert_eq!(
            parse_hello(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]),
            Err(ParseError::NotHandshake)
        );
    }

    #[test]
    fn an_empty_input_is_rejected_without_panicking() {
        assert!(parse_hello(&[]).is_err());
    }

    /// Truncates a real ClientHello at EVERY byte offset and requires that none of
    /// them panic. The cheapest available substitute for fuzzing, and it catches
    /// the majority of bounds bugs immediately.
    #[test]
    fn truncation_at_every_offset_errors_and_never_panics() {
        for name in ["curl-8.7.1-macos", "chrome-macos"] {
            let raw = fixture(name);
            for cut in 0..raw.len() {
                let slice = raw.get(..cut).unwrap_or_default();
                let _ = parse_hello(slice);
            }
        }
    }

    // --- byte spans ----------------------------------------------------------

    /// The span must independently reproduce the value the parser returned. An
    /// off-by-one span still slices cleanly and still yields u16s, so comparing
    /// against `h.ciphers` is what actually catches it.
    #[test]
    fn the_cipher_span_reproduces_the_parsed_cipher_list() {
        for name in ["curl-8.7.1-macos", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            let bytes = &raw[h.cipher_span.start..h.cipher_span.start + h.cipher_span.len];
            let from_span: Vec<u16> = bytes
                .chunks_exact(2)
                .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
                .collect();
            assert_eq!(from_span, h.ciphers, "{name}");
        }
    }

    /// Each extension span covers the whole extension record, its 4-byte header
    /// plus its body, so a renderer can highlight one extension as a unit.
    #[test]
    fn each_extension_span_covers_its_own_header_and_body() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        assert!(!h.extensions.is_empty(), "precondition");

        for e in &h.extensions {
            let b = &raw[e.span.start..e.span.start + e.span.len];
            assert_eq!(b.len(), 4 + e.body.len(), "ext {} length", e.id);
            assert_eq!(
                u16::from_be_bytes([b[0], b[1]]),
                e.id,
                "ext {} must start with its own id",
                e.id
            );
            assert_eq!(&b[4..], e.body, "ext {} body", e.id);
        }
    }

    /// The extensions block span must contain every individual extension span, or
    /// a renderer drawing the block would draw it in the wrong place.
    #[test]
    fn the_extensions_span_contains_every_extension() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        let block_end = h.extensions_span.start + h.extensions_span.len;

        for e in &h.extensions {
            assert!(e.span.start >= h.extensions_span.start, "ext {}", e.id);
            assert!(e.span.start + e.span.len <= block_end, "ext {}", e.id);
        }
    }

    /// Every span must be in bounds for the buffer it indexes. A span past the end
    /// would panic a renderer that slices with it, and the renderer is the one
    /// place that cannot afford a panic.
    #[test]
    fn every_span_is_in_bounds() {
        for name in ["curl-8.7.1-macos", "chrome-macos", "curl-8.7.1-macos-sni"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            let mut spans = vec![h.cipher_span, h.extensions_span];
            spans.extend(h.extensions.iter().map(|e| e.span));
            for s in spans {
                assert!(
                    s.start + s.len <= raw.len(),
                    "{name}: span {s:?} exceeds {} bytes",
                    raw.len()
                );
            }
        }
    }
}
