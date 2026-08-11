//! The ClientHello walk. Knows the message layout; knows nothing about what any
//! individual extension means — that is `ext`'s job.

use crate::reader::{ParseError, Reader};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExt<'a> {
    pub id: u16,
    pub body: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawHello<'a> {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<RawExt<'a>>,
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
    let record_body = r.take(record_len)?;

    let mut h = Reader::new(record_body);
    if h.u8()? != 0x01 {
        return Err(ParseError::NotClientHello);
    }
    let hs_len = h.u24()? as usize;
    let mut c = Reader::new(h.take(hs_len)?);

    let legacy_version = c.u16()?;
    let _random = c.take(32)?;
    let sid_len = c.u8()? as usize;
    let _session_id = c.take(sid_len)?;

    let cs_len = c.u16()? as usize;
    if cs_len % 2 != 0 {
        return Err(ParseError::Malformed("cipher_suites length"));
    }
    let cs_bytes = c.take(cs_len)?;
    let ciphers: Vec<u16> = cs_bytes
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect();

    let comp_len = c.u8()? as usize;
    let _compression = c.take(comp_len)?;

    // TLS 1.2 and earlier may omit the extensions block entirely.
    let mut extensions = Vec::new();
    if c.remaining() >= 2 {
        let ext_total = c.u16()? as usize;
        let mut e = Reader::new(c.take(ext_total)?);
        while e.remaining() >= 4 {
            let id = e.u16()?;
            let len = e.u16()? as usize;
            let body = e.take(len)?;
            extensions.push(RawExt { id, body });
        }
    }

    Ok(RawHello {
        legacy_version,
        ciphers,
        extensions,
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
    /// extension slots. Positions are asserted; values deliberately are not.
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
}
