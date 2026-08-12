//! Extension bodies. Knows what individual extensions mean. Knows nothing about
//! the outer ClientHello layout.

use crate::grease::is_grease;
use crate::hello::RawExt;
use crate::reader::Reader;

pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub const EXT_SIG_ALGS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;

fn body_of<'a>(exts: &'a [RawExt<'a>], id: u16) -> Option<&'a [u8]> {
    exts.iter().find(|e| e.id == id).map(|e| e.body)
}

pub fn has_sni(exts: &[RawExt]) -> bool {
    exts.iter().any(|e| e.id == EXT_SERVER_NAME)
}

/// ALPN body: `list_len(2)` then repeated `{ len(1), bytes }`. Returns the first
/// protocol only, that is all JA4 uses.
pub fn first_alpn(exts: &[RawExt]) -> Option<String> {
    let body = body_of(exts, EXT_ALPN)?;
    let mut r = Reader::new(body);
    let list_len = r.u16().ok()? as usize;
    let mut list = Reader::new(r.take(list_len).ok()?);
    let n = list.u8().ok()? as usize;
    let bytes = list.take(n).ok()?;
    String::from_utf8(bytes.to_vec()).ok()
}

/// A `len(2)`-prefixed list of u16s. Any malformation yields an empty list rather
/// than an error: a missing extension and an unreadable one mean the same thing
/// to a fingerprint.
fn u16_list(body: Option<&[u8]>) -> Vec<u16> {
    let Some(body) = body else {
        return Vec::new();
    };
    let mut r = Reader::new(body);
    let Ok(len) = r.u16() else {
        return Vec::new();
    };
    let Ok(items) = r.take(len as usize) else {
        return Vec::new();
    };
    items
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .collect()
}

/// Wire order, deliberately unsorted, JA4 segment (c) appends these as they appear.
pub fn sig_algs(exts: &[RawExt]) -> Vec<u16> {
    u16_list(body_of(exts, EXT_SIG_ALGS))
}

pub fn supported_groups(exts: &[RawExt]) -> Vec<u16> {
    u16_list(body_of(exts, EXT_SUPPORTED_GROUPS))
}

/// ec_point_formats body: `len(1)` then single-byte formats. Used only by JA3.
pub fn ec_point_formats(exts: &[RawExt]) -> Vec<u8> {
    let Some(body) = body_of(exts, EXT_EC_POINT_FORMATS) else {
        return Vec::new();
    };
    let mut r = Reader::new(body);
    let Ok(len) = r.u8() else {
        return Vec::new();
    };
    r.take(len as usize).map(<[u8]>::to_vec).unwrap_or_default()
}

/// Highest non-GREASE value in `supported_versions`, falling back to the record's
/// legacy version when the extension is absent or unreadable.
pub fn negotiated_version(exts: &[RawExt], legacy: u16) -> u16 {
    let Some(body) = body_of(exts, EXT_SUPPORTED_VERSIONS) else {
        return legacy;
    };
    let mut r = Reader::new(body);
    let Ok(len) = r.u8() else {
        return legacy;
    };
    let Ok(items) = r.take(len as usize) else {
        return legacy;
    };
    items
        .chunks_exact(2)
        .filter_map(|p| Some(u16::from_be_bytes([*p.first()?, *p.get(1)?])))
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(legacy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::parse_hello;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    /// Both IP-target fixtures were captured against `127.0.0.1`, where clients
    /// correctly omit SNI. This is the observed basis for JA4's `d`/`i` flag.
    #[test]
    fn no_sni_when_captured_over_an_ip_connection() {
        for name in ["curl-8.7.1-macos", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            assert!(!has_sni(&h.extensions), "{name} should have no SNI");
        }
    }

    #[test]
    fn sni_is_detected_in_the_domain_fixture() {
        let raw = fixture("curl-8.7.1-macos-sni");
        let h = parse_hello(&raw).expect("parse");
        assert!(has_sni(&h.extensions));
    }

    #[test]
    fn first_alpn_is_h2_for_every_fixture() {
        for name in ["curl-8.7.1-macos", "curl-8.7.1-macos-sni", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            assert_eq!(first_alpn(&h.extensions).as_deref(), Some("h2"), "{name}");
        }
    }

    /// Cross-checked against tshark's ja4_r for the curl fixture, which reports
    /// these exact values in this exact order after the underscore.
    #[test]
    fn curl_signature_algorithms_match_the_oracle_in_wire_order() {
        let raw = fixture("curl-8.7.1-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(
            sig_algs(&h.extensions),
            vec![
                0x0806, 0x0601, 0x0603, 0x0805, 0x0501, 0x0503, 0x0804, 0x0401, 0x0403, 0x0201,
                0x0203
            ]
        );
    }

    #[test]
    fn chrome_signature_algorithms_match_the_oracle_in_wire_order() {
        let raw = fixture("chrome-macos");
        let h = parse_hello(&raw).expect("parse");
        assert_eq!(
            sig_algs(&h.extensions),
            vec![
                0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806,
                0x0601
            ]
        );
    }

    #[test]
    fn negotiated_version_is_tls13_for_every_fixture() {
        for name in ["curl-8.7.1-macos", "curl-8.7.1-macos-sni", "chrome-macos"] {
            let raw = fixture(name);
            let h = parse_hello(&raw).expect("parse");
            assert_eq!(
                negotiated_version(&h.extensions, h.legacy_version),
                0x0304,
                "{name}"
            );
        }
    }

    /// supported_versions carries GREASE too. It must not win the "highest" contest.
    #[test]
    fn grease_in_supported_versions_is_ignored() {
        let ext = [RawExt {
            id: 43,
            body: &[0x04, 0x0a, 0x0a, 0x03, 0x04],
        }];
        assert_eq!(negotiated_version(&ext, 0x0303), 0x0304);
    }

    #[test]
    fn a_missing_supported_versions_falls_back_to_legacy() {
        assert_eq!(negotiated_version(&[], 0x0303), 0x0303);
    }

    #[test]
    fn a_truncated_extension_body_yields_a_default_not_a_panic() {
        assert_eq!(
            first_alpn(&[RawExt {
                id: 16,
                body: &[0xff]
            }]),
            None
        );
        assert!(sig_algs(&[RawExt {
            id: 13,
            body: &[0xff, 0xff]
        }])
        .is_empty());
        assert_eq!(
            negotiated_version(
                &[RawExt {
                    id: 43,
                    body: &[0xff]
                }],
                0x0303
            ),
            0x0303
        );
    }
}
