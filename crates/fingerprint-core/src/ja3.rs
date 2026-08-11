//! JA3 — retained for compatibility, and unreliable for browsers by construction.
//!
//! JA3 hashes the extension list in **wire order**. Chrome has permuted that order
//! per connection since v110 (M0 finding 1), so a Chrome JA3 changes on every
//! handshake. JA4 exists because of this; see `ja4`.

use crate::grease::strip;

fn join_u16(values: &[u16]) -> String {
    strip(values)
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// `version,ciphers,extensions,curves,point_formats` — decimal, dash-joined within
/// each field, GREASE removed, **wire order preserved**.
///
/// `version` is the ClientHello's `legacy_version`, not the version negotiated via
/// `supported_versions`.
pub fn ja3_string(
    legacy_version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    curves: &[u16],
    point_formats: &[u8],
) -> String {
    let pf = point_formats
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        legacy_version,
        join_u16(ciphers),
        join_u16(extensions),
        join_u16(curves),
        pf
    )
}

pub fn ja3_hash(s: &str) -> String {
    use md5::{Digest, Md5};
    format!("{:x}", Md5::digest(s.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext;
    use crate::hello::parse_hello;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    fn ja3_of(name: &str) -> (String, String) {
        let raw = fixture(name);
        let h = parse_hello(&raw).expect("parse");
        let ext_ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
        let s = ja3_string(
            h.legacy_version,
            &h.ciphers,
            &ext_ids,
            &ext::supported_groups(&h.extensions),
            &ext::ec_point_formats(&h.extensions),
        );
        let hash = ja3_hash(&s);
        (s, hash)
    }

    /// Oracle: tshark 4.4.9 `tls.handshake.ja3` / `ja3_full` over the same bytes.
    #[test]
    fn curl_ja3_matches_the_tshark_oracle() {
        let (s, hash) = ja3_of("curl-8.7.1-macos");
        assert_eq!(
            s,
            "771,4867-4866-4865-52393-52392-52394-49200-49196-49192-49188-49172-49162-159-107-57-65413-196-136-129-157-61-53-192-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,43-51-11-10-13-16,29-23-24-25,0"
        );
        assert_eq!(hash, "4f2655722e37c542ebeaf1eed48cbbbb");
    }

    #[test]
    fn chrome_ja3_matches_the_tshark_oracle() {
        let (s, hash) = ja3_of("chrome-macos");
        assert_eq!(
            s,
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-27-45-13-16-18-11-65281-35-51-10-5-43-65037-17613-41,4588-29-23-24,0"
        );
        assert_eq!(hash, "044a769f778e5088d7f82861feeccab6");
    }

    /// JA3 uses the ClientHello's `legacy_version` (771 = 0x0303), *not* the version
    /// negotiated via `supported_versions` — which is 0x0304 for both fixtures.
    #[test]
    fn ja3_uses_legacy_version_not_the_negotiated_one() {
        let (s, _) = ja3_of("curl-8.7.1-macos");
        assert!(s.starts_with("771,"));
    }

    #[test]
    fn ja3_string_removes_grease_but_keeps_wire_order() {
        let s = ja3_string(
            0x0303,
            &[0x0a0a, 0x1302, 0x1301],
            &[0x1a1a, 0x000a],
            &[],
            &[],
        );
        assert_eq!(s, "771,4866-4865,10,,");
    }

    /// The defect, stated as an executable fact: permuting the extension order —
    /// which Chrome does on every connection — changes the JA3.
    #[test]
    fn permuting_extensions_changes_ja3() {
        let a = ja3_string(0x0303, &[0x1301], &[0x000a, 0x000b], &[], &[]);
        let b = ja3_string(0x0303, &[0x1301], &[0x000b, 0x000a], &[], &[]);
        assert_ne!(
            a, b,
            "JA3 is order-sensitive; this is why it fails on Chrome"
        );
        assert_ne!(ja3_hash(&a), ja3_hash(&b));
    }

    #[test]
    fn empty_fields_produce_empty_segments() {
        assert_eq!(ja3_string(0x0303, &[], &[], &[], &[]), "771,,,,");
    }
}
