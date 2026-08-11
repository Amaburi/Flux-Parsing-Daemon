//! JA4. Rules verified against the FoxIO specification and cross-checked against
//! tshark 4.4.9 (`tls.handshake.ja4` / `ja4_r`) over the committed fixtures.

use crate::ext;
use crate::grease::strip;
use crate::hello::{parse_hello, RawHello};
use crate::reader::ParseError;

const EMPTY_HASH: &str = "000000000000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFingerprint {
    pub ja3: String,
    pub ja3_string: String,
    pub ja4: String,
    pub ja4_r: String,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub grease_cipher_positions: Vec<usize>,
    pub grease_ext_positions: Vec<usize>,
    pub alpn: Option<String>,
    pub has_sni: bool,
}

pub(crate) fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

/// Two-digit decimal, capped at 99 — the spec's "if there's > 99, output 99".
pub(crate) fn count2(n: usize) -> String {
    format!("{:02}", n.min(99))
}

pub(crate) fn version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_digit() || b.is_ascii_uppercase() || b.is_ascii_lowercase()
}

/// First and last characters of the first ALPN value; `00` when absent or empty.
///
/// NOTE: the non-alphanumeric branch below is **not exercised by any fixture** —
/// every capture so far negotiates `h2`. The spec calls for a hex representation
/// there; this implementation is a reasonable reading of it but should be checked
/// against a reference implementation before it is relied on. Recorded as a known
/// gap in the M2 plan.
pub(crate) fn alpn_chars(alpn: Option<&str>) -> String {
    let Some(s) = alpn.filter(|s| !s.is_empty()) else {
        return "00".to_string();
    };
    let bytes = s.as_bytes();
    let (Some(&first), Some(&last)) = (bytes.first(), bytes.last()) else {
        return "00".to_string();
    };
    if is_alnum(first) && is_alnum(last) {
        format!("{}{}", first as char, last as char)
    } else {
        format!("{:x}{:x}", first >> 4, last & 0x0f)
    }
}

fn hex_list(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// Ciphers sorted ascending, GREASE removed, 4-digit lowercase hex, comma-joined.
pub(crate) fn ja4_b_string(ciphers: &[u16]) -> String {
    let mut c = strip(ciphers);
    c.sort_unstable();
    hex_list(&c)
}

pub fn ja4_b(ciphers: &[u16]) -> String {
    let s = ja4_b_string(ciphers);
    if s.is_empty() {
        return EMPTY_HASH.to_string();
    }
    sha256_hex(&s).get(..12).unwrap_or(EMPTY_HASH).to_string()
}

/// Extensions sorted ascending with SNI (0000) and ALPN (0010) removed — segment
/// (a) already carries both — then `_`, then signature algorithms in wire order.
pub(crate) fn ja4_c_string(extensions: &[u16], sig_algs: &[u16]) -> String {
    let mut e: Vec<u16> = strip(extensions)
        .into_iter()
        .filter(|id| *id != ext::EXT_SERVER_NAME && *id != ext::EXT_ALPN)
        .collect();
    e.sort_unstable();
    format!("{}_{}", hex_list(&e), hex_list(sig_algs))
}

pub fn ja4_c(extensions: &[u16], sig_algs: &[u16]) -> String {
    if strip(extensions)
        .iter()
        .all(|id| *id == ext::EXT_SERVER_NAME || *id == ext::EXT_ALPN)
        && sig_algs.is_empty()
    {
        return EMPTY_HASH.to_string();
    }
    sha256_hex(&ja4_c_string(extensions, sig_algs))
        .get(..12)
        .unwrap_or(EMPTY_HASH)
        .to_string()
}

pub(crate) fn ja4_a(h: &RawHello) -> String {
    let ext_ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
    let version = ext::negotiated_version(&h.extensions, h.legacy_version);
    let alpn = ext::first_alpn(&h.extensions);

    format!(
        "t{}{}{}{}{}",
        version_str(version),
        if ext::has_sni(&h.extensions) {
            "d"
        } else {
            "i"
        },
        count2(strip(&h.ciphers).len()),
        count2(strip(&ext_ids).len()),
        alpn_chars(alpn.as_deref()),
    )
}

pub(crate) fn ja4_from_hello(h: &RawHello) -> String {
    let ext_ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
    format!(
        "{}_{}_{}",
        ja4_a(h),
        ja4_b(&h.ciphers),
        ja4_c(&ext_ids, &ext::sig_algs(&h.extensions))
    )
}

pub fn fingerprint(raw: &[u8]) -> Result<TlsFingerprint, ParseError> {
    let h = parse_hello(raw)?;
    let ext_ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
    let sig = ext::sig_algs(&h.extensions);

    let ja3_string = crate::ja3::ja3_string(
        h.legacy_version,
        &h.ciphers,
        &ext_ids,
        &ext::supported_groups(&h.extensions),
        &ext::ec_point_formats(&h.extensions),
    );

    Ok(TlsFingerprint {
        ja3: crate::ja3::ja3_hash(&ja3_string),
        ja3_string,
        ja4: ja4_from_hello(&h),
        ja4_r: format!(
            "{}_{}_{}",
            ja4_a(&h),
            ja4_b_string(&h.ciphers),
            ja4_c_string(&ext_ids, &sig)
        ),
        grease_cipher_positions: crate::grease::positions(&h.ciphers),
        grease_ext_positions: crate::grease::positions(&ext_ids),
        alpn: ext::first_alpn(&h.extensions),
        has_sni: ext::has_sni(&h.extensions),
        ciphers: h.ciphers,
        extensions: ext_ids,
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

    // ---- oracle values, from tshark over these exact bytes -----------------

    #[test]
    fn curl_ja4_matches_the_oracle() {
        let raw = fixture("curl-8.7.1-macos");
        assert_eq!(
            fingerprint(&raw).expect("fp").ja4,
            "t13i4906h2_0d8feac7bc37_7395dae3b2f3"
        );
    }

    #[test]
    fn curl_sni_ja4_matches_the_oracle() {
        let raw = fixture("curl-8.7.1-macos-sni");
        assert_eq!(
            fingerprint(&raw).expect("fp").ja4,
            "t13d4907h2_0d8feac7bc37_7395dae3b2f3"
        );
    }

    #[test]
    fn chrome_ja4_matches_the_oracle() {
        let raw = fixture("chrome-macos");
        assert_eq!(
            fingerprint(&raw).expect("fp").ja4,
            "t13i1516h2_8daaf6152771_a87ad97598a9"
        );
    }

    /// The controlled pair. Same client, one extension of difference, so the diff
    /// isolates exactly two rules: SNI flips `i`→`d` and is COUNTED in segment (a)
    /// (06→07), while segments (b) and (c) are unchanged because SNI is EXCLUDED
    /// from the (c) hash.
    #[test]
    fn the_sni_pair_isolates_the_sni_rules() {
        let plain_raw = fixture("curl-8.7.1-macos");
        let sni_raw = fixture("curl-8.7.1-macos-sni");
        let plain = fingerprint(&plain_raw).expect("fp");
        let sni = fingerprint(&sni_raw).expect("fp");

        let (pa, pb, pc) = split3(&plain.ja4);
        let (sa, sb, sc) = split3(&sni.ja4);

        assert_eq!(pa, "t13i4906h2");
        assert_eq!(sa, "t13d4907h2");
        assert_eq!(pb, sb, "SNI must not affect the cipher hash");
        assert_eq!(pc, sc, "SNI must be excluded from the extension hash");
    }

    fn split3(ja4: &str) -> (&str, &str, &str) {
        let mut it = ja4.split('_');
        (
            it.next().unwrap_or_default(),
            it.next().unwrap_or_default(),
            it.next().unwrap_or_default(),
        )
    }

    // ---- the property JA4 exists for --------------------------------------

    /// M0 finding 1: Chrome permutes extension order on every connection. JA4
    /// sorts before hashing, so it must survive that. This is the single most
    /// important assertion in M2 — it is the reason JA4 replaced JA3.
    #[test]
    fn ja4_is_stable_across_extension_permutation() {
        let raw = fixture("chrome-macos");
        let h = crate::hello::parse_hello(&raw).expect("parse");

        let forward = ja4_from_hello(&h);
        let mut reversed = h.clone();
        reversed.extensions.reverse();
        let backward = ja4_from_hello(&reversed);

        assert_eq!(
            forward, backward,
            "JA4 must not change when extension order does"
        );
    }

    /// The contrast, on the same input: JA3 does change.
    #[test]
    fn ja3_by_contrast_does_not_survive_permutation() {
        let raw = fixture("chrome-macos");
        let h = crate::hello::parse_hello(&raw).expect("parse");
        let ids: Vec<u16> = h.extensions.iter().map(|e| e.id).collect();
        let mut rev = ids.clone();
        rev.reverse();

        let a = crate::ja3::ja3_string(h.legacy_version, &h.ciphers, &ids, &[], &[]);
        let b = crate::ja3::ja3_string(h.legacy_version, &h.ciphers, &rev, &[], &[]);
        assert_ne!(a, b);
    }

    // ---- segment mechanics ------------------------------------------------

    #[test]
    fn counts_are_two_digit_decimal_capped_at_99() {
        assert_eq!(count2(0), "00");
        assert_eq!(count2(6), "06");
        assert_eq!(count2(99), "99");
        assert_eq!(count2(100), "99");
        assert_eq!(count2(250), "99");
    }

    #[test]
    fn ja4_b_sorts_so_permutation_cannot_change_it() {
        assert_eq!(ja4_b(&[0x1301, 0x1302]), ja4_b(&[0x1302, 0x1301]));
    }

    #[test]
    fn ja4_b_strips_grease() {
        assert_eq!(ja4_b(&[0x0a0a, 0x1301]), ja4_b(&[0x1301]));
    }

    /// Externally checkable: `printf '1301,1302,1303' | shasum -a 256 | cut -c1-12`
    #[test]
    fn ja4_b_is_truncated_sha256_of_the_sorted_lowercase_hex_list() {
        let b = ja4_b(&[0x1303, 0x1301, 0x1302]);
        assert_eq!(b.len(), 12);
        assert_eq!(b, &sha256_hex("1301,1302,1303")[..12]);
    }

    #[test]
    fn empty_lists_emit_the_literal_zero_string() {
        assert_eq!(ja4_b(&[]), "000000000000");
        assert_eq!(ja4_c(&[], &[]), "000000000000");
    }

    #[test]
    fn ja4_c_excludes_sni_and_alpn_but_keeps_everything_else() {
        let with = ja4_c(&[0x0000, 0x000a, 0x0010, 0x000b], &[]);
        let without = ja4_c(&[0x000a, 0x000b], &[]);
        assert_eq!(with, without);
    }

    #[test]
    fn ja4_c_appends_signature_algorithms_in_wire_order_unsorted() {
        let a = ja4_c(&[0x000a], &[0x0806, 0x0601]);
        let b = ja4_c(&[0x000a], &[0x0601, 0x0806]);
        assert_ne!(a, b, "signature algorithm order is significant");
        assert_eq!(a, &sha256_hex("000a_0806,0601")[..12]);
    }

    #[test]
    fn version_mapping_covers_the_documented_values() {
        assert_eq!(version_str(0x0304), "13");
        assert_eq!(version_str(0x0303), "12");
        assert_eq!(version_str(0x0302), "11");
        assert_eq!(version_str(0x0301), "10");
    }

    #[test]
    fn alpn_takes_first_and_last_character() {
        assert_eq!(alpn_chars(Some("h2")), "h2");
        assert_eq!(alpn_chars(Some("http/1.1")), "h1");
        assert_eq!(alpn_chars(None), "00");
        assert_eq!(alpn_chars(Some("")), "00");
    }

    #[test]
    fn a_malformed_record_yields_an_error_not_a_fingerprint() {
        assert!(fingerprint(&[0x17, 0x03, 0x03, 0x00, 0x00]).is_err());
        assert!(fingerprint(&[]).is_err());
    }
}
