//! GREASE (RFC 8701) detection and normalisation.
//!
//! M0 finding 2: GREASE *values* rotate every connection. Only positions are
//! stable. Every comparison and hash in this crate normalises them first, or
//! every Chrome result becomes non-deterministic.

/// RFC 8701 GREASE: both bytes equal, low nibble `0xA`.
pub fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (lo & 0x0f) == 0x0a
}

/// Removes GREASE, preserving the order of what remains.
pub fn strip(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_grease(*v)).collect()
}

/// Where GREASE sat. Positions are stable across connections even though the
/// values are not, so this is what a profile records.
pub fn positions(values: &[u16]) -> Vec<usize> {
    values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| is_grease(*v).then_some(i))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 16 GREASE values, spelled out rather than generated, so a wrong
    /// predicate cannot agree with a wrong generator.
    const ALL_GREASE: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];

    #[test]
    fn every_rfc8701_grease_value_is_recognised() {
        for v in ALL_GREASE {
            assert!(is_grease(v), "{v:#06x} is GREASE");
        }
    }

    #[test]
    fn real_values_are_not_mistaken_for_grease() {
        for v in [
            0x1301, 0x1302, 0x1303, 0xc02b, 0x002f, 0x0000, 0x0010, 0x002b, 0x0a0b, 0x1a2a, 0xff01,
            0x44cd, 0xfe0d,
        ] {
            assert!(!is_grease(v), "{v:#06x} is not GREASE");
        }
    }

    /// Values observed live as Chrome's cipher[0] across successive handshakes in
    /// the M0 S1 capture.
    #[test]
    fn values_observed_in_the_s1_capture_are_recognised() {
        for v in [
            2570u16, 6682, 14906, 19018, 23130, 27242, 35466, 43690, 47802, 51914, 56026, 60138,
            64250,
        ] {
            assert!(is_grease(v), "{v} was observed as Chrome cipher[0]");
        }
    }

    #[test]
    fn strip_removes_grease_and_preserves_order() {
        assert_eq!(
            strip(&[0x0a0a, 0x1301, 0x1a1a, 0x1302]),
            vec![0x1301, 0x1302]
        );
    }

    #[test]
    fn positions_reports_where_grease_sat() {
        assert_eq!(positions(&[0x0a0a, 0x1301, 0x1a1a]), vec![0, 2]);
    }

    #[test]
    fn stripping_a_list_with_no_grease_is_the_identity() {
        let v = vec![0x1301, 0x1302, 0x1303];
        assert_eq!(strip(&v), v);
        assert!(positions(&v).is_empty());
    }
}
