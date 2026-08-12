//! HPACK integer representation, RFC 7541 section 5.1.
//!
//! A value smaller than the prefix maximum fits in the prefix. Otherwise the
//! prefix is set to all ones and the remainder follows as a sequence of octets,
//! seven bits each, with the top bit marking continuation.

use super::HpackError;

/// Decodes an N-bit prefix integer starting at `buf[0]`.
///
/// Returns the value and how many octets were consumed. `prefix_bits` is 1 to 8.
///
/// Overflow is an error rather than a wrap. An attacker controls these bytes, and
/// a wrapped length would become an out of bounds read further up.
pub fn decode(buf: &[u8], prefix_bits: u8) -> Result<(u64, usize), HpackError> {
    if prefix_bits == 0 || prefix_bits > 8 {
        return Err(HpackError::BadInteger);
    }
    let mask: u64 = (1u64 << prefix_bits) - 1;

    let first = *buf.first().ok_or(HpackError::Truncated)? as u64;
    let mut value = first & mask;
    if value < mask {
        return Ok((value, 1));
    }

    // Continuation octets, seven bits each, little endian.
    let mut shift = 0u32;
    let mut consumed = 1usize;
    loop {
        let byte = *buf.get(consumed).ok_or(HpackError::Truncated)?;
        consumed += 1;

        // A value needing more than ten continuation octets cannot fit in u64.
        if shift >= 63 {
            return Err(HpackError::BadInteger);
        }
        let add = ((byte & 0x7f) as u64)
            .checked_shl(shift)
            .ok_or(HpackError::BadInteger)?;
        value = value.checked_add(add).ok_or(HpackError::BadInteger)?;

        if byte & 0x80 == 0 {
            return Ok((value, consumed));
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RFC 7541 Appendix C.1, the normative worked examples ----------------

    /// C.1.1: the value 10 with a 5-bit prefix fits in the prefix.
    #[test]
    fn rfc_c1_1_ten_with_a_five_bit_prefix() {
        assert_eq!(decode(&[0x0a], 5).expect("decode"), (10, 1));
    }

    /// C.1.2: the value 1337 with a 5-bit prefix needs continuation octets.
    #[test]
    fn rfc_c1_2_thirteen_thirty_seven_with_a_five_bit_prefix() {
        assert_eq!(decode(&[0x1f, 0x9a, 0x0a], 5).expect("decode"), (1337, 3));
    }

    /// C.1.3: the value 42 at an octet boundary, 8-bit prefix.
    #[test]
    fn rfc_c1_3_forty_two_with_an_eight_bit_prefix() {
        assert_eq!(decode(&[0x2a], 8).expect("decode"), (42, 1));
    }

    // --- the prefix boundary -------------------------------------------------

    /// One below the prefix maximum stays in the prefix. The maximum itself does
    /// not, because that pattern signals continuation. Getting this off by one is
    /// the classic HPACK bug.
    #[test]
    fn the_prefix_maximum_signals_continuation_rather_than_a_value() {
        assert_eq!(decode(&[0x1e], 5).expect("decode"), (30, 1));
        assert_eq!(decode(&[0x1f, 0x00], 5).expect("decode"), (31, 2));
    }

    #[test]
    fn high_bits_outside_the_prefix_are_ignored() {
        // 0xea = 111_01010. With a 5-bit prefix only 01010 = 10 is the value.
        assert_eq!(decode(&[0xea], 5).expect("decode"), (10, 1));
    }

    // --- the failure modes that make this safe -------------------------------

    /// The exact shape that panics fluke-hpack 0.3.1. A saturated prefix with no
    /// continuation octet must be an error, not a panic and not a wrong value.
    #[test]
    fn a_saturated_prefix_with_no_continuation_is_truncated_not_a_panic() {
        assert_eq!(decode(&[0x1f], 5), Err(HpackError::Truncated));
        assert_eq!(decode(&[0x3f], 5), Err(HpackError::Truncated));
    }

    #[test]
    fn an_empty_buffer_is_truncated() {
        assert_eq!(decode(&[], 5), Err(HpackError::Truncated));
    }

    #[test]
    fn a_continuation_that_never_terminates_is_truncated() {
        assert_eq!(
            decode(&[0x1f, 0x80, 0x80, 0x80], 5),
            Err(HpackError::Truncated)
        );
    }

    /// A value too large for u64 must be rejected, not wrapped. A wrapped length
    /// becomes an out of bounds read one layer up.
    #[test]
    fn an_integer_too_large_for_u64_is_rejected_rather_than_wrapped() {
        let mut buf = vec![0x1f];
        buf.extend(std::iter::repeat_n(0xff, 12));
        buf.push(0x00);
        assert_eq!(decode(&buf, 5), Err(HpackError::BadInteger));
    }

    #[test]
    fn an_invalid_prefix_width_is_rejected() {
        assert_eq!(decode(&[0x00], 0), Err(HpackError::BadInteger));
        assert_eq!(decode(&[0x00], 9), Err(HpackError::BadInteger));
    }

    /// No input may panic. The whole reason this module exists.
    #[test]
    fn no_two_byte_input_panics_at_any_prefix_width() {
        for a in 0u16..=255 {
            for b in 0u16..=255 {
                for bits in 1..=8u8 {
                    let _ = decode(&[a as u8, b as u8], bits);
                }
            }
        }
    }
}
