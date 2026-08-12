//! Bounds-checked cursor over untrusted bytes.
//!
//! This is the only module in the crate that touches raw offsets. Every length
//! field in a ClientHello is attacker-controlled, so `raw[i]` is a panic waiting
//! to happen, everything above this layer works on already-validated slices.

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("unexpected end of input")]
    Truncated,
    #[error("not a TLS handshake record")]
    NotHandshake,
    #[error("not a ClientHello")]
    NotClientHello,
    #[error("malformed {0}")]
    Malformed(&'static str),
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Offset of the next unread byte, relative to the slice this reader was built
    /// over. Callers combine it with the base offset of that slice to get a
    /// position that is absolute within the original buffer.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// The single choke point. `checked_add` matters: a length near `usize::MAX`
    /// would otherwise wrap and turn the range check into a silent over-read.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(ParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, ParseError> {
        self.take(1)?.first().copied().ok_or(ParseError::Truncated)
    }

    pub fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([
            *b.first().ok_or(ParseError::Truncated)?,
            *b.get(1).ok_or(ParseError::Truncated)?,
        ]))
    }

    /// 24-bit big-endian, as used by the handshake-message length field.
    pub fn u24(&mut self) -> Result<u32, ParseError> {
        let b = self.take(3)?;
        Ok(u32::from_be_bytes([
            0,
            *b.first().ok_or(ParseError::Truncated)?,
            *b.get(1).ok_or(ParseError::Truncated)?,
            *b.get(2).ok_or(ParseError::Truncated)?,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_values_in_order() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03]);
        assert_eq!(r.u8().expect("u8"), 0x01);
        assert_eq!(r.u16().expect("u16"), 0x0203);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reading_past_the_end_errors_rather_than_panicking() {
        let mut r = Reader::new(&[0x01]);
        assert_eq!(r.u8().expect("u8"), 0x01);
        assert!(r.u8().is_err());
        assert!(r.u16().is_err());
        assert!(r.take(1).is_err());
    }

    #[test]
    fn an_oversized_length_errors_rather_than_panicking() {
        let mut r = Reader::new(&[0xff, 0xff, 0x00]);
        let n = r.u16().expect("u16") as usize; // 65535, far past the end
        assert!(r.take(n).is_err(), "must not panic or over-read");
    }

    /// `pos + n` must not wrap. Without the checked_add this is a silent over-read.
    #[test]
    fn a_length_near_usize_max_does_not_overflow() {
        let mut r = Reader::new(&[0x01, 0x02]);
        assert!(r.take(usize::MAX).is_err());
        assert_eq!(r.remaining(), 2, "a failed take must not advance");
    }

    #[test]
    fn take_returns_exactly_n_bytes() {
        let mut r = Reader::new(&[1, 2, 3, 4]);
        assert_eq!(r.take(3).expect("take"), &[1, 2, 3]);
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn take_zero_is_allowed_and_does_not_advance() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.take(0).expect("take"), &[] as &[u8]);
        assert_eq!(r.remaining(), 2);
    }
}
