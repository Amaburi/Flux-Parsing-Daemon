//! Connection preface and frame header walk.
//!
//! Knows the 9-byte frame header layout and nothing about payload contents.

use fingerprint_core::reader::{ParseError, Reader};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_PRIORITY: u8 = 0x2;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum H2Error {
    #[error("missing or malformed connection preface")]
    NoPreface,
    #[error("truncated frame")]
    Truncated,
}

impl From<ParseError> for H2Error {
    fn from(_: ParseError) -> Self {
        H2Error::Truncated
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: u8,
    pub flags: u8,
    pub stream_id: u32,
    pub payload: &'a [u8],
}

/// Walks the connection preface and the frames that follow, stopping after the
/// first HEADERS frame because the request is complete at that point.
///
/// Frame header layout is `length(3) | type(1) | flags(1) | R + stream_id(4)`.
pub fn parse_preamble(raw: &[u8]) -> Result<Vec<Frame<'_>>, H2Error> {
    let mut r = Reader::new(raw);
    if r.take(PREFACE.len())? != PREFACE {
        return Err(H2Error::NoPreface);
    }

    let mut frames = Vec::new();
    while r.remaining() >= 9 {
        let len = r.u24()? as usize;
        let kind = r.u8()?;
        let flags = r.u8()?;

        let sid = r.take(4)?;
        let stream_id = u32::from_be_bytes([
            *sid.first().ok_or(H2Error::Truncated)? & 0x7f,
            *sid.get(1).ok_or(H2Error::Truncated)?,
            *sid.get(2).ok_or(H2Error::Truncated)?,
            *sid.get(3).ok_or(H2Error::Truncated)?,
        ]);

        let payload = r.take(len)?;
        frames.push(Frame {
            kind,
            flags,
            stream_id,
            payload,
        });

        if kind == FRAME_HEADERS {
            break;
        }
    }
    Ok(frames)
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
    fn rejects_input_without_the_connection_preface() {
        assert!(parse_preamble(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_empty_input() {
        assert!(parse_preamble(&[]).is_err());
    }

    #[test]
    fn curl_preamble_is_settings_then_window_update_then_headers() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        let kinds: Vec<u8> = frames.iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            vec![0x4, 0x8, 0x1],
            "SETTINGS, WINDOW_UPDATE, HEADERS"
        );
    }

    #[test]
    fn chrome_preamble_ends_at_the_headers_frame() {
        let raw = fixture("chrome-h2");
        let frames = parse_preamble(&raw).expect("parse");
        assert_eq!(frames.last().map(|f| f.kind), Some(0x1));
        assert!(frames.iter().any(|f| f.kind == 0x4), "SETTINGS present");
    }

    /// M0 S2 finding 6. The stream identifier lives at bytes 5..9 of the frame
    /// header, not 4..8. Reading it one byte early swallows the flags byte and
    /// yields 83886080 (0x05000000) for what is really stream 1. The bug is silent
    /// because frame boundaries stay correct, so it needs its own assertion.
    #[test]
    fn headers_frame_is_stream_one_with_end_stream_and_end_headers() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        let h = frames.iter().find(|f| f.kind == 0x1).expect("HEADERS");
        assert_eq!(h.stream_id, 1, "an off-by-one here would give 83886080");
        assert_eq!(h.flags, 0x05, "END_STREAM | END_HEADERS");
    }

    #[test]
    fn connection_level_frames_are_stream_zero() {
        for name in ["curl-8.7.1-h2", "chrome-h2"] {
            let raw = fixture(name);
            let frames = parse_preamble(&raw).expect("parse");
            for f in frames.iter().filter(|f| f.kind != 0x1) {
                assert_eq!(f.stream_id, 0, "{name}: {} should be stream 0", f.kind);
            }
        }
    }

    #[test]
    fn payload_lengths_match_the_declared_frame_lengths() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        let settings = frames.iter().find(|f| f.kind == 0x4).expect("SETTINGS");
        assert_eq!(settings.payload.len(), 18, "3 settings of 6 bytes each");
        let wu = frames
            .iter()
            .find(|f| f.kind == 0x8)
            .expect("WINDOW_UPDATE");
        assert_eq!(wu.payload.len(), 4);
    }

    #[test]
    fn truncation_at_every_offset_never_panics() {
        for name in ["curl-8.7.1-h2", "chrome-h2"] {
            let raw = fixture(name);
            for cut in 0..=raw.len() {
                let _ = parse_preamble(raw.get(..cut).unwrap_or_default());
            }
        }
    }

    #[test]
    fn a_frame_length_longer_than_the_input_errors() {
        let mut data = PREFACE.to_vec();
        data.extend_from_slice(&[0xff, 0xff, 0xff, 0x04, 0x00, 0, 0, 0, 0]);
        assert!(parse_preamble(&data).is_err());
    }
}
