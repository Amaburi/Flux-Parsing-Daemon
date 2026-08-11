//! SETTINGS, WINDOW_UPDATE and PRIORITY payloads.
//!
//! Two rules drive every decision here, both measured rather than assumed.
//! Order is signal: curl sends its settings as `3, 4, 2`, not ascending.
//! Absence is signal: Chrome sends no id 3 at all, while curl announces `3:100`.

use crate::frame::{Frame, FRAME_PRIORITY, FRAME_SETTINGS, FRAME_WINDOW_UPDATE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    pub stream_id: u32,
    pub exclusive: bool,
    pub depends_on: u32,
    pub weight: u16,
}

/// Settings in the order they appeared on the wire. Never sorted, never defaulted.
/// A payload that is not a multiple of six is malformed and contributes nothing.
pub fn settings_pairs(frames: &[Frame]) -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    for f in frames.iter().filter(|f| f.kind == FRAME_SETTINGS) {
        if f.payload.len() % 6 != 0 {
            continue;
        }
        for c in f.payload.chunks_exact(6) {
            let (Some(&a), Some(&b), Some(&x), Some(&y), Some(&z), Some(&w)) =
                (c.first(), c.get(1), c.get(2), c.get(3), c.get(4), c.get(5))
            else {
                continue;
            };
            out.push((u16::from_be_bytes([a, b]), u32::from_be_bytes([x, y, z, w])));
        }
    }
    out
}

/// The connection-level window increment. The reserved top bit is masked off.
pub fn window_update(frames: &[Frame]) -> Option<u32> {
    let f = frames.iter().find(|f| f.kind == FRAME_WINDOW_UPDATE)?;
    let p = f.payload;
    Some(u32::from_be_bytes([
        *p.first()? & 0x7f,
        *p.get(1)?,
        *p.get(2)?,
        *p.get(3)?,
    ]))
}

/// PRIORITY payload: `E + stream_dependency(4) | weight(1)`. The wire weight is
/// zero-based, so the reported value is weight + 1.
pub fn priorities(frames: &[Frame]) -> Vec<Priority> {
    frames
        .iter()
        .filter(|f| f.kind == FRAME_PRIORITY)
        .filter_map(|f| {
            let p = f.payload;
            let b0 = *p.first()?;
            Some(Priority {
                stream_id: f.stream_id,
                exclusive: b0 & 0x80 != 0,
                depends_on: u32::from_be_bytes([b0 & 0x7f, *p.get(1)?, *p.get(2)?, *p.get(3)?]),
                weight: u16::from(*p.get(4)?) + 1,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{parse_preamble, Frame};

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    /// Oracle: tshark reports `http2.settings.id` as `3,4,2`. Not ascending. This
    /// asserts the sequence, not a set.
    #[test]
    fn curl_settings_are_in_wire_order_not_sorted() {
        let raw = fixture("curl-8.7.1-h2");
        let frames = parse_preamble(&raw).expect("parse");
        assert_eq!(
            settings_pairs(&frames),
            vec![(3, 100), (4, 10_485_760), (2, 0)]
        );
    }

    /// Oracle: tshark reports `1,2,4,6` with values 65536, 0, 6291456, 262144.
    #[test]
    fn chrome_settings_match_the_oracle() {
        let raw = fixture("chrome-h2");
        let frames = parse_preamble(&raw).expect("parse");
        assert_eq!(
            settings_pairs(&frames),
            vec![(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)]
        );
    }

    /// The discriminator. No browser sends SETTINGS id 3, so its presence alone
    /// separates curl-family clients from browsers.
    #[test]
    fn chrome_sends_no_max_concurrent_streams_but_curl_does() {
        let chrome_raw = fixture("chrome-h2");
        let curl_raw = fixture("curl-8.7.1-h2");
        let chrome = parse_preamble(&chrome_raw).expect("parse");
        let curl = parse_preamble(&curl_raw).expect("parse");

        let ids =
            |f: &[Frame]| -> Vec<u16> { settings_pairs(f).iter().map(|(id, _)| *id).collect() };
        assert!(!ids(&chrome).contains(&3), "no browser sends id 3");
        assert!(ids(&curl).contains(&3), "curl announces 3:100");
    }

    #[test]
    fn window_update_matches_the_oracle_for_both_fixtures() {
        let curl_raw = fixture("curl-8.7.1-h2");
        let chrome_raw = fixture("chrome-h2");
        assert_eq!(
            window_update(&parse_preamble(&curl_raw).expect("parse")),
            Some(1_048_510_465)
        );
        assert_eq!(
            window_update(&parse_preamble(&chrome_raw).expect("parse")),
            Some(15_663_105)
        );
    }

    /// Absence must stay distinguishable from present-at-default. A map with
    /// defaults filled in would destroy the fingerprint.
    #[test]
    fn a_setting_absent_from_the_wire_is_absent_from_the_list() {
        let frames = vec![Frame {
            kind: 0x4,
            flags: 0,
            stream_id: 0,
            payload: &[0, 4, 0, 1, 0, 0],
        }];
        let pairs = settings_pairs(&frames);
        assert_eq!(pairs, vec![(4, 65_536)]);
        assert!(!pairs.iter().any(|(id, _)| *id == 3));
    }

    #[test]
    fn a_settings_payload_that_is_not_a_multiple_of_six_is_ignored_not_panicked_on() {
        let frames = vec![Frame {
            kind: 0x4,
            flags: 0,
            stream_id: 0,
            payload: &[0, 4, 0],
        }];
        assert!(settings_pairs(&frames).is_empty());
    }

    #[test]
    fn a_missing_window_update_frame_yields_none() {
        assert_eq!(window_update(&[]), None);
    }

    /// Both fixtures are modern clients, so neither sends PRIORITY frames. Chrome
    /// uses RFC 9218 extensible priorities instead, visible as a `priority` header.
    #[test]
    fn neither_fixture_sends_priority_frames() {
        for name in ["curl-8.7.1-h2", "chrome-h2"] {
            let raw = fixture(name);
            let frames = parse_preamble(&raw).expect("parse");
            assert!(priorities(&frames).is_empty(), "{name}");
        }
    }

    /// The parsing path still has to work, so it is exercised synthetically until
    /// a Firefox fixture arrives.
    #[test]
    fn a_synthetic_priority_frame_is_parsed() {
        let frames = vec![Frame {
            kind: 0x2,
            flags: 0,
            stream_id: 3,
            payload: &[0x80, 0, 0, 0, 200],
        }];
        assert_eq!(
            priorities(&frames),
            vec![Priority {
                stream_id: 3,
                exclusive: true,
                depends_on: 0,
                weight: 201
            }]
        );
    }
}
