//! The Akamai HTTP/2 fingerprint.
//!
//! Format: `SETTINGS | WINDOW_UPDATE | PRIORITY | pseudo-header order`, where
//! SETTINGS is `id:value` joined by `;` in wire order, PRIORITY is
//! `streamId:exclusive:dependsOn:weight` joined by `,` or `0` when there are none,
//! and the pseudo-header order uses the letters m, a, s, p.
//!
//! Every component here was validated against tshark in `settings` and `headers`.
//! This module only assembles them.

use crate::frame::{parse_preamble, H2Error, FRAME_HEADERS};
use crate::headers::{decode_headers, pseudo_header_order};
pub use crate::settings::Priority;
use crate::settings::{priorities, settings_pairs, window_update};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Fingerprint {
    pub settings: Vec<(u16, u32)>,
    pub window_update: Option<u32>,
    pub priorities: Vec<Priority>,
    pub pseudo_order: String,
    pub headers: Vec<(String, String)>,
    pub akamai: String,
}

fn render_settings(pairs: &[(u16, u32)]) -> String {
    pairs
        .iter()
        .map(|(id, v)| format!("{id}:{v}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// `streamId:exclusive:dependsOn:weight`, comma joined. `0` when there are none,
/// which is the case for every modern client.
pub fn render_priorities(p: &[Priority]) -> String {
    if p.is_empty() {
        return "0".to_string();
    }
    p.iter()
        .map(|x| {
            format!(
                "{}:{}:{}:{}",
                x.stream_id,
                u8::from(x.exclusive),
                x.depends_on,
                x.weight
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

pub fn fingerprint(raw: &[u8]) -> Result<H2Fingerprint, H2Error> {
    let frames = parse_preamble(raw)?;

    let headers = frames
        .iter()
        .find(|f| f.kind == FRAME_HEADERS)
        .map(decode_headers)
        .unwrap_or_default();

    let settings = settings_pairs(&frames);
    let wu = window_update(&frames);
    let prio = priorities(&frames);
    let pseudo_order = pseudo_header_order(&headers);

    let akamai = format!(
        "{}|{}|{}|{}",
        render_settings(&settings),
        wu.unwrap_or(0),
        render_priorities(&prio),
        pseudo_order
    );

    Ok(H2Fingerprint {
        settings,
        window_update: wu,
        priorities: prio,
        pseudo_order,
        headers,
        akamai,
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
    fn curl_akamai_string_is_assembled_correctly() {
        let raw = fixture("curl-8.7.1-h2");
        assert_eq!(
            fingerprint(&raw).expect("fp").akamai,
            "3:100;4:10485760;2:0|1048510465|0|m,s,a,p"
        );
    }

    #[test]
    fn chrome_akamai_string_is_assembled_correctly() {
        let raw = fixture("chrome-h2");
        assert_eq!(
            fingerprint(&raw).expect("fp").akamai,
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
    }

    /// Both discriminators in one assertion: presence of SETTINGS id 3, and
    /// pseudo-header order.
    #[test]
    fn the_two_fixtures_differ_on_both_discriminators() {
        let curl_raw = fixture("curl-8.7.1-h2");
        let chrome_raw = fixture("chrome-h2");
        let c = fingerprint(&curl_raw).expect("fp");
        let g = fingerprint(&chrome_raw).expect("fp");

        assert_ne!(c.akamai, g.akamai);
        assert!(c.akamai.contains("3:100"), "curl announces id 3");
        assert!(!g.akamai.contains("3:100"), "Chrome never sends id 3");
        assert!(c.akamai.ends_with("m,s,a,p"));
        assert!(g.akamai.ends_with("m,a,s,p"));
    }

    /// Modern clients send no PRIORITY frames. Chrome carries priority in the
    /// HEADERS frame flags instead, which the Akamai priority field does not count.
    #[test]
    fn absent_priority_frames_render_as_zero() {
        for name in ["curl-8.7.1-h2", "chrome-h2"] {
            let raw = fixture(name);
            let fp = fingerprint(&raw).expect("fp");
            assert!(fp.priorities.is_empty(), "{name}");
            assert!(fp.akamai.contains("|0|"), "{name}");
        }
    }

    #[test]
    fn settings_are_rendered_in_wire_order_not_sorted() {
        let raw = fixture("curl-8.7.1-h2");
        let fp = fingerprint(&raw).expect("fp");
        assert!(
            fp.akamai.starts_with("3:100;4:10485760;2:0|"),
            "wire order 3,4,2 must survive into the string"
        );
    }

    #[test]
    fn a_synthetic_priority_frame_is_rendered_in_the_third_field() {
        let p = vec![Priority {
            stream_id: 3,
            exclusive: false,
            depends_on: 0,
            weight: 201,
        }];
        assert_eq!(render_priorities(&p), "3:0:0:201");
    }

    #[test]
    fn malformed_input_yields_an_error_not_a_fingerprint() {
        assert!(fingerprint(&[]).is_err());
        assert!(fingerprint(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }
}
