//! Emitting an HTTP/2 preamble that reproduces a profile.
//!
//! The design assumed a vendored and patched `h2` crate would be needed, because
//! stock `h2` normalises SETTINGS and hides frame order, which is the measurement
//! itself. Revisiting that once the shape was clear: **we do not need an HTTP/2
//! client, we need to emit a preamble.** Preface, SETTINGS, WINDOW_UPDATE and one
//! HEADERS frame, then stop.
//!
//! That is a few hundred bytes of writing, against roughly fifteen thousand lines
//! of vendored `h2` to maintain and re-patch on every upstream release. The same
//! reasoning that replaced the HPACK decoder applies here.

use fingerprint_h2::hpack::encode::encode_headers;
use fingerprint_probe::profile::Profile;

use crate::EmulateError;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADERS: u8 = 0x1;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// Frame header: `length(3) | type(1) | flags(1) | R + stream_id(4)`.
///
/// The stream identifier occupies bytes 5..9. Placing it at 4..8 is the exact
/// off-by-one the M0 S2 spike found on the reading side, and it is just as easy
/// to make here.
fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut out = Vec::with_capacity(9 + len);
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Builds the pseudo-header list in the order the profile recorded.
///
/// Pseudo-header order is one of the two discriminators the Akamai fingerprint
/// rests on, so it comes from the profile rather than from a fixed order here.
fn pseudo_headers(order: &str, authority: &str, scheme: &str, path: &str) -> Vec<(String, String)> {
    order
        .split(',')
        .filter_map(|letter| match letter.trim() {
            "m" => Some((":method".to_string(), "GET".to_string())),
            "a" => Some((":authority".to_string(), authority.to_string())),
            "s" => Some((":scheme".to_string(), scheme.to_string())),
            "p" => Some((":path".to_string(), path.to_string())),
            _ => None,
        })
        .collect()
}

/// The bytes an emulated client writes immediately after the TLS handshake.
///
/// Regular headers come from the profile's recorded order, with values supplied
/// by `values`. **Profiles never store header values**, by design: the privacy
/// position is that fpd records names, order and counts and nothing else. So a
/// profile carries the *shape* of a request and the caller supplies what goes in
/// it, which is the correct division. A caller wanting to look like Chrome to a
/// real server must provide real values; empty ones reproduce the fingerprint but
/// would not survive anything that inspects content.
pub fn preamble_for(profile: &Profile, authority: &str) -> Result<Vec<u8>, EmulateError> {
    preamble_with_values(profile, authority, &[])
}

/// As [`preamble_for`], with values for named headers. Anything unnamed is sent
/// empty.
pub fn preamble_with_values(
    profile: &Profile,
    authority: &str,
    values: &[(&str, &str)],
) -> Result<Vec<u8>, EmulateError> {
    let h2 = profile
        .h2
        .as_ref()
        .ok_or_else(|| EmulateError::Tls("profile has no HTTP/2 section".into()))?;

    let mut out = Vec::new();
    out.extend_from_slice(PREFACE);

    // SETTINGS in the profile's wire order. M0 S2 measured curl sending 3, 4, 2,
    // not ascending, so sorting here would change the fingerprint.
    let mut settings = Vec::with_capacity(h2.settings.len() * 6);
    for (id, value) in &h2.settings {
        settings.extend_from_slice(&id.to_be_bytes());
        settings.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&frame(FRAME_SETTINGS, 0, 0, &settings));

    if let Some(increment) = h2.window_update {
        let payload = (increment & 0x7fff_ffff).to_be_bytes();
        out.extend_from_slice(&frame(FRAME_WINDOW_UPDATE, 0, 0, &payload));
    }

    let mut headers = pseudo_headers(&h2.pseudo_order, authority, "https", "/");

    // Regular headers in the profile's recorded order. Order is the fingerprint,
    // so this list is followed exactly.
    if let Some(http) = &profile.http {
        for name in &http.header_names {
            let value = values
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| (*v).to_string())
                .unwrap_or_default();
            headers.push((name.clone(), value));
        }
    }

    let block = encode_headers(&headers);
    out.extend_from_slice(&frame(
        FRAME_HEADERS,
        FLAG_END_STREAM | FLAG_END_HEADERS,
        1,
        &block,
    ));

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fingerprint_probe::profile::ProfileDb;

    fn profile(label: &str) -> Profile {
        ProfileDb::shipped()
            .expect("db")
            .get(label)
            .expect("profile")
            .clone()
    }

    /// The whole point. What we emit must parse back to the profile's own Akamai
    /// string, through the parser that reads real browsers.
    #[test]
    fn the_emitted_preamble_reproduces_the_profile_akamai_string() {
        for label in ["chrome-macos", "curl-8.7.1-macos"] {
            let p = profile(label);
            let bytes = preamble_for(&p, "example.com").expect("preamble");
            let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");
            let want = p.h2.as_ref().expect("h2").akamai.clone();
            assert_eq!(fp.akamai, want, "{label}");
        }
    }

    /// M0 S2 finding: curl sends settings as 3, 4, 2. Sorting would change the
    /// fingerprint, so emission has to preserve the recorded order.
    #[test]
    fn settings_are_emitted_in_the_profile_order_not_sorted() {
        let p = profile("curl-8.7.1-macos");
        let bytes = preamble_for(&p, "example.com").expect("preamble");
        let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");
        assert_eq!(fp.settings, p.h2.expect("h2").settings);
    }

    /// The other discriminator.
    #[test]
    fn pseudo_header_order_follows_the_profile() {
        for (label, want) in [("chrome-macos", "m,a,s,p"), ("curl-8.7.1-macos", "m,s,a,p")] {
            let bytes = preamble_for(&profile(label), "example.com").expect("preamble");
            let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");
            assert_eq!(fp.pseudo_order, want, "{label}");
        }
    }

    /// Same off-by-one the reading side had. Worth its own assertion on this side
    /// too, because the symptom is a nonsense stream id rather than a parse error.
    #[test]
    fn the_headers_frame_is_stream_one_with_both_end_flags() {
        let bytes = preamble_for(&profile("chrome-macos"), "example.com").expect("preamble");
        let frames = fingerprint_h2::frame::parse_preamble(&bytes).expect("parse");
        let h = frames
            .iter()
            .find(|f| f.kind == FRAME_HEADERS)
            .expect("HEADERS");
        assert_eq!(h.stream_id, 1);
        assert_eq!(h.flags, FLAG_END_STREAM | FLAG_END_HEADERS);
    }

    #[test]
    fn the_preamble_begins_with_the_connection_preface() {
        let bytes = preamble_for(&profile("chrome-macos"), "example.com").expect("preamble");
        assert!(bytes.starts_with(PREFACE));
    }

    /// The HTTP layer is part of the fingerprint too, so the emitted request must
    /// carry the profile's header names in the profile's order.
    #[test]
    fn regular_headers_follow_the_profile_order() {
        let p = profile("chrome-macos");
        let bytes = preamble_for(&p, "example.com").expect("preamble");
        let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");

        let want = p.http.as_ref().expect("http").header_names.clone();
        assert_eq!(fp.http.comparable_headers(), want);
    }

    /// Values are the caller's to supply, since profiles never record them.
    #[test]
    fn supplied_values_reach_the_encoded_headers() {
        let p = profile("chrome-macos");
        let bytes = preamble_with_values(&p, "example.com", &[("user-agent", "fpd/0.1")])
            .expect("preamble");
        let fp = fingerprint_h2::akamai::fingerprint(&bytes).expect("parse");

        let ua = fp
            .headers
            .iter()
            .find(|(n, _)| n == "user-agent")
            .map(|(_, v)| v.clone());
        assert_eq!(ua.as_deref(), Some("fpd/0.1"));
    }

    #[test]
    fn a_profile_without_an_http2_section_is_an_error() {
        let mut p = profile("chrome-macos");
        p.h2 = None;
        assert!(preamble_for(&p, "example.com").is_err());
    }
}
