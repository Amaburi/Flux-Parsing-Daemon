//! The HTTP layer of a client's identity.
//!
//! This is fpd's own design, not JA4H. Three reasons, in order of weight.
//!
//! **It is not hashed.** fpd's job is to say *what* differs, not merely *that*
//! something does. A hash destroys that. Compare `header order: got A, expected B`
//! against `hash 974ebe531c03, expected a1b2c3d4e5f6`. Only one of those is
//! actionable.
//!
//! **Header values are not read.** JA4H hashes cookie fields together with their
//! values. fpd promises that header values never enter the fingerprint path, and
//! that promise is worth more than the extra signal. The number of `cookie`
//! headers is recorded instead, which is real signal because HPACK splits cookies,
//! and it requires reading nothing.
//!
//! **JA4H fingerprints a request. fpd profiles a client.** Method and referer
//! change between requests from the same browser, so comparing them would make
//! Chrome fail to match itself. Fields are therefore split into those that
//! identify the client and those that only describe this particular request.
//!
//! JA4H is also patent pending and licensed under FoxIO License 1.1, which is not
//! permissive for monetization. That alone would be reason enough to avoid
//! copying it, but the three above stand on their own.

/// Headers excluded from the comparable header count, because their presence is a
/// property of the site and the navigation rather than of the client.
const REQUEST_SCOPED: &[&str] = &["cookie", "referer"];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpProfile {
    // --- client identifying, compared ---------------------------------------
    /// Regular header names in wire order. Pseudo-headers are excluded because
    /// their order is already carried by the Akamai fingerprint.
    pub header_names: Vec<String>,
    /// Count excluding request-scoped headers.
    pub header_count: usize,
    /// Browsers send `accept-language`, curl does not. The value is deliberately
    /// not recorded: it reveals user locale and adds little over presence.
    pub has_accept_language: bool,

    // --- request scoped, reported but never compared -------------------------
    /// From the `:method` pseudo-header. Varies between requests from one client.
    pub method: Option<String>,
    /// HPACK splits a cookie header into several. The count is signal, the values
    /// are never read.
    pub cookie_header_count: usize,
    pub has_referer: bool,
}

fn is_pseudo(name: &str) -> bool {
    name.starts_with(':')
}

impl HttpProfile {
    pub fn from_headers(headers: &[(String, String)]) -> Self {
        let mut header_names = Vec::new();
        let mut cookie_header_count = 0usize;
        let mut has_referer = false;
        let mut has_accept_language = false;
        let mut method = None;

        for (name, value) in headers {
            let lower = name.to_ascii_lowercase();

            if is_pseudo(&lower) {
                if lower == ":method" {
                    method = Some(value.clone());
                }
                continue;
            }

            match lower.as_str() {
                "cookie" => cookie_header_count += 1,
                "referer" => has_referer = true,
                "accept-language" => has_accept_language = true,
                _ => {}
            }
            header_names.push(lower);
        }

        let header_count = header_names
            .iter()
            .filter(|n| !REQUEST_SCOPED.contains(&n.as_str()))
            .count();

        Self {
            header_names,
            header_count,
            has_accept_language,
            method,
            cookie_header_count,
            has_referer,
        }
    }

    /// Header names with request-scoped ones removed. This is what a client
    /// comparison uses, so that a site setting a cookie does not make a browser
    /// stop matching its own profile.
    pub fn comparable_headers(&self) -> Vec<String> {
        self.header_names
            .iter()
            .filter(|n| !REQUEST_SCOPED.contains(&n.as_str()))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{parse_preamble, FRAME_HEADERS};
    use crate::headers::decode_headers;

    fn fixture(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("{name}.bin"));
        std::fs::read(p).expect("fixture")
    }

    fn profile_of(name: &str) -> HttpProfile {
        let raw = fixture(name);
        let frames = parse_preamble(&raw).expect("parse");
        let h = frames
            .iter()
            .find(|f| f.kind == FRAME_HEADERS)
            .expect("HEADERS");
        HttpProfile::from_headers(&decode_headers(h))
    }

    /// Derived from the tshark-validated header list. curl sends only two regular
    /// headers, which is itself the discriminator against any browser.
    #[test]
    fn curl_has_two_regular_headers() {
        let p = profile_of("curl-8.7.1-h2");
        assert_eq!(p.header_names, vec!["user-agent", "accept"]);
        assert_eq!(p.header_count, 2);
        assert!(!p.has_accept_language, "curl sends no accept-language");
        assert_eq!(p.cookie_header_count, 0);
    }

    /// Chrome's `sec-ch-ua` and `sec-fetch-` block is strongly browser shaped.
    #[test]
    fn chrome_header_order_matches_the_oracle() {
        let p = profile_of("chrome-h2");
        assert_eq!(
            p.header_names,
            vec![
                "cache-control",
                "sec-ch-ua",
                "sec-ch-ua-mobile",
                "sec-ch-ua-platform",
                "upgrade-insecure-requests",
                "user-agent",
                "accept",
                "sec-fetch-site",
                "sec-fetch-mode",
                "sec-fetch-user",
                "sec-fetch-dest",
                "accept-encoding",
                "accept-language",
                "cookie",
                "cookie",
                "cookie",
                "priority",
            ]
        );
        assert!(p.has_accept_language);
    }

    /// HPACK splits cookies, so the count is real signal. Recording it needs no
    /// value to be read.
    #[test]
    fn cookie_headers_are_counted_but_never_read() {
        let p = profile_of("chrome-h2");
        assert_eq!(p.cookie_header_count, 3);
    }

    /// Pseudo-headers belong to the Akamai fingerprint, not here, so they must not
    /// be duplicated into the header list.
    #[test]
    fn pseudo_headers_are_excluded_from_the_header_list() {
        for name in ["curl-8.7.1-h2", "chrome-h2"] {
            let p = profile_of(name);
            assert!(
                !p.header_names.iter().any(|n| n.starts_with(':')),
                "{name} leaked a pseudo-header"
            );
        }
    }

    #[test]
    fn the_method_is_recorded_from_the_pseudo_header() {
        assert_eq!(profile_of("chrome-h2").method.as_deref(), Some("GET"));
    }

    /// The reason request-scoped headers are separated. A site setting a cookie
    /// must not make a browser stop matching its own profile.
    #[test]
    fn request_scoped_headers_are_excluded_from_the_comparable_set() {
        let with_cookie = HttpProfile::from_headers(&[
            ("user-agent".into(), "x".into()),
            ("cookie".into(), "a=1".into()),
            ("referer".into(), "https://example.com".into()),
        ]);
        let without = HttpProfile::from_headers(&[("user-agent".into(), "x".into())]);

        assert_eq!(
            with_cookie.comparable_headers(),
            without.comparable_headers()
        );
        assert_eq!(with_cookie.header_count, without.header_count);
        // But they are still reported.
        assert_eq!(with_cookie.cookie_header_count, 1);
        assert!(with_cookie.has_referer);
    }

    #[test]
    fn header_names_are_lowercased_so_casing_cannot_split_a_match() {
        let p = HttpProfile::from_headers(&[("User-Agent".into(), "x".into())]);
        assert_eq!(p.header_names, vec!["user-agent"]);
    }

    #[test]
    fn an_empty_header_list_is_handled() {
        let p = HttpProfile::from_headers(&[]);
        assert_eq!(p.header_count, 0);
        assert!(p.method.is_none());
    }
}
