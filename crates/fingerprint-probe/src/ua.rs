//! Extracting a claimed browser family from a User-Agent string.
//!
//! **This is deliberately conservative.** The value of mismatch detection comes
//! entirely from refusing to guess. An operator who sees one wrong flag stops
//! trusting all of them, so `Unknown` is a good answer and is the default for
//! anything unrecognised.
//!
//! Order of matching matters, because these strings nest. Chrome's User-Agent
//! contains the literal word `Safari`, and Edge's contains `Chrome`. Substring
//! matching in the wrong order misclassifies both, and both are common enough
//! that the error would be constant rather than rare.

/// The one header value fpd reads.
///
/// Everything else, cookie and authorization above all, is never read. Mismatch
/// detection compares what a client *claims* against what it *is*, and the claim
/// lives in this value. There is no way to do it without reading this, and the
/// exception is documented in the README rather than left implicit.
pub const USER_AGENT: &str = "user-agent";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Curl,
    Python,
    Go,
    Node,
    /// Not recognised. Never a guess.
    Unknown,
}

impl Family {
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Chrome => "chrome",
            Family::Firefox => "firefox",
            Family::Safari => "safari",
            Family::Edge => "edge",
            Family::Curl => "curl",
            Family::Python => "python",
            Family::Go => "go",
            Family::Node => "node",
            Family::Unknown => "unknown",
        }
    }
}

/// Classifies a User-Agent, or returns `Unknown`.
///
/// Browsers are tested most specific first. Edge before Chrome, Chrome before
/// Safari, since each carries the next one's token.
pub fn claimed_family(ua: &str) -> Family {
    let s = ua.to_ascii_lowercase();

    // Non-browser clients first: their strings are unambiguous.
    if s.starts_with("curl/") {
        return Family::Curl;
    }
    if s.starts_with("python-requests/") || s.starts_with("python-urllib") {
        return Family::Python;
    }
    if s.starts_with("go-http-client/") {
        return Family::Go;
    }
    if s.starts_with("node") || s.starts_with("undici") || s.starts_with("axios/") {
        return Family::Node;
    }

    // Browsers, most specific token first.
    if s.contains("edg/") || s.contains("edga/") || s.contains("edgios/") {
        return Family::Edge;
    }
    if s.contains("firefox/") || s.contains("fxios/") {
        return Family::Firefox;
    }
    if s.contains("chrome/") || s.contains("crios/") {
        return Family::Chrome;
    }
    // Only reached when no Chrome or Edge token was present, which is what makes
    // this Safari rather than any Chromium browser.
    if s.contains("safari/") && s.contains("version/") {
        return Family::Safari;
    }

    Family::Unknown
}

/// Pulls the User-Agent out of a decoded header list.
pub fn user_agent_of(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(USER_AGENT))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_user_agents_are_classified() {
        let cases = [
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                Family::Chrome,
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) \
                 Gecko/20100101 Firefox/133.0",
                Family::Firefox,
            ),
            ("curl/8.7.1", Family::Curl),
            ("python-requests/2.31.0", Family::Python),
            ("Go-http-client/2.0", Family::Go),
        ];
        for (ua, want) in cases {
            assert_eq!(claimed_family(ua), want, "{ua}");
        }
    }

    /// The trap. Chrome's string contains "Safari", Edge's contains "Chrome".
    /// Naive substring matching gets both wrong, constantly.
    #[test]
    fn chrome_is_not_mistaken_for_safari_and_edge_is_not_mistaken_for_chrome() {
        let chrome = "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) \
                      Chrome/131.0.0.0 Safari/537.36";
        assert_eq!(claimed_family(chrome), Family::Chrome);

        let edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                    (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0";
        assert_eq!(claimed_family(edge), Family::Edge);

        let safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 \
                      (KHTML, like Gecko) Version/17.6 Safari/605.1.15";
        assert_eq!(claimed_family(safari), Family::Safari);
    }

    /// Chrome on iOS reports CriOS, Firefox on iOS reports FxiOS, and neither
    /// carries the desktop token. Missing these would flag every mobile visitor.
    #[test]
    fn ios_browser_variants_are_recognised() {
        let crios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.0.0 \
                     Mobile/15E148 Safari/604.1";
        assert_eq!(claimed_family(crios), Family::Chrome);

        let fxios = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) \
                     AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 \
                     Mobile/15E148 Safari/605.1.15";
        assert_eq!(claimed_family(fxios), Family::Firefox);
    }

    /// Anything unrecognised is Unknown. This is the property the whole feature
    /// rests on.
    #[test]
    fn unrecognised_and_empty_agents_are_unknown() {
        for ua in [
            "",
            "x",
            "Mozilla/5.0",
            "SomeInternalTool/1.2",
            "🙂",
            "Safari/537.36",
        ] {
            assert_eq!(claimed_family(ua), Family::Unknown, "{ua:?}");
        }
    }

    /// A bare `Safari/` token without `Version/` is what Chromium derivatives
    /// carry. Treating it as Safari would misclassify a large share of traffic.
    #[test]
    fn a_bare_safari_token_is_not_enough_to_claim_safari() {
        assert_eq!(
            claimed_family("AppleWebKit/605.1.15 Safari/604.1"),
            Family::Unknown
        );
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(claimed_family("CURL/8.7.1"), Family::Curl);
        assert_eq!(claimed_family("... CHROME/131.0.0.0 ..."), Family::Chrome);
    }

    #[test]
    fn the_user_agent_is_found_regardless_of_header_name_casing() {
        let h = vec![("User-Agent".to_string(), "curl/8.7.1".to_string())];
        assert_eq!(user_agent_of(&h), Some("curl/8.7.1"));
        assert_eq!(user_agent_of(&[]), None);
    }
}
