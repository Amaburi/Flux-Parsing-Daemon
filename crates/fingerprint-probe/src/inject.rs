//! The headers `serve` attaches to a request before forwarding it.
//!
//! Any application in any language reads these with its existing logger. That is
//! the point of the sidecar shape: no application code changes.

use crate::probe::ClientReport;
use crate::verdict::Identification;

/// Prefix owned by fpd. Anything arriving from a client with this prefix is
/// removed before injection.
pub const FP_PREFIX: &str = "x-fp-";

/// Removes every inbound `X-FP-*` header.
///
/// **This is a security property, not tidiness.** Without it a client sends its
/// own `X-FP-Verdict: chrome-macos` and the upstream believes it, which turns the
/// whole mechanism into something a caller controls. Matching is case insensitive
/// because header names are.
pub fn strip_inbound(headers: &mut Vec<(String, String)>) {
    headers.retain(|(name, _)| !name.to_ascii_lowercase().starts_with(FP_PREFIX));
}

/// The headers to attach.
///
/// Values are always present, never omitted on failure. Downstream must be able
/// to distinguish "fpd looked and found nothing" from "fpd was not in the path",
/// and an absent header cannot express the first.
pub fn fp_headers(report: &ClientReport, id: &Identification) -> Vec<(String, String)> {
    let mut out = Vec::new();

    out.push(("x-fp-ja4".into(), report.tls.ja4.clone()));
    out.push(("x-fp-ja3".into(), report.tls.ja3.clone()));

    match &report.h2 {
        Some(h2) => {
            out.push(("x-fp-h2".into(), h2.akamai.clone()));
            out.push((
                "x-fp-http-headers".into(),
                h2.http.comparable_headers().join(","),
            ));
        }
        None => {
            out.push(("x-fp-h2".into(), "none".into()));
            out.push(("x-fp-http-headers".into(), String::new()));
        }
    }

    match &id.best {
        Some(best) => {
            out.push(("x-fp-verdict".into(), best.label.clone()));
            out.push(("x-fp-confidence".into(), format!("{:.2}", best.score)));
        }
        None => {
            out.push(("x-fp-verdict".into(), "unknown".into()));
            out.push(("x-fp-confidence".into(), "0.00".into()));
        }
    }

    match &id.mismatch {
        Some(m) => {
            out.push(("x-fp-mismatch".into(), "true".into()));
            out.push(("x-fp-claimed".into(), m.claimed.as_str().into()));
        }
        None => out.push(("x-fp-mismatch".into(), "false".into())),
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// The security property of this milestone.
    #[test]
    fn inbound_fp_headers_are_stripped_before_injection() {
        let mut h = headers(&[
            ("x-fp-verdict", "chrome-macos"),
            ("X-FP-Mismatch", "false"),
            ("x-fp-ja4", "forged"),
            ("x-real-header", "kept"),
            ("user-agent", "curl/8.7.1"),
        ]);

        strip_inbound(&mut h);

        assert!(!h
            .iter()
            .any(|(n, _)| n.to_ascii_lowercase().starts_with("x-fp-")));
        assert_eq!(h.len(), 2, "non-fpd headers must survive");
    }

    #[test]
    fn stripping_is_case_insensitive_because_header_names_are() {
        for name in ["X-FP-JA4", "x-fp-ja4", "X-Fp-Ja4", "x-FP-verdict"] {
            let mut h = headers(&[(name, "x")]);
            strip_inbound(&mut h);
            assert!(h.is_empty(), "{name} survived stripping");
        }
    }

    /// A header that merely starts similarly must not be caught.
    #[test]
    fn headers_that_only_resemble_the_prefix_are_kept() {
        let mut h = headers(&[("x-fpx-thing", "kept"), ("x-f", "kept"), ("xfp-a", "kept")]);
        strip_inbound(&mut h);
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn stripping_an_empty_list_is_harmless() {
        let mut h: Vec<(String, String)> = Vec::new();
        strip_inbound(&mut h);
        assert!(h.is_empty());
    }
}
