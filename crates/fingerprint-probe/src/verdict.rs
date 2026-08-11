//! Identifying an unknown client against the whole profile database.
//!
//! `diff` answers "does this match profile X". This answers "which profile is
//! this, if any". The second question is what `serve` will need, because inbound
//! traffic does not come with a label.

use crate::diff::{diff, Diff};
use crate::probe::ClientReport;
use crate::profile::ProfileDb;
use crate::ua::{claimed_family, user_agent_of, Family};

/// TLS fields that must all agree before a profile is named.
///
/// Equal weighting alone is not enough. There are ten compared fields and seven
/// of them are HTTP/2 or HTTP, so a client with a completely wrong TLS
/// fingerprint but a similar HTTP layer still scored 0.70, which cleared the
/// floor. That is backwards: the TLS layer is the harder one to forge and the
/// more reliable identity signal, so it gates the identification rather than
/// merely contributing to a score.
///
/// ALPN and SNI are deliberately absent. Both depend on how the connection was
/// made rather than on the client, and requiring SNI would stop a browser
/// matching its own profile when reached by IP instead of by name.
const REQUIRED_TLS_FIELDS: &[&str] = &["ciphers", "extensions", "GREASE"];

/// Below this, no profile is named.
///
/// Calibrated from measurement rather than taste. With the current database:
/// a client against its own profile scores 1.00, and curl against the Chrome
/// profile scores 0.20. The floor sits well clear of the latter. It should be
/// re-measured when more profiles are added, because a larger database makes
/// near-misses more likely. `the_measured_scores_still_bracket_the_floor` fails
/// if that assumption stops holding.
pub const MATCH_FLOOR: f32 = 0.60;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub label: String,
    pub score: f32,
    pub diff: Diff,
}

/// A client whose User-Agent contradicts its fingerprint.
///
/// No real browser can produce a `python-requests` TLS fingerprint while claiming
/// Chrome, so this needs no tuning by an operator. That property survives only
/// because every uncertain case declines to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimMismatch {
    pub claimed: Family,
    pub observed: Family,
}

#[derive(Debug, Clone)]
pub struct Identification {
    /// `None` when nothing scored above [`MATCH_FLOOR`]. A tool that always names
    /// a browser is useless, so this has to be reachable.
    pub best: Option<Candidate>,
    /// Every profile, best first. The runner-up is what tells an operator whether
    /// an identification was obvious or close.
    pub ranked: Vec<Candidate>,
    /// Set only when a claim and an identification are both confident and they
    /// disagree. See [`ClaimMismatch`].
    pub mismatch: Option<ClaimMismatch>,
}

pub fn identify(report: &ClientReport, db: &ProfileDb) -> Identification {
    let mut ranked: Vec<Candidate> = db
        .iter()
        .map(|p| {
            let d = diff(report, p);
            Candidate {
                label: p.label.clone(),
                score: d.score(),
                diff: d,
            }
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let best = ranked
        .first()
        .filter(|c| c.score >= MATCH_FLOOR && tls_layer_agrees(&c.diff))
        .cloned();

    let mismatch = detect_mismatch(report, best.as_ref(), db);

    Identification {
        best,
        ranked,
        mismatch,
    }
}

/// Reports a mismatch only when both sides are known.
///
/// Three ways this declines, and each one is a false positive that would
/// otherwise happen constantly:
///
/// - No User-Agent, or one that is not recognised. Silence is not a claim.
/// - No confident identification. If the fingerprint matches nothing, there is
///   nothing to contradict the claim, and reporting one would flag every client
///   the database has not seen.
/// - A profile carrying no family, which cannot be compared against anything.
fn detect_mismatch(
    report: &ClientReport,
    best: Option<&Candidate>,
    db: &ProfileDb,
) -> Option<ClaimMismatch> {
    let headers = &report.h2.as_ref()?.headers;
    let ua = user_agent_of(headers)?;

    let claimed = claimed_family(ua);
    if claimed == Family::Unknown {
        return None;
    }

    let best = best?;
    let profile = db.get(&best.label).ok()?;
    let observed = family_from_name(&profile.family);
    if observed == Family::Unknown {
        return None;
    }

    (claimed != observed).then_some(ClaimMismatch { claimed, observed })
}

/// True when every field in [`REQUIRED_TLS_FIELDS`] compared clean.
fn tls_layer_agrees(d: &Diff) -> bool {
    REQUIRED_TLS_FIELDS.iter().all(|name| {
        d.fields
            .iter()
            .find(|f| f.field == *name)
            .map(|f| f.ok)
            .unwrap_or(false)
    })
}

fn family_from_name(name: &str) -> Family {
    match name {
        "chrome" => Family::Chrome,
        "firefox" => Family::Firefox,
        "safari" => Family::Safari,
        "edge" => Family::Edge,
        "curl" => Family::Curl,
        "python" => Family::Python,
        "go" => Family::Go,
        "node" => Family::Node,
        _ => Family::Unknown,
    }
}
