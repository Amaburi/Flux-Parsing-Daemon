//! Append-only log of every acceptance event.

use crate::record::AcceptanceRecord;
use crate::store::TermsError;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn history_path(dir: &Path) -> PathBuf {
    dir.join("terms-history.jsonl")
}

/// Opens in append mode only, never truncates, never rewrites. `source` records
/// how acceptance was given (`interactive`, `env`), so a CI acceptance leaves the
/// same audit trail as one typed by a human.
pub fn append(dir: &Path, r: &AcceptanceRecord, source: &str) -> Result<(), TermsError> {
    std::fs::create_dir_all(dir)?;

    let mut line = serde_json::to_value(r)?;
    if let Some(obj) = line.as_object_mut() {
        obj.insert("source".into(), serde_json::Value::String(source.into()));
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(history_path(dir))?;
    writeln!(f, "{}", serde_json::to_string(&line)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::AcceptanceRecord;

    #[test]
    fn appending_never_truncates_prior_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        append(dir.path(), &AcceptanceRecord::new("0.1.0"), "interactive").expect("1");
        append(dir.path(), &AcceptanceRecord::new("0.2.0"), "env").expect("2");

        let text = std::fs::read_to_string(history_path(dir.path())).expect("read");
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 2, "second append must not truncate the first");
        assert!(lines[0].contains("0.1.0"));
        assert!(lines[1].contains(r#""source":"env""#));
    }

    /// `FPD_ACCEPT_TERMS=1` is an acceptance mechanism, not an exemption, it must
    /// leave the same audit trail an interactive acceptance does.
    #[test]
    fn the_acceptance_source_is_recorded() {
        let dir = tempfile::tempdir().expect("tempdir");
        append(dir.path(), &AcceptanceRecord::new("0.1.0"), "env").expect("append");

        let text = std::fs::read_to_string(history_path(dir.path())).expect("read");
        assert!(text.contains(r#""source":"env""#));
        assert!(text.contains("terms_version"));
        assert!(text.contains("accepted_at"));
    }
}
