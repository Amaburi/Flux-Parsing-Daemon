//! Where the acceptance record lives on disk, and how it is read back.
//!
//! This module knows paths and I/O but nothing about HMAC; `record` knows HMAC but
//! nothing about the filesystem. That split is why the forgery tests need no disk
//! and the path tests need no crypto.

use crate::record::AcceptanceRecord;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum TermsError {
    #[error("cannot determine config directory")]
    NoConfigDir,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Config directory, overridable via `FPD_CONFIG_DIR` so tests never touch the
/// real user config.
pub fn config_dir() -> Result<PathBuf, TermsError> {
    if let Ok(p) = std::env::var("FPD_CONFIG_DIR") {
        return Ok(PathBuf::from(p));
    }
    directories::ProjectDirs::from("", "", "fpd")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or(TermsError::NoConfigDir)
}

pub fn record_path(dir: &Path) -> PathBuf {
    dir.join("terms-accepted")
}

pub fn save(dir: &Path, r: &AcceptanceRecord) -> Result<(), TermsError> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(record_path(dir), serde_json::to_vec_pretty(r)?)?;
    Ok(())
}

/// Returns `Option`, deliberately, not `Result`.
///
/// Missing, unreadable, malformed, and unverifiable all collapse to the same
/// answer: **not accepted**. There is no failure mode in which removing or
/// corrupting a file grants access — deletion locks the user out instead.
pub fn load(dir: &Path) -> Option<AcceptanceRecord> {
    let bytes = std::fs::read(record_path(dir)).ok()?;
    let r: AcceptanceRecord = serde_json::from_slice(&bytes).ok()?;
    r.verify().then_some(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::AcceptanceRecord;

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = AcceptanceRecord::new("0.1.0");
        save(dir.path(), &r).expect("save");
        let back = load(dir.path()).expect("should load");
        assert_eq!(back.sig, r.sig);
        assert!(back.verify());
    }

    #[test]
    fn a_missing_file_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(load(dir.path()).is_none());
    }

    /// The property the whole gate rests on: there is no file whose deletion
    /// disables the gate. Removing the record revokes access, never grants it.
    #[test]
    fn deleting_the_record_locks_out_rather_than_admits() {
        let dir = tempfile::tempdir().expect("tempdir");
        save(dir.path(), &AcceptanceRecord::new("0.1.0")).expect("save");
        assert!(load(dir.path()).is_some(), "precondition: accepted");

        std::fs::remove_file(record_path(dir.path())).expect("remove");
        assert!(
            load(dir.path()).is_none(),
            "deletion must revoke, never grant"
        );
    }

    #[test]
    fn malformed_json_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(record_path(dir.path()), b"{ not json").expect("write");
        assert!(load(dir.path()).is_none());
    }

    /// Proves `load` actually runs verification rather than merely deserialising.
    /// Without this, dropping the `verify()` call would leave every other store
    /// test green while making hand-forged records acceptable.
    #[test]
    fn a_tampered_record_on_disk_is_not_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut r = AcceptanceRecord::new("0.1.0");
        save(dir.path(), &r).expect("save");
        assert!(load(dir.path()).is_some(), "precondition: accepted");

        // Simulate a user editing the file by hand to fake an earlier acceptance.
        r.accepted_at = "1999-01-01T00:00:00Z".into();
        save(dir.path(), &r).expect("save tampered");
        assert!(load(dir.path()).is_none(), "tampered record must not load");
    }

    #[test]
    fn config_dir_honours_the_env_override() {
        std::env::set_var("FPD_CONFIG_DIR", "/tmp/fpd-test-override");
        assert_eq!(
            config_dir().expect("dir"),
            std::path::PathBuf::from("/tmp/fpd-test-override")
        );
        std::env::remove_var("FPD_CONFIG_DIR");
    }
}
