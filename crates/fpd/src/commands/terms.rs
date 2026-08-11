//! `fpd terms show` and `fpd terms accept`.

use fingerprint_terms::{history, record::AcceptanceRecord, store, TERMS, TERMS_HASH};

/// Prints the terms compiled into this binary. Never reads from disk, so a
/// `TERMS.md` sitting in the working directory has no effect whatsoever.
pub fn show(hash_only: bool) {
    if hash_only {
        println!("{TERMS_HASH}");
    } else {
        println!("{TERMS}");
        println!("terms hash: {TERMS_HASH}");
    }
}

pub fn accept() -> Result<(), Box<dyn std::error::Error>> {
    let dir = store::config_dir()?;
    let rec = AcceptanceRecord::new(env!("CARGO_PKG_VERSION"));

    store::save(&dir, &rec)?;
    history::append(&dir, &rec, "interactive")?;

    println!("Terms accepted.");
    println!("  version:  {}", rec.terms_version);
    println!("  recorded: {}", store::record_path(&dir).display());
    Ok(())
}
