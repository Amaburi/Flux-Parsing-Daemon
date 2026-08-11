//! Computes the canonical SHA-256 of TERMS.md at compile time and exposes it as
//! `FPD_TERMS_HASH`. Together with `include_str!` in lib.rs this means the terms
//! text and its hash can never drift apart, and neither is ever read from disk
//! at runtime.

use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo");
    let terms = PathBuf::from(&manifest).join("../../TERMS.md");

    println!("cargo:rerun-if-changed={}", terms.display());

    let bytes = fs::read(&terms).unwrap_or_else(|e| {
        panic!(
            "TERMS.md must exist at the repo root ({}): {e}",
            terms.display()
        )
    });

    println!(
        "cargo:rustc-env=FPD_TERMS_HASH=sha256:{:x}",
        Sha256::digest(&bytes)
    );
}
