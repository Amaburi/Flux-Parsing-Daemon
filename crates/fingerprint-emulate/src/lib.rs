#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Building a TLS client that reproduces a captured profile, and proving it does.
//!
//! Every browser-emulation client in existence emits a browser-shaped handshake
//! and asks you to believe it still works. None can answer whether its output
//! still matches Chrome after a dependency bump, because the emitter and the
//! ground truth live in different projects.
//!
//! fpd already holds the parser, the profile database and a capture probe.
//! Adding the emitter closes the loop: [`verify`] binds the probe in process,
//! drives the emulated client at it, and diffs the result against the profile it
//! was built from. No external network, so it runs in CI.
//!
//! # Feature gate
//!
//! Everything here is behind the non-default `emulation` feature, per design
//! section 4.2. Enabling it is an explicit opt-in and pulls in BoringSSL, a C
//! dependency a default build does not carry.
//!
//! # Equivalence, not byte equality
//!
//! Two consecutive real Chrome handshakes are not identical to each other, since
//! Chrome permutes extension order per connection and its GREASE values rotate.
//! Verification therefore asserts equivalence under the profile's own stated
//! class rather than byte equality. Comparing literally makes every Chrome
//! verification flake; comparing too loosely lets a wrong handshake pass.

pub mod ciphers;

#[cfg(feature = "emulation")]
pub mod build;
#[cfg(feature = "emulation")]
pub mod extensions;
#[cfg(feature = "emulation")]
pub mod verify;

#[derive(Debug, thiserror::Error)]
pub enum EmulateError {
    #[error("profile uses cipher {0:#06x}, which has no name mapping")]
    UnknownCipher(u16),
    #[error("tls setup: {0}")]
    Tls(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("the probe captured nothing")]
    NoCapture,
    #[error("emulation support was not compiled in; build with --features emulation")]
    NotCompiledIn,
}
