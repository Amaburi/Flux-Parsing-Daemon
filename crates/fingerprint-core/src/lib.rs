#![deny(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]

//! Pure TLS fingerprint parsing. No sockets, no clock, no randomness.

pub mod ext;
pub mod grease;
pub mod hello;
pub mod ja3;
pub mod ja4;
pub mod reader;
