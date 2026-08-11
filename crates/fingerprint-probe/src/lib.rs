#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Everything in fpd that touches a socket.
//!
//! `fingerprint-core` and `fingerprint-h2` stay pure. This crate is the only
//! place a listener, a certificate or a clock appears.

pub mod diff;
pub mod probe;
pub mod profile;
pub mod recording;
