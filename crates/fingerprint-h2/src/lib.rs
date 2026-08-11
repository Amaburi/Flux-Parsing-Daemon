#![deny(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]

//! Pure HTTP/2 preamble parsing. No sockets, no clock, no randomness.

pub mod akamai;
pub mod frame;
pub mod headers;
pub mod hpack;
pub mod http;
pub mod settings;
