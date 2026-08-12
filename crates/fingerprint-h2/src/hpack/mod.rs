//! HPACK decoding, RFC 7541.
//!
//! Written rather than taken from a crate for one concrete reason: the decoder
//! consumes attacker-controlled bytes straight off a socket, and the crate this
//! replaced (`fluke-hpack` 0.3.1) panics on malformed input at
//! `decoder.rs:505`, where a `Result` is unwrapped inside a function that returns
//! `Result`. Containing that with `catch_unwind` worked but left three problems:
//! it does nothing under `panic = "abort"`, it turns a flood of malformed
//! requests into log noise, and it made the fuzz target unable to cover the path
//! at all.
//!
//! Scope is deliberately narrow. Decoding only, since nothing here encodes. The
//! dynamic table is implemented because a single header block may reference
//! entries it added earlier in the same block.

pub mod decoder;
pub mod encode;
pub mod huffman;
pub mod integer;
pub mod table;
mod table_huffman;
mod table_static;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HpackError {
    #[error("input ended mid-representation")]
    Truncated,
    #[error("integer is malformed or too large")]
    BadInteger,
    #[error("huffman string is malformed")]
    BadHuffman,
    #[error("header index {0} is not in the static or dynamic table")]
    BadIndex(u64),
}
