//! The two extensions BoringSSL does not expose through a plain builder call.
//!
//! Everything else in a Chrome ClientHello comes from one method. These two do
//! not, and each needed a different kind of work. Kept here rather than scattered,
//! so the crate's only unsafe block has exactly one home.

use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration};
use foreign_types::ForeignTypeRef;

/// Advertises certificate compression without implementing it.
///
/// **This advertises brotli and cannot actually decompress.** A client only needs
/// to *offer* the algorithm for the extension to appear in its ClientHello, which
/// is what a fingerprint is made of, and the verification probe never sends a
/// compressed certificate.
///
/// The limitation is real and worth stating plainly. `decompress` returns an
/// error, so against a live server that actually chooses to compress its
/// certificate chain, the connection fails. Wiring a real brotli implementation is
/// a small follow-up that would remove the caveat entirely.
///
/// Advertising an algorithm one cannot honour is acceptable for reproducing a
/// fingerprint and is not acceptable for a general-purpose client. Anyone using
/// this crate to talk to real servers rather than to verify a profile should
/// implement the trait properly.
#[derive(Debug, Default)]
pub struct AdvertiseOnlyBrotli;

impl CertificateCompressor for AdvertiseOnlyBrotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    // A client offers the algorithm and would only ever *decompress*, since the
    // server is the side that compresses its certificate chain. `boring` asserts
    // at compile time that at least one direction is supported, which is a fair
    // guard: an algorithm that can do neither has no business being registered.
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, _input: &[u8], _output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        Err(std::io::Error::other(
            "fpd advertises certificate compression but does not implement it",
        ))
    }

    fn decompress<W>(&self, _input: &[u8], _output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        Err(std::io::Error::other(
            "fpd advertises certificate compression but does not implement it",
        ))
    }
}

/// Enables ALPS for one protocol.
///
/// `boring` 4.22.0 ships no safe wrapper, though BoringSSL supports it and the
/// symbol is present in the generated bindings. This is the only unsafe block in
/// the crate.
///
/// Safety: `cfg` owns a live `SSL` for the duration of the call, and the slices
/// outlive it because BoringSSL copies them rather than retaining the pointers.
pub fn enable_alps(cfg: &mut ConnectConfiguration, proto: &[u8]) -> Result<(), &'static str> {
    let settings: &[u8] = &[];
    let rc = unsafe {
        boring_sys::SSL_add_application_settings(
            cfg.as_ptr(),
            proto.as_ptr(),
            proto.len(),
            settings.as_ptr(),
            settings.len(),
        )
    };
    if rc == 1 {
        Ok(())
    } else {
        Err("SSL_add_application_settings failed")
    }
}
