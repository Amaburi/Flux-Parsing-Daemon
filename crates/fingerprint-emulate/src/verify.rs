//! The verification loop.
//!
//! Binds the capture probe in process, drives the emulated client at it, and
//! diffs what arrived against the profile the client was built from. No external
//! network, so this runs in CI and on a laptop with no connectivity.
//!
//! This is the property no other tool in the category has. `curl-impersonate`,
//! `uTLS` and `rquest` all emit browser-shaped handshakes and ask you to believe
//! they still work. Holding the parser, the profile and the emitter in one place
//! turns that belief into a test.

use std::time::Duration;

use fingerprint_probe::diff::{diff, Diff};
use fingerprint_probe::probe::Probe;
use fingerprint_probe::profile::Profile;

use crate::build::{build, configure};
use crate::EmulateError;

/// Builds a client from `profile`, connects it to a local probe, and reports how
/// the captured handshake compares to the profile it came from.
///
/// The comparison uses the profile's own equivalence class. Chrome permutes its
/// extension order and rotates GREASE values, so byte equality would fail against
/// the real browser too. See `fingerprint_probe::diff`.
///
/// Covers both layers. The emulated client completes the handshake and then
/// writes an HTTP/2 preamble built from the same profile, so SETTINGS order,
/// WINDOW_UPDATE and pseudo-header order are compared alongside the TLS fields.
pub async fn verify(profile: &Profile) -> Result<Diff, EmulateError> {
    let probe = Probe::bind()
        .await
        .map_err(|e| EmulateError::Tls(e.to_string()))?;
    let port = probe.port();

    let connector = build(profile)?;
    let cfg = configure(&connector, profile, "localhost")?;

    // Built before the client task so a bad profile fails here rather than inside
    // a spawned task where the error would be lost.
    let preamble = crate::h2::preamble_for(profile, "localhost").unwrap_or_default();

    // The client runs on a separate task so the probe can accept it.
    let client = tokio::spawn(async move {
        let Ok(tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await else {
            return;
        };
        let Ok(mut tls) = tokio_boring::connect(cfg, "localhost", tcp).await else {
            return;
        };
        // The probe reads the preamble and never replies, so a write error here
        // means the probe already has what it needs.
        use tokio::io::AsyncWriteExt;
        let _ = tls.write_all(&preamble).await;
        let _ = tls.flush().await;
    });

    let report = probe
        .accept_one(Duration::from_secs(10))
        .await
        .map_err(|_| EmulateError::NoCapture)?;

    client.abort();

    Ok(diff(&report, profile))
}
