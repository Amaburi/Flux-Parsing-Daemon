//! The byte tee.
//!
//! Copies everything read from an inner stream into a shared buffer so the raw
//! handshake can be parsed independently of the TLS library that consumed it.
//! rustls does not expose extension order or GREASE placement, which is exactly
//! what a fingerprint needs, so the bytes have to be kept separately.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bytes captured beyond this are dropped. A ClientHello is a few kilobytes at
/// most, so nothing past the cap is ever useful, and an unbounded buffer under a
/// client that streams forever is memory exhaustion.
pub const DEFAULT_CAP: usize = 64 * 1024;

pub struct RecordingStream<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
    cap: usize,
}

impl<S> RecordingStream<S> {
    pub fn new(inner: S, seen: Arc<Mutex<Vec<u8>>>) -> Self {
        Self::with_cap(inner, seen, DEFAULT_CAP)
    }

    pub fn with_cap(inner: S, seen: Arc<Mutex<Vec<u8>>>, cap: usize) -> Self {
        Self { inner, seen, cap }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &res {
            let new = buf.filled().get(before..).unwrap_or_default();
            if !new.is_empty() {
                let cap = self.cap;
                if let Ok(mut g) = self.seen.lock() {
                    // Record up to the cap and then stop. The caller still receives
                    // every byte. Only our copy is bounded.
                    let room = cap.saturating_sub(g.len());
                    if room > 0 {
                        g.extend_from_slice(new.get(..room.min(new.len())).unwrap_or_default());
                    }
                }
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn buf() -> Arc<Mutex<Vec<u8>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[tokio::test]
    async fn records_every_byte_that_is_read() {
        let inner = tokio_test::io::Builder::new()
            .read(b"hello")
            .read(b" world")
            .build();
        let seen = buf();
        let mut s = RecordingStream::new(inner, Arc::clone(&seen));

        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read");

        assert_eq!(out, b"hello world");
        assert_eq!(seen.lock().expect("lock").as_slice(), b"hello world");
    }

    /// The difference between the M0 spike and production code. A client that
    /// streams forever must not grow our buffer without bound.
    #[tokio::test]
    async fn recording_is_capped_but_the_caller_still_sees_everything() {
        let big = vec![0x41u8; 100_000];
        let inner = tokio_test::io::Builder::new().read(&big).build();
        let seen = buf();
        let mut s = RecordingStream::with_cap(inner, Arc::clone(&seen), 4096);

        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read");

        assert_eq!(
            seen.lock().expect("lock").len(),
            4096,
            "capture stops at the cap"
        );
        assert_eq!(out.len(), big.len(), "but the caller is not truncated");
    }

    #[tokio::test]
    async fn a_cap_of_zero_records_nothing_and_still_reads() {
        let inner = tokio_test::io::Builder::new().read(b"abc").build();
        let seen = buf();
        let mut s = RecordingStream::with_cap(inner, Arc::clone(&seen), 0);

        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read");

        assert!(seen.lock().expect("lock").is_empty());
        assert_eq!(out, b"abc");
    }

    #[tokio::test]
    async fn a_read_that_returns_nothing_records_nothing() {
        let inner = tokio_test::io::Builder::new().read(b"").build();
        let seen = buf();
        let mut s = RecordingStream::new(inner, Arc::clone(&seen));

        let mut out = Vec::new();
        s.read_to_end(&mut out).await.expect("read");

        assert!(seen.lock().expect("lock").is_empty());
    }
}
