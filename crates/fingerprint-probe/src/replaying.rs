//! Hands already-consumed bytes back to a reader.
//!
//! `serve` must read the HTTP/2 preamble itself to fingerprint it, then let hyper
//! drive the same connection. hyper expects to read the preface from the start,
//! so the consumed bytes are replayed before the live socket is exposed.
//!
//! The M0 S2 spike proved this works: curl received `HTTP/2 200` from a
//! connection whose preface, SETTINGS, WINDOW_UPDATE and HEADERS had already been
//! read by hand. This is that adapter promoted out of spike code, with a bound
//! added.

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct Replaying<S> {
    buf: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Replaying<S> {
    pub fn new(buf: Vec<u8>, inner: S) -> Self {
        Self { buf, pos: 0, inner }
    }

    /// True while buffered bytes remain.
    pub fn replaying(&self) -> bool {
        self.pos < self.buf.len()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replaying<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.buf.len() {
            let take = std::cmp::min(out.remaining(), self.buf.len() - self.pos);
            let start = self.pos;
            let chunk = self
                .buf
                .get(start..start + take)
                .unwrap_or_default()
                .to_vec();
            out.put_slice(&chunk);
            self.pos += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replaying<S> {
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

    #[tokio::test]
    async fn buffered_bytes_are_delivered_before_the_live_stream() {
        let inner = tokio_test::io::Builder::new().read(b"LIVE").build();
        let mut r = Replaying::new(b"REPLAY".to_vec(), inner);

        let mut out = Vec::new();
        r.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"REPLAYLIVE");
    }

    #[tokio::test]
    async fn an_empty_buffer_passes_straight_through() {
        let inner = tokio_test::io::Builder::new().read(b"LIVE").build();
        let mut r = Replaying::new(Vec::new(), inner);
        assert!(!r.replaying());

        let mut out = Vec::new();
        r.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"LIVE");
    }

    /// A reader taking one byte at a time must still see the boundary correctly.
    /// Getting this wrong duplicates or drops a byte exactly at the handover,
    /// which would corrupt the h2 preface in a way that is painful to debug.
    #[tokio::test]
    async fn a_byte_at_a_time_reader_sees_the_boundary_correctly() {
        let inner = tokio_test::io::Builder::new().read(b"XY").build();
        let mut r = Replaying::new(b"AB".to_vec(), inner);

        let mut seen = Vec::new();
        let mut one = [0u8; 1];
        while let Ok(n) = r.read(&mut one).await {
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&one[..n]);
        }
        assert_eq!(seen, b"ABXY");
    }

    #[tokio::test]
    async fn replaying_reports_false_once_the_buffer_is_drained() {
        let inner = tokio_test::io::Builder::new().read(b"").build();
        let mut r = Replaying::new(b"AB".to_vec(), inner);
        assert!(r.replaying());

        let mut two = [0u8; 2];
        let _ = r.read(&mut two).await;
        assert!(!r.replaying());
    }
}
