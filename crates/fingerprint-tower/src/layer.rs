//! The tower layer that puts the fingerprint into request extensions.
//!
//! The fingerprint is **per connection, not per request**. HTTP/2 multiplexes many
//! requests over one connection and they all share the client that opened it,
//! which is correct: a fingerprint describes the client, not the request. A reader
//! expecting per-request values will be surprised, so the docs say so plainly.

use std::task::{Context, Poll};

use tower::{Layer, Service};

use crate::acceptor::ClientFingerprint;

#[derive(Clone)]
pub struct FingerprintLayer {
    fingerprint: ClientFingerprint,
}

impl FingerprintLayer {
    pub fn new(fingerprint: ClientFingerprint) -> Self {
        Self { fingerprint }
    }
}

impl<S> Layer<S> for FingerprintLayer {
    type Service = FingerprintService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        FingerprintService {
            inner,
            fingerprint: self.fingerprint.clone(),
        }
    }
}

#[derive(Clone)]
pub struct FingerprintService<S> {
    inner: S,
    fingerprint: ClientFingerprint,
}

impl<S, B> Service<http::Request<B>> for FingerprintService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.fingerprint.clone());
        self.inner.call(req)
    }
}
