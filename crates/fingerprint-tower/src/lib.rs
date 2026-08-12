#![deny(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

//! Fingerprinting inside a Rust application, with no separate process and no
//! extra network hop.
//!
//! `fpd serve` works with any language but costs a process and a localhost hop.
//! A Rust application needs neither. One line changes:
//!
//! ```no_run
//! # use std::sync::Arc;
//! # fn demo(config: Arc<rustls::ServerConfig>) {
//! // before
//! let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
//! // after
//! let acceptor = fingerprint_tower::Acceptor::new(config);
//! # }
//! ```
//!
//! Then, per connection:
//!
//! ```no_run
//! # use fingerprint_tower::{Acceptor, FingerprintLayer};
//! # use tower::{ServiceBuilder, service_fn};
//! # async fn demo(acceptor: Acceptor, tcp: tokio::net::TcpStream)
//! #     -> Result<(), Box<dyn std::error::Error>> {
//! # let app = service_fn(|_: http::Request<()>| async {
//! #     Ok::<_, std::convert::Infallible>(http::Response::new(()))
//! # });
//! let accepted = acceptor.accept(tcp).await?;
//! let svc = ServiceBuilder::new()
//!     .layer(FingerprintLayer::new(accepted.fingerprint))
//!     .service(app);
//! # Ok(())
//! # }
//! ```
//!
//! and the fingerprint is in every request:
//!
//! ```no_run
//! # use axum::Extension;
//! # use fingerprint_tower::ClientFingerprint;
//! async fn handler(Extension(fp): Extension<ClientFingerprint>) -> String {
//!     fp.ja4.clone()
//! }
//! ```
//!
//! Two things this deliberately does not do. It does not own the accept loop, so
//! connection limits and timeouts remain the caller's responsibility, unlike
//! `serve` which bounds them itself. And it is Rust only.

pub mod acceptor;
pub mod layer;

pub use acceptor::{AcceptError, Accepted, Acceptor, ClientFingerprint};
pub use layer::{FingerprintLayer, FingerprintService};
