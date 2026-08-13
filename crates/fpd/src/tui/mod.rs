//! `fpd tui`, a live view of connections showing which bytes produced each
//! fingerprint.
//!
//! One ink. The entire interface is the terminal's default foreground, with
//! hierarchy from weight and inversion rather than colour. No hue is assigned to
//! anything, so there is no palette to clash with a user's theme, nothing to lose
//! under `NO_COLOR`, and nothing that colour vision deficiency affects.

pub mod app;
pub mod render;
pub mod source;
pub mod theme;
