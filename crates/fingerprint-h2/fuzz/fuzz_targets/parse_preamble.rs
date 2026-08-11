#![no_main]

//! Fuzzes the frame-layer parsing that this crate owns: connection preface,
//! frame headers, SETTINGS, WINDOW_UPDATE and PRIORITY.
//!
//! HPACK is deliberately NOT exercised here. `fluke-hpack` 0.3.1 panics on
//! adversarial input (see `headers::decode_fragment`), and `headers` contains
//! that panic with `catch_unwind`. cargo-fuzz compiles with `panic = "abort"`,
//! where `catch_unwind` cannot function, so fuzzing through HPACK would only
//! rediscover the upstream bug in a configuration that is never shipped.
//!
//! HPACK is covered instead by `tests/properties.rs`, which runs under unwind and
//! asserts the containment holds, plus the pinned regression test
//! `the_upstream_hpack_size_update_panic_stays_contained`.
//!
//! This split is a workaround for a dependency defect, not a permanent design.
//! Replacing or patching the HPACK decoder removes the need for it and lets this
//! target cover the whole path.

use fingerprint_h2::{frame, settings};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(frames) = frame::parse_preamble(data) {
        let _ = settings::settings_pairs(&frames);
        let _ = settings::window_update(&frames);
        let _ = settings::priorities(&frames);
    }
});
