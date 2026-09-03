//! The process-wide rustls crypto provider.
//!
//! `reqwest` is built against a rustls with no provider compiled in, so one has
//! to be installed before the first TLS client is constructed. Which provider,
//! and why not `ring` or a system TLS: (realm net-observer, node #46).

use std::sync::Once;

static INSTALL: Once = Once::new();

/// Install the crypto provider as the process default, once.
///
/// Idempotent and safe to call from every client constructor: `Once` collapses
/// the repeats, and an install that lost the race to another provider is
/// ignored rather than fatal — the client that follows would fail loudly on its
/// first handshake, which is the observable we want, not a panic at startup.
pub fn install_default_provider() {
    INSTALL.call_once(|| {
        let _ = rustls_graviola::default_provider().install_default();
    });
}
