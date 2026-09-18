//! `collector-connections` — the `connections` collector: what this machine
//! talks to, read each tick from the proxy's Clash API (`GET /connections`)
//! and folded into a per-destination aggregate [`types::ConnectionsSample`]
//! (realm net-observer, nodes #75, #127).
//!
//! Holds the [`ConnectionFacts`] port trait (implemented by the `macos` crate)
//! with the [`OwnListeners`] it reads from sing-box's rendered config, the pure
//! [`build_connections_sample`] fold — which judges each row's
//! [`types::ConnectionScope`] against those listeners — static [`META`], and
//! the [`ConnectionsCollector`] that plugs into `collector_core::Collector` for
//! the daemon.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{ConnectionsCollector, META};
pub use facts::{ConnectionFacts, OwnListeners};
pub use sample::build_connections_sample;
