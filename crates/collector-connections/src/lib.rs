//! `collector-connections` — the `connections` collector: what this machine
//! talks to, read each tick from the proxy's Clash API (`GET /connections`)
//! and folded into a per-destination aggregate [`types::ConnectionsSample`]
//! (realm net-observer, nodes #75, #127).
//!
//! Holds the [`ConnectionFacts`] port trait (implemented by the `macos` crate),
//! the pure [`build_connections_sample`] fold, static [`META`], and the
//! [`ConnectionsCollector`] that plugs into `collector_core::Collector` for the
//! daemon.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{ConnectionsCollector, META};
pub use facts::ConnectionFacts;
pub use sample::build_connections_sample;
