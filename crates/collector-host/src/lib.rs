//! `collector-host` — the `host` collector: host load / starvation signals
//! (1/5/15-min averages) mapped into [`types::HostSample`]s.
//!
//! Holds the [`HostFacts`] port trait (implemented by the `macos` crate), the pure
//! [`build_host_sample`] mapping, static [`META`], and the [`HostCollector`] that
//! plugs into `collector_core::Collector` for the daemon.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{HostCollector, META};
pub use facts::HostFacts;
pub use sample::build_host_sample;
