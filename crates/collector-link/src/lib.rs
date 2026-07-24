//! `collector-link` — the `link` collector: gateway ping, iface-bound direct TCP,
//! and OS link facts (DHCP lease, ARP, Wi-Fi) mapped into a [`types::LinkSample`].
//!
//! Holds the [`LinkFacts`] port trait (implemented by the `macos` crate), the pure
//! [`build_link_sample`] mapping, static [`META`], and the [`LinkCollector`] that
//! plugs into `collector_core::Collector` for the daemon.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{LinkCollector, META};
pub use facts::LinkFacts;
pub use sample::build_link_sample;
