//! `collector-neighbors` — the `neighbors` collector: who else is on the local
//! segment, read from the kernel's own ARP and NDP caches and mapped into a
//! [`types::NeighborsSample`].
//!
//! **Passive by construction.** This collector reads caches the OS already
//! filled; it addresses no packet at anybody, which is why it keeps running
//! under quiet mode exactly like the DHCP-lease and ARP reads the `link`
//! collector does. Filling those caches deliberately — a subnet sweep, an mDNS
//! query — is a separate, operator-pressed action and never happens on this
//! timer.
//!
//! Holds the [`NeighborFacts`] port trait (implemented by the `macos` crate), the
//! pure [`build_neighbors_sample`] mapping, static [`META`], and the
//! [`NeighborsCollector`] that plugs into `collector_core::Collector`.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{META, NeighborsCollector};
pub use facts::{NeighborFacts, NeighborReading};
pub use sample::build_neighbors_sample;
