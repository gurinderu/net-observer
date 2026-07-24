//! `collector-core` — abstractions only: the [`Collector`] trait, generic probe
//! ports ([`Pinger`]/[`TcpProber`]), static OS metadata ([`CollectorMeta`]/[`Os`]),
//! and the runtime [`Readiness`] preflight verdict. No concrete collectors live
//! here — each collector is its own crate depending on this one.

pub mod collector;
pub mod meta;
pub mod probes;

pub use collector::{Collector, EventSource, Source};
pub use meta::{CollectorMeta, Os, Readiness};
pub use probes::{PingOutcome, Pinger, TcpProber};
