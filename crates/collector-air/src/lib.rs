//! `collector-air` — the `air` collector: the radio environment, i.e. the
//! foreign access points this machine can hear, mapped into a [`types::AirSample`].
//!
//! The `wifi` collector says how our own association is doing. This one says
//! what else is in the air around it — which is what turns "the link is
//! associated and the signal is fine but nothing moves" from a mystery into a
//! band that three neighbours are also sitting on.
//!
//! Two things it is NOT, and both are load-bearing (realm net-observer, nodes
//! #47 and #48):
//!
//! * It **never transmits**. There are no probe requests of our own here — the
//!   collector reads the system's own wireless report and nothing else.
//! * It **never claims measured interference**. No channel-occupancy figure is
//!   available on this platform, so the overlap with our own channel is offered
//!   as a hypothesis (`types::ChannelOverlapHypothesis`), computed by the reader.
//!
//! Its period is its own, and slow: the report costs seconds, so it is not
//! driven at the daemon's tick.
//!
//! Holds the [`AirFacts`] port trait (implemented by the `macos` crate over
//! `system_profiler`), the pure [`build_air_sample`] mapping, static [`META`],
//! and the [`AirCollector`] that plugs into `collector_core::Collector`.

pub mod collector;
pub mod facts;
pub mod sample;

pub use collector::{AirCollector, META};
pub use facts::{AirFacts, AirRead};
pub use sample::build_air_sample;
