//! `collector-route` — the `route` collector: the first **Event**-cadence
//! collector, driven by a persistent PF_ROUTE socket (opened by the `macos`
//! crate), emitting [`types::RouteEvent`]s.
//!
//! Holds static [`META`] and the [`RouteCollector`], which owns a
//! `Box<dyn collector_core::EventSource>` and hands it to the daemon via
//! `into_event_source()`. Its [`collector_core::Readiness`] is decided at
//! construction (the `macos` adapter tries to open the PF_ROUTE socket).

pub mod collector;

pub use collector::{META, RouteCollector};
