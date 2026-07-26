//! The [`Collector`] abstraction: one trait every collector implements, plus its
//! cadence ([`Source`]) and, for event-driven collectors, the blocking
//! [`EventSource`] it hands off. `collector-core` stays runtime-agnostic (no
//! tokio) — the async driving of both cadences lives in `observerd`.

use std::time::Duration;

use types::Sample;

use crate::meta::{CollectorMeta, Readiness};

/// How a collector produces samples — not everything is a timer.
pub enum Source {
    /// Poll on a timer: link, proxy, and the future dns/host.
    Interval(Duration),
    /// Driven by an OS event stream: route-events (PF_ROUTE), ...
    Event,
}

/// A blocking system-event source. `next()` blocks until the next event and
/// returns its sample(s); `None` ends the stream. A blocking read on a PF_ROUTE
/// socket maps onto this directly; the daemon runs it on the blocking pool.
pub trait EventSource: Send {
    fn next(&mut self) -> Option<Vec<Sample>>;
}

/// One collector subsystem. Interval collectors implement `collect()`/`skip()`;
/// event collectors leave those defaults and override `into_event_source()`.
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait Collector: Send + Sync {
    /// Static metadata: name + supported OSes.
    fn meta(&self) -> &'static CollectorMeta;
    /// The cadence the daemon should drive this collector on.
    fn source(&self) -> Source;
    /// Runtime capability probe: deps present? perms? interface exists?
    async fn preflight(&self) -> Readiness;
    /// One interval tick: `await`s the probes, then a sync `build_*` composes the samples.
    async fn collect(&self, _ts_us: i64) -> Vec<Sample> {
        Vec::new()
    }
    /// SKIP samples emitted when a probe fails (absence of a signal is diagnostic).
    fn skip(&self, _ts_us: i64) -> Vec<Sample> {
        Vec::new()
    }
    /// For event collectors: hand off the blocking source the daemon drives.
    fn into_event_source(self: Box<Self>) -> Option<Box<dyn EventSource>> {
        None
    }
}
