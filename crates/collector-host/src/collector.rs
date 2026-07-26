//! Static [`META`] and the [`HostCollector`] that wires the `host` load facts
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::Sample;

use crate::facts::HostFacts;
use crate::sample::build_host_sample;

/// Static metadata for the `host` collector: load averages exist on macOS and
/// Linux, so both are declared supported.
pub const META: CollectorMeta = CollectorMeta {
    name: "host",
    supported_os: &[Os::MacOs, Os::Linux],
};

/// The `host` collector: 1/5/15-minute host load averages, polled on a fixed
/// interval. The starvation discriminator (`load` in the tens while `tun=000`).
///
/// Generic over its [`HostFacts`] port for static dispatch — native `async fn`
/// in the port trait rules out `dyn`, and the daemon enumerates the concrete
/// collectors in its `AnyCollector` enum (no boxing, no macros).
pub struct HostCollector<F: HostFacts> {
    facts: Arc<F>,
    interval: Duration,
}

impl<F: HostFacts> HostCollector<F> {
    /// Construct a `host` collector from its load-facts port and poll interval.
    pub fn new(facts: Arc<F>, interval: Duration) -> Self {
        Self { facts, interval }
    }
}

impl<F: HostFacts> Collector for HostCollector<F> {
    fn meta(&self) -> &'static CollectorMeta {
        &META
    }

    fn source(&self) -> Source {
        Source::Interval(self.interval)
    }

    async fn preflight(&self) -> Readiness {
        self.facts.preflight().await
    }

    async fn collect(&self, ts_us: i64) -> Vec<Sample> {
        // Await the one probe, then compose the sample with the sync `build_*`.
        let load = self.facts.loadavg().await;
        match build_host_sample(ts_us, load) {
            Some(s) => vec![Sample::Host(s)],
            None => self.skip(ts_us),
        }
    }

    fn skip(&self, _ts_us: i64) -> Vec<Sample> {
        // A `HostSample` carries only load numbers — there is no SKIP verdict to
        // record — so an unreadable loadavg is recorded as the absence of a row.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeHost(Option<(f64, f64, f64)>);
    impl HostFacts for FakeHost {
        async fn loadavg(&self) -> Option<(f64, f64, f64)> {
            self.0
        }
        async fn preflight(&self) -> Readiness {
            if self.0.is_some() {
                Readiness::Ready
            } else {
                Readiness::Unavailable("loadavg unreadable".into())
            }
        }
    }

    fn collector(load: Option<(f64, f64, f64)>) -> HostCollector<FakeHost> {
        HostCollector::new(Arc::new(FakeHost(load)), Duration::from_secs(15))
    }

    #[tokio::test]
    async fn unavailable_preflight_is_not_ready() {
        assert!(!collector(None).preflight().await.is_ready());
    }

    #[tokio::test]
    async fn ready_preflight_collects_one_host_sample() {
        let c = collector(Some((1.0, 2.0, 3.0)));
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Host(_)));
    }

    #[tokio::test]
    async fn unreadable_loadavg_collects_a_skip() {
        let c = collector(None);
        assert!(c.collect(42).await.is_empty());
    }
}
