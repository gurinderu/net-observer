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
        // Await the probes, then compose the sample with the sync `build_*`.
        let load = self.facts.loadavg().await;
        let disk = self.facts.disk().await;
        let swap = self.facts.swap().await;
        match build_host_sample(ts_us, load, disk, swap) {
            Some(s) => vec![Sample::Host(s)],
            None => self.skip(ts_us),
        }
    }

    fn skip(&self, _ts_us: i64) -> Vec<Sample> {
        // A `HostSample` carries only numbers — there is no SKIP verdict to
        // record — so an unreadable loadavg is recorded as the absence of a row.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeHost {
        load: Option<(f64, f64, f64)>,
        disk: Option<(f64, u64)>,
        swap: Option<u64>,
    }
    impl HostFacts for FakeHost {
        async fn loadavg(&self) -> Option<(f64, f64, f64)> {
            self.load
        }
        async fn disk(&self) -> Option<(f64, u64)> {
            self.disk
        }
        async fn swap(&self) -> Option<u64> {
            self.swap
        }
        async fn preflight(&self) -> Readiness {
            if self.load.is_some() {
                Readiness::Ready
            } else {
                Readiness::Unavailable("loadavg unreadable".into())
            }
        }
    }

    fn collector(load: Option<(f64, f64, f64)>) -> HostCollector<FakeHost> {
        collector_with(load, None, None)
    }

    fn collector_with(
        load: Option<(f64, f64, f64)>,
        disk: Option<(f64, u64)>,
        swap: Option<u64>,
    ) -> HostCollector<FakeHost> {
        HostCollector::new(
            Arc::new(FakeHost { load, disk, swap }),
            Duration::from_secs(15),
        )
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

    /// Disk and swap read from the port land in the tick's sample.
    #[tokio::test]
    async fn disk_and_swap_facts_land_in_the_sample() {
        let c = collector_with(Some((1.0, 2.0, 3.0)), Some((87.5, 61_440)), Some(1235));
        let samples = c.collect(42).await;
        let Some(Sample::Host(h)) = samples.first() else {
            panic!("expected one host sample, got {samples:?}");
        };
        assert_eq!(h.disk_used_pct, Some(87.5));
        assert_eq!(h.disk_free_mb, Some(61_440));
        assert_eq!(h.swap_used_mb, Some(1235));
    }

    /// An unreadable disk or swap does not cost the tick its row: the load
    /// still lands, and the unreadable facts are `None` — never a zero.
    #[tokio::test]
    async fn unreadable_disk_and_swap_leave_the_load_sample_with_none() {
        let c = collector_with(Some((1.0, 2.0, 3.0)), None, None);
        let samples = c.collect(42).await;
        let Some(Sample::Host(h)) = samples.first() else {
            panic!("expected one host sample, got {samples:?}");
        };
        assert_eq!(h.load1, 1.0);
        assert_eq!(h.disk_used_pct, None);
        assert_eq!(h.disk_free_mb, None);
        assert_eq!(h.swap_used_mb, None);
    }

    /// Disk and swap alone do not make a sample: the load average anchors the
    /// row, so without it the tick is a skip even when the others read.
    #[tokio::test]
    async fn disk_and_swap_without_load_still_collect_a_skip() {
        let c = collector_with(None, Some((87.5, 61_440)), Some(1235));
        assert!(!c.preflight().await.is_ready());
        assert!(c.collect(42).await.is_empty());
    }
}
