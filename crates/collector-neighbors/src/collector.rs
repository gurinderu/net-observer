//! Static [`META`] and the [`NeighborsCollector`] that wires the neighbour-cache
//! reading into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use oui_db::OuiDb;
use types::Sample;

use crate::facts::NeighborFacts;
use crate::role::assign_passive_roles;
use crate::sample::build_neighbors_sample;

/// Static metadata for the `neighbors` collector. Only macOS is declared: the
/// adapter reads `arp -an`/`ndp -an`, whose output format is BSD's.
pub const META: CollectorMeta = CollectorMeta {
    name: "neighbors",
    supported_os: &[Os::MacOs],
};

/// The `neighbors` collector: the ARP and NDP caches, polled on a fixed interval.
///
/// Answers a question no other collector does — is the *segment* alive while I am
/// not? A cache that keeps filling while L3 goes nowhere puts the fault at the
/// gateway or the uplink rather than at this machine's radio.
///
/// Generic over its [`NeighborFacts`] port for static dispatch, like the others.
pub struct NeighborsCollector<F: NeighborFacts> {
    facts: Arc<F>,
    interval: Duration,
    /// The OUI registry used to hypothesise each neighbour's ROLE, loaded once at
    /// startup and shared. `None` when no snapshot is provisioned — roles then
    /// degrade to gateway/unknown only, never a guessed vendor. (node #36)
    oui: Option<Arc<OuiDb>>,
}

impl<F: NeighborFacts> NeighborsCollector<F> {
    /// Construct from the neighbour-facts port, the poll interval, and the shared
    /// OUI registry (`None` when no snapshot is provisioned).
    pub fn new(facts: Arc<F>, interval: Duration, oui: Option<Arc<OuiDb>>) -> Self {
        Self {
            facts,
            interval,
            oui,
        }
    }
}

impl<F: NeighborFacts> Collector for NeighborsCollector<F> {
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
        let reading = self.facts.read().await;
        let mut sample = build_neighbors_sample(ts_us, reading);
        // Passive ROLE hypothesis: gateway by key, vendor by OUI, no ports.
        assign_passive_roles(&mut sample, self.oui.as_deref());
        vec![Sample::Neighbors(sample)]
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Neighbors(build_neighbors_sample(ts_us, None))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::NeighborReading;
    use types::{NeighborObs, NeighborRole, NeighborSource, NeighborsVerdict};

    struct FakeFacts(Option<NeighborReading>);
    impl NeighborFacts for FakeFacts {
        async fn read(&self) -> Option<NeighborReading> {
            self.0.clone()
        }
        async fn preflight(&self) -> Readiness {
            if self.0.is_some() {
                Readiness::Ready
            } else {
                Readiness::Unavailable("no neighbour cache".into())
            }
        }
    }

    fn collector(reading: Option<NeighborReading>) -> NeighborsCollector<FakeFacts> {
        NeighborsCollector::new(Arc::new(FakeFacts(reading)), Duration::from_secs(60), None)
    }

    #[tokio::test]
    async fn a_reading_collects_one_ok_sample() {
        let c = collector(Some(NeighborReading {
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            neighbors: vec![NeighborObs {
                mac: "11:22:33:44:55:66".into(),
                ip: "192.168.1.5".into(),
                source: NeighborSource::Arp,
                hostname: None,
                role: NeighborRole::Unknown,
            }],
        }));
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        assert_eq!(samples.len(), 1);
        let Sample::Neighbors(n) = &samples[0] else {
            panic!("expected a neighbors sample");
        };
        assert_eq!(n.verdict, NeighborsVerdict::Ok);
    }

    /// The SKIP rule: an unreadable cache still emits a row every tick.
    #[tokio::test]
    async fn an_unreadable_cache_still_emits_a_skip_row() {
        for samples in [collector(None).collect(42).await, collector(None).skip(42)] {
            let Sample::Neighbors(n) = &samples[0] else {
                panic!("expected a neighbors sample");
            };
            assert_eq!(n.verdict, NeighborsVerdict::Skip);
        }
    }
}
