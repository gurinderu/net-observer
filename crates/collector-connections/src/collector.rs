//! Static [`META`] and the [`ConnectionsCollector`] that wires the proxy's
//! live flow list into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::Sample;

use crate::facts::ConnectionFacts;
use crate::sample::build_connections_sample;

/// Static metadata for the `connections` collector. The flow list comes from
/// sing-box's Clash API, which this deployment runs on macOS only.
pub const META: CollectorMeta = CollectorMeta {
    name: "connections",
    supported_os: &[Os::MacOs],
};

/// The `connections` collector: the proxy's live flow table, polled on a fixed
/// interval and folded per destination.
///
/// Passive by construction: it reads a local HTTP API on the loopback and puts
/// nothing on the wire of its own accord, so it is not an
/// `types::EmissionClass` and takes no `ProbingState` — like `host`, `wifi`
/// and `neighbors` it keeps reading in the passive tier, which never reaches
/// it (realm net-observer, node #88).
///
/// Generic over its [`ConnectionFacts`] port for static dispatch — native
/// `async fn` in the port trait rules out `dyn`, and the daemon enumerates the
/// concrete collectors in its `AnyCollector` enum (no boxing, no macros).
pub struct ConnectionsCollector<F: ConnectionFacts> {
    facts: Arc<F>,
    interval: Duration,
}

impl<F: ConnectionFacts> ConnectionsCollector<F> {
    /// Construct a `connections` collector from its port and poll interval.
    pub fn new(facts: Arc<F>, interval: Duration) -> Self {
        Self { facts, interval }
    }
}

impl<F: ConnectionFacts> Collector for ConnectionsCollector<F> {
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
        // Await the API, then compose the sample with the sync `build_*`. An
        // unanswered API is folded into a SKIP sample by the fold itself.
        let connections = self.facts.connections().await;
        vec![Sample::Connections(build_connections_sample(
            ts_us,
            connections,
        ))]
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Connections(build_connections_sample(ts_us, None))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{ConnectionsVerdict, LiveConnection};

    struct FakeApi {
        answer: Option<Vec<LiveConnection>>,
    }
    impl ConnectionFacts for FakeApi {
        async fn connections(&self) -> Option<Vec<LiveConnection>> {
            self.answer.clone()
        }
        async fn preflight(&self) -> Readiness {
            Readiness::Ready
        }
    }

    fn collector(answer: Option<Vec<LiveConnection>>) -> ConnectionsCollector<FakeApi> {
        ConnectionsCollector::new(Arc::new(FakeApi { answer }), Duration::from_secs(15))
    }

    fn flow(host: &str) -> LiveConnection {
        LiveConnection {
            host: Some(host.into()),
            dst_ip: None,
            dst_port: Some(443),
            process: None,
            network: "tcp".into(),
            chain: Some("vless-out-6".into()),
            upload: 1,
            download: 1,
        }
    }

    #[tokio::test]
    async fn an_answered_api_collects_one_ok_sample_with_the_flows() {
        let c = collector(Some(vec![flow("claude.ai"), flow("claude.ai")]));
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        let [Sample::Connections(s)] = samples.as_slice() else {
            panic!("expected one connections sample, got {samples:?}");
        };
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.verdict, ConnectionsVerdict::Ok);
        assert_eq!(s.rows.len(), 1);
        assert_eq!(s.rows[0].count, 2);
    }

    /// SKIP, never silence: an API that did not answer still leaves a sample
    /// on the tick, saying so.
    #[tokio::test]
    async fn an_unanswered_api_collects_a_skip_sample() {
        let c = collector(None);
        let samples = c.collect(42).await;
        let [Sample::Connections(s)] = samples.as_slice() else {
            panic!("expected one connections sample, got {samples:?}");
        };
        assert_eq!(s.verdict, ConnectionsVerdict::Skip);
        assert!(s.rows.is_empty());
    }

    #[tokio::test]
    async fn a_failed_preflight_tick_skips_with_a_sample() {
        let c = collector(None);
        let samples = c.skip(7);
        let [Sample::Connections(s)] = samples.as_slice() else {
            panic!("expected one connections sample, got {samples:?}");
        };
        assert_eq!(s.ts_us, 7);
        assert_eq!(s.verdict, ConnectionsVerdict::Skip);
    }
}
