//! Static [`META`] and the [`ConnectionsCollector`] that wires the proxy's
//! live flow list into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::Sample;

use crate::facts::{ConnectionFacts, OwnListeners};
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
        // Await the API and the config's listeners, then compose the sample
        // with the sync `build_*`. An unanswered API is folded into a SKIP
        // sample by the fold itself.
        let connections = self.facts.connections().await;
        let listeners = self.facts.own_listeners().await;
        vec![Sample::Connections(build_connections_sample(
            ts_us,
            connections,
            &listeners,
        ))]
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        // A SKIP has no rows to classify, so no listeners are read.
        vec![Sample::Connections(build_connections_sample(
            ts_us,
            None,
            &OwnListeners::default(),
        ))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{ConnectionScope, ConnectionsVerdict, LiveConnection};

    struct FakeApi {
        answer: Option<Vec<LiveConnection>>,
    }
    impl ConnectionFacts for FakeApi {
        async fn connections(&self) -> Option<Vec<LiveConnection>> {
            self.answer.clone()
        }
        async fn own_listeners(&self) -> OwnListeners {
            OwnListeners {
                tun_addr: Some("172.19.0.1".into()),
                dns_pin: Some("192.0.2.53".into()),
                tun_if: Some("utun10".into()),
                direct_if: Some("en0".into()),
                direct_tags: vec!["direct-egress".into()],
                block_tags: vec!["reject-ads".into()],
            }
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

    /// The tick's rows are classified against the listeners the port read:
    /// a flow to the TUN address lands `internal`, one to the world
    /// `external`.
    #[tokio::test]
    async fn the_ticks_rows_are_scoped_against_the_ports_listeners() {
        let mut dns = flow("");
        dns.host = None;
        dns.dst_ip = Some("172.19.0.1".into());
        dns.dst_port = Some(53);
        let mut world = flow("claude.ai");
        world.dst_ip = Some("149.154.167.41".into());
        let c = collector(Some(vec![dns, world]));
        let samples = c.collect(42).await;
        let [Sample::Connections(s)] = samples.as_slice() else {
            panic!("expected one connections sample, got {samples:?}");
        };
        let scopes: Vec<ConnectionScope> = s.rows.iter().map(|r| r.scope).collect();
        assert_eq!(
            scopes,
            vec![ConnectionScope::Internal, ConnectionScope::External]
        );
    }

    /// The tick's rows are stamped with the interface derived from the
    /// port's listeners: a tunneled flow gets the TUN interface, a
    /// direct-tagged one the physical egress, a block-tagged one `blocked`
    /// (realm net-observer, node #75) — this collector never touches the
    /// derivation itself, only wires the port's facts into the fold.
    #[tokio::test]
    async fn the_ticks_rows_are_stamped_with_the_iface_derived_from_the_ports_listeners() {
        let mut direct = flow("printer.local");
        direct.chain = Some("direct-egress".into());
        let mut blocked = flow("ads.example");
        blocked.chain = Some("reject-ads".into());
        let c = collector(Some(vec![flow("claude.ai"), direct, blocked]));
        let samples = c.collect(42).await;
        let [Sample::Connections(s)] = samples.as_slice() else {
            panic!("expected one connections sample, got {samples:?}");
        };
        let ifaces: Vec<Option<String>> = s.rows.iter().map(|r| r.iface.clone()).collect();
        assert_eq!(
            ifaces,
            vec![
                Some("utun10".to_string()),
                Some("en0".to_string()),
                Some("blocked".to_string()),
            ]
        );
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
