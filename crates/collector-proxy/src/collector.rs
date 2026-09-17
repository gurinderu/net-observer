//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber`/`StallProbe` ports into the [`build_proxy_samples`]
//! mapping.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, ProbingState, Readiness, Source, TcpProber};
use types::{EmissionClass, ProxySample, Sample, TcpVerdict};

use crate::probes::{ProxyFacts, StallProbe, StallReading, UrlTest};
use crate::proxy::build_proxy_samples;

/// Static metadata for the proxy collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "proxy",
    supported_os: &[Os::MacOs],
};

/// Interval collector for per-upstream-server TCP reachability, the TUN 204
/// probe, the active upstream node selection, the established-flow
/// discriminator (held reference streams checked each tick), and sing-box's
/// own URL-test history per node of the selector group — read, never
/// triggered (realm net-observer, node #62).
///
/// Static dispatch over the [`TcpProber`], [`ProxyFacts`] and [`StallProbe`]
/// ports: native `async fn` in traits is not `dyn`-compatible, so the ports are
/// generic type parameters (the daemon monomorphizes them via
/// `enum AnyCollector`).
pub struct ProxyCollector<T: TcpProber, F: ProxyFacts, S: StallProbe> {
    tcp: T,
    facts: F,
    stall: S,
    tun_url: String,
    iface: String,
    interval: Duration,
    /// The probing tier, shared with the control socket. This is the most
    /// talkative collector — three emission classes — and in the passive tier
    /// every one is withheld: no 204 through the TUN, no connect to any
    /// endpoint, and the held reference streams are CLOSED rather than kept
    /// open and exercised. The local reads continue under every tier: the
    /// selector group and each member's URL-test history (loopback,
    /// sing-box's own API) and the node list (the rendered config) — the
    /// endpoints are not connected to under passive, but a node's reading
    /// still needs the endpoint it belongs to, so the tick lands as the
    /// `SKIP` placeholder row plus one reading row per member.
    /// (realm net-observer, node #88)
    probing: Arc<ProbingState>,
}

impl<T: TcpProber, F: ProxyFacts, S: StallProbe> ProxyCollector<T, F, S> {
    /// Construct a proxy collector from its ports, cadence and the shared
    /// probing tier (see [`ProxyCollector::probing`]).
    pub fn new(
        tcp: T,
        facts: F,
        stall: S,
        tun_url: String,
        iface: String,
        interval: Duration,
        probing: Arc<ProbingState>,
    ) -> Self {
        Self {
            tcp,
            facts,
            stall,
            tun_url,
            iface,
            interval,
            probing,
        }
    }
}

impl<T: TcpProber, F: ProxyFacts, S: StallProbe> Collector for ProxyCollector<T, F, S> {
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
        // Read the tier ONCE per tick, so the probes withheld and the verdicts
        // that report them cannot disagree.
        let tier = self.probing.tier();
        // Await the probes, then a sync `build_*` composes the samples. An
        // attempted probe always yields a code — the HTTP status, or `0` for
        // no status at all; `None` means it was not attempted (see `TunProbe`).
        let tun_code = if tier.emits(EmissionClass::TunProbe) {
            Some(self.facts.tun_probe(&self.tun_url).await.code())
        } else {
            None
        };
        // The local reads, under every tier: ONE group read serves both the
        // selection and the members, ONE config read both the endpoints to
        // probe and the row each node's reading rides.
        let group = self.facts.group().await.unwrap_or_default();
        let selector = group.now.clone();
        let nodes = self.facts.node_endpoints().await;
        // The held-stream check runs in the same tick as the fresh probes, so
        // "fresh OK while established dead" is one cohort, not a correlation.
        // Withheld, the streams are closed outright: a held stream is a per-tick
        // emission, and one kept open would be exercised on the next active
        // tick as if it had been measured all along. Its fields read `None` —
        // no measurement — until the streams are re-opened on the next active
        // tick.
        let stall = if tier.emits(EmissionClass::HeldStream) {
            self.stall.check().await
        } else {
            self.stall.close().await;
            StallReading::default()
        };
        // Withheld, no endpoint is connected to: the tick lands with the
        // single `SKIP` placeholder row (`tcp = SKIP`, no rtt) the mapping
        // produces for "nothing was probed", carrying the passive facts.
        // Probed, each DISTINCT endpoint is connected to once: nodes share
        // endpoints across outbounds, and one listener is probed once.
        let mut probed = Vec::new();
        if tier.emits(EmissionClass::EndpointProbe) {
            for (_, endpoint) in &nodes {
                if probed.iter().any(|(e, _)| e == endpoint) {
                    continue;
                }
                // Split at the LAST ':' so the host half keeps any earlier
                // colons; an endpoint that does not parse as "host:port" is
                // probed on 443.
                let (host, port) = match endpoint.rsplit_once(':') {
                    Some((host, port)) => match port.parse::<u16>() {
                        Ok(port) => (host, port),
                        Err(_) => (endpoint.as_str(), 443),
                    },
                    None => (endpoint.as_str(), 443),
                };
                let o = self.tcp.connect_bound(host, port, &self.iface).await;
                // The sample carries the full "host:port" string: the row must
                // name the listener that was probed, matching the oracle's
                // vless[ip:port].
                probed.push((endpoint.clone(), o));
            }
        }
        // sing-box's own URL tests, the selected node first so its reading
        // takes its endpoint's row before a sibling on the same endpoint can.
        let mut targets: Vec<String> = selector.iter().cloned().collect();
        for member in group.all {
            if !targets.contains(&member) {
                targets.push(member);
            }
        }
        let mut urltests = Vec::with_capacity(targets.len());
        for node in targets {
            let entry = self.facts.urltest(&node).await;
            let endpoint = nodes
                .iter()
                .find(|(n, _)| *n == node)
                .map(|(_, e)| e.clone());
            urltests.push(UrlTest {
                node,
                endpoint,
                entry,
            });
        }
        build_proxy_samples(ts_us, tun_code, selector, stall, probed, urltests)
            .into_iter()
            .map(Sample::Proxy)
            .collect()
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "-".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code: None,
            selector: None,
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{ProxyGroup, StallReading, StreamCheck, TunProbe, UrlTestEntry};
    use collector_core::PingOutcome;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::ProbingTier;

    /// A prober that counts the connects actually attempted.
    #[derive(Default)]
    struct T {
        sent: Arc<AtomicUsize>,
    }
    impl TcpProber for T {
        async fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            self.sent.fetch_add(1, Ordering::Release);
            PingOutcome {
                reachable: true,
                rtt_ms: Some(9.0),
            }
        }
    }

    /// Facts that count the TUN probes actually sent and answer them as
    /// scripted; the nodes the config names with their endpoints, the
    /// selector group, and each node's newest URL-test entry — with a count
    /// of every local read.
    struct Facts {
        readiness: Readiness,
        tun_probes: Arc<AtomicUsize>,
        tun_answer: TunProbe,
        /// `(node, endpoint)` as the config declares them.
        nodes: Vec<(String, String)>,
        group: Option<ProxyGroup>,
        /// Each node's newest history entry; a node absent here has none.
        history: Vec<(String, UrlTestEntry)>,
        config_reads: Arc<AtomicUsize>,
        group_reads: Arc<AtomicUsize>,
        urltest_reads: Arc<AtomicUsize>,
    }
    impl Facts {
        fn new(readiness: Readiness, tun_answer: TunProbe) -> Self {
            Self {
                readiness,
                tun_probes: Arc::default(),
                tun_answer,
                nodes: vec![("node-a".into(), "1.1.1.1:443".into())],
                group: Some(ProxyGroup {
                    now: Some("node-a".into()),
                    all: vec!["node-a".into()],
                }),
                history: vec![(
                    "node-a".into(),
                    UrlTestEntry {
                        at_us: 1_000,
                        ms: 202,
                    },
                )],
                config_reads: Arc::default(),
                group_reads: Arc::default(),
                urltest_reads: Arc::default(),
            }
        }
    }
    impl ProxyFacts for Facts {
        async fn node_endpoints(&self) -> Vec<(String, String)> {
            self.config_reads.fetch_add(1, Ordering::Release);
            self.nodes.clone()
        }
        async fn tun_probe(&self, _: &str) -> TunProbe {
            self.tun_probes.fetch_add(1, Ordering::Release);
            self.tun_answer
        }
        async fn group(&self) -> Option<ProxyGroup> {
            self.group_reads.fetch_add(1, Ordering::Release);
            self.group.clone()
        }
        async fn urltest(&self, node: &str) -> Option<UrlTestEntry> {
            self.urltest_reads.fetch_add(1, Ordering::Release);
            self.history
                .iter()
                .find(|(n, _)| n == node)
                .map(|(_, e)| *e)
        }
        async fn preflight(&self) -> Readiness {
            self.readiness.clone()
        }
    }

    /// A scripted stall probe: both held streams alive and 60s old, and a
    /// record of how often it was checked and how often closed.
    #[derive(Default)]
    struct FakeStall {
        checks: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
    }
    impl StallProbe for FakeStall {
        async fn check(&self) -> StallReading {
            self.checks.fetch_add(1, Ordering::Release);
            StallReading {
                direct: Some(StreamCheck {
                    alive: true,
                    age_s: 60,
                }),
                tun: Some(StreamCheck {
                    alive: true,
                    age_s: 60,
                }),
            }
        }
        async fn close(&self) {
            self.closes.fetch_add(1, Ordering::Release);
        }
    }

    fn collector_in(
        readiness: Readiness,
        tier: ProbingTier,
    ) -> (ProxyCollector<T, Facts, FakeStall>, Arc<ProbingState>) {
        collector_answering(readiness, tier, TunProbe::Status(204))
    }

    fn collector_answering(
        readiness: Readiness,
        tier: ProbingTier,
        tun_answer: TunProbe,
    ) -> (ProxyCollector<T, Facts, FakeStall>, Arc<ProbingState>) {
        collector_with(Facts::new(readiness, tun_answer), tier)
    }

    fn collector_with(
        facts: Facts,
        tier: ProbingTier,
    ) -> (ProxyCollector<T, Facts, FakeStall>, Arc<ProbingState>) {
        let probing = Arc::new(ProbingState::new(tier));
        let c = ProxyCollector::new(
            T::default(),
            facts,
            FakeStall::default(),
            "http://x/204".into(),
            "en0".into(),
            Duration::from_secs(15),
            probing.clone(),
        );
        (c, probing)
    }

    fn collector(readiness: Readiness) -> ProxyCollector<T, Facts, FakeStall> {
        collector_in(readiness, ProbingTier::Active).0
    }

    /// One proxy row's `(endpoint, tcp, node, ms, at_us)`.
    type Row = (String, TcpVerdict, Option<String>, Option<u32>, Option<i64>);

    fn rows(samples: &[Sample]) -> Vec<Row> {
        samples
            .iter()
            .map(|s| {
                let Sample::Proxy(p) = s else {
                    panic!("expected a proxy sample")
                };
                (
                    p.server_ip.clone(),
                    p.tcp,
                    p.urltest_node.clone(),
                    p.urltest_ms,
                    p.urltest_at_us,
                )
            })
            .collect()
    }

    /// The record's dead-tun shape: a probe that was ATTEMPTED and got no HTTP
    /// status lands as `tun_code = 0` (the shell oracle's curl `000`), the
    /// value `why`, `wedge-or-starvation` and the live `starvation` rule all
    /// read as dead — distinct from `None`, which only a probe never attempted
    /// (the passive tier, below) leaves behind.
    #[tokio::test]
    async fn a_probe_with_no_http_status_records_tun_code_zero() {
        let (c, _) = collector_answering(Readiness::Ready, ProbingTier::Active, TunProbe::NoStatus);
        let samples = c.collect(7).await;
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.tun_code, Some(0), "attempted, no status: 0, never NULL");
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 1);
        assert_eq!(TunProbe::Status(502).code(), 502);
        assert_eq!(TunProbe::NoStatus.code(), 0);
    }

    #[tokio::test]
    async fn preflight_unavailable_is_not_ready() {
        let c = collector(Readiness::Unavailable(
            "no upstream proxy facts available".into(),
        ));
        assert!(!c.preflight().await.is_ready());
    }

    #[tokio::test]
    async fn ready_collect_yields_one_proxy_sample() {
        let c = collector(Readiness::Ready);
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(7).await;
        assert_eq!(samples.len(), 1);
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        // The held-stream reading reaches the row.
        assert_eq!(p.est_tun_alive, Some(true));
        assert_eq!(p.est_direct_age_s, Some(60));
        assert_eq!(c.stall.closes.load(Ordering::Acquire), 0);
        // And so does sing-box's own test of the node the row belongs to.
        assert_eq!(p.urltest_node.as_deref(), Some("node-a"));
        assert_eq!(p.urltest_ms, Some(202));
        assert_eq!(p.urltest_at_us, Some(1_000));
    }

    /// Every member of the selector group is read each tick from ONE group
    /// read and ONE config read, the selected node first; each reading rides
    /// its node's endpoint row, a failed test as `0`, an untested node as no
    /// measurement, and the selected node's row lands last.
    #[tokio::test]
    async fn every_member_is_read_each_tick_from_one_group_and_one_config_read() {
        let facts = Facts {
            nodes: vec![
                ("node-a".into(), "1.1.1.1:443".into()),
                ("node-b".into(), "2.2.2.2:443".into()),
                ("node-c".into(), "3.3.3.3:443".into()),
            ],
            group: Some(ProxyGroup {
                now: Some("node-b".into()),
                all: vec!["node-a".into(), "node-b".into(), "node-c".into()],
            }),
            history: vec![
                (
                    "node-a".into(),
                    UrlTestEntry {
                        at_us: 1_000,
                        ms: 202,
                    },
                ),
                ("node-b".into(), UrlTestEntry { at_us: 900, ms: 0 }),
            ],
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        let (c, _) = collector_with(facts, ProbingTier::Active);
        for tick in 1..=2 {
            let got = rows(&c.collect(tick).await);
            assert_eq!(
                got.len(),
                3,
                "one row per endpoint, each with its node's reading"
            );
            let of = |ip: &str| got.iter().find(|r| r.0 == ip).unwrap().clone();
            assert_eq!(
                of("1.1.1.1:443"),
                (
                    "1.1.1.1:443".into(),
                    TcpVerdict::Ok,
                    Some("node-a".into()),
                    Some(202),
                    Some(1_000)
                )
            );
            assert_eq!(
                of("2.2.2.2:443"),
                (
                    "2.2.2.2:443".into(),
                    TcpVerdict::Ok,
                    Some("node-b".into()),
                    Some(0),
                    Some(900)
                ),
                "sing-box's failed test is the record's 0"
            );
            assert_eq!(
                of("3.3.3.3:443"),
                (
                    "3.3.3.3:443".into(),
                    TcpVerdict::Ok,
                    Some("node-c".into()),
                    None,
                    None
                ),
                "an untested node reads as no measurement"
            );
            assert_eq!(
                got.last().unwrap().2.as_deref(),
                Some("node-b"),
                "selected last"
            );
            let ticks = usize::try_from(tick).unwrap();
            assert_eq!(c.facts.group_reads.load(Ordering::Acquire), ticks);
            assert_eq!(c.facts.config_reads.load(Ordering::Acquire), ticks);
            assert_eq!(c.facts.urltest_reads.load(Ordering::Acquire), 3 * ticks);
            assert_eq!(c.tcp.sent.load(Ordering::Acquire), 3 * ticks);
        }
    }

    /// Nodes sharing one endpoint: the listener is connected to once, the
    /// selected node's reading takes the endpoint's row and the sibling's
    /// lands on a reading-only row beside it.
    #[tokio::test]
    async fn a_shared_endpoint_is_probed_once_and_both_readings_land() {
        let facts = Facts {
            nodes: vec![
                ("node-a".into(), "1.1.1.1:443".into()),
                ("node-b".into(), "1.1.1.1:443".into()),
            ],
            group: Some(ProxyGroup {
                now: Some("node-a".into()),
                all: vec!["node-a".into(), "node-b".into()],
            }),
            history: vec![
                (
                    "node-a".into(),
                    UrlTestEntry {
                        at_us: 1_000,
                        ms: 202,
                    },
                ),
                (
                    "node-b".into(),
                    UrlTestEntry {
                        at_us: 1_000,
                        ms: 250,
                    },
                ),
            ],
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let got = rows(&c.collect(1).await);
        assert_eq!(
            c.tcp.sent.load(Ordering::Acquire),
            1,
            "one listener, one connect"
        );
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0],
            (
                "1.1.1.1:443".into(),
                TcpVerdict::Skip,
                Some("node-b".into()),
                Some(250),
                Some(1_000)
            ),
            "the sibling's reading-only row"
        );
        assert_eq!(
            got[1],
            (
                "1.1.1.1:443".into(),
                TcpVerdict::Ok,
                Some("node-a".into()),
                Some(202),
                Some(1_000)
            ),
            "the selected node on the endpoint's own row, last"
        );
    }

    /// The API silent (no group): nothing is read per node and no reading is
    /// invented; the endpoint rows still land, without a selector.
    #[tokio::test]
    async fn no_group_reads_no_node() {
        let facts = Facts {
            group: None,
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let samples = c.collect(1).await;
        assert_eq!(
            rows(&samples),
            vec![("1.1.1.1:443".into(), TcpVerdict::Ok, None, None, None)]
        );
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.selector, None);
        assert_eq!(c.facts.urltest_reads.load(Ordering::Acquire), 0);
    }

    /// The passive tier withholds all three emission classes: no TUN probe, no
    /// endpoint connect, and the held streams are closed rather than checked.
    /// The tick still lands with the `SKIP` placeholder row with every
    /// measurement `None`, while the local reads still flow — the selector,
    /// and sing-box's own URL test of each member, on a reading-only row
    /// beside the placeholder. Switching to active re-opens everything on
    /// the next tick, and the reading then rides the endpoint's own row.
    #[tokio::test]
    async fn passive_withholds_every_probe_closes_the_streams_and_still_emits() {
        let (c, probing) = collector_in(Readiness::Ready, ProbingTier::Passive);

        let samples = c.collect(7).await;
        assert_eq!(
            rows(&samples),
            vec![
                ("-".into(), TcpVerdict::Skip, None, None, None),
                (
                    "1.1.1.1:443".into(),
                    TcpVerdict::Skip,
                    Some("node-a".into()),
                    Some(202),
                    Some(1_000)
                ),
            ],
            "the placeholder, then sing-box's own test on a reading-only row"
        );
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.rtt_ms, None);
        assert_eq!(p.tun_code, None);
        assert_eq!(p.est_direct_alive, None);
        assert_eq!(p.est_tun_alive, None);
        assert_eq!(p.selector.as_deref(), Some("node-a"), "a passive fact");
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 0, "no connect");
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 0, "no 204");
        assert_eq!(
            c.facts.urltest_reads.load(Ordering::Acquire),
            1,
            "a local read"
        );
        assert_eq!(c.stall.checks.load(Ordering::Acquire), 0, "no HEAD");
        assert_eq!(c.stall.closes.load(Ordering::Acquire), 1, "streams closed");

        probing.set(ProbingTier::Active);
        let samples = c.collect(8).await;
        assert_eq!(samples.len(), 1, "the reading rides the endpoint's row");
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.tcp, TcpVerdict::Ok);
        assert_eq!(p.tun_code, Some(204));
        assert_eq!(p.est_tun_alive, Some(true));
        assert_eq!(p.urltest_node.as_deref(), Some("node-a"));
        assert_eq!(p.urltest_ms, Some(202));
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 1);
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 1);
        assert_eq!(c.stall.checks.load(Ordering::Acquire), 1);
        assert_eq!(
            c.stall.closes.load(Ordering::Acquire),
            1,
            "not closed again"
        );
    }
}
