//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber`/`StallProbe` ports into the [`build_proxy_samples`]
//! mapping.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, ProbingState, Readiness, Source, TcpProber};
use types::{EmissionClass, ProxySample, Sample, TcpVerdict};

use crate::probes::{Dial, ProxyFacts, StallProbe, StallReading};
use crate::proxy::build_proxy_samples;

/// Static metadata for the proxy collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "proxy",
    supported_os: &[Os::MacOs],
};

/// The URLs the proxy collector's active probes fetch, from the config: the
/// TUN 204 target, and the two dial targets — one by IP (transport through
/// the node) and one by name (transport plus sing-box's own DNS path)
/// (realm net-observer, node #62).
#[derive(Debug, Clone)]
pub struct ProbeUrls {
    pub tun: String,
    pub dial_ip: String,
    pub dial_name: String,
}

/// Interval collector for per-upstream-server TCP reachability, the TUN 204
/// probe, the active upstream node selection, the established-flow
/// discriminator (held reference streams checked each tick), and the dial
/// probe through the selector group's nodes.
///
/// Static dispatch over the [`TcpProber`], [`ProxyFacts`] and [`StallProbe`]
/// ports: native `async fn` in traits is not `dyn`-compatible, so the ports are
/// generic type parameters (the daemon monomorphizes them via
/// `enum AnyCollector`).
pub struct ProxyCollector<T: TcpProber, F: ProxyFacts, S: StallProbe> {
    tcp: T,
    facts: F,
    stall: S,
    urls: ProbeUrls,
    iface: String,
    interval: Duration,
    /// The probing tier, shared with the control socket. This is the most
    /// talkative collector — four emission classes — and in the passive tier
    /// every one is withheld: no 204 through the TUN, no connect to any
    /// endpoint, no dial asked of sing-box, and the held reference streams
    /// are CLOSED rather than kept open and exercised. The selector read
    /// (loopback, sing-box's own API) is passive and continues; the endpoint
    /// list is NOT read at all under passive — it exists only to be connected
    /// to, and the tick lands as the single `SKIP` placeholder row instead.
    /// (realm net-observer, node #88)
    probing: Arc<ProbingState>,
    /// The dial probe's round-robin position over the selector group's
    /// non-selected members: the selected node is dialled every tick (it is
    /// what traffic uses), the rest one per tick in turn, so a four-node
    /// group is fully dialled every four ticks (realm net-observer, node
    /// #62). Advances once per active tick; the group may change size
    /// between ticks, so it is taken modulo the current member count.
    dial_cursor: AtomicUsize,
}

impl<T: TcpProber, F: ProxyFacts, S: StallProbe> ProxyCollector<T, F, S> {
    /// Construct a proxy collector from its ports, probe URLs, cadence and
    /// the shared probing tier (see [`ProxyCollector::probing`]).
    pub fn new(
        tcp: T,
        facts: F,
        stall: S,
        urls: ProbeUrls,
        iface: String,
        interval: Duration,
        probing: Arc<ProbingState>,
    ) -> Self {
        Self {
            tcp,
            facts,
            stall,
            urls,
            iface,
            interval,
            probing,
            dial_cursor: AtomicUsize::new(0),
        }
    }

    /// One tick's dials: the selected node, then one of the group's other
    /// members by round-robin (see [`ProxyCollector::dial_cursor`]). Nothing
    /// to dial — no selection and no members, the API silent — yields no
    /// dial at all, which the mapping records as "not dialled".
    ///
    /// Each node is fetched by IP and by name at once, and the two nodes at
    /// once as well, so a tick whose dials all die pays ONE delay-test
    /// timeout, not four in a row past the tick.
    async fn dial_round(&self, selected: Option<&str>) -> Vec<Dial> {
        let members = self.facts.group_members().await;
        let others: Vec<&String> = members
            .iter()
            .filter(|m| Some(m.as_str()) != selected)
            .collect();
        let rotating = if others.is_empty() {
            None
        } else {
            let at = self.dial_cursor.fetch_add(1, Ordering::Relaxed) % others.len();
            Some(others[at].clone())
        };
        if selected.is_none() && rotating.is_none() {
            return Vec::new();
        }
        let endpoints = self.facts.node_endpoints().await;
        let (first, second) = join(
            async {
                match selected {
                    Some(node) => Some(self.dial_node(node.to_string(), &endpoints).await),
                    None => None,
                }
            },
            async {
                match rotating {
                    Some(node) => Some(self.dial_node(node, &endpoints).await),
                    None => None,
                }
            },
        )
        .await;
        first.into_iter().chain(second).collect()
    }

    /// Dial one node by both URLs at once and pair the readings with the
    /// endpoint the node dials through (`None` when the config names none).
    async fn dial_node(&self, node: String, endpoints: &[(String, String)]) -> Dial {
        let (ip, name) = join(
            self.facts.dial(&node, &self.urls.dial_ip),
            self.facts.dial(&node, &self.urls.dial_name),
        )
        .await;
        let endpoint = endpoints
            .iter()
            .find(|(n, _)| *n == node)
            .map(|(_, e)| e.clone());
        Dial {
            node,
            endpoint,
            ip,
            name,
        }
    }
}

/// Drive two futures to completion together and return both outputs.
///
/// `std` only: this crate carries no runtime crate (`collector-core` keeps
/// tokio out of the collectors' abstractions), and the one thing needed here
/// is that the dials of a tick overlap — a tick is on a 15 s cadence and
/// each dial may wait the delay test's whole timeout.
async fn join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let mut a = std::pin::pin!(a);
    let mut b = std::pin::pin!(b);
    let (mut out_a, mut out_b) = (None, None);
    std::future::poll_fn(|cx| {
        if out_a.is_none()
            && let Poll::Ready(v) = a.as_mut().poll(cx)
        {
            out_a = Some(v);
        }
        if out_b.is_none()
            && let Poll::Ready(v) = b.as_mut().poll(cx)
        {
            out_b = Some(v);
        }
        if out_a.is_some() && out_b.is_some() {
            return Poll::Ready(out_a.take().zip(out_b.take()).expect("both ready"));
        }
        Poll::Pending
    })
    .await
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
            Some(self.facts.tun_probe(&self.urls.tun).await.code())
        } else {
            None
        };
        let selector = self.facts.selector().await;
        // The dial probe: sing-box's own dial through the selected node and
        // one rotating member, by IP and by name. Withheld, no dial is asked
        // of sing-box and every row reads "not dialled"; the group members
        // are then not read either — they exist only to be dialled.
        let dials = if tier.emits(EmissionClass::DialProbe) {
            self.dial_round(selector.as_deref()).await
        } else {
            Vec::new()
        };
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
        // Withheld, the endpoint list is not walked: the tick lands as the
        // single `SKIP` placeholder row (`tcp = SKIP`, no rtt) the mapping
        // produces for "nothing was probed", carrying the passive facts.
        let endpoints = if tier.emits(EmissionClass::EndpointProbe) {
            self.facts.server_endpoints().await
        } else {
            Vec::new()
        };
        let mut probed = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            // Split at the LAST ':' so the host half keeps any earlier colons;
            // an endpoint that does not parse as "host:port" is probed on 443.
            let (host, port) = match endpoint.rsplit_once(':') {
                Some((host, port)) => match port.parse::<u16>() {
                    Ok(port) => (host, port),
                    Err(_) => (endpoint.as_str(), 443),
                },
                None => (endpoint.as_str(), 443),
            };
            let o = self.tcp.connect_bound(host, port, &self.iface).await;
            // The sample carries the full "host:port" string: the row must name
            // the listener that was probed, matching the oracle's vless[ip:port].
            probed.push((endpoint, o));
        }
        build_proxy_samples(ts_us, tun_code, selector, stall, probed, dials)
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
            dial_ip_ms: None,
            dial_name_ms: None,
            dial_target: None,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{DialOutcome, StallReading, StreamCheck, TunProbe};
    use collector_core::PingOutcome;
    use std::sync::Mutex;
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
    /// selector group's selection and members, and every dial asked.
    struct Facts {
        readiness: Readiness,
        tun_probes: Arc<AtomicUsize>,
        tun_answer: TunProbe,
        /// `(node, endpoint)` as the config declares them; the endpoints to
        /// probe are these, deduplicated.
        nodes: Vec<(String, String)>,
        selected: Option<String>,
        members: Vec<String>,
        member_reads: Arc<AtomicUsize>,
        dial_answer: DialOutcome,
        /// Every dial asked, as `(node, url)`, in order.
        dials: Arc<Mutex<Vec<(String, String)>>>,
    }
    impl Facts {
        fn new(readiness: Readiness, tun_answer: TunProbe) -> Self {
            Self {
                readiness,
                tun_probes: Arc::default(),
                tun_answer,
                nodes: vec![("node-a".into(), "1.1.1.1:443".into())],
                selected: Some("node-a".into()),
                members: Vec::new(),
                member_reads: Arc::default(),
                dial_answer: DialOutcome::Ok(202),
                dials: Arc::default(),
            }
        }
        fn dialled(&self) -> Vec<(String, String)> {
            self.dials.lock().unwrap().clone()
        }
    }
    impl ProxyFacts for Facts {
        async fn server_endpoints(&self) -> Vec<String> {
            let mut out: Vec<String> = Vec::new();
            for (_, e) in &self.nodes {
                if !out.contains(e) {
                    out.push(e.clone());
                }
            }
            out
        }
        async fn node_endpoints(&self) -> Vec<(String, String)> {
            self.nodes.clone()
        }
        async fn tun_probe(&self, _: &str) -> TunProbe {
            self.tun_probes.fetch_add(1, Ordering::Release);
            self.tun_answer
        }
        async fn selector(&self) -> Option<String> {
            self.selected.clone()
        }
        async fn group_members(&self) -> Vec<String> {
            self.member_reads.fetch_add(1, Ordering::Release);
            self.members.clone()
        }
        async fn dial(&self, node: &str, url: &str) -> DialOutcome {
            self.dials
                .lock()
                .unwrap()
                .push((node.to_string(), url.to_string()));
            self.dial_answer
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
            ProbeUrls {
                tun: "http://x/204".into(),
                dial_ip: "http://ip/".into(),
                dial_name: "http://name/".into(),
            },
            "en0".into(),
            Duration::from_secs(15),
            probing.clone(),
        );
        (c, probing)
    }

    fn collector(readiness: Readiness) -> ProxyCollector<T, Facts, FakeStall> {
        collector_in(readiness, ProbingTier::Active).0
    }

    /// A three-node selector group, each node on its own endpoint, `node-a`
    /// selected.
    fn group_facts() -> Facts {
        Facts {
            nodes: vec![
                ("node-a".into(), "1.1.1.1:443".into()),
                ("node-b".into(), "2.2.2.2:443".into()),
                ("node-c".into(), "3.3.3.3:443".into()),
            ],
            members: vec!["node-a".into(), "node-b".into(), "node-c".into()],
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        }
    }

    /// One proxy row's `(endpoint, dial target, dial by IP, dial by name)`.
    type DialRow = (String, Option<String>, Option<u32>, Option<u32>);

    /// The dial reading of every proxy row of a tick, by endpoint.
    fn dial_rows(samples: &[Sample]) -> Vec<DialRow> {
        samples
            .iter()
            .map(|s| {
                let Sample::Proxy(p) = s else {
                    panic!("expected a proxy sample")
                };
                (
                    p.server_ip.clone(),
                    p.dial_target.clone(),
                    p.dial_ip_ms,
                    p.dial_name_ms,
                )
            })
            .collect()
    }

    /// The selected node is dialled on every tick — by IP and by name — and
    /// the other members take turns, one per tick, so the group is fully
    /// dialled every `members - 1` ticks; each dial rides its node's endpoint
    /// row, and a node not dialled this tick reads "not dialled" there.
    #[tokio::test]
    async fn the_selected_node_is_dialled_every_tick_and_the_rest_rotate() {
        let (c, _) = collector_with(group_facts(), ProbingTier::Active);
        let expect = |samples: &[Sample], rotating: &str, idle: &str| {
            let rows = dial_rows(samples);
            assert_eq!(rows.len(), 3, "a dial with a row of its own adds none");
            let of = |ip: &str| rows.iter().find(|r| r.0 == ip).unwrap().clone();
            assert_eq!(
                of("1.1.1.1:443"),
                (
                    "1.1.1.1:443".into(),
                    Some("node-a".into()),
                    Some(202),
                    Some(202)
                ),
                "the selected node, every tick"
            );
            let (ep, node) = match rotating {
                "node-b" => ("2.2.2.2:443", "node-b"),
                _ => ("3.3.3.3:443", "node-c"),
            };
            assert_eq!(of(ep).1.as_deref(), Some(node), "this tick's turn");
            let idle_ep = if idle == "node-b" {
                "2.2.2.2:443"
            } else {
                "3.3.3.3:443"
            };
            assert_eq!(
                of(idle_ep),
                (idle_ep.into(), None, None, None),
                "not its turn"
            );
            assert_eq!(rows.last().unwrap().1.as_deref(), Some("node-a"));
        };
        expect(&c.collect(1).await, "node-b", "node-c");
        expect(&c.collect(2).await, "node-c", "node-b");
        expect(&c.collect(3).await, "node-b", "node-c");
        // Two nodes by two URLs per tick, three ticks.
        let dialled = c.facts.dialled();
        assert_eq!(dialled.len(), 12);
        assert_eq!(
            dialled
                .iter()
                .filter(|(n, u)| n == "node-a" && u == "http://name/")
                .count(),
            3
        );
        assert_eq!(dialled.iter().filter(|(n, _)| n == "node-b").count(), 4);
        assert_eq!(dialled.iter().filter(|(n, _)| n == "node-c").count(), 2);
    }

    /// A dial sing-box could not complete is the record's `0` on both sides
    /// — attempted, no answer — never `None`, which only a dial not asked
    /// leaves behind.
    #[tokio::test]
    async fn a_dial_with_no_answer_records_zero() {
        let facts = Facts {
            dial_answer: DialOutcome::NoAnswer,
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let rows = dial_rows(&c.collect(1).await);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1.as_deref(), Some("node-a"));
        assert_eq!(rows[0].2, Some(0));
        assert_eq!(rows[0].3, Some(0));
    }

    /// No selection and no members (the API silent): nothing is dialled and
    /// the rows say so, rather than a dial asked of a node nobody named.
    #[tokio::test]
    async fn nothing_to_dial_asks_nothing() {
        let facts = Facts {
            selected: None,
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let rows = dial_rows(&c.collect(1).await);
        assert_eq!(rows, vec![("1.1.1.1:443".into(), None, None, None)]);
        assert!(c.facts.dialled().is_empty());
    }

    /// The record's dead-tun shape: a probe that was ATTEMPTED and got no HTTP
    /// status lands as `tun_code = 0` (the shell oracle's curl `000`), the
    /// value `why`, `wedge-or-starvation` and the live `starvation` rule all
    /// read as dead — distinct from `None`, which only a probe never attempted
    /// (the passive tier, above) leaves behind.
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
    }

    /// The passive tier withholds all four emission classes: no TUN probe, no
    /// endpoint connect, no dial asked of sing-box (nor its group members
    /// read), and the held streams are closed rather than checked. The tick
    /// still lands as the `SKIP` placeholder row with every measurement
    /// `None`, while the selector (a loopback read) still flows. Switching to
    /// active re-opens everything on the next tick.
    #[tokio::test]
    async fn passive_withholds_every_probe_closes_the_streams_and_still_emits() {
        let (c, probing) = collector_in(Readiness::Ready, ProbingTier::Passive);

        let samples = c.collect(7).await;
        assert_eq!(samples.len(), 1, "passive must not silence the tick");
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.tcp, TcpVerdict::Skip);
        assert_eq!(p.rtt_ms, None);
        assert_eq!(p.tun_code, None);
        assert_eq!(p.est_direct_alive, None);
        assert_eq!(p.est_tun_alive, None);
        assert_eq!(p.dial_target, None, "not dialled");
        assert_eq!(p.dial_ip_ms, None);
        assert_eq!(p.dial_name_ms, None);
        assert_eq!(p.selector.as_deref(), Some("node-a"), "a passive fact");
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 0, "no connect");
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 0, "no 204");
        assert!(c.facts.dialled().is_empty(), "no dial");
        assert_eq!(c.facts.member_reads.load(Ordering::Acquire), 0);
        assert_eq!(c.stall.checks.load(Ordering::Acquire), 0, "no HEAD");
        assert_eq!(c.stall.closes.load(Ordering::Acquire), 1, "streams closed");

        probing.set(ProbingTier::Active);
        let samples = c.collect(8).await;
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.tcp, TcpVerdict::Ok);
        assert_eq!(p.tun_code, Some(204));
        assert_eq!(p.est_tun_alive, Some(true));
        assert_eq!(p.dial_target.as_deref(), Some("node-a"));
        assert_eq!(p.dial_ip_ms, Some(202));
        assert_eq!(p.dial_name_ms, Some(202));
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 1);
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 1);
        assert_eq!(c.facts.dialled().len(), 2, "by IP and by name");
        assert_eq!(c.stall.checks.load(Ordering::Acquire), 1);
        assert_eq!(
            c.stall.closes.load(Ordering::Acquire),
            1,
            "not closed again"
        );
    }
}
