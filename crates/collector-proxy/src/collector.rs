//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber`/`StallProbe` ports into the [`build_proxy_samples`]
//! mapping.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, ProbingState, Readiness, Source, TcpProber};
use types::{EmissionClass, ProxySample, Sample, TcpVerdict};

use crate::probes::{ProxyFacts, ProxyInfo, StallProbe, StallReading, UrlTest, UrlTestEntry};
use crate::proxy::build_proxy_samples;

/// Static metadata for the proxy collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "proxy",
    supported_os: &[Os::MacOs],
};

/// How deep the collector follows groups nested in groups — both when it
/// descends the selection (`now` naming a group whose `now` names a group…)
/// and when it flattens the members. sing-box configs nest a URLTest group
/// inside a Selector (two levels, observed on the Mac: realm net-observer,
/// node #139); eight is far past any sane config, and a cycle between groups
/// stops here rather than never — the selector then stays a group name,
/// which the record shows as it is (this crate carries no logger).
const MAX_GROUP_DEPTH: usize = 8;

/// What the collector remembers of one node's URL-test history across
/// ticks, keyed by node (realm net-observer, node #62). sing-box deletes a
/// node's history entry when its test fails, so a failed test is observable
/// only as an ABSENCE after a presence — which needs memory. Process-scoped:
/// a daemon restart forgets it, and a restart is already bracketed by the
/// startup observing edge, so the reader can see where the memory begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UrltestMemory {
    /// The newest read showed an entry.
    Present,
    /// The history has read empty since this tick, after having shown an
    /// entry before.
    AbsentSince(i64),
}

/// Fold one tick's read of `node`'s history into the memory and return
/// what the sample carries as `urltest_absent_since_us`: `None` while an
/// entry is present, or for a node never seen with one (not tested
/// periodically — a node outside every URLTest group — so its entry goes
/// stale but never absent; honest silence); the tick of the FIRST empty read
/// after a presence, kept across later empty reads.
fn note_urltest(
    memory: &mut HashMap<String, UrltestMemory>,
    node: &str,
    entry: Option<UrlTestEntry>,
    ts_us: i64,
) -> Option<i64> {
    if entry.is_some() {
        memory.insert(node.to_string(), UrltestMemory::Present);
        return None;
    }
    match memory.get(node) {
        None => None,
        Some(UrltestMemory::AbsentSince(since)) => Some(*since),
        Some(UrltestMemory::Present) => {
            memory.insert(node.to_string(), UrltestMemory::AbsentSince(ts_us));
            Some(ts_us)
        }
    }
}

/// The selector group's view of sing-box, resolved for one tick: the node
/// that carries traffic and the leaves whose history is read.
struct GroupView {
    /// The node traffic goes through: the configured group's `now`, followed
    /// down through nested groups to a node (realm net-observer, node #139).
    selector: Option<String>,
    /// Every testable leaf under the configured group, groups flattened
    /// transitively, deduplicated, the selected node first.
    leaves: Vec<String>,
    /// What each read answered, by name.
    infos: HashMap<String, ProxyInfo>,
}

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
    /// selector group, its nested groups and each leaf's URL-test history
    /// (loopback, sing-box's own API) and the node list (the rendered
    /// config) — the endpoints are not connected to under passive, but a
    /// node's reading still needs the endpoint it belongs to, so the tick
    /// lands as the `SKIP` placeholder row plus one reading row per leaf.
    /// (realm net-observer, node #88)
    probing: Arc<ProbingState>,
    /// The absence memory (see [`UrltestMemory`]), keyed by node.
    urltest_memory: Mutex<HashMap<String, UrltestMemory>>,
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
            urltest_memory: Mutex::new(HashMap::new()),
        }
    }

    /// Read the configured group and everything under it: its members, the
    /// members of any nested group, level by level (one batched API read per
    /// level, each name read once), then resolve the node that carries
    /// traffic by following `now` down through the groups (realm
    /// net-observer, node #139). `None` when the configured group itself did
    /// not answer.
    async fn read_group(&self) -> Option<GroupView> {
        let root = self.facts.group().await?;
        let mut infos: HashMap<String, ProxyInfo> = HashMap::new();
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(root.name.clone());
        let mut leaves: Vec<String> = Vec::new();
        let mut frontier: Vec<String> = root.all.clone();
        let mut depth = 0;
        loop {
            let names: Vec<String> = std::mem::take(&mut frontier)
                .into_iter()
                .filter(|n| visited.insert(n.clone()))
                .collect();
            if names.is_empty() {
                break;
            }
            if depth == MAX_GROUP_DEPTH {
                // Nested deeper than followed (a cycle between groups):
                // the members beyond are not read and get no reading row.
                break;
            }
            for (name, info) in names.iter().zip(self.facts.proxies(&names).await) {
                // A member the API did not answer for this tick gets no
                // reading row (the adapter logs the failed read); a failed
                // read is not an empty history.
                let Some(info) = info else {
                    continue;
                };
                if info.is_group() {
                    frontier.extend(info.all.iter().cloned());
                } else if !info.is_untestable() {
                    leaves.push(name.clone());
                }
                infos.insert(name.clone(), info);
            }
            depth += 1;
        }
        infos.insert(root.name.clone(), root.clone());
        // The descent: the group's `now`, and while that names a group, ITS
        // `now` — the node reached is the one traffic goes through.
        let mut selector = None;
        let mut current = &root;
        for hop in 0..=MAX_GROUP_DEPTH {
            let Some(now) = current.now.clone() else {
                break;
            };
            selector = Some(now.clone());
            match infos.get(&now) {
                // A selection descending deeper than followed (a cycle
                // between groups) stops here: the selector stays the last
                // group's name — a group where the record expects a node,
                // which is how the operator sees the shape is off.
                Some(info) if info.is_group() && hop < MAX_GROUP_DEPTH => current = info,
                // A node, or a group at the bound, or a selected member the
                // API did not answer for (its name stays the selector; the
                // adapter logs the failed read).
                _ => break,
            }
        }
        // The selected node's reading goes first, so it takes its endpoint's
        // row before a sibling on the same endpoint can.
        if let Some(sel) = &selector
            && let Some(at) = leaves.iter().position(|l| l == sel)
            && at > 0
        {
            let node = leaves.remove(at);
            leaves.insert(0, node);
        }
        Some(GroupView {
            selector,
            leaves,
            infos,
        })
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
        // The local reads, under every tier: the group and everything under
        // it from the API, the node list from the config — the latter ONE
        // read serving both the endpoints to probe and the row each node's
        // reading rides.
        let view = self.read_group().await;
        let selector = view.as_ref().and_then(|v| v.selector.clone());
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
        // sing-box's own URL tests, one reading per leaf, folded through the
        // absence memory. A leaf the API did not answer for this tick has no
        // reading and leaves the memory untouched: a failed read is not an
        // empty history.
        let mut urltests = Vec::new();
        if let Some(view) = view {
            let mut memory = self
                .urltest_memory
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for node in view.leaves {
                let Some(info) = view.infos.get(&node) else {
                    continue;
                };
                let entry = info.urltest;
                let absent_since_us = note_urltest(&mut memory, &node, entry, ts_us);
                let endpoint = nodes
                    .iter()
                    .find(|(n, _)| *n == node)
                    .map(|(_, e)| e.clone());
                urltests.push(UrlTest {
                    node,
                    endpoint,
                    entry,
                    absent_since_us,
                });
            }
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
            urltest_absent_since_us: None,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{StallReading, StreamCheck, TunProbe};
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

    fn entry(at_us: i64, ms: u32) -> UrlTestEntry {
        UrlTestEntry { at_us, ms }
    }

    fn group(name: &str, kind: &str, now: &str, all: &[&str]) -> ProxyInfo {
        ProxyInfo {
            name: name.into(),
            kind: kind.into(),
            now: Some(now.into()),
            all: all.iter().map(|s| (*s).to_string()).collect(),
            urltest: None,
        }
    }

    fn node(name: &str, kind: &str, urltest: Option<UrlTestEntry>) -> ProxyInfo {
        ProxyInfo {
            name: name.into(),
            kind: kind.into(),
            now: None,
            all: Vec::new(),
            urltest,
        }
    }

    /// Facts that count the TUN probes actually sent and answer them as
    /// scripted; the nodes the config names with their endpoints, and the
    /// Clash API's proxies by name (the configured group is `root`) —
    /// with a count of every local read and every batch.
    struct Facts {
        readiness: Readiness,
        tun_probes: Arc<AtomicUsize>,
        tun_answer: TunProbe,
        /// `(node, endpoint)` as the config declares them.
        nodes: Vec<(String, String)>,
        /// What `GET /proxies/<name>` answers, by name; a name absent here
        /// does not answer.
        api: Mutex<HashMap<String, ProxyInfo>>,
        root: String,
        config_reads: Arc<AtomicUsize>,
        group_reads: Arc<AtomicUsize>,
        batches: Arc<AtomicUsize>,
        proxy_reads: Arc<AtomicUsize>,
    }
    impl Facts {
        fn new(readiness: Readiness, tun_answer: TunProbe) -> Self {
            let api = HashMap::from([
                (
                    "auto".to_string(),
                    group("auto", "URLTest", "node-a", &["node-a"]),
                ),
                (
                    "node-a".to_string(),
                    node("node-a", "VLESS", Some(entry(1_000, 202))),
                ),
            ]);
            Self {
                readiness,
                tun_probes: Arc::default(),
                tun_answer,
                nodes: vec![("node-a".into(), "1.1.1.1:443".into())],
                api: Mutex::new(api),
                root: "auto".into(),
                config_reads: Arc::default(),
                group_reads: Arc::default(),
                batches: Arc::default(),
                proxy_reads: Arc::default(),
            }
        }
        fn set(&self, info: ProxyInfo) {
            self.api.lock().unwrap().insert(info.name.clone(), info);
        }
        fn forget(&self, name: &str) {
            self.api.lock().unwrap().remove(name);
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
        async fn group(&self) -> Option<ProxyInfo> {
            self.group_reads.fetch_add(1, Ordering::Release);
            self.api.lock().unwrap().get(&self.root).cloned()
        }
        async fn proxies(&self, names: &[String]) -> Vec<Option<ProxyInfo>> {
            self.batches.fetch_add(1, Ordering::Release);
            self.proxy_reads.fetch_add(names.len(), Ordering::Release);
            let api = self.api.lock().unwrap();
            names.iter().map(|n| api.get(n).cloned()).collect()
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

    /// The Mac's shape (realm net-observer, node #139): a top Selector
    /// `main` whose `now` the operator pointed at the node `out-8`, holding
    /// the URLTest group `auto` (selecting `out-6`), two more nodes and
    /// `block-out`.
    fn mac_facts() -> Facts {
        let facts = Facts {
            nodes: vec![
                ("out-6".into(), "6.6.6.6:443".into()),
                ("out-5".into(), "5.5.5.5:443".into()),
                ("out-8".into(), "8.8.8.8:443".into()),
                ("out-4".into(), "4.4.4.4:443".into()),
            ],
            root: "main".into(),
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        facts.set(group(
            "main",
            "Selector",
            "out-8",
            &["auto", "out-8", "out-4", "block-out"],
        ));
        facts.set(group("auto", "URLTest", "out-6", &["out-6", "out-5"]));
        facts.set(node("out-6", "VLESS", Some(entry(1_000, 202))));
        facts.set(node("out-5", "VLESS", Some(entry(1_000, 250))));
        facts.set(node("out-8", "VLESS", Some(entry(2_000, 186))));
        facts.set(node("out-4", "VLESS", None));
        facts.set(node("block-out", "Block", None));
        facts
    }

    /// One proxy row's `(endpoint, tcp, node, ms, absent_since)`.
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
                    p.urltest_absent_since_us,
                )
            })
            .collect()
    }

    fn selector_of(samples: &[Sample]) -> Option<String> {
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        p.selector.clone()
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
        assert_eq!(p.selector.as_deref(), Some("node-a"));
        assert_eq!(p.urltest_node.as_deref(), Some("node-a"));
        assert_eq!(p.urltest_ms, Some(202));
        assert_eq!(p.urltest_at_us, Some(1_000));
        assert_eq!(p.urltest_absent_since_us, None);
    }

    /// The Mac's shape: the configured Selector's `now` names a NODE, so
    /// the selector is that node — not the nested URLTest group's `now` —
    /// and the leaves are every testable node under both groups, `block-out`
    /// excluded, each read once, level by level in two batches, the
    /// selected node's row last. (realm net-observer, node #139)
    #[tokio::test]
    async fn the_selector_is_the_node_that_carries_traffic_and_leaves_flatten() {
        let (c, _) = collector_with(mac_facts(), ProbingTier::Active);
        let samples = c.collect(1).await;
        assert_eq!(selector_of(&samples).as_deref(), Some("out-8"));
        let got = rows(&samples);
        assert_eq!(
            got.len(),
            4,
            "one row per endpoint, each with its node's reading"
        );
        let of = |ip: &str| got.iter().find(|r| r.0 == ip).unwrap().clone();
        assert_eq!(
            of("8.8.8.8:443"),
            (
                "8.8.8.8:443".into(),
                TcpVerdict::Ok,
                Some("out-8".into()),
                Some(186),
                None
            )
        );
        assert_eq!(of("6.6.6.6:443").2.as_deref(), Some("out-6"));
        assert_eq!(of("5.5.5.5:443").2.as_deref(), Some("out-5"));
        assert_eq!(
            of("4.4.4.4:443"),
            (
                "4.4.4.4:443".into(),
                TcpVerdict::Ok,
                Some("out-4".into()),
                None,
                None
            ),
            "never seen tested: no entry and no absence"
        );
        assert!(
            got.iter().all(|r| r.2.as_deref() != Some("block-out")),
            "a Block outbound has no test to read"
        );
        assert_eq!(
            got.last().unwrap().2.as_deref(),
            Some("out-8"),
            "selected last"
        );
        assert_eq!(c.facts.group_reads.load(Ordering::Acquire), 1);
        assert_eq!(c.facts.config_reads.load(Ordering::Acquire), 1);
        assert_eq!(
            c.facts.batches.load(Ordering::Acquire),
            2,
            "two levels, two batches"
        );
        assert_eq!(
            c.facts.proxy_reads.load(Ordering::Acquire),
            6,
            "auto, out-8, out-4, block-out; then out-6, out-5 — each once"
        );
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 4);
    }

    /// The other Mac shape: the top Selector's `now` names the nested
    /// URLTest group, so the descent follows it and the selector is that
    /// group's `now`.
    #[tokio::test]
    async fn the_descent_follows_now_through_a_nested_group() {
        let facts = mac_facts();
        facts.set(group(
            "main",
            "Selector",
            "auto",
            &["auto", "out-8", "out-4", "block-out"],
        ));
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let samples = c.collect(1).await;
        assert_eq!(selector_of(&samples).as_deref(), Some("out-6"));
        assert_eq!(rows(&samples).last().unwrap().2.as_deref(), Some("out-6"));
    }

    /// A member the API cannot answer for is skipped, not invented: no
    /// reading row, and when it is the selected one its name is still the
    /// selector. A group that selects itself through a nested group ends at
    /// the depth bound instead of looping.
    #[tokio::test]
    async fn unreadable_members_and_cycles_are_bounded() {
        let facts = mac_facts();
        facts.forget("out-8");
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let samples = c.collect(1).await;
        assert_eq!(selector_of(&samples).as_deref(), Some("out-8"));
        assert!(
            rows(&samples)
                .iter()
                .all(|r| r.2.as_deref() != Some("out-8")),
            "no reading for a member that did not answer"
        );

        let facts = mac_facts();
        facts.set(group("main", "Selector", "loop", &["loop"]));
        facts.set(group("loop", "Selector", "main", &["main"]));
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let samples = c.collect(1).await;
        assert_eq!(selector_of(&samples).as_deref(), Some("loop"));
        assert!(
            rows(&samples).iter().all(|r| r.2.is_none()),
            "no leaf to read"
        );
    }

    /// The absence memory (realm net-observer, node #62): an entry present
    /// on tick 1, gone on tick 2, sets `absent_since` to tick 2's `ts_us`
    /// and keeps it through tick 3; the entry back on tick 4 clears it; and
    /// a node never seen with an entry stays `None` however long its
    /// history reads empty.
    #[tokio::test]
    async fn absence_is_dated_from_the_first_empty_read_after_a_presence() {
        let (c, _) = collector_with(mac_facts(), ProbingTier::Active);
        let of = |samples: &[Sample], node: &str| {
            rows(samples)
                .into_iter()
                .find(|r| r.2.as_deref() == Some(node))
                .unwrap()
        };
        let s1 = c.collect(10).await;
        assert_eq!(of(&s1, "out-8").3, Some(186));
        assert_eq!(of(&s1, "out-8").4, None);
        assert_eq!(of(&s1, "out-4").4, None, "never seen tested");

        c.facts.set(node("out-8", "VLESS", None));
        let s2 = c.collect(20).await;
        assert_eq!(of(&s2, "out-8").3, None);
        assert_eq!(of(&s2, "out-8").4, Some(20), "absent since this tick");
        let s3 = c.collect(30).await;
        assert_eq!(of(&s3, "out-8").4, Some(20), "kept across empty reads");
        assert_eq!(of(&s3, "out-4").4, None, "still never seen tested");

        c.facts.set(node("out-8", "VLESS", Some(entry(3_000, 190))));
        let s4 = c.collect(40).await;
        assert_eq!(of(&s4, "out-8").3, Some(190));
        assert_eq!(of(&s4, "out-8").4, None, "an entry clears the absence");

        // A read that did not answer is not an empty history: the memory
        // stays as it was, and the node has no row this tick.
        c.facts.set(node("out-8", "VLESS", None));
        let s5 = c.collect(50).await;
        assert_eq!(of(&s5, "out-8").4, Some(50));
        c.facts.forget("out-8");
        let s6 = c.collect(60).await;
        assert!(rows(&s6).iter().all(|r| r.2.as_deref() != Some("out-8")));
        c.facts.set(node("out-8", "VLESS", None));
        let s7 = c.collect(70).await;
        assert_eq!(
            of(&s7, "out-8").4,
            Some(50),
            "the unread tick changed nothing"
        );
    }

    /// The fold on its own, the four transitions named in the field's doc.
    #[test]
    fn note_urltest_folds_presence_and_absence() {
        let mut m = HashMap::new();
        assert_eq!(note_urltest(&mut m, "n", None, 1), None, "never seen");
        assert_eq!(note_urltest(&mut m, "n", Some(entry(0, 1)), 2), None);
        assert_eq!(
            note_urltest(&mut m, "n", None, 3),
            Some(3),
            "first empty read"
        );
        assert_eq!(note_urltest(&mut m, "n", None, 4), Some(3), "kept");
        assert_eq!(
            note_urltest(&mut m, "n", Some(entry(0, 1)), 5),
            None,
            "cleared"
        );
        assert_eq!(note_urltest(&mut m, "n", None, 6), Some(6), "dated afresh");
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
            ..Facts::new(Readiness::Ready, TunProbe::Status(204))
        };
        facts.set(group("auto", "URLTest", "node-a", &["node-b", "node-a"]));
        facts.set(node("node-b", "VLESS", Some(entry(1_000, 250))));
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
                None
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
                None
            ),
            "the selected node on the endpoint's own row, last"
        );
    }

    /// The API silent (no group): nothing is read per node and no reading is
    /// invented; the endpoint rows still land, without a selector.
    #[tokio::test]
    async fn no_group_reads_no_node() {
        let facts = Facts::new(Readiness::Ready, TunProbe::Status(204));
        facts.forget("auto");
        let (c, _) = collector_with(facts, ProbingTier::Active);
        let samples = c.collect(1).await;
        assert_eq!(
            rows(&samples),
            vec![("1.1.1.1:443".into(), TcpVerdict::Ok, None, None, None)]
        );
        assert_eq!(selector_of(&samples), None);
        assert_eq!(c.facts.batches.load(Ordering::Acquire), 0);
    }

    /// The passive tier withholds all three emission classes: no TUN probe, no
    /// endpoint connect, and the held streams are closed rather than checked.
    /// The tick still lands with the `SKIP` placeholder row with every
    /// measurement `None`, while the local reads still flow — the selector,
    /// and sing-box's own URL test of each leaf, on a reading-only row
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
                    None
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
            c.facts.proxy_reads.load(Ordering::Acquire),
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
