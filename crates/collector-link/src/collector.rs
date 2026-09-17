//! Static [`META`] and the [`LinkCollector`] that wires the `link` probe ports
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{
    Collector, CollectorMeta, Os, Pinger, ProbingState, Readiness, Source, TcpProber,
};
use types::{EmissionClass, GwVerdict, LinkSample, Sample, TcpVerdict};

use crate::facts::{LinkFacts, LinkSummary};
use crate::sample::build_link_sample;

/// Static metadata for the `link` collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "link",
    supported_os: &[Os::MacOs],
};

/// How many LAN neighbors a probe-on-suspicion tick pings at most. Bounded so a
/// crowded segment cannot stretch the tick; three answers are enough to tell
/// "the segment is alive" from "everything is dead".
const LAN_PROBE_MAX: usize = 3;

/// The `link` collector: gateway ping + iface-bound direct TCP + OS link facts,
/// polled on a fixed interval.
///
/// Generic over its probe ports for **static dispatch** — the ports are native
/// `async fn` traits (not dyn-compatible), so the daemon composes concrete types
/// via its `enum AnyCollector` rather than boxing.
pub struct LinkCollector<P, T, F> {
    ping: P,
    tcp: T,
    facts: F,
    interval: Duration,
    /// The probing tier, shared with the control socket. In the passive tier
    /// this collector puts NOTHING on the wire: the gateway echo, the direct
    /// probe and the neighbour pings are all withheld and read `SKIP`, while
    /// the local facts keep being read. (realm net-observer, node #88)
    probing: Arc<ProbingState>,
}

impl<P, T, F> LinkCollector<P, T, F>
where
    P: Pinger,
    T: TcpProber,
    F: LinkFacts,
{
    /// Construct a `link` collector from its probe ports, poll interval and the
    /// shared probing tier (see [`LinkCollector::probing`]).
    pub fn new(ping: P, tcp: T, facts: F, interval: Duration, probing: Arc<ProbingState>) -> Self {
        Self {
            ping,
            tcp,
            facts,
            interval,
            probing,
        }
    }
}

impl<P, T, F> Collector for LinkCollector<P, T, F>
where
    P: Pinger,
    T: TcpProber,
    F: LinkFacts,
{
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
        // Await the probes/facts, then a sync `build_*` composes the sample.
        let gw_addr = self.facts.default_gw().await;
        // Resolved ONCE per tick and handed to every per-interface read below,
        // so a default-route move mid-tick (a dock or undock) cannot stamp one
        // sample with one adapter's medium and the other's MAC.
        let phys_iface = self.facts.phys_iface().await;
        let iface = phys_iface.clone().unwrap_or_default();
        // Read the tier ONCE per tick, so the packet that is skipped and the
        // verdict that reports it can never disagree. The tier decides per
        // emission class. A probe that is not sent is `None` here, and
        // `build_link_sample` reports it as `SKIP`.
        let tier = self.probing.tier();
        let echo = tier.emits(EmissionClass::GatewayEcho);
        let ping = match &gw_addr {
            Some(gw) if echo => Some(self.ping.ping_gw(gw).await),
            // Withheld, or no gateway to address: the echo is never sent.
            _ => None,
        };
        // Probe-on-suspicion: only on a tick whose gateway verdict will read
        // FAIL — never on a healthy tick (no suspicion, no extra packets), and
        // never off a withheld echo, which has no verdict to be suspicious of;
        // neighbour pings during an incident are exactly the packets the
        // passive tier exists to withhold. `None` = not probed.
        let lan = match (&gw_addr, ping) {
            (Some(gw), Some(ping)) if !ping.reachable && tier.emits(EmissionClass::LanProbe) => {
                let mut ips = self.facts.arp_neighbor_ips().await;
                ips.retain(|ip| ip != gw);
                ips.truncate(LAN_PROBE_MAX);
                let probed = ips.len() as u16;
                let mut alive: u16 = 0;
                for ip in &ips {
                    if self.ping.ping_host(ip).await.reachable {
                        alive += 1;
                    }
                }
                (Some(probed), Some(alive))
            }
            _ => (None, None),
        };
        let direct = if tier.emits(EmissionClass::DirectProbe) {
            Some(self.tcp.connect_bound("1.1.1.1", 443, &iface).await)
        } else {
            None
        };
        let dhcp = self.facts.dhcp().await;
        let arp = match &gw_addr {
            Some(gw) => self.facts.gw_arp_mac(gw).await,
            None => None,
        };
        // The SSID and the link's identity triple — the AP associated with,
        // the interface's own MAC and the medium that MAC belongs to (measured
        // from the hardware-port table, not inferred from a readable Wi-Fi
        // name: the identity rules judge an `if_mac` change by it, and a
        // wired hop must never read as a roam). Local reads, no packet on
        // the wire, so they keep running in the passive tier too; recorded
        // every tick because a roam between twin SSIDs shows
        // up here and nowhere else (realm net-observer, node #59). All four
        // are read from the ONE interface this tick resolved; with no
        // interface there is nothing to read them from, and each is the
        // absence of a measurement.
        let (ssid, summary, if_mac, medium) = match phys_iface.as_deref() {
            Some(iface) => (
                self.facts.ssid(iface).await,
                self.facts.summary(iface).await,
                self.facts.if_mac(iface).await,
                self.facts.medium(iface).await,
            ),
            None => (None, LinkSummary::default(), None, None),
        };
        let wifi_present = self.facts.wifi_capture_present().await;
        // Two local reads, not probes: the fakeip pool's route egress and the
        // interface carrying sing-box's own TUN address (the sing-box-alive
        // fact). Both keep running in the passive tier like the other passive
        // facts, and both come from THIS tick so `fakeip-hijack` compares them
        // without skew.
        let fakeip_route_if = self.facts.fakeip_route_iface().await;
        let singbox_tun_if = self.facts.singbox_tun_iface().await;
        vec![Sample::Link(build_link_sample(
            ts_us,
            ping,
            direct,
            gw_addr,
            dhcp,
            arp,
            lan,
            fakeip_route_if,
            singbox_tun_if,
            ssid,
            summary,
            if_mac,
            medium,
            wifi_present,
        ))]
    }

    /// The tick preflight could not run (no physical interface resolved):
    /// nothing was measured, so every verdict is `SKIP` and every fact `None`.
    /// Never `NOGW` — that is a MEASURED verdict, an interface with no default
    /// route, and `gw-drop` fires on it (realm net-observer, node #25).
    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Link(LinkSample {
            ts_us,
            gw: GwVerdict::Skip,
            gw_rtt_ms: None,
            direct: TcpVerdict::Skip,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_core::PingOutcome;
    use std::sync::atomic::Ordering;
    use types::{LinkMedium, ProbingTier};

    /// A pinger that records the echoes actually sent — the gateway count and
    /// the exact neighbor addresses — so withholding can be asserted on the
    /// packet (not only on the verdict) and the neighbor selection on the
    /// addresses (not only on a count). `gw_alive`/`hosts_alive` script the
    /// outcomes.
    struct CountingPing {
        sent: Arc<std::sync::atomic::AtomicUsize>,
        lan_pinged: Arc<std::sync::Mutex<Vec<String>>>,
        gw_alive: bool,
        hosts_alive: bool,
    }
    impl Default for CountingPing {
        fn default() -> Self {
            Self {
                sent: Arc::default(),
                lan_pinged: Arc::default(),
                gw_alive: true,
                hosts_alive: true,
            }
        }
    }
    impl Pinger for CountingPing {
        async fn ping_gw(&self, _: &str) -> PingOutcome {
            self.sent.fetch_add(1, Ordering::Release);
            PingOutcome {
                reachable: self.gw_alive,
                rtt_ms: self.gw_alive.then_some(1.0),
            }
        }
        async fn ping_host(&self, addr: &str) -> PingOutcome {
            self.lan_pinged.lock().unwrap().push(addr.to_string());
            PingOutcome {
                reachable: self.hosts_alive,
                rtt_ms: self.hosts_alive.then_some(1.0),
            }
        }
    }
    /// A TCP prober that counts the connects actually attempted, so the
    /// passive tier can be asserted on the packet, not only on the verdict.
    #[derive(Default)]
    struct FakeTcp {
        sent: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl TcpProber for FakeTcp {
        async fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            self.sent.fetch_add(1, Ordering::Release);
            PingOutcome {
                reachable: true,
                rtt_ms: None,
            }
        }
    }
    /// Link facts with a scripted identity triple — `bssid` (now bundled with
    /// the lease pair into one [`LinkSummary`]), `if_mac` and `medium` — each
    /// returned exactly as set, so a test can hand the collector a
    /// determinable or an undeterminable identity and read what lands in the
    /// sample. `route_lookups` counts the `phys_iface` resolutions and
    /// `asked_for` records the interface each per-interface read was given,
    /// so a test can hold the collector to one route lookup per tick.
    struct FakeFacts {
        ready: bool,
        bssid: Option<String>,
        lease_start_us: Option<i64>,
        lease_secs: Option<u32>,
        if_mac: Option<String>,
        medium: Option<LinkMedium>,
        route_lookups: Arc<std::sync::atomic::AtomicUsize>,
        asked_for: Arc<std::sync::Mutex<Vec<String>>>,
    }
    impl Default for FakeFacts {
        fn default() -> Self {
            Self {
                ready: true,
                bssid: Some("3c:22:fb:12:34:56".into()),
                lease_start_us: None,
                lease_secs: None,
                if_mac: Some("f0:18:98:0a:0b:0c".into()),
                medium: Some(LinkMedium::Wifi),
                route_lookups: Arc::default(),
                asked_for: Arc::default(),
            }
        }
    }
    impl FakeFacts {
        fn asked(&self, iface: &str) {
            self.asked_for.lock().unwrap().push(iface.to_string());
        }
    }
    impl LinkFacts for FakeFacts {
        async fn default_gw(&self) -> Option<String> {
            Some("10.0.0.1".into())
        }
        async fn phys_iface(&self) -> Option<String> {
            self.route_lookups
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some("en0".into())
        }
        async fn dhcp(&self) -> (Option<String>, Option<String>) {
            (None, None)
        }
        async fn gw_arp_mac(&self, _: &str) -> Option<String> {
            None
        }
        async fn arp_neighbor_ips(&self) -> Vec<String> {
            // Five candidates INCLUDING the gateway, so the collector's own
            // filter and the LAN_PROBE_MAX cap are both observable.
            vec![
                "10.0.0.1".into(),
                "10.0.0.11".into(),
                "10.0.0.12".into(),
                "10.0.0.13".into(),
                "10.0.0.14".into(),
            ]
        }
        async fn fakeip_route_iface(&self) -> Option<String> {
            Some("utun8".into())
        }
        async fn singbox_tun_iface(&self) -> Option<String> {
            Some("utun8".into())
        }
        async fn ssid(&self, iface: &str) -> Option<String> {
            self.asked(iface);
            None
        }
        async fn summary(&self, iface: &str) -> LinkSummary {
            self.asked(iface);
            LinkSummary {
                bssid: self.bssid.clone(),
                lease_start_us: self.lease_start_us,
                lease_secs: self.lease_secs,
            }
        }
        async fn if_mac(&self, iface: &str) -> Option<String> {
            self.asked(iface);
            self.if_mac.clone()
        }
        async fn medium(&self, iface: &str) -> Option<LinkMedium> {
            self.asked(iface);
            self.medium
        }
        async fn wifi_capture_present(&self) -> bool {
            false
        }
        async fn preflight(&self) -> Readiness {
            if self.ready {
                Readiness::Ready
            } else {
                Readiness::Unavailable("no physical interface".into())
            }
        }
    }

    /// The tier every existing test runs under: active, so the probes it
    /// asserts on are actually sent. The passive tests hand in their own.
    fn active() -> Arc<ProbingState> {
        Arc::new(ProbingState::new(ProbingTier::Active))
    }

    fn collector_with_ping(ping: CountingPing) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            ping,
            FakeTcp::default(),
            FakeFacts::default(),
            Duration::from_secs(15),
            active(),
        )
    }

    fn collector_with_facts(facts: FakeFacts) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            CountingPing::default(),
            FakeTcp::default(),
            facts,
            Duration::from_secs(15),
            active(),
        )
    }

    fn collector_with_tier(
        ready: bool,
        probing: Arc<ProbingState>,
    ) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            CountingPing::default(),
            FakeTcp::default(),
            FakeFacts {
                ready,
                ..FakeFacts::default()
            },
            Duration::from_secs(15),
            probing,
        )
    }

    fn collector(ready: bool) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        collector_with_tier(ready, active())
    }

    #[tokio::test]
    async fn unavailable_preflight_is_not_ready() {
        assert!(!collector(false).preflight().await.is_ready());
    }

    /// The SKIP tick — preflight unavailable, no physical interface resolved
    /// — measured nothing, so every verdict on it is `SKIP` and every fact
    /// `None`. It must NOT read `NOGW`: that is a measured verdict ("an
    /// interface with no default route") and `gw-drop` fires on it. Observed
    /// live: a boot before any interface was up opened `gw-drop … gateway
    /// NOGW` from a tick that never looked at the gateway (realm
    /// net-observer, node #25).
    #[test]
    fn the_skip_tick_reads_skip_not_nogw() {
        let samples = collector(false).skip(42);
        assert_eq!(samples.len(), 1, "SKIP, never silence");
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.ts_us, 42);
        assert_eq!(
            l.gw,
            GwVerdict::Skip,
            "a tick that measured nothing is not NOGW"
        );
        assert_eq!(l.gw_rtt_ms, None);
        assert_eq!(l.direct, TcpVerdict::Skip);
        assert_eq!(l.direct_rtt_ms, None);
        // No interface: no lease, no ARP, no identity — absence, not a value.
        assert_eq!(l.dhcp_router, None);
        assert_eq!(l.gw_arp_mac, None);
        assert_eq!(l.ssid, None);
        assert_eq!(l.if_mac, None);
        assert_eq!(l.medium, None);
    }

    #[tokio::test]
    async fn ready_preflight_collects_one_link_sample() {
        let c = collector(true);
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Link(_)));
    }

    /// The fakeip-pool egress interface flows through to the sample untouched
    /// — it is a passive fact, present on healthy and failed ticks alike.
    #[tokio::test]
    async fn the_fakeip_route_interface_flows_through() {
        let c = collector(true);
        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.fakeip_route_if.as_deref(), Some("utun8"));
    }

    /// The identity pair the facts port reads — the AP's BSSID and the
    /// interface's own MAC — lands in the sample every tick, untouched, and
    /// `if_mac_private` is folded from that MAC's own U/L bit.
    #[tokio::test]
    async fn the_link_identity_lands_in_the_sample() {
        let c = collector(true);
        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.bssid.as_deref(), Some("3c:22:fb:12:34:56"));
        assert_eq!(l.if_mac.as_deref(), Some("f0:18:98:0a:0b:0c"));
        // f0:.. is a real OUI: the hardware-burned address, not private.
        assert_eq!(l.if_mac_private, Some(false));
    }

    /// The lease pair the ONE `summary` call carries alongside the BSSID
    /// lands in the sample every tick, untouched (realm net-observer, node
    /// #93 item 1; node #109 item 1).
    #[tokio::test]
    async fn the_lease_pair_lands_in_the_sample() {
        let c = collector_with_facts(FakeFacts {
            lease_start_us: Some(1_758_066_844_000_000),
            lease_secs: Some(86400),
            ..FakeFacts::default()
        });
        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.lease_start_us, Some(1_758_066_844_000_000));
        assert_eq!(l.lease_secs, Some(86400));
    }

    /// An identity the facts port could not determine stays `None` in the
    /// sample: not associated / not readable is recorded as absence, never as
    /// a placeholder address a roam comparison could mistake for a real one.
    #[tokio::test]
    async fn an_undeterminable_link_identity_stays_none() {
        let c = collector_with_facts(FakeFacts {
            bssid: None,
            if_mac: None,
            medium: None,
            ..FakeFacts::default()
        });
        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.bssid, None);
        assert_eq!(l.if_mac, None);
        assert_eq!(l.medium, None);
    }

    /// The medium the facts port measured lands in the sample as read —
    /// Wi-Fi, wired, or not determinable — and is never derived from whether
    /// the Wi-Fi identity was readable: a Wi-Fi tick whose SSID and BSSID
    /// are both unreadable (the root reader's view) still says `Wifi`, and a
    /// wired tick still says `Wired` with no Wi-Fi identity at all.
    #[tokio::test]
    async fn the_medium_lands_in_the_sample_unchanged() {
        for medium in [Some(LinkMedium::Wifi), Some(LinkMedium::Wired), None] {
            let c = collector_with_facts(FakeFacts {
                bssid: None,
                if_mac: Some("f0:18:98:0a:0b:0c".into()),
                medium,
                ..FakeFacts::default()
            });
            let samples = c.collect(42).await;
            let Sample::Link(l) = &samples[0] else {
                panic!("expected a link sample")
            };
            assert_eq!(l.medium, medium, "medium {medium:?} must land as read");
            assert_eq!(l.bssid, None);
        }
    }

    /// One route lookup per tick: the SSID and the identity triple are read
    /// from the interface the tick resolved, never each from a resolution of
    /// its own. Dies under per-read `phys_iface` calls — a default-route
    /// move between two of them (a dock or undock) then stamps one sample
    /// with one adapter's medium and the other's MAC, a roam that never was.
    #[tokio::test]
    async fn the_identity_triple_is_read_from_the_interface_the_tick_resolved() {
        let facts = FakeFacts::default();
        let route_lookups = facts.route_lookups.clone();
        let asked_for = facts.asked_for.clone();
        let c = collector_with_facts(facts);
        c.collect(42).await;
        assert_eq!(
            route_lookups.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the tick resolves the interface once"
        );
        assert_eq!(
            *asked_for.lock().unwrap(),
            vec!["en0"; 4],
            "ssid, summary, if_mac and medium are all read from that interface"
        );
    }

    /// A silent gateway triggers the probe-on-suspicion: at most
    /// [`LAN_PROBE_MAX`] non-gateway ARP entries are pinged and the counts land
    /// in the sample. Asserted on the ADDRESSES pinged, not only a count: the
    /// fake ARP cache holds five candidates including the gateway itself, so
    /// dropping the gateway filter would ping `10.0.0.1` and dropping the cap
    /// would ping `10.0.0.14` — either changes the list, while a bare count of
    /// three would notice neither.
    #[tokio::test]
    async fn a_failed_gateway_tick_probes_lan_neighbors() {
        let ping = CountingPing {
            gw_alive: false,
            ..CountingPing::default()
        };
        let c = collector_with_ping(ping);
        let lan_pinged = c.ping.lan_pinged.clone();

        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Fail);
        assert_eq!(l.lan_probed, Some(3));
        assert_eq!(l.lan_alive, Some(3));
        assert_eq!(
            *lan_pinged.lock().unwrap(),
            vec!["10.0.0.11", "10.0.0.12", "10.0.0.13"],
            "the gateway is filtered out and the cap stops before 10.0.0.14"
        );
    }

    /// A healthy gateway means no suspicion: no neighbor is pinged and the
    /// fields read `None` — "not probed", never a zero that would look like a
    /// dead segment.
    #[tokio::test]
    async fn a_healthy_gateway_tick_probes_no_neighbors() {
        let c = collector(true);
        let lan_pinged = c.ping.lan_pinged.clone();

        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Ok);
        assert_eq!(l.lan_probed, None);
        assert_eq!(l.lan_alive, None);
        assert!(lan_pinged.lock().unwrap().is_empty());
    }

    /// The passive tier puts NOTHING on the wire: no echo, no direct connect,
    /// no neighbour ping — even with a gateway that would read FAIL, which is
    /// the one tick the neighbour probe fires on. The tick still lands, every
    /// probe verdict `SKIP`, and the local facts still flow through. Asserted
    /// on the packets (counters) as well as on the verdicts.
    #[tokio::test]
    async fn passive_sends_nothing_and_still_emits_a_skip_sample() {
        let probing = Arc::new(ProbingState::new(ProbingTier::Passive));
        let c = LinkCollector::new(
            CountingPing {
                gw_alive: false,
                ..CountingPing::default()
            },
            FakeTcp::default(),
            FakeFacts::default(),
            Duration::from_secs(15),
            probing.clone(),
        );
        let echoes = c.ping.sent.clone();
        let lan_pinged = c.ping.lan_pinged.clone();
        let connects = c.tcp.sent.clone();

        let samples = c.collect(42).await;
        assert_eq!(samples.len(), 1, "passive must not silence the tick");
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Skip);
        assert_eq!(l.gw_rtt_ms, None);
        assert_eq!(l.direct, TcpVerdict::Skip);
        assert_eq!(l.direct_rtt_ms, None);
        assert_eq!(l.lan_probed, None);
        assert_eq!(l.lan_alive, None);
        assert_eq!(echoes.load(Ordering::Acquire), 0, "no echo");
        assert_eq!(connects.load(Ordering::Acquire), 0, "no direct connect");
        assert!(lan_pinged.lock().unwrap().is_empty(), "no neighbour ping");
        // The passive facts are read as on any other tick.
        assert_eq!(l.bssid.as_deref(), Some("3c:22:fb:12:34:56"));
        assert_eq!(l.fakeip_route_if.as_deref(), Some("utun8"));

        // Switching to active takes effect on the next tick: the echo and the
        // direct connect are sent again.
        probing.set(ProbingTier::Active);
        let samples = c.collect(43).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Fail);
        assert_eq!(l.direct, TcpVerdict::Ok);
        assert_eq!(echoes.load(Ordering::Acquire), 1);
        assert_eq!(connects.load(Ordering::Acquire), 1);
        assert_eq!(l.lan_probed, Some(3), "suspicion probes again once active");
    }
}
