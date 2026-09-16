//! Static [`META`] and the [`LinkCollector`] that wires the `link` probe ports
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use collector_core::{
    Collector, CollectorMeta, Os, PingOutcome, Pinger, Readiness, Source, TcpProber,
};
use types::{GwVerdict, LinkSample, Sample, TcpVerdict};

use crate::facts::LinkFacts;
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
    /// The operator's "quiet" switch, shared with the control socket: while set,
    /// this collector addresses NO packet at the gateway — the ICMP echo is not
    /// sent and the tick reports [`GwVerdict::Skip`]. Reading the ARP table and
    /// the DHCP lease is passive and continues. Process-scoped and never
    /// persisted: a restart resumes normal probing.
    quiet: Arc<AtomicBool>,
}

impl<P, T, F> LinkCollector<P, T, F>
where
    P: Pinger,
    T: TcpProber,
    F: LinkFacts,
{
    /// Construct a `link` collector from its probe ports, poll interval and the
    /// shared `quiet` flag (see [`LinkCollector::quiet`]).
    pub fn new(ping: P, tcp: T, facts: F, interval: Duration, quiet: Arc<AtomicBool>) -> Self {
        Self {
            ping,
            tcp,
            facts,
            interval,
            quiet,
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
        let iface = self.facts.phys_iface().await.unwrap_or_default();
        // Read the switch ONCE per tick, so the packet that is skipped and the
        // verdict that reports it can never disagree.
        let quiet = self.quiet.load(Ordering::Acquire);
        let ping = match &gw_addr {
            // Quiet: the echo is never sent. The placeholder outcome is not a
            // measurement and `build_link_sample` does not read it — the verdict
            // is `SKIP`.
            Some(_) if quiet => PingOutcome {
                reachable: false,
                rtt_ms: None,
            },
            Some(gw) => self.ping.ping_gw(gw).await,
            None => PingOutcome {
                reachable: false,
                rtt_ms: None,
            },
        };
        // Probe-on-suspicion: only on a tick whose gateway verdict will read
        // FAIL. Never on a healthy tick (no suspicion, no extra packets), and
        // never under quiet — neighbor pings during an incident are exactly the
        // packets quiet exists to withhold. `None` = not probed.
        let lan = match &gw_addr {
            Some(gw) if !quiet && !ping.reachable => {
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
        let direct = self.tcp.connect_bound("1.1.1.1", 443, &iface).await;
        let dhcp = self.facts.dhcp().await;
        let arp = match &gw_addr {
            Some(gw) => self.facts.gw_arp_mac(gw).await,
            None => None,
        };
        let ssid = self.facts.ssid().await;
        // The link's identity pair: the AP associated with and the interface's
        // own MAC. Two local reads (no packet on the wire), so they keep
        // running under quiet mode. Recorded every tick because a roam between
        // twin SSIDs shows up here and nowhere else (realm net-observer,
        // node #59).
        let bssid = self.facts.bssid().await;
        let if_mac = self.facts.if_mac().await;
        // The medium `if_mac` belongs to, measured from the hardware-port table
        // (not inferred from a readable Wi-Fi name): the identity rules judge
        // an `if_mac` change by it, and a wired hop must never read as a roam.
        let medium = self.facts.medium().await;
        let wifi_present = self.facts.wifi_capture_present().await;
        // Two local reads, not probes: the fakeip pool's route egress and the
        // interface carrying sing-box's own TUN address (the sing-box-alive
        // fact). Both keep running under quiet mode like the other passive
        // facts, and both come from THIS tick so `fakeip-hijack` compares them
        // without skew.
        let fakeip_route_if = self.facts.fakeip_route_iface().await;
        let singbox_tun_if = self.facts.singbox_tun_iface().await;
        vec![Sample::Link(build_link_sample(
            ts_us,
            ping,
            direct,
            quiet,
            gw_addr,
            dhcp,
            arp,
            lan,
            fakeip_route_if,
            singbox_tun_if,
            ssid,
            bssid,
            if_mac,
            medium,
            wifi_present,
        ))]
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Link(LinkSample {
            ts_us,
            gw: GwVerdict::NoGw,
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
    use types::LinkMedium;

    /// A pinger that records the echoes actually sent — the gateway count and
    /// the exact neighbor addresses — so "quiet" can be asserted on the packet
    /// (not only on the verdict) and the neighbor selection on the addresses
    /// (not only on a count). `gw_alive`/`hosts_alive` script the outcomes.
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
    struct FakeTcp;
    impl TcpProber for FakeTcp {
        async fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: true,
                rtt_ms: None,
            }
        }
    }
    /// Link facts with a scripted identity pair: `bssid`/`if_mac` are returned
    /// exactly as set, so a test can hand the collector a determinable or an
    /// undeterminable identity and read what lands in the sample.
    struct FakeFacts {
        ready: bool,
        bssid: Option<String>,
        if_mac: Option<String>,
        medium: Option<LinkMedium>,
    }
    impl Default for FakeFacts {
        fn default() -> Self {
            Self {
                ready: true,
                bssid: Some("3c:22:fb:12:34:56".into()),
                if_mac: Some("f0:18:98:0a:0b:0c".into()),
                medium: Some(LinkMedium::Wifi),
            }
        }
    }
    impl LinkFacts for FakeFacts {
        async fn default_gw(&self) -> Option<String> {
            Some("10.0.0.1".into())
        }
        async fn phys_iface(&self) -> Option<String> {
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
        async fn ssid(&self) -> Option<String> {
            None
        }
        async fn bssid(&self) -> Option<String> {
            self.bssid.clone()
        }
        async fn if_mac(&self) -> Option<String> {
            self.if_mac.clone()
        }
        async fn medium(&self) -> Option<LinkMedium> {
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

    fn collector_with_ping(
        ping: CountingPing,
        quiet: Arc<AtomicBool>,
    ) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            ping,
            FakeTcp,
            FakeFacts::default(),
            Duration::from_secs(15),
            quiet,
        )
    }

    fn collector_with_facts(facts: FakeFacts) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            CountingPing::default(),
            FakeTcp,
            facts,
            Duration::from_secs(15),
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn collector_with_quiet(
        ready: bool,
        quiet: Arc<AtomicBool>,
    ) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            CountingPing::default(),
            FakeTcp,
            FakeFacts {
                ready,
                ..FakeFacts::default()
            },
            Duration::from_secs(15),
            quiet,
        )
    }

    fn collector(ready: bool) -> LinkCollector<CountingPing, FakeTcp, FakeFacts> {
        collector_with_quiet(ready, Arc::new(AtomicBool::new(false)))
    }

    #[tokio::test]
    async fn unavailable_preflight_is_not_ready() {
        assert!(!collector(false).preflight().await.is_ready());
    }

    /// Quiet sends no echo at all and still emits its tick, with the gateway
    /// verdict `SKIP` — the daemon goes quiet on the wire, never in the record.
    #[tokio::test]
    async fn quiet_sends_no_echo_and_still_emits_a_skip_sample() {
        let quiet = Arc::new(AtomicBool::new(true));
        let c = collector_with_quiet(true, quiet.clone());
        let sent = c.ping.sent.clone();

        let samples = c.collect(42).await;
        assert_eq!(samples.len(), 1, "quiet must not silence the tick");
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Skip);
        assert_eq!(l.gw_rtt_ms, None);
        assert_eq!(
            sent.load(Ordering::Acquire),
            0,
            "quiet must address no packet at the gateway"
        );

        // Flipping the shared flag back takes effect on the next tick.
        quiet.store(false, Ordering::Release);
        let samples = c.collect(43).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Ok);
        assert_eq!(sent.load(Ordering::Acquire), 1);
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
    /// interface's own MAC — lands in the sample every tick, untouched.
    #[tokio::test]
    async fn the_link_identity_lands_in_the_sample() {
        let c = collector(true);
        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.bssid.as_deref(), Some("3c:22:fb:12:34:56"));
        assert_eq!(l.if_mac.as_deref(), Some("f0:18:98:0a:0b:0c"));
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
        let c = collector_with_ping(ping, Arc::new(AtomicBool::new(false)));
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

    /// Quiet must suppress the neighbor pings too: they are addressed packets,
    /// and pinging the segment during an incident is exactly what a network
    /// admin sees. Dies under gating on the placeholder ping outcome (which
    /// reads unreachable under quiet) instead of on the quiet flag.
    #[tokio::test]
    async fn quiet_suppresses_the_neighbor_probes_too() {
        let ping = CountingPing {
            gw_alive: false,
            ..CountingPing::default()
        };
        let c = collector_with_ping(ping, Arc::new(AtomicBool::new(true)));
        let lan_pinged = c.ping.lan_pinged.clone();

        let samples = c.collect(42).await;
        let Sample::Link(l) = &samples[0] else {
            panic!("expected a link sample")
        };
        assert_eq!(l.gw, GwVerdict::Skip);
        assert_eq!(l.lan_probed, None);
        assert_eq!(l.lan_alive, None);
        assert!(
            lan_pinged.lock().unwrap().is_empty(),
            "quiet must address no packet at the segment"
        );
    }
}
