//! Static [`META`] and the [`LinkCollector`] that wires the `link` probe ports
//! into the [`Collector`] abstraction the daemon drives.

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
}

impl<P, T, F> LinkCollector<P, T, F>
where
    P: Pinger,
    T: TcpProber,
    F: LinkFacts,
{
    /// Construct a `link` collector from its probe ports and poll interval.
    pub fn new(ping: P, tcp: T, facts: F, interval: Duration) -> Self {
        Self {
            ping,
            tcp,
            facts,
            interval,
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
        let ping = match &gw_addr {
            Some(gw) => self.ping.ping_gw(gw).await,
            None => PingOutcome {
                reachable: false,
                rtt_ms: None,
            },
        };
        let direct = self.tcp.connect_bound("1.1.1.1", 443, &iface).await;
        let dhcp = self.facts.dhcp().await;
        let arp = match &gw_addr {
            Some(gw) => self.facts.gw_arp_mac(gw).await,
            None => None,
        };
        let ssid = self.facts.ssid().await;
        let wifi_present = self.facts.wifi_capture_present().await;
        vec![Sample::Link(build_link_sample(
            ts_us,
            ping,
            direct,
            gw_addr,
            dhcp,
            arp,
            ssid,
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
            wifi_capture_present: false,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePing;
    impl Pinger for FakePing {
        async fn ping_gw(&self, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: true,
                rtt_ms: Some(1.0),
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
    struct FakeFacts {
        ready: bool,
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
        async fn ssid(&self) -> Option<String> {
            None
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

    fn collector(ready: bool) -> LinkCollector<FakePing, FakeTcp, FakeFacts> {
        LinkCollector::new(
            FakePing,
            FakeTcp,
            FakeFacts { ready },
            Duration::from_secs(15),
        )
    }

    #[tokio::test]
    async fn unavailable_preflight_is_not_ready() {
        assert!(!collector(false).preflight().await.is_ready());
    }

    #[tokio::test]
    async fn ready_preflight_collects_one_link_sample() {
        let c = collector(true);
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Link(_)));
    }
}
