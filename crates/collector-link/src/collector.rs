//! Static [`META`] and the [`LinkCollector`] that wires the `link` probe ports
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Pinger, Readiness, Source, TcpProber};
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
pub struct LinkCollector {
    ping: Arc<dyn Pinger>,
    tcp: Arc<dyn TcpProber>,
    facts: Arc<dyn LinkFacts>,
    interval: Duration,
}

impl LinkCollector {
    /// Construct a `link` collector from its probe ports and poll interval.
    pub fn new(
        ping: Arc<dyn Pinger>,
        tcp: Arc<dyn TcpProber>,
        facts: Arc<dyn LinkFacts>,
        interval: Duration,
    ) -> Self {
        Self {
            ping,
            tcp,
            facts,
            interval,
        }
    }
}

impl Collector for LinkCollector {
    fn meta(&self) -> &'static CollectorMeta {
        &META
    }

    fn source(&self) -> Source {
        Source::Interval(self.interval)
    }

    fn preflight(&self) -> Readiness {
        self.facts.preflight()
    }

    fn collect(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Link(build_link_sample(
            ts_us,
            &*self.ping,
            &*self.tcp,
            &*self.facts,
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
    use collector_core::PingOutcome;

    struct FakePing;
    impl Pinger for FakePing {
        fn ping_gw(&self, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: true,
                rtt_ms: Some(1.0),
            }
        }
    }
    struct FakeTcp;
    impl TcpProber for FakeTcp {
        fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
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
        fn default_gw(&self) -> Option<String> {
            Some("10.0.0.1".into())
        }
        fn phys_iface(&self) -> Option<String> {
            Some("en0".into())
        }
        fn dhcp(&self) -> (Option<String>, Option<String>) {
            (None, None)
        }
        fn gw_arp_mac(&self, _: &str) -> Option<String> {
            None
        }
        fn ssid(&self) -> Option<String> {
            None
        }
        fn wifi_capture_present(&self) -> bool {
            false
        }
        fn preflight(&self) -> Readiness {
            if self.ready {
                Readiness::Ready
            } else {
                Readiness::Unavailable("no physical interface".into())
            }
        }
    }

    fn collector(ready: bool) -> LinkCollector {
        LinkCollector::new(
            Arc::new(FakePing),
            Arc::new(FakeTcp),
            Arc::new(FakeFacts { ready }),
            Duration::from_secs(15),
        )
    }

    #[test]
    fn unavailable_preflight_is_not_ready() {
        assert!(!collector(false).preflight().is_ready());
    }

    #[test]
    fn ready_preflight_collects_one_link_sample() {
        let c = collector(true);
        assert!(c.preflight().is_ready());
        let samples = c.collect(42);
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Link(_)));
    }
}
