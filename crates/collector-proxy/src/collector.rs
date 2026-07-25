//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber` ports into the [`build_proxy_samples`] mapping.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source, TcpProber};
use types::{ProxySample, Sample, TcpVerdict};

use crate::probes::ProxyFacts;
use crate::proxy::build_proxy_samples;

/// Static metadata for the proxy collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "proxy",
    supported_os: &[Os::MacOs],
};

/// Interval collector for per-upstream-server TCP reachability, the TUN 204
/// probe, and the active upstream node selection.
pub struct ProxyCollector {
    tcp: Arc<dyn TcpProber>,
    facts: Arc<dyn ProxyFacts>,
    tun_url: String,
    iface: String,
    interval: Duration,
}

impl ProxyCollector {
    /// Construct a proxy collector from its ports and cadence.
    pub fn new(
        tcp: Arc<dyn TcpProber>,
        facts: Arc<dyn ProxyFacts>,
        tun_url: String,
        iface: String,
        interval: Duration,
    ) -> Self {
        Self {
            tcp,
            facts,
            tun_url,
            iface,
            interval,
        }
    }
}

impl Collector for ProxyCollector {
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
        build_proxy_samples(ts_us, &*self.tcp, &*self.facts, &self.tun_url, &self.iface)
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
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_core::PingOutcome;

    struct T;
    impl TcpProber for T {
        fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: true,
                rtt_ms: Some(9.0),
            }
        }
    }

    struct Facts(Readiness);
    impl ProxyFacts for Facts {
        fn server_endpoints(&self) -> Vec<String> {
            vec!["1.1.1.1".into()]
        }
        fn tun_probe(&self, _: &str) -> Option<u16> {
            Some(204)
        }
        fn selector(&self) -> Option<String> {
            Some("node-a".into())
        }
        fn preflight(&self) -> Readiness {
            self.0.clone()
        }
    }

    fn collector(readiness: Readiness) -> ProxyCollector {
        ProxyCollector::new(
            Arc::new(T),
            Arc::new(Facts(readiness)),
            "http://x/204".into(),
            "en0".into(),
            Duration::from_secs(15),
        )
    }

    #[test]
    fn preflight_unavailable_is_not_ready() {
        let c = collector(Readiness::Unavailable(
            "no upstream proxy facts available".into(),
        ));
        assert!(!c.preflight().is_ready());
    }

    #[test]
    fn ready_collect_yields_one_proxy_sample() {
        let c = collector(Readiness::Ready);
        assert!(c.preflight().is_ready());
        let samples = c.collect(7);
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Proxy(_)));
    }
}
