//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber` ports into the [`build_proxy_samples`] mapping.

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
///
/// Static dispatch over the [`TcpProber`] and [`ProxyFacts`] ports: native
/// `async fn` in traits is not `dyn`-compatible, so the ports are generic
/// type parameters (the daemon monomorphizes them via `enum AnyCollector`).
pub struct ProxyCollector<T: TcpProber, F: ProxyFacts> {
    tcp: T,
    facts: F,
    tun_url: String,
    iface: String,
    interval: Duration,
}

impl<T: TcpProber, F: ProxyFacts> ProxyCollector<T, F> {
    /// Construct a proxy collector from its ports and cadence.
    pub fn new(tcp: T, facts: F, tun_url: String, iface: String, interval: Duration) -> Self {
        Self {
            tcp,
            facts,
            tun_url,
            iface,
            interval,
        }
    }
}

impl<T: TcpProber, F: ProxyFacts> Collector for ProxyCollector<T, F> {
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
        // Await the probes, then a sync `build_*` composes the samples.
        let tun_code = self.facts.tun_probe(&self.tun_url).await;
        let selector = self.facts.selector().await;
        let ips = self.facts.server_endpoints().await;
        let mut probed = Vec::with_capacity(ips.len());
        for ip in ips {
            let o = self.tcp.connect_bound(&ip, 443, &self.iface).await;
            probed.push((ip, o));
        }
        build_proxy_samples(ts_us, tun_code, selector, probed)
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
        async fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: true,
                rtt_ms: Some(9.0),
            }
        }
    }

    struct Facts(Readiness);
    impl ProxyFacts for Facts {
        async fn server_endpoints(&self) -> Vec<String> {
            vec!["1.1.1.1".into()]
        }
        async fn tun_probe(&self, _: &str) -> Option<u16> {
            Some(204)
        }
        async fn selector(&self) -> Option<String> {
            Some("node-a".into())
        }
        async fn preflight(&self) -> Readiness {
            self.0.clone()
        }
    }

    fn collector(readiness: Readiness) -> ProxyCollector<T, Facts> {
        ProxyCollector::new(
            T,
            Facts(readiness),
            "http://x/204".into(),
            "en0".into(),
            Duration::from_secs(15),
        )
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
        assert!(matches!(samples[0], Sample::Proxy(_)));
    }
}
