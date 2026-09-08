//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber`/`StallProbe` ports into the [`build_proxy_samples`]
//! mapping.

use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source, TcpProber};
use types::{ProxySample, Sample, TcpVerdict};

use crate::probes::{ProxyFacts, StallProbe};
use crate::proxy::build_proxy_samples;

/// Static metadata for the proxy collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "proxy",
    supported_os: &[Os::MacOs],
};

/// Interval collector for per-upstream-server TCP reachability, the TUN 204
/// probe, the active upstream node selection, and the established-flow
/// discriminator (held reference streams checked each tick).
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
}

impl<T: TcpProber, F: ProxyFacts, S: StallProbe> ProxyCollector<T, F, S> {
    /// Construct a proxy collector from its ports and cadence.
    pub fn new(
        tcp: T,
        facts: F,
        stall: S,
        tun_url: String,
        iface: String,
        interval: Duration,
    ) -> Self {
        Self {
            tcp,
            facts,
            stall,
            tun_url,
            iface,
            interval,
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
        // Await the probes, then a sync `build_*` composes the samples.
        let tun_code = self.facts.tun_probe(&self.tun_url).await;
        let selector = self.facts.selector().await;
        // The held-stream check runs in the same tick as the fresh probes, so
        // "fresh OK while established dead" is one cohort, not a correlation.
        let stall = self.stall.check().await;
        let endpoints = self.facts.server_endpoints().await;
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
        build_proxy_samples(ts_us, tun_code, selector, stall, probed)
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
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{StallReading, StreamCheck};
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
            vec!["1.1.1.1:443".into()]
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

    /// A scripted stall probe: both held streams alive and 60s old.
    struct FakeStall;
    impl StallProbe for FakeStall {
        async fn check(&self) -> StallReading {
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
    }

    fn collector(readiness: Readiness) -> ProxyCollector<T, Facts, FakeStall> {
        ProxyCollector::new(
            T,
            Facts(readiness),
            FakeStall,
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
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        // The held-stream reading reaches the row.
        assert_eq!(p.est_tun_alive, Some(true));
        assert_eq!(p.est_direct_age_s, Some(60));
    }
}
