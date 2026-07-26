//! Static [`META`] and the [`DnsCollector`] that wires the `dns` resolver port
//! into the [`Collector`] abstraction the daemon drives.

use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::{DnsSample, DnsVerdict, Sample};

use crate::facts::DnsFacts;
use crate::sample::{ResolvedProbe, build_dns_samples};

/// Static metadata for the `dns` collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "dns",
    supported_os: &[Os::MacOs],
};

/// The `dns` collector: resolver probes (sing-box TUN DNS, DHCP resolver, DoH,
/// control domain), polled on a fixed interval.
///
/// Generic over its [`DnsFacts`] port for static dispatch — the async probe
/// methods make the trait non-`dyn`-compatible, so the daemon enumerates the
/// concrete collector types instead of boxing.
pub struct DnsCollector<F: DnsFacts> {
    facts: F,
    interval: Duration,
}

impl<F: DnsFacts> DnsCollector<F> {
    /// Construct a `dns` collector from its resolver port and poll interval.
    pub fn new(facts: F, interval: Duration) -> Self {
        Self { facts, interval }
    }
}

impl<F: DnsFacts> Collector for DnsCollector<F> {
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
        let pairs = self.facts.probes().await;
        let mut resolved = Vec::with_capacity(pairs.len());
        for (probe, server) in pairs {
            let (verdict, ip, rtt_ms) = self.facts.resolve(&probe, &server).await;
            resolved.push(ResolvedProbe {
                probe,
                server,
                verdict,
                ip,
                rtt_ms,
            });
        }
        build_dns_samples(ts_us, resolved)
            .into_iter()
            .map(Sample::Dns)
            .collect()
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Dns(DnsSample {
            ts_us,
            probe: "-".into(),
            server: "-".into(),
            verdict: DnsVerdict::Skip,
            ip: None,
            rtt_ms: None,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Facts(Readiness);
    impl DnsFacts for Facts {
        async fn resolve(&self, _: &str, _: &str) -> (DnsVerdict, Option<String>, Option<f64>) {
            (DnsVerdict::Ok, Some("10.0.0.1".into()), Some(2.0))
        }
        async fn probes(&self) -> Vec<(String, String)> {
            vec![("nks".into(), "sb".into())]
        }
        async fn preflight(&self) -> Readiness {
            self.0.clone()
        }
    }

    fn collector(readiness: Readiness) -> DnsCollector<Facts> {
        DnsCollector::new(Facts(readiness), Duration::from_secs(15))
    }

    #[tokio::test]
    async fn preflight_unavailable_is_not_ready() {
        let c = collector(Readiness::Unavailable("no resolver path configured".into()));
        assert!(!c.preflight().await.is_ready());
    }

    #[tokio::test]
    async fn ready_collect_yields_dns_samples() {
        let c = collector(Readiness::Ready);
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(7).await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Dns(_)));
    }

    #[test]
    fn skip_yields_one_dns_skip_sample() {
        let c = collector(Readiness::Ready);
        let samples = c.skip(7);
        assert_eq!(samples.len(), 1);
        match &samples[0] {
            Sample::Dns(d) => assert_eq!(d.verdict, DnsVerdict::Skip),
            other => panic!("expected Sample::Dns, got {other:?}"),
        }
    }
}
