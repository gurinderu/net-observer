//! Static [`META`] and the [`DnsCollector`] that wires the `dns` resolver port
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::{DnsSample, DnsVerdict, Sample};

use crate::facts::DnsFacts;
use crate::sample::build_dns_samples;

/// Static metadata for the `dns` collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "dns",
    supported_os: &[Os::MacOs],
};

/// The `dns` collector: resolver probes (sing-box TUN DNS, DHCP resolver, DoH,
/// control domain), polled on a fixed interval.
pub struct DnsCollector {
    facts: Arc<dyn DnsFacts>,
    interval: Duration,
}

impl DnsCollector {
    /// Construct a `dns` collector from its resolver port and poll interval.
    pub fn new(facts: Arc<dyn DnsFacts>, interval: Duration) -> Self {
        Self { facts, interval }
    }
}

impl Collector for DnsCollector {
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
        build_dns_samples(ts_us, &*self.facts)
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
        fn resolve(&self, _: &str, _: &str) -> (DnsVerdict, Option<String>, Option<f64>) {
            (DnsVerdict::Ok, Some("10.0.0.1".into()), Some(2.0))
        }
        fn probes(&self) -> Vec<(String, String)> {
            vec![("nks".into(), "sb".into())]
        }
        fn preflight(&self) -> Readiness {
            self.0.clone()
        }
    }

    fn collector(readiness: Readiness) -> DnsCollector {
        DnsCollector::new(Arc::new(Facts(readiness)), Duration::from_secs(15))
    }

    #[test]
    fn preflight_unavailable_is_not_ready() {
        let c = collector(Readiness::Unavailable("no resolver path configured".into()));
        assert!(!c.preflight().is_ready());
    }

    #[test]
    fn ready_collect_yields_dns_samples() {
        let c = collector(Readiness::Ready);
        assert!(c.preflight().is_ready());
        let samples = c.collect(7);
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
