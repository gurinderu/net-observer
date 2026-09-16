//! Static [`META`] and the [`DnsCollector`] that wires the `dns` resolver port
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, ProbingState, Readiness, Source};
use types::{DnsSample, DnsVerdict, EmissionClass, Sample};

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
    /// The probing tier, shared with the control socket. Every resolver query
    /// is one emission class; in the passive tier none is sent and each
    /// `(name, server)` pair the tick would have resolved lands as a `SKIP`
    /// row instead — the probe list itself is a config fact, not a packet.
    /// (realm net-observer, node #88)
    probing: Arc<ProbingState>,
}

impl<F: DnsFacts> DnsCollector<F> {
    /// Construct a `dns` collector from its resolver port, poll interval and
    /// the shared probing tier (see [`DnsCollector::probing`]).
    pub fn new(facts: F, interval: Duration, probing: Arc<ProbingState>) -> Self {
        Self {
            facts,
            interval,
            probing,
        }
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
        // Read the tier ONCE per tick, so the queries withheld and the
        // verdicts that report them cannot disagree.
        let query = self.probing.tier().emits(EmissionClass::DnsQuery);
        let pairs = self.facts.probes().await;
        let mut resolved = Vec::with_capacity(pairs.len());
        for (probe, server) in pairs {
            let (verdict, ip, rtt_ms) = if query {
                self.facts.resolve(&probe, &server).await
            } else {
                // Withheld: no packet, no answer, and the row says so.
                (DnsVerdict::Skip, None, None)
            };
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::ProbingTier;

    /// Resolver facts that count the queries actually sent.
    struct Facts {
        readiness: Readiness,
        resolved: Arc<AtomicUsize>,
    }
    impl DnsFacts for Facts {
        async fn resolve(&self, _: &str, _: &str) -> (DnsVerdict, Option<String>, Option<f64>) {
            self.resolved.fetch_add(1, Ordering::Release);
            (DnsVerdict::Ok, Some("10.0.0.1".into()), Some(2.0))
        }
        async fn probes(&self) -> Vec<(String, String)> {
            vec![("nks".into(), "sb".into()), ("ru".into(), "doh".into())]
        }
        async fn preflight(&self) -> Readiness {
            self.readiness.clone()
        }
    }

    fn collector_in(readiness: Readiness, tier: ProbingTier) -> DnsCollector<Facts> {
        DnsCollector::new(
            Facts {
                readiness,
                resolved: Arc::default(),
            },
            Duration::from_secs(15),
            Arc::new(ProbingState::new(tier)),
        )
    }

    fn collector(readiness: Readiness) -> DnsCollector<Facts> {
        collector_in(readiness, ProbingTier::Active)
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
        assert_eq!(samples.len(), 2);
        assert!(matches!(samples[0], Sample::Dns(_)));
        assert_eq!(c.facts.resolved.load(Ordering::Acquire), 2);
    }

    /// The passive tier sends no query and still emits one `SKIP` row per
    /// probe pair, naming the pair — the record shows WHICH probes were
    /// withheld, not a bare placeholder. Switching to active resolves them on
    /// the next tick.
    #[tokio::test]
    async fn passive_sends_no_query_and_emits_a_skip_row_per_probe() {
        let c = collector_in(Readiness::Ready, ProbingTier::Passive);
        let samples = c.collect(7).await;
        assert_eq!(samples.len(), 2, "passive must not silence the tick");
        for s in &samples {
            let Sample::Dns(d) = s else {
                panic!("expected a dns sample")
            };
            assert_eq!(d.verdict, DnsVerdict::Skip);
            assert_eq!(d.ip, None);
            assert_eq!(d.rtt_ms, None);
        }
        let Sample::Dns(d) = &samples[1] else {
            panic!("expected a dns sample")
        };
        assert_eq!((d.probe.as_str(), d.server.as_str()), ("ru", "doh"));
        assert_eq!(c.facts.resolved.load(Ordering::Acquire), 0, "no query");

        c.probing.set(ProbingTier::Active);
        let samples = c.collect(8).await;
        let Sample::Dns(d) = &samples[0] else {
            panic!("expected a dns sample")
        };
        assert_eq!(d.verdict, DnsVerdict::Ok);
        assert_eq!(c.facts.resolved.load(Ordering::Acquire), 2);
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
