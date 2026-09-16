//! The proxy [`Collector`]: static [`META`] and the [`ProxyCollector`] wiring the
//! `ProxyFacts`/`TcpProber`/`StallProbe` ports into the [`build_proxy_samples`]
//! mapping.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, ProbingState, Readiness, Source, TcpProber};
use types::{EmissionClass, ProxySample, Sample, TcpVerdict};

use crate::probes::{ProxyFacts, StallProbe, StallReading};
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
    /// The probing tier, shared with the control socket. This is the most
    /// talkative collector — three emission classes — and in the passive tier
    /// every one is withheld: no 204 through the TUN, no connect to any
    /// endpoint, and the held reference streams are CLOSED rather than kept
    /// open and exercised. The selector read (loopback, sing-box's own API)
    /// and the endpoint list (a config read) are passive and continue.
    /// (realm net-observer, node #88)
    probing: Arc<ProbingState>,
}

impl<T: TcpProber, F: ProxyFacts, S: StallProbe> ProxyCollector<T, F, S> {
    /// Construct a proxy collector from its ports, cadence and the shared
    /// probing tier (see [`ProxyCollector::probing`]).
    pub fn new(
        tcp: T,
        facts: F,
        stall: S,
        tun_url: String,
        iface: String,
        interval: Duration,
        probing: Arc<ProbingState>,
    ) -> Self {
        Self {
            tcp,
            facts,
            stall,
            tun_url,
            iface,
            interval,
            probing,
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
        // Read the tier ONCE per tick, so the probes withheld and the verdicts
        // that report them cannot disagree.
        let tier = self.probing.tier();
        // Await the probes, then a sync `build_*` composes the samples.
        let tun_code = if tier.emits(EmissionClass::TunProbe) {
            self.facts.tun_probe(&self.tun_url).await
        } else {
            None
        };
        let selector = self.facts.selector().await;
        // The held-stream check runs in the same tick as the fresh probes, so
        // "fresh OK while established dead" is one cohort, not a correlation.
        // Withheld, the streams are closed outright: a held stream is a per-tick
        // emission, and one kept open would be exercised on the next active
        // tick as if it had been measured all along. Its fields read `None` —
        // no measurement — until the streams are re-opened on the next active
        // tick.
        let stall = if tier.emits(EmissionClass::HeldStream) {
            self.stall.check().await
        } else {
            self.stall.close().await;
            StallReading::default()
        };
        // Withheld, the endpoint list is not walked: the tick lands as the
        // single `SKIP` placeholder row (`tcp = SKIP`, no rtt) the mapping
        // produces for "nothing was probed", carrying the passive facts.
        let endpoints = if tier.emits(EmissionClass::EndpointProbe) {
            self.facts.server_endpoints().await
        } else {
            Vec::new()
        };
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::ProbingTier;

    /// A prober that counts the connects actually attempted.
    #[derive(Default)]
    struct T {
        sent: Arc<AtomicUsize>,
    }
    impl TcpProber for T {
        async fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            self.sent.fetch_add(1, Ordering::Release);
            PingOutcome {
                reachable: true,
                rtt_ms: Some(9.0),
            }
        }
    }

    /// Facts that count the TUN probes actually sent.
    struct Facts {
        readiness: Readiness,
        tun_probes: Arc<AtomicUsize>,
    }
    impl ProxyFacts for Facts {
        async fn server_endpoints(&self) -> Vec<String> {
            vec!["1.1.1.1:443".into()]
        }
        async fn tun_probe(&self, _: &str) -> Option<u16> {
            self.tun_probes.fetch_add(1, Ordering::Release);
            Some(204)
        }
        async fn selector(&self) -> Option<String> {
            Some("node-a".into())
        }
        async fn preflight(&self) -> Readiness {
            self.readiness.clone()
        }
    }

    /// A scripted stall probe: both held streams alive and 60s old, and a
    /// record of how often it was checked and how often closed.
    #[derive(Default)]
    struct FakeStall {
        checks: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
    }
    impl StallProbe for FakeStall {
        async fn check(&self) -> StallReading {
            self.checks.fetch_add(1, Ordering::Release);
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
        async fn close(&self) {
            self.closes.fetch_add(1, Ordering::Release);
        }
    }

    fn collector_in(
        readiness: Readiness,
        tier: ProbingTier,
    ) -> (ProxyCollector<T, Facts, FakeStall>, Arc<ProbingState>) {
        let probing = Arc::new(ProbingState::new(tier));
        let c = ProxyCollector::new(
            T::default(),
            Facts {
                readiness,
                tun_probes: Arc::default(),
            },
            FakeStall::default(),
            "http://x/204".into(),
            "en0".into(),
            Duration::from_secs(15),
            probing.clone(),
        );
        (c, probing)
    }

    fn collector(readiness: Readiness) -> ProxyCollector<T, Facts, FakeStall> {
        collector_in(readiness, ProbingTier::Active).0
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
        assert_eq!(c.stall.closes.load(Ordering::Acquire), 0);
    }

    /// The passive tier withholds all three emission classes: no TUN probe, no
    /// endpoint connect, and the held streams are closed rather than checked.
    /// The tick still lands as the `SKIP` placeholder row with every
    /// measurement `None`, while the selector (a loopback read) still flows.
    /// Switching to active re-opens everything on the next tick.
    #[tokio::test]
    async fn passive_withholds_every_probe_closes_the_streams_and_still_emits() {
        let (c, probing) = collector_in(Readiness::Ready, ProbingTier::Passive);

        let samples = c.collect(7).await;
        assert_eq!(samples.len(), 1, "passive must not silence the tick");
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.tcp, TcpVerdict::Skip);
        assert_eq!(p.rtt_ms, None);
        assert_eq!(p.tun_code, None);
        assert_eq!(p.est_direct_alive, None);
        assert_eq!(p.est_tun_alive, None);
        assert_eq!(p.selector.as_deref(), Some("node-a"), "a passive fact");
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 0, "no connect");
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 0, "no 204");
        assert_eq!(c.stall.checks.load(Ordering::Acquire), 0, "no HEAD");
        assert_eq!(c.stall.closes.load(Ordering::Acquire), 1, "streams closed");

        probing.set(ProbingTier::Active);
        let samples = c.collect(8).await;
        let Sample::Proxy(p) = &samples[0] else {
            panic!("expected a proxy sample")
        };
        assert_eq!(p.tcp, TcpVerdict::Ok);
        assert_eq!(p.tun_code, Some(204));
        assert_eq!(p.est_tun_alive, Some(true));
        assert_eq!(c.tcp.sent.load(Ordering::Acquire), 1);
        assert_eq!(c.facts.tun_probes.load(Ordering::Acquire), 1);
        assert_eq!(c.stall.checks.load(Ordering::Acquire), 1);
        assert_eq!(
            c.stall.closes.load(Ordering::Acquire),
            1,
            "not closed again"
        );
    }
}
