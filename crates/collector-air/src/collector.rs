//! Static [`META`] and the [`AirCollector`] that wires the air-map facts port
//! into the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::{AirSample, AirVerdict, Sample};

use crate::facts::AirFacts;
use crate::sample::build_air_sample;

/// Static metadata for the `air` collector: the system wireless report is
/// macOS-only.
pub const META: CollectorMeta = CollectorMeta {
    name: "air",
    supported_os: &[Os::MacOs],
};

/// The `air` collector: one radio-environment slice per period.
///
/// Entirely passive — it reads the system's own wireless report and puts nothing
/// on the air itself, so there is no `quiet` switch to honour here.
///
/// **Its own interval, deliberately separate from the daemon's tick**: producing
/// the report costs seconds on this machine (realm net-observer, node #47), so
/// driving it at tick cadence would keep a collector busy most of the time for a
/// picture that changes on the timescale of neighbours rearranging their routers.
///
/// Generic over its [`AirFacts`] port for static dispatch: native `async fn` in
/// the port rules out `dyn`, and the daemon enumerates the concrete collectors in
/// its `AnyCollector` enum.
pub struct AirCollector<F: AirFacts> {
    facts: Arc<F>,
    interval: Duration,
}

impl<F: AirFacts> AirCollector<F> {
    /// Construct an `air` collector from its facts port and scan interval.
    pub fn new(facts: Arc<F>, interval: Duration) -> Self {
        Self { facts, interval }
    }
}

impl<F: AirFacts> Collector for AirCollector<F> {
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
        // A radio that cannot be scanned comes back as `AirRead::Unavailable` and
        // maps to a SKIP sample, so this arm never returns an empty vec.
        let read = self.facts.read().await;
        vec![Sample::Air(build_air_sample(ts_us, read))]
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        // A period whose preflight failed still leaves a row. The reason is
        // deliberately generic: preflight reported it in the daemon's log, and
        // the sample's job here is to mark that the scan did not run at all.
        vec![Sample::Air(AirSample {
            ts_us,
            air: AirVerdict::Skip,
            reason: Some("air collector preflight unavailable".into()),
            aps: Vec::new(),
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::AirRead;
    use types::AirObservation;

    struct FakeAir {
        ready: bool,
        read: AirRead,
    }
    impl AirFacts for FakeAir {
        async fn read(&self) -> AirRead {
            self.read.clone()
        }
        async fn preflight(&self) -> Readiness {
            if self.ready {
                Readiness::Ready
            } else {
                Readiness::Unavailable("no Wi-Fi interface".into())
            }
        }
    }

    fn collector(ready: bool, read: AirRead) -> AirCollector<FakeAir> {
        AirCollector::new(Arc::new(FakeAir { ready, read }), Duration::from_secs(300))
    }

    fn air(samples: &[Sample]) -> &AirSample {
        match samples {
            [Sample::Air(a)] => a,
            other => panic!("expected exactly one air sample, got {other:?}"),
        }
    }

    #[test]
    fn the_scan_runs_on_its_own_slow_period_not_the_tick() {
        let c = collector(true, AirRead::Scan(Vec::new()));
        match c.source() {
            Source::Interval(d) => assert_eq!(d, Duration::from_secs(300)),
            Source::Event => panic!("the air scan is an interval collector, not event-driven"),
        }
    }

    #[tokio::test]
    async fn unavailable_preflight_is_not_ready() {
        let c = collector(false, AirRead::Unavailable("no Wi-Fi interface".into()));
        assert!(!c.preflight().await.is_ready());
    }

    #[tokio::test]
    async fn ready_preflight_collects_one_air_sample() {
        let c = collector(
            true,
            AirRead::Scan(vec![AirObservation {
                channel: Some(44),
                channel_band: Some("5ghz".into()),
                channel_width_mhz: Some(80),
                phy_mode: Some("802.11a/n/ac/ax".into()),
                security: Some("wpa2_personal".into()),
                rssi_dbm: Some(-72),
                noise_dbm: Some(-95),
            }]),
        );
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        let a = air(&samples);
        assert_eq!(a.air, AirVerdict::Ok);
        assert_eq!(a.aps.len(), 1);
    }

    /// A radio that cannot be scanned is a SKIP sample every period, with the
    /// reason — never an absent period and never an empty `Ok`.
    #[tokio::test]
    async fn an_unusable_radio_still_emits_a_skip_sample() {
        let c = collector(true, AirRead::Unavailable("Wi-Fi powered off".into()));
        let a = air(&c.collect(42).await).clone();
        assert_eq!(a.air, AirVerdict::Skip);
        assert_eq!(a.reason.as_deref(), Some("Wi-Fi powered off"));
    }

    /// A failed preflight leaves a row too, so an offline reader can tell "the
    /// scan could not run" from "nobody asked".
    #[test]
    fn skip_period_emits_a_skip_sample() {
        let c = collector(false, AirRead::Unavailable("no Wi-Fi interface".into()));
        let samples = c.skip(99);
        let a = air(&samples);
        assert_eq!(a.ts_us, 99);
        assert_eq!(a.air, AirVerdict::Skip);
        assert!(a.reason.is_some());
        assert!(a.aps.is_empty());
    }
}
