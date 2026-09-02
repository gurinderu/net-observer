//! Static [`META`] and the [`WifiCollector`] that wires the Wi-Fi facts port into
//! the [`Collector`] abstraction the daemon drives.

use std::sync::Arc;
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::{Sample, WifiSample, WifiVerdict};

use crate::facts::WifiFacts;
use crate::sample::build_wifi_sample;

/// Static metadata for the `wifi` collector: CoreWLAN is macOS-only.
pub const META: CollectorMeta = CollectorMeta {
    name: "wifi",
    supported_os: &[Os::MacOs],
};

/// The `wifi` collector: one air-quality reading per tick.
///
/// Entirely passive — reading the radio's own statistics addresses no packet at
/// anything and never scans, so there is no `quiet` switch to honour here.
///
/// Generic over its [`WifiFacts`] port for static dispatch: native `async fn` in
/// the port rules out `dyn`, and the daemon enumerates the concrete collectors in
/// its `AnyCollector` enum.
pub struct WifiCollector<F: WifiFacts> {
    facts: Arc<F>,
    interval: Duration,
}

impl<F: WifiFacts> WifiCollector<F> {
    /// Construct a `wifi` collector from its facts port and poll interval.
    pub fn new(facts: Arc<F>, interval: Duration) -> Self {
        Self { facts, interval }
    }
}

impl<F: WifiFacts> Collector for WifiCollector<F> {
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
        // Await the one port, then compose the sample with the sync `build_*`.
        // Not being on Wi-Fi comes back as `WifiRead::Unavailable` and maps to a
        // SKIP sample, so this arm never returns an empty vec.
        let read = self.facts.read().await;
        vec![Sample::Wifi(build_wifi_sample(ts_us, read))]
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        // A tick whose preflight failed still leaves a row. The reason is
        // deliberately generic: preflight reported it in the daemon's log, and
        // the sample's job here is to mark that the probe did not run at all.
        vec![Sample::Wifi(WifiSample {
            ts_us,
            wifi: WifiVerdict::Skip,
            reason: Some("wifi collector preflight unavailable".into()),
            rssi_dbm: None,
            noise_dbm: None,
            snr_db: None,
            tx_rate_mbps: None,
            phy_mode: None,
            channel: None,
            channel_width_mhz: None,
            channel_band: None,
        })]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{WifiRead, WifiReading};

    struct FakeWifi {
        ready: bool,
        read: WifiRead,
    }
    impl WifiFacts for FakeWifi {
        async fn read(&self) -> WifiRead {
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

    fn collector(ready: bool, read: WifiRead) -> WifiCollector<FakeWifi> {
        WifiCollector::new(Arc::new(FakeWifi { ready, read }), Duration::from_secs(15))
    }

    fn wifi(samples: &[Sample]) -> &WifiSample {
        match samples {
            [Sample::Wifi(w)] => w,
            other => panic!("expected exactly one wifi sample, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unavailable_preflight_is_not_ready() {
        let c = collector(false, WifiRead::Unavailable("no Wi-Fi interface".into()));
        assert!(!c.preflight().await.is_ready());
    }

    #[tokio::test]
    async fn ready_preflight_collects_one_wifi_sample() {
        let c = collector(
            true,
            WifiRead::Associated(WifiReading {
                rssi_dbm: Some(-53),
                noise_dbm: Some(-96),
                tx_rate_mbps: Some(270.0),
                phy_mode: Some("11ax".into()),
                channel: Some(48),
                channel_width_mhz: Some(20),
                channel_band: Some("5ghz".into()),
            }),
        );
        assert!(c.preflight().await.is_ready());
        let samples = c.collect(42).await;
        let w = wifi(&samples);
        assert_eq!(w.wifi, WifiVerdict::Ok);
        assert_eq!(w.snr_db, Some(43));
    }

    /// Not on Wi-Fi is a SKIP sample every tick, with the reason — the collector
    /// must never go quiet just because the radio is not in use.
    #[tokio::test]
    async fn not_on_wifi_still_emits_a_skip_sample() {
        let c = collector(true, WifiRead::Unavailable("not associated".into()));
        let samples = c.collect(42).await;
        let w = wifi(&samples);
        assert_eq!(w.wifi, WifiVerdict::Skip);
        assert_eq!(w.reason.as_deref(), Some("not associated"));
    }

    /// A failed preflight leaves a row too, so an offline reader can tell "the
    /// probe could not run" from "nobody asked".
    #[test]
    fn skip_tick_emits_a_skip_sample() {
        let c = collector(false, WifiRead::Unavailable("no Wi-Fi interface".into()));
        let samples = c.skip(99);
        let w = wifi(&samples);
        assert_eq!(w.ts_us, 99);
        assert_eq!(w.wifi, WifiVerdict::Skip);
        assert!(w.reason.is_some());
    }
}
