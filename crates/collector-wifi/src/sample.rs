//! Pure mapping from a fetched [`WifiRead`] to a [`WifiSample`].

use types::{WifiSample, WifiVerdict};

use crate::facts::WifiRead;

/// Pure, SYNC mapping from one fetched radio reading to a [`WifiSample`].
///
/// `collect()` `await`s the port, then hands the fetched value here so the
/// assembly stays trivially testable while async lives only in the port.
///
/// Two rules the daemon depends on:
///
/// * **A tick always produces a sample.** A radio that cannot be read yields
///   [`WifiVerdict::Skip`] with the reason attached, not silence.
/// * **SNR is derived, never measured.** `snr_db = rssi_dbm - noise_dbm`, and only
///   when *both* raw values are present; the raw pair is recorded alongside it, so
///   a later change of derivation can be recomputed from what was measured. RSSI
///   alone barely moves until the link is already gone, while the margin over the
///   noise floor degrades earlier — which is why the margin is worth deriving and
///   the pair is worth keeping.
#[must_use]
pub fn build_wifi_sample(ts_us: i64, read: WifiRead) -> WifiSample {
    match read {
        WifiRead::Unavailable(reason) => WifiSample {
            ts_us,
            wifi: WifiVerdict::Skip,
            reason: Some(reason),
            rssi_dbm: None,
            noise_dbm: None,
            snr_db: None,
            tx_rate_mbps: None,
            phy_mode: None,
            channel: None,
            channel_width_mhz: None,
            channel_band: None,
        },
        WifiRead::Associated(r) => {
            let snr_db = match (r.rssi_dbm, r.noise_dbm) {
                (Some(rssi), Some(noise)) => Some(rssi - noise),
                _ => None,
            };
            WifiSample {
                ts_us,
                wifi: WifiVerdict::Ok,
                reason: None,
                rssi_dbm: r.rssi_dbm,
                noise_dbm: r.noise_dbm,
                snr_db,
                tx_rate_mbps: r.tx_rate_mbps,
                phy_mode: r.phy_mode,
                channel: r.channel,
                channel_width_mhz: r.channel_width_mhz,
                channel_band: r.channel_band,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::WifiReading;

    /// The reading measured on the author's Mac, so the healthy case is a real
    /// shape and not an invented one.
    fn healthy() -> WifiReading {
        WifiReading {
            rssi_dbm: Some(-53),
            noise_dbm: Some(-96),
            tx_rate_mbps: Some(270.0),
            phy_mode: Some("11ax".into()),
            channel: Some(48),
            channel_width_mhz: Some(20),
            channel_band: Some("5ghz".into()),
        }
    }

    #[test]
    fn healthy_reading_keeps_the_raw_pair_and_derives_the_margin() {
        let s = build_wifi_sample(42, WifiRead::Associated(healthy()));
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.wifi, WifiVerdict::Ok);
        assert_eq!(s.reason, None);
        // The raw pair survives the derivation.
        assert_eq!(s.rssi_dbm, Some(-53));
        assert_eq!(s.noise_dbm, Some(-96));
        assert_eq!(s.snr_db, Some(43));
        assert_eq!(s.tx_rate_mbps, Some(270.0));
        assert_eq!(s.phy_mode.as_deref(), Some("11ax"));
        assert_eq!(s.channel, Some(48));
        assert_eq!(s.channel_width_mhz, Some(20));
        assert_eq!(s.channel_band.as_deref(), Some("5ghz"));
    }

    /// Not on Wi-Fi is a SKIP sample carrying the reason — never an absent tick.
    #[test]
    fn not_on_wifi_is_a_skip_with_a_reason() {
        let s = build_wifi_sample(7, WifiRead::Unavailable("no Wi-Fi interface".into()));
        assert_eq!(s.wifi, WifiVerdict::Skip);
        assert_eq!(s.reason.as_deref(), Some("no Wi-Fi interface"));
        assert_eq!(s.rssi_dbm, None);
        assert_eq!(s.noise_dbm, None);
        assert_eq!(s.snr_db, None);
        assert_eq!(s.tx_rate_mbps, None);
        assert_eq!(s.channel, None);
    }

    /// One field the API declined does not demote the tick: the sample is still
    /// `OK` and every field that WAS given is recorded. Only the derivation that
    /// depends on the missing half goes `None`.
    #[test]
    fn partial_reading_stays_ok_and_drops_only_the_derivation() {
        let s = build_wifi_sample(
            9,
            WifiRead::Associated(WifiReading {
                noise_dbm: None,
                ..healthy()
            }),
        );
        assert_eq!(s.wifi, WifiVerdict::Ok);
        assert_eq!(s.reason, None);
        assert_eq!(s.rssi_dbm, Some(-53));
        assert_eq!(s.noise_dbm, None);
        assert_eq!(s.snr_db, None, "SNR needs both halves of the raw pair");
        // Everything else still flows through.
        assert_eq!(s.tx_rate_mbps, Some(270.0));
        assert_eq!(s.phy_mode.as_deref(), Some("11ax"));
    }

    /// The mirror case: RSSI missing, noise present. The margin is undefined
    /// either way — it is never half-derived from one value.
    #[test]
    fn missing_rssi_also_yields_no_margin() {
        let s = build_wifi_sample(
            10,
            WifiRead::Associated(WifiReading {
                rssi_dbm: None,
                ..healthy()
            }),
        );
        assert_eq!(s.wifi, WifiVerdict::Ok);
        assert_eq!(s.noise_dbm, Some(-96));
        assert_eq!(s.snr_db, None);
    }

    /// An associated radio that gave nothing at all is still `OK`, not `SKIP`:
    /// "associated but mute" and "not on Wi-Fi" are different facts and the
    /// verdict must not conflate them.
    #[test]
    fn associated_but_empty_reading_is_ok_not_skip() {
        let s = build_wifi_sample(11, WifiRead::Associated(WifiReading::default()));
        assert_eq!(s.wifi, WifiVerdict::Ok);
        assert_eq!(s.reason, None);
        assert_eq!(s.snr_db, None);
    }
}
