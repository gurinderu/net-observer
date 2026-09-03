//! Pure mapping from a fetched [`AirRead`] to an [`AirSample`].

use types::{AirSample, AirVerdict};

use crate::facts::AirRead;

/// Pure, SYNC mapping from one fetched scan to an [`AirSample`].
///
/// `collect()` `await`s the port, then hands the fetched value here so the
/// assembly stays trivially testable while async lives only in the port.
///
/// The rule the daemon depends on: **a period always produces a sample.** A scan
/// that could not run yields [`AirVerdict::Skip`] with the reason attached and an
/// empty `aps` list that the verdict marks as meaningless — never a missing
/// sample, and never an `Ok` with an empty list, which is the *different* fact
/// that the scan ran and heard nobody.
#[must_use]
pub fn build_air_sample(ts_us: i64, read: AirRead) -> AirSample {
    match read {
        AirRead::Unavailable(reason) => AirSample {
            ts_us,
            air: AirVerdict::Skip,
            reason: Some(reason),
            aps: Vec::new(),
        },
        AirRead::Scan(aps) => AirSample {
            ts_us,
            air: AirVerdict::Ok,
            reason: None,
            aps,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::AirObservation;

    fn ap(channel: i32, band: &str, width: i32, rssi: i32) -> AirObservation {
        AirObservation {
            channel: Some(channel),
            channel_band: Some(band.into()),
            channel_width_mhz: Some(width),
            phy_mode: Some("802.11a/n/ac/ax".into()),
            security: Some("wpa2_personal".into()),
            rssi_dbm: Some(rssi),
            noise_dbm: Some(-95),
        }
    }

    #[test]
    fn a_scan_becomes_an_ok_sample_carrying_every_ap() {
        let s = build_air_sample(
            42,
            AirRead::Scan(vec![ap(44, "5ghz", 80, -72), ap(2, "2ghz", 20, -69)]),
        );
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.air, AirVerdict::Ok);
        assert_eq!(s.reason, None);
        assert_eq!(s.aps.len(), 2);
        assert_eq!(s.aps[0].channel, Some(44));
        assert_eq!(s.aps[1].rssi_dbm, Some(-69));
    }

    /// The distinction the whole SKIP rule exists for: a scan that could not run
    /// is a SKIP with a reason, NOT an `Ok` with nothing in it.
    #[test]
    fn a_failed_scan_is_a_skip_with_a_reason_not_clear_air() {
        let s = build_air_sample(7, AirRead::Unavailable("Wi-Fi powered off".into()));
        assert_eq!(s.air, AirVerdict::Skip);
        assert_eq!(s.reason.as_deref(), Some("Wi-Fi powered off"));
        assert!(s.aps.is_empty());
    }

    /// And the mirror: a scan that ran and heard nobody is a real reading, `Ok`
    /// with an empty list — a fact, not a failure.
    #[test]
    fn an_empty_scan_that_ran_is_ok_not_skip() {
        let s = build_air_sample(9, AirRead::Scan(Vec::new()));
        assert_eq!(s.air, AirVerdict::Ok);
        assert_eq!(s.reason, None);
        assert!(s.aps.is_empty());
    }
}
