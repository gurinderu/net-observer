//! The radio environment: the foreign access points macOS can hear, read from
//! `system_profiler -json SPAirPortDataType`.
//!
//! Measured first-hand on this machine (realm net-observer, node #47). The
//! report lists each foreign AP under
//! `spairport_airport_other_local_wireless_networks`, and what it gives is
//! narrow and awkwardly shaped:
//!
//! ```text
//! "_name":                      "<redacted>"          // always; never a name
//! "spairport_network_channel":  "36 (5GHz, 80MHz)"    // number, band, width in ONE string
//! "spairport_network_phymode":  "802.11a/n/ac/ax"
//! "spairport_security_mode":    "spairport_security_mode_wpa2_personal_mixed"
//! "spairport_signal_noise":     "-62 dBm / -94 dBm"   // signal and noise in ONE string
//! ```
//!
//! **No BSSID at all**, under root or under a user — so a foreign AP cannot be
//! followed between scans. That is a limit of the surface, not an unfinished
//! adapter.
//!
//! The call costs about 2.7 s, which is why the collector has its own slow
//! period rather than running on the daemon's tick.
//!
//! Nothing here transmits: the report is produced by the system, and this module
//! only spawns the reporter and parses its JSON.

use std::time::Duration;

use collector_air::{AirFacts, AirRead};
use collector_core::Readiness;
use tokio::process::Command;
use types::AirObservation;

/// The report the adapter asks `system_profiler` for.
const DATA_TYPE: &str = "SPAirPortDataType";

/// JSON key holding the array of foreign access points.
const OTHER_NETWORKS_KEY: &str = "spairport_airport_other_local_wireless_networks";

/// How long to wait for the report before giving up. The call is measured at
/// ~2.7 s; a radio that is wedged can hang far longer, and a hung scan must
/// become a SKIP with a reason rather than a collector that never returns.
const REPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// The production [`AirFacts`]: shells out to `system_profiler` and parses its
/// JSON.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemProfilerAir;

impl SystemProfilerAir {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Run the reporter and return its stdout, or the reason it could not be had.
    async fn report(&self) -> Result<String, String> {
        let run = Command::new("system_profiler")
            .args(["-json", DATA_TYPE])
            // On timeout the future is dropped; without this the wedged child
            // outlives it and one process leaks per period.
            .kill_on_drop(true)
            .output();
        let out = match tokio::time::timeout(REPORT_TIMEOUT, run).await {
            Err(_) => return Err(format!("system_profiler {DATA_TYPE} timed out")),
            Ok(Err(e)) => return Err(format!("system_profiler {DATA_TYPE} failed to run: {e}")),
            Ok(Ok(out)) => out,
        };
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.trim();
            return Err(format!(
                "system_profiler {DATA_TYPE} exited {}: {}",
                out.status,
                if err.is_empty() { "no stderr" } else { err }
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

impl AirFacts for SystemProfilerAir {
    async fn read(&self) -> AirRead {
        match self.report().await {
            Err(reason) => AirRead::Unavailable(reason),
            Ok(body) => match parse_air_report(&body) {
                Ok(aps) => AirRead::Scan(aps),
                Err(reason) => AirRead::Unavailable(reason),
            },
        }
    }

    async fn preflight(&self) -> Readiness {
        // The only capability that matters is that the report can be produced at
        // all; whether it currently lists anybody is the reading, not readiness.
        match self.report().await {
            Ok(body) if serde_json::from_str::<serde_json::Value>(&body).is_ok() => {
                Readiness::Ready
            }
            Ok(_) => Readiness::Unavailable(format!("{DATA_TYPE} report is not valid JSON")),
            Err(reason) => Readiness::Unavailable(reason),
        }
    }
}

/// Parse the whole report into one observation per foreign access point.
///
/// The array is looked up by key **anywhere in the document** rather than at a
/// fixed path: `system_profiler` nests its payload differently per data type and
/// per OS release, and a hard-coded path is the thing that silently returns
/// nothing after an update. Several arrays (one per radio) are concatenated.
///
/// Returns `Err` when the document is not JSON or carries no wireless section at
/// all — an absent section is "could not look", which the collector turns into a
/// SKIP. An *empty* array, by contrast, is a real reading and yields `Ok(vec![])`.
pub fn parse_air_report(body: &str) -> Result<Vec<AirObservation>, String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("{DATA_TYPE} report is not JSON: {e}"))?;
    let mut arrays = Vec::new();
    collect_key(&doc, OTHER_NETWORKS_KEY, &mut arrays);
    if arrays.is_empty() {
        return Err(format!(
            "{DATA_TYPE} report carries no `{OTHER_NETWORKS_KEY}` section \
             (Wi-Fi powered off, or no wireless interface)"
        ));
    }
    let mut out = Vec::new();
    for array in arrays {
        for entry in array {
            out.push(parse_observation(entry));
        }
    }
    Ok(out)
}

/// Depth-first walk collecting every array stored under `key`.
fn collect_key<'a>(
    value: &'a serde_json::Value,
    key: &str,
    out: &mut Vec<&'a Vec<serde_json::Value>>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if k == key
                    && let Some(array) = v.as_array()
                {
                    out.push(array);
                } else {
                    collect_key(v, key, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_key(item, key, out);
            }
        }
        _ => {}
    }
}

/// Map one report entry to an [`AirObservation`].
///
/// Every field is independently optional: a missing or unparseable one becomes
/// `None` rather than throwing the whole entry away — an AP heard on a known
/// channel with an unreadable security label is still an AP on that channel.
fn parse_observation(entry: &serde_json::Value) -> AirObservation {
    let text = |key: &str| entry.get(key).and_then(serde_json::Value::as_str);
    let (channel, band, width) =
        text("spairport_network_channel").map_or((None, None, None), parse_channel);
    let (rssi_dbm, noise_dbm) =
        text("spairport_signal_noise").map_or((None, None), parse_signal_noise);
    AirObservation {
        channel,
        channel_band: band,
        channel_width_mhz: width,
        phy_mode: text("spairport_network_phymode").map(str::to_string),
        security: text("spairport_security_mode").map(parse_security),
        rssi_dbm,
        noise_dbm,
    }
}

/// Parse `"36 (5GHz, 80MHz)"` into `(channel, band, width_mhz)`.
///
/// Each of the three is recovered independently, so a shape the platform changes
/// in one place still yields the parts that are still there. The band is
/// normalised to the store's lowercase spelling ("5ghz"), matching what the
/// `wifi` collector records for our own association — the two must be comparable,
/// since the whole point is to overlay them.
#[must_use]
pub fn parse_channel(s: &str) -> (Option<i32>, Option<String>, Option<i32>) {
    let s = s.trim();
    // The leading run of digits is the channel number.
    let channel = {
        let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<i32>().ok()
    };
    // The parenthesised part, when present, holds comma-separated qualifiers.
    let inner = s
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(inner, _)| inner);
    let mut band = None;
    let mut width = None;
    for part in inner.into_iter().flat_map(|i| i.split(',')) {
        let part = part.trim();
        if let Some(b) = types::Band::parse(part) {
            band = Some(b.as_str().to_string());
        } else if let Some(mhz) = part
            .strip_suffix("MHz")
            .or_else(|| part.strip_suffix("mhz"))
            .or_else(|| part.strip_suffix("MHZ"))
            && let Ok(w) = mhz.trim().parse::<i32>()
            && w > 0
        {
            width = Some(w);
        }
    }
    (channel, band, width)
}

/// Parse `"-62 dBm / -94 dBm"` into `(rssi_dbm, noise_dbm)`.
///
/// The halves are recovered independently: a report that gives a signal but no
/// readable noise floor still yields the signal.
#[must_use]
pub fn parse_signal_noise(s: &str) -> (Option<i32>, Option<i32>) {
    let mut halves = s.split('/');
    let signal = halves.next().and_then(parse_dbm);
    let noise = halves.next().and_then(parse_dbm);
    (signal, noise)
}

/// Parse one `"-62 dBm"` field. Anything that is not a number followed by the
/// unit is `None` — never a zero standing in for an unread value.
fn parse_dbm(s: &str) -> Option<i32> {
    let s = s.trim();
    let number = s
        .strip_suffix("dBm")
        .or_else(|| s.strip_suffix("dbm"))
        .unwrap_or(s)
        .trim();
    number.parse::<i32>().ok()
}

/// Strip the platform's `spairport_security_mode_` prefix, leaving
/// `"wpa2_personal_mixed"`. A label without the prefix is kept as it came.
///
/// The report on this machine also emits the token with its leading `s` missing
/// — `pairport_security_mode_wpa3_transition` — for every WPA3-transition
/// network, so that spelling is stripped too. Matching only the documented
/// spelling leaked the raw token into the menu bar's labels, which is how this
/// was found (realm net-observer, node #48).
#[must_use]
pub fn parse_security(s: &str) -> String {
    for prefix in ["spairport_security_mode_", "pairport_security_mode_"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.to_string();
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from the real report on this machine, macOS 26.6.2 — three
    /// entries as `system_profiler` actually shapes them (realm net-observer,
    /// node #47).
    const REAL_REPORT: &str = r#"{
      "SPAirPortDataType": [
        {
          "spairport_airport_interfaces": [
            {
              "_name": "en0",
              "spairport_current_network_information": {
                "_name": "<redacted>",
                "spairport_network_channel": "56 (5GHz, 80MHz)",
                "spairport_network_phymode": "802.11ac",
                "spairport_signal_noise": "-71 dBm / -89 dBm"
              },
              "spairport_airport_other_local_wireless_networks": [
                {
                  "_name": "<redacted>",
                  "spairport_network_channel": "2 (2GHz, 20MHz)",
                  "spairport_network_phymode": "802.11b/g/n",
                  "spairport_security_mode": "spairport_security_mode_wpa2_personal_mixed",
                  "spairport_signal_noise": "-69 dBm / -94 dBm"
                },
                {
                  "_name": "<redacted>",
                  "spairport_network_channel": "44 (5GHz, 80MHz)",
                  "spairport_network_phymode": "802.11a/n/ac/ax",
                  "spairport_security_mode": "spairport_security_mode_wpa2_personal",
                  "spairport_signal_noise": "-72 dBm / -95 dBm"
                }
              ]
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn parses_the_real_report() {
        let aps = parse_air_report(REAL_REPORT).unwrap();
        assert_eq!(aps.len(), 2);
        assert_eq!(aps[0].channel, Some(2));
        assert_eq!(aps[0].channel_band.as_deref(), Some("2ghz"));
        assert_eq!(aps[0].channel_width_mhz, Some(20));
        assert_eq!(aps[0].rssi_dbm, Some(-69));
        assert_eq!(aps[0].noise_dbm, Some(-94));
        assert_eq!(aps[0].security.as_deref(), Some("wpa2_personal_mixed"));
        assert_eq!(aps[1].channel, Some(44));
        assert_eq!(aps[1].channel_band.as_deref(), Some("5ghz"));
        assert_eq!(aps[1].channel_width_mhz, Some(80));
        assert_eq!(aps[1].phy_mode.as_deref(), Some("802.11a/n/ac/ax"));
    }

    /// No BSSID and no usable name come back, and nothing here invents one — the
    /// observation type has no field for either.
    #[test]
    fn the_report_carries_no_identity_to_track_an_ap_by() {
        let aps = parse_air_report(REAL_REPORT).unwrap();
        // The only identity-ish thing in the entry is the redacted `_name`, which
        // the mapping deliberately drops.
        assert!(!format!("{:?}", aps[0]).contains("redacted"));
    }

    /// A report with the section present but empty is a real reading: the scan
    /// ran and heard nobody.
    #[test]
    fn an_empty_section_is_an_empty_reading_not_an_error() {
        let body =
            r#"{"SPAirPortDataType":[{"spairport_airport_other_local_wireless_networks":[]}]}"#;
        assert_eq!(parse_air_report(body).unwrap(), Vec::new());
    }

    /// A report with NO wireless section at all is "could not look" — an error
    /// the collector turns into a SKIP, never an empty list that reads as clear air.
    #[test]
    fn a_report_without_the_section_is_an_error_not_clear_air() {
        let body = r#"{"SPAirPortDataType":[{"spairport_airport_interfaces":[]}]}"#;
        let err = parse_air_report(body).unwrap_err();
        assert!(err.contains("no `spairport_airport_other_local_wireless_networks` section"));
    }

    #[test]
    fn junk_is_an_error_not_a_silent_empty_scan() {
        assert!(parse_air_report("not json at all").is_err());
        assert!(parse_air_report("").is_err());
    }

    /// An entry missing every field is still an entry: an AP was heard. Nothing
    /// is invented for what the report declined to say.
    #[test]
    fn an_entry_with_no_fields_yields_all_nones() {
        let body = r#"{"spairport_airport_other_local_wireless_networks":[{}]}"#;
        let aps = parse_air_report(body).unwrap();
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0], AirObservation::default());
    }

    /// A field of the wrong shape degrades only itself.
    #[test]
    fn a_garbled_field_does_not_take_the_rest_of_the_entry_with_it() {
        let body = r#"{"spairport_airport_other_local_wireless_networks":[{
            "spairport_network_channel": "wat",
            "spairport_signal_noise": "-62 dBm / -94 dBm",
            "spairport_network_phymode": "802.11ax"
        }]}"#;
        let aps = parse_air_report(body).unwrap();
        assert_eq!(aps[0].channel, None);
        assert_eq!(aps[0].channel_band, None);
        assert_eq!(aps[0].rssi_dbm, Some(-62));
        assert_eq!(aps[0].phy_mode.as_deref(), Some("802.11ax"));
    }

    #[test]
    fn parses_the_channel_string() {
        assert_eq!(
            parse_channel("36 (5GHz, 80MHz)"),
            (Some(36), Some("5ghz".into()), Some(80))
        );
        assert_eq!(
            parse_channel("2 (2GHz, 20MHz)"),
            (Some(2), Some("2ghz".into()), Some(20))
        );
        assert_eq!(
            parse_channel("37 (6GHz, 160MHz)"),
            (Some(37), Some("6ghz".into()), Some(160))
        );
    }

    /// Each of the three parts is recovered on its own, so a shape that loses one
    /// still yields the others.
    #[test]
    fn channel_parts_are_independent() {
        assert_eq!(parse_channel("149"), (Some(149), None, None));
        assert_eq!(
            parse_channel("149 (5GHz)"),
            (Some(149), Some("5ghz".into()), None)
        );
        assert_eq!(
            parse_channel("(5GHz, 40MHz)"),
            (None, Some("5ghz".into()), Some(40))
        );
        assert_eq!(parse_channel(""), (None, None, None));
        assert_eq!(parse_channel("wat"), (None, None, None));
        assert_eq!(
            parse_channel("11 (2GHz, unknown)"),
            (Some(11), Some("2ghz".into()), None)
        );
        // A width of zero is not a width.
        assert_eq!(
            parse_channel("11 (2GHz, 0MHz)"),
            (Some(11), Some("2ghz".into()), None)
        );
    }

    #[test]
    fn parses_the_signal_noise_string() {
        assert_eq!(
            parse_signal_noise("-62 dBm / -94 dBm"),
            (Some(-62), Some(-94))
        );
        assert_eq!(parse_signal_noise("-62dBm/-94dBm"), (Some(-62), Some(-94)));
    }

    /// A missing or garbled half is `None`, never a zero standing in for a
    /// measurement nobody made.
    #[test]
    fn signal_and_noise_halves_are_independent() {
        assert_eq!(parse_signal_noise("-62 dBm"), (Some(-62), None));
        assert_eq!(parse_signal_noise("-62 dBm / n/a"), (Some(-62), None));
        assert_eq!(parse_signal_noise(" / -94 dBm"), (None, Some(-94)));
        assert_eq!(parse_signal_noise(""), (None, None));
        assert_eq!(parse_signal_noise("garbage"), (None, None));
    }

    #[test]
    fn strips_the_security_prefix_and_keeps_anything_else() {
        assert_eq!(
            parse_security("spairport_security_mode_wpa3_transition"),
            "wpa3_transition"
        );
        assert_eq!(parse_security("none"), "none");
    }

    /// The live report on this machine spells the WPA3-transition token without
    /// its leading `s`. Observed, not supposed: the fixture in the menu bar's
    /// tests is a verbatim `system_profiler` slice that carries it.
    #[test]
    fn strips_the_security_prefix_the_report_spells_without_its_leading_s() {
        assert_eq!(
            parse_security("pairport_security_mode_wpa3_transition"),
            "wpa3_transition"
        );
    }
}
