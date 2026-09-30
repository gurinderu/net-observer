//! The captive-portal probe's reading (realm net-observer, nodes #177, #178).
//!
//! A route event on a physical interface (a fresh address, a new default)
//! starts a probe series against the captive-detect URL, pinned to that
//! interface so the tunnel cannot answer for the underlay. Each probe writes
//! one of these: the network passed the request through (`OK`), something
//! intercepted it (`PORTAL`, with the login page when the intercept named
//! one), or the probe could not run (`SKIP`, with the reason) — absence of a
//! signal is itself diagnostic, never silence.

use serde::{Deserialize, Serialize};

use crate::verdict::PortalVerdict;

/// One captive-portal probe's outcome on one physical interface: a row of the
/// `portal_sample` table and the payload of the `portal` frame on the bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortalSample {
    /// When the probe finished (epoch microseconds).
    pub ts_us: i64,
    /// The physical interface the probe was pinned to (`IP_BOUND_IF`).
    pub iface: String,
    pub verdict: PortalVerdict,
    /// The portal's login page, from the intercept's `Location` — present
    /// only under `PORTAL`, and only when the intercept was a redirect.
    /// `serde(default)`: a sender that omits it leaves the page unsaid
    /// rather than the frame undecodable.
    #[serde(default)]
    pub login_url: Option<String>,
    /// What shaped this reading: the `SKIP` reason (withheld by the passive
    /// tier, no DHCP resolver, transport failure), or the non-`Success`
    /// shape behind a `PORTAL` verdict without a redirect.
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_round_trips_with_and_without_its_optional_fields() {
        let full = PortalSample {
            ts_us: 42,
            iface: "en0".into(),
            verdict: PortalVerdict::Portal,
            login_url: Some("http://login.wifi.example/".into()),
            reason: None,
        };
        // On the wire the verdict travels as the serde variant name (like
        // every other verdict enum); "PORTAL" is the Display/DB spelling.
        let json = serde_json::to_string(&full).unwrap();
        assert!(json.contains("\"verdict\":\"Portal\""), "{json}");
        assert_eq!(serde_json::from_str::<PortalSample>(&json).unwrap(), full);
        assert_eq!(PortalVerdict::Portal.to_string(), "PORTAL");

        // A row written without the optional fields still decodes.
        let bare = r#"{"ts_us":7,"iface":"en0","verdict":"Skip"}"#;
        assert_eq!(
            serde_json::from_str::<PortalSample>(bare).unwrap(),
            PortalSample {
                ts_us: 7,
                iface: "en0".into(),
                verdict: PortalVerdict::Skip,
                login_url: None,
                reason: None,
            }
        );
    }
}
