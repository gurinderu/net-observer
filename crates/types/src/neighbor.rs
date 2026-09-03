//! Neighbours on the local segment: who else is on this network.
//!
//! Unlike every other collector's output, a neighbour is not a point in time but
//! an entity with a lifetime — the same device keeps the same MAC across ticks
//! while its IP, name and reachability move under it. Writing one row per tick
//! per device would bury the database, so the store keeps two shapes: the
//! per-tick [`NeighborsSample`] (what the reading was, including a SKIP) and a
//! long-lived `neighbor` row per `(network_key, mac)` carrying first/last seen.
//!
//! Passive by default: the ARP and NDP caches are read, never filled. Rows whose
//! [`NeighborSource`] is `Sweep` or `Mdns` exist only because an operator pressed
//! the scan button — the daemon does not probe the segment on a timer.

use serde::{Deserialize, Serialize};

use crate::verdict::{NeighborSource, NeighborsVerdict};

/// A confidence-rated hypothesis about what kind of device a neighbour is.
///
/// Never an asserted fact — a wrong guess rendered as certainty is worse than no
/// guess (realm net-observer, node #33). The variants keep the certain-ish case
/// (`Gateway`, decided by the segment's own key) apart from the inferred ones,
/// and `Infra` carries how strong the inference is so the reader can weigh it.
///
/// Internally tagged (`{"kind": ...}`) and `#[serde(default)]`-friendly via
/// [`NeighborRole::Unknown`]: an older peer that never sent a `role` decodes to
/// `Unknown` rather than failing — the same forward-compatibility the rest of the
/// socket surface relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NeighborRole {
    /// The segment's gateway: this neighbour's MAC is the sample's `network_key`.
    /// The one near-certain classification — it needs no vendor guess.
    Gateway,
    /// Network gear (switch / AP / router), a hypothesis. `confidence` says how
    /// much to trust it: vendor-only is weak, vendor plus a management port is
    /// strong. (realm net-observer, node #36)
    Infra {
        /// How strongly the infra hypothesis is held.
        confidence: RoleConfidence,
    },
    /// An end host: a universally-administered MAC whose vendor is not network
    /// gear (or is unknown), with no management port open.
    Host,
    /// Nothing to go on: a randomized/locally-administered MAC, or no OUI
    /// snapshot to resolve a vendor against. Never a guessed vendor.
    #[default]
    Unknown,
}

/// How strongly an [`NeighborRole::Infra`] hypothesis is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleConfidence {
    /// A single weak signal — an infra-vendor OUI alone.
    Low,
    /// A stronger standalone signal — a management protocol (SNMP) answering.
    Medium,
    /// Corroborated — an infra-vendor OUI *and* a management port open.
    High,
}

/// One neighbour as observed in a single reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborObs {
    /// Normalised lowercase `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// The address the neighbour answered on (v4 or v6, as text).
    pub ip: String,
    /// Which reading produced this observation.
    pub source: NeighborSource,
    /// Name, when one is known. Only mDNS supplies it today.
    pub hostname: Option<String>,
    /// A confidence-rated hypothesis about the neighbour's role on the segment.
    /// `#[serde(default)]` so a sender that predates the field decodes to
    /// [`NeighborRole::Unknown`]. Filled by the inference step (gateway + OUI
    /// vendor passively; refined with open ports after a scan); left `Unknown`
    /// when there is no OUI snapshot to reason from.
    #[serde(default)]
    pub role: NeighborRole,
}

impl NeighborObs {
    /// The OUI — the vendor-assigned first three octets of the MAC, lowercase
    /// `aa:bb:cc`. Kept as its own column so a network can be recognised by the
    /// mix of hardware in it without parsing MACs in SQL.
    #[must_use]
    pub fn oui(&self) -> Option<String> {
        let mut parts = self.mac.split(':');
        let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
        Some(format!("{a}:{b}:{c}"))
    }
}

/// One tick of the `neighbors` collector.
///
/// `network_key` is what separates the coworking segment from the home one: the
/// gateway's MAC, which survives a duplicated `192.168.1.0/24` that an SSID or a
/// subnet does not. `None` when no gateway ARP entry was readable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborsSample {
    pub ts_us: i64,
    pub verdict: NeighborsVerdict,
    /// Why the reading could not run. `Some` iff `verdict == Skip`.
    pub reason: Option<String>,
    pub network_key: Option<String>,
    pub iface: Option<String>,
    pub neighbors: Vec<NeighborObs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oui_is_the_first_three_octets() {
        let n = NeighborObs {
            mac: "a4:83:e7:1b:2c:3d".into(),
            ip: "192.168.1.5".into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        };
        assert_eq!(n.oui().as_deref(), Some("a4:83:e7"));
    }

    #[test]
    fn a_malformed_mac_has_no_oui() {
        let n = NeighborObs {
            mac: "incomplete".into(),
            ip: "192.168.1.5".into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        };
        assert_eq!(n.oui(), None);
    }

    /// A snapshot from a peer that predates the `role` field must still decode —
    /// the same forward-compatibility the whole socket surface relies on. The
    /// missing field defaults to [`NeighborRole::Unknown`], never a decode error.
    #[test]
    fn an_older_obs_without_a_role_decodes_to_unknown() {
        let older =
            r#"{"mac":"a4:83:e7:1b:2c:3d","ip":"192.168.1.5","source":"Arp","hostname":null}"#;
        let n: NeighborObs = serde_json::from_str(older).expect("older obs must decode");
        assert_eq!(n.role, NeighborRole::Unknown);
    }

    /// The role is internally tagged: `{"kind": ...}`, with the confidence carried
    /// inside the infra hypothesis. A round-trip keeps both.
    #[test]
    fn role_is_tagged_and_round_trips() {
        let infra = NeighborRole::Infra {
            confidence: RoleConfidence::High,
        };
        let json = serde_json::to_string(&infra).unwrap();
        assert!(json.contains("\"kind\":\"infra\""), "got {json}");
        assert!(json.contains("\"confidence\":\"high\""), "got {json}");
        assert_eq!(serde_json::from_str::<NeighborRole>(&json).unwrap(), infra);

        let gw = NeighborRole::Gateway;
        assert_eq!(serde_json::to_string(&gw).unwrap(), r#"{"kind":"gateway"}"#);
    }
}
