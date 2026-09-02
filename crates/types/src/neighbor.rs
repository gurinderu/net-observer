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
        };
        assert_eq!(n.oui(), None);
    }
}
