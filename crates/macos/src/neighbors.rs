//! macOS implementation of [`NeighborFacts`]: the kernel's own ARP and NDP
//! caches, read with `arp -an` and `ndp -an`.
//!
//! **Nothing here addresses a packet at anybody.** Both commands print tables the
//! kernel already holds, which is why this collector keeps reading under quiet
//! mode. Filling those tables on purpose is `ScanNeighbors`, a separate
//! operator-pressed action.
//!
//! `arp -an` (BSD) prints one line per entry:
//!
//! ```text
//! ? (192.168.1.1) at a4:83:e7:1b:2c:3d on en0 ifscope [ethernet]
//! ? (192.168.1.9) at (incomplete) on en0 [ethernet]
//! ```
//!
//! and `ndp -an` a fixed-column table:
//!
//! ```text
//! Neighbor                Linklayer Address  Netif Expire    St Flgs Prbs
//! fe80::1%en0             a4:83:e7:1b:2c:3d  en0   23h59m50s S  R
//! ```
//!
//! Both parse defensively: an unrecognised line is skipped, never a panic.

use collector_core::Readiness;
use collector_link::LinkFacts;
use collector_neighbors::{NeighborFacts, NeighborReading};
use types::{NeighborObs, NeighborRole, NeighborSource};

use crate::dhcp_arp::{SystemFacts, run};

/// macOS implementation of [`NeighborFacts`], reusing [`SystemFacts`] for the
/// default gateway and physical interface (and therefore honouring the same
/// config overrides the `link` collector does).
#[derive(Debug, Clone, Default)]
pub struct SystemNeighbors {
    facts: SystemFacts,
}

impl SystemNeighbors {
    /// Build from an already-configured [`SystemFacts`].
    #[must_use]
    pub fn new(facts: SystemFacts) -> Self {
        Self { facts }
    }
}

impl NeighborFacts for SystemNeighbors {
    async fn read(&self) -> Option<NeighborReading> {
        let iface = self.facts.phys_iface().await;
        // The segment's identity: the gateway's own MAC. `None` when there is no
        // default route or no ARP entry for it — the sample then records the
        // neighbours under the "unknown network" key rather than under a wrong one.
        let network_key = match self.facts.default_gw().await {
            Some(gw) => self.facts.gw_arp_mac(&gw).await,
            None => None,
        };

        let arp = run("arp", &["-an"]).await;
        let ndp = run("ndp", &["-an"]).await;
        // Both commands failing is a genuinely unreadable cache: SKIP. One of the
        // two failing is not — a host with IPv6 disabled has no `ndp` output and
        // its ARP table is still the truth about the segment.
        if arp.is_none() && ndp.is_none() {
            return None;
        }

        let mut neighbors = Vec::new();
        if let Some(out) = &arp {
            neighbors.extend(parse_arp_table(out, iface.as_deref()));
        }
        if let Some(out) = &ndp {
            neighbors.extend(parse_ndp_table(out, iface.as_deref()));
        }
        // One row per device, because `neighbor` is keyed by MAC. Sorting by
        // (mac, ip) before the dedup makes the survivor deterministic rather than
        // dependent on which table was read first, and the v4 address wins for a
        // dual-stack device: digits sort before the hex letters and colons of a
        // v6 literal. That is a deliberate choice of the address a human can act
        // on — a v6-only neighbour still keeps its own address, since it has no
        // v4 entry to lose to.
        neighbors.sort_by(|a, b| (&a.mac, &a.ip).cmp(&(&b.mac, &b.ip)));
        neighbors.dedup_by(|a, b| a.mac == b.mac);

        Some(NeighborReading {
            network_key,
            iface,
            neighbors,
        })
    }

    async fn preflight(&self) -> Readiness {
        if run("arp", &["-an"]).await.is_some() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("arp(8) unavailable".into())
        }
    }
}

/// Read the ARP cache now and parse it: the post-sweep re-read, and the one
/// place outside the collector that needs the table on demand.
pub async fn read_arp(iface: Option<&str>) -> Option<Vec<NeighborObs>> {
    Some(parse_arp_table(&run("arp", &["-an"]).await?, iface))
}

/// Parse `arp -an` output into observations, keeping only entries on `iface`
/// (when known) that carry a real unicast MAC.
#[must_use]
pub fn parse_arp_table(out: &str, iface: Option<&str>) -> Vec<NeighborObs> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some(rest) = line.split_once(" (").map(|(_, r)| r) else {
            continue;
        };
        let Some((ip, rest)) = rest.split_once(") at ") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        let Some(mac_raw) = fields.next() else {
            continue;
        };
        // `on <iface>` follows the MAC; an entry without it is not attributable.
        let on_iface = match (fields.next(), fields.next()) {
            (Some("on"), Some(name)) => name,
            _ => continue,
        };
        if iface.is_some_and(|want| want != on_iface) {
            continue;
        }
        let Some(mac) = normalize_mac(mac_raw) else {
            continue;
        };
        v.push(NeighborObs {
            mac,
            ip: ip.to_string(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        });
    }
    v
}

/// Parse `ndp -an` output into observations, same filtering as the ARP table.
/// The scope suffix (`fe80::1%en0`) is stripped from the address.
#[must_use]
pub fn parse_ndp_table(out: &str, iface: Option<&str>) -> Vec<NeighborObs> {
    let mut v = Vec::new();
    for line in out.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(addr), Some(mac_raw), Some(netif)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if iface.is_some_and(|want| want != netif) {
            continue;
        }
        let Some(mac) = normalize_mac(mac_raw) else {
            continue;
        };
        let ip = addr.split('%').next().unwrap_or(addr);
        v.push(NeighborObs {
            mac: mac.clone(),
            ip: ip.to_string(),
            source: NeighborSource::Ndp,
            hostname: None,
            role: NeighborRole::Unknown,
        });
    }
    v
}

/// Normalise a BSD-printed MAC to lowercase `aa:bb:cc:dd:ee:ff`, or `None` when
/// it is not a usable neighbour address.
///
/// BSD prints octets without leading zeros (`0:1c:42:…`), so the padding matters:
/// unpadded, the same device would key two different `neighbor` rows depending on
/// which tool saw it. Rejected outright: `(incomplete)` placeholders, the
/// broadcast address, and any multicast MAC (least-significant bit of the first
/// octet set) — those are not devices on the segment.
#[must_use]
pub fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut octets = Vec::with_capacity(6);
    for p in parts {
        octets.push(u8::from_str_radix(p, 16).ok()?);
    }
    if octets.iter().all(|&o| o == 0xff) || octets[0] & 1 == 1 {
        return None;
    }
    Some(
        octets
            .iter()
            .map(|o| format!("{o:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str = "\
? (192.168.1.1) at a4:83:e7:1b:2c:3d on en0 ifscope [ethernet]
? (192.168.1.9) at 0:1c:42:8:9:a on en0 ifscope [ethernet]
? (192.168.1.77) at (incomplete) on en0 [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (10.0.0.2) at aa:bb:cc:dd:ee:ff on en5 [ethernet]";

    const NDP: &str = "\
Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                          a4:83:e7:1b:2c:3d  en0   23h59m50s S  R
fe80::99%en0                         (incomplete)       en0   expired   N
fe80::5%en5                          12:22:33:44:55:66  en5   1m0s      S";

    #[test]
    fn arp_keeps_only_real_neighbours_on_the_interface() {
        let v = parse_arp_table(ARP, Some("en0"));
        let ips: Vec<&str> = v.iter().map(|n| n.ip.as_str()).collect();
        assert_eq!(ips, vec!["192.168.1.1", "192.168.1.9"]);
        assert!(v.iter().all(|n| n.source == NeighborSource::Arp));
    }

    /// Unpadded octets must key the same row as padded ones.
    #[test]
    fn arp_pads_bsd_short_octets() {
        let v = parse_arp_table(ARP, Some("en0"));
        assert_eq!(v[1].mac, "00:1c:42:08:09:0a");
    }

    #[test]
    fn ndp_strips_the_scope_and_skips_incomplete() {
        let v = parse_ndp_table(NDP, Some("en0"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ip, "fe80::1");
        assert_eq!(v[0].source, NeighborSource::Ndp);
    }

    #[test]
    fn a_different_interface_is_excluded() {
        assert!(
            parse_arp_table(ARP, Some("en0"))
                .iter()
                .all(|n| n.ip != "10.0.0.2")
        );
        assert_eq!(parse_ndp_table(NDP, Some("en5")).len(), 1);
    }

    #[test]
    fn broadcast_and_multicast_are_not_neighbours() {
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize_mac("01:00:5e:00:00:fb"), None);
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(
            normalize_mac("a4:83:E7:1b:2c:3d").as_deref(),
            Some("a4:83:e7:1b:2c:3d")
        );
    }

    /// The dual-stack rule the reading relies on: one row per MAC, and the v4
    /// address is the survivor. Asserted on the ordering directly, since the
    /// merge itself needs a live `arp`/`ndp`.
    #[test]
    fn a_dual_stack_device_keeps_its_v4_address() {
        let mut v = vec![
            NeighborObs {
                mac: "a4:83:e7:1b:2c:3d".into(),
                ip: "fe80::1".into(),
                source: NeighborSource::Ndp,
                hostname: None,
                role: NeighborRole::Unknown,
            },
            NeighborObs {
                mac: "a4:83:e7:1b:2c:3d".into(),
                ip: "192.168.1.1".into(),
                source: NeighborSource::Arp,
                hostname: None,
                role: NeighborRole::Unknown,
            },
        ];
        v.sort_by(|a, b| (&a.mac, &a.ip).cmp(&(&b.mac, &b.ip)));
        v.dedup_by(|a, b| a.mac == b.mac);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ip, "192.168.1.1");
    }

    #[test]
    fn garbage_lines_are_skipped_not_panicked_on() {
        assert!(parse_arp_table("total nonsense\n\n? () at\n", None).is_empty());
        assert!(parse_ndp_table("hdr\nnonsense\n", None).is_empty());
    }
}
