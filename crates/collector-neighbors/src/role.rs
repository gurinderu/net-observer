//! Neighbour ROLE inference: a confidence-rated hypothesis about what kind of
//! device each neighbour is (gateway / infra / host / unknown).
//!
//! Every verdict is a hypothesis, never an asserted fact — a wrong guess dressed
//! as certainty is worse than no guess (realm net-observer, node #33). The rules,
//! applied in order:
//!
//! 1. **Gateway** — the neighbour's MAC is the segment's `network_key`. The one
//!    near-certain case; it needs no vendor guess and is kept distinct.
//! 2. **Infra** (switch / AP / router) — a hypothesis. Two independent signals,
//!    graded by [`RoleConfidence`]:
//!    * an OUI that resolves to curated network-gear vendor ([`INFRA_VENDORS`]) —
//!      weak on its own (`Low`);
//!    * a management protocol answering — SNMP on 161 stands alone (`Medium`);
//!    * both together corroborate (`High`). A management web/SSH port
//!      ([`MGMT_PORTS`]) counts only to *raise* an already-infra-vendor device,
//!      never to name a plain host infra — a webserver is not a switch.
//! 3. **Host** — a universally-administered MAC whose vendor is not network gear
//!    (or is unknown), with no infra signal.
//! 4. **Unknown** — a randomized/locally-administered MAC (oui-db says
//!    `Randomized`), or no OUI snapshot at all: nothing to go on, and a vendor is
//!    never guessed. (realm net-observer, node #36)
//!
//! Passive callers pass no ports and get a gateway/vendor-only verdict; a scan
//! refines the same function with the ports it found open.
//!
//! **Deliberately deferred — do NOT build:** AP detection via the associated
//! BSSID. macOS gates the BSSID behind Location Services for a LaunchDaemon, so
//! it is not reliably available to this daemon; naming a device an AP from an
//! absent BSSID would be exactly the guess this module refuses. When a reliable
//! BSSID source appears, it attaches here as another infra signal.

use oui_db::{OuiDb, VendorLookup};
use types::{NeighborObs, NeighborRole, NeighborsSample, RoleConfidence};

/// Curated network-gear vendor substrings, matched case-insensitively against the
/// resolved OUI vendor name (and its short form). Small and explicit on purpose:
/// a broad list would turn "vendor-only" from a weak hint into noise. Documented
/// here as the single source of truth. (realm net-observer, node #36)
pub const INFRA_VENDORS: &[&str] = &[
    "cisco", "ubiquiti", "aruba", "mikrotik", "ruckus", "netgear", "tp-link", "juniper", "extreme",
    "fortinet",
];

/// SNMP — the management protocol whose presence is an infra signal on ITS OWN,
/// independent of vendor: a host that answers SNMP is managed like network gear.
pub const SNMP_PORT: u16 = 161;

/// Management surfaces (SSH, HTTP, HTTPS) that only *corroborate* an already
/// infra-vendor device — a plain host serving HTTP is not thereby a switch.
pub const MGMT_PORTS: &[u16] = &[22, 80, 443];

/// Whether a resolved vendor is on the curated network-gear list.
fn is_infra_vendor(lookup: &VendorLookup) -> bool {
    let VendorLookup::Vendor { name, short } = lookup else {
        return false;
    };
    let mut hay = name.to_lowercase();
    if let Some(s) = short {
        hay.push(' ');
        hay.push_str(&s.to_lowercase());
    }
    INFRA_VENDORS.iter().any(|v| hay.contains(v))
}

/// Classify one neighbour into a [`NeighborRole`] hypothesis.
///
/// `oui` is the loaded registry, or `None` when no snapshot is provisioned — in
/// which case the verdict degrades honestly to gateway-or-unknown, never a
/// guessed vendor. `open_ports` is empty for a passive reading and carries the
/// scan's findings otherwise.
#[must_use]
pub fn classify_role(
    mac: &str,
    network_key: Option<&str>,
    oui: Option<&OuiDb>,
    open_ports: &[u16],
) -> NeighborRole {
    // 1. Gateway — decided by the segment's own key, independent of any snapshot.
    if let Some(key) = network_key
        && mac.eq_ignore_ascii_case(key)
    {
        return NeighborRole::Gateway;
    }

    // Without a snapshot there is nothing to reason a vendor from: honest Unknown.
    let Some(db) = oui else {
        return NeighborRole::Unknown;
    };

    let lookup = db.lookup(mac);
    // A randomized/locally-administered MAC carries no owner — never a guess.
    if lookup == VendorLookup::Randomized {
        return NeighborRole::Unknown;
    }

    let infra_vendor = is_infra_vendor(&lookup);
    let snmp = open_ports.contains(&SNMP_PORT);
    let mgmt = open_ports.iter().any(|p| MGMT_PORTS.contains(p));

    // 2. Infra hypotheses, strongest first.
    if infra_vendor && (snmp || mgmt) {
        NeighborRole::Infra {
            confidence: RoleConfidence::High,
        }
    } else if snmp {
        NeighborRole::Infra {
            confidence: RoleConfidence::Medium,
        }
    } else if infra_vendor {
        NeighborRole::Infra {
            confidence: RoleConfidence::Low,
        }
    } else {
        // 3. A universally-administered MAC with a non-infra (or unknown) vendor
        //    and no infra signal is an end host.
        NeighborRole::Host
    }
}

/// Fill the `role` on each neighbour of a sample from a PASSIVE reading — gateway
/// plus vendor only, no ports. A scan uses [`classify_role`] directly with the
/// per-neighbour ports it found.
pub fn assign_passive_roles(sample: &mut NeighborsSample, oui: Option<&OuiDb>) {
    let key = sample.network_key.clone();
    for n in &mut sample.neighbors {
        n.role = classify_role(&n.mac, key.as_deref(), oui, &[]);
    }
}

/// Refine the roles on a scan's found neighbours with the ports it observed.
/// `ports_for` yields the open ports attributed to a given MAC.
pub fn assign_scan_roles<'a>(
    found: &mut [NeighborObs],
    network_key: Option<&str>,
    oui: Option<&OuiDb>,
    mut ports_for: impl FnMut(&str) -> &'a [u16],
) {
    for n in found.iter_mut() {
        let ports = ports_for(&n.mac);
        n.role = classify_role(&n.mac, network_key, oui, ports);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny in-memory oui-db from `manuf`-format lines, so the rules are tested
    /// with fake vendor data and no snapshot file.
    fn fake_db(lines: &str) -> OuiDb {
        // A UNIQUE file per call: tests run in parallel, so a name keyed only on
        // the pid let one test's `remove_file` delete the file another was about
        // to load — a race that failed `load_from_file` nondeterministically.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "role-test-{}-{n}.manuf",
            std::process::id()
        ));
        std::fs::write(&path, lines).unwrap();
        let db = OuiDb::load_from_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        db
    }

    // Cisco OUI (infra vendor), Dell OUI (a plain host vendor). Universally
    // administered first octets (low bit of the 0x02 mask clear).
    const MANUF: &str = "00:1a:2b\tCisco\tCisco Systems\n\
                         b8:2a:72\tDell\tDell Inc.\n";

    #[test]
    fn gateway_wins_by_key_match_even_without_a_db() {
        let role = classify_role("aa:bb:cc:dd:ee:ff", Some("AA:BB:CC:DD:EE:FF"), None, &[]);
        assert_eq!(role, NeighborRole::Gateway);
    }

    #[test]
    fn no_db_degrades_non_gateway_to_unknown() {
        let role = classify_role("00:1a:2b:11:22:33", Some("ff:ff:ff:ff:ff:ff"), None, &[]);
        assert_eq!(role, NeighborRole::Unknown);
    }

    #[test]
    fn infra_vendor_alone_is_low_confidence_infra() {
        let db = fake_db(MANUF);
        let role = classify_role("00:1a:2b:11:22:33", None, Some(&db), &[]);
        assert_eq!(
            role,
            NeighborRole::Infra {
                confidence: RoleConfidence::Low
            }
        );
    }

    #[test]
    fn infra_vendor_plus_mgmt_port_is_high_confidence() {
        let db = fake_db(MANUF);
        let role = classify_role("00:1a:2b:11:22:33", None, Some(&db), &[443]);
        assert_eq!(
            role,
            NeighborRole::Infra {
                confidence: RoleConfidence::High
            }
        );
    }

    #[test]
    fn snmp_alone_is_medium_infra_even_for_a_plain_vendor() {
        let db = fake_db(MANUF);
        // Dell is not an infra vendor, but an SNMP agent is a management signal.
        let role = classify_role("b8:2a:72:11:22:33", None, Some(&db), &[SNMP_PORT]);
        assert_eq!(
            role,
            NeighborRole::Infra {
                confidence: RoleConfidence::Medium
            }
        );
    }

    #[test]
    fn a_plain_vendor_with_no_infra_signal_is_a_host() {
        let db = fake_db(MANUF);
        // Dell with only a web port open is a host, not infra — mgmt ports only
        // corroborate an already-infra vendor.
        let role = classify_role("b8:2a:72:11:22:33", None, Some(&db), &[80]);
        assert_eq!(role, NeighborRole::Host);
    }

    #[test]
    fn an_unknown_vendor_universal_mac_is_a_host() {
        let db = fake_db(MANUF);
        let role = classify_role("3c:11:22:33:44:55", None, Some(&db), &[]);
        assert_eq!(role, NeighborRole::Host);
    }

    #[test]
    fn a_randomized_mac_is_unknown_never_guessed() {
        let db = fake_db(MANUF);
        // 0x02 bit set in the first octet -> locally administered / randomized.
        let role = classify_role("02:00:00:11:22:33", None, Some(&db), &[SNMP_PORT]);
        assert_eq!(role, NeighborRole::Unknown);
    }

    #[test]
    fn assign_passive_roles_fills_gateway_and_vendor() {
        let db = fake_db(MANUF);
        let mut sample = NeighborsSample {
            ts_us: 1,
            verdict: types::NeighborsVerdict::Ok,
            reason: None,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            neighbors: vec![
                NeighborObs {
                    mac: "aa:bb:cc:dd:ee:ff".into(),
                    ip: "192.168.1.1".into(),
                    source: types::NeighborSource::Arp,
                    hostname: None,
                    role: NeighborRole::Unknown,
                },
                NeighborObs {
                    mac: "00:1a:2b:11:22:33".into(),
                    ip: "192.168.1.2".into(),
                    source: types::NeighborSource::Arp,
                    hostname: None,
                    role: NeighborRole::Unknown,
                },
            ],
        };
        assign_passive_roles(&mut sample, Some(&db));
        assert_eq!(sample.neighbors[0].role, NeighborRole::Gateway);
        assert_eq!(
            sample.neighbors[1].role,
            NeighborRole::Infra {
                confidence: RoleConfidence::Low
            }
        );
    }
}
