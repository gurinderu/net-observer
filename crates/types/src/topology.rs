//! Switch-topology links learned passively from LLDP/CDP discovery frames.
//!
//! A switch or access point periodically broadcasts who it is and which of its
//! ports you are plugged into, over LLDP (EtherType `0x88CC`) or Cisco's CDP
//! (SNAP-encapsulated). Receiving one such frame tells this machine a single
//! forensic fact: **the interface `iface` uplinks to a device whose chassis is
//! `remote_chassis`, on that device's port `remote_port`**. That is one edge of
//! the physical topology, discovered without emitting anything — we only listen.
//!
//! This module is the pure mapping from a captured raw Ethernet frame to a
//! stored [`TopologyLink`]. It consumes the `lldp` decoder (realm net-observer,
//! node #42), which is panic-safe on arbitrary bytes; every path here that the
//! decoder cannot make sense of yields `None`, never a panic. The *capture* of
//! the frame is a separate, privileged concern (a BPF/pcap read needing root);
//! this mapping is what the capture feeds and what the tests exercise.
//!
//! # A hypothesis, not a claim
//! LLDP and CDP are unauthenticated and trivially spoofable, so a link here is a
//! hypothesis about the physical topology, not an asserted fact — the reader and
//! the map treat it as such.

use serde::{Deserialize, Serialize};

use lldp::{CapabilitySet, parse_cdp, parse_lldp};

/// EtherType for LLDP (IEEE 802.1AB).
const ETHERTYPE_LLDP: u16 = 0x88CC;

/// The 8-byte LLC + SNAP header that prefixes a CDP payload on an 802.3 frame:
/// LLC `AA AA 03` (SNAP), then OUI `00 00 0C` (Cisco) and protocol id `20 00`
/// (CDP). The frame's EtherType slot instead carries the 802.3 length, so CDP is
/// recognised by this header rather than by an EtherType.
const CDP_SNAP: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00];

/// The minimum Ethernet header: 6-byte destination, 6-byte source, 2-byte
/// EtherType / 802.3 length.
const ETH_HEADER_LEN: usize = 14;

/// How a topology link was learned. Serialised as its lowercase token
/// (`"lldp"` / `"cdp"`) so it reads the same in the store column and on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearnedVia {
    /// IEEE 802.1AB LLDP.
    Lldp,
    /// Cisco Discovery Protocol.
    Cdp,
    /// A protocol a newer peer knows and this build does not: the `#[serde(other)]`
    /// sink, so an unknown token decodes here instead of failing the whole
    /// `StatusSnapshot` decode and blanking an older reader.
    #[default]
    #[serde(other)]
    Unknown,
}

impl LearnedVia {
    /// The lowercase token stored in the `learned_via` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LearnedVia::Lldp => "lldp",
            LearnedVia::Cdp => "cdp",
            LearnedVia::Unknown => "unknown",
        }
    }
}

/// One discovered uplink: this machine's `iface` is connected to a switch/AP
/// identified by `remote_chassis`, on that device's `remote_port`.
///
/// The identity triple `(iface, remote_chassis, remote_port)` is the stable key
/// the store upserts on, mirroring the `neighbor` entity: the same uplink keeps
/// the same key across sightings while `remote_system_name` and `capabilities`
/// may be refined, and `first_seen`/`last_seen` bound its lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyLink {
    /// The local interface the frame was received on (e.g. `en0`).
    pub iface: String,
    /// The remote device's chassis identity — a rendered MAC/name when the
    /// decoder could interpret it, else a hex rendering of the raw id bytes.
    /// Never empty: a frame carrying no usable remote identity yields no link.
    pub remote_chassis: String,
    /// The remote device's port the machine is plugged into — rendered when
    /// possible, else a hex rendering, else the literal `"?"` when the frame
    /// carried no port id at all (the chassis alone still names an uplink).
    pub remote_port: String,
    /// The remote device's advertised system name / hostname, when present.
    pub remote_system_name: Option<String>,
    /// The remote device's enabled capabilities as a comma-joined token list
    /// (e.g. `"bridge,router"`); empty when none were advertised. A device
    /// advertising `bridge` or `wlan_ap` is the switch/AP this machine uplinks
    /// through — the whole point of drawing the edge.
    pub capabilities: String,
    /// Which protocol carried the frame.
    pub learned_via: LearnedVia,
    /// When this sighting was observed.
    pub ts_us: i64,
}

/// How long an uplink has been on record: the lifetime bounds the store keeps
/// for one `topology_link` row.
///
/// A **sibling** of [`TopologyLink`], for the same reason [`NeighborLifetime`]
/// is a sibling of `NeighborObs`: a link on the socket is a *sighting*
/// (`ts_us` is when the patrol last heard the advertisement), while `first_seen`
/// is what the record remembers. The daemon reads these from `topology_link` and
/// puts them on the status snapshot beside the links, so the bar can say "this
/// uplink has been there since X" without opening the database.
///
/// An uplink on the snapshot may have NO lifetime here — the store write may
/// have failed, or the daemon may predate this field. Render that as *unknown*,
/// never as *now*. (realm net-observer, node #43)
///
/// [`NeighborLifetime`]: crate::neighbor::NeighborLifetime
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyLifetime {
    /// The local interface — first third of the identity triple this bounds.
    pub iface: String,
    /// The remote chassis identity — second third of the triple.
    pub remote_chassis: String,
    /// The remote port — final third of the triple.
    pub remote_port: String,
    /// When this uplink was first written. Never reset by a later sighting.
    pub first_seen_us: i64,
    /// When it was most recently heard, as the record has it.
    pub last_seen_us: i64,
}

impl TopologyLifetime {
    /// Whether this lifetime bounds `link` — the identity triple, compared as a
    /// whole. The one place the join is spelled, so no consumer invents a looser
    /// match.
    #[must_use]
    pub fn bounds(&self, link: &TopologyLink) -> bool {
        self.iface == link.iface
            && self.remote_chassis == link.remote_chassis
            && self.remote_port == link.remote_port
    }
}

/// Map a captured **raw Ethernet frame** (starting at the destination MAC) to a
/// [`TopologyLink`], or `None` when it is not an LLDP/CDP frame this machine can
/// turn into an uplink edge.
///
/// Returns `None` — never panics — for a frame too short to hold an Ethernet
/// header, a non-LLDP/non-CDP EtherType, a payload the decoder rejects, or a
/// decoded frame that carries no usable remote chassis identity. Absence is the
/// honest answer: a frame we cannot interpret is not a guessed edge.
#[must_use]
pub fn link_from_frame(eth: &[u8], iface: &str, ts_us: i64) -> Option<TopologyLink> {
    if eth.len() < ETH_HEADER_LEN {
        return None;
    }
    // Bytes 12..14 are the EtherType (LLDP) or the 802.3 length (CDP path). A
    // single 802.1Q VLAN tag (0x8100) is peeled first: the real EtherType and
    // payload sit 4 bytes further on. LLDP is normally untagged, but a tagged
    // trunk would otherwise silently yield no edges.
    let (ethertype, payload) = match u16::from_be_bytes([eth[12], eth[13]]) {
        0x8100 if eth.len() >= ETH_HEADER_LEN + 4 => (
            u16::from_be_bytes([eth[16], eth[17]]),
            &eth[ETH_HEADER_LEN + 4..],
        ),
        other => (other, &eth[ETH_HEADER_LEN..]),
    };

    if ethertype == ETHERTYPE_LLDP {
        link_from_lldp(payload, iface, ts_us)
    } else if payload.len() >= CDP_SNAP.len() && payload[..CDP_SNAP.len()] == CDP_SNAP {
        // 802.3-framed CDP: strip the LLC + SNAP header to reach the CDP payload.
        link_from_cdp(&payload[CDP_SNAP.len()..], iface, ts_us)
    } else {
        None
    }
}

/// Map an LLDPDU (bytes starting at the first TLV) to a link. Public so a caller
/// that already stripped the Ethernet framing (or a test) can map directly.
#[must_use]
pub fn link_from_lldp(pdu: &[u8], iface: &str, ts_us: i64) -> Option<TopologyLink> {
    let frame = parse_lldp(pdu).ok()?;
    let remote_chassis = render_id(frame.chassis_id.rendered.as_deref(), &frame.chassis_id.raw)?;
    let remote_port = render_id(frame.port_id.rendered.as_deref(), &frame.port_id.raw)
        .unwrap_or_else(|| "?".to_string());
    let capabilities = frame
        .capabilities
        .map(|c| caps_tokens(&c.enabled))
        .unwrap_or_default();
    Some(TopologyLink {
        iface: iface.to_string(),
        remote_chassis,
        remote_port,
        remote_system_name: frame.system_name,
        capabilities,
        learned_via: LearnedVia::Lldp,
        ts_us,
    })
}

/// Map a CDP payload (bytes starting at the CDP header) to a link.
#[must_use]
pub fn link_from_cdp(payload: &[u8], iface: &str, ts_us: i64) -> Option<TopologyLink> {
    let frame = parse_cdp(payload).ok()?;
    // CDP's Device ID is the remote's identity (its hostname); without it there
    // is no chassis to key an edge on.
    let remote_chassis = frame.device_id.clone().filter(|s| !s.is_empty())?;
    let remote_port = frame
        .port_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "?".to_string());
    let capabilities = frame
        .capabilities
        .map(|c| caps_tokens(&c.enabled))
        .unwrap_or_default();
    Some(TopologyLink {
        iface: iface.to_string(),
        // CDP has no separate system-name TLV; the Device ID is both. Keep it in
        // `remote_system_name` too so the map has a human label without re-deriving.
        remote_system_name: Some(remote_chassis.clone()),
        remote_chassis,
        remote_port,
        capabilities,
        learned_via: LearnedVia::Cdp,
        ts_us,
    })
}

/// Prefer the decoder's confident rendering; fall back to a hex rendering of the
/// raw bytes. `None` only when there is nothing at all to identify the device by
/// (no rendering and no raw bytes) — an edge with no remote identity is dropped.
fn render_id(rendered: Option<&str>, raw: &[u8]) -> Option<String> {
    if let Some(r) = rendered.filter(|s| !s.is_empty()) {
        return Some(r.to_string());
    }
    if raw.is_empty() {
        return None;
    }
    Some(hex(raw))
}

/// Lowercase colon-separated hex of the bytes, e.g. `aa:bb:cc`.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The enabled capability flags as a comma-joined token list, in a fixed order
/// so the same device always renders the same string (a stable value the upsert
/// can compare and the reader can group on).
fn caps_tokens(set: &CapabilitySet) -> String {
    let mut tokens = Vec::new();
    if set.bridge {
        tokens.push("bridge");
    }
    if set.wlan_ap {
        tokens.push("wlan_ap");
    }
    if set.router {
        tokens.push("router");
    }
    if set.repeater {
        tokens.push("repeater");
    }
    if set.telephone {
        tokens.push("telephone");
    }
    if set.docsis {
        tokens.push("docsis");
    }
    if set.station {
        tokens.push("station");
    }
    if set.other {
        tokens.push("other");
    }
    tokens.join(",")
}

#[cfg(test)]
mod tests {
    use super::TopologyLifetime;

    /// The lifetime join is the WHOLE identity triple. A link that shares two of
    /// the three is a different uplink and must not borrow its neighbour's
    /// first-seen.
    #[test]
    fn bounds_matches_only_the_full_identity_triple() {
        let lt = TopologyLifetime {
            iface: "en0".into(),
            remote_chassis: "sw-1".into(),
            remote_port: "Gi0/1".into(),
            first_seen_us: 1,
            last_seen_us: 2,
        };
        let mut link = super::TopologyLink {
            iface: "en0".into(),
            remote_chassis: "sw-1".into(),
            remote_port: "Gi0/1".into(),
            remote_system_name: None,
            capabilities: String::new(),
            learned_via: super::LearnedVia::Lldp,
            ts_us: 5,
        };
        assert!(lt.bounds(&link));
        link.remote_port = "Gi0/2".into();
        assert!(!lt.bounds(&link));
    }

    use super::*;

    /// Prepend a synthetic Ethernet header (dst, src, EtherType) to a payload so
    /// a PDU fixture built like the `lldp` crate's own tests can be fed through
    /// the full raw-frame path.
    fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // dst: LLDP multicast
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
        ];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// A minimal LLDPDU: Chassis ID (MAC), Port ID (iface name), TTL, capabilities
    /// (bridge enabled), System Name, End — the same construction style as the
    /// `lldp` crate's tests.
    fn lldp_pdu() -> Vec<u8> {
        vec![
            0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // chassis id: MAC
            0x04, 0x06, 0x05, b'G', b'i', b'0', b'/', b'1', // port id: "Gi0/1"
            0x06, 0x02, 0x00, 0x78, // ttl: 120
            // System Capabilities TLV (type 7, len 4): available + enabled, bridge bit.
            0x0e, 0x04, 0x00, 0x04, 0x00, 0x04, // system name TLV (type 5): "sw1"
            0x0a, 0x03, b's', b'w', b'1', 0x00, 0x00, // end
        ]
    }

    /// A single 802.1Q VLAN tag before the LLDP EtherType is peeled, so a
    /// tagged-trunk LLDP frame still yields an edge instead of silently None.
    #[test]
    fn a_vlan_tagged_lldp_frame_still_yields_an_edge() {
        let mut f = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x81, 0x00, 0x00, 0x64, // 802.1Q tag, VLAN 100
        ];
        f.extend_from_slice(&ETHERTYPE_LLDP.to_be_bytes());
        f.extend_from_slice(&lldp_pdu());
        let link = link_from_frame(&f, "en0", 9).expect("a tagged LLDP frame is an edge");
        assert_eq!(link.remote_chassis, "00:11:22:33:44:55");
    }

    /// A `learned_via` token a newer peer might send decodes to `Unknown`, never
    /// failing the whole decode — the serde(other) forward-compat.
    #[test]
    fn an_unknown_learned_via_token_decodes_to_unknown() {
        let v: LearnedVia = serde_json::from_str("\"future_proto\"").expect("must not fail");
        assert_eq!(v, LearnedVia::Unknown);
    }

    #[test]
    fn an_lldp_frame_yields_the_expected_edge() {
        let link = link_from_frame(&eth_frame(ETHERTYPE_LLDP, &lldp_pdu()), "en0", 42).unwrap();
        assert_eq!(link.iface, "en0");
        assert_eq!(link.remote_chassis, "00:11:22:33:44:55");
        assert_eq!(link.remote_port, "Gi0/1");
        assert_eq!(link.remote_system_name.as_deref(), Some("sw1"));
        assert_eq!(link.capabilities, "bridge");
        assert_eq!(link.learned_via, LearnedVia::Lldp);
        assert_eq!(link.ts_us, 42);
    }

    /// A CDP frame (802.3 length + LLC/SNAP + CDP header) yields a CDP-learned
    /// edge keyed by the Device ID.
    #[test]
    fn a_cdp_frame_yields_the_expected_edge() {
        // CDP header: version 2, ttl 180, checksum 0x0000, then TLVs.
        let mut cdp = vec![0x02, 0xb4, 0x00, 0x00];
        // Device ID TLV (type 0x0001), length counts the 4-byte header: "core-sw".
        cdp.extend_from_slice(&[0x00, 0x01, 0x00, 0x0b]);
        cdp.extend_from_slice(b"core-sw");
        // Port ID TLV (type 0x0003): "Gi0/2".
        cdp.extend_from_slice(&[0x00, 0x03, 0x00, 0x09]);
        cdp.extend_from_slice(b"Gi0/2");
        // Capabilities TLV (type 0x0004, 32-bit): Switch (0x08) set.
        cdp.extend_from_slice(&[0x00, 0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08]);

        // Wrap in 802.3 framing: length slot + LLC/SNAP header + CDP.
        let mut payload = Vec::new();
        payload.extend_from_slice(&CDP_SNAP);
        payload.extend_from_slice(&cdp);
        let len = payload.len() as u16;
        let frame = eth_frame(len, &payload);

        let link = link_from_frame(&frame, "en0", 7).unwrap();
        assert_eq!(link.remote_chassis, "core-sw");
        assert_eq!(link.remote_port, "Gi0/2");
        assert_eq!(link.remote_system_name.as_deref(), Some("core-sw"));
        assert_eq!(link.capabilities, "bridge");
        assert_eq!(link.learned_via, LearnedVia::Cdp);
    }

    /// A malformed frame yields nothing, never a panic — the forensics
    /// discipline the `lldp` crate guarantees, carried through this mapping.
    #[test]
    fn a_malformed_frame_yields_nothing() {
        // Too short for even an Ethernet header.
        assert!(link_from_frame(&[0x00, 0x01, 0x02], "en0", 1).is_none());
        // Right EtherType, but a truncated/garbage LLDPDU the decoder rejects.
        assert!(
            link_from_frame(&eth_frame(ETHERTYPE_LLDP, &[0xff, 0xff, 0xff]), "en0", 1).is_none()
        );
        // A non-LLDP, non-CDP EtherType (IPv4).
        assert!(link_from_frame(&eth_frame(0x0800, &[0u8; 40]), "en0", 1).is_none());
    }

    /// Arbitrary bytes never panic — a fuzz-style guard mirroring the decoder's.
    #[test]
    fn arbitrary_bytes_never_panic() {
        for len in 0..64usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let _ = link_from_frame(&bytes, "en0", 0);
        }
    }

    /// A frame whose port id is absent still names an uplink by its chassis, with
    /// the port rendered as `"?"`.
    #[test]
    fn a_missing_port_still_names_the_chassis() {
        let pdu = vec![
            0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // chassis id: MAC
            0x04, 0x01, 0x05, // port id: subtype 5, but no value bytes
            0x06, 0x02, 0x00, 0x78, // ttl
            0x00, 0x00, // end
        ];
        let link = link_from_lldp(&pdu, "en0", 1).unwrap();
        assert_eq!(link.remote_chassis, "00:11:22:33:44:55");
        assert_eq!(link.remote_port, "?");
    }
}
