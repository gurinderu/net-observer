//! Decoder tests built from hand-assembled fixture frames.
//!
//! Conventions under test: input begins at the LLDPDU (LLDP) or the CDP header
//! (CDP), never at the Ethernet header. See the crate root.

use crate::{LldpError, parse_cdp, parse_lldp};

/// Build one LLDP TLV: a 2-byte big-endian header (7-bit type, 9-bit length)
/// followed by `value`.
fn lldp_tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
    let header = ((u16::from(tlv_type) & 0x7f) << 9) | (value.len() as u16 & 0x01ff);
    let mut out = header.to_be_bytes().to_vec();
    out.extend_from_slice(value);
    out
}

/// Build one CDP TLV: 2-byte type, 2-byte length (counting the 4-byte header),
/// then `value`.
fn cdp_tlv(tlv_type: u16, value: &[u8]) -> Vec<u8> {
    let len = (value.len() + 4) as u16;
    let mut out = tlv_type.to_be_bytes().to_vec();
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    out
}

// ----- LLDP -----------------------------------------------------------------

#[test]
fn minimal_valid_lldp_frame() {
    let mut pdu = Vec::new();
    // Chassis ID: subtype 4 (MAC) + 6 bytes.
    pdu.extend(lldp_tlv(1, &[0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    // Port ID: subtype 5 (interface name) + "eth0".
    pdu.extend(lldp_tlv(2, &[0x05, b'e', b't', b'h', b'0']));
    // TTL: 120.
    pdu.extend(lldp_tlv(3, &[0x00, 0x78]));
    // End of LLDPDU.
    pdu.extend(lldp_tlv(0, &[]));

    let f = parse_lldp(&pdu).expect("well-formed frame decodes");
    assert_eq!(f.chassis_id.subtype, 4);
    assert_eq!(f.chassis_id.rendered.as_deref(), Some("00:11:22:33:44:55"));
    assert_eq!(f.chassis_id.raw, vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(f.port_id.subtype, 5);
    assert_eq!(f.port_id.rendered.as_deref(), Some("eth0"));
    assert_eq!(f.ttl, 120);
    assert!(f.system_name.is_none());
    assert!(f.capabilities.is_none());
    assert!(f.management_addresses.is_empty());
}

#[test]
fn lldp_with_system_name_capabilities_and_mgmt_address() {
    let mut pdu = Vec::new();
    pdu.extend(lldp_tlv(1, &[0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    pdu.extend(lldp_tlv(2, &[0x05, b'g', b'i', b'0']));
    pdu.extend(lldp_tlv(3, &[0x00, 0x3c]));
    // System name.
    pdu.extend(lldp_tlv(5, b"switch-1"));
    // System capabilities: available = bridge+router, enabled = bridge.
    pdu.extend(lldp_tlv(7, &[0x00, 0x14, 0x00, 0x04]));
    // Management address: IPv4 192.0.2.7.
    // addr-str-len = 1 (family) + 4 (addr) = 5; family = 1 (IPv4); then iface
    // numbering (subtype + 4 bytes) and OID length 0.
    pdu.extend(lldp_tlv(
        8,
        &[0x05, 0x01, 192, 0, 2, 7, 0x02, 0, 0, 0, 1, 0x00],
    ));
    pdu.extend(lldp_tlv(0, &[]));

    let f = parse_lldp(&pdu).expect("decodes");
    assert_eq!(f.system_name.as_deref(), Some("switch-1"));

    let caps = f.capabilities.expect("capabilities present");
    assert!(caps.available.bridge);
    assert!(caps.available.router);
    assert!(caps.enabled.bridge);
    assert!(!caps.enabled.router);

    assert_eq!(f.management_addresses.len(), 1);
    let m = &f.management_addresses[0];
    assert_eq!(m.address_family, 1);
    assert_eq!(m.rendered.as_deref(), Some("192.0.2.7"));
}

#[test]
fn lldp_unknown_tlv_is_skipped() {
    let mut pdu = Vec::new();
    pdu.extend(lldp_tlv(1, &[0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    // An organizationally-specific TLV (type 127) we do not decode, mid-stream.
    pdu.extend(lldp_tlv(127, &[0xde, 0xad, 0xbe, 0xef]));
    pdu.extend(lldp_tlv(2, &[0x05, b'e', b'0']));
    pdu.extend(lldp_tlv(3, &[0x00, 0x1e]));
    pdu.extend(lldp_tlv(0, &[]));

    let f = parse_lldp(&pdu).expect("unknown TLV is skipped, not fatal");
    assert_eq!(f.port_id.rendered.as_deref(), Some("e0"));
    assert_eq!(f.ttl, 30);
}

#[test]
fn lldp_tlv_length_past_buffer_errors_cleanly() {
    // Chassis TLV header claims 7 value bytes, but only 3 follow.
    let pdu = [0x02, 0x07, 0x04, 0x00, 0x11];
    let err = parse_lldp(&pdu).unwrap_err();
    assert!(matches!(err, LldpError::Truncated { .. }), "got {err:?}");
}

#[test]
fn lldp_missing_mandatory_errors() {
    // Only a system name, then End: no chassis/port/ttl.
    let mut pdu = Vec::new();
    pdu.extend(lldp_tlv(5, b"lonely"));
    pdu.extend(lldp_tlv(0, &[]));
    let err = parse_lldp(&pdu).unwrap_err();
    assert_eq!(err, LldpError::MissingMandatory("chassis id"));
}

#[test]
fn lldp_empty_input_errors() {
    assert_eq!(parse_lldp(&[]).unwrap_err(), LldpError::Empty);
}

#[test]
fn lldp_unknown_chassis_subtype_keeps_raw_no_render() {
    let mut pdu = Vec::new();
    // Chassis subtype 1 (chassis component) — we do not render it.
    pdu.extend(lldp_tlv(1, &[0x01, 0x01, 0x02, 0x03]));
    pdu.extend(lldp_tlv(2, &[0x05, b'e', b'0']));
    pdu.extend(lldp_tlv(3, &[0x00, 0x1e]));
    pdu.extend(lldp_tlv(0, &[]));

    let f = parse_lldp(&pdu).expect("decodes");
    assert_eq!(f.chassis_id.subtype, 1);
    assert!(f.chassis_id.rendered.is_none());
    assert_eq!(f.chassis_id.raw, vec![0x01, 0x02, 0x03]);
}

// ----- CDP ------------------------------------------------------------------

#[test]
fn valid_cdp_frame() {
    let mut pkt = vec![0x02, 0xb4, 0x00, 0x00]; // version 2, ttl 180, checksum
    pkt.extend(cdp_tlv(0x0001, b"R1")); // device id
    pkt.extend(cdp_tlv(0x0003, b"GigabitEthernet0/1")); // port id
    pkt.extend(cdp_tlv(0x0004, &[0x00, 0x00, 0x00, 0x01])); // capabilities: router
    pkt.extend(cdp_tlv(0x0005, b"IOS 15.2")); // software version
    pkt.extend(cdp_tlv(0x0006, b"cisco WS-C2960")); // platform

    let f = parse_cdp(&pkt).expect("decodes");
    assert_eq!(f.version, 2);
    assert_eq!(f.ttl, 180);
    assert_eq!(f.device_id.as_deref(), Some("R1"));
    assert_eq!(f.port_id.as_deref(), Some("GigabitEthernet0/1"));
    assert_eq!(f.software_version.as_deref(), Some("IOS 15.2"));
    assert_eq!(f.platform.as_deref(), Some("cisco WS-C2960"));
    let caps = f.capabilities.expect("caps present");
    assert!(caps.available.router);
    assert!(!caps.available.bridge);
}

#[test]
fn cdp_switch_capabilities_map_to_bridge() {
    let mut pkt = vec![0x02, 0x0a, 0x00, 0x00];
    // CDP 0x08 = Switch -> our logical `bridge`.
    pkt.extend(cdp_tlv(0x0004, &[0x00, 0x00, 0x00, 0x08]));
    let f = parse_cdp(&pkt).expect("decodes");
    let caps = f.capabilities.expect("caps");
    assert!(caps.available.bridge);
    assert!(!caps.available.router);
}

#[test]
fn cdp_unknown_tlv_skipped_and_addresses_ignored() {
    let mut pkt = vec![0x01, 0x0a, 0x00, 0x00];
    pkt.extend(cdp_tlv(0x0002, &[0x00, 0x00, 0x00, 0x00])); // Addresses: not decoded
    pkt.extend(cdp_tlv(0x00ff, &[0xaa, 0xbb])); // unknown type
    pkt.extend(cdp_tlv(0x0001, b"dev")); // device id still found
    let f = parse_cdp(&pkt).expect("decodes past unknown TLVs");
    assert_eq!(f.device_id.as_deref(), Some("dev"));
}

#[test]
fn cdp_tlv_length_below_header_errors() {
    let mut pkt = vec![0x02, 0x0a, 0x00, 0x00];
    // A TLV declaring length 2 (< its own 4-byte header).
    pkt.extend([0x00, 0x01, 0x00, 0x02]);
    let err = parse_cdp(&pkt).unwrap_err();
    assert!(matches!(err, LldpError::Malformed { .. }), "got {err:?}");
}

#[test]
fn cdp_tlv_length_past_buffer_errors() {
    let mut pkt = vec![0x02, 0x0a, 0x00, 0x00];
    // Declares 10 value bytes but none follow.
    pkt.extend([0x00, 0x01, 0x00, 0x0e]);
    let err = parse_cdp(&pkt).unwrap_err();
    assert!(matches!(err, LldpError::Truncated { .. }), "got {err:?}");
}

#[test]
fn cdp_empty_input_errors() {
    assert_eq!(parse_cdp(&[]).unwrap_err(), LldpError::Empty);
}

// ----- fuzz-style: never panic on arbitrary bytes ---------------------------

#[test]
fn never_panics_on_arbitrary_bytes() {
    // A cheap deterministic PRNG (xorshift) drives many random-length, random
    // byte inputs through both decoders. The property under test is only that
    // neither ever panics — every outcome must be a returned `Result`.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    for _ in 0..5_000 {
        let len = (next() % 64) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push((next() & 0xff) as u8);
        }
        // Must not panic; the value is irrelevant.
        let _ = parse_lldp(&bytes);
        let _ = parse_cdp(&bytes);
    }
}

#[test]
fn never_panics_on_truncations_of_a_valid_frame() {
    // Every prefix of a valid LLDPDU must also decode-or-error, never panic.
    let mut pdu = Vec::new();
    pdu.extend(lldp_tlv(1, &[0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    pdu.extend(lldp_tlv(2, &[0x05, b'e', b't', b'h', b'0']));
    pdu.extend(lldp_tlv(3, &[0x00, 0x78]));
    pdu.extend(lldp_tlv(7, &[0x00, 0x14, 0x00, 0x04]));
    pdu.extend(lldp_tlv(0, &[]));
    for n in 0..=pdu.len() {
        let _ = parse_lldp(&pdu[..n]);
    }
}
