//! LLDP (IEEE 802.1AB) decoder.
//!
//! An LLDPDU is a flat sequence of TLVs. Each TLV is a 2-byte big-endian
//! header — the top 7 bits are the type, the low 9 bits are the value length —
//! followed by that many value bytes. The mandatory TLVs (Chassis ID, Port ID,
//! Time To Live) come first, and an End-of-LLDPDU TLV (type 0, length 0)
//! terminates the unit. See the crate root for the input convention (the
//! LLDPDU, **not** the Ethernet header).

use crate::error::LldpError;
use crate::model::{
    Capabilities, CapabilitySet, ChassisId, ManagementAddress, PortId, render_ip, render_mac,
    render_text,
};
use crate::reader::Reader;

// LLDP TLV type numbers.
const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESC: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESC: u8 = 6;
const TLV_SYSTEM_CAPS: u8 = 7;
const TLV_MGMT_ADDR: u8 = 8;

/// A decoded LLDP data unit.
///
/// The three mandatory fields are always present (decoding fails otherwise); the
/// optional fields are present only when their TLV appeared and decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpFrame {
    /// Chassis ID (mandatory).
    pub chassis_id: ChassisId,
    /// Port ID (mandatory).
    pub port_id: PortId,
    /// Time To Live in seconds (mandatory).
    pub ttl: u16,
    /// System Name (TLV 5), if advertised.
    pub system_name: Option<String>,
    /// System Description (TLV 6), if advertised.
    pub system_description: Option<String>,
    /// Port Description (TLV 4), if advertised.
    pub port_description: Option<String>,
    /// System Capabilities (TLV 7), if advertised.
    pub capabilities: Option<Capabilities>,
    /// Management Addresses (TLV 8, may repeat).
    pub management_addresses: Vec<ManagementAddress>,
}

/// Decode an LLDPDU from bytes that begin at the first TLV (Ethernet header
/// already stripped).
///
/// Malformed input never panics: an unknown TLV type is skipped, and any length
/// that would run past the buffer yields [`LldpError::Truncated`]. The three
/// mandatory TLVs must be present or [`LldpError::MissingMandatory`] is returned.
pub fn parse_lldp(bytes: &[u8]) -> Result<LldpFrame, LldpError> {
    if bytes.is_empty() {
        return Err(LldpError::Empty);
    }

    let mut r = Reader::new(bytes);

    let mut chassis_id: Option<ChassisId> = None;
    let mut port_id: Option<PortId> = None;
    let mut ttl: Option<u16> = None;
    let mut system_name = None;
    let mut system_description = None;
    let mut port_description = None;
    let mut capabilities = None;
    let mut management_addresses = Vec::new();

    while !r.is_empty() {
        let header = r.u16_be("tlv header")?;
        let tlv_type = (header >> 9) as u8;
        let tlv_len = (header & 0x01ff) as usize;

        if tlv_type == TLV_END {
            break;
        }

        // Borrow exactly this TLV's value; a length past the buffer errors here.
        let value = r.take(tlv_len, "tlv value")?;

        match tlv_type {
            TLV_CHASSIS_ID => chassis_id = Some(decode_chassis_id(value)?),
            TLV_PORT_ID => port_id = Some(decode_port_id(value)?),
            TLV_TTL => {
                let mut vr = Reader::new(value);
                ttl = Some(vr.u16_be("ttl value")?);
            }
            TLV_PORT_DESC => port_description = render_text(value),
            TLV_SYSTEM_NAME => system_name = render_text(value),
            TLV_SYSTEM_DESC => system_description = render_text(value),
            TLV_SYSTEM_CAPS => capabilities = decode_capabilities(value),
            TLV_MGMT_ADDR => {
                if let Some(addr) = decode_management_address(value) {
                    management_addresses.push(addr);
                }
            }
            // Unknown / unhandled optional TLV: skip. Its bytes were already
            // consumed by `take` above.
            _ => {}
        }
    }

    Ok(LldpFrame {
        chassis_id: chassis_id.ok_or(LldpError::MissingMandatory("chassis id"))?,
        port_id: port_id.ok_or(LldpError::MissingMandatory("port id"))?,
        ttl: ttl.ok_or(LldpError::MissingMandatory("ttl"))?,
        system_name,
        system_description,
        port_description,
        capabilities,
        management_addresses,
    })
}

/// Decode a Chassis ID value: a subtype byte followed by the id.
fn decode_chassis_id(value: &[u8]) -> Result<ChassisId, LldpError> {
    let (subtype, id) = split_subtype(value, "chassis id")?;
    let rendered = match subtype {
        // 4 = MAC address.
        4 => render_mac(id),
        // 5 = network address (IANA family byte + address).
        5 => id
            .split_first()
            .and_then(|(fam, addr)| render_ip(*fam, addr)),
        // 6 = interface name, 7 = locally assigned: text.
        6 | 7 => render_text(id),
        _ => None,
    };
    Ok(ChassisId {
        subtype,
        rendered,
        raw: id.to_vec(),
    })
}

/// Decode a Port ID value: a subtype byte followed by the id.
fn decode_port_id(value: &[u8]) -> Result<PortId, LldpError> {
    let (subtype, id) = split_subtype(value, "port id")?;
    let rendered = match subtype {
        // 3 = MAC address.
        3 => render_mac(id),
        // 4 = network address (IANA family byte + address).
        4 => id
            .split_first()
            .and_then(|(fam, addr)| render_ip(*fam, addr)),
        // 1 = interface alias, 5 = interface name, 7 = locally assigned: text.
        1 | 5 | 7 => render_text(id),
        _ => None,
    };
    Ok(PortId {
        subtype,
        rendered,
        raw: id.to_vec(),
    })
}

/// Decode a System Capabilities TLV: two 16-bit fields (system, enabled).
/// Returns `None` on a short value rather than erroring — a malformed optional
/// TLV is dropped, not fatal.
fn decode_capabilities(value: &[u8]) -> Option<Capabilities> {
    let mut r = Reader::new(value);
    let available = r.u16_be("system caps").ok()?;
    let enabled = r.u16_be("enabled caps").ok()?;
    Some(Capabilities {
        available: CapabilitySet::from_lldp_bits(available),
        enabled: CapabilitySet::from_lldp_bits(enabled),
    })
}

/// Decode a Management Address TLV far enough to surface the address itself.
///
/// Layout: address-string length (1, counts the subtype byte + address),
/// address subtype (1, IANA family), address bytes, then interface-numbering
/// fields and an OID we do not need. Returns `None` if the declared lengths do
/// not fit — a malformed optional TLV is dropped, not fatal.
fn decode_management_address(value: &[u8]) -> Option<ManagementAddress> {
    let mut r = Reader::new(value);
    let addr_str_len = r.u8("mgmt addr str len").ok()? as usize;
    if addr_str_len == 0 {
        return None;
    }
    let address_family = r.u8("mgmt addr family").ok()?;
    // The address string length counts the family byte plus the address.
    let addr = r.take(addr_str_len - 1, "mgmt addr").ok()?;
    let rendered = render_ip(address_family, addr);
    Some(ManagementAddress {
        address_family,
        rendered,
        raw: addr.to_vec(),
    })
}

/// Split a `subtype || value` field, erroring if the subtype byte is absent.
fn split_subtype<'a>(value: &'a [u8], context: &'static str) -> Result<(u8, &'a [u8]), LldpError> {
    value.split_first().map(|(s, rest)| (*s, rest)).ok_or({
        LldpError::Truncated {
            context,
            need: 1,
            have: 0,
        }
    })
}
