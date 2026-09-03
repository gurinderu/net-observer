//! CDP (Cisco Discovery Protocol) decoder.
//!
//! CDP is SNAP-encapsulated and has its own TLV layout, unrelated to LLDP's: a
//! fixed header — version (1 byte), TTL (1 byte), checksum (2 bytes) — then a
//! sequence of TLVs. Each CDP TLV is `type` (2 bytes, big-endian), `length`
//! (2 bytes, big-endian, **counting its own 4-byte header**), then
//! `length - 4` value bytes.
//!
//! This decoder handles the commonly useful TLVs (Device ID, Port ID, Platform,
//! Capabilities, Software Version) fully. Other TLVs — Addresses among them —
//! are skipped, not decoded: what is returned is always what was decoded with
//! confidence, never a guess, and malformed input never panics. See the crate
//! root for the input convention (the CDP payload, **not** the Ethernet /
//! LLC / SNAP header).

use crate::error::LldpError;
use crate::model::{Capabilities, CapabilitySet, render_text};
use crate::reader::Reader;

// CDP TLV type numbers.
const TLV_DEVICE_ID: u16 = 0x0001;
const TLV_PORT_ID: u16 = 0x0003;
const TLV_CAPABILITIES: u16 = 0x0004;
const TLV_SOFTWARE_VERSION: u16 = 0x0005;
const TLV_PLATFORM: u16 = 0x0006;

/// A decoded CDP packet.
///
/// All TLV-borne fields are optional: CDP does not mandate any particular TLV,
/// so each is present only when its TLV appeared and decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdpFrame {
    /// CDP protocol version from the header.
    pub version: u8,
    /// Holdtime / TTL in seconds from the header.
    pub ttl: u8,
    /// Device ID (TLV 0x0001), typically the neighbour's hostname.
    pub device_id: Option<String>,
    /// Port ID (TLV 0x0003), the neighbour's egress port name.
    pub port_id: Option<String>,
    /// Platform (TLV 0x0006), the neighbour's hardware/software platform.
    pub platform: Option<String>,
    /// Software Version (TLV 0x0005).
    pub software_version: Option<String>,
    /// Capabilities (TLV 0x0004), mapped onto the shared logical flag set.
    pub capabilities: Option<Capabilities>,
}

/// Decode a CDP packet from bytes that begin at the CDP header (Ethernet / LLC /
/// SNAP already stripped).
///
/// Malformed input never panics: an unknown TLV type is skipped, and any length
/// that would run past the buffer (or a TLV whose declared length is below its
/// own 4-byte header) yields an error rather than an out-of-bounds read.
pub fn parse_cdp(bytes: &[u8]) -> Result<CdpFrame, LldpError> {
    if bytes.is_empty() {
        return Err(LldpError::Empty);
    }

    let mut r = Reader::new(bytes);
    let version = r.u8("cdp version")?;
    let ttl = r.u8("cdp ttl")?;
    let _checksum = r.u16_be("cdp checksum")?;

    let mut frame = CdpFrame {
        version,
        ttl,
        device_id: None,
        port_id: None,
        platform: None,
        software_version: None,
        capabilities: None,
    };

    while !r.is_empty() {
        let tlv_type = r.u16_be("cdp tlv type")?;
        let tlv_len = r.u16_be("cdp tlv length")? as usize;
        // The length counts the 4-byte header (type + length).
        if tlv_len < 4 {
            return Err(LldpError::Malformed {
                context: "cdp tlv",
                detail: "declared length below its 4-byte header",
            });
        }
        let value = r.take(tlv_len - 4, "cdp tlv value")?;

        match tlv_type {
            TLV_DEVICE_ID => frame.device_id = render_text(value),
            TLV_PORT_ID => frame.port_id = render_text(value),
            TLV_PLATFORM => frame.platform = render_text(value),
            TLV_SOFTWARE_VERSION => frame.software_version = render_text(value),
            TLV_CAPABILITIES => frame.capabilities = decode_capabilities(value),
            // Unknown / unhandled TLV (e.g. Addresses): skip.
            _ => {}
        }
    }

    Ok(frame)
}

/// Decode the CDP Capabilities TLV: a single 32-bit big-endian bitfield. Returns
/// `None` on a short value — a malformed optional TLV is dropped, not fatal.
fn decode_capabilities(value: &[u8]) -> Option<Capabilities> {
    let mut r = Reader::new(value);
    let bits = r.u32_be("cdp caps").ok()?;
    let set = CapabilitySet::from_cdp_bits(bits);
    Some(Capabilities {
        available: set,
        enabled: set,
    })
}
