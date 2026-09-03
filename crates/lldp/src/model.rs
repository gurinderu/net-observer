//! Shared structured facts produced by both decoders, and the small rendering
//! helpers they use.
//!
//! A rendered value is only ever present when the bytes were interpreted with
//! confidence (a MAC of the right length, a printable interface name, a valid
//! IPv4/IPv6 address). When the subtype is unknown or the bytes do not fit the
//! shape, `rendered` is `None` and the caller reads `raw` — a field we cannot
//! interpret is absent or raw, never a guess.

/// An identifier carrying its subtype byte, a best-effort rendering, and the
/// original bytes.
///
/// Used for both the LLDP Chassis ID and Port ID TLVs, whose value shape is
/// selected by the leading subtype byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdField {
    /// The subtype byte that selects how `raw` is to be interpreted.
    pub subtype: u8,
    /// A rendered value when the subtype was one we render and the bytes fit
    /// (e.g. a MAC as `aa:bb:cc:dd:ee:ff`, or an interface name as text).
    pub rendered: Option<String>,
    /// The raw value bytes, always retained.
    pub raw: Vec<u8>,
}

/// The LLDP Chassis ID (TLV type 1).
pub type ChassisId = IdField;
/// The LLDP Port ID (TLV type 2).
pub type PortId = IdField;

/// System capabilities, normalised into one logical set that both protocols map
/// onto (LLDP's System Capabilities TLV, and CDP's Capabilities TLV).
///
/// `available` is what the device is capable of; `enabled` is what is currently
/// on. LLDP carries both as separate 16-bit fields. CDP carries a single
/// 32-bit field with a different bit layout; it is mapped onto these logical
/// flags at decode time, and for CDP `enabled == available`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// Which capabilities the device advertises it is capable of.
    pub available: CapabilitySet,
    /// Which of those are currently enabled.
    pub enabled: CapabilitySet,
}

/// A single set of capability flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    /// "Other" / unclassified.
    pub other: bool,
    /// Repeater / hub.
    pub repeater: bool,
    /// MAC bridge (a switch).
    pub bridge: bool,
    /// WLAN access point.
    pub wlan_ap: bool,
    /// Router.
    pub router: bool,
    /// Telephone (e.g. a VoIP phone).
    pub telephone: bool,
    /// DOCSIS cable device.
    pub docsis: bool,
    /// Station only (an end host, not forwarding).
    pub station: bool,
}

impl CapabilitySet {
    /// Decode the LLDP System Capabilities bitfield (IEEE 802.1AB Table 8-4).
    pub(crate) fn from_lldp_bits(bits: u16) -> Self {
        Self {
            other: bits & (1 << 0) != 0,
            repeater: bits & (1 << 1) != 0,
            bridge: bits & (1 << 2) != 0,
            wlan_ap: bits & (1 << 3) != 0,
            router: bits & (1 << 4) != 0,
            telephone: bits & (1 << 5) != 0,
            docsis: bits & (1 << 6) != 0,
            station: bits & (1 << 7) != 0,
        }
    }

    /// Map the CDP Capabilities bitfield onto the same logical flags. CDP's
    /// layout (Cisco): 0x01 Router, 0x02 Transparent Bridge, 0x04 Source-Route
    /// Bridge, 0x08 Switch, 0x10 Host, 0x20 IGMP, 0x40 Repeater.
    pub(crate) fn from_cdp_bits(bits: u32) -> Self {
        Self {
            other: false,
            repeater: bits & 0x40 != 0,
            bridge: bits & (0x02 | 0x04 | 0x08) != 0,
            wlan_ap: false,
            router: bits & 0x01 != 0,
            telephone: false,
            docsis: false,
            station: bits & 0x10 != 0,
        }
    }
}

/// A management address advertised by an LLDP Management Address TLV (type 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementAddress {
    /// IANA address-family number (1 = IPv4, 2 = IPv6, others left raw).
    pub address_family: u8,
    /// The address rendered as text when it is an IPv4/IPv6 address of the
    /// expected length; `None` otherwise.
    pub rendered: Option<String>,
    /// The raw address bytes (without the leading subtype byte).
    pub raw: Vec<u8>,
}

/// Render six bytes as a lower-case colon-separated MAC, or `None` if the length
/// is not exactly six.
pub(crate) fn render_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Render bytes as a UTF-8 string when they are valid UTF-8 and carry no control
/// characters OTHER than the common whitespace (`\t`, `\n`, `\r`); `None`
/// otherwise. The whitespace exception matters: real CDP Software Version and
/// LLDP System Description strings are routinely multi-line, and rejecting every
/// control byte silently dropped the single most device-identifying field on
/// well-formed frames. A genuinely binary/mojibake value (other control bytes,
/// or invalid UTF-8) is still left absent rather than lossily coerced.
pub(crate) fn render_text(bytes: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return None;
    }
    Some(s.to_owned())
}

/// Render a management address as text, gated on the IANA `address_family` the
/// TLV itself declares (1 = IPv4, 2 = IPv6) so the rendering can never contradict
/// its own family byte — a family-1 TLV carrying 16 bytes stays raw rather than
/// being confidently shown as an IPv6 address it never claimed to be. `None` for
/// a family/length mismatch or an unrendered family, leaving the raw bytes.
pub(crate) fn render_ip(family: u8, bytes: &[u8]) -> Option<String> {
    match (family, bytes.len()) {
        (1, 4) => {
            let a: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(a).to_string())
        }
        (2, 16) => {
            let a: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(a).to_string())
        }
        _ => None,
    }
}
