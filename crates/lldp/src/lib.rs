//! `lldp` — a pure, offline decoder for link-layer discovery frames.
//!
//! Switches and access points periodically broadcast who and what they are —
//! their chassis, the port you are plugged into, their capabilities — over two
//! competing protocols: **LLDP** (IEEE 802.1AB, EtherType `0x88CC`) and Cisco's
//! **CDP**. This crate turns the raw frame bytes of either into structured
//! neighbour/link facts. It is groundwork for a later switch-topology feature:
//! the daemon will capture these frames from its pcap ring and hand the bytes
//! here.
//!
//! # Scope — decode only
//! This crate does **nothing but decode**: `&[u8] -> Result<_, LldpError>`. No
//! capture, no network, no OS calls, no async, no `unsafe`. A caller decides
//! whether a frame is relevant; the decoder just reports what is structurally
//! there.
//!
//! # Input convention — the PDU, not the Ethernet header
//! Both entry points expect the caller to have **already stripped the layer-2
//! framing**:
//!
//! * [`parse_lldp`] expects bytes starting at the **first LLDP TLV** (the
//!   LLDPDU) — i.e. after the 14-byte Ethernet header (`dst`, `src`,
//!   EtherType `0x88CC`).
//! * [`parse_cdp`] expects bytes starting at the **CDP header** (version / TTL /
//!   checksum) — i.e. after the Ethernet `802.3` length field, the LLC header
//!   and the 8-byte SNAP header (`AA AA 03 00 00 0C 20 00`).
//!
//! The caller strips (or keeps) the header to match. This crate never inspects
//! layer-2 addressing.
//!
//! # Forensics discipline
//! This is a forensics tool, so silent wrong data is worse than none:
//!
//! * **Never panics on malformed input.** Every read is bounds-checked; a
//!   truncated TLV, a length that runs past the buffer, an unknown type or a
//!   bad subtype yields an [`LldpError`] or is skipped — never an out-of-bounds
//!   read. (There is a fuzz-style test asserting arbitrary bytes never panic.)
//! * **A field that cannot be interpreted is absent or raw, never guessed.**
//!   Identifier fields keep their `subtype` and raw bytes, and only carry a
//!   `rendered` value when the bytes fit that subtype with confidence.
//!
//! # Example
//! ```
//! use lldp::parse_lldp;
//!
//! // Minimal LLDPDU: Chassis ID (MAC), Port ID (iface name), TTL, End.
//! let pdu = [
//!     0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // chassis id: MAC
//!     0x04, 0x04, 0x05, b'e', b't', b'h',                   // port id: "eth"
//!     0x06, 0x02, 0x00, 0x78,                               // ttl: 120
//!     0x00, 0x00,                                           // end
//! ];
//! let frame = parse_lldp(&pdu).unwrap();
//! assert_eq!(frame.chassis_id.rendered.as_deref(), Some("00:11:22:33:44:55"));
//! assert_eq!(frame.port_id.rendered.as_deref(), Some("eth"));
//! assert_eq!(frame.ttl, 120);
//! ```

mod cdp;
mod error;
mod lldp;
mod model;
mod reader;

#[cfg(test)]
mod tests;

pub use cdp::{CdpFrame, parse_cdp};
pub use error::LldpError;
pub use lldp::{LldpFrame, parse_lldp};
pub use model::{Capabilities, CapabilitySet, ChassisId, IdField, ManagementAddress, PortId};
