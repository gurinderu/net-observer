//! What physically leaves the machine's egress interface, read off one
//! captured outgoing frame: the destination IP and the packet's on-wire IP
//! length. (realm net-observer, node #170)
//!
//! # Why this exists next to `connections`
//! The `connections` collector reads sing-box's Clash API — the *tunneled*
//! view of what applications talk to. It structurally cannot see what actually
//! leaves the physical uplink (`en0`): the encrypted packets sing-box writes to
//! the wire carry the proxy endpoint's address, not the app's destination, and
//! anything routed around the tunnel never appears in the Clash API at all. An
//! on-demand capture of the physical interface's *outgoing* IP packets, folded
//! by destination address, is the only view of what physically egresses.
//!
//! This module is the pure mapping from a captured raw Ethernet frame to a
//! [`EgressPacket`] — destination address and on-wire byte count. The *capture*
//! of the frame is a separate, privileged concern (a BPF/pcap read needing
//! root); this mapping is what the capture feeds and what the tests exercise.
//! Like `topology::link_from_frame`, every path a malformed frame can take
//! yields `None`, never a panic.

use std::net::IpAddr;

use etherparse::{LaxNetSlice, LaxSlicedPacket};

/// One outgoing packet reduced to what the egress fold keys on: where it went
/// and how many bytes it was on the wire (the IP layer's own length, so the
/// figure matches what the network carried, not the captured slice length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressPacket {
    /// The destination IP address the packet was headed to.
    pub dst_ip: IpAddr,
    /// The on-wire IP length: an IPv4 packet's `total_len`, or 40 (the fixed
    /// IPv6 header) plus the IPv6 `payload_length`. Snaplen truncation on the
    /// capture side does not change this — it is read from the header field,
    /// not measured from the captured bytes.
    pub bytes: u16,
}

/// Map one captured **raw Ethernet frame** (starting at the destination MAC) to
/// its destination IP and on-wire length, or `None` when the frame is not an
/// IPv4/IPv6 packet this fold counts.
///
/// Returns `None` — never panics — for a frame the lax slicer cannot make an
/// Ethernet+IP sense of, for ARP (a link-layer frame with no IP destination to
/// fold on), and for a frame too short to carry an IP header. Absence is the
/// honest answer: a frame we cannot read a destination from is not counted
/// against a guessed one.
#[must_use]
pub fn dst_and_len(bytes: &[u8]) -> Option<EgressPacket> {
    let s = LaxSlicedPacket::from_ethernet(bytes).ok()?;
    match s.net? {
        LaxNetSlice::Ipv4(v4) => Some(EgressPacket {
            dst_ip: v4.header().destination_addr().into(),
            bytes: v4.header().total_len(),
        }),
        LaxNetSlice::Ipv6(v6) => Some(EgressPacket {
            // The IPv6 header is a fixed 40 bytes; `payload_length` counts what
            // follows it. `saturating_add` rather than `+` so a hostile
            // payload-length of 0xFFFF cannot overflow the on-wire figure.
            dst_ip: v6.header().destination_addr().into(),
            bytes: 40u16.saturating_add(v6.header().payload_length()),
        }),
        LaxNetSlice::Arp(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SRC_MAC: [u8; 6] = [0x3c, 0x22, 0xfb, 0x00, 0x00, 0x01];
    const DST_MAC: [u8; 6] = [0x60, 0x22, 0x32, 0xaa, 0x25, 0x21];

    /// An Ethernet/IPv4/UDP frame carrying `payload`, built the same way the
    /// announce decoder's tests build theirs.
    fn ipv4_frame(dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let b = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv4(Ipv4Addr::new(10, 0, 0, 2).octets(), dst.octets(), 64)
            .udp(1234, 443);
        let mut out = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut out, payload).unwrap();
        out
    }

    /// An Ethernet/IPv6/UDP frame carrying `payload`.
    fn ipv6_frame(dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let b = PacketBuilder::ethernet2(SRC_MAC, DST_MAC)
            .ipv6(src.octets(), dst.octets(), 64)
            .udp(1234, 443);
        let mut out = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn an_ipv4_frame_yields_its_destination_and_on_wire_length() {
        let dst = Ipv4Addr::new(203, 0, 113, 7);
        let payload = [0u8; 100];
        let pkt = dst_and_len(&ipv4_frame(dst, &payload)).expect("an IPv4 frame is counted");
        assert_eq!(pkt.dst_ip, IpAddr::V4(dst));
        // IPv4 header (20) + UDP header (8) + payload (100) = 128.
        assert_eq!(pkt.bytes, 128);
    }

    #[test]
    fn an_ipv6_frame_yields_its_destination_and_on_wire_length() {
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x42);
        let payload = [0u8; 100];
        let pkt = dst_and_len(&ipv6_frame(dst, &payload)).expect("an IPv6 frame is counted");
        assert_eq!(pkt.dst_ip, IpAddr::V6(dst));
        // IPv6 header (40) + UDP header (8) + payload (100) = 148.
        assert_eq!(pkt.bytes, 148);
    }

    /// ARP is a link-layer frame with no IP destination to fold on — dropped,
    /// not counted against a guessed address.
    #[test]
    fn an_arp_frame_is_not_counted() {
        use etherparse::{ArpHardwareId, ArpOperation, ArpPacket, EtherType};
        let arp = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            ArpOperation::REQUEST,
            &SRC_MAC,
            &Ipv4Addr::new(10, 0, 0, 2).octets(),
            &[0u8; 6],
            &Ipv4Addr::new(10, 0, 0, 1).octets(),
        )
        .unwrap();
        let b = PacketBuilder::ethernet2(SRC_MAC, DST_MAC).arp(arp);
        let mut frame = Vec::with_capacity(b.size());
        b.write(&mut frame).unwrap();
        assert!(dst_and_len(&frame).is_none());
    }

    /// A frame too short to carry an Ethernet header, and arbitrary bytes,
    /// yield nothing — never a panic (the forensics discipline).
    #[test]
    fn short_and_arbitrary_frames_never_panic() {
        assert!(dst_and_len(&[]).is_none());
        assert!(dst_and_len(&[0x00, 0x01, 0x02]).is_none());
        for len in 0..64usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let _ = dst_and_len(&bytes);
        }
    }
}
