//! One captured Ethernet frame reduced to what the listener reads from it:
//! who sent it (the Ethernet source), and either an ARP sender pair or a UDP
//! datagram with its addresses and ports. Everything else the frame carries
//! is discarded here; the protocol decoders take the UDP payload from
//! [`Heard::Udp`].
//!
//! Slicing is `etherparse`'s *lax* mode: a frame whose IP length field
//! disagrees with what the capture delivered still yields its source MAC and
//! address, so a malformed announcement costs its payload, never the sighting.

use std::net::IpAddr;

use etherparse::{LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice};

/// A MAC as six octets, the form the window keys on before rendering.
pub type Mac = [u8; 6];

/// Render a MAC as the normalised lowercase text every neighbour row carries.
#[must_use]
pub fn mac_text(mac: &Mac) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse `aa:bb:cc:dd:ee:ff` (any case, BSD's unpadded octets accepted) into
/// octets, or `None` when it is not six hex octets. Does NOT reject multicast
/// or broadcast — that judgement is [`is_unicast`]'s.
#[must_use]
pub fn mac_octets(text: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in text.split(':') {
        if n == 6 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

/// Whether a MAC can name a device: not the broadcast address and not a
/// group (multicast) address — the least-significant bit of the first octet.
#[must_use]
pub fn is_unicast(mac: &Mac) -> bool {
    mac[0] & 1 == 0 && mac.iter().any(|&o| o != 0xff)
}

/// What one frame said, once the Ethernet header is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Heard<'a> {
    /// An ARP packet over Ethernet/IPv4: the sender pair, straight from the
    /// ARP body (not the Ethernet header — the two can legitimately differ),
    /// and whether it is a reply (a request or a gratuitous announcement is
    /// a device speaking for itself; a reply may be a proxy speaking for
    /// someone else).
    Arp {
        sender_mac: Mac,
        sender_ip: std::net::Ipv4Addr,
        reply: bool,
    },
    /// A UDP datagram over IPv4 or IPv6.
    Udp {
        src_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    /// Something the filter let through that carries neither: an IP frame
    /// that is not UDP, an ARP for a protocol other than IPv4, an unknown
    /// EtherType. Still a frame from `src_mac`, so still counted.
    Other,
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The Ethernet source — who put the frame on the segment.
    pub src_mac: Mac,
    pub heard: Heard<'a>,
}

/// Decode a captured Ethernet frame, or `None` when it is too short to even
/// carry an Ethernet header.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<Frame<'_>> {
    let sliced = LaxSlicedPacket::from_ethernet(bytes).ok()?;
    let src_mac = match &sliced.link {
        Some(LinkSlice::Ethernet2(eth)) => eth.source(),
        _ => return None,
    };
    let heard = match &sliced.net {
        Some(LaxNetSlice::Arp(arp)) => {
            let hw: Result<Mac, _> = arp.sender_hw_addr().try_into();
            let proto: Result<[u8; 4], _> = arp.sender_protocol_addr().try_into();
            match (hw, proto) {
                (Ok(sender_mac), Ok(ip)) => Heard::Arp {
                    sender_mac,
                    sender_ip: ip.into(),
                    reply: arp.operation() == etherparse::ArpOperation::REPLY,
                },
                _ => Heard::Other,
            }
        }
        Some(LaxNetSlice::Ipv4(v4)) => udp(v4.header().source_addr().into(), &sliced.transport),
        Some(LaxNetSlice::Ipv6(v6)) => udp(v6.header().source_addr().into(), &sliced.transport),
        None => Heard::Other,
    };
    Some(Frame { src_mac, heard })
}

/// The UDP half of an IP frame, or `Other` for any other transport.
fn udp<'a>(src_ip: IpAddr, transport: &Option<TransportSlice<'a>>) -> Heard<'a> {
    match transport {
        Some(TransportSlice::Udp(u)) => Heard::Udp {
            src_ip,
            src_port: u.source_port(),
            dst_port: u.destination_port(),
            payload: u.payload(),
        },
        _ => Heard::Other,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use etherparse::{ArpHardwareId, ArpOperation, ArpPacket, EtherType, PacketBuilder};
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub(crate) const OWN: Mac = [0x3c, 0x22, 0xfb, 0x00, 0x00, 0x01];
    pub(crate) const GATEWAY: Mac = [0x60, 0x22, 0x32, 0xaa, 0x25, 0x21];
    pub(crate) const PEER: Mac = [0xa4, 0x83, 0xe7, 0x1b, 0x2c, 0x3d];
    pub(crate) const BROADCAST: Mac = [0xff; 6];

    /// An Ethernet/IPv4/UDP frame from the fields.
    pub(crate) fn udp4(
        src_mac: Mac,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let dst_mac = if dst.is_multicast() {
            [
                0x01,
                0x00,
                0x5e,
                dst.octets()[1] & 0x7f,
                dst.octets()[2],
                dst.octets()[3],
            ]
        } else if dst.is_broadcast() {
            BROADCAST
        } else {
            GATEWAY
        };
        let b = PacketBuilder::ethernet2(src_mac, dst_mac)
            .ipv4(src.octets(), dst.octets(), 255)
            .udp(sport, dport);
        let mut out = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut out, payload).unwrap();
        out
    }

    /// An Ethernet/IPv6/UDP frame from the fields.
    pub(crate) fn udp6(
        src_mac: Mac,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let o = dst.octets();
        let dst_mac = [0x33, 0x33, o[12], o[13], o[14], o[15]];
        let b = PacketBuilder::ethernet2(src_mac, dst_mac)
            .ipv6(src.octets(), dst.octets(), 255)
            .udp(sport, dport);
        let mut out = Vec::with_capacity(b.size(payload.len()));
        b.write(&mut out, payload).unwrap();
        out
    }

    /// An ARP-over-Ethernet frame from the fields; `reply` selects the opcode.
    pub(crate) fn arp(
        src_mac: Mac,
        sender_mac: Mac,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        reply: bool,
    ) -> Vec<u8> {
        let packet = ArpPacket::new(
            ArpHardwareId::ETHERNET,
            EtherType::IPV4,
            if reply {
                ArpOperation::REPLY
            } else {
                ArpOperation::REQUEST
            },
            &sender_mac,
            &sender_ip.octets(),
            &if reply { GATEWAY } else { [0u8; 6] },
            &target_ip.octets(),
        )
        .unwrap();
        let b =
            PacketBuilder::ethernet2(src_mac, if reply { GATEWAY } else { BROADCAST }).arp(packet);
        let mut out = Vec::with_capacity(b.size());
        b.write(&mut out).unwrap();
        out
    }

    #[test]
    fn mac_text_and_octets_round_trip_and_pad() {
        assert_eq!(mac_text(&PEER), "a4:83:e7:1b:2c:3d");
        assert_eq!(mac_octets("A4:83:E7:1B:2C:3D"), Some(PEER));
        assert_eq!(
            mac_octets("0:1c:42:8:9:a"),
            Some([0, 0x1c, 0x42, 8, 9, 0xa])
        );
        assert_eq!(mac_octets("a4:83:e7:1b:2c"), None);
        assert_eq!(mac_octets("a4:83:e7:1b:2c:3d:00"), None);
        assert_eq!(mac_octets("zz:83:e7:1b:2c:3d"), None);
    }

    #[test]
    fn unicast_excludes_broadcast_and_group_addresses() {
        assert!(is_unicast(&PEER));
        assert!(!is_unicast(&BROADCAST));
        assert!(!is_unicast(&[0x01, 0x00, 0x5e, 0, 0, 0xfb]));
        assert!(!is_unicast(&[0x33, 0x33, 0, 0, 0, 0xfb]));
    }

    #[test]
    fn an_arp_reply_yields_its_sender_pair_from_the_arp_body() {
        let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
        let bytes = arp(GATEWAY, GATEWAY, gw_ip, Ipv4Addr::new(192, 168, 1, 5), true);
        let f = decode(&bytes).unwrap();
        assert_eq!(f.src_mac, GATEWAY);
        assert_eq!(
            f.heard,
            Heard::Arp {
                sender_mac: GATEWAY,
                sender_ip: gw_ip,
                reply: true,
            }
        );
        let bytes = arp(PEER, PEER, Ipv4Addr::new(192, 168, 1, 6), gw_ip, false);
        assert!(matches!(
            decode(&bytes).unwrap().heard,
            Heard::Arp { reply: false, .. }
        ));
    }

    #[test]
    fn a_udp_datagram_yields_addresses_ports_and_payload() {
        let bytes = udp4(
            PEER,
            Ipv4Addr::new(192, 168, 1, 6),
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            5353,
            b"hello",
        );
        let f = decode(&bytes).unwrap();
        assert_eq!(f.src_mac, PEER);
        assert_eq!(
            f.heard,
            Heard::Udp {
                src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6)),
                src_port: 5353,
                dst_port: 5353,
                payload: b"hello",
            }
        );
        let bytes = udp6(
            PEER,
            "fe80::1".parse().unwrap(),
            "ff02::fb".parse().unwrap(),
            5353,
            5353,
            b"x",
        );
        let v6 = decode(&bytes).unwrap();
        assert!(matches!(
            v6.heard,
            Heard::Udp {
                src_ip: IpAddr::V6(_),
                ..
            }
        ));
    }

    #[test]
    fn a_short_or_foreign_frame_is_none_or_other_never_a_panic() {
        assert_eq!(decode(&[0u8; 5]), None);
        // A bare Ethernet header with an EtherType nobody decodes.
        let mut raw = Vec::new();
        raw.extend_from_slice(&GATEWAY);
        raw.extend_from_slice(&PEER);
        raw.extend_from_slice(&[0x88, 0xcc]);
        let f = decode(&raw).unwrap();
        assert_eq!(f.src_mac, PEER);
        assert_eq!(f.heard, Heard::Other);
        // Arbitrary bytes of every length up to a full frame never panic.
        for len in 0..80 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            let _ = decode(&junk);
        }
    }

    /// A frame whose IP header claims more payload than the capture delivered
    /// (a lying length field) still yields its source, the sighting the
    /// listener needs most.
    #[test]
    fn a_frame_whose_ip_length_lies_still_names_its_source() {
        let mut frame = udp4(
            PEER,
            Ipv4Addr::new(192, 168, 1, 6),
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            5353,
            b"payload-bytes",
        );
        // Chop the last bytes so the IPv4 total length overruns the slice.
        frame.truncate(frame.len() - 6);
        let f = decode(&frame).expect("lax slicing keeps the headers");
        assert_eq!(f.src_mac, PEER);
    }
}
