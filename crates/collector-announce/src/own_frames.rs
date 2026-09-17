//! Our own frames in a frozen pcap slice — the experiment window's proof
//! that the daemon was silent (realm net-observer, node #61).
//!
//! The window's end freeze copies the pcap ring's files out; this walks one
//! such file with the same [`PcapStream`] the announce listener reads the
//! live capture through, and counts, inside `[start_us, end_us]`, the frames
//! whose Ethernet source is this machine's own MAC — by protocol, so an ICMP
//! echo request (a probe of the daemon's) is told apart from the ARP and
//! DHCP the operating system sends on its own. Everything the ring's filter
//! let through is tallied; nothing here is a claim about frames the filter
//! never captured.
//!
//! Pure Rust over `&[u8]`, like every decoder in this crate: tested on
//! frames built from their fields, no root, no network, no macOS.

use std::io::{self, Read};

use etherparse::{Icmpv4Type, Icmpv6Type, LaxNetSlice, LaxSlicedPacket, LinkSlice, TransportSlice};
use types::OwnFrames;

use crate::frame::Mac;
use crate::pcap::PcapStream;

/// The DHCP ports the ring's filter names (`udp port 67 or 68`).
const DHCP_PORTS: [u16; 2] = [67, 68];

/// Walk one pcap slice and count what it held (see [`OwnFrames`]).
///
/// Every record is tallied into `records` and the earliest/latest stamps;
/// only records inside `[start_us, end_us]` count toward `in_window` and,
/// when their Ethernet source is `own_mac`, toward one of the four buckets.
/// A slice that ends mid-record — a ring file copied while `tcpdump` was
/// still writing it — yields the counts of what was readable with
/// `truncated` set, never an error: a partial count that says it is partial
/// is a measurement, an error in its place would be silence. A stream that is
/// not classic pcap at all is an error.
pub fn count_own_frames<R: Read>(
    reader: R,
    own_mac: &Mac,
    start_us: i64,
    end_us: i64,
) -> io::Result<OwnFrames> {
    let mut stream = PcapStream::new(reader);
    let mut out = OwnFrames::default();
    loop {
        let record = match stream.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                out.truncated = true;
                break;
            }
            Err(e) => return Err(e),
        };
        out.records += 1;
        out.earliest_us = Some(
            out.earliest_us
                .map_or(record.ts_us, |t| t.min(record.ts_us)),
        );
        out.latest_us = Some(out.latest_us.map_or(record.ts_us, |t| t.max(record.ts_us)));
        if record.ts_us < start_us || record.ts_us > end_us {
            continue;
        }
        out.in_window += 1;
        match classify(&record.data, own_mac) {
            Some(Bucket::IcmpEcho) => {
                out.icmp_echo += 1;
                // The first and last echo of ours: a tick that read `active`
                // a moment before the flip still sends its echo after the
                // window opened, and the report names that offset rather
                // than the count hiding it (realm net-observer, node #61).
                out.first_echo_us = Some(
                    out.first_echo_us
                        .map_or(record.ts_us, |t| t.min(record.ts_us)),
                );
                out.last_echo_us = Some(
                    out.last_echo_us
                        .map_or(record.ts_us, |t| t.max(record.ts_us)),
                );
            }
            Some(Bucket::Arp) => out.arp += 1,
            Some(Bucket::Dhcp) => out.dhcp += 1,
            Some(Bucket::Other) => out.other += 1,
            None => {}
        }
    }
    Ok(out)
}

/// Which bucket a frame from this machine lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    IcmpEcho,
    Arp,
    Dhcp,
    Other,
}

/// The bucket for a frame whose Ethernet source is `own_mac`; `None` for a
/// frame from anyone else, or one too short to carry an Ethernet header.
///
/// `etherparse`'s lax slicing, as in [`crate::frame::decode`]: the ring
/// captures 128 bytes per frame, and a length field that disagrees with the
/// captured bytes must still yield the headers.
fn classify(bytes: &[u8], own_mac: &Mac) -> Option<Bucket> {
    let sliced = LaxSlicedPacket::from_ethernet(bytes).ok()?;
    let src = match &sliced.link {
        Some(LinkSlice::Ethernet2(eth)) => eth.source(),
        _ => return None,
    };
    if &src != own_mac {
        return None;
    }
    if matches!(sliced.net, Some(LaxNetSlice::Arp(_))) {
        return Some(Bucket::Arp);
    }
    Some(match &sliced.transport {
        Some(TransportSlice::Icmpv4(icmp))
            if matches!(icmp.icmp_type(), Icmpv4Type::EchoRequest(_)) =>
        {
            Bucket::IcmpEcho
        }
        Some(TransportSlice::Icmpv6(icmp))
            if matches!(icmp.icmp_type(), Icmpv6Type::EchoRequest(_)) =>
        {
            Bucket::IcmpEcho
        }
        Some(TransportSlice::Udp(udp))
            if DHCP_PORTS.contains(&udp.source_port())
                || DHCP_PORTS.contains(&udp.destination_port()) =>
        {
            Bucket::Dhcp
        }
        _ => Bucket::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::tests::{GATEWAY, OWN, PEER, arp, udp4};
    use crate::pcap::tests::{MAGIC_LE_US, savefile};
    use etherparse::{IcmpEchoHeader, PacketBuilder};
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    const OWN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);
    const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    /// An Ethernet/IPv4/ICMP echo request from `src_mac` to the gateway.
    fn echo_request(src_mac: Mac) -> Vec<u8> {
        let b = PacketBuilder::ethernet2(src_mac, GATEWAY)
            .ipv4(OWN_IP.octets(), GW_IP.octets(), 64)
            .icmpv4_echo_request(7, 1);
        let mut out = Vec::with_capacity(b.size(8));
        b.write(&mut out, &[0u8; 8]).unwrap();
        out
    }

    /// An echo REPLY from `src_mac`: the OS answering a ping, not a probe.
    fn echo_reply(src_mac: Mac) -> Vec<u8> {
        let b = PacketBuilder::ethernet2(src_mac, GATEWAY)
            .ipv4(OWN_IP.octets(), GW_IP.octets(), 64)
            .icmpv4(Icmpv4Type::EchoReply(IcmpEchoHeader { id: 7, seq: 1 }));
        let mut out = Vec::with_capacity(b.size(8));
        b.write(&mut out, &[0u8; 8]).unwrap();
        out
    }

    /// A DHCP discover-shaped datagram from `src_mac` (ports are what count).
    fn dhcp(src_mac: Mac) -> Vec<u8> {
        udp4(
            src_mac,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            68,
            67,
            b"dhcp",
        )
    }

    /// Timestamps in whole seconds; the window is `[10 s, 20 s]`.
    const START: i64 = 10_000_000;
    const END: i64 = 20_000_000;

    fn count(records: &[(u32, u32, &[u8])]) -> OwnFrames {
        let file = savefile(MAGIC_LE_US, records);
        count_own_frames(Cursor::new(file), &OWN, START, END).unwrap()
    }

    /// An echo request from our MAC inside the window is the count's whole
    /// purpose: it lands in `icmp_echo`, and the total says one of ours.
    #[test]
    fn an_echo_of_ours_inside_the_window_counts() {
        let ours = echo_request(OWN);
        let f = count(&[(15, 0, &ours)]);
        assert_eq!(f.records, 1);
        assert_eq!(f.in_window, 1);
        assert_eq!(f.icmp_echo, 1);
        assert_eq!(f.own_total(), 1);
        assert_eq!(f.earliest_us, Some(15_000_000));
        assert_eq!(f.latest_us, Some(15_000_000));
        assert_eq!(f.first_echo_us, Some(15_000_000));
        assert_eq!(f.last_echo_us, Some(15_000_000));
        assert!(!f.truncated);
        assert!(
            !f.covers_from(START),
            "the slice starts after the window opened"
        );
    }

    /// Outside the window a frame of ours is still a record — the slice held
    /// it — but counts toward nothing inside the window.
    #[test]
    fn an_echo_of_ours_outside_the_window_does_not_count() {
        let ours = echo_request(OWN);
        let f = count(&[(5, 0, &ours), (25, 0, &ours)]);
        assert_eq!(f.records, 2);
        assert_eq!(f.in_window, 0);
        assert_eq!(f.icmp_echo, 0);
        assert_eq!(f.own_total(), 0);
        assert_eq!(f.earliest_us, Some(5_000_000));
        assert!(f.covers_from(START));
    }

    /// The window's bounds are inclusive on both ends, and the first and
    /// last echo of ours are the earliest and latest of them — the offset
    /// the report names for a tick that straddled the flip.
    #[test]
    fn the_window_bounds_are_inclusive_and_the_echoes_are_stamped() {
        let ours = echo_request(OWN);
        let theirs = echo_request(PEER);
        let f = count(&[(10, 0, &ours), (12, 500_000, &theirs), (20, 0, &ours)]);
        assert_eq!(f.in_window, 3);
        assert_eq!(f.icmp_echo, 2);
        assert_eq!(f.first_echo_us, Some(10_000_000));
        assert_eq!(f.last_echo_us, Some(20_000_000));
        // An echo of ours outside the window stamps nothing.
        let f = count(&[(25, 0, &ours)]);
        assert_eq!(f.first_echo_us, None);
        assert_eq!(f.last_echo_us, None);
        // The straddling shape: every echo within one 15 s tick of the start.
        let f = count(&[(10, 0, &ours), (24, 0, &ours)]);
        assert!(f.echoes_are_the_straddling_tick(START, 15_000_000));
        let f = count(&[(10, 0, &ours), (20, 0, &ours), (25, 0, &ours)]);
        assert!(f.echoes_are_the_straddling_tick(START, 15_000_000));
        let f = count(&[(10, 0, &ours), (20, 0, &ours)]);
        assert!(!f.echoes_are_the_straddling_tick(START, 5_000_000));
        assert!(!count(&[(15, 0, &theirs)]).echoes_are_the_straddling_tick(START, 15_000_000));
    }

    /// Another machine's echo inside the window is a frame in the window,
    /// never one of ours.
    #[test]
    fn a_frame_from_another_mac_is_not_ours() {
        let theirs = echo_request(PEER);
        let f = count(&[(15, 0, &theirs)]);
        assert_eq!(f.in_window, 1);
        assert_eq!(f.own_total(), 0);
    }

    /// The OS's own traffic lands in its own buckets: ARP, DHCP, and an echo
    /// REPLY (answering someone's ping) as other — so a zero `icmp_echo`
    /// says the DAEMON was silent while the OS still spoke.
    #[test]
    fn the_operating_systems_frames_land_in_their_buckets() {
        let our_arp = arp(OWN, OWN, OWN_IP, GW_IP, false);
        let our_dhcp = dhcp(OWN);
        let our_reply = echo_reply(OWN);
        let their_arp = arp(GATEWAY, GATEWAY, GW_IP, OWN_IP, true);
        let f = count(&[
            (11, 0, &our_arp),
            (12, 0, &our_dhcp),
            (13, 0, &our_reply),
            (14, 0, &their_arp),
        ]);
        assert_eq!(f.in_window, 4);
        assert_eq!(f.icmp_echo, 0);
        assert_eq!(f.arp, 1);
        assert_eq!(f.dhcp, 1);
        assert_eq!(f.other, 1);
        assert_eq!(f.own_total(), 3);
    }

    /// A ring file copied mid-write ends mid-record: what was readable is
    /// counted and the count says it is partial — never an error, never a
    /// silent full count.
    #[test]
    fn a_truncated_slice_counts_what_it_could_and_says_so() {
        let ours = echo_request(OWN);
        let mut file = savefile(MAGIC_LE_US, &[(15, 0, &ours)]);
        file.extend_from_slice(&16u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&100u32.to_le_bytes());
        file.extend_from_slice(&100u32.to_le_bytes());
        file.extend_from_slice(&[0xde, 0xad]);
        let f = count_own_frames(Cursor::new(file), &OWN, START, END).unwrap();
        assert_eq!(f.records, 1);
        assert_eq!(f.icmp_echo, 1);
        assert!(f.truncated);
        // An empty file is a slice cut before its header: nothing counted,
        // truncated said.
        let empty = count_own_frames(Cursor::new(Vec::new()), &OWN, START, END).unwrap();
        assert_eq!(empty.records, 0);
        assert!(empty.truncated);
        assert_eq!(empty.earliest_us, None);
    }

    /// A stream that is not pcap at all is refused, not counted as empty.
    #[test]
    fn a_non_pcap_stream_is_an_error() {
        let mut ng = vec![0x0a, 0x0d, 0x0d, 0x0a];
        ng.extend_from_slice(&[0u8; 40]);
        let err = count_own_frames(Cursor::new(ng), &OWN, START, END).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Junk of every length never panics the classifier.
    #[test]
    fn junk_never_panics() {
        for len in 0..80 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            let _ = classify(&junk, &OWN);
        }
    }
}
