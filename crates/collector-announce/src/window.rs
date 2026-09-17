//! One flush window of the listener: every frame heard since the last flush,
//! folded into the neighbour facts it announced. Pure and synchronous — the
//! source feeds it bytes and asks for the sample; nothing here knows where
//! the bytes came from (realm net-observer, node #92).
//!
//! What a frame contributes:
//!
//! * Its Ethernet source is the sender. Our own frames (source = the
//!   interface's MAC) are counted and dropped: a machine is not its own
//!   neighbour, and the count is what lets the record check that the daemon
//!   itself put nothing on the wire.
//! * ARP: the sender pair from the ARP body, unless the sender address is
//!   unspecified (an address-conflict probe, RFC 5227).
//! * Every IPv4/IPv6 frame: the Ethernet source paired with the IP source —
//!   except when the Ethernet source is the gateway's own MAC. The gateway
//!   forwards: a DHCP reply relayed from an off-link server, an SSDP
//!   announcement forwarded from the uplink, arrive with its MAC and a
//!   foreign address, and the pairing would put that address on the
//!   gateway's row. The gateway's own address comes from its ARP traffic
//!   instead, which never carries anyone else's.
//! * mDNS: the sender's strongest hostname claim and the service types it
//!   announced; SSDP: the type a `NOTIFY` / search response announced; DHCP:
//!   a client's hostname and vendor class, a server's replies as the
//!   `dhcp-server` role, and the address an `ACK` confirms for a client.
//!
//! Devices are keyed by MAC and services by `(MAC, service)`, so a window is
//! bounded by the segment's size, not by its chatter.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use types::{
    AnnounceKind, AnnouncedService, HeardFrames, NeighborObs, NeighborRole, NeighborSource,
    NeighborsSample, NeighborsVerdict,
};

use crate::frame::{self, Heard, Mac, is_unicast, mac_octets, mac_text};
use crate::{dhcp, mdns, ssdp};

/// The mDNS port, both directions.
const MDNS_PORT: u16 = 5353;
/// The SSDP port, both directions.
const SSDP_PORT: u16 = 1900;
/// DHCP: servers listen on 67, clients on 68.
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

/// The service name under which a DHCP server's replies are recorded.
const DHCP_SERVER_SERVICE: &str = "dhcp-server";
/// The service name under which a DHCP client's vendor class is recorded.
const DHCP_VENDOR_CLASS_SERVICE: &str = "vendor-class";

#[derive(Debug, Default)]
struct Device {
    /// Every address this MAC was paired with; the lowest IPv4 is the one the
    /// sample carries (`IpAddr` orders every v4 before every v6), a v6 only
    /// when the device showed no v4 — the same preference the neighbour-cache
    /// reading applies.
    ips: BTreeSet<IpAddr>,
    hostname: Option<String>,
}

#[derive(Debug)]
struct Announced {
    ip: Option<IpAddr>,
    kind: AnnounceKind,
    detail: Option<String>,
}

/// The accumulator for one flush window.
#[derive(Debug)]
pub struct Window {
    own_mac: Mac,
    gateway_mac: Option<Mac>,
    network_key: Option<String>,
    iface: Option<String>,
    heard: u32,
    own: u32,
    undecoded: u32,
    devices: BTreeMap<Mac, Device>,
    services: BTreeMap<(Mac, String), Announced>,
    /// Hostnames from DHCP requests whose client had no address yet, waiting
    /// for the `ACK` that names one. Dropped with the window if none comes.
    pending_names: BTreeMap<Mac, String>,
}

impl Window {
    /// An empty window keyed by `network_key` (the gateway's MAC, which also
    /// arms the forwarding guard) on `iface`, dropping frames from `own_mac`.
    #[must_use]
    pub fn new(own_mac: Mac, network_key: Option<String>, iface: Option<String>) -> Self {
        let gateway_mac = network_key.as_deref().and_then(mac_octets);
        Self {
            own_mac,
            gateway_mac,
            network_key,
            iface,
            heard: 0,
            own: 0,
            undecoded: 0,
            devices: BTreeMap::new(),
            services: BTreeMap::new(),
            pending_names: BTreeMap::new(),
        }
    }

    /// Fold one captured Ethernet frame in.
    pub fn absorb(&mut self, bytes: &[u8]) {
        self.heard = self.heard.saturating_add(1);
        let Some(frame) = frame::decode(bytes) else {
            self.undecoded = self.undecoded.saturating_add(1);
            return;
        };
        if frame.src_mac == self.own_mac {
            self.own = self.own.saturating_add(1);
            return;
        }
        match frame.heard {
            Heard::Arp {
                sender_mac,
                sender_ip,
            } => {
                if sender_mac != self.own_mac && !sender_ip.is_unspecified() {
                    self.sight(sender_mac, IpAddr::V4(sender_ip));
                }
            }
            Heard::Udp {
                src_ip,
                src_port,
                dst_port,
                payload,
            } => {
                if addressable(src_ip) && Some(frame.src_mac) != self.gateway_mac {
                    self.sight(frame.src_mac, src_ip);
                }
                let ports = (src_port, dst_port);
                if ports.0 == MDNS_PORT || ports.1 == MDNS_PORT {
                    self.absorb_mdns(frame.src_mac, src_ip, payload);
                } else if ports.0 == SSDP_PORT || ports.1 == SSDP_PORT {
                    self.absorb_ssdp(frame.src_mac, src_ip, payload);
                } else if [DHCP_SERVER_PORT, DHCP_CLIENT_PORT].contains(&ports.0)
                    || [DHCP_SERVER_PORT, DHCP_CLIENT_PORT].contains(&ports.1)
                {
                    self.absorb_dhcp(frame.src_mac, src_ip, payload);
                }
            }
            Heard::Other => {}
        }
    }

    /// The frame counts so far.
    #[must_use]
    pub fn heard(&self) -> HeardFrames {
        HeardFrames {
            total: self.heard,
            own: self.own,
        }
    }

    /// Frames the capture delivered but no Ethernet header could be read from.
    #[must_use]
    pub fn undecoded(&self) -> u32 {
        self.undecoded
    }

    /// Whether nothing at all was heard.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.heard == 0
    }

    /// The window as one reading. A device seen without any address (a name
    /// claimed by a MAC the guard kept from pairing) has no row: the
    /// neighbour record is keyed on an address the device can be reached at.
    #[must_use]
    pub fn flush(self, ts_us: i64) -> NeighborsSample {
        let heard = self.heard();
        let neighbors = self
            .devices
            .into_iter()
            .filter_map(|(mac, dev)| {
                let ip = dev.ips.iter().next()?;
                Some(NeighborObs {
                    mac: mac_text(&mac),
                    ip: ip.to_string(),
                    source: NeighborSource::Announce,
                    hostname: dev.hostname,
                    role: NeighborRole::Unknown,
                })
            })
            .collect();
        let services = self
            .services
            .into_iter()
            .map(|((mac, service), a)| AnnouncedService {
                mac: mac_text(&mac),
                ip: a.ip.map(|ip| ip.to_string()),
                service,
                kind: a.kind,
                detail: a.detail,
            })
            .collect();
        NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: self.network_key,
            iface: self.iface,
            neighbors,
            services,
            heard: Some(heard),
        }
    }

    /// Record that `mac` was seen using `ip`.
    fn sight(&mut self, mac: Mac, ip: IpAddr) {
        if !is_unicast(&mac) {
            return;
        }
        self.devices.entry(mac).or_default().ips.insert(ip);
    }

    /// Attach a name to `mac`, keeping one already learned this window.
    fn name(&mut self, mac: Mac, hostname: String) {
        if !is_unicast(&mac) {
            return;
        }
        self.devices
            .entry(mac)
            .or_default()
            .hostname
            .get_or_insert(hostname);
    }

    fn announce(
        &mut self,
        mac: Mac,
        ip: Option<IpAddr>,
        service: String,
        kind: AnnounceKind,
        detail: Option<String>,
    ) {
        if !is_unicast(&mac) {
            return;
        }
        let slot = self
            .services
            .entry((mac, service))
            .or_insert(Announced { ip, kind, detail });
        // A later repeat may carry what the first lacked; it never erases.
        if slot.ip.is_none() {
            slot.ip = ip;
        }
    }

    fn absorb_mdns(&mut self, src_mac: Mac, src_ip: IpAddr, payload: &[u8]) {
        let Some(facts) = mdns::decode(payload, src_ip) else {
            return;
        };
        if let Some(name) = facts.hostnames.into_iter().next() {
            self.name(src_mac, name);
        }
        for (service, detail) in facts.services {
            self.announce(src_mac, Some(src_ip), service, AnnounceKind::Mdns, detail);
        }
    }

    fn absorb_ssdp(&mut self, src_mac: Mac, src_ip: IpAddr, payload: &[u8]) {
        let Some(facts) = ssdp::decode(payload) else {
            return;
        };
        self.announce(
            src_mac,
            Some(src_ip),
            facts.service,
            AnnounceKind::Ssdp,
            facts.detail,
        );
    }

    fn absorb_dhcp(&mut self, src_mac: Mac, src_ip: IpAddr, payload: &[u8]) {
        let Some(msg) = dhcp::decode(payload) else {
            return;
        };
        match msg.op {
            dhcp::Op::Request => {
                let client = msg.chaddr;
                if client == self.own_mac {
                    return;
                }
                let addr = msg.ciaddr.map(IpAddr::V4);
                match (addr, msg.hostname) {
                    (Some(ip), hostname) => {
                        self.sight(client, ip);
                        if let Some(h) = hostname {
                            self.name(client, h);
                        }
                    }
                    (None, Some(h)) => {
                        self.pending_names.entry(client).or_insert(h);
                    }
                    (None, None) => {}
                }
                if let Some(class) = msg.vendor_class {
                    self.announce(
                        client,
                        addr,
                        DHCP_VENDOR_CLASS_SERVICE.to_string(),
                        AnnounceKind::Dhcp,
                        Some(class),
                    );
                }
            }
            dhcp::Op::Reply => {
                // The replying MAC is a DHCP server on this segment — or the
                // relay standing in for one; either way the frames come from it.
                self.announce(
                    src_mac,
                    msg.server_id.map(IpAddr::V4).or(Some(src_ip)),
                    DHCP_SERVER_SERVICE.to_string(),
                    AnnounceKind::Dhcp,
                    msg.message_type.map(str::to_string),
                );
                if msg.message_type == Some("ack")
                    && let Some(ip) = msg.yiaddr
                    && msg.chaddr != self.own_mac
                {
                    self.sight(msg.chaddr, IpAddr::V4(ip));
                    if let Some(h) = self.pending_names.remove(&msg.chaddr) {
                        self.name(msg.chaddr, h);
                    }
                }
            }
        }
    }
}

/// Whether an IP source can name a device: not unspecified (a DHCP client
/// without an address sends from `0.0.0.0`), not a group or broadcast
/// address, not loopback.
fn addressable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_multicast() && !v4.is_broadcast() && !v4.is_loopback()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast() && !v6.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp::tests::message as dhcp_message;
    use crate::frame::tests::{BROADCAST, GATEWAY, OWN, PEER, arp, udp4, udp6};
    use crate::mdns::tests::owner_announcement;
    use crate::ssdp::tests::{M_SEARCH, NOTIFY_ALIVE};
    use std::net::Ipv4Addr;

    const GW_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
    const PEER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 6);
    const OWN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 5);
    const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    const SSDP_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

    fn window() -> Window {
        Window::new(OWN, Some(mac_text(&GATEWAY)), Some("en0".into()))
    }

    fn obs<'a>(s: &'a NeighborsSample, mac: &Mac) -> &'a NeighborObs {
        let text = mac_text(mac);
        s.neighbors
            .iter()
            .find(|n| n.mac == text)
            .unwrap_or_else(|| panic!("no obs for {text} in {:?}", s.neighbors))
    }

    /// The two minutes the owner watched, replayed: the gateway's ARP reply,
    /// the peer's mDNS announcement, an ARP request to us, our own SSDP
    /// search. Two neighbours, three services, one frame of ours counted and
    /// dropped (realm net-observer, node #92).
    #[test]
    fn the_owners_two_minutes_fold_into_two_neighbours_and_their_services() {
        let mut w = window();
        w.absorb(&arp(GATEWAY, GATEWAY, GW_IP, OWN_IP, true));
        w.absorb(&udp4(
            PEER,
            PEER_IP,
            MDNS_GROUP,
            5353,
            5353,
            &owner_announcement(PEER_IP),
        ));
        let asker: Mac = [0x00, 0x1c, 0x42, 0x08, 0x09, 0x0a];
        w.absorb(&arp(
            asker,
            asker,
            Ipv4Addr::new(192, 168, 1, 239),
            OWN_IP,
            false,
        ));
        w.absorb(&udp4(
            OWN,
            OWN_IP,
            SSDP_GROUP,
            50000,
            1900,
            M_SEARCH.as_bytes(),
        ));

        assert_eq!(w.heard(), HeardFrames { total: 4, own: 1 });
        let s = w.flush(42);
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.verdict, NeighborsVerdict::Ok);
        assert_eq!(s.network_key.as_deref(), Some("60:22:32:aa:25:21"));
        assert_eq!(s.iface.as_deref(), Some("en0"));
        assert_eq!(s.heard, Some(HeardFrames { total: 4, own: 1 }));
        assert!(s.is_listener_flush());

        assert_eq!(s.neighbors.len(), 3, "{:?}", s.neighbors);
        assert!(
            s.neighbors
                .iter()
                .all(|n| n.source == NeighborSource::Announce)
        );
        assert_eq!(obs(&s, &GATEWAY).ip, "192.168.1.1");
        let peer = obs(&s, &PEER);
        assert_eq!(peer.ip, "192.168.1.6");
        assert_eq!(peer.hostname.as_deref(), Some("0xFF.local"));
        assert_eq!(obs(&s, &asker).ip, "192.168.1.239");
        assert!(s.neighbors.iter().all(|n| n.mac != mac_text(&OWN)));

        let mut services: Vec<(&str, &str)> = s
            .services
            .iter()
            .map(|a| (a.service.as_str(), a.detail.as_deref().unwrap_or("")))
            .collect();
        services.sort();
        assert_eq!(
            services,
            vec![
                ("_asquic._udp", "0xFF"),
                ("_companion-link._tcp", ""),
                ("_rdlink._tcp", "0xFF"),
            ]
        );
        assert!(s.services.iter().all(|a| a.mac == mac_text(&PEER)
            && a.kind == AnnounceKind::Mdns
            && a.ip.as_deref() == Some("192.168.1.6")));
    }

    #[test]
    fn a_frame_of_ours_is_counted_and_dropped_even_when_it_announces() {
        let mut w = window();
        w.absorb(&udp4(
            OWN,
            OWN_IP,
            MDNS_GROUP,
            5353,
            5353,
            &owner_announcement(OWN_IP),
        ));
        assert_eq!(w.heard(), HeardFrames { total: 1, own: 1 });
        let s = w.flush(1);
        assert!(s.neighbors.is_empty());
        assert!(s.services.is_empty());
    }

    /// The forwarding guard: an IP frame from the gateway's MAC carrying a
    /// foreign address must not put that address on the gateway's row — the
    /// gateway's own address comes from its ARP.
    #[test]
    fn a_frame_forwarded_by_the_gateway_does_not_pair_its_mac_with_a_foreign_address() {
        let mut w = window();
        let relayed = dhcp_message(
            2,
            PEER,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 168, 1, 77),
            &[(53, &[5]), (54, &[10, 0, 0, 5])],
        );
        w.absorb(&udp4(
            GATEWAY,
            Ipv4Addr::new(10, 0, 0, 5),
            Ipv4Addr::BROADCAST,
            67,
            68,
            &relayed,
        ));
        let s = w.flush(1);
        assert!(
            s.neighbors.iter().all(|n| n.mac != mac_text(&GATEWAY)),
            "{:?}",
            s.neighbors
        );
        // The client the ACK confirmed IS recorded, from the DHCP body.
        assert_eq!(obs(&s, &PEER).ip, "192.168.1.77");
        // And the replies name their source as a DHCP server, by server id.
        let srv = &s.services[0];
        assert_eq!(srv.mac, mac_text(&GATEWAY));
        assert_eq!(srv.service, "dhcp-server");
        assert_eq!(srv.kind, AnnounceKind::Dhcp);
        assert_eq!(srv.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(srv.detail.as_deref(), Some("ack"));
    }

    /// Without a gateway key there is no guard: every unicast IP frame pairs.
    #[test]
    fn without_a_network_key_every_ip_frame_pairs() {
        let mut w = Window::new(OWN, None, None);
        w.absorb(&udp4(
            GATEWAY,
            GW_IP,
            SSDP_GROUP,
            1900,
            1900,
            NOTIFY_ALIVE.as_bytes(),
        ));
        let s = w.flush(1);
        assert_eq!(s.network_key, None);
        assert_eq!(obs(&s, &GATEWAY).ip, "192.168.1.1");
        assert_eq!(
            s.services[0].service,
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
        );
        assert_eq!(s.services[0].kind, AnnounceKind::Ssdp);
    }

    /// A joining client: DISCOVER (no address, a hostname) then the server's
    /// ACK naming one — the name lands on the confirmed address.
    #[test]
    fn a_dhcp_hostname_waits_for_the_ack_that_names_an_address() {
        let mut w = window();
        let discover = dhcp_message(
            1,
            PEER,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &[(53, &[1]), (12, b"nicks-phone"), (60, b"android-dhcp-13")],
        );
        w.absorb(&udp4(
            PEER,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            68,
            67,
            &discover,
        ));
        // Nothing addressable yet: no neighbour row, but the class is known.
        assert!(w.devices.is_empty());
        let ack = dhcp_message(
            2,
            PEER,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(192, 168, 1, 42),
            &[(53, &[5]), (54, &GW_IP.octets())],
        );
        w.absorb(&udp4(GATEWAY, GW_IP, Ipv4Addr::BROADCAST, 67, 68, &ack));
        let s = w.flush(1);
        let peer = obs(&s, &PEER);
        assert_eq!(peer.ip, "192.168.1.42");
        assert_eq!(peer.hostname.as_deref(), Some("nicks-phone"));
        let class = s
            .services
            .iter()
            .find(|a| a.service == "vendor-class")
            .unwrap();
        assert_eq!(class.mac, mac_text(&PEER));
        assert_eq!(class.detail.as_deref(), Some("android-dhcp-13"));
        assert_eq!(class.ip, None);
        assert!(
            s.services
                .iter()
                .any(|a| a.service == "dhcp-server" && a.mac == mac_text(&GATEWAY))
        );
    }

    /// One row per device: a dual-stack announcer keeps its v4 address, the
    /// repeated announcement is one service, and its name survives.
    #[test]
    fn a_device_heard_on_both_stacks_and_twice_is_one_row_with_its_v4_address() {
        let mut w = window();
        let msg = owner_announcement(PEER_IP);
        w.absorb(&udp6(
            PEER,
            "fe80::1".parse().unwrap(),
            "ff02::fb".parse().unwrap(),
            5353,
            5353,
            &msg,
        ));
        w.absorb(&udp4(PEER, PEER_IP, MDNS_GROUP, 5353, 5353, &msg));
        w.absorb(&udp4(PEER, PEER_IP, MDNS_GROUP, 5353, 5353, &msg));
        let s = w.flush(1);
        assert_eq!(s.neighbors.len(), 1);
        assert_eq!(s.neighbors[0].ip, "192.168.1.6");
        assert_eq!(s.neighbors[0].hostname.as_deref(), Some("0xFF.local"));
        assert_eq!(s.services.len(), 3);
        assert_eq!(s.heard, Some(HeardFrames { total: 3, own: 0 }));
    }

    /// A v6-only announcer keeps its v6 address — it has no v4 to lose to.
    #[test]
    fn a_v6_only_announcer_keeps_its_v6_address() {
        let mut w = window();
        w.absorb(&udp6(
            PEER,
            "fe80::1".parse().unwrap(),
            "ff02::fb".parse().unwrap(),
            5353,
            5353,
            &owner_announcement(PEER_IP),
        ));
        let s = w.flush(1);
        assert_eq!(s.neighbors[0].ip, "fe80::1");
    }

    /// An ARP probe (sender 0.0.0.0), a frame from a group MAC, and bytes that
    /// are no frame at all are counted, never rows.
    #[test]
    fn probes_group_sources_and_junk_are_counted_not_recorded() {
        let mut w = window();
        w.absorb(&arp(PEER, PEER, Ipv4Addr::UNSPECIFIED, PEER_IP, false));
        w.absorb(&udp4(BROADCAST, PEER_IP, MDNS_GROUP, 5353, 5353, b"x"));
        w.absorb(&[1, 2, 3]);
        assert_eq!(w.undecoded(), 1);
        assert_eq!(w.heard(), HeardFrames { total: 3, own: 0 });
        assert!(!w.is_empty());
        let s = w.flush(1);
        assert!(s.neighbors.is_empty(), "{:?}", s.neighbors);
    }

    /// An empty window is a reading too: the segment was silent.
    #[test]
    fn an_empty_window_flushes_as_a_silent_reading() {
        let w = window();
        assert!(w.is_empty());
        let s = w.flush(7);
        assert_eq!(s.verdict, NeighborsVerdict::Ok);
        assert!(s.neighbors.is_empty());
        assert_eq!(s.heard, Some(HeardFrames { total: 0, own: 0 }));
    }
}
