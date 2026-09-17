//! What an mDNS message (UDP 5353, RFC 6762 / DNS-SD RFC 6763) says about
//! its sender: the names it claims and the services it offers.
//!
//! Only resource records are read — answers, the authority section (a host
//! joining the segment *probes* with its proposed records there) and the
//! additionals. Questions are somebody asking, not announcing.
//!
//! Decoding is `simple-dns`'s; this module turns records into facts:
//!
//! * `A` / `AAAA` — the owner name is a hostname of the sender ONLY when the
//!   record's address is the frame's own source. A responder speaks for
//!   others too: a Bonjour Sleep Proxy re-announces a sleeping host's records
//!   from its own address, so an `A` for another address, or an `SRV`
//!   target, would put the sleeper's name on the proxy's row. Neither is a
//!   name claim here.
//! * `SRV` — the owner is a service *instance* (`Nick._companion-link._tcp.local`):
//!   its type is the service, its first label the detail — unless the
//!   message ties the SRV target to an address that is not the frame's
//!   source: then the instance is announced on another host's behalf (the
//!   Sleep Proxy again) and is refused and counted (`proxied`), not put on
//!   the announcer's row.
//! * `PTR` — under `_services._dns-sd._udp.local` the target names a type the
//!   sender offers; under a service type the target is an instance of it
//!   (refused with the instance when that instance is proxied); under
//!   `in-addr.arpa` / `ip6.arpa` the target is a reverse-lookup name, a
//!   claim only when the owner spells the frame's own source address.
//!
//! `TXT`, `NSEC`, `OPT` and every other type carry nothing the record wants.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, ResourceRecord};

/// The facts one mDNS message announced about its sender.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsFacts {
    /// Hostnames the packet ties to the sender's own address, strongest
    /// claim first (an address record before a reverse pointer), trailing
    /// `.local` kept (`0xFF.local`), no trailing dot — the form the
    /// operator-pressed mDNS scan records too.
    pub hostnames: Vec<String>,
    /// `(service type, detail)`: the type without `.local`
    /// (`_companion-link._tcp`), the detail an instance name when the record
    /// carried one.
    pub services: Vec<(String, Option<String>)>,
    /// Service records the message announced on another host's behalf — an
    /// SRV whose target the message ties to an address that is not the
    /// frame's source, and the PTRs naming that instance: a Bonjour Sleep
    /// Proxy answering for a sleeper. Not the sender's services, so not in
    /// `services`; counted so the flush can say it refused them.
    pub proxied: u32,
}

/// The meta-query name under which DNS-SD responders enumerate their types.
const SERVICES_META: &str = "_services._dns-sd._udp.local";
/// The mDNS domain every announced name ends in.
const LOCAL: &str = "local";

/// Decode one mDNS payload sent from `src_ip`; `None` when it is not a DNS
/// message `simple-dns` can parse (the caller counts it, nothing else).
#[must_use]
pub fn decode(payload: &[u8], src_ip: IpAddr) -> Option<MdnsFacts> {
    let packet = Packet::parse(payload).ok()?;
    let records: Vec<&ResourceRecord<'_>> = packet
        .answers
        .iter()
        .chain(packet.name_servers.iter())
        .chain(packet.additional_records.iter())
        .collect();

    // What addresses the message itself ties to each name.
    let mut addresses: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    for rr in &records {
        let addr = match &rr.rdata {
            RData::A(a) => IpAddr::V4(Ipv4Addr::from(a.address)),
            RData::AAAA(a) => IpAddr::V6(Ipv6Addr::from(a.address)),
            _ => continue,
        };
        addresses
            .entry(join(&labels(&rr.name)))
            .or_default()
            .push(addr);
    }
    // Instances announced on another host's behalf: an SRV whose target the
    // message ties to addresses none of which is the frame's source — the
    // Sleep Proxy shape. A target the message ties to nothing is taken as
    // the sender's own (a responder always includes its own address records).
    let proxied: BTreeSet<String> = records
        .iter()
        .filter_map(|rr| match &rr.rdata {
            RData::SRV(srv) => {
                let target = join(&labels(&srv.target));
                addresses
                    .get(&target)
                    .is_some_and(|ips| !ips.contains(&src_ip))
                    .then(|| join(&labels(&rr.name)))
            }
            _ => None,
        })
        .collect();

    let mut facts = MdnsFacts::default();
    // Ranked name claims: (rank, name); lower rank = stronger.
    let mut names: Vec<(u8, String)> = Vec::new();
    for rr in records {
        absorb(rr, src_ip, &proxied, &mut names, &mut facts);
    }
    // Stable, so two claims of one rank keep record order.
    names.sort_by_key(|(rank, _)| *rank);
    for (_, name) in names {
        if !facts.hostnames.contains(&name) {
            facts.hostnames.push(name);
        }
    }
    facts.services.dedup();
    Some(facts)
}

fn absorb(
    rr: &ResourceRecord<'_>,
    src_ip: IpAddr,
    proxied: &BTreeSet<String>,
    names: &mut Vec<(u8, String)>,
    facts: &mut MdnsFacts,
) {
    let owner = labels(&rr.name);
    match &rr.rdata {
        RData::A(a) => {
            if src_ip == IpAddr::V4(Ipv4Addr::from(a.address)) {
                names.push((0, join(&owner)));
            }
        }
        RData::AAAA(a) => {
            if src_ip == IpAddr::V6(Ipv6Addr::from(a.address)) {
                names.push((0, join(&owner)));
            }
        }
        RData::SRV(_) => {
            // Owner: <instance> . <_type> . <_tcp|_udp> . local
            if let Some((service, instance)) = split_instance(&owner) {
                if proxied.contains(&join(&owner)) {
                    facts.proxied += 1;
                } else {
                    facts.services.push((service, Some(instance)));
                }
            }
        }
        RData::PTR(ptr) => {
            let target = labels(&ptr.0);
            let owner_text = join(&owner);
            if owner_text == SERVICES_META {
                if let Some(service) = service_type(&target) {
                    facts.services.push((service, None));
                }
            } else if is_reverse_of(&owner, src_ip) {
                names.push((1, join(&target)));
            } else if let Some(service) = service_type(&owner) {
                if proxied.contains(&join(&target)) {
                    facts.proxied += 1;
                } else {
                    let instance = split_instance(&target).map(|(_, i)| i);
                    facts.services.push((service, instance));
                }
            }
        }
        _ => {}
    }
}
/// Whether `owner` is the reverse-lookup name of `ip`: `d.c.b.a.in-addr.arpa`
/// for an IPv4 `a.b.c.d`, or the 32 reversed nibbles under `ip6.arpa`.
fn is_reverse_of(owner: &[String], ip: IpAddr) -> bool {
    let expected: Vec<String> = match ip {
        IpAddr::V4(v4) => v4
            .octets()
            .iter()
            .rev()
            .map(ToString::to_string)
            .chain(["in-addr".to_string(), "arpa".to_string()])
            .collect(),
        IpAddr::V6(v6) => v6
            .octets()
            .iter()
            .rev()
            .flat_map(|o| [o & 0x0f, o >> 4])
            .map(|n| format!("{n:x}"))
            .chain(["ip6".to_string(), "arpa".to_string()])
            .collect(),
    };
    owner.len() == expected.len()
        && owner
            .iter()
            .zip(&expected)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// A name as its labels, rendered lossily as text — a label may hold any
/// byte, and an instance label may hold dots, which is why names are never
/// split on `.`.
fn labels(name: &Name<'_>) -> Vec<String> {
    name.get_labels().iter().map(|l| l.to_string()).collect()
}

fn join(labels: &[String]) -> String {
    labels.join(".")
}

/// `_type._tcp.local` / `_type._udp.local` (any label count before the
/// protocol label, e.g. `_sub` types) → the type without `.local`.
fn service_type(labels: &[String]) -> Option<String> {
    let n = labels.len();
    if n < 3 || labels[n - 1] != LOCAL || !matches!(labels[n - 2].as_str(), "_tcp" | "_udp") {
        return None;
    }
    if !labels[0].starts_with('_') {
        return None;
    }
    Some(join(&labels[..n - 1]))
}

/// `<instance>._type._tcp.local` → `(_type._tcp, instance)`.
fn split_instance(labels: &[String]) -> Option<(String, String)> {
    if labels.len() < 4 || labels[0].starts_with('_') {
        return None;
    }
    let service = service_type(&labels[1..])?;
    Some((service, labels[0].clone()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use simple_dns::rdata::{A, AAAA, PTR, SRV, TXT};
    use simple_dns::{CLASS, Name, Packet, ResourceRecord};

    fn rr<'a>(name: &'a str, rdata: RData<'a>) -> ResourceRecord<'a> {
        ResourceRecord::new(Name::new_unchecked(name), CLASS::IN, 120, rdata)
    }

    /// The announcement the owner watched on his segment: a host naming
    /// itself and three service types (realm net-observer, node #92).
    pub(crate) fn owner_announcement(host_v4: Ipv4Addr) -> Vec<u8> {
        let mut p = Packet::new_reply(0);
        p.answers.push(rr(
            "_services._dns-sd._udp.local",
            RData::PTR(PTR(Name::new_unchecked("_companion-link._tcp.local"))),
        ));
        p.answers.push(rr(
            "_rdlink._tcp.local",
            RData::PTR(PTR(Name::new_unchecked("0xFF._rdlink._tcp.local"))),
        ));
        p.answers.push(rr(
            "0xFF._asquic._udp.local",
            RData::SRV(SRV {
                priority: 0,
                weight: 0,
                port: 49152,
                target: Name::new_unchecked("0xFF.local"),
            }),
        ));
        p.additional_records.push(rr(
            "0xFF.local",
            RData::A(A {
                address: u32::from(host_v4),
            }),
        ));
        p.additional_records.push(rr(
            "0xFF.local",
            RData::AAAA(AAAA {
                address: u128::from("fe80::1".parse::<Ipv6Addr>().unwrap()),
            }),
        ));
        p.additional_records
            .push(rr("0xFF._asquic._udp.local", RData::TXT(TXT::new())));
        p.build_bytes_vec().unwrap()
    }

    #[test]
    fn the_owners_announcement_yields_its_name_and_three_services() {
        let ip = Ipv4Addr::new(192, 168, 1, 6);
        let facts = decode(&owner_announcement(ip), IpAddr::V4(ip)).unwrap();
        assert_eq!(facts.hostnames, vec!["0xFF.local".to_string()]);
        assert_eq!(
            facts.services,
            vec![
                ("_companion-link._tcp".to_string(), None),
                ("_rdlink._tcp".to_string(), Some("0xFF".to_string())),
                ("_asquic._udp".to_string(), Some("0xFF".to_string())),
            ]
        );
        assert_eq!(facts.proxied, 0, "the SRV target is the sender itself");
    }

    /// Only a name the packet ties to the frame's own source is the sender's:
    /// an `A` for its address, or a reverse pointer spelling that address.
    /// An SRV target and an `A` for another address are somebody else's name
    /// (a Sleep Proxy re-announces a sleeper's records from its own address)
    /// and must never land on the sender's row.
    #[test]
    fn only_names_tied_to_the_senders_own_address_are_its_hostname() {
        let src = Ipv4Addr::new(192, 168, 1, 6);
        let mut p = Packet::new_reply(0);
        p.answers.push(rr(
            "6.1.168.192.in-addr.arpa",
            RData::PTR(PTR(Name::new_unchecked("reverse.local"))),
        ));
        p.answers.push(rr(
            "9.1.168.192.in-addr.arpa",
            RData::PTR(PTR(Name::new_unchecked("someone-else.local"))),
        ));
        p.answers.push(rr(
            "printer._ipp._tcp.local",
            RData::SRV(SRV {
                priority: 0,
                weight: 0,
                port: 631,
                target: Name::new_unchecked("srv-target.local"),
            }),
        ));
        p.answers.push(rr(
            "other.local",
            RData::A(A {
                address: u32::from(Ipv4Addr::new(192, 168, 1, 99)),
            }),
        ));
        p.answers.push(rr(
            "self.local",
            RData::A(A {
                address: u32::from(src),
            }),
        ));
        let facts = decode(&p.build_bytes_vec().unwrap(), IpAddr::V4(src)).unwrap();
        assert_eq!(facts.hostnames, vec!["self.local", "reverse.local"]);
        assert_eq!(
            facts.services,
            vec![("_ipp._tcp".to_string(), Some("printer".to_string()))]
        );
    }

    /// The Sleep Proxy shape itself: a proxy announcing a sleeper's `A`, `SRV`,
    /// service `PTR` and reverse pointer from the proxy's own address names
    /// nobody and offers nothing on the proxy's row — the SRV target's address
    /// is not the frame's source, so the instance is somebody else's — and
    /// the refused records are counted, so the flush can say so.
    #[test]
    fn a_sleep_proxys_announcement_yields_neither_name_nor_service_for_the_proxy() {
        let proxy = Ipv4Addr::new(192, 168, 1, 9);
        let sleeper = Ipv4Addr::new(192, 168, 1, 6);
        let mut p = Packet::new_reply(0);
        p.answers.push(rr(
            "_afpovertcp._tcp.local",
            RData::PTR(PTR(Name::new_unchecked("Sleeper._afpovertcp._tcp.local"))),
        ));
        p.answers.push(rr(
            "Sleeper._afpovertcp._tcp.local",
            RData::SRV(SRV {
                priority: 0,
                weight: 0,
                port: 548,
                target: Name::new_unchecked("sleeper.local"),
            }),
        ));
        p.additional_records.push(rr(
            "sleeper.local",
            RData::A(A {
                address: u32::from(sleeper),
            }),
        ));
        p.additional_records.push(rr(
            "6.1.168.192.in-addr.arpa",
            RData::PTR(PTR(Name::new_unchecked("sleeper.local"))),
        ));
        let facts = decode(&p.build_bytes_vec().unwrap(), IpAddr::V4(proxy)).unwrap();
        assert!(facts.hostnames.is_empty(), "{:?}", facts.hostnames);
        assert!(facts.services.is_empty(), "{:?}", facts.services);
        assert_eq!(facts.proxied, 2, "the SRV and the PTR naming its instance");

        // The same message from the sleeper itself is its own announcement.
        let own = decode(&p.build_bytes_vec().unwrap(), IpAddr::V4(sleeper)).unwrap();
        assert_eq!(own.hostnames, vec!["sleeper.local"]);
        assert_eq!(
            own.services,
            vec![("_afpovertcp._tcp".to_string(), Some("Sleeper".to_string()))]
        );
        assert_eq!(own.proxied, 0);
    }

    /// The reverse-pointer check, both families, case-insensitively.
    #[test]
    fn a_reverse_pointer_must_spell_the_source_address() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 6));
        let lab = |s: &str| s.split('.').map(str::to_string).collect::<Vec<_>>();
        assert!(is_reverse_of(&lab("6.1.168.192.in-addr.arpa"), v4));
        assert!(!is_reverse_of(&lab("7.1.168.192.in-addr.arpa"), v4));
        assert!(!is_reverse_of(&lab("6.1.168.192.arpa"), v4));
        let v6: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_reverse_of(
            &lab("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa"),
            v6
        ));
        assert!(!is_reverse_of(
            &lab("2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"),
            v6
        ));
        assert!(!is_reverse_of(&lab("6.1.168.192.in-addr.arpa"), v6));
    }
    /// A probe (a host joining) carries its proposed records in the authority
    /// section; they are announcements too.
    #[test]
    fn authority_records_of_a_probe_count() {
        let src = Ipv4Addr::new(192, 168, 1, 7);
        let mut p = Packet::new_query(0);
        p.name_servers.push(rr(
            "newcomer.local",
            RData::A(A {
                address: u32::from(src),
            }),
        ));
        let facts = decode(&p.build_bytes_vec().unwrap(), IpAddr::V4(src)).unwrap();
        assert_eq!(facts.hostnames, vec!["newcomer.local"]);
    }

    /// A sub-typed service (`_printer._sub._http._tcp.local`) is still a
    /// service; a PTR under a name that is not a service type is not.
    #[test]
    fn service_types_are_recognised_by_their_protocol_label() {
        let mut p = Packet::new_reply(0);
        p.answers.push(rr(
            "_printer._sub._http._tcp.local",
            RData::PTR(PTR(Name::new_unchecked("Office._http._tcp.local"))),
        ));
        p.answers.push(rr(
            "plain.local",
            RData::PTR(PTR(Name::new_unchecked("nothing.local"))),
        ));
        let facts = decode(
            &p.build_bytes_vec().unwrap(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .unwrap();
        assert_eq!(
            facts.services,
            vec![(
                "_printer._sub._http._tcp".to_string(),
                Some("Office".to_string())
            )]
        );
        assert!(facts.hostnames.is_empty());
    }

    #[test]
    fn junk_is_none_never_a_panic() {
        assert_eq!(decode(&[], IpAddr::V4(Ipv4Addr::LOCALHOST)), None);
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 53 % 251) as u8).collect();
            let _ = decode(&junk, IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
    }
}
