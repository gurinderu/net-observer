//! What an mDNS message (UDP 5353, RFC 6762 / DNS-SD RFC 6763) says about
//! its sender: the names it claims and the services it offers.
//!
//! Only resource records are read — answers, the authority section (a host
//! joining the segment *probes* with its proposed records there) and the
//! additionals. Questions are somebody asking, not announcing.
//!
//! Decoding is `simple-dns`'s; this module turns records into facts:
//!
//! * `A` / `AAAA` — the owner name is a hostname of the sender; the strongest
//!   claim is the one whose address is the frame's own source.
//! * `SRV` — the owner is a service *instance* (`Nick._companion-link._tcp.local`):
//!   its type is the service, its first label the detail; the SRV target is
//!   another hostname claim.
//! * `PTR` — under `_services._dns-sd._udp.local` the target names a type the
//!   sender offers; under a service type the target is an instance of it;
//!   under `in-addr.arpa` / `ip6.arpa` the target is a reverse-lookup name,
//!   the weakest hostname claim.
//!
//! `TXT`, `NSEC`, `OPT` and every other type carry nothing the record wants.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use simple_dns::rdata::RData;
use simple_dns::{Name, Packet, ResourceRecord};

/// The facts one mDNS message announced about its sender.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsFacts {
    /// Hostnames the sender claimed, strongest claim first, trailing `.local`
    /// kept (`0xFF.local`), no trailing dot — the form the operator-pressed
    /// mDNS scan records too.
    pub hostnames: Vec<String>,
    /// `(service type, detail)`: the type without `.local`
    /// (`_companion-link._tcp`), the detail an instance name when the record
    /// carried one.
    pub services: Vec<(String, Option<String>)>,
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
    let mut facts = MdnsFacts::default();
    // Ranked name claims: (rank, name); lower rank = stronger.
    let mut names: Vec<(u8, String)> = Vec::new();
    let records = packet
        .answers
        .iter()
        .chain(packet.name_servers.iter())
        .chain(packet.additional_records.iter());
    for rr in records {
        absorb(rr, src_ip, &mut names, &mut facts.services);
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
    names: &mut Vec<(u8, String)>,
    services: &mut Vec<(String, Option<String>)>,
) {
    let owner = labels(&rr.name);
    match &rr.rdata {
        RData::A(a) => {
            let same = src_ip == IpAddr::V4(Ipv4Addr::from(a.address));
            names.push((if same { 0 } else { 3 }, join(&owner)));
        }
        RData::AAAA(a) => {
            let same = src_ip == IpAddr::V6(Ipv6Addr::from(a.address));
            names.push((if same { 0 } else { 3 }, join(&owner)));
        }
        RData::SRV(srv) => {
            // Owner: <instance> . <_type> . <_tcp|_udp> . local
            if let Some((service, instance)) = split_instance(&owner) {
                services.push((service, Some(instance)));
            }
            names.push((1, join(&labels(&srv.target))));
        }
        RData::PTR(ptr) => {
            let target = labels(&ptr.0);
            let owner_text = join(&owner);
            if owner_text == SERVICES_META {
                if let Some(service) = service_type(&target) {
                    services.push((service, None));
                }
            } else if owner.len() >= 2
                && (owner.last().is_some_and(|l| l == "arpa"))
                && matches!(owner[owner.len() - 2].as_str(), "in-addr" | "ip6")
            {
                names.push((2, join(&target)));
            } else if let Some(service) = service_type(&owner) {
                let instance = split_instance(&target).map(|(_, i)| i);
                services.push((service, instance));
            }
        }
        _ => {}
    }
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
    }

    /// The name whose address IS the frame's source outranks a name learned
    /// second-hand (an SRV target, a reverse PTR, an A for another address).
    #[test]
    fn hostname_claims_are_ranked_by_how_directly_they_name_the_sender() {
        let src = Ipv4Addr::new(192, 168, 1, 6);
        let mut p = Packet::new_reply(0);
        p.answers.push(rr(
            "6.1.168.192.in-addr.arpa",
            RData::PTR(PTR(Name::new_unchecked("reverse.local"))),
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
        assert_eq!(
            facts.hostnames,
            vec![
                "self.local",
                "srv-target.local",
                "reverse.local",
                "other.local"
            ]
        );
        assert_eq!(
            facts.services,
            vec![("_ipp._tcp".to_string(), Some("printer".to_string()))]
        );
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
