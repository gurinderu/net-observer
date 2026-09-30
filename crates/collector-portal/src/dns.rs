//! A single DNS A question and its answer, pure both ways: the probe asks the
//! interface's DHCP resolver directly (bound to the interface), because the
//! system resolver answers through the tunnel — a fakeip there would send the
//! probe into the TUN and the reading would be about the wrong path (realm
//! net-observer, node #178).
//!
//! On a portal network the resolver often hijacks the name to the portal's
//! own address — that is a fine answer: the probe then reaches the portal and
//! reads the intercept.

use std::net::Ipv4Addr;

/// Build one recursion-desired A question for `host`.
#[must_use]
pub fn a_query(id: u16, host: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(17 + host.len());
    q.extend_from_slice(&id.to_be_bytes());
    // Flags: RD only. One question, no other sections.
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.').filter(|l| !l.is_empty()) {
        // Labels beyond 63 bytes do not occur in the pinned host; clamp is
        // still safe because the split never yields them for it.
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    // QTYPE A, QCLASS IN.
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

/// The first A record in `packet`, answering the query `id`. `Err` names what
/// made the answer unusable — a mismatched id, an error rcode, no A record,
/// or a malformed packet.
pub fn first_a_answer(packet: &[u8], id: u16) -> Result<Ipv4Addr, String> {
    if packet.len() < 12 {
        return Err("DNS answer shorter than its header".into());
    }
    if packet[0..2] != id.to_be_bytes() {
        return Err("DNS answer id mismatch".into());
    }
    if packet[2] & 0x80 == 0 {
        return Err("DNS packet is not a response".into());
    }
    let rcode = packet[3] & 0x0f;
    if rcode != 0 {
        return Err(format!("DNS rcode {rcode}"));
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        pos = pos
            .checked_add(4)
            .filter(|p| *p <= packet.len())
            .ok_or("question section truncated")?;
    }
    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            return Err("answer record truncated".into());
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let class = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > packet.len() {
            return Err("answer rdata truncated".into());
        }
        if rtype == 1 && class == 1 && rdlen == 4 {
            return Ok(Ipv4Addr::new(
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            ));
        }
        // A CNAME (or anything else) is skipped; the A usually follows it in
        // the same answer.
        pos += rdlen;
    }
    Err("no A record in the answer".into())
}

/// Skip one (possibly compressed) name starting at `pos`, returning the
/// offset just past it.
fn skip_name(packet: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        let &len = packet.get(pos).ok_or("name runs past the packet")?;
        match len {
            0 => return Ok(pos + 1),
            // A compression pointer ends the name in two bytes.
            l if l & 0xc0 == 0xc0 => {
                return (pos + 2 <= packet.len())
                    .then_some(pos + 2)
                    .ok_or_else(|| "pointer runs past the packet".into());
            }
            l => pos += 1 + l as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_query_carries_the_name_type_and_class() {
        let q = a_query(0xbeef, "captive.apple.com");
        assert_eq!(&q[0..2], &[0xbe, 0xef]);
        // RD set, one question.
        assert_eq!(&q[2..6], &[0x01, 0x00, 0, 1]);
        let name = b"\x07captive\x05apple\x03com\x00";
        assert_eq!(&q[12..12 + name.len()], name);
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1]);
    }

    /// A response with the question echoed, a CNAME, then the A — the A wins,
    /// compression pointers and all.
    #[test]
    fn walks_cname_and_compression_to_the_a_record() {
        let mut p = Vec::new();
        p.extend_from_slice(&0xbeefu16.to_be_bytes());
        p.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]);
        // Question: captive.apple.com A IN — its name starts at offset 12.
        p.extend_from_slice(b"\x07captive\x05apple\x03com\x00");
        p.extend_from_slice(&[0, 1, 0, 1]);
        // Answer 1: pointer to offset 12, CNAME → "portal" (rdata is a name,
        // opaque to the walker).
        p.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8]);
        p.extend_from_slice(b"\x06portal\x00");
        // Answer 2: pointer, A, 192.168.100.1.
        p.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 168, 100, 1]);
        assert_eq!(
            first_a_answer(&p, 0xbeef),
            Ok(Ipv4Addr::new(192, 168, 100, 1))
        );
    }

    #[test]
    fn refusals_and_damage_are_named() {
        assert!(first_a_answer(&[], 1).unwrap_err().contains("header"));

        let mut wrong_id = a_query(2, "a.b");
        wrong_id[2] |= 0x80;
        assert!(first_a_answer(&wrong_id, 1).unwrap_err().contains("id"));

        // A response with rcode 3 (NXDOMAIN).
        let mut nx = a_query(7, "a.b");
        nx[2] |= 0x80;
        nx[3] |= 0x03;
        assert_eq!(first_a_answer(&nx, 7).unwrap_err(), "DNS rcode 3");

        // The query itself (QR unset) is not a response.
        assert!(
            first_a_answer(&a_query(7, "a.b"), 7)
                .unwrap_err()
                .contains("not a response")
        );

        // A well-formed response with no answers.
        let mut empty = a_query(9, "a.b");
        empty[2] |= 0x80;
        assert!(
            first_a_answer(&empty, 9)
                .unwrap_err()
                .contains("no A record")
        );
    }
}
