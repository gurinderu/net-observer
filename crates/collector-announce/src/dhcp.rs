//! What a DHCP message (UDP 67/68, RFC 2131 / RFC 2132) says about the
//! device that sent it and the device it is about.
//!
//! The fixed BOOTP header: `op` at 0 (1 = a client's request, 2 = a server's
//! reply), `htype` 1 / `hlen` 2 (Ethernet, 6), `ciaddr` at 12..16 (the
//! client's address when it already has one), `yiaddr` at 16..20 (the
//! address a server is handing out), `chaddr` at 28..44 (the client's MAC in
//! the first `hlen` bytes), and the options after the 4-byte magic cookie at
//! 236..240. Options are `code, len, value…`, with `0` a pad and `255` the
//! end; the record wants 53 (message type), 12 (hostname), 60 (vendor
//! class) and 54 (server identifier).

use std::net::Ipv4Addr;

use crate::frame::Mac;

/// Which side of the exchange the message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `BOOTREQUEST`: from a client — DISCOVER, REQUEST, INFORM, DECLINE, RELEASE.
    Request,
    /// `BOOTREPLY`: from a server (or a relay) — OFFER, ACK, NAK.
    Reply,
}

/// The message type (option 53) by its RFC 2132 name, lowercase; an unknown
/// code is `None` on the message, never a guess.
#[must_use]
pub fn message_type_name(code: u8) -> Option<&'static str> {
    Some(match code {
        1 => "discover",
        2 => "offer",
        3 => "request",
        4 => "decline",
        5 => "ack",
        6 => "nak",
        7 => "release",
        8 => "inform",
        _ => return None,
    })
}

/// One DHCP message, reduced to what the neighbour record reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub op: Op,
    /// The client's MAC (`chaddr`).
    pub chaddr: Mac,
    /// `ciaddr` when non-zero: the address the client already holds.
    pub ciaddr: Option<Ipv4Addr>,
    /// `yiaddr` when non-zero: the address a reply is handing the client.
    pub yiaddr: Option<Ipv4Addr>,
    /// Option 53, by name.
    pub message_type: Option<&'static str>,
    /// Option 12: the name the client calls itself.
    pub hostname: Option<String>,
    /// Option 60: the client's vendor class (`MSFT 5.0`, `android-dhcp-13`).
    pub vendor_class: Option<String>,
    /// Option 54: the server a reply comes from / a request is addressed to.
    pub server_id: Option<Ipv4Addr>,
}

const HEADER_LEN: usize = 240;
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Decode one DHCP payload, or `None` when it is not a DHCP-over-Ethernet
/// message (too short, an unknown `op`, a non-Ethernet `htype`/`hlen`, or a
/// missing magic cookie). Options are read until `255`, the end of the
/// buffer, or an option whose length runs past it — whatever was read up to
/// that point stands.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<DhcpMessage> {
    if payload.len() < HEADER_LEN || payload[236..240] != MAGIC_COOKIE {
        return None;
    }
    let op = match payload[0] {
        1 => Op::Request,
        2 => Op::Reply,
        _ => return None,
    };
    if payload[1] != 1 || payload[2] != 6 {
        return None;
    }
    let ip_at = |at: usize| {
        let a = Ipv4Addr::new(
            payload[at],
            payload[at + 1],
            payload[at + 2],
            payload[at + 3],
        );
        (!a.is_unspecified()).then_some(a)
    };
    let chaddr: Mac = payload[28..34].try_into().ok()?;
    let mut msg = DhcpMessage {
        op,
        chaddr,
        ciaddr: ip_at(12),
        yiaddr: ip_at(16),
        message_type: None,
        hostname: None,
        vendor_class: None,
        server_id: None,
    };

    let opts = &payload[HEADER_LEN..];
    let mut i = 0;
    while i < opts.len() {
        let code = opts[i];
        match code {
            0 => {
                i += 1;
                continue;
            }
            255 => break,
            _ => {}
        }
        let Some(&len) = opts.get(i + 1) else { break };
        let start = i + 2;
        let end = start + usize::from(len);
        let Some(value) = opts.get(start..end) else {
            break;
        };
        match code {
            53 => msg.message_type = value.first().and_then(|&c| message_type_name(c)),
            12 => msg.hostname = text(value),
            60 => msg.vendor_class = text(value),
            54 => {
                if let Ok(o) = <[u8; 4]>::try_from(value) {
                    msg.server_id = Some(Ipv4Addr::from(o));
                }
            }
            _ => {}
        }
        i = end;
    }
    Some(msg)
}

/// An option's bytes as text, `None` when empty or not UTF-8 — a name the
/// record cannot render is left out rather than mangled.
fn text(value: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(value)
        .ok()?
        .trim_end_matches('\0')
        .trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a DHCP message from the fields; `options` are `(code, bytes)`.
    pub(crate) fn message(
        op: u8,
        chaddr: Mac,
        ciaddr: Ipv4Addr,
        yiaddr: Ipv4Addr,
        options: &[(u8, &[u8])],
    ) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN];
        out[0] = op;
        out[1] = 1; // htype: Ethernet
        out[2] = 6; // hlen
        out[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        out[12..16].copy_from_slice(&ciaddr.octets());
        out[16..20].copy_from_slice(&yiaddr.octets());
        out[28..34].copy_from_slice(&chaddr);
        out[236..240].copy_from_slice(&MAGIC_COOKIE);
        for (code, value) in options {
            out.push(*code);
            out.push(value.len() as u8);
            out.extend_from_slice(value);
        }
        out.push(255);
        out
    }

    const CLIENT: Mac = [0xca, 0x8f, 0x38, 0xb3, 0x12, 0xd3];
    const ZERO: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

    #[test]
    fn a_discover_carries_its_hostname_and_vendor_class_and_no_address() {
        let m = decode(&message(
            1,
            CLIENT,
            ZERO,
            ZERO,
            &[(53, &[1]), (12, b"nicks-phone"), (60, b"android-dhcp-13")],
        ))
        .unwrap();
        assert_eq!(m.op, Op::Request);
        assert_eq!(m.chaddr, CLIENT);
        assert_eq!(m.ciaddr, None);
        assert_eq!(m.yiaddr, None);
        assert_eq!(m.message_type, Some("discover"));
        assert_eq!(m.hostname.as_deref(), Some("nicks-phone"));
        assert_eq!(m.vendor_class.as_deref(), Some("android-dhcp-13"));
    }

    #[test]
    fn an_ack_carries_the_handed_out_address_and_the_server() {
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let m = decode(&message(
            2,
            CLIENT,
            ZERO,
            Ipv4Addr::new(192, 168, 1, 42),
            &[
                (53, &[5]),
                (54, &server.octets()),
                (51, &3600u32.to_be_bytes()),
            ],
        ))
        .unwrap();
        assert_eq!(m.op, Op::Reply);
        assert_eq!(m.yiaddr, Some(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(m.message_type, Some("ack"));
        assert_eq!(m.server_id, Some(server));
        assert_eq!(m.hostname, None);
    }

    #[test]
    fn a_renewing_request_names_the_address_the_client_holds() {
        let m = decode(&message(
            1,
            CLIENT,
            Ipv4Addr::new(192, 168, 1, 42),
            ZERO,
            &[(53, &[3]), (0, &[]), (12, b"laptop")],
        ))
        .unwrap();
        assert_eq!(m.ciaddr, Some(Ipv4Addr::new(192, 168, 1, 42)));
        assert_eq!(m.message_type, Some("request"));
        assert_eq!(m.hostname.as_deref(), Some("laptop"));
    }

    #[test]
    fn a_truncated_option_keeps_what_was_read_before_it() {
        let mut bytes = message(1, CLIENT, ZERO, ZERO, &[(12, b"first")]);
        bytes.pop(); // drop the end marker
        bytes.extend_from_slice(&[60, 40, b'x', b'y']); // claims 40 bytes, has 2
        let m = decode(&bytes).unwrap();
        assert_eq!(m.hostname.as_deref(), Some("first"));
        assert_eq!(m.vendor_class, None);
    }

    #[test]
    fn not_dhcp_is_none_never_a_panic() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0u8; 300]), None); // no cookie
        let mut bad_op = message(1, CLIENT, ZERO, ZERO, &[]);
        bad_op[0] = 9;
        assert_eq!(decode(&bad_op), None);
        let mut token_ring = message(1, CLIENT, ZERO, ZERO, &[]);
        token_ring[1] = 6;
        assert_eq!(decode(&token_ring), None);
        for len in 0..300 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 31 % 253) as u8).collect();
            let _ = decode(&junk);
        }
    }
}
