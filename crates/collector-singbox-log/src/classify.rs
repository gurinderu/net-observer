//! From a parsed ERROR/WARN line to its [`SingboxLogClass`] — the observed
//! vocabulary of sing-box 1.13.19's log (realm net-observer, node #140), each
//! message shape one class. Anything else at those levels is
//! [`SingboxLogClass::Other`]; INFO and DEBUG lines are no class at all.

use types::SingboxLogClass;

use crate::parse::LogLine;

/// The class of `line` and, for an outbound dial, the node it went through
/// (`using outbound/vless[<node>]`). `None` for a line below WARN.
#[must_use]
pub fn classify(line: &LogLine) -> Option<(SingboxLogClass, Option<String>)> {
    use SingboxLogClass as C;
    if !line.level.is_alert() {
        return None;
    }
    let msg = line.message.as_str();
    let class = match line.component.as_str() {
        // `connection: open connection to <ip:port> using outbound/vless[<node>]: dial tcp <ip:port>: <error>`
        "connection" if msg.starts_with("open connection to") => {
            let class = if msg.contains("no route to internet") {
                C::NoRoute
            } else if msg.contains("network is unreachable") {
                C::Unreachable
            } else if msg.contains("i/o timeout") {
                C::DialTimeout
            } else if msg.contains("context canceled") || msg.contains("operation was canceled") {
                C::Canceled
            } else {
                C::Other
            };
            return Some((class, outbound_node(msg)));
        }
        "connection"
            if msg.starts_with("connection download closed")
                || msg.starts_with("connection upload closed") =>
        {
            C::StreamClosed
        }
        "network" | "dns/local" if msg.contains("missing default interface") => C::NoDefaultIface,
        "dns/local"
            if msg.contains("context deadline exceeded")
                || msg.contains("address already in use") =>
        {
            C::DnsServersFailed
        }
        "dns" if msg.starts_with("exchange failed") => C::DnsExchangeFailed,
        "router" if msg.starts_with("process DNS packet: unpack request") => C::DnsBadPacket,
        "router" if msg.starts_with("process DNS packet: dial UDP connection") => {
            C::DnsExchangeFailed
        }
        "outbound/direct"
            if msg.starts_with("receive ICMP echo reply") && msg.contains("i/o timeout") =>
        {
            C::IcmpReplyTimeout
        }
        "inbound/tun" if msg.contains("icmp is not supported by default outbound") => {
            C::IcmpUnsupported
        }
        _ => C::Other,
    };
    Some((class, None))
}

/// The node named by `using outbound/<kind>[<node>]`, when the message names
/// one.
fn outbound_node(msg: &str) -> Option<String> {
    let after = &msg[msg.find("using outbound/")? + "using outbound/".len()..];
    let open = after.find('[')?;
    let close = after[open + 1..].find(']')?;
    Some(after[open + 1..open + 1 + close].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_line;

    fn class_of(line: &str) -> Option<(SingboxLogClass, Option<String>)> {
        classify(&parse_line(line).expect("a well-formed line"))
    }

    fn error(rest: &str) -> String {
        format!("+0300 2026-09-17 20:56:25 ERROR {rest}")
    }

    fn warn(rest: &str) -> String {
        format!("+0300 2026-09-17 20:56:25 WARN {rest}")
    }

    #[test]
    fn no_route_names_the_node() {
        assert_eq!(
            class_of(&error(
                "[179023894 0ms] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: dial tcp 1.2.3.4:443: no route to internet"
            )),
            Some((SingboxLogClass::NoRoute, Some("vless-out-6".into())))
        );
    }

    #[test]
    fn unreachable_names_the_node() {
        assert_eq!(
            class_of(&error(
                "[179023895 0ms] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-2]: dial tcp 1.2.3.4:443: connect: network is unreachable"
            )),
            Some((SingboxLogClass::Unreachable, Some("vless-out-2".into())))
        );
    }

    #[test]
    fn dial_timeout_names_the_node() {
        assert_eq!(
            class_of(&error(
                "[179023896 10.0s] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: dial tcp 1.2.3.4:443: i/o timeout"
            )),
            Some((SingboxLogClass::DialTimeout, Some("vless-out-6".into())))
        );
    }

    #[test]
    fn canceled_in_both_spellings_names_the_node() {
        assert_eq!(
            class_of(&error(
                "[1 2.1s] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: context canceled"
            )),
            Some((SingboxLogClass::Canceled, Some("vless-out-6".into())))
        );
        assert_eq!(
            class_of(&error(
                "[1 2.1s] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: dial tcp 1.2.3.4:443: operation was canceled"
            )),
            Some((SingboxLogClass::Canceled, Some("vless-out-6".into())))
        );
    }

    #[test]
    fn no_default_iface_from_the_network_monitor_and_the_local_resolver() {
        assert_eq!(
            class_of(&error("network: missing default interface")),
            Some((SingboxLogClass::NoDefaultIface, None))
        );
        assert_eq!(
            class_of(&error(
                "dns/local[local]: fetch DNS servers: dhcp: prepare interface: missing default interface"
            )),
            Some((SingboxLogClass::NoDefaultIface, None))
        );
    }

    #[test]
    fn dns_servers_failed_in_its_three_shapes() {
        for rest in [
            "dns/local[local]: fetch DNS servers: context deadline exceeded",
            "dns/local[local]: update servers: context deadline exceeded",
            "dns/local[local]: fetch DNS servers: dhcp: listen udp4 0.0.0.0:68: bind: address already in use",
        ] {
            assert_eq!(
                class_of(&error(rest)),
                Some((SingboxLogClass::DnsServersFailed, None)),
                "{rest}"
            );
        }
    }

    #[test]
    fn dns_exchange_failed_from_dns_and_from_the_router() {
        assert_eq!(
            class_of(&error(
                "[1 5.0s] dns: exchange failed for example.com. IN A: context deadline exceeded"
            )),
            Some((SingboxLogClass::DnsExchangeFailed, None))
        );
        assert_eq!(
            class_of(&error(
                "[1 0ms] router: process DNS packet: dial UDP connection: no route to internet"
            )),
            Some((SingboxLogClass::DnsExchangeFailed, None))
        );
    }

    #[test]
    fn dns_bad_packet() {
        assert_eq!(
            class_of(&error(
                "[1 0ms] router: process DNS packet: unpack request: dns: overflow unpacking uint16"
            )),
            Some((SingboxLogClass::DnsBadPacket, None))
        );
    }

    #[test]
    fn icmp_reply_timeout_on_the_observed_line() {
        assert_eq!(
            class_of(
                "+0300 2026-09-17 20:56:25 \x1b[31mERROR\x1b[0m [\x1b[38;5;38m179023894\x1b[0m 15.22s] outbound/direct[direct-out]: receive ICMP echo reply: read udp 0.0.0.0:0: i/o timeout"
            ),
            Some((SingboxLogClass::IcmpReplyTimeout, None))
        );
    }

    #[test]
    fn stream_closed() {
        assert_eq!(
            class_of(&error(
                "[1 61.0s] connection: connection download closed: http2: client connection lost"
            )),
            Some((SingboxLogClass::StreamClosed, None))
        );
    }

    #[test]
    fn icmp_unsupported_is_a_warn() {
        assert_eq!(
            class_of(&warn(
                "[1 0ms] inbound/tun[0]: link icmp connection from 198.18.0.5 to 1.1.1.1: icmp is not supported by default outbound: vless-auto"
            )),
            Some((SingboxLogClass::IcmpUnsupported, None))
        );
    }

    #[test]
    fn anything_else_at_error_or_warn_is_other() {
        assert_eq!(
            class_of(&error(
                "inbound/tun[0]: something this reader has never seen"
            )),
            Some((SingboxLogClass::Other, None))
        );
        // An unlisted dial error still names its node.
        assert_eq!(
            class_of(&error(
                "[1 0ms] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: dial tcp 1.2.3.4:443: connect: connection refused"
            )),
            Some((SingboxLogClass::Other, Some("vless-out-6".into())))
        );
        assert_eq!(
            class_of(&warn("sing-box is running as root")),
            Some((SingboxLogClass::Other, None))
        );
    }

    #[test]
    fn info_and_debug_lines_are_no_class() {
        assert_eq!(
            class_of(
                "+0300 2026-09-17 20:25:52 INFO network: updated default interface en0, index 11"
            ),
            None
        );
        assert_eq!(
            class_of(
                "+0300 2026-09-17 20:25:52 DEBUG [1 0ms] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: dial tcp 1.2.3.4:443: no route to internet"
            ),
            None
        );
    }
}
