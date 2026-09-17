//! sing-box's own log, read passively: the ERROR/WARN lines it writes, each
//! folded into a class the record can count (realm net-observer, nodes #140,
//! #141).
//!
//! Under the passive tier the daemon records `SKIP` for the proxy and cannot
//! say why the network died through sing-box. sing-box's log is the one place
//! its dial failures and its "missing default interface" are written, and it is
//! world-readable — so the `singbox-log` collector tails it and writes one row
//! per `(class, node)` seen in a tick. A tick with no ERROR/WARN line writes
//! nothing: the absence of errors is the healthy state, and the tick itself is
//! evidenced by the other collectors.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::verdict::ParseVerdictError;

/// One class of ERROR/WARN line in sing-box's log — its observed vocabulary
/// (sing-box 1.13.19, realm net-observer, node #140), plus [`Self::Other`] for
/// a line at those levels the classifier does not name and
/// [`Self::Unreadable`] for a tick on which the log itself could not be read.
///
/// Serialised in kebab-case, the same token [`fmt::Display`] prints and the
/// `singbox_log_sample.class` column holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SingboxLogClass {
    /// `dial tcp …: no route to internet` on an outbound dial.
    NoRoute,
    /// `dial tcp …: connect: network is unreachable` on an outbound dial.
    Unreachable,
    /// `dial tcp …: i/o timeout` on an outbound dial.
    DialTimeout,
    /// `context canceled` / `operation was canceled` on an outbound dial.
    Canceled,
    /// `network: missing default interface`, or the local DNS resolver's
    /// `dhcp: prepare interface: missing default interface`.
    NoDefaultIface,
    /// The local resolver could not fetch or update its servers (`context
    /// deadline exceeded`, `bind: address already in use`).
    DnsServersFailed,
    /// A DNS exchange failed (`dns: exchange failed for …`, or the router's
    /// `process DNS packet: dial UDP connection: …`).
    DnsExchangeFailed,
    /// `router: process DNS packet: unpack request: …`.
    DnsBadPacket,
    /// `outbound/direct: receive ICMP echo reply: … i/o timeout`.
    IcmpReplyTimeout,
    /// `connection: connection download closed: http2: …`.
    StreamClosed,
    /// WARN `inbound/tun: … icmp is not supported by default outbound`.
    IcmpUnsupported,
    /// Any other ERROR/WARN line; the sample carries its message.
    Other,
    /// Not a log class: the reader could not open or read the log this tick.
    /// Written with `count: 0` and the I/O error as the sample message, one
    /// row per tick while it lasts — SKIP's spirit, never silence.
    Unreadable,
}

impl SingboxLogClass {
    /// Every class, in declaration order.
    pub const ALL: [SingboxLogClass; 13] = [
        Self::NoRoute,
        Self::Unreachable,
        Self::DialTimeout,
        Self::Canceled,
        Self::NoDefaultIface,
        Self::DnsServersFailed,
        Self::DnsExchangeFailed,
        Self::DnsBadPacket,
        Self::IcmpReplyTimeout,
        Self::StreamClosed,
        Self::IcmpUnsupported,
        Self::Other,
        Self::Unreadable,
    ];

    /// The kebab-case token: the wire spelling and the DuckDB column value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRoute => "no-route",
            Self::Unreachable => "unreachable",
            Self::DialTimeout => "dial-timeout",
            Self::Canceled => "canceled",
            Self::NoDefaultIface => "no-default-iface",
            Self::DnsServersFailed => "dns-servers-failed",
            Self::DnsExchangeFailed => "dns-exchange-failed",
            Self::DnsBadPacket => "dns-bad-packet",
            Self::IcmpReplyTimeout => "icmp-reply-timeout",
            Self::StreamClosed => "stream-closed",
            Self::IcmpUnsupported => "icmp-unsupported",
            Self::Other => "other",
            Self::Unreadable => "unreadable",
        }
    }
}

impl fmt::Display for SingboxLogClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SingboxLogClass {
    type Err = ParseVerdictError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| ParseVerdictError(s.to_string()))
    }
}

/// One `(class, node)` of sing-box's ERROR/WARN lines in one tick of the
/// `singbox-log` collector (realm net-observer, node #141).
///
/// `count` is how many lines of the class (via `node`, when the class names
/// one) the tick saw; `sample_message` is the first of them, ANSI stripped and
/// bounded in length, so a class is never a bare label. An
/// [`SingboxLogClass::Unreadable`] row carries `count: 0` and the I/O error.
///
/// `serde(default)` on the optional fields so a row written without them
/// still decodes on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SingboxLogSample {
    /// The tick's timestamp (epoch microseconds), not the log line's own.
    pub ts_us: i64,
    pub class: SingboxLogClass,
    pub count: u32,
    /// The outbound node the line names (`using outbound/vless[<node>]`),
    /// when it names one.
    #[serde(default)]
    pub node: Option<String>,
    /// The first message of the class in this tick, ANSI stripped, truncated;
    /// for `Unreadable`, the I/O error.
    #[serde(default)]
    pub sample_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The class travels as one kebab-case token in every form: serde, Display
    /// and the reverse parse the store reads the column back with.
    #[test]
    fn class_token_round_trips_in_every_form() {
        for class in SingboxLogClass::ALL {
            let token = class.as_str();
            assert_eq!(class.to_string(), token);
            assert_eq!(SingboxLogClass::from_str(token).unwrap(), class);
            let json = serde_json::to_string(&class).unwrap();
            assert_eq!(json, format!("\"{token}\""), "{class:?}");
            assert_eq!(serde_json::from_str::<SingboxLogClass>(&json).unwrap(), class);
        }
        assert_eq!(SingboxLogClass::NoRoute.as_str(), "no-route");
        assert_eq!(SingboxLogClass::NoDefaultIface.as_str(), "no-default-iface");
        assert!(SingboxLogClass::from_str("NoRoute").is_err());
        assert!(SingboxLogClass::from_str("").is_err());
    }

    #[test]
    fn sample_round_trips_with_and_without_its_optional_fields() {
        let full = SingboxLogSample {
            ts_us: 42,
            class: SingboxLogClass::DialTimeout,
            count: 3,
            node: Some("vless-out-6".into()),
            sample_message: Some("dial tcp 1.2.3.4:443: i/o timeout".into()),
        };
        let json = serde_json::to_string(&full).unwrap();
        assert!(json.contains("\"class\":\"dial-timeout\""), "{json}");
        assert_eq!(serde_json::from_str::<SingboxLogSample>(&json).unwrap(), full);

        // A row without the optional fields still decodes: absent is `None`.
        let bare = r#"{"ts_us":7,"class":"unreadable","count":0}"#;
        assert_eq!(
            serde_json::from_str::<SingboxLogSample>(bare).unwrap(),
            SingboxLogSample {
                ts_us: 7,
                class: SingboxLogClass::Unreadable,
                count: 0,
                node: None,
                sample_message: None,
            }
        );
    }
}
