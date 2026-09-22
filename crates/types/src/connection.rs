//! What this machine talks to: the live flows sing-box carries, read from its
//! Clash API (`GET /connections`) and folded per tick into an aggregate table
//! (realm net-observer, nodes #75, #127).
//!
//! `netstat` cannot answer the question here — every destination it shows is a
//! fakeip — so the flow table comes from the proxy that resolves them: each flow
//! with the name the client asked for, the real destination, the process behind
//! it and the outbound it left through.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::verdict::ConnectionsVerdict;

/// Where a flow's destination lies, judged once at collection from its
/// address and carried on the row so every reader folds the same way (realm
/// net-observer, node #75).
///
/// Measured on the owner's Mac: ~1080 flows in a tick, of which 1023 were
/// keyed by the TUN address — every app's DNS query to sing-box's own
/// `dns-in` listener is a flow — and ~60 were the traffic the operator meant
/// by "connections". The readers show `external` by default and fold the rest
/// into one line, so the count on screen is the count that was asked for.
///
/// Serialised as lowercase tokens (`internal` / `lan` / `external`), which is
/// also what the `connection_sample.scope` column holds. `Default` is
/// `External`: a row from a sender or a record that predates the scope might
/// be real traffic, and hiding it would be the silent wrong datum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionScope {
    /// The destination never leaves the machine, or only reaches sing-box's
    /// own listeners: the TUN inbound's address, the `dns-in` listener,
    /// loopback, link-local.
    Internal,
    /// A private address (RFC 1918 / ULA) that is not one of the listeners
    /// above — the segment, not the world.
    Lan,
    /// Everything else — including a flow whose address the proxy never
    /// learned (a name resolved on the far side of the tunnel: the bulk of
    /// the real traffic) and a destination that could not be parsed: it
    /// might be real traffic, and the honest default is to show it.
    #[default]
    External,
}

impl ConnectionScope {
    /// The three scopes in the order the readers fold them: the plumbing
    /// first, then the segment, then the world.
    pub const ALL: [ConnectionScope; 3] = [
        ConnectionScope::Internal,
        ConnectionScope::Lan,
        ConnectionScope::External,
    ];

    /// The token the scope travels as — the same one serde writes and the
    /// column holds.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionScope::Internal => "internal",
            ConnectionScope::Lan => "lan",
            ConnectionScope::External => "external",
        }
    }
}

impl fmt::Display for ConnectionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A scope token that names none of the three.
#[derive(Debug, thiserror::Error)]
#[error("unknown connection scope: {0} (expected internal, lan or external)")]
pub struct ParseScopeError(pub String);

impl FromStr for ConnectionScope {
    type Err = ParseScopeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ConnectionScope::ALL
            .into_iter()
            .find(|scope| scope.as_str() == s)
            .ok_or_else(|| ParseScopeError(s.to_string()))
    }
}

/// Judge one flow's scope from its destination address and sing-box's own
/// two listeners, read from its rendered config: `tun_addr` is the TUN
/// inbound's address (`172.19.0.1`), `dns_pin` the `dns-in` listener
/// (`192.0.2.53`). Neither is hardcoded: the TUN address is RFC 1918 and the
/// pin is TEST-NET, so without them the one reads as `lan` and the other as
/// `external` — the collector passes what the config says, and a config it
/// could not read passes `None` for both.
///
/// Pure. An absent or empty destination is `external`, not `internal`: on
/// the owner's Mac the Clash API lists a flow to `claude.ai` through the
/// tunnel with `"destinationIP": ""` — the proxy resolves the name on the
/// far side and never learns an address here (the fixture in
/// `macos::clash`, realm net-observer, node #127) — so an empty destination
/// is the very traffic the reader asked for, and hiding it would be the
/// silent wrong datum. An address that does not parse is `external` for the
/// same reason: it might be real traffic.
#[must_use]
pub fn classify_scope(
    dst_ip: Option<&str>,
    tun_addr: Option<&str>,
    dns_pin: Option<&str>,
) -> ConnectionScope {
    let Ok(ip) = dst_ip.map_or("", str::trim).parse::<IpAddr>() else {
        return ConnectionScope::External;
    };
    // An IPv4-mapped v6 address (`::ffff:10.0.0.1`) is judged as its v4.
    let ip = ip.to_canonical();
    let is_listener = |own: Option<&str>| {
        own.and_then(|a| a.trim().parse::<IpAddr>().ok())
            .is_some_and(|a| a.to_canonical() == ip)
    };
    if is_listener(tun_addr) || is_listener(dns_pin) || ip.is_loopback() || is_link_local(ip) {
        return ConnectionScope::Internal;
    }
    if is_private(ip) {
        ConnectionScope::Lan
    } else {
        ConnectionScope::External
    }
}

/// `169.254/16` or `fe80::/10`.
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_unicast_link_local(),
    }
}

/// RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) or ULA (`fc00::/7`).
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// One live flow as the proxy's API reports it. Empty API strings are `None`
/// here: an absent fact is not an empty name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveConnection {
    /// The name the client asked for (the sniffed SNI, or the name a fakeip
    /// answer stood for). `None` for a flow opened to a bare address. Not
    /// authoritative: an SNI is whatever the client put there (`www.google.com`
    /// on a Telegram flow has been observed).
    pub host: Option<String>,
    /// The real destination address. `None` when the proxy resolves the name
    /// itself on the far side and never learns an address here.
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    /// The client process — the last path component of the API's
    /// `processPath`, its ` (user)` suffix stripped: `Telegram`, `stable`.
    /// `None` when the proxy could not attribute the flow.
    pub process: Option<String>,
    /// `tcp` | `udp`.
    pub network: String,
    /// The outbound that actually carried the flow — the FIRST element of the
    /// Clash API's `chains`: sing-box lists them node-first, so
    /// `["vless-out-6","vless-auto","vless-main"]` is the node, its group and,
    /// last, the top-level selector (`vless-main` is the same on every flow).
    /// `None` when the API listed no chain.
    pub chain: Option<String>,
    /// Bytes sent so far on this flow.
    pub upload: u64,
    /// Bytes received so far on this flow.
    pub download: u64,
}

/// One row of the per-tick aggregate: every live flow sharing the key
/// `(host, dst_ip, dst_port, process, network, chain, scope)`, with how many
/// there were and their traffic summed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub host: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub process: Option<String>,
    pub network: String,
    pub chain: Option<String>,
    /// How many live flows share this key.
    pub count: u32,
    pub upload: u64,
    pub download: u64,
    /// Where `dst_ip` lies, judged by [`classify_scope`] at collection. A
    /// function of `dst_ip`, so it splits no key. `serde(default)` —
    /// `External` — so a row from a sender that predates the scope is shown,
    /// never hidden.
    #[serde(default)]
    pub scope: ConnectionScope,
    /// The egress interface this flow actually left through, derived from
    /// `chain` and sing-box's rendered config at collection (realm
    /// net-observer, node #75): the TUN interface name for a tunneled flow,
    /// the physical interface for a `direct`-typed outbound, and the literal
    /// `blocked` for a `block`-typed one. `None` means unknown — an old
    /// daemon's row, a config that could not be read, or a chain naming an
    /// outbound the config does not — never invented. `chain` is part of the
    /// row's key, so `iface` (a function of `chain` plus the config) is
    /// constant within a row and splits no key. `serde(default)` so an older
    /// sender's row still decodes.
    #[serde(default)]
    pub iface: Option<String>,
}

/// One tick of the `connections` collector.
///
/// `Skip` means the proxy's API did not answer (unreachable, a non-2xx status,
/// an undecodable body) — the daemon could not look, which is a different fact
/// from a tick that looked and found no flow (`Ok` with no rows). Both are
/// recorded as a row, never as silence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionsSample {
    pub ts_us: i64,
    pub verdict: ConnectionsVerdict,
    pub rows: Vec<ConnectionRow>,
}

impl ConnectionsSample {
    /// How many live flows the tick saw — the aggregate's counts summed.
    #[must_use]
    pub fn flows(&self) -> u32 {
        self.rows.iter().map(|r| r.count).sum()
    }

    /// How many distinct names the flows were opened to. A flow with no name
    /// (a bare address) counts no host.
    #[must_use]
    pub fn hosts(&self) -> u32 {
        let mut hosts: Vec<&str> = self.rows.iter().filter_map(|r| r.host.as_deref()).collect();
        hosts.sort_unstable();
        hosts.dedup();
        u32::try_from(hosts.len()).unwrap_or(u32::MAX)
    }
}

/// How the live connections table is grouped when read back — the one parameter
/// the `connections` diagnosis carries.
///
/// Lives here, not in `store`, for the reason [`HistoryWindow`](crate::HistoryWindow)
/// does: it travels. The CLI parses it from `--by`, `store::diagnosis` turns it
/// into SQL, and `net_observer_ipc::DiagnosticQuery::Connections` carries it to a
/// running daemon. Serialised as the same lowercase tokens the CLI accepts
/// (`host` / `ip` / `ip-port` / `process` / `process-host`); a sender that
/// omits it means `host`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionsGroupBy {
    /// By the name asked for (a bare-address flow falls back to its address).
    #[default]
    Host,
    /// By the real destination address (a flow whose address the proxy never
    /// learned falls back to its name).
    Ip,
    /// By destination address and port.
    IpPort,
    /// By the client process.
    Process,
    /// By the pair (client process, destination host) — the same host-key
    /// expression `Host` uses, but never folded across a process's other
    /// destinations: "who talks to where, and how much" (realm net-observer,
    /// node #168).
    ProcessHost,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: Option<&str>, count: u32) -> ConnectionRow {
        ConnectionRow {
            host: host.map(str::to_string),
            dst_ip: None,
            dst_port: Some(443),
            process: None,
            network: "tcp".into(),
            chain: None,
            count,
            upload: 0,
            download: 0,
            scope: ConnectionScope::External,
            iface: None,
        }
    }

    /// Loopback, link-local and the two config-derived listeners are
    /// `internal`; private space is `lan`; the world, a destination the
    /// proxy never learned (the tunnel's own traffic — `claude.ai` with
    /// `"destinationIP": ""` in the observed API body) and anything that
    /// does not parse are `external`.
    #[test]
    fn scope_is_judged_from_the_destination_and_the_configured_listeners() {
        let tun = Some("172.19.0.1");
        let pin = Some("192.0.2.53");
        let judge = |dst: &str| classify_scope(Some(dst), tun, pin);
        assert_eq!(judge("172.19.0.1"), ConnectionScope::Internal);
        assert_eq!(judge("192.0.2.53"), ConnectionScope::Internal);
        assert_eq!(judge("127.0.0.1"), ConnectionScope::Internal);
        assert_eq!(judge("::1"), ConnectionScope::Internal);
        assert_eq!(judge("169.254.1.1"), ConnectionScope::Internal);
        assert_eq!(judge("fe80::1"), ConnectionScope::Internal);
        assert_eq!(judge(""), ConnectionScope::External);
        assert_eq!(classify_scope(None, tun, pin), ConnectionScope::External);
        assert_eq!(judge("10.20.0.5"), ConnectionScope::Lan);
        assert_eq!(judge("172.31.255.1"), ConnectionScope::Lan);
        assert_eq!(judge("192.168.1.1"), ConnectionScope::Lan);
        assert_eq!(judge("fd00::1"), ConnectionScope::Lan);
        assert_eq!(judge("149.154.167.41"), ConnectionScope::External);
        assert_eq!(judge("2606:4700::1"), ConnectionScope::External);
        assert_eq!(judge("garbage"), ConnectionScope::External);
        assert_eq!(judge("172.32.0.1"), ConnectionScope::External);
        // An IPv4-mapped v6 address is judged as its v4.
        assert_eq!(judge("::ffff:192.168.1.1"), ConnectionScope::Lan);
        assert_eq!(judge("::ffff:172.19.0.1"), ConnectionScope::Internal);
    }

    /// Without the config-derived listeners the TUN address is private space
    /// and the DNS pin is TEST-NET: `lan` and `external`, not `internal` —
    /// the classification hardcodes neither.
    #[test]
    fn without_the_configured_listeners_their_addresses_are_not_internal() {
        assert_eq!(
            classify_scope(Some("172.19.0.1"), None, None),
            ConnectionScope::Lan
        );
        assert_eq!(
            classify_scope(Some("192.0.2.53"), None, None),
            ConnectionScope::External
        );
        // A listener the config spells in another form still matches.
        assert_eq!(
            classify_scope(Some("::ffff:192.0.2.53"), None, Some(" 192.0.2.53 ")),
            ConnectionScope::Internal
        );
        // A listener that is not an address matches nothing.
        assert_eq!(
            classify_scope(Some("172.19.0.1"), Some("not an address"), None),
            ConnectionScope::Lan
        );
    }

    /// The scope travels as its lowercase token, parses back from it, and a
    /// row written before the scope existed decodes as `external` — shown,
    /// never hidden.
    #[test]
    fn scope_serialises_as_lowercase_tokens_and_a_row_without_one_is_external() {
        for (scope, token) in [
            (ConnectionScope::Internal, "internal"),
            (ConnectionScope::Lan, "lan"),
            (ConnectionScope::External, "external"),
        ] {
            assert_eq!(
                serde_json::to_string(&scope).unwrap(),
                format!("\"{token}\"")
            );
            assert_eq!(
                serde_json::from_str::<ConnectionScope>(&format!("\"{token}\"")).unwrap(),
                scope
            );
            assert_eq!(scope.to_string(), token);
            assert_eq!(token.parse::<ConnectionScope>().unwrap(), scope);
        }
        assert!("Internal".parse::<ConnectionScope>().is_err());
        assert_eq!(ConnectionScope::default(), ConnectionScope::External);

        let older = r#"{"host":"claude.ai","dst_ip":null,"dst_port":443,"process":null,
            "network":"tcp","chain":null,"count":1,"upload":0,"download":0}"#;
        let row: ConnectionRow = serde_json::from_str(older).expect("must decode");
        assert_eq!(row.scope, ConnectionScope::External);
        let mut scoped = row.clone();
        scoped.scope = ConnectionScope::Internal;
        let wire = serde_json::to_string(&scoped).unwrap();
        assert!(wire.contains(r#""scope":"internal""#), "{wire}");
        assert_eq!(
            serde_json::from_str::<ConnectionRow>(&wire).unwrap(),
            scoped
        );
    }

    #[test]
    fn flows_sum_the_counts_and_hosts_count_distinct_names() {
        let s = ConnectionsSample {
            ts_us: 1,
            verdict: ConnectionsVerdict::Ok,
            rows: vec![
                row(Some("claude.ai"), 3),
                row(Some("claude.ai"), 1),
                row(Some("o540343.ingest.sentry.io"), 1),
                row(None, 2),
            ],
        };
        assert_eq!(s.flows(), 7);
        assert_eq!(s.hosts(), 2);
    }

    #[test]
    fn a_skip_has_no_flows_and_no_hosts() {
        let s = ConnectionsSample {
            ts_us: 1,
            verdict: ConnectionsVerdict::Skip,
            rows: Vec::new(),
        };
        assert_eq!(s.flows(), 0);
        assert_eq!(s.hosts(), 0);
    }

    /// The grouping travels as the CLI's own tokens, and an absent one is
    /// `host` — so a sender built before a grouping existed still asks a
    /// well-formed question.
    #[test]
    fn group_by_serialises_as_the_cli_tokens_and_defaults_to_host() {
        for (v, s) in [
            (ConnectionsGroupBy::Host, "\"host\""),
            (ConnectionsGroupBy::Ip, "\"ip\""),
            (ConnectionsGroupBy::IpPort, "\"ip-port\""),
            (ConnectionsGroupBy::Process, "\"process\""),
            (ConnectionsGroupBy::ProcessHost, "\"process-host\""),
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), s);
            assert_eq!(serde_json::from_str::<ConnectionsGroupBy>(s).unwrap(), v);
        }
        assert_eq!(ConnectionsGroupBy::default(), ConnectionsGroupBy::Host);
    }
}
