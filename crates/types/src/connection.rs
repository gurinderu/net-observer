//! What this machine talks to: the live flows sing-box carries, read from its
//! Clash API (`GET /connections`) and folded per tick into an aggregate table
//! (realm net-observer, nodes #75, #127).
//!
//! `netstat` cannot answer the question here — every destination it shows is a
//! fakeip — so the flow table comes from the proxy that resolves them: each flow
//! with the name the client asked for, the real destination, the process behind
//! it and the outbound it left through.

use serde::{Deserialize, Serialize};

use crate::verdict::ConnectionsVerdict;

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
    /// The outbound the flow actually left through — the LAST element of the
    /// API's `chains` (`["vless-out-6","vless-auto","vless-main"]` names the
    /// selector, the group and, last, the node: `vless-main`). `None` when the
    /// API listed no chain.
    pub chain: Option<String>,
    /// Bytes sent so far on this flow.
    pub upload: u64,
    /// Bytes received so far on this flow.
    pub download: u64,
}

/// One row of the per-tick aggregate: every live flow sharing the key
/// `(host, dst_ip, dst_port, process, network, chain)`, with how many there
/// were and their traffic summed.
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
/// (`host` / `ip` / `ip-port` / `process`); a sender that omits it means `host`.
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
        }
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
        ] {
            assert_eq!(serde_json::to_string(&v).unwrap(), s);
            assert_eq!(serde_json::from_str::<ConnectionsGroupBy>(s).unwrap(), v);
        }
        assert_eq!(ConnectionsGroupBy::default(), ConnectionsGroupBy::Host);
    }
}
