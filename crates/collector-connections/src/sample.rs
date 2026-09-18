use types::{
    ConnectionRow, ConnectionScope, ConnectionsSample, ConnectionsVerdict, LiveConnection,
};

use crate::facts::OwnListeners;

/// Pure, synchronous fold from the fetched flow list to a
/// [`ConnectionsSample`]. The collector `await`s the API, then this sync
/// `build_*` composes the sample — async lives only in the port.
///
/// `None` (the API did not answer) is a `SKIP` sample with no rows; `Some`
/// is an `OK` sample whose rows are the flows aggregated by their key
/// `(host, dst_ip, dst_port, process, network, chain, scope)` — `count`
/// flows per key, their bytes summed — in the order each key was first
/// listed. An empty list is an `OK` sample with no rows: the API answered,
/// and nothing is talking.
///
/// Each row's `scope` is judged here, once, from its destination and
/// `listeners` — the one site that has the config facts — so every reader
/// folds the same classification (realm net-observer, node #75). The scope
/// is a function of `dst_ip`, which is already in the key, so it splits no
/// key.
pub fn build_connections_sample(
    ts_us: i64,
    connections: Option<Vec<LiveConnection>>,
    listeners: &OwnListeners,
) -> ConnectionsSample {
    let Some(connections) = connections else {
        return ConnectionsSample {
            ts_us,
            verdict: ConnectionsVerdict::Skip,
            rows: Vec::new(),
        };
    };
    let mut rows: Vec<ConnectionRow> = Vec::new();
    for c in connections {
        let scope = listeners.classify(c.dst_ip.as_deref());
        match rows.iter_mut().find(|r| same_key(r, &c, scope)) {
            Some(r) => {
                r.count = r.count.saturating_add(1);
                r.upload = r.upload.saturating_add(c.upload);
                r.download = r.download.saturating_add(c.download);
            }
            None => rows.push(ConnectionRow {
                host: c.host,
                dst_ip: c.dst_ip,
                dst_port: c.dst_port,
                process: c.process,
                network: c.network,
                chain: c.chain,
                count: 1,
                upload: c.upload,
                download: c.download,
                scope,
            }),
        }
    }
    ConnectionsSample {
        ts_us,
        verdict: ConnectionsVerdict::Ok,
        rows,
    }
}

/// Whether a flow belongs to an aggregate row: every key field equal.
fn same_key(r: &ConnectionRow, c: &LiveConnection, scope: ConnectionScope) -> bool {
    r.host == c.host
        && r.dst_ip == c.dst_ip
        && r.dst_port == c.dst_port
        && r.process == c.process
        && r.network == c.network
        && r.chain == c.chain
        && r.scope == scope
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The listeners the owner's config names (realm net-observer, node #75).
    fn listeners() -> OwnListeners {
        OwnListeners {
            tun_addr: Some("172.19.0.1".into()),
            dns_pin: Some("192.0.2.53".into()),
        }
    }

    /// The fold under the owner's listeners.
    fn fold(ts_us: i64, connections: Option<Vec<LiveConnection>>) -> ConnectionsSample {
        build_connections_sample(ts_us, connections, &listeners())
    }

    fn flow(host: Option<&str>, dst_ip: Option<&str>, port: u16, upload: u64) -> LiveConnection {
        LiveConnection {
            host: host.map(str::to_string),
            dst_ip: dst_ip.map(str::to_string),
            dst_port: Some(port),
            process: Some("stable".into()),
            network: "tcp".into(),
            chain: Some("vless-out-6".into()),
            upload,
            download: 2 * upload,
        }
    }

    #[test]
    fn no_answer_is_a_skip_with_no_rows() {
        let s = fold(42, None);
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.verdict, ConnectionsVerdict::Skip);
        assert!(s.rows.is_empty());
    }

    /// An answered, empty list is the reading "nothing is talking" — `OK`,
    /// not a `SKIP` in disguise.
    #[test]
    fn an_empty_answer_is_ok_with_no_rows() {
        let s = fold(42, Some(Vec::new()));
        assert_eq!(s.verdict, ConnectionsVerdict::Ok);
        assert!(s.rows.is_empty());
    }

    #[test]
    fn flows_sharing_a_key_fold_into_one_row_with_their_bytes_summed() {
        let s = fold(
            42,
            Some(vec![
                flow(Some("claude.ai"), None, 443, 10),
                flow(Some("claude.ai"), None, 443, 5),
                flow(Some("claude.ai"), None, 443, 1),
            ]),
        );
        assert_eq!(s.rows.len(), 1);
        let r = &s.rows[0];
        assert_eq!(r.host.as_deref(), Some("claude.ai"));
        assert_eq!(r.count, 3);
        assert_eq!(r.upload, 16);
        assert_eq!(r.download, 32);
        assert_eq!(s.flows(), 3);
    }

    /// Any key field differing is a different row: the same name on another
    /// port, the same address with and without a name.
    #[test]
    fn a_differing_key_field_is_a_separate_row_in_first_seen_order() {
        let s = fold(
            42,
            Some(vec![
                flow(Some("www.google.com"), Some("194.221.250.50"), 5222, 1),
                flow(Some("claude.ai"), None, 443, 1),
                flow(None, Some("194.221.250.50"), 5222, 1),
                flow(Some("claude.ai"), None, 80, 1),
                flow(Some("claude.ai"), None, 443, 1),
            ]),
        );
        // Each row as `host|dst_ip|port xcount`, absent facts spelled `-`.
        let keys: Vec<String> = s
            .rows
            .iter()
            .map(|r| {
                format!(
                    "{}|{}|{} x{}",
                    r.host.as_deref().unwrap_or("-"),
                    r.dst_ip.as_deref().unwrap_or("-"),
                    r.dst_port.map_or("-".to_string(), |p| p.to_string()),
                    r.count
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                "www.google.com|194.221.250.50|5222 x1",
                "claude.ai|-|443 x2",
                "-|194.221.250.50|5222 x1",
                "claude.ai|-|80 x1",
            ]
        );
        assert_eq!(s.hosts(), 2);
    }

    /// A flow on another outbound is another row: the chain is part of the
    /// key, because "which node carried it" is the question after a
    /// selector switch.
    #[test]
    fn the_outbound_chain_is_part_of_the_key() {
        let mut other = flow(Some("claude.ai"), None, 443, 1);
        other.chain = Some("vless-backup".into());
        let s = fold(42, Some(vec![flow(Some("claude.ai"), None, 443, 1), other]));
        assert_eq!(s.rows.len(), 2);
        assert_eq!(s.rows[1].chain.as_deref(), Some("vless-backup"));
    }

    /// Every row carries the scope of its destination, judged against the
    /// configured listeners: the TUN address and the DNS pin are `internal`
    /// (the 1023-of-1080 case), private space is `lan`, the world is
    /// `external` — and so is a flow to a name whose address the proxy
    /// never learned, which is the tunnel's own traffic.
    #[test]
    fn each_row_carries_the_scope_of_its_destination() {
        let s = fold(
            42,
            Some(vec![
                flow(None, Some("172.19.0.1"), 53, 1),
                flow(None, Some("192.0.2.53"), 53, 1),
                flow(Some("printer.local"), Some("192.168.1.20"), 631, 1),
                flow(None, Some("149.154.167.41"), 80, 1),
                flow(Some("claude.ai"), None, 443, 1),
            ]),
        );
        let scopes: Vec<ConnectionScope> = s.rows.iter().map(|r| r.scope).collect();
        assert_eq!(
            scopes,
            vec![
                ConnectionScope::Internal,
                ConnectionScope::Internal,
                ConnectionScope::Lan,
                ConnectionScope::External,
                ConnectionScope::External,
            ]
        );
    }

    /// The scope is a function of the destination, which is already in the
    /// key: flows sharing a key share a scope and fold into one row — 1023
    /// DNS flows to the TUN address are one row counting 1023, not 1023
    /// rows.
    #[test]
    fn the_scope_splits_no_key() {
        let dns: Vec<LiveConnection> = (0..1023)
            .map(|_| flow(None, Some("172.19.0.1"), 53, 1))
            .collect();
        let s = fold(42, Some(dns));
        assert_eq!(s.rows.len(), 1);
        assert_eq!(s.rows[0].count, 1023);
        assert_eq!(s.rows[0].scope, ConnectionScope::Internal);
    }

    /// Without the config's listeners the fold still judges, and honestly:
    /// the TUN address is private space and the pin is TEST-NET, so they
    /// read as `lan` and `external` — shown, never hidden.
    #[test]
    fn without_listeners_the_singbox_addresses_are_not_internal() {
        let s = build_connections_sample(
            42,
            Some(vec![
                flow(None, Some("172.19.0.1"), 53, 1),
                flow(None, Some("192.0.2.53"), 53, 1),
            ]),
            &OwnListeners::default(),
        );
        let scopes: Vec<ConnectionScope> = s.rows.iter().map(|r| r.scope).collect();
        assert_eq!(
            scopes,
            vec![ConnectionScope::Lan, ConnectionScope::External]
        );
    }
}
