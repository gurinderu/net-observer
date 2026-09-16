use types::{ConnectionRow, ConnectionsSample, ConnectionsVerdict, LiveConnection};

/// Pure, synchronous fold from the fetched flow list to a
/// [`ConnectionsSample`]. The collector `await`s the API, then this sync
/// `build_*` composes the sample — async lives only in the port.
///
/// `None` (the API did not answer) is a `SKIP` sample with no rows; `Some`
/// is an `OK` sample whose rows are the flows aggregated by their key
/// `(host, dst_ip, dst_port, process, network, chain)` — `count` flows per
/// key, their bytes summed — in the order each key was first listed. An
/// empty list is an `OK` sample with no rows: the API answered, and nothing
/// is talking.
pub fn build_connections_sample(
    ts_us: i64,
    connections: Option<Vec<LiveConnection>>,
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
        match rows.iter_mut().find(|r| same_key(r, &c)) {
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
fn same_key(r: &ConnectionRow, c: &LiveConnection) -> bool {
    r.host == c.host
        && r.dst_ip == c.dst_ip
        && r.dst_port == c.dst_port
        && r.process == c.process
        && r.network == c.network
        && r.chain == c.chain
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(host: Option<&str>, dst_ip: Option<&str>, port: u16, upload: u64) -> LiveConnection {
        LiveConnection {
            host: host.map(str::to_string),
            dst_ip: dst_ip.map(str::to_string),
            dst_port: Some(port),
            process: Some("stable".into()),
            network: "tcp".into(),
            chain: Some("vless-main".into()),
            upload,
            download: 2 * upload,
        }
    }

    #[test]
    fn no_answer_is_a_skip_with_no_rows() {
        let s = build_connections_sample(42, None);
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.verdict, ConnectionsVerdict::Skip);
        assert!(s.rows.is_empty());
    }

    /// An answered, empty list is the reading "nothing is talking" — `OK`,
    /// not a `SKIP` in disguise.
    #[test]
    fn an_empty_answer_is_ok_with_no_rows() {
        let s = build_connections_sample(42, Some(Vec::new()));
        assert_eq!(s.verdict, ConnectionsVerdict::Ok);
        assert!(s.rows.is_empty());
    }

    #[test]
    fn flows_sharing_a_key_fold_into_one_row_with_their_bytes_summed() {
        let s = build_connections_sample(
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
        let s = build_connections_sample(
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
        let s =
            build_connections_sample(42, Some(vec![flow(Some("claude.ai"), None, 443, 1), other]));
        assert_eq!(s.rows.len(), 2);
        assert_eq!(s.rows[1].chain.as_deref(), Some("vless-backup"));
    }
}
