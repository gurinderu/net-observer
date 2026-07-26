use collector_core::PingOutcome;
use types::{ProxySample, TcpVerdict};

/// Pure mapping: one [`ProxySample`] per upstream server, with the shared
/// `tun_code`/`selector` attached to every row. Emits a single `SKIP` row when
/// no servers are configured (absence of a signal is itself diagnostic).
///
/// This is a SYNC assembly step: the async `collect` awaits the probes, then
/// hands the fetched values here. `probed` is the per-server `(ip, outcome)`
/// pairs already gathered from the [`TcpProber`](collector_core::TcpProber).
pub fn build_proxy_samples(
    ts_us: i64,
    tun_code: Option<u16>,
    selector: Option<String>,
    probed: Vec<(String, PingOutcome)>,
) -> Vec<ProxySample> {
    if probed.is_empty() {
        return vec![ProxySample {
            ts_us,
            server_ip: "-".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code,
            selector,
        }];
    }
    probed
        .into_iter()
        .map(|(ip, o)| ProxySample {
            ts_us,
            server_ip: ip,
            tcp: if o.reachable {
                TcpVerdict::Ok
            } else {
                TcpVerdict::Fail
            },
            rtt_ms: o.rtt_ms,
            tun_code,
            selector: selector.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::TcpVerdict;

    #[test]
    fn one_row_per_server_with_tun_and_selector() {
        let probed = vec![
            (
                "1.1.1.1".to_string(),
                PingOutcome {
                    reachable: true,
                    rtt_ms: Some(9.0),
                },
            ),
            (
                "2.2.2.2".to_string(),
                PingOutcome {
                    reachable: true,
                    rtt_ms: Some(9.0),
                },
            ),
        ];
        let rows = build_proxy_samples(7, Some(204), Some("node-a".into()), probed);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.tcp == TcpVerdict::Ok
            && r.tun_code == Some(204)
            && r.selector.as_deref() == Some("node-a")));
    }

    #[test]
    fn skip_verdict_when_no_servers() {
        let rows = build_proxy_samples(7, None, None, Vec::new());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tcp, TcpVerdict::Skip);
    }
}
