use collector_core::PingOutcome;
use types::{ProxySample, TcpVerdict};

use crate::probes::StallReading;

/// Pure mapping: one [`ProxySample`] per upstream endpoint (ip:port), with the
/// shared `tun_code`/`selector` and the established-stream reading attached to
/// every row. Emits a single `SKIP` row when no endpoints are configured
/// (absence of a signal is itself diagnostic).
///
/// This is a SYNC assembly step: the async `collect` awaits the probes, then
/// hands the fetched values here. `probed` is the per-endpoint
/// `(endpoint, outcome)` pairs already gathered from the
/// [`TcpProber`](collector_core::TcpProber); `stall` is the per-tick held
/// reference-stream reading, replicated across the rows exactly like
/// `tun_code` (`None` sides = no measurement).
pub fn build_proxy_samples(
    ts_us: i64,
    tun_code: Option<u16>,
    selector: Option<String>,
    stall: StallReading,
    probed: Vec<(String, PingOutcome)>,
) -> Vec<ProxySample> {
    let est_direct_alive = stall.direct.map(|c| c.alive);
    let est_direct_age_s = stall.direct.map(|c| c.age_s);
    let est_tun_alive = stall.tun.map(|c| c.alive);
    let est_tun_age_s = stall.tun.map(|c| c.age_s);
    if probed.is_empty() {
        return vec![ProxySample {
            ts_us,
            server_ip: "-".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code,
            selector,
            est_direct_alive,
            est_direct_age_s,
            est_tun_alive,
            est_tun_age_s,
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
            est_direct_alive,
            est_direct_age_s,
            est_tun_alive,
            est_tun_age_s,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::StreamCheck;
    use types::TcpVerdict;

    #[test]
    fn one_row_per_server_with_tun_and_selector() {
        let probed = vec![
            (
                "1.1.1.1:443".to_string(),
                PingOutcome {
                    reachable: true,
                    rtt_ms: Some(9.0),
                },
            ),
            (
                "2.2.2.2:2053".to_string(),
                PingOutcome {
                    reachable: true,
                    rtt_ms: Some(9.0),
                },
            ),
        ];
        let rows = build_proxy_samples(
            7,
            Some(204),
            Some("node-a".into()),
            StallReading::default(),
            probed,
        );
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.tcp == TcpVerdict::Ok
            && r.tun_code == Some(204)
            && r.selector.as_deref() == Some("node-a")));
    }

    /// The established-stream reading is a per-tick fact and rides every row,
    /// exactly like `tun_code` — the offline reader must find it on whichever
    /// row it lands on.
    #[test]
    fn the_stall_reading_rides_every_row() {
        let probed = vec![(
            "1.1.1.1:443".to_string(),
            PingOutcome {
                reachable: true,
                rtt_ms: Some(9.0),
            },
        )];
        let stall = StallReading {
            direct: Some(StreamCheck {
                alive: true,
                age_s: 120,
            }),
            tun: Some(StreamCheck {
                alive: false,
                age_s: 45,
            }),
        };
        let rows = build_proxy_samples(7, Some(204), None, stall, probed);
        assert_eq!(rows[0].est_direct_alive, Some(true));
        assert_eq!(rows[0].est_direct_age_s, Some(120));
        assert_eq!(rows[0].est_tun_alive, Some(false));
        assert_eq!(rows[0].est_tun_age_s, Some(45));
    }

    #[test]
    fn skip_verdict_when_no_servers() {
        let rows = build_proxy_samples(7, None, None, StallReading::default(), Vec::new());
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tcp, TcpVerdict::Skip);
        // No measurement, not a dead stream: the skip row says None.
        assert_eq!(rows[0].est_tun_alive, None);
    }
}
