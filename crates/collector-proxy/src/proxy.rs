use collector_core::PingOutcome;
use types::{ProxySample, TcpVerdict};

use crate::probes::{Dial, StallReading};

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
///
/// `dials` are the tick's dial readings (realm net-observer, node #62), one
/// per dialled node, selected node first. Each rides the row of the endpoint
/// its node dials through, so `tcp` beside it is the raw reachability of that
/// very listener. A dial with no free row of its own — its node names no
/// endpoint, that endpoint was not probed, or another dialled node already
/// took the row (nodes may share an endpoint) — lands on a **dial-only row**:
/// `server_ip` the endpoint it went through (`-` when unknown), `tcp = SKIP`,
/// no rtt, the tick's shared facts, and the dial. Such a row measures the
/// dial and nothing else; the endpoint's own verdict stays on its own row.
/// The row carrying the SELECTED node's dial is emitted last, because the
/// live snapshot keeps the newest row of a tick and the operator's `status`
/// line reads its dial from there.
pub fn build_proxy_samples(
    ts_us: i64,
    tun_code: Option<u16>,
    selector: Option<String>,
    stall: StallReading,
    probed: Vec<(String, PingOutcome)>,
    dials: Vec<Dial>,
) -> Vec<ProxySample> {
    let est_direct_alive = stall.direct.map(|c| c.alive);
    let est_direct_age_s = stall.direct.map(|c| c.age_s);
    let est_tun_alive = stall.tun.map(|c| c.alive);
    let est_tun_age_s = stall.tun.map(|c| c.age_s);
    // The tick's shared facts, on every row alike.
    let shared = ProxySample {
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
        dial_ip_ms: None,
        dial_name_ms: None,
        dial_target: None,
    };
    let mut rows: Vec<ProxySample> = probed
        .into_iter()
        .map(|(ip, o)| ProxySample {
            server_ip: ip,
            tcp: if o.reachable {
                TcpVerdict::Ok
            } else {
                TcpVerdict::Fail
            },
            rtt_ms: o.rtt_ms,
            ..shared.clone()
        })
        .collect();
    if rows.is_empty() {
        rows.push(shared.clone());
    }
    for dial in dials {
        let home = rows.iter().position(|r| {
            r.dial_target.is_none() && dial.endpoint.as_deref() == Some(r.server_ip.as_str())
        });
        let at = home.unwrap_or_else(|| {
            rows.push(ProxySample {
                server_ip: dial.endpoint.clone().unwrap_or_else(|| "-".into()),
                ..shared.clone()
            });
            rows.len() - 1
        });
        let row = &mut rows[at];
        row.dial_ip_ms = dial.ip.ms();
        row.dial_name_ms = dial.name.ms();
        row.dial_target = Some(dial.node);
    }
    // Stable: only the selected node's row moves, to the end.
    rows.sort_by_key(|r| r.dial_target.is_some() && r.dial_target == r.selector);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{DialOutcome, StreamCheck};
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
            Vec::new(),
        );
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.tcp == TcpVerdict::Ok
            && r.tun_code == Some(204)
            && r.selector.as_deref() == Some("node-a")));
        // No dial this tick: every dial field reads "not dialled".
        assert!(rows.iter().all(|r| r.dial_target.is_none()
            && r.dial_ip_ms.is_none()
            && r.dial_name_ms.is_none()));
    }

    fn ok(rtt: f64) -> PingOutcome {
        PingOutcome {
            reachable: true,
            rtt_ms: Some(rtt),
        }
    }

    fn dial(node: &str, endpoint: Option<&str>, ip: DialOutcome, name: DialOutcome) -> Dial {
        Dial {
            node: node.into(),
            endpoint: endpoint.map(str::to_string),
            ip,
            name,
        }
    }

    /// A dial rides the row of the endpoint its node dials through — so the
    /// raw TCP verdict beside it is that listener's — and the selected node's
    /// row is emitted last, whatever the probe order, so the live snapshot's
    /// newest row carries it. The rotating node's row keeps its place.
    #[test]
    fn a_dial_rides_its_endpoint_row_and_the_selected_one_lands_last() {
        let probed = vec![
            ("1.1.1.1:443".to_string(), ok(9.0)),
            ("2.2.2.2:2053".to_string(), ok(11.0)),
            ("3.3.3.3:443".to_string(), ok(12.0)),
        ];
        let dials = vec![
            dial(
                "node-a",
                Some("1.1.1.1:443"),
                DialOutcome::Ok(202),
                DialOutcome::NoAnswer,
            ),
            dial(
                "node-c",
                Some("3.3.3.3:443"),
                DialOutcome::Ok(350),
                DialOutcome::Ok(360),
            ),
        ];
        let rows = build_proxy_samples(
            7,
            Some(204),
            Some("node-a".into()),
            StallReading::default(),
            probed,
            dials,
        );
        assert_eq!(rows.len(), 3, "a dial with a row of its own adds none");
        let by_ip = |ip: &str| rows.iter().find(|r| r.server_ip == ip).unwrap();
        let a = by_ip("1.1.1.1:443");
        assert_eq!(a.dial_target.as_deref(), Some("node-a"));
        assert_eq!(a.dial_ip_ms, Some(202));
        assert_eq!(a.dial_name_ms, Some(0), "no answer is the record's 0");
        assert_eq!(a.tcp, TcpVerdict::Ok, "the endpoint's own verdict stays");
        assert_eq!(a.rtt_ms, Some(9.0));
        let c = by_ip("3.3.3.3:443");
        assert_eq!(c.dial_target.as_deref(), Some("node-c"));
        assert_eq!(c.dial_ip_ms, Some(350));
        assert_eq!(c.dial_name_ms, Some(360));
        assert!(by_ip("2.2.2.2:2053").dial_target.is_none());
        assert_eq!(
            rows.last().unwrap().server_ip,
            "1.1.1.1:443",
            "the selected node's row is the tick's newest"
        );
        assert_eq!(
            rows[0].server_ip, "2.2.2.2:2053",
            "the rest keep probe order"
        );
        assert_eq!(rows[1].server_ip, "3.3.3.3:443");
    }

    /// Two dialled nodes on one endpoint: the selected node (first in the
    /// list) takes the endpoint's row and the other lands on a dial-only row
    /// — `tcp = SKIP`, no rtt, the dial — so no endpoint verdict is ever
    /// written twice and no dial is lost. A node whose endpoint the config
    /// does not name lands the same way, with `server_ip = "-"`. The API's
    /// "cannot run this test" is `None` under the named target, never a `0`.
    #[test]
    fn a_dial_without_a_free_row_lands_on_a_dial_only_row() {
        let probed = vec![("1.1.1.1:443".to_string(), ok(9.0))];
        let dials = vec![
            dial(
                "node-a",
                Some("1.1.1.1:443"),
                DialOutcome::Ok(202),
                DialOutcome::Ok(210),
            ),
            dial(
                "node-b",
                Some("1.1.1.1:443"),
                DialOutcome::NoAnswer,
                DialOutcome::Unknown,
            ),
            dial("stray", None, DialOutcome::Ok(5), DialOutcome::Ok(6)),
        ];
        let rows = build_proxy_samples(
            7,
            Some(204),
            Some("node-a".into()),
            StallReading::default(),
            probed,
            dials,
        );
        assert_eq!(rows.len(), 3);
        let b = rows
            .iter()
            .find(|r| r.dial_target.as_deref() == Some("node-b"))
            .unwrap();
        assert_eq!(b.server_ip, "1.1.1.1:443");
        assert_eq!(
            b.tcp,
            TcpVerdict::Skip,
            "a dial-only row measures no endpoint"
        );
        assert_eq!(b.rtt_ms, None);
        assert_eq!(b.dial_ip_ms, Some(0));
        assert_eq!(
            b.dial_name_ms, None,
            "the API could not run it: no measurement"
        );
        assert_eq!(b.tun_code, Some(204), "the shared facts still ride it");
        let stray = rows
            .iter()
            .find(|r| r.dial_target.as_deref() == Some("stray"))
            .unwrap();
        assert_eq!(stray.server_ip, "-");
        assert_eq!(stray.tcp, TcpVerdict::Skip);
        assert_eq!(stray.dial_ip_ms, Some(5));
        let a = rows.last().unwrap();
        assert_eq!(a.dial_target.as_deref(), Some("node-a"));
        assert_eq!(
            a.tcp,
            TcpVerdict::Ok,
            "the endpoint's verdict is written once"
        );
        assert_eq!(
            rows.iter().filter(|r| r.tcp == TcpVerdict::Ok).count(),
            1,
            "the endpoint's verdict is written once"
        );
    }

    /// Nothing probed but a dial ran (the config was unreadable while the API
    /// answered): the SKIP placeholder still lands — it is what tells
    /// `endpoint-block` no endpoints were parsed — and the dial rides its own
    /// dial-only row beside it rather than the placeholder.
    #[test]
    fn the_skip_placeholder_survives_a_dial_with_nothing_probed() {
        let dials = vec![dial(
            "node-a",
            None,
            DialOutcome::Ok(202),
            DialOutcome::Ok(210),
        )];
        let rows = build_proxy_samples(
            7,
            Some(204),
            Some("node-a".into()),
            StallReading::default(),
            Vec::new(),
            dials,
        );
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().any(|r| r.server_ip == "-"
                && r.tcp == TcpVerdict::Skip
                && r.dial_target.is_none()),
            "the placeholder row is untouched"
        );
        let a = rows.last().unwrap();
        assert_eq!(a.dial_target.as_deref(), Some("node-a"));
        assert_eq!(a.server_ip, "-");
        assert_eq!(a.tcp, TcpVerdict::Skip);
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
        let rows = build_proxy_samples(7, Some(204), None, stall, probed, Vec::new());
        assert_eq!(rows[0].est_direct_alive, Some(true));
        assert_eq!(rows[0].est_direct_age_s, Some(120));
        assert_eq!(rows[0].est_tun_alive, Some(false));
        assert_eq!(rows[0].est_tun_age_s, Some(45));
    }

    #[test]
    fn skip_verdict_when_no_servers() {
        let rows = build_proxy_samples(
            7,
            None,
            None,
            StallReading::default(),
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tcp, TcpVerdict::Skip);
        // No measurement, not a dead stream: the skip row says None.
        assert_eq!(rows[0].est_tun_alive, None);
    }
}
