use collector_core::PingOutcome;
use types::{ProxySample, TcpVerdict};

use crate::probes::{StallReading, UrlTest};

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
/// `urltests` are the tick's readings of sing-box's own URL-test history
/// (realm net-observer, node #62), one per member of the selector group,
/// selected node first. Each rides the row of the endpoint its node tests
/// through, so `tcp` beside it is the raw reachability of that very
/// listener. A reading with no free row of its own — its node names no
/// endpoint, that endpoint was not probed (the passive tier probes none), or
/// another node already took the row (nodes may share an endpoint) — lands on
/// a **reading-only row**: `server_ip` the endpoint (`-` when unknown),
/// `tcp = SKIP`, no rtt, the tick's shared facts, and the reading. Such a
/// row measures no endpoint; the endpoint's own verdict stays on its own row.
/// The row carrying the SELECTED node's reading is emitted last, because the
/// live snapshot keeps the newest row of a tick and the operator's `status`
/// line reads its test from there.
pub fn build_proxy_samples(
    ts_us: i64,
    tun_code: Option<u16>,
    selector: Option<String>,
    stall: StallReading,
    probed: Vec<(String, PingOutcome)>,
    urltests: Vec<UrlTest>,
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
        urltest_ms: None,
        urltest_at_us: None,
        urltest_node: None,
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
    for test in urltests {
        let home = rows.iter().position(|r| {
            r.urltest_node.is_none() && test.endpoint.as_deref() == Some(r.server_ip.as_str())
        });
        let at = home.unwrap_or_else(|| {
            rows.push(ProxySample {
                server_ip: test.endpoint.clone().unwrap_or_else(|| "-".into()),
                ..shared.clone()
            });
            rows.len() - 1
        });
        let row = &mut rows[at];
        row.urltest_ms = test.entry.map(|e| e.ms);
        row.urltest_at_us = test.entry.map(|e| e.at_us);
        row.urltest_node = Some(test.node);
    }
    // Stable: only the selected node's row moves, to the end.
    rows.sort_by_key(|r| r.urltest_node.is_some() && r.urltest_node == r.selector);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::{StreamCheck, UrlTestEntry};
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
        // No reading this tick: every urltest field reads "no reading".
        assert!(rows.iter().all(|r| r.urltest_node.is_none()
            && r.urltest_ms.is_none()
            && r.urltest_at_us.is_none()));
    }

    fn ok(rtt: f64) -> PingOutcome {
        PingOutcome {
            reachable: true,
            rtt_ms: Some(rtt),
        }
    }

    fn test(node: &str, endpoint: Option<&str>, entry: Option<(i64, u32)>) -> UrlTest {
        UrlTest {
            node: node.into(),
            endpoint: endpoint.map(str::to_string),
            entry: entry.map(|(at_us, ms)| UrlTestEntry { at_us, ms }),
        }
    }

    /// A reading rides the row of the endpoint its node tests through — so
    /// the raw TCP verdict beside it is that listener's — and the selected
    /// node's row is emitted last, whatever the probe order, so the live
    /// snapshot's newest row carries it. The other rows keep their place.
    #[test]
    fn a_reading_rides_its_endpoint_row_and_the_selected_one_lands_last() {
        let probed = vec![
            ("1.1.1.1:443".to_string(), ok(9.0)),
            ("2.2.2.2:2053".to_string(), ok(11.0)),
            ("3.3.3.3:443".to_string(), ok(12.0)),
        ];
        let urltests = vec![
            test("node-a", Some("1.1.1.1:443"), Some((1_000, 202))),
            test("node-c", Some("3.3.3.3:443"), Some((900, 0))),
            test("node-b", Some("2.2.2.2:2053"), None),
        ];
        let rows = build_proxy_samples(
            7,
            Some(204),
            Some("node-a".into()),
            StallReading::default(),
            probed,
            urltests,
        );
        assert_eq!(rows.len(), 3, "a reading with a row of its own adds none");
        let by_ip = |ip: &str| rows.iter().find(|r| r.server_ip == ip).unwrap();
        let a = by_ip("1.1.1.1:443");
        assert_eq!(a.urltest_node.as_deref(), Some("node-a"));
        assert_eq!(a.urltest_ms, Some(202));
        assert_eq!(a.urltest_at_us, Some(1_000));
        assert_eq!(a.tcp, TcpVerdict::Ok, "the endpoint's own verdict stays");
        assert_eq!(a.rtt_ms, Some(9.0));
        let c = by_ip("3.3.3.3:443");
        assert_eq!(c.urltest_node.as_deref(), Some("node-c"));
        assert_eq!(
            c.urltest_ms,
            Some(0),
            "sing-box's failed test is the record's 0"
        );
        assert_eq!(c.urltest_at_us, Some(900));
        let b = by_ip("2.2.2.2:2053");
        assert_eq!(b.urltest_node.as_deref(), Some("node-b"));
        assert_eq!(b.urltest_ms, None, "not tested yet: no measurement");
        assert_eq!(b.urltest_at_us, None);
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

    /// Two nodes on one endpoint: the selected node (first in the list)
    /// takes the endpoint's row and the other lands on a reading-only row —
    /// `tcp = SKIP`, no rtt, the reading — so no endpoint verdict is ever
    /// written twice and no reading is lost. A node whose endpoint the
    /// config does not name lands the same way, with `server_ip = "-"`.
    #[test]
    fn a_reading_without_a_free_row_lands_on_a_reading_only_row() {
        let probed = vec![("1.1.1.1:443".to_string(), ok(9.0))];
        let urltests = vec![
            test("node-a", Some("1.1.1.1:443"), Some((1_000, 202))),
            test("node-b", Some("1.1.1.1:443"), Some((950, 0))),
            test("stray", None, Some((900, 5))),
        ];
        let rows = build_proxy_samples(
            7,
            Some(204),
            Some("node-a".into()),
            StallReading::default(),
            probed,
            urltests,
        );
        assert_eq!(rows.len(), 3);
        let b = rows
            .iter()
            .find(|r| r.urltest_node.as_deref() == Some("node-b"))
            .unwrap();
        assert_eq!(b.server_ip, "1.1.1.1:443");
        assert_eq!(
            b.tcp,
            TcpVerdict::Skip,
            "a reading-only row measures no endpoint"
        );
        assert_eq!(b.rtt_ms, None);
        assert_eq!(b.urltest_ms, Some(0));
        assert_eq!(b.urltest_at_us, Some(950));
        assert_eq!(b.tun_code, Some(204), "the shared facts still ride it");
        let stray = rows
            .iter()
            .find(|r| r.urltest_node.as_deref() == Some("stray"))
            .unwrap();
        assert_eq!(stray.server_ip, "-");
        assert_eq!(stray.tcp, TcpVerdict::Skip);
        assert_eq!(stray.urltest_ms, Some(5));
        let a = rows.last().unwrap();
        assert_eq!(a.urltest_node.as_deref(), Some("node-a"));
        assert_eq!(a.tcp, TcpVerdict::Ok);
        assert_eq!(
            rows.iter().filter(|r| r.tcp == TcpVerdict::Ok).count(),
            1,
            "the endpoint's verdict is written once"
        );
    }

    /// Nothing probed (the passive tier, or the config unreadable) while
    /// sing-box's history was read: the SKIP placeholder still lands — it is
    /// what tells `endpoint-block` no endpoints were probed — and each
    /// reading rides its own reading-only row beside it, never the
    /// placeholder. So the passive tier still records sing-box's own tests.
    #[test]
    fn the_skip_placeholder_survives_readings_with_nothing_probed() {
        let urltests = vec![
            test("node-a", Some("1.1.1.1:443"), Some((1_000, 202))),
            test("node-b", None, None),
        ];
        let rows = build_proxy_samples(
            7,
            None,
            Some("node-a".into()),
            StallReading::default(),
            Vec::new(),
            urltests,
        );
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter().any(|r| r.server_ip == "-"
                && r.tcp == TcpVerdict::Skip
                && r.urltest_node.is_none()),
            "the placeholder row is untouched"
        );
        let a = rows.last().unwrap();
        assert_eq!(a.urltest_node.as_deref(), Some("node-a"));
        assert_eq!(a.server_ip, "1.1.1.1:443", "the endpoint is still named");
        assert_eq!(a.tcp, TcpVerdict::Skip, "but was not probed");
        assert_eq!(a.urltest_ms, Some(202));
        let b = rows
            .iter()
            .find(|r| r.urltest_node.as_deref() == Some("node-b"))
            .unwrap();
        assert_eq!(b.server_ip, "-");
        assert_eq!(b.urltest_ms, None);
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
