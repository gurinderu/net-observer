//! The "network without us" half of an experiment report (realm
//! net-observer, node #61): what the record says the network did inside the
//! window, counted from the rows the passive collectors kept writing while
//! the daemon's own probes were withheld.
//!
//! Every count is a bounded `WHERE ts_us BETWEEN ? AND ?` over one table —
//! no `ASOF JOIN`, no whole-record sort — and the two flow-table readings
//! are "the newest tick at or before" each bound. The values are bound, never
//! interpolated, like every builder in [`crate::diagnosis`]; the daemon runs
//! them on its blocking pool under the same deadline it gives a diagnosis.

use std::time::Duration;

use duckdb::types::Value;
use types::{
    FlowTotals, NetworkFacts, ObservingCause, ObservingEdge, ProbingEdge, ProbingReason,
    WindowEdges,
};

use crate::diagnosis::PreparedSql;
use crate::{QueryTable, Store, StoreError};

/// The boundary rows inside `[start_us, end_us]`, both ends inclusive: every
/// `observing_edge` (a pause or resume) and every `probing_edge` (the
/// window's own opening edge at `start_us` among them — the reader filters
/// by reason). The window's end task reads these BEFORE its closing edge, to
/// decide whether the tier is still its own to restore, and the report names
/// each so a zero read against a paused stretch is not read as an unbroken
/// window (realm net-observer, node #61).
pub fn window_edges(
    store: &dyn Store,
    start_us: i64,
    end_us: i64,
    budget: Duration,
) -> Result<WindowEdges, StoreError> {
    let between = || vec![Value::BigInt(start_us), Value::BigInt(end_us)];
    let observing = store.query_prepared_within(
        &PreparedSql::bound(
            "SELECT ts_us, observing, peer_uid, cause FROM observing_edge
             WHERE ts_us BETWEEN ? AND ? ORDER BY ts_us",
            between(),
        ),
        budget,
    )?;
    let probing = store.query_prepared_within(
        &PreparedSql::bound(
            "SELECT ts_us, tier, peer_uid, reason FROM probing_edge
             WHERE ts_us BETWEEN ? AND ? ORDER BY ts_us",
            between(),
        ),
        budget,
    )?;
    // The state in force at the start: a pause that landed just before the
    // opening edge is a row the bounded list above cannot see.
    let at_start = store.query_prepared_within(
        &PreparedSql::bound(
            "SELECT observing FROM observing_edge WHERE ts_us <= ?
             ORDER BY ts_us DESC LIMIT 1",
            vec![Value::BigInt(start_us)],
        ),
        budget,
    )?;
    Ok(WindowEdges {
        observing_at_start: at_start.rows.first().map(|r| cell(r, 0) == "true"),
        observing: observing
            .rows
            .iter()
            .map(|r| {
                Ok(ObservingEdge {
                    ts_us: parse_i64(cell(r, 0), 0)?,
                    observing: cell(r, 1) == "true",
                    peer_uid: parse_opt_u32(cell(r, 2), 2)?,
                    // A NULL cause is a row from before the column: an
                    // operator's toggle, as the gap derivation reads it.
                    cause: parse_token_or(cell(r, 3), ObservingCause::Control, 3)?,
                })
            })
            .collect::<Result<_, StoreError>>()?,
        probing: probing
            .rows
            .iter()
            .map(|r| {
                Ok(ProbingEdge {
                    ts_us: parse_i64(cell(r, 0), 0)?,
                    tier: parse_token(cell(r, 1), 1)?,
                    peer_uid: parse_opt_u32(cell(r, 2), 2)?,
                    // A NULL reason is a row from before the column: control.
                    reason: parse_token_or(cell(r, 3), ProbingReason::Control, 3)?,
                })
            })
            .collect::<Result<_, StoreError>>()?,
    })
}

/// A token column as its enum, the driver's own conversion failure when the
/// text is not a token this build knows.
fn parse_token<T>(text: &str, col: usize) -> Result<T, StoreError>
where
    T: std::str::FromStr<Err = types::ParseVerdictError>,
{
    text.parse::<T>().map_err(|e| {
        StoreError::Duckdb(duckdb::Error::FromSqlConversionFailure(
            col,
            duckdb::types::Type::Text,
            Box::new(e),
        ))
    })
}

/// [`parse_token`] with an empty cell (SQL `NULL`) reading as `absent`.
fn parse_token_or<T>(text: &str, absent: T, col: usize) -> Result<T, StoreError>
where
    T: std::str::FromStr<Err = types::ParseVerdictError>,
{
    if text.is_empty() {
        Ok(absent)
    } else {
        parse_token(text, col)
    }
}

fn parse_opt_u32(text: &str, col: usize) -> Result<Option<u32>, StoreError> {
    if text.is_empty() {
        return Ok(None);
    }
    text.parse::<u32>()
        .map(Some)
        .map_err(|e| conversion(col, e))
}

/// The newest flow-table tick at or before a moment, its rows summed. A
/// `SKIP` tick (the API did not answer) is one row with NULL counts, so the
/// sums are `0` and the verdict says why.
const FLOWS_AT_SQL: &str = "\
SELECT ts_us, max(verdict) AS verdict,
       coalesce(sum(count), 0) AS flows,
       coalesce(sum(upload), 0) AS upload,
       coalesce(sum(download), 0) AS download
FROM connection_sample
WHERE ts_us = (SELECT max(ts_us) FROM connection_sample WHERE ts_us <= ?)
GROUP BY ts_us";

/// Count what the record holds inside `[start_us, end_us]`.
///
/// Each statement runs within `budget` through
/// [`Store::query_prepared_within`]; the first failure is returned as is —
/// a half-counted window would read as a quieter network than the record
/// shows, so the caller reports the network as unread rather than partial.
pub fn window_facts(
    store: &dyn Store,
    start_us: i64,
    end_us: i64,
    budget: Duration,
) -> Result<NetworkFacts, StoreError> {
    let between = || vec![Value::BigInt(start_us), Value::BigInt(end_us)];
    let run = |sql: &str, params: Vec<Value>| {
        store.query_prepared_within(&PreparedSql::bound(sql, params), budget)
    };

    let route = run(
        "SELECT count(*) FROM route_event WHERE ts_us BETWEEN ? AND ?",
        between(),
    )?;
    let incidents = run(
        "SELECT id, trigger_id FROM incident
         WHERE opened_us BETWEEN ? AND ? ORDER BY opened_us, id",
        between(),
    )?;
    let gw = run(
        "SELECT gw, count(*) FROM link_sample
         WHERE ts_us BETWEEN ? AND ? GROUP BY gw ORDER BY gw",
        between(),
    )?;
    let announce = run(
        "SELECT count(*), coalesce(sum(heard_frames), 0) FROM neighbor_sample
         WHERE ts_us BETWEEN ? AND ? AND heard_frames IS NOT NULL",
        between(),
    )?;
    let flows_at_start = run(FLOWS_AT_SQL, vec![Value::BigInt(start_us)])?;
    let flows_at_end = run(FLOWS_AT_SQL, vec![Value::BigInt(end_us)])?;
    let rssi = run(
        "SELECT min(rssi_dbm), max(rssi_dbm) FROM wifi_sample WHERE ts_us BETWEEN ? AND ?",
        between(),
    )?;

    Ok(NetworkFacts {
        route_events: cell_u64(&route, 0, 0)?,
        incidents: incidents
            .rows
            .iter()
            .map(|r| (cell(r, 0).to_string(), cell(r, 1).to_string()))
            .collect(),
        gw_verdicts: gw
            .rows
            .iter()
            .map(|r| Ok((cell(r, 0).to_string(), parse_u64(cell(r, 1), 1)?)))
            .collect::<Result<_, StoreError>>()?,
        announce_flushes: cell_u64(&announce, 0, 0)?,
        announce_heard_frames: cell_u64(&announce, 0, 1)?,
        flows_at_start: flows(&flows_at_start)?,
        flows_at_end: flows(&flows_at_end)?,
        rssi_min_dbm: cell_opt_i64(&rssi, 0, 0)?,
        rssi_max_dbm: cell_opt_i64(&rssi, 0, 1)?,
    })
}

/// The one row [`FLOWS_AT_SQL`] yields, or `None` when no tick lies at or
/// before the moment.
fn flows(t: &QueryTable) -> Result<Option<FlowTotals>, StoreError> {
    let Some(r) = t.rows.first() else {
        return Ok(None);
    };
    Ok(Some(FlowTotals {
        ts_us: parse_i64(cell(r, 0), 0)?,
        verdict: cell(r, 1).to_string(),
        flows: parse_u64(cell(r, 2), 2)?,
        upload: parse_u64(cell(r, 3), 3)?,
        download: parse_u64(cell(r, 4), 4)?,
    }))
}

/// One cell of a row, the empty string (SQL `NULL`) when the row is short.
fn cell(row: &[String], col: usize) -> &str {
    row.get(col).map_or("", String::as_str)
}

fn cell_u64(t: &QueryTable, row: usize, col: usize) -> Result<u64, StoreError> {
    parse_u64(t.rows.get(row).map_or("", |r| cell(r, col)), col)
}

fn cell_opt_i64(t: &QueryTable, row: usize, col: usize) -> Result<Option<i64>, StoreError> {
    let text = t.rows.get(row).map_or("", |r| cell(r, col));
    if text.is_empty() {
        return Ok(None);
    }
    parse_i64(text, col).map(Some)
}

/// A count cell as a number. An empty cell is an aggregate over no rows
/// (`count(*)` never is, but `sum` can be) and reads as zero; a cell that is
/// not a number is the driver's own conversion failure, column named.
fn parse_u64(text: &str, col: usize) -> Result<u64, StoreError> {
    if text.is_empty() {
        return Ok(0);
    }
    text.parse::<u64>().map_err(|e| conversion(col, e))
}

fn parse_i64(text: &str, col: usize) -> Result<i64, StoreError> {
    text.parse::<i64>().map_err(|e| conversion(col, e))
}

fn conversion(col: usize, e: std::num::ParseIntError) -> StoreError {
    StoreError::Duckdb(duckdb::Error::FromSqlConversionFailure(
        col,
        duckdb::types::Type::Text,
        Box::new(e),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DuckdbStore;
    use types::{
        ConnectionRow, ConnectionsSample, ConnectionsVerdict, GwVerdict, HeardFrames, Incident,
        LinkSample, NeighborsSample, NeighborsVerdict, RouteEvent, Sample, TcpVerdict, WifiSample,
        WifiVerdict,
    };

    const BUDGET: Duration = Duration::from_secs(30);
    const START: i64 = 1_000_000;
    const END: i64 = 5_000_000;

    fn link(s: &DuckdbStore, ts_us: i64, gw: GwVerdict) {
        s.write_sample(&Sample::Link(LinkSample {
            ts_us,
            gw,
            gw_rtt_ms: None,
            direct: TcpVerdict::Skip,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        }))
        .unwrap();
    }

    fn route(s: &DuckdbStore, ts_us: i64) {
        s.write_sample(&Sample::Route(RouteEvent {
            ts_us,
            kind: "route".into(),
            iface: Some("en0".into()),
            detail: "default route changed".into(),
        }))
        .unwrap();
    }

    fn incident(s: &DuckdbStore, id: &str, trigger_id: &str, opened_us: i64) {
        s.open_incident(&Incident {
            id: id.into(),
            opened_us,
            closed_us: None,
            trigger_id: trigger_id.into(),
            signature: String::new(),
        })
        .unwrap();
    }

    fn wifi(s: &DuckdbStore, ts_us: i64, rssi_dbm: Option<i32>) {
        s.write_sample(&Sample::Wifi(WifiSample {
            ts_us,
            wifi: if rssi_dbm.is_some() {
                WifiVerdict::Ok
            } else {
                WifiVerdict::Skip
            },
            reason: rssi_dbm.is_none().then(|| "not associated".to_string()),
            rssi_dbm,
            noise_dbm: None,
            snr_db: None,
            tx_rate_mbps: None,
            phy_mode: None,
            channel: None,
            channel_width_mhz: None,
            channel_band: None,
        }))
        .unwrap();
    }

    fn flush(s: &DuckdbStore, ts_us: i64, heard: Option<u32>) {
        s.write_sample(&Sample::Neighbors(NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            neighbors: Vec::new(),
            services: Vec::new(),
            heard: heard.map(|total| HeardFrames {
                total,
                own: Some(0),
                dropped: 0,
            }),
        }))
        .unwrap();
    }

    fn connections(s: &DuckdbStore, ts_us: i64, counts: Option<&[(u32, u64, u64)]>) {
        s.write_sample(&Sample::Connections(ConnectionsSample {
            ts_us,
            verdict: if counts.is_some() {
                ConnectionsVerdict::Ok
            } else {
                ConnectionsVerdict::Skip
            },
            rows: counts
                .unwrap_or(&[])
                .iter()
                .map(|&(count, upload, download)| ConnectionRow {
                    host: Some("example.org".into()),
                    dst_ip: None,
                    dst_port: Some(443),
                    process: None,
                    network: "tcp".into(),
                    chain: None,
                    count,
                    upload,
                    download,
                })
                .collect(),
        }))
        .unwrap();
    }

    /// An empty record counts to nothing and names every absence as `None`
    /// — never a fabricated tick or signal.
    #[test]
    fn an_empty_record_counts_to_nothing() {
        let s = DuckdbStore::in_memory().unwrap();
        let f = window_facts(&s, START, END, BUDGET).unwrap();
        assert_eq!(f, NetworkFacts::default());
        assert_eq!(f.flows_at_start, None);
        assert_eq!(f.rssi_min_dbm, None);
    }

    /// Every count is bounded to the window on both ends, inclusive, and the
    /// rows outside it — before and after — are not in it.
    #[test]
    fn counts_are_bounded_to_the_window() {
        let s = DuckdbStore::in_memory().unwrap();
        for ts in [START - 1, START, 2_000_000, END, END + 1] {
            route(&s, ts);
            link(&s, ts, GwVerdict::Skip);
            wifi(&s, ts, Some(if ts == 2_000_000 { -80 } else { -50 }));
            flush(&s, ts, Some(7));
        }
        link(&s, 3_000_000, GwVerdict::Ok);
        flush(&s, 3_500_000, None); // a neighbour-cache tick, not a flush
        incident(&s, "gw-drop-a", "gw-drop", START - 1);
        incident(&s, "roam-b", "roam", 2_500_000);
        incident(&s, "gw-drop-c", "gw-drop", END);
        incident(&s, "wedge-d", "wedge", END + 1);
        wifi(&s, 2_200_000, None); // a SKIP row carries no rssi

        let f = window_facts(&s, START, END, BUDGET).unwrap();
        assert_eq!(f.route_events, 3);
        assert_eq!(
            f.incidents,
            vec![
                ("roam-b".to_string(), "roam".to_string()),
                ("gw-drop-c".to_string(), "gw-drop".to_string()),
            ]
        );
        assert_eq!(f.incidents_by("roam"), 1);
        assert_eq!(
            f.gw_verdicts,
            vec![("OK".to_string(), 1), ("SKIP".to_string(), 3)]
        );
        assert!(!f.gw_all_skip());
        assert_eq!(f.announce_flushes, 3);
        assert_eq!(f.announce_heard_frames, 21);
        assert_eq!(f.rssi_min_dbm, Some(-80));
        assert_eq!(f.rssi_max_dbm, Some(-50));
    }

    /// Under passive every gateway verdict is `SKIP`, and the facts say so
    /// outright.
    #[test]
    fn a_passive_window_is_all_skip() {
        let s = DuckdbStore::in_memory().unwrap();
        for ts in [START, 2_000_000, 3_000_000] {
            link(&s, ts, GwVerdict::Skip);
        }
        let f = window_facts(&s, START, END, BUDGET).unwrap();
        assert_eq!(f.gw_verdicts, vec![("SKIP".to_string(), 3)]);
        assert!(f.gw_all_skip());
    }

    /// The boundary rows inside the window come back as the edges they
    /// were written as — the window's own opening edge included, an
    /// operator's switch and a pause with their instants — and rows from
    /// outside the bounds stay outside.
    #[test]
    fn window_edges_read_back_the_rows_inside_the_bounds() {
        use types::{ObservingCause, ObservingEdge, ProbingEdge, ProbingReason, ProbingTier};
        let s = DuckdbStore::in_memory().unwrap();
        let probing = |ts_us, tier, reason| ProbingEdge {
            ts_us,
            tier,
            peer_uid: Some(501),
            reason,
        };
        let observing = |ts_us, observing| ObservingEdge {
            ts_us,
            observing,
            peer_uid: Some(501),
            cause: ObservingCause::Control,
        };
        s.write_probing_edge(&probing(
            START - 1,
            ProbingTier::Active,
            ProbingReason::Control,
        ))
        .unwrap();
        s.write_probing_edge(&probing(
            START,
            ProbingTier::Passive,
            ProbingReason::Experiment,
        ))
        .unwrap();
        s.write_probing_edge(&probing(
            2_000_000,
            ProbingTier::Active,
            ProbingReason::Control,
        ))
        .unwrap();
        s.write_probing_edge(&probing(
            END + 1,
            ProbingTier::Passive,
            ProbingReason::Control,
        ))
        .unwrap();
        s.write_observing_edge(&observing(START - 1, false))
            .unwrap();
        s.write_observing_edge(&observing(3_000_000, false))
            .unwrap();
        s.write_observing_edge(&observing(END, true)).unwrap();

        let e = window_edges(&s, START, END, BUDGET).unwrap();
        assert_eq!(
            e.probing,
            vec![
                probing(START, ProbingTier::Passive, ProbingReason::Experiment),
                probing(2_000_000, ProbingTier::Active, ProbingReason::Control),
            ]
        );
        assert_eq!(
            e.observing,
            vec![observing(3_000_000, false), observing(END, true)]
        );
        assert_eq!(e.pauses().count(), 1);
        assert_eq!(
            e.operator_probing().map(|p| p.ts_us).collect::<Vec<_>>(),
            vec![2_000_000]
        );
        assert_eq!(
            window_edges(&s, END + 10, END + 20, BUDGET).unwrap(),
            WindowEdges {
                observing_at_start: Some(true),
                ..WindowEdges::default()
            },
            "the state at a later start is the resume at END"
        );
    }

    /// The state in force at the start is the newest `observing_edge` at or
    /// before `start_us`: a pause landing just before the opening edge is
    /// seen there and nowhere in the bounded list; a pause after the start
    /// is in the list, not the state at the start; and a record with no edge
    /// that early says so with `None`, never a fabricated state.
    #[test]
    fn observing_at_start_is_the_newest_edge_at_or_before_the_start() {
        use types::{ObservingCause, ObservingEdge};
        let s = DuckdbStore::in_memory().unwrap();
        let observing = |ts_us, observing| ObservingEdge {
            ts_us,
            observing,
            peer_uid: Some(501),
            cause: ObservingCause::Control,
        };
        assert_eq!(
            window_edges(&s, START, END, BUDGET)
                .unwrap()
                .observing_at_start,
            None,
            "no edge that early"
        );
        // A pause one microsecond before the start: seen as the state, not
        // as a row inside the window.
        s.write_observing_edge(&observing(START - 1, false))
            .unwrap();
        let e = window_edges(&s, START, END, BUDGET).unwrap();
        assert_eq!(e.observing_at_start, Some(false));
        assert!(e.observing.is_empty());
        assert_eq!(e.pauses().count(), 0);
        // A resume exactly at the start is at-or-before: the state is on.
        s.write_observing_edge(&observing(START, true)).unwrap();
        let e = window_edges(&s, START, END, BUDGET).unwrap();
        assert_eq!(e.observing_at_start, Some(true));
        assert_eq!(e.observing.len(), 1);
        // A pause after the start is inside the window, and does not move
        // the state at the start.
        s.write_observing_edge(&observing(START + 5, false))
            .unwrap();
        let e = window_edges(&s, START, END, BUDGET).unwrap();
        assert_eq!(e.observing_at_start, Some(true));
        assert_eq!(e.pauses().count(), 1);
    }

    /// The flow readings are the newest tick at or before each bound — a
    /// tick before the window serves the start, and a SKIP tick reads as
    /// SKIP with zero sums, never as zero flows.
    #[test]
    fn flows_are_the_newest_tick_at_or_before_each_bound() {
        let s = DuckdbStore::in_memory().unwrap();
        connections(&s, START - 10, Some(&[(3, 100, 200), (2, 10, 20)]));
        connections(&s, 2_000_000, None);
        connections(&s, END + 1, Some(&[(9, 9, 9)]));
        let f = window_facts(&s, START, END, BUDGET).unwrap();
        assert_eq!(
            f.flows_at_start,
            Some(FlowTotals {
                ts_us: START - 10,
                verdict: "OK".into(),
                flows: 5,
                upload: 110,
                download: 220,
            })
        );
        assert_eq!(
            f.flows_at_end,
            Some(FlowTotals {
                ts_us: 2_000_000,
                verdict: "SKIP".into(),
                flows: 0,
                upload: 0,
                download: 0,
            })
        );
    }
}
