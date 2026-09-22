//! The named diagnoses served over the socket: `store::diagnosis` reachable
//! while the daemon runs.
//!
//! The daemon holds DuckDB's per-process lock, so for as long as it is up no
//! other process can open the record — and the moment of an incident is exactly
//! when `why`, `incident-context`, `gateway-ramp` and the rest are wanted. This
//! module is the read-only bridge: one [`DiagnosticQuery`] in, the matching
//! `store::diagnosis` builder run through the daemon's own store handle, one
//! [`Table`] out. Reads carry no authority, so a query is in the same class as
//! `Status`/`Incidents` and passes no peer-credential gate. (realm net-observer,
//! node #58)
//!
//! DuckDB is synchronous, and a diagnosis is an `ASOF JOIN` across the whole
//! record: the caller (`api::handle_conn`) runs [`run_query`] on
//! `tokio::task::spawn_blocking`, never on the runtime. The store's connection
//! mutex is still held for the duration, so a long diagnosis delays the
//! pipeline's next write by that much — the price of a single connection.
//! What keeps a client from turning that into a stall is the caller's gate:
//! one diagnosis in flight at a time (`api::MAX_QUERIES_IN_FLIGHT`), a second
//! refused at once rather than queued. So the delay is bounded by the
//! record's size, never by how many queries someone sends.

use std::time::Duration;

use net_observer_ipc::{DiagnosticQuery, Table, experiment_table_from_json};
use store::diagnosis::{self, PreparedSql};
use store::{QueryTable, Store, StoreError};

/// Run one named diagnosis against `store`, read-only, within `budget`.
///
/// `load_threshold` is the daemon's own starvation load — the same number the
/// `starvation` trigger judges by — so a live reading of the record cannot
/// disagree with the incidents the daemon recorded from it. The other
/// thresholds a diagnosis needs (episode gap) are `diagnosis`'s defaults, the
/// ones the CLI's offline path uses.
///
/// `budget` is the server-side deadline: the statement is interrupted at it
/// (`Store::query_prepared_within`) and the error names the budget. Without it
/// a diagnosis a client had already given up on would keep the store mutex —
/// and every write behind it — for as long as the `ASOF JOIN` took.
///
/// `Err` carries the daemon's own words for the client to show: a key the
/// store could never have written (the builders refuse it rather than match
/// nothing), the deadline, or a DuckDB error. It never starts with
/// [`net_observer_ipc::UNDECODABLE_REQUEST_PREFIX`] — that spelling is
/// reserved for a request the daemon could not read at all, and the client's
/// fallback rule turns on the difference.
pub fn run_query(
    store: &dyn Store,
    q: DiagnosticQuery,
    load_threshold: f64,
    budget: Duration,
) -> Result<Table, String> {
    let bad = |e: &dyn std::fmt::Display| e.to_string();
    let statement = match q {
        DiagnosticQuery::Why { ts_us } => diagnosis::verdict_at_sql(ts_us, load_threshold),
        DiagnosticQuery::IncidentContext => diagnosis::incident_context_sql(load_threshold),
        DiagnosticQuery::WedgeVsStarvation => {
            diagnosis::wedge_vs_starvation_sql(load_threshold, diagnosis::DEFAULT_EPISODE_GAP_US)
        }
        DiagnosticQuery::GwDrops => PreparedSql::plain(diagnosis::GW_DROPS_SQL.to_string()),
        DiagnosticQuery::GatewayRamp {
            drop_ts_us,
            window_us,
        } => diagnosis::gateway_ramp_sql(drop_ts_us, window_us),
        DiagnosticQuery::Gaps => PreparedSql::plain(diagnosis::observation_gaps_sql()),
        DiagnosticQuery::Silences => PreparedSql::plain(diagnosis::silences_sql()),
        DiagnosticQuery::Neighbors { network } => {
            PreparedSql::plain(diagnosis::neighbors_sql(network.as_deref()).map_err(|e| bad(&e))?)
        }
        DiagnosticQuery::Vulns { network } => {
            PreparedSql::plain(diagnosis::vulns_sql(network.as_deref()).map_err(|e| bad(&e))?)
        }
        DiagnosticQuery::Segments => PreparedSql::plain(diagnosis::segments_sql()),
        DiagnosticQuery::History { network, window } => {
            PreparedSql::plain(diagnosis::history_sql(&network, window).map_err(|e| bad(&e))?)
        }
        DiagnosticQuery::Topology { iface } => {
            PreparedSql::plain(diagnosis::topology_sql(iface.as_deref()).map_err(|e| bad(&e))?)
        }
        DiagnosticQuery::EgressScan => {
            PreparedSql::plain(diagnosis::EGRESS_LATEST_SCAN_SQL.to_string())
        }
        DiagnosticQuery::EgressDsts { scan_ts_us } => diagnosis::egress_dsts_at_sql(scan_ts_us),
        DiagnosticQuery::Connections { group_by } => {
            PreparedSql::plain(diagnosis::connections_sql(group_by))
        }
        DiagnosticQuery::AirScan => PreparedSql::plain(diagnosis::AIR_LATEST_SCAN_SQL.to_string()),
        DiagnosticQuery::AirAps { scan_ts_us } => diagnosis::air_aps_at_sql(scan_ts_us),
        DiagnosticQuery::AirSelfChannel => {
            PreparedSql::plain(diagnosis::AIR_SELF_CHANNEL_SQL.to_string())
        }
        // Not a SQL diagnosis: a primary-key read of the `experiment` table,
        // rendered through the one conversion the CLI's offline path also
        // uses. Reached only for a window the daemon no longer holds in
        // memory (`api::experiment_in_memory` answers those first). (realm
        // net-observer, node #61)
        DiagnosticQuery::Experiment { id } => {
            return match store.experiment(&id).map_err(describe)? {
                Some(record) => experiment_table_from_json(&record.report_json)
                    .map_err(|e| format!("experiment {id}: {e}")),
                None => Err(format!(
                    "experiment {id} not found: this daemon did not run it and the record holds no such window"
                )),
            };
        }
        // Never actually reached: `api::handle_conn` routes `CveLookup` to
        // `api::cve_lookup_response` BEFORE `query_store` (and therefore
        // before this function) ever sees it — a name-only lookup is a pure
        // index read against the cached `VulnDb`, not a SQL diagnosis, and
        // touches neither the store nor its query gate. This arm exists only
        // so the match stays exhaustive if that routing is ever removed.
        DiagnosticQuery::CveLookup { .. } => {
            return Err(
                "CveLookup is not a store diagnosis and should never reach run_query".to_string(),
            );
        }
    };
    store
        .query_prepared_within(&statement, budget)
        .map(table_from_query)
        .map_err(describe)
}

/// A store failure in the daemon's words: the deadline is named as the budget
/// in seconds (never the driver's `INTERRUPT` spelling), everything else as
/// a failed diagnosis. Separated so the wording is tested without a slow query.
fn describe(e: StoreError) -> String {
    match e {
        StoreError::Interrupted { budget } => format!(
            "diagnosis exceeded {} s and was interrupted",
            budget.as_secs()
        ),
        other => format!("diagnosis failed: {other}"),
    }
}

/// `store::QueryTable` → the wire's [`Table`]: the same two fields, moved.
/// The CLI carries the same conversion for its offline path; neither crate may
/// own it for both, because `net-observer-ipc` must not depend on `store`.
fn table_from_query(q: QueryTable) -> Table {
    Table {
        columns: q.columns,
        rows: q.rows,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_observer_ipc::UNDECODABLE_REQUEST_PREFIX;
    use store::DuckdbStore;

    /// A budget no test query reaches, so the ordinary cases are about the
    /// mapping and not the deadline.
    const GENEROUS: Duration = Duration::from_secs(30);

    /// The deadline reaches the operator in the daemon's words — the budget
    /// named in seconds, never the driver's `INTERRUPT` spelling — and never in
    /// the spelling reserved for an undecodable request. The interruption
    /// itself is proved against the real store in `store`'s own tests; this
    /// pins the wording, which no slow query is needed for.
    #[test]
    fn the_deadline_is_reported_in_the_daemons_words() {
        let e = describe(store::StoreError::Interrupted {
            budget: Duration::from_secs(30),
        });
        assert_eq!(e, "diagnosis exceeded 30 s and was interrupted");
        assert!(!e.starts_with(UNDECODABLE_REQUEST_PREFIX));
        assert!(!e.contains("INTERRUPT"), "{e}");
        let other = describe(store::StoreError::Panicked("boom".into()));
        assert!(other.starts_with("diagnosis failed: "), "{other}");
    }

    /// Every variant runs against an empty in-memory record and answers with
    /// the columns its renderer looks up by name — the same names the CLI's
    /// offline path gets from the same builders.
    #[test]
    fn every_diagnosis_answers_with_its_columns() {
        let store = DuckdbStore::in_memory().unwrap();
        let expect = |q: DiagnosticQuery, cols: &[&str]| {
            let table = run_query(
                &store,
                q.clone(),
                diagnosis::DEFAULT_STARVATION_LOAD,
                GENEROUS,
            )
            .unwrap_or_else(|e| panic!("{q:?}: {e}"));
            for c in cols {
                assert!(
                    table.columns.iter().any(|x| x == c),
                    "{q:?} lacks column {c}: {:?}",
                    table.columns
                );
            }
        };
        expect(
            DiagnosticQuery::Why { ts_us: 1 },
            &["ts_us", "layer", "gap_opened_us"],
        );
        expect(
            DiagnosticQuery::IncidentContext,
            &["id", "layer", "state_ts_us"],
        );
        expect(
            DiagnosticQuery::WedgeVsStarvation,
            &["episode", "verdict", "max_load1"],
        );
        expect(DiagnosticQuery::GwDrops, &["ts_us"]);
        expect(
            DiagnosticQuery::GatewayRamp {
                drop_ts_us: 1,
                window_us: 10,
            },
            &["ts_us", "slope_ms_per_s", "observation_gap_us"],
        );
        expect(DiagnosticQuery::Gaps, &["gap_opened_us", "gap_closed_by"]);
        expect(
            DiagnosticQuery::Silences,
            &["kind", "gap_opened_us", "gap_closed_by"],
        );
        expect(
            DiagnosticQuery::Neighbors { network: None },
            &["mac", "source"],
        );
        expect(
            DiagnosticQuery::Vulns {
                network: Some("unknown".into()),
            },
            &["cve_id", "confidence"],
        );
        expect(DiagnosticQuery::Segments, &["network_key", "ssid_guess"]);
        expect(
            DiagnosticQuery::History {
                network: "unknown".into(),
                window: types::HistoryWindow::At(0),
            },
            &["mac", "open_ports", "vulns"],
        );
        expect(
            DiagnosticQuery::Topology {
                iface: Some("en0".into()),
            },
            &["remote_chassis", "learned_via"],
        );
        expect(
            DiagnosticQuery::Connections {
                group_by: types::ConnectionsGroupBy::IpPort,
            },
            &[
                "ts_us", "verdict", "key", "scope", "count", "upload", "download", "hosts",
            ],
        );
        expect(
            DiagnosticQuery::Connections {
                group_by: types::ConnectionsGroupBy::ProcessHost,
            },
            &[
                "ts_us", "verdict", "key", "process", "scope", "count", "upload", "download",
                "hosts",
            ],
        );
        expect(
            DiagnosticQuery::AirScan,
            &["ts_us", "air", "reason", "ap_count"],
        );
        expect(
            DiagnosticQuery::AirAps { scan_ts_us: 1 },
            &[
                "channel",
                "channel_band",
                "channel_width_mhz",
                "phy_mode",
                "security",
                "rssi_dbm",
                "noise_dbm",
            ],
        );
        expect(
            DiagnosticQuery::AirSelfChannel,
            &["ts_us", "channel", "channel_band", "channel_width_mhz"],
        );
        expect(
            DiagnosticQuery::EgressScan,
            &[
                "ts_us",
                "iface",
                "verdict",
                "reason",
                "duration_ms",
                "packet_count",
                "dst_count",
                "byte_count",
            ],
        );
        expect(
            DiagnosticQuery::EgressDsts { scan_ts_us: 1 },
            &["dst_ip", "packets", "bytes"],
        );
    }

    /// An experiment the record does not hold is a failure in the daemon's
    /// words — never a bad request, never the CLI's cue to wait — and one
    /// the record holds renders as the `key | value` table the live answer
    /// would have been.
    #[test]
    fn an_experiment_is_read_from_the_table_or_named_as_absent() {
        let store = DuckdbStore::in_memory().unwrap();
        let absent = run_query(
            &store,
            DiagnosticQuery::Experiment {
                id: "experiment-7".into(),
            },
            10.0,
            GENEROUS,
        )
        .expect_err("no such window");
        assert!(absent.contains("experiment-7 not found"), "{absent}");
        assert!(!absent.starts_with(UNDECODABLE_REQUEST_PREFIX));
        assert!(!net_observer_ipc::is_experiment_running(&absent));

        let report = types::ExperimentReport {
            id: "experiment-7".into(),
            window: types::ExperimentWindow {
                start_us: 7,
                end_us: 7 + 60_000_000,
                requested_minutes: 1,
                link_interval_us: 15_000_000,
                tier_before: types::ProbingTier::Active,
                tier_at_end: types::ProbingTier::Active,
                restore: types::TierRestore::Restored,
                freeze_start_dir: None,
                freeze_end_dir: None,
                frames_pcap_start: None,
                frames_pcap_end: None,
            },
            ring_filter: "arp or icmp".into(),
            own_mac: None,
            our_frames: None,
            network: Some(types::NetworkFacts::default()),
            edges: types::WindowEdges::default(),
            notes: Vec::new(),
        };
        store
            .write_experiment(&::store::ExperimentRecord {
                id: "experiment-7".into(),
                start_us: 7,
                end_us: 7 + 60_000_000,
                tier_before: types::ProbingTier::Active,
                freeze_start_dir: None,
                freeze_end_dir: None,
                report_json: net_observer_ipc::experiment_report_json(&report).unwrap(),
            })
            .unwrap();
        let table = run_query(
            &store,
            DiagnosticQuery::Experiment {
                id: "experiment-7".into(),
            },
            10.0,
            GENEROUS,
        )
        .unwrap();
        assert_eq!(table, Table::from(&report));
    }

    /// A filter the store could never have written is refused with the
    /// builder's own words — and never in the spelling reserved for a request
    /// the daemon could not read, or the CLI would fall back to the offline
    /// file over a typo and meet the lock instead.
    #[test]
    fn a_bad_key_is_a_failure_in_the_daemons_words_not_a_bad_request() {
        let store = DuckdbStore::in_memory().unwrap();
        for q in [
            DiagnosticQuery::Neighbors {
                network: Some("nope".into()),
            },
            DiagnosticQuery::Vulns {
                network: Some("a4:83".into()),
            },
            DiagnosticQuery::History {
                network: "'; DROP TABLE neighbor; --".into(),
                window: types::HistoryWindow::At(0),
            },
            DiagnosticQuery::Topology {
                iface: Some("en0; DROP".into()),
            },
        ] {
            let e = run_query(&store, q.clone(), 10.0, GENEROUS).expect_err("must be refused");
            assert!(
                !e.starts_with(UNDECODABLE_REQUEST_PREFIX),
                "{q:?}: {e} would read as an undecodable request"
            );
            assert!(e.contains("not a"), "{q:?}: {e}");
        }
    }
}
