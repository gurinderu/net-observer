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

use net_observer_ipc::{DiagnosticQuery, Table};
use store::{QueryTable, Store, diagnosis};

/// Run one named diagnosis against `store`, read-only.
///
/// `load_threshold` is the daemon's own starvation load — the same number the
/// `starvation` trigger judges by — so a live reading of the record cannot
/// disagree with the incidents the daemon recorded from it. The other
/// thresholds a diagnosis needs (episode gap) are `diagnosis`'s defaults, the
/// ones the CLI's offline path uses.
///
/// `Err` carries the daemon's own words for the client to show: a key the
/// store could never have written (the builders refuse it rather than match
/// nothing), or a DuckDB error. It never starts with
/// [`net_observer_ipc::UNDECODABLE_REQUEST_PREFIX`] — that spelling is
/// reserved for a request the daemon could not read at all, and the client's
/// fallback rule turns on the difference.
pub fn run_query(
    store: &dyn Store,
    q: DiagnosticQuery,
    load_threshold: f64,
) -> Result<Table, String> {
    let table = match q {
        DiagnosticQuery::Why { ts_us } => {
            store.query_prepared(&diagnosis::verdict_at_sql(ts_us, load_threshold))
        }
        DiagnosticQuery::IncidentContext => {
            store.query_prepared(&diagnosis::incident_context_sql(load_threshold))
        }
        DiagnosticQuery::WedgeVsStarvation => store.query_prepared(
            &diagnosis::wedge_vs_starvation_sql(load_threshold, diagnosis::DEFAULT_EPISODE_GAP_US),
        ),
        DiagnosticQuery::GwDrops => store.query_table(diagnosis::GW_DROPS_SQL),
        DiagnosticQuery::GatewayRamp {
            drop_ts_us,
            window_us,
        } => store.query_prepared(&diagnosis::gateway_ramp_sql(drop_ts_us, window_us)),
        DiagnosticQuery::Gaps => store.query_table(&diagnosis::observation_gaps_sql()),
        DiagnosticQuery::Neighbors { network } => {
            let sql = diagnosis::neighbors_sql(network.as_deref()).map_err(|e| e.to_string())?;
            store.query_table(&sql)
        }
        DiagnosticQuery::Vulns { network } => {
            let sql = diagnosis::vulns_sql(network.as_deref()).map_err(|e| e.to_string())?;
            store.query_table(&sql)
        }
        DiagnosticQuery::Segments => store.query_table(&diagnosis::segments_sql()),
        DiagnosticQuery::History { network, window } => {
            let sql = diagnosis::history_sql(&network, window).map_err(|e| e.to_string())?;
            store.query_table(&sql)
        }
        DiagnosticQuery::Topology { iface } => {
            let sql = diagnosis::topology_sql(iface.as_deref()).map_err(|e| e.to_string())?;
            store.query_table(&sql)
        }
    };
    table
        .map(table_from_query)
        .map_err(|e| format!("diagnosis failed: {e}"))
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

    /// Every variant runs against an empty in-memory record and answers with
    /// the columns its renderer looks up by name — the same names the CLI's
    /// offline path gets from the same builders.
    #[test]
    fn every_diagnosis_answers_with_its_columns() {
        let store = DuckdbStore::in_memory().unwrap();
        let expect = |q: DiagnosticQuery, cols: &[&str]| {
            let table = run_query(&store, q.clone(), diagnosis::DEFAULT_STARVATION_LOAD)
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
            let e = run_query(&store, q.clone(), 10.0).expect_err("must be refused");
            assert!(
                !e.starts_with(UNDECODABLE_REQUEST_PREFIX),
                "{q:?}: {e} would read as an undecodable request"
            );
            assert!(e.contains("not a"), "{q:?}: {e}");
        }
    }
}
