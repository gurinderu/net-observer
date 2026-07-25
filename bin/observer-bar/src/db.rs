//! A read-only DuckDB connection for the glance.
//!
//! `observer-bar` only ever reads, so it opens with `access_mode=read_only`:
//! no `CREATE TABLE IF NOT EXISTS` DDL runs (unlike [`store::DuckdbStore::open`],
//! which does), and the connection never tries to take DuckDB's read-write slot.
//!
//! ## Concurrency with `observerd` — important caveat
//!
//! This does **not** make the glance safe to run *concurrently* with a live
//! `observerd`. DuckDB 1.x takes a single-process file lock: while `observerd`
//! holds the store open read-write, DuckDB refuses **every** other-process open
//! of that file — read-only opens included ("Conflicting lock is held ..."). So
//! [`ReadOnlyDb::open`] succeeds only when no `observerd` is holding the store
//! (e.g. offline forensics with the daemon stopped, or a copied/detached file).
//! While the daemon runs, the open fails and the panel surfaces "store
//! unavailable" (see [`crate::ui::read_fresh`], retried each tick).
//!
//! Concurrent live access is a post-v1 concern: the toolbar is specified to talk
//! to the daemon over a local socket (or read a snapshot the daemon exports),
//! never to open the daemon's DB file directly. `access_mode=read_only` still
//! matters here (no DDL, never contends for the write slot), but it is not what
//! makes cross-process access work.

use crate::status::QuerySource;
use duckdb::{AccessMode, Config, Connection};
use store::{QueryTable, StoreError};

/// A read-only handle to the observer DuckDB file. Opening it runs no DDL and
/// never takes DuckDB's read-write slot.
///
/// Note: this can only open the file when no `observerd` is holding it open
/// read-write — DuckDB's file lock is exclusive per process and blocks even
/// read-only opens while the daemon runs (see the module docs).
pub struct ReadOnlyDb {
    conn: Connection,
}

impl ReadOnlyDb {
    /// Open `path` read-only (`access_mode=read_only`). Fails if the file does
    /// not exist yet — there is nothing to glance at until `observerd` has
    /// created the store — and also fails while a live `observerd` holds the
    /// store open read-write (DuckDB's per-process file lock blocks read-only
    /// opens too; see the module docs).
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let config = Config::default().access_mode(AccessMode::ReadOnly)?;
        let conn = Connection::open_with_flags(path, config)?;
        Ok(Self { conn })
    }
}

impl QuerySource for ReadOnlyDb {
    fn query_table(&self, sql: &str) -> Result<QueryTable, StoreError> {
        let mut stmt = self.conn.prepare(sql)?;
        let mut rows = stmt.query([])?;
        let columns = rows.as_ref().map(|s| s.column_names()).unwrap_or_default();
        let ncols = columns.len();
        let mut out_rows = Vec::new();
        while let Some(row) = rows.next()? {
            let mut cells = Vec::with_capacity(ncols);
            for i in 0..ncols {
                let value: duckdb::types::Value = row.get(i)?;
                cells.push(value_to_string(&value));
            }
            out_rows.push(cells);
        }
        Ok(QueryTable {
            columns,
            rows: out_rows,
        })
    }
}

/// Stringify a DuckDB cell value the same way `store::DuckdbStore::query_table`
/// does, so `status::read_status` parses read-only rows identically to
/// store-backed rows. Kept in sync with the store crate's private helper.
fn value_to_string(v: &duckdb::types::Value) -> String {
    use duckdb::types::Value;
    match v {
        Value::Null => String::new(),
        Value::Boolean(b) => b.to_string(),
        Value::TinyInt(n) => n.to_string(),
        Value::SmallInt(n) => n.to_string(),
        Value::Int(n) => n.to_string(),
        Value::BigInt(n) => n.to_string(),
        Value::HugeInt(n) => n.to_string(),
        Value::UTinyInt(n) => n.to_string(),
        Value::USmallInt(n) => n.to_string(),
        Value::UInt(n) => n.to_string(),
        Value::UBigInt(n) => n.to_string(),
        Value::Float(n) => n.to_string(),
        Value::Double(n) => n.to_string(),
        Value::Text(s) => s.clone(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::read_status;
    use store::{DuckdbStore, Store};
    use types::{GwVerdict, Incident, LinkSample, ProxySample, Sample, TcpVerdict};

    /// End-to-end read-only path: a writer (`DuckdbStore`) creates the file and
    /// releases it, then `ReadOnlyDb` opens it read-only and `read_status` reads
    /// through it. Exercises the production glance path (open + SELECT + LIMIT).
    #[test]
    fn read_only_db_reads_status_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("observer.duckdb");
        let path = path.to_str().unwrap().to_string();

        // Writer: create the store on disk, populate it, then drop it to release
        // DuckDB's read-write lock so the read-only handle can open the file.
        {
            let store = DuckdbStore::open(&path).unwrap();
            store
                .write_sample(&Sample::Link(LinkSample {
                    ts_us: 200,
                    gw: GwVerdict::Fail,
                    gw_rtt_ms: None,
                    direct: TcpVerdict::Ok,
                    direct_rtt_ms: None,
                    dhcp_router: None,
                    dhcp_dns: None,
                    gw_arp_mac: None,
                    ssid: None,
                    wifi_capture_present: false,
                }))
                .unwrap();
            store
                .write_sample(&Sample::Proxy(ProxySample {
                    ts_us: 150,
                    server_ip: "1.2.3.4".into(),
                    tcp: TcpVerdict::Ok,
                    rtt_ms: None,
                    tun_code: Some(0),
                    selector: Some("auto".into()),
                }))
                .unwrap();
            store
                .open_incident(&Incident {
                    id: "i1".into(),
                    opened_us: 90,
                    closed_us: None,
                    trigger_id: "wedge".into(),
                    signature: "tun dead".into(),
                })
                .unwrap();
        }

        let ro = ReadOnlyDb::open(&path).unwrap();
        let status = read_status(&ro, 10).unwrap();

        let link = status.link.expect("link present");
        assert_eq!(link.ts_us, 200);
        assert_eq!(link.gw, "FAIL");

        let proxy = status.proxy.expect("proxy present");
        assert_eq!(proxy.tun_code, Some(0));
        assert_eq!(proxy.selector.as_deref(), Some("auto"));

        assert_eq!(status.incidents.len(), 1);
        assert_eq!(status.incidents[0].trigger_id, "wedge");
    }
}
