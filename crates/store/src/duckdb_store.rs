use crate::{Store, diagnosis::PreparedSql, schema::SCHEMA_SQL};
use duckdb::{Connection, InterruptHandle, params};
use std::panic::AssertUnwindSafe;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use types::{
    BlobRef, Incident, NeighborLifetime, ObservingEdge, ParseVerdictError, ProbingEdge,
    ProbingTier, Sample, TopologyLifetime, TopologyLink, TriggerFired,
};

/// `network_key` for a segment whose gateway MAC could not be read. Neighbours
/// still get recorded — under a key that says plainly the network was not
/// identified, rather than being silently merged into someone else's.
const UNKNOWN_NETWORK: &str = "unknown";

/// One finished experiment window, as written to `experiment` (realm
/// net-observer, node #61).
///
/// The report itself travels as the JSON `net_observer_ipc` renders from a
/// `types::ExperimentReport` — this crate stores the text and never reads
/// inside it, so it needs no JSON dependency of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExperimentRecord {
    /// `experiment-<start_us>`.
    pub id: String,
    pub start_us: i64,
    pub end_us: i64,
    /// The tier in force before the window (restored at its close unless an
    /// operator moved the tier inside it).
    pub tier_before: ProbingTier,
    /// Where the start and end freezes copied the ring; `None` when a freeze
    /// copied nothing. Each copied file also has a `blob_ref` row against
    /// the window's id.
    pub freeze_start_dir: Option<String>,
    pub freeze_end_dir: Option<String>,
    /// The `ExperimentReport`, serialised.
    pub report_json: String,
}

/// One open port found on a neighbour, as written to `neighbor_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborPort {
    pub network_key: Option<String>,
    pub mac: String,
    pub ip: String,
    pub port: u16,
    pub ts_us: i64,
    /// Raw text the service volunteered when the banner rung grabbed it; `None`
    /// when that rung did not run or nothing readable came back.
    pub banner: Option<String>,
}

/// One CVE hypothesised for an open port, as written to `neighbor_vuln`.
///
/// A match is never an asserted fact: `confidence` and `known_exploited` record
/// how much to trust it. `confidence` is stored as its lowercase token
/// (`low`/`medium`/`high`).
#[derive(Debug, Clone, PartialEq)]
pub struct NeighborVuln {
    pub network_key: Option<String>,
    pub mac: String,
    pub port: u16,
    pub cve_id: String,
    /// Lowercase confidence token: `low` | `medium` | `high`.
    pub confidence: String,
    pub known_exploited: bool,
    /// CVSS base score when the record carried one; `None` otherwise.
    pub cvss: Option<f64>,
    pub ts_us: i64,
}

/// One operator-pressed neighbour scan, as written to `neighbor_scan`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborScan {
    pub ts_us: i64,
    pub network_key: Option<String>,
    pub iface: Option<String>,
    /// "sweep" | "mdns".
    pub method: String,
    /// What was probed: the subnet in CIDR form, or the mDNS service type.
    pub target: String,
    pub found: i32,
    pub duration_ms: i64,
    pub detail: Option<String>,
}

/// What a store call can fail with.
///
/// Two variants exist because the connection is shared with the writer: a
/// read that runs past its budget, or panics, must hand the connection back
/// whole and say what happened, never take the pipeline's next write down
/// with it (realm net-observer, node #58).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The driver's own error, verbatim.
    #[error(transparent)]
    Duckdb(#[from] duckdb::Error),
    /// The statement ran past the budget [`DuckdbStore::query_prepared_within`]
    /// was given and was interrupted at the deadline. The connection is usable
    /// again the moment this is returned.
    #[error("query exceeded its budget of {budget:?} and was interrupted")]
    Interrupted { budget: Duration },
    /// The driver or a row conversion panicked under the connection lock. The
    /// panic was caught so the lock was released normally — a poisoned mutex
    /// would panic the writer's next `lock()` and with it the consumer loop.
    /// The message is the panic's own payload.
    #[error("store panicked under its connection lock: {0}")]
    Panicked(String),
}

pub struct DuckdbStore {
    conn: Mutex<Connection>,
    /// Taken from the connection ONCE, at open: obtaining it needs the
    /// connection, and the moment a deadline fires the connection is exactly
    /// what the running query holds. Interrupts only a statement in flight; a
    /// flag left set with nothing running is cleared by DuckDB at the start of
    /// the next statement (`ClientContext::InitialCleanup`).
    interrupt: Arc<InterruptHandle>,
}

/// A generic query result: column names plus already-stringified rows.
///
/// Cells are rendered to `String` inside the store so that callers (e.g. the
/// CLI) never need to depend on `duckdb`'s value types directly.
#[derive(Debug, Clone, Default)]
pub struct QueryTable {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// One table the opened file shapes differently from what this build's
/// positional INSERT supplies (see [`Store::schema_drift`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDrift {
    pub table: String,
    /// Values this build's `INSERT INTO <table> VALUES (?,…)` binds.
    pub expected: usize,
    /// Columns the file's table has.
    pub actual: usize,
}

impl DuckdbStore {
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_conn(Connection::open_in_memory()?)
    }
    pub fn open(path: &str) -> Result<Self, StoreError> {
        Self::from_conn(Connection::open(path)?)
    }
    fn from_conn(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(SCHEMA_SQL)?;
        let interrupt = conn.interrupt_handle();
        Ok(Self {
            conn: Mutex::new(conn),
            interrupt,
        })
    }

    /// Close every still-open incident at `ts_us`, returning how many there were.
    ///
    /// Called once at daemon startup. An incident's closing edge (the trigger
    /// condition's Some→None transition) lives in the previous process's
    /// memory, so a restart would otherwise leave its open incidents open
    /// FOREVER — the first live-trial week accumulated 60+ such rows. A close
    /// stamped at startup is an observation bound ("nothing can track this
    /// past here"), not a recovery claim; the trigger_fired rows keep the
    /// full firing history either way.
    pub fn close_open_incidents(&self, ts_us: i64) -> Result<usize, StoreError> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE incident SET closed_us=? WHERE closed_us IS NULL",
            params![ts_us],
        )?;
        Ok(n)
    }

    /// The newest `ts_us` across every SAMPLE table — the record's own
    /// observation bound, distinct from whatever the wall clock reads when a
    /// fresh process asks. `None` when the record holds no samples at all (a
    /// freshly created database file).
    ///
    /// The pairing for [`Self::close_open_incidents`] at startup: a crashed
    /// process's open incidents must close at the last instant this record
    /// actually observed something, not at the new process's own start time —
    /// `now_us()` is always later than that bound, so it would stamp a
    /// crashed run's incidents as having lasted until this later moment
    /// (realm net-observer, node #124).
    pub fn latest_sample_ts_us(&self) -> Result<Option<i64>, StoreError> {
        let max: Option<i64> = self.conn.lock().unwrap().query_row(
            "SELECT MAX(m) FROM (
                SELECT MAX(ts_us) AS m FROM link_sample
                UNION ALL SELECT MAX(ts_us) FROM proxy_sample
                UNION ALL SELECT MAX(ts_us) FROM dns_sample
                UNION ALL SELECT MAX(ts_us) FROM route_event
                UNION ALL SELECT MAX(ts_us) FROM host_sample
                UNION ALL SELECT MAX(ts_us) FROM wifi_sample
                UNION ALL SELECT MAX(ts_us) FROM air_sample
                UNION ALL SELECT MAX(ts_us) FROM neighbor_sample
            )",
            [],
            |r| r.get(0),
        )?;
        Ok(max)
    }

    /// List incidents as `(trigger_id, opened_us, closed_us)`, newest first.
    pub fn list_incidents(&self) -> Result<Vec<(String, i64, Option<i64>)>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT trigger_id, opened_us, closed_us FROM incident ORDER BY opened_us DESC",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, duckdb::Error>>()?;
        Ok(rows)
    }

    /// Run a prepared query with positional `?` parameter values and return its
    /// column names plus stringified rows.
    ///
    /// `params` is bound positionally, in the order the `?` placeholders appear
    /// in `sql` — a value that is reused at several placeholders is passed once
    /// per occurrence. This is how `diagnosis`'s per-moment builders (`realm
    /// net-observer, node #29`) supply the moment and the thresholds they used
    /// to interpolate as text: the value never becomes part of the SQL string.
    pub(crate) fn query_table_params(
        &self,
        sql: &str,
        params: &[&dyn duckdb::types::ToSql],
    ) -> Result<QueryTable, StoreError> {
        self.with_conn(|conn| run_statement(conn, sql, params))
    }

    /// Run `f` on the connection under its lock, with a panic inside `f`
    /// turned into [`StoreError::Panicked`] rather than left to poison the
    /// mutex. The connection is shared with the pipeline's writer, whose next
    /// `lock()` would otherwise panic the consumer loop over a read that blew
    /// up — the panic is still reported through the panic hook, it simply does
    /// not take the guard down with it.
    pub(crate) fn with_conn<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let conn = self.conn.lock().unwrap();
        match std::panic::catch_unwind(AssertUnwindSafe(|| f(&conn))) {
            Ok(result) => result,
            Err(payload) => Err(StoreError::Panicked(panic_message(payload.as_ref()))),
        }
    }
}

/// One prepared statement, executed and read out in full. Free of the lock so
/// [`DuckdbStore::with_conn`] can wrap it.
fn run_statement(
    conn: &Connection,
    sql: &str,
    params: &[&dyn duckdb::types::ToSql],
) -> Result<QueryTable, StoreError> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;
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

/// The text a panic payload carries, for [`StoreError::Panicked`]: `panic!`
/// with a literal gives a `&str`, with a `format!` a `String`; anything else
/// is named as such rather than lost.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// A deadline on one statement: a thread that interrupts the connection if it
/// is not stood down within `budget`.
///
/// Armed and disarmed INSIDE the connection lock, and standing down JOINS the
/// thread — on the explicit `disarm` and, through `Drop`, on the panic path
/// `with_conn` catches — so once the guard is gone, no interrupt can still be
/// on its way to hit whatever the writer runs next. The remaining case, an
/// interrupt that lands after the statement finished but before the join,
/// leaves a flag with nothing running; DuckDB clears it at the start of the
/// next statement (`ClientContext::InitialCleanup`, checked against the
/// bundled sources), so that statement is unaffected. Likewise an interrupt
/// landing during `prepare` — unreachable at a 30 s budget — is cleared by
/// the execute step's own reset, and the statement then runs unbounded rather
/// than misfiring on the writer.
struct Watchdog {
    stand_down: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<bool>>,
}

impl Watchdog {
    fn arm(interrupt: Arc<InterruptHandle>, budget: Duration) -> Self {
        let (stand_down, rx) = mpsc::channel::<()>();
        let thread = std::thread::spawn(move || match rx.recv_timeout(budget) {
            // The deadline passed with the statement still running.
            Err(RecvTimeoutError::Timeout) => {
                interrupt.interrupt();
                true
            }
            // Stood down: the sender was dropped before the deadline.
            Ok(()) | Err(RecvTimeoutError::Disconnected) => false,
        });
        Self {
            stand_down: Some(stand_down),
            thread: Some(thread),
        }
    }

    /// Stand the thread down and wait for it; `true` iff it fired. Idempotent
    /// with [`Drop`]: whichever runs first does the work, the other finds
    /// nothing left to do.
    fn disarm(mut self) -> bool {
        self.stand_down_and_join()
    }

    fn stand_down_and_join(&mut self) -> bool {
        drop(self.stand_down.take());
        self.thread
            .take()
            .map(|t| t.join().unwrap_or(false))
            .unwrap_or(false)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stand_down_and_join();
    }
}

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

/// The statements this build writes with POSITIONAL values — `INSERT INTO t
/// VALUES (?,…)`, one `?` per column in the order `SCHEMA_SQL` gives the
/// table — named here so [`Store::schema_drift`] can count what each supplies
/// against what the opened file has. The statement IS the count: a column
/// added to a table is one `?` added here and one value added to the
/// `params!` beside its use, nothing else to keep in step. A table written
/// through a named column list (`neighbor_service`, `neighbor_port`,
/// `neighbor_vuln`, `topology_link`, `observing_edge`, `probing_edge`,
/// `experiment`) is absent on purpose: a column a newer build appended to it
/// is NULL-filled by that INSERT, not refused (realm net-observer, node #150).
const INSERT_LINK_SAMPLE: &str =
    "INSERT INTO link_sample VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
const INSERT_PROXY_SAMPLE: &str = "INSERT INTO proxy_sample VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
const INSERT_DNS_SAMPLE: &str = "INSERT INTO dns_sample VALUES (?,?,?,?,?,?)";
const INSERT_ROUTE_EVENT: &str = "INSERT INTO route_event VALUES (?,?,?,?)";
const INSERT_HOST_SAMPLE: &str = "INSERT INTO host_sample VALUES (?,?,?,?,?,?,?)";
const INSERT_WIFI_SAMPLE: &str = "INSERT INTO wifi_sample VALUES (?,?,?,?,?,?,?,?,?,?,?)";
const INSERT_AIR_SAMPLE: &str = "INSERT INTO air_sample VALUES (?,?,?,?)";
const INSERT_AIR_AP: &str = "INSERT INTO air_ap VALUES (?,?,?,?,?,?,?,?)";
const INSERT_NEIGHBOR_SAMPLE: &str = "INSERT INTO neighbor_sample VALUES (?,?,?,?,?,?,?,?,?)";
/// `first_seen_us` is never overwritten — it is the whole point of the row. A
/// hostname already known is kept when the new sighting carries none (a
/// passive ARP read never has one, and must not erase what a scan learned).
const INSERT_NEIGHBOR: &str = "INSERT INTO neighbor VALUES (?,?,?,?,?,?,?,?,?)
     ON CONFLICT (network_key, mac) DO UPDATE SET
       ip = excluded.ip,
       iface = excluded.iface,
       hostname = coalesce(excluded.hostname, neighbor.hostname),
       source = excluded.source,
       last_seen_us = excluded.last_seen_us";
const INSERT_CONNECTION_SAMPLE: &str =
    "INSERT INTO connection_sample VALUES (?,?,?,?,?,?,?,?,?,?,?)";
const INSERT_NEIGHBOR_SCAN: &str = "INSERT INTO neighbor_scan VALUES (?,?,?,?,?,?,?,?)";
const INSERT_INCIDENT: &str = "INSERT INTO incident VALUES (?,?,?,?,?)";
const INSERT_BLOB_REF: &str = "INSERT INTO blob_ref VALUES (?,?,?,?,?)";
const INSERT_TRIGGER_FIRED: &str = "INSERT INTO trigger_fired VALUES (?,?,?,?)";

/// `(table, statement)` for every positional INSERT above — what
/// [`Store::schema_drift`] walks.
const POSITIONAL_INSERTS: &[(&str, &str)] = &[
    ("link_sample", INSERT_LINK_SAMPLE),
    ("proxy_sample", INSERT_PROXY_SAMPLE),
    ("dns_sample", INSERT_DNS_SAMPLE),
    ("route_event", INSERT_ROUTE_EVENT),
    ("host_sample", INSERT_HOST_SAMPLE),
    ("wifi_sample", INSERT_WIFI_SAMPLE),
    ("air_sample", INSERT_AIR_SAMPLE),
    ("air_ap", INSERT_AIR_AP),
    ("neighbor_sample", INSERT_NEIGHBOR_SAMPLE),
    ("neighbor", INSERT_NEIGHBOR),
    ("connection_sample", INSERT_CONNECTION_SAMPLE),
    ("neighbor_scan", INSERT_NEIGHBOR_SCAN),
    ("incident", INSERT_INCIDENT),
    ("blob_ref", INSERT_BLOB_REF),
    ("trigger_fired", INSERT_TRIGGER_FIRED),
];

impl Store for DuckdbStore {
    fn write_sample(&self, s: &Sample) -> Result<(), StoreError> {
        let mut c = self.conn.lock().unwrap();
        match s {
            Sample::Link(l) => c.execute(
                INSERT_LINK_SAMPLE,
                params![
                    l.ts_us,
                    l.gw.to_string(),
                    l.gw_rtt_ms,
                    l.direct.to_string(),
                    l.direct_rtt_ms,
                    l.dhcp_router,
                    l.dhcp_dns,
                    l.gw_arp_mac,
                    l.ssid,
                    l.wifi_capture_present,
                    l.lan_probed,
                    l.lan_alive,
                    l.fakeip_route_if,
                    l.singbox_tun_if,
                    l.bssid,
                    l.if_mac,
                    l.medium.map(|m| m.to_string()),
                    l.lease_start_us,
                    l.lease_secs,
                    l.if_mac_private
                ],
            )?,
            Sample::Proxy(p) => c.execute(
                INSERT_PROXY_SAMPLE,
                params![
                    p.ts_us,
                    p.server_ip,
                    p.tcp.to_string(),
                    p.rtt_ms,
                    p.tun_code,
                    p.selector,
                    p.est_direct_alive,
                    p.est_direct_age_s,
                    p.est_tun_alive,
                    p.est_tun_age_s,
                    p.urltest_ms,
                    p.urltest_at_us,
                    p.urltest_node,
                    p.urltest_absent_since_us
                ],
            )?,
            Sample::Dns(d) => c.execute(
                INSERT_DNS_SAMPLE,
                params![
                    d.ts_us,
                    d.probe,
                    d.server,
                    d.verdict.to_string(),
                    d.ip,
                    d.rtt_ms
                ],
            )?,
            Sample::Route(r) => c.execute(
                INSERT_ROUTE_EVENT,
                params![r.ts_us, r.kind, r.iface, r.detail],
            )?,
            Sample::Host(h) => c.execute(
                INSERT_HOST_SAMPLE,
                params![
                    h.ts_us,
                    h.load1,
                    h.load5,
                    h.load15,
                    h.disk_used_pct,
                    h.disk_free_mb,
                    h.swap_used_mb
                ],
            )?,
            Sample::Wifi(w) => c.execute(
                INSERT_WIFI_SAMPLE,
                params![
                    w.ts_us,
                    w.wifi.to_string(),
                    w.reason,
                    w.rssi_dbm,
                    w.noise_dbm,
                    w.snr_db,
                    w.tx_rate_mbps,
                    w.phy_mode,
                    w.channel,
                    w.channel_width_mhz,
                    w.channel_band
                ],
            )?,
            // Two writes, like the neighbours arm — but the second table is a
            // per-scan slice, not a long-lived entity: with no BSSID in the
            // report there is nothing to key an AP by across scans (realm
            // net-observer, node #47). The scan's own row is written even when it
            // is a SKIP, so "could not look" never renders as clear air.
            Sample::Air(a) => {
                c.execute(
                    INSERT_AIR_SAMPLE,
                    params![
                        a.ts_us,
                        a.air.to_string(),
                        a.reason,
                        i32::try_from(a.aps.len()).unwrap_or(i32::MAX)
                    ],
                )?;
                for ap in &a.aps {
                    c.execute(
                        INSERT_AIR_AP,
                        params![
                            a.ts_us,
                            ap.channel,
                            ap.channel_band,
                            ap.channel_width_mhz,
                            ap.phy_mode,
                            ap.security,
                            ap.rssi_dbm,
                            ap.noise_dbm
                        ],
                    )?;
                }
                0
            }
            // Three writes, not one: the tick's own row (so a SKIP leaves a
            // trace, and a listener flush its frame counts), an upsert per
            // neighbour into the long-lived entity table, and an upsert per
            // announced service — the last only ever non-empty on a listener
            // flush (realm net-observer, node #92).
            Sample::Neighbors(n) => {
                c.execute(
                    INSERT_NEIGHBOR_SAMPLE,
                    params![
                        n.ts_us,
                        n.network_key,
                        n.iface,
                        n.verdict.to_string(),
                        n.reason,
                        i32::try_from(n.neighbors.len()).unwrap_or(i32::MAX),
                        n.heard.map(|h| h.total),
                        n.heard.and_then(|h| h.own),
                        n.heard.map(|h| h.dropped)
                    ],
                )?;
                let key = n.network_key.as_deref().unwrap_or(UNKNOWN_NETWORK);
                for nb in &n.neighbors {
                    c.execute(
                        INSERT_NEIGHBOR,
                        params![
                            key,
                            nb.mac,
                            nb.ip,
                            n.iface,
                            nb.oui(),
                            nb.hostname,
                            nb.source.to_string(),
                            n.ts_us,
                            n.ts_us
                        ],
                    )?;
                }
                for svc in &n.services {
                    c.execute(
                        // `first_seen_us` preserved, like `neighbor`: the point of
                        // the row is since-when this device has announced this.
                        // A repeat that carries no address or detail (a DHCP
                        // client still without a lease, an SSDP notify without a
                        // SERVER line) keeps what an earlier sighting learned.
                        "INSERT INTO neighbor_service
                           (network_key, mac, ip, service, kind, detail,
                            first_seen_us, last_seen_us)
                         VALUES (?,?,?,?,?,?,?,?)
                         ON CONFLICT (network_key, mac, service) DO UPDATE SET
                           ip = COALESCE(excluded.ip, neighbor_service.ip),
                           kind = excluded.kind,
                           detail = COALESCE(excluded.detail, neighbor_service.detail),
                           last_seen_us = excluded.last_seen_us",
                        params![
                            key,
                            svc.mac,
                            svc.ip,
                            svc.service,
                            svc.kind.to_string(),
                            svc.detail,
                            n.ts_us,
                            n.ts_us
                        ],
                    )?;
                }
                0
            }
            // One row per aggregate row, the verdict replicated — and, for a
            // tick with none, ONE all-NULL row carrying the verdict, so a SKIP
            // (could not look) and an empty OK (nothing is talking) are both
            // rows, and different ones (realm net-observer, node #75).
            //
            // The tick is ONE transaction: a failure on any row rolls the whole
            // tick back (the transaction drops uncommitted on the early `?`
            // return), so `connections_sql` never presents a half-written tick
            // as the complete flow table.
            Sample::Connections(cs) => {
                let verdict = cs.verdict.to_string();
                let tx = c.transaction()?;
                if cs.rows.is_empty() {
                    tx.execute(
                        "INSERT INTO connection_sample (ts_us, verdict) VALUES (?,?)",
                        params![cs.ts_us, verdict],
                    )?;
                }
                for r in &cs.rows {
                    tx.execute(
                        INSERT_CONNECTION_SAMPLE,
                        params![
                            cs.ts_us, verdict, r.host, r.dst_ip, r.dst_port, r.process, r.network,
                            r.chain, r.count, r.upload, r.download
                        ],
                    )?;
                }
                tx.commit()?;
                0
            }
        };
        Ok(())
    }

    fn write_neighbor_scan(&self, s: &NeighborScan) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            INSERT_NEIGHBOR_SCAN,
            params![
                s.ts_us,
                s.network_key,
                s.iface,
                s.method,
                s.target,
                s.found,
                s.duration_ms,
                s.detail
            ],
        )?;
        Ok(())
    }

    fn write_neighbor_port(&self, p: &NeighborPort) -> Result<(), StoreError> {
        let key = p.network_key.as_deref().unwrap_or(UNKNOWN_NETWORK);
        self.conn.lock().unwrap().execute(
            // `first_seen_us` preserved, like `neighbor`: the point of the row is
            // since-when a port has been open on this device.
            "INSERT INTO neighbor_port
               (network_key, mac, ip, port, first_seen_us, last_seen_us, banner)
             VALUES (?,?,?,?,?,?,?)
             ON CONFLICT (network_key, mac, port) DO UPDATE SET
               ip = excluded.ip,
               last_seen_us = excluded.last_seen_us,
               -- A run that grabbed no banner (NULL) must not erase one an
               -- earlier grab learned; a fresh banner overwrites the old.
               banner = COALESCE(excluded.banner, neighbor_port.banner)",
            params![key, p.mac, p.ip, p.port, p.ts_us, p.ts_us, p.banner],
        )?;
        Ok(())
    }
    fn write_neighbor_vuln(&self, v: &NeighborVuln) -> Result<(), StoreError> {
        let key = v.network_key.as_deref().unwrap_or(UNKNOWN_NETWORK);
        self.conn.lock().unwrap().execute(
            // `first_seen_us` preserved: the point of the row is since-when a CVE
            // has been hypothesised for a port. The re-match's verdict wins —
            // confidence, KEV flag and CVSS all reflect the current snapshot.
            "INSERT INTO neighbor_vuln
               (network_key, mac, port, cve_id, confidence, known_exploited, cvss,
                first_seen_us, last_seen_us)
             VALUES (?,?,?,?,?,?,?,?,?)
             ON CONFLICT (network_key, mac, port, cve_id) DO UPDATE SET
               confidence = excluded.confidence,
               known_exploited = excluded.known_exploited,
               cvss = excluded.cvss,
               last_seen_us = excluded.last_seen_us",
            params![
                key,
                v.mac,
                v.port,
                v.cve_id,
                v.confidence,
                v.known_exploited,
                v.cvss,
                v.ts_us,
                v.ts_us
            ],
        )?;
        Ok(())
    }
    fn write_topology_link(&self, l: &TopologyLink) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            // `first_seen_us` preserved, like `neighbor`: the point of the row is
            // since-when this interface has uplinked to that switch:port. A later
            // sighting refines the system name and capabilities but never resets
            // when the uplink was first seen. A NULL system name from a frame that
            // carried none must not erase one an earlier frame advertised.
            "INSERT INTO topology_link
               (iface, remote_chassis, remote_port, remote_system_name,
                capabilities, learned_via, first_seen_us, last_seen_us)
             VALUES (?,?,?,?,?,?,?,?)
             ON CONFLICT (iface, remote_chassis, remote_port) DO UPDATE SET
               remote_system_name =
                 COALESCE(excluded.remote_system_name, topology_link.remote_system_name),
               -- Keep a previously-learned capability set when a later frame
               -- carries no System-Capabilities TLV (empty string), mirroring the
               -- system-name COALESCE: silent wrong data is worse than none.
               capabilities =
                 COALESCE(NULLIF(excluded.capabilities, ''), topology_link.capabilities),
               learned_via = excluded.learned_via,
               last_seen_us = excluded.last_seen_us",
            params![
                l.iface,
                l.remote_chassis,
                l.remote_port,
                l.remote_system_name,
                l.capabilities,
                l.learned_via.as_str(),
                l.ts_us,
                l.ts_us
            ],
        )?;
        Ok(())
    }
    fn open_incident(&self, i: &Incident) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            INSERT_INCIDENT,
            params![i.id, i.opened_us, i.closed_us, i.trigger_id, i.signature],
        )?;
        Ok(())
    }
    fn close_incident(&self, id: &str, closed_us: i64) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            "UPDATE incident SET closed_us=? WHERE id=?",
            params![closed_us, id],
        )?;
        Ok(())
    }
    fn write_blob_ref(&self, b: &BlobRef) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            INSERT_BLOB_REF,
            params![b.id, b.incident_id, b.ts_us, b.kind, b.path],
        )?;
        Ok(())
    }
    fn write_trigger_fired(&self, t: &TriggerFired) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            INSERT_TRIGGER_FIRED,
            params![t.ts_us, t.trigger_id, t.incident_id, t.detail],
        )?;
        Ok(())
    }
    fn write_observing_edge(&self, e: &ObservingEdge) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO observing_edge (ts_us, observing, peer_uid, cause) VALUES (?,?,?,?)",
            params![
                e.ts_us,
                e.observing,
                e.peer_uid.map(i64::from),
                e.cause.as_str()
            ],
        )?;
        Ok(())
    }
    fn write_probing_edge(&self, e: &ProbingEdge) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO probing_edge (ts_us, tier, peer_uid, reason) VALUES (?,?,?,?)",
            params![
                e.ts_us,
                e.tier.as_str(),
                e.peer_uid.map(i64::from),
                e.reason.as_str()
            ],
        )?;
        Ok(())
    }
    fn write_experiment(&self, x: &ExperimentRecord) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            // An id is one window's start instant; a second write of the same
            // id is the same window reported again (a retry), so it replaces.
            "INSERT OR REPLACE INTO experiment
               (id, start_us, end_us, tier_before, freeze_start_dir, freeze_end_dir,
                report_json)
             VALUES (?,?,?,?,?,?,?)",
            params![
                x.id,
                x.start_us,
                x.end_us,
                x.tier_before.as_str(),
                x.freeze_start_dir,
                x.freeze_end_dir,
                x.report_json
            ],
        )?;
        Ok(())
    }
    fn experiment(&self, id: &str) -> Result<Option<ExperimentRecord>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, start_us, end_us, tier_before, freeze_start_dir, freeze_end_dir,
                    report_json
             FROM experiment WHERE id = ?",
        )?;
        let mut rows = stmt.query(params![id])?;
        let Some(r) = rows.next()? else {
            return Ok(None);
        };
        let tier: String = r.get(3)?;
        Ok(Some(ExperimentRecord {
            id: r.get(0)?,
            start_us: r.get(1)?,
            end_us: r.get(2)?,
            // A token this build cannot name is the driver's own conversion
            // failure, column named — never a silently substituted tier.
            tier_before: tier.parse().map_err(|e: ParseVerdictError| {
                duckdb::Error::FromSqlConversionFailure(3, duckdb::types::Type::Text, Box::new(e))
            })?,
            freeze_start_dir: r.get(4)?,
            freeze_end_dir: r.get(5)?,
            report_json: r.get(6)?,
        }))
    }
    fn neighbor_lifetimes(
        &self,
        network_key: Option<&str>,
    ) -> Result<Vec<NeighborLifetime>, StoreError> {
        // The same `None -> UNKNOWN_NETWORK` folding the writer applies, so a
        // segment with no readable gateway ARP entry reads back what it wrote
        // rather than nothing.
        let key = network_key.unwrap_or(UNKNOWN_NETWORK);
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT mac, first_seen_us, last_seen_us FROM neighbor WHERE network_key = ?",
        )?;
        let rows = stmt.query_map(params![key], |r| {
            Ok(NeighborLifetime {
                mac: r.get(0)?,
                first_seen_us: r.get(1)?,
                last_seen_us: r.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    fn topology_lifetimes(&self) -> Result<Vec<TopologyLifetime>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT iface, remote_chassis, remote_port, first_seen_us, last_seen_us
             FROM topology_link",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(TopologyLifetime {
                iface: r.get(0)?,
                remote_chassis: r.get(1)?,
                remote_port: r.get(2)?,
                first_seen_us: r.get(3)?,
                last_seen_us: r.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError> {
        Ok(self.conn.lock().unwrap().query_row(sql, [], |r| r.get(0))?)
    }

    fn query_table(&self, sql: &str) -> Result<QueryTable, StoreError> {
        self.query_table_params(sql, &[])
    }

    fn query_prepared(&self, p: &PreparedSql) -> Result<QueryTable, StoreError> {
        self.query_table_params(p.sql(), &p.params_as_dyn())
    }

    fn query_prepared_within(
        &self,
        p: &PreparedSql,
        budget: Duration,
    ) -> Result<QueryTable, StoreError> {
        self.with_conn(|conn| {
            let watchdog = Watchdog::arm(Arc::clone(&self.interrupt), budget);
            let result = run_statement(conn, p.sql(), &p.params_as_dyn());
            let fired = watchdog.disarm();
            match result {
                // The driver reports an interrupt as its own failure, spelled
                // `INTERRUPT`; only that, and only when the watchdog fired, is
                // ours to rename. Any other error at the deadline stays itself.
                Err(StoreError::Duckdb(e)) if fired && e.to_string().contains("INTERRUPT") => {
                    Err(StoreError::Interrupted { budget })
                }
                other => other,
            }
        })
    }

    fn schema_drift(&self) -> Result<Vec<SchemaDrift>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT count(*) FROM information_schema.columns WHERE table_name = ?")?;
        let mut drift = Vec::new();
        for (table, insert) in POSITIONAL_INSERTS {
            let expected = insert.matches('?').count();
            let actual: usize = stmt.query_row(params![table], |r| r.get(0))?;
            if actual != expected {
                drift.push(SchemaDrift {
                    table: (*table).to_string(),
                    expected,
                    actual,
                });
            }
        }
        Ok(drift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use types::{
        GwVerdict, LinkMedium, LinkSample, NeighborObs, NeighborRole, NeighborSource,
        NeighborsSample, NeighborsVerdict, ProxySample, Sample, TcpVerdict,
    };

    /// A neighbours tick for one device, so the upsert rules can be driven.
    fn neighbors_tick(
        ts_us: i64,
        mac: &str,
        ip: &str,
        hostname: Option<&str>,
        source: NeighborSource,
    ) -> Sample {
        Sample::Neighbors(NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            neighbors: vec![NeighborObs {
                mac: mac.into(),
                ip: ip.into(),
                source,
                hostname: hostname.map(str::to_string),
                role: NeighborRole::Unknown,
            }],
            services: Vec::new(),
            heard: None,
        })
    }

    /// The read half of what the upsert writes: the same bounds the row keeps,
    /// scoped to one segment. Without this the fact is recorded and unreachable
    /// to the socket. (realm net-observer, node #43)
    #[test]
    fn neighbor_lifetimes_read_back_the_bounds_the_upsert_kept() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&neighbors_tick(
            1000,
            "11:22:33:44:55:66",
            "192.168.1.5",
            None,
            NeighborSource::Arp,
        ))
        .unwrap();
        s.write_sample(&neighbors_tick(
            2000,
            "11:22:33:44:55:66",
            "192.168.1.9",
            None,
            NeighborSource::Arp,
        ))
        .unwrap();

        let lts = s.neighbor_lifetimes(Some("aa:bb:cc:dd:ee:ff")).unwrap();
        assert_eq!(lts.len(), 1);
        assert_eq!(lts[0].mac, "11:22:33:44:55:66");
        assert_eq!(lts[0].first_seen_us, 1000);
        assert_eq!(lts[0].last_seen_us, 2000);

        // A different segment is a different record — never another network's
        // history rendered as this one's.
        assert!(
            s.neighbor_lifetimes(Some("00:00:00:00:00:00"))
                .unwrap()
                .is_empty()
        );
    }

    /// `None` must read back what `None` wrote: the writer folds an unidentified
    /// segment onto the `unknown` key, and the reader must fold it the same way
    /// or a gatewayless segment silently loses its whole history.
    #[test]
    fn an_unidentified_segment_reads_back_under_the_same_key() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Neighbors(NeighborsSample {
            ts_us: 42,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: None,
            iface: Some("en0".into()),
            neighbors: vec![NeighborObs {
                mac: "11:22:33:44:55:66".into(),
                ip: "192.168.1.5".into(),
                source: NeighborSource::Arp,
                hostname: None,
                role: NeighborRole::Unknown,
            }],
            services: Vec::new(),
            heard: None,
        }))
        .unwrap();
        let lts = s.neighbor_lifetimes(None).unwrap();
        assert_eq!(lts.len(), 1);
        assert_eq!(lts[0].first_seen_us, 42);
    }

    /// The topology read half, against the same upsert that preserves
    /// `first_seen_us`: a second sighting moves last-seen and leaves first-seen.
    #[test]
    fn topology_lifetimes_read_back_first_seen_across_sightings() {
        let s = DuckdbStore::in_memory().unwrap();
        let mut link = TopologyLink {
            iface: "en0".into(),
            remote_chassis: "sw-1".into(),
            remote_port: "Gi0/1".into(),
            remote_system_name: Some("switch".into()),
            capabilities: "bridge".into(),
            learned_via: types::LearnedVia::Lldp,
            ts_us: 500,
        };
        s.write_topology_link(&link).unwrap();
        link.ts_us = 1500;
        s.write_topology_link(&link).unwrap();

        let lts = s.topology_lifetimes().unwrap();
        assert_eq!(lts.len(), 1);
        assert_eq!(lts[0].first_seen_us, 500);
        assert_eq!(lts[0].last_seen_us, 1500);
        assert!(lts[0].bounds(&link));
    }

    /// The whole reason `neighbor` is not a per-tick table: a device seen twice
    /// is ONE row, keeping the moment it was first seen while its address and
    /// last sighting move forward.
    #[test]
    fn a_neighbour_seen_twice_is_one_row_that_keeps_its_first_sighting() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&neighbors_tick(
            1000,
            "11:22:33:44:55:66",
            "192.168.1.5",
            None,
            NeighborSource::Arp,
        ))
        .unwrap();
        s.write_sample(&neighbors_tick(
            2000,
            "11:22:33:44:55:66",
            "192.168.1.9",
            None,
            NeighborSource::Arp,
        ))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor").unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64("SELECT first_seen_us FROM neighbor")
                .unwrap(),
            1000
        );
        assert_eq!(
            s.query_scalar_i64("SELECT last_seen_us FROM neighbor")
                .unwrap(),
            2000
        );
        let t = s.query_table("SELECT ip, oui FROM neighbor").unwrap();
        assert_eq!(t.rows[0], vec!["192.168.1.9", "11:22:33"]);
        // Both ticks are still individually visible as readings.
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor_sample")
                .unwrap(),
            2
        );
    }

    /// A passive ARP read carries no name; it must not erase the name a scan
    /// learned earlier.
    #[test]
    fn a_nameless_sighting_does_not_erase_a_known_hostname() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&neighbors_tick(
            1000,
            "11:22:33:44:55:66",
            "192.168.1.5",
            Some("printer.local"),
            NeighborSource::Mdns,
        ))
        .unwrap();
        s.write_sample(&neighbors_tick(
            2000,
            "11:22:33:44:55:66",
            "192.168.1.5",
            None,
            NeighborSource::Arp,
        ))
        .unwrap();
        let t = s
            .query_table("SELECT hostname, source FROM neighbor")
            .unwrap();
        assert_eq!(t.rows[0], vec!["printer.local", "arp"]);
    }

    /// A listener flush for one announcer, so the service upsert can be driven.
    fn listener_flush(
        ts_us: i64,
        ip: Option<&str>,
        detail: Option<&str>,
        heard: (u32, Option<u32>, u32),
    ) -> Sample {
        use types::{AnnounceKind, AnnouncedService, HeardFrames};
        Sample::Neighbors(NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            neighbors: vec![NeighborObs {
                mac: "11:22:33:44:55:66".into(),
                ip: "192.168.1.6".into(),
                source: NeighborSource::Announce,
                hostname: Some("0xFF.local".into()),
                role: NeighborRole::Unknown,
            }],
            services: vec![AnnouncedService {
                mac: "11:22:33:44:55:66".into(),
                ip: ip.map(str::to_string),
                service: "_companion-link._tcp".into(),
                kind: AnnounceKind::Mdns,
                detail: detail.map(str::to_string),
            }],
            heard: Some(HeardFrames {
                total: heard.0,
                own: heard.1,
                dropped: heard.2,
            }),
        })
    }

    /// A listener flush lands in all three tables: its frame counts on the
    /// reading, the announcer as a neighbour with the `announce` provenance,
    /// and the service as one row per (network, mac, service) that keeps its
    /// first sighting and what an earlier repeat learned (realm net-observer,
    /// node #92).
    #[test]
    fn a_listener_flush_records_its_counts_the_announcer_and_the_service_once() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&listener_flush(
            1000,
            Some("192.168.1.6"),
            Some("0xFF"),
            (7, Some(2), 0),
        ))
        .unwrap();
        // The repeat: no address, no detail, more frames, no own MAC to tell
        // our frames by, and five observations its caps refused.
        s.write_sample(&listener_flush(2000, None, None, (3, None, 5)))
            .unwrap();

        let t = s
            .query_table(
                "SELECT ts_us, heard_frames, own_frames, dropped_obs, neighbor_count \
                 FROM neighbor_sample ORDER BY ts_us",
            )
            .unwrap();
        assert_eq!(t.rows[0], vec!["1000", "7", "2", "0", "1"]);
        // A window with no readable own MAC: heard counted, own NULL — not 0.
        assert_eq!(t.rows[1], vec!["2000", "3", "", "5", "1"]);

        let t = s
            .query_table("SELECT source, hostname, ip FROM neighbor")
            .unwrap();
        assert_eq!(t.rows[0], vec!["announce", "0xFF.local", "192.168.1.6"]);

        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor_service")
                .unwrap(),
            1
        );
        let t = s
            .query_table(
                "SELECT network_key, mac, ip, service, kind, detail, first_seen_us, last_seen_us \
                 FROM neighbor_service",
            )
            .unwrap();
        assert_eq!(
            t.rows[0],
            vec![
                "aa:bb:cc:dd:ee:ff",
                "11:22:33:44:55:66",
                "192.168.1.6",
                "_companion-link._tcp",
                "mdns",
                "0xFF",
                "1000",
                "2000"
            ]
        );
    }

    /// A cache tick counts no frames: NULL, never a zero — so "the listener
    /// heard nothing" and "this reading is not the listener's" stay apart.
    #[test]
    fn a_cache_tick_leaves_the_frame_counts_null() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&neighbors_tick(
            1000,
            "11:22:33:44:55:66",
            "192.168.1.5",
            None,
            NeighborSource::Arp,
        ))
        .unwrap();
        let t = s
            .query_table(
                "SELECT heard_frames IS NULL, own_frames IS NULL, dropped_obs IS NULL \
                 FROM neighbor_sample",
            )
            .unwrap();
        assert_eq!(t.rows[0], vec!["true", "true", "true"]);
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor_service")
                .unwrap(),
            0
        );
    }

    /// A SKIP tick writes its row and no neighbours — the gap stays visible.
    #[test]
    fn a_skip_tick_records_the_reading_without_neighbours() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Neighbors(NeighborsSample {
            ts_us: 1000,
            verdict: NeighborsVerdict::Skip,
            reason: Some("arp(8) unavailable".into()),
            network_key: None,
            iface: None,
            neighbors: Vec::new(),
            services: Vec::new(),
            heard: None,
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor").unwrap(),
            0
        );
        let t = s
            .query_table("SELECT verdict, reason, neighbor_count FROM neighbor_sample")
            .unwrap();
        assert_eq!(t.rows[0], vec!["SKIP", "arp(8) unavailable", "0"]);
    }

    /// A port sighting is one row per (network_key, mac, port), keeping the
    /// moment it was first seen open while its last sighting moves forward.
    #[test]
    fn a_port_seen_twice_is_one_row_that_keeps_its_first_sighting() {
        let s = DuckdbStore::in_memory().unwrap();
        for ts in [1000, 2000] {
            s.write_neighbor_port(&NeighborPort {
                network_key: Some("aa:bb:cc:dd:ee:ff".into()),
                mac: "11:22:33:44:55:66".into(),
                ip: "192.168.1.5".into(),
                port: 445,
                ts_us: ts,
                banner: None,
            })
            .unwrap();
        }
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor_port")
                .unwrap(),
            1
        );
        let t = s
            .query_table("SELECT first_seen_us, last_seen_us, port FROM neighbor_port")
            .unwrap();
        assert_eq!(t.rows[0], vec!["1000", "2000", "445"]);
    }

    /// The banner rung's grab lands on the port row, upserting the banner text
    /// while keeping the first sighting; a later grab that finds nothing keeps
    /// the banner already learned rather than erasing it.
    #[test]
    fn a_banner_upserts_onto_the_port_and_survives_a_later_empty_grab() {
        let s = DuckdbStore::in_memory().unwrap();
        let mut row = NeighborPort {
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            mac: "11:22:33:44:55:66".into(),
            ip: "192.168.1.5".into(),
            port: 22,
            ts_us: 1000,
            banner: None,
        };
        // First: a bare port sighting, no banner yet.
        s.write_neighbor_port(&row).unwrap();
        // Then: the banner rung grabs a banner for the same port.
        row.ts_us = 2000;
        row.banner = Some("SSH-2.0-OpenSSH_9.6".into());
        s.write_neighbor_port(&row).unwrap();
        // Later: a grab that reads nothing must not wipe the stored banner.
        row.ts_us = 3000;
        row.banner = None;
        s.write_neighbor_port(&row).unwrap();

        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor_port")
                .unwrap(),
            1
        );
        let t = s
            .query_table("SELECT first_seen_us, last_seen_us, banner FROM neighbor_port")
            .unwrap();
        assert_eq!(t.rows[0], vec!["1000", "3000", "SSH-2.0-OpenSSH_9.6"]);
    }

    /// A topology link is one row per (iface, remote_chassis, remote_port),
    /// keeping the moment the uplink was first seen while its last sighting moves
    /// forward. A later frame that carried no system name must not erase one an
    /// earlier frame advertised.
    #[test]
    fn a_topology_link_seen_twice_keeps_its_first_sighting_and_coalesces_the_name() {
        use types::LearnedVia;
        let s = DuckdbStore::in_memory().unwrap();
        s.write_topology_link(&TopologyLink {
            iface: "en0".into(),
            remote_chassis: "00:11:22:33:44:55".into(),
            remote_port: "Gi0/1".into(),
            remote_system_name: Some("sw1".into()),
            capabilities: "bridge".into(),
            learned_via: LearnedVia::Lldp,
            ts_us: 1000,
        })
        .unwrap();
        // A later sighting of the same uplink whose frame carried no system name.
        s.write_topology_link(&TopologyLink {
            iface: "en0".into(),
            remote_chassis: "00:11:22:33:44:55".into(),
            remote_port: "Gi0/1".into(),
            remote_system_name: None,
            capabilities: "bridge,router".into(),
            learned_via: LearnedVia::Lldp,
            ts_us: 2000,
        })
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM topology_link")
                .unwrap(),
            1
        );
        let t = s
            .query_table(
                "SELECT first_seen_us, last_seen_us, remote_system_name, capabilities \
                 FROM topology_link",
            )
            .unwrap();
        assert_eq!(t.rows[0], vec!["1000", "2000", "sw1", "bridge,router"]);

        // A THIRD sighting whose frame carried no capabilities TLV (empty string)
        // must NOT blank the previously-learned set — empty is absence, not "none".
        s.write_topology_link(&TopologyLink {
            iface: "en0".into(),
            remote_chassis: "00:11:22:33:44:55".into(),
            remote_port: "Gi0/1".into(),
            remote_system_name: None,
            capabilities: String::new(),
            learned_via: LearnedVia::Lldp,
            ts_us: 3000,
        })
        .unwrap();
        let cap = s
            .query_table("SELECT capabilities FROM topology_link")
            .unwrap();
        assert_eq!(
            cap.rows[0],
            vec!["bridge,router"],
            "empty caps must not erase"
        );
    }

    /// A CVE hypothesis upserts onto its port keeping the first sighting; a later
    /// match with a sharper verdict updates confidence/KEV/CVSS in place, and the
    /// lowercase confidence token round-trips.
    #[test]
    fn a_vuln_upserts_preserving_first_seen_and_round_trips_the_confidence_token() {
        let s = DuckdbStore::in_memory().unwrap();
        let mut row = NeighborVuln {
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            mac: "11:22:33:44:55:66".into(),
            port: 22,
            cve_id: "CVE-2016-6210".into(),
            confidence: "low".into(),
            known_exploited: false,
            cvss: None,
            ts_us: 1000,
        };
        s.write_neighbor_vuln(&row).unwrap();
        // A later run matches the same (port, cve) with more to say.
        row.ts_us = 2000;
        row.confidence = "high".into();
        row.known_exploited = true;
        row.cvss = Some(5.9);
        s.write_neighbor_vuln(&row).unwrap();

        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM neighbor_vuln")
                .unwrap(),
            1
        );
        let t = s
            .query_table(
                "SELECT first_seen_us, last_seen_us, confidence, known_exploited, cvss \
                 FROM neighbor_vuln",
            )
            .unwrap();
        assert_eq!(
            t.rows[0],
            vec!["1000", "2000", "high", "true", "5.9"],
            "first_seen preserved, latest verdict wins, confidence token intact"
        );
    }

    /// An operator scan leaves its own durable trace, separate from the entities
    /// it discovered.
    #[test]
    fn a_scan_is_recorded_as_its_own_row() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_neighbor_scan(&NeighborScan {
            ts_us: 1000,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            method: "sweep".into(),
            target: "192.168.1.0/24".into(),
            found: 7,
            duration_ms: 2500,
            detail: None,
        })
        .unwrap();
        let t = s
            .query_table("SELECT method, target, found FROM neighbor_scan")
            .unwrap();
        assert_eq!(t.rows[0], vec!["sweep", "192.168.1.0/24", "7"]);
    }

    #[test]
    fn write_and_count_link_sample() {
        let s = DuckdbStore::in_memory().unwrap();
        let sample = Sample::Link(LinkSample {
            ts_us: 1000,
            gw: GwVerdict::Fail,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: Some(12.5),
            dhcp_router: Some("10.20.0.1".into()),
            dhcp_dns: None,
            gw_arp_mac: Some("incomplete".into()),
            ssid: Some("cowork".into()),
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
        });
        s.write_sample(&sample).unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM link_sample WHERE gw='FAIL'")
                .unwrap(),
            1
        );
    }

    /// The probe-on-suspicion counts land in their own columns, and an unprobed
    /// tick lands as NULL — "not probed" must stay distinguishable from a
    /// probed tick where nobody answered.
    #[test]
    fn link_sample_lan_counts_round_trip() {
        let s = DuckdbStore::in_memory().unwrap();
        let base = LinkSample {
            ts_us: 1000,
            gw: GwVerdict::Fail,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
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
            lan_probed: Some(3),
            lan_alive: Some(1),
            fakeip_route_if: None,
            singbox_tun_if: None,
        };
        s.write_sample(&Sample::Link(base.clone())).unwrap();
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 2000,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
            ..base
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample WHERE lan_probed = 3 AND lan_alive = 1"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample \
                 WHERE ts_us = 2000 AND lan_probed IS NULL AND lan_alive IS NULL"
            )
            .unwrap(),
            1
        );
    }

    /// The fakeip-pool egress interface lands in its own column; NULL means it
    /// could not be determined, distinguishable from any real interface name.
    #[test]
    fn link_sample_fakeip_route_if_round_trips() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 1000,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
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
            fakeip_route_if: Some("awdl0".into()),
            singbox_tun_if: Some("utun6".into()),
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample \
                 WHERE fakeip_route_if = 'awdl0' AND singbox_tun_if = 'utun6'"
            )
            .unwrap(),
            1
        );
    }

    /// The link's identity pair lands in its own columns, and an
    /// undeterminable identity lands as NULL — "not associated / not readable"
    /// must stay distinguishable from any real address, or a later roam
    /// comparison would read a gap as a change.
    #[test]
    fn link_sample_identity_round_trips() {
        let s = DuckdbStore::in_memory().unwrap();
        let base = LinkSample {
            ts_us: 1000,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: Some("cowork".into()),
            bssid: Some("3c:22:fb:12:34:56".into()),
            if_mac: Some("f0:18:98:0a:0b:0c".into()),
            medium: Some(LinkMedium::Wifi),
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        };
        s.write_sample(&Sample::Link(base.clone())).unwrap();
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 2000,
            bssid: None,
            if_mac: None,
            medium: None,
            ..base.clone()
        }))
        .unwrap();
        // The medium as a lowercase token, and a wired reading — the root
        // reader's dock/undock — distinguishable from a Wi-Fi one and from
        // "not determinable".
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 3000,
            medium: Some(LinkMedium::Wired),
            ..base
        }))
        .unwrap();
        let t = s
            .query_table(
                "SELECT ts_us, ssid, bssid, if_mac, medium FROM link_sample ORDER BY ts_us",
            )
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec![
                    "1000",
                    "cowork",
                    "3c:22:fb:12:34:56",
                    "f0:18:98:0a:0b:0c",
                    "wifi"
                ],
                vec!["2000", "cowork", "", "", ""],
                vec![
                    "3000",
                    "cowork",
                    "3c:22:fb:12:34:56",
                    "f0:18:98:0a:0b:0c",
                    "wired"
                ],
            ]
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample \
                 WHERE ts_us = 2000 AND bssid IS NULL AND if_mac IS NULL AND medium IS NULL"
            )
            .unwrap(),
            1
        );
    }

    /// The DHCP lease pair and the MAC-class fold land in their own columns,
    /// and an unmeasured tick lands as NULL — distinguishable from an
    /// actual zero-length lease or a hardware address (realm net-observer,
    /// node #93 item 1; node #109 item 1).
    #[test]
    fn link_sample_lease_and_mac_class_round_trip() {
        let s = DuckdbStore::in_memory().unwrap();
        let base = LinkSample {
            ts_us: 1000,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: Some("ca:8f:38:b3:12:d3".into()),
            medium: None,
            lease_start_us: Some(1_758_066_844_000_000),
            lease_secs: Some(86400),
            if_mac_private: Some(true),
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        };
        s.write_sample(&Sample::Link(base.clone())).unwrap();
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 2000,
            if_mac: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            ..base
        }))
        .unwrap();
        let t = s
            .query_table(
                "SELECT ts_us, lease_start_us, lease_secs, if_mac_private \
                 FROM link_sample ORDER BY ts_us",
            )
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec!["1000", "1758066844000000", "86400", "true"],
                vec!["2000", "", "", ""],
            ]
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample \
                 WHERE ts_us = 2000 AND lease_start_us IS NULL \
                   AND lease_secs IS NULL AND if_mac_private IS NULL"
            )
            .unwrap(),
            1
        );
    }

    /// A database written by the daemon that shipped `link_sample` with
    /// `medium` but no lease pair or MAC class keeps its seventeen-column
    /// table (`CREATE TABLE IF NOT EXISTS` does nothing to an existing one);
    /// the three new columns are added on open, the old row reads back with
    /// them NULL, and the new daemon's twenty-value insert lands (realm
    /// net-observer, node #93 item 1; node #109 item 1).
    #[test]
    fn an_old_link_table_without_lease_columns_opens_and_keeps_its_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE link_sample (
                ts_us BIGINT, gw VARCHAR, gw_rtt_ms DOUBLE, direct VARCHAR, direct_rtt_ms DOUBLE,
                dhcp_router VARCHAR, dhcp_dns VARCHAR, gw_arp_mac VARCHAR, ssid VARCHAR,
                wifi_capture_present BOOLEAN, lan_probed USMALLINT, lan_alive USMALLINT,
                fakeip_route_if VARCHAR, singbox_tun_if VARCHAR, bssid VARCHAR, if_mac VARCHAR,
                medium VARCHAR);
             INSERT INTO link_sample VALUES
                (1000, 'OK', 1.0, 'OK', 1.0, NULL, NULL, NULL, NULL, false, NULL, NULL,
                 NULL, NULL, NULL, 'f0:18:98:0a:0b:0c', 'wifi');",
        )
        .unwrap();
        let s = DuckdbStore::from_conn(conn).unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample \
                 WHERE ts_us = 1000 AND if_mac = 'f0:18:98:0a:0b:0c' \
                   AND lease_start_us IS NULL AND lease_secs IS NULL \
                   AND if_mac_private IS NULL"
            )
            .unwrap(),
            1,
            "the old row must survive the added columns"
        );
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 2000,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: Some("ca:8f:38:b3:12:d3".into()),
            medium: None,
            lease_start_us: Some(1_758_066_844_000_000),
            lease_secs: Some(86400),
            if_mac_private: Some(true),
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM link_sample \
                 WHERE ts_us = 2000 AND lease_start_us = 1758066844000000 \
                   AND lease_secs = 86400 AND if_mac_private"
            )
            .unwrap(),
            1
        );
    }

    /// The established-flow discriminator lands in its own proxy columns;
    /// NULL = no measurement, distinguishable from a stream that died at 0s.
    #[test]
    fn proxy_sample_established_columns_round_trip() {
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Proxy(ProxySample {
            ts_us: 1000,
            server_ip: "1.1.1.1:443".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: Some(9.0),
            tun_code: Some(204),
            selector: None,
            est_direct_alive: Some(true),
            est_direct_age_s: Some(120),
            est_tun_alive: Some(false),
            est_tun_age_s: Some(45),
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
            urltest_absent_since_us: None,
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM proxy_sample \
                 WHERE est_direct_alive AND est_direct_age_s = 120 \
                   AND NOT est_tun_alive AND est_tun_age_s = 45"
            )
            .unwrap(),
            1
        );
    }

    /// sing-box's own URL test lands in its own proxy columns (realm
    /// net-observer, node #62): the node, the newest entry's delay and its
    /// time, and — for a node whose entry sing-box deleted — since when the
    /// history has read empty; a node never seen tested carries NULLs under
    /// its name, and a row without a reading NULLs throughout — told apart in
    /// SQL.
    #[test]
    fn proxy_sample_urltest_columns_round_trip() {
        let s = DuckdbStore::in_memory().unwrap();
        let row = ProxySample {
            ts_us: 1000,
            server_ip: "1.1.1.1:443".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: Some(9.0),
            tun_code: Some(204),
            selector: Some("vless-out-6".into()),
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: Some("vless-out-6".into()),
            urltest_absent_since_us: Some(700),
        };
        s.write_sample(&Sample::Proxy(row.clone())).unwrap();
        s.write_sample(&Sample::Proxy(ProxySample {
            server_ip: "2.2.2.2:443".into(),
            urltest_ms: Some(0),
            urltest_at_us: Some(1_789_659_600_000_000),
            urltest_node: Some("vless-out-5".into()),
            urltest_absent_since_us: None,
            ..row.clone()
        }))
        .unwrap();
        s.write_sample(&Sample::Proxy(ProxySample {
            server_ip: "3.3.3.3:443".into(),
            urltest_node: Some("vless-out-4".into()),
            urltest_absent_since_us: None,
            ..row.clone()
        }))
        .unwrap();
        s.write_sample(&Sample::Proxy(ProxySample {
            server_ip: "4.4.4.4:443".into(),
            urltest_node: None,
            urltest_absent_since_us: None,
            ..row
        }))
        .unwrap();
        let t = s
            .query_table(
                "SELECT server_ip, urltest_node, urltest_ms, urltest_at_us, \
                        urltest_absent_since_us \
                 FROM proxy_sample ORDER BY server_ip",
            )
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec![
                    "1.1.1.1:443".to_string(),
                    "vless-out-6".to_string(),
                    String::new(),
                    String::new(),
                    "700".to_string(),
                ],
                vec![
                    "2.2.2.2:443".to_string(),
                    "vless-out-5".to_string(),
                    "0".to_string(),
                    "1789659600000000".to_string(),
                    String::new(),
                ],
                vec![
                    "3.3.3.3:443".to_string(),
                    "vless-out-4".to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
                vec![
                    "4.4.4.4:443".to_string(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
            ]
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM proxy_sample \
                 WHERE urltest_node = selector AND tcp = 'OK' \
                   AND ts_us - urltest_absent_since_us >= 300"
            )
            .unwrap(),
            1,
            "the selected node's absent test over a live listener is one SQL predicate"
        );
    }

    /// A database written by the daemon that shipped `proxy_sample` with the
    /// established-stream columns but no URL-test columns keeps its
    /// ten-column table (`CREATE TABLE IF NOT EXISTS` does nothing to an
    /// existing one); the four columns are added on open, the old row reads
    /// back with them NULL, and the new daemon's fourteen-value insert lands.
    #[test]
    fn an_old_proxy_table_without_urltest_columns_opens_and_keeps_its_rows() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE proxy_sample (
                ts_us BIGINT, server_ip VARCHAR, tcp VARCHAR, rtt_ms DOUBLE, tun_code USMALLINT,
                selector VARCHAR, est_direct_alive BOOLEAN, est_direct_age_s UINTEGER,
                est_tun_alive BOOLEAN, est_tun_age_s UINTEGER);
             INSERT INTO proxy_sample VALUES
                (1000, '1.1.1.1:443', 'OK', 9.0, 204, 'vless-out-6', NULL, NULL, NULL, NULL);",
        )
        .unwrap();
        let s = DuckdbStore::from_conn(conn).unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM proxy_sample \
                 WHERE ts_us = 1000 AND tun_code = 204 \
                   AND urltest_ms IS NULL AND urltest_at_us IS NULL AND urltest_node IS NULL \
                   AND urltest_absent_since_us IS NULL"
            )
            .unwrap(),
            1,
            "the old row must survive the added columns"
        );
        s.write_sample(&Sample::Proxy(ProxySample {
            ts_us: 2000,
            server_ip: "1.1.1.1:443".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: Some(9.0),
            tun_code: Some(204),
            selector: Some("vless-out-6".into()),
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
            urltest_ms: Some(202),
            urltest_at_us: Some(1_789_659_600_000_000),
            urltest_node: Some("vless-out-6".into()),
            urltest_absent_since_us: None,
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM proxy_sample \
                 WHERE ts_us = 2000 AND urltest_node = 'vless-out-6' \
                   AND urltest_ms = 202 AND urltest_at_us = 1789659600000000"
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn write_and_count_host_sample() {
        use types::{HostSample, Sample};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Host(HostSample {
            ts_us: 5000,
            load1: 12.0,
            load5: 8.0,
            load15: 4.0,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM host_sample WHERE load1 > 10")
                .unwrap(),
            1
        );
    }

    /// The bound the startup sweep closes stale incidents at: the newest
    /// `ts_us` across every sample table, not merely one of them — a link
    /// sample older than a later host sample must not win (realm net-observer,
    /// node #124).
    #[test]
    fn latest_sample_ts_us_is_the_max_across_every_sample_table() {
        use types::{GwVerdict, HostSample, LinkSample, Sample, TcpVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 1000,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
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
        s.write_sample(&Sample::Host(HostSample {
            ts_us: 5000,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
        }))
        .unwrap();

        assert_eq!(s.latest_sample_ts_us().unwrap(), Some(5000));
    }

    /// A freshly created database file holds no samples at all: the sweep must
    /// read that as `None`, not as a phantom `ts_us` of `0` — the caller falls
    /// back to `now_us()` only for exactly this case (realm net-observer, node
    /// #124).
    #[test]
    fn latest_sample_ts_us_is_none_with_no_samples() {
        let s = DuckdbStore::in_memory().unwrap();
        assert_eq!(s.latest_sample_ts_us().unwrap(), None);
    }

    /// The record volume's usage and the swap in use land in their own host
    /// columns; NULL = not measured, distinguishable from an empty disk or an
    /// idle swap.
    #[test]
    fn host_sample_disk_and_swap_columns_round_trip() {
        use types::{HostSample, Sample};
        let s = DuckdbStore::in_memory().unwrap();
        let base = HostSample {
            ts_us: 1000,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
            disk_used_pct: Some(87.5),
            disk_free_mb: Some(61_440),
            swap_used_mb: Some(1235),
        };
        s.write_sample(&Sample::Host(base.clone())).unwrap();
        s.write_sample(&Sample::Host(HostSample {
            ts_us: 2000,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
            ..base
        }))
        .unwrap();
        let t = s
            .query_table(
                "SELECT ts_us, load1, disk_used_pct, disk_free_mb, swap_used_mb \
                 FROM host_sample ORDER BY ts_us",
            )
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec!["1000", "1", "87.5", "61440", "1235"],
                vec!["2000", "1", "", "", ""],
            ]
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM host_sample \
                 WHERE ts_us = 2000 AND disk_used_pct IS NULL \
                   AND disk_free_mb IS NULL AND swap_used_mb IS NULL"
            )
            .unwrap(),
            1
        );
    }

    /// A database written by the daemon that shipped host samples with only
    /// the load triple keeps its four-column table (CREATE TABLE IF NOT EXISTS
    /// does nothing to an existing one); the disk and swap columns are added
    /// on open, the old rows read back with them NULL, and the new daemon's
    /// seven-value insert lands.
    #[test]
    fn an_old_four_column_host_table_opens_and_keeps_its_rows() {
        use types::{HostSample, Sample};
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE host_sample (ts_us BIGINT, load1 DOUBLE, load5 DOUBLE, load15 DOUBLE);
             INSERT INTO host_sample VALUES (1000, 12.0, 8.0, 4.0);",
        )
        .unwrap();
        let s = DuckdbStore::from_conn(conn).unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM host_sample \
                 WHERE ts_us = 1000 AND load1 = 12 AND disk_used_pct IS NULL \
                   AND disk_free_mb IS NULL AND swap_used_mb IS NULL"
            )
            .unwrap(),
            1,
            "the old row must survive the added columns"
        );
        s.write_sample(&Sample::Host(HostSample {
            ts_us: 2000,
            load1: 1.0,
            load5: 1.0,
            load15: 1.0,
            disk_used_pct: Some(99.5),
            disk_free_mb: Some(120),
            swap_used_mb: Some(0),
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM host_sample \
                 WHERE ts_us = 2000 AND disk_used_pct = 99.5 \
                   AND disk_free_mb = 120 AND swap_used_mb = 0"
            )
            .unwrap(),
            1
        );
    }

    /// One air scan lands as its own row plus one row per access point heard,
    /// joined by `ts_us` — the slice shape the missing BSSID forces.
    #[test]
    fn write_and_read_back_air_sample() {
        use types::{AirObservation, AirSample, AirVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Air(AirSample {
            ts_us: 7000,
            air: AirVerdict::Ok,
            reason: None,
            aps: vec![
                AirObservation {
                    channel: Some(44),
                    channel_band: Some("5ghz".into()),
                    channel_width_mhz: Some(80),
                    phy_mode: Some("802.11a/n/ac/ax".into()),
                    security: Some("wpa2_personal".into()),
                    rssi_dbm: Some(-72),
                    noise_dbm: Some(-95),
                },
                AirObservation {
                    channel: Some(2),
                    channel_band: Some("2ghz".into()),
                    channel_width_mhz: Some(20),
                    phy_mode: Some("802.11b/g/n".into()),
                    security: None,
                    rssi_dbm: Some(-69),
                    noise_dbm: None,
                },
            ],
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT ap_count FROM air_sample WHERE ts_us=7000")
                .unwrap(),
            2
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM air_ap WHERE ts_us=7000 AND channel=44 \
                 AND channel_band='5ghz' AND channel_width_mhz=80 AND rssi_dbm=-72 \
                 AND noise_dbm=-95 AND security='wpa2_personal'"
            )
            .unwrap(),
            1
        );
        // A field the report declined stays NULL rather than becoming a zero.
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM air_ap WHERE ts_us=7000 AND channel=2 \
                 AND security IS NULL AND noise_dbm IS NULL"
            )
            .unwrap(),
            1
        );
    }

    /// The distinction the SKIP rule exists for, at the storage layer: a scan
    /// that could not run leaves a row saying so, while a scan that ran and heard
    /// nobody leaves an `OK` row with no access points. Both are rows; they are
    /// not the same row.
    #[test]
    fn a_skipped_air_scan_is_not_stored_as_clear_air() {
        use types::{AirSample, AirVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Air(AirSample {
            ts_us: 7100,
            air: AirVerdict::Skip,
            reason: Some("Wi-Fi powered off".into()),
            aps: Vec::new(),
        }))
        .unwrap();
        s.write_sample(&Sample::Air(AirSample {
            ts_us: 7200,
            air: AirVerdict::Ok,
            reason: None,
            aps: Vec::new(),
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM air_sample \
                 WHERE ts_us=7100 AND air='SKIP' AND reason='Wi-Fi powered off' AND ap_count=0"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM air_sample WHERE ts_us=7200 AND air='OK' AND ap_count=0"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM air_ap").unwrap(),
            0
        );
    }

    fn connection_row(
        host: Option<&str>,
        dst_ip: Option<&str>,
        process: Option<&str>,
        count: u32,
    ) -> types::ConnectionRow {
        types::ConnectionRow {
            host: host.map(str::to_string),
            dst_ip: dst_ip.map(str::to_string),
            dst_port: Some(443),
            process: process.map(str::to_string),
            network: "tcp".into(),
            chain: Some("vless-out-6".into()),
            count,
            upload: 10 * u64::from(count),
            download: 5000,
        }
    }

    /// Every aggregate row reaches its own columns with the tick's verdict on
    /// it, and an absent fact (no address, no process) is NULL, not an empty
    /// string.
    #[test]
    fn write_and_read_back_connection_sample() {
        use types::{ConnectionsSample, ConnectionsVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Connections(ConnectionsSample {
            ts_us: 8000,
            verdict: ConnectionsVerdict::Ok,
            rows: vec![
                connection_row(Some("claude.ai"), None, None, 3),
                connection_row(
                    Some("o540343.ingest.sentry.io"),
                    Some("35.186.243.94"),
                    Some("stable"),
                    1,
                ),
            ],
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM connection_sample WHERE ts_us=8000")
                .unwrap(),
            2
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM connection_sample WHERE ts_us=8000 AND verdict='OK' \
                 AND host='claude.ai' AND dst_ip IS NULL AND dst_port=443 AND process IS NULL \
                 AND network='tcp' AND chain='vless-out-6' AND count=3 AND upload=30 \
                 AND download=5000"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM connection_sample WHERE ts_us=8000 \
                 AND dst_ip='35.186.243.94' AND process='stable' AND count=1"
            )
            .unwrap(),
            1
        );
        // No marker row when the tick had rows.
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM connection_sample WHERE ts_us=8000 AND network IS NULL"
            )
            .unwrap(),
            0
        );
    }

    /// A multi-row tick lands whole under one transaction — every row present,
    /// one `ts_us`, and the grouped read sees exactly that tick — so a store
    /// that commits per tick has nothing half-written to present.
    #[test]
    fn a_three_row_tick_is_written_whole_and_read_as_one_tick() {
        use types::{ConnectionsGroupBy, ConnectionsSample, ConnectionsVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Connections(ConnectionsSample {
            ts_us: 8300,
            verdict: ConnectionsVerdict::Ok,
            rows: vec![
                connection_row(Some("a.example"), None, None, 1),
                connection_row(Some("b.example"), Some("10.0.0.2"), Some("curl"), 2),
                connection_row(None, Some("10.0.0.3"), None, 1),
            ],
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM connection_sample WHERE ts_us=8300")
                .unwrap(),
            3
        );
        assert_eq!(
            s.query_scalar_i64("SELECT count(DISTINCT ts_us) FROM connection_sample")
                .unwrap(),
            1
        );
        let t = s.connections(ConnectionsGroupBy::Host).unwrap();
        let ts = t.columns.iter().position(|c| c == "ts_us").unwrap();
        assert_eq!(t.rows.len(), 3);
        assert!(t.rows.iter().all(|r| r[ts] == "8300"), "{:?}", t.rows);
    }

    /// The distinction the SKIP rule exists for, at the storage layer: a tick
    /// on which the API did not answer leaves an all-NULL row saying SKIP, a
    /// tick that answered with nothing leaves an all-NULL row saying OK. Both
    /// are rows; they are not the same row.
    #[test]
    fn a_skipped_connections_tick_is_not_stored_as_nothing_talking() {
        use types::{ConnectionsSample, ConnectionsVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Connections(ConnectionsSample {
            ts_us: 8100,
            verdict: ConnectionsVerdict::Skip,
            rows: Vec::new(),
        }))
        .unwrap();
        s.write_sample(&Sample::Connections(ConnectionsSample {
            ts_us: 8200,
            verdict: ConnectionsVerdict::Ok,
            rows: Vec::new(),
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM connection_sample WHERE ts_us=8100 AND verdict='SKIP' \
                 AND host IS NULL AND network IS NULL AND count IS NULL"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM connection_sample WHERE ts_us=8200 AND verdict='OK' \
                 AND host IS NULL AND network IS NULL AND count IS NULL"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM connection_sample")
                .unwrap(),
            2
        );
    }

    /// The raw pair and the derived margin all reach their own columns, and a
    /// SKIP tick lands as a row with its reason — never as a missing row.
    #[test]
    fn write_and_read_back_wifi_sample() {
        use types::{Sample, WifiSample, WifiVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Wifi(WifiSample {
            ts_us: 6000,
            wifi: WifiVerdict::Ok,
            reason: None,
            rssi_dbm: Some(-53),
            noise_dbm: Some(-96),
            snr_db: Some(43),
            tx_rate_mbps: Some(270.0),
            phy_mode: Some("11ax".into()),
            channel: Some(48),
            channel_width_mhz: Some(20),
            channel_band: Some("5ghz".into()),
        }))
        .unwrap();
        s.write_sample(&Sample::Wifi(WifiSample {
            ts_us: 6100,
            wifi: WifiVerdict::Skip,
            reason: Some("not associated".into()),
            rssi_dbm: None,
            noise_dbm: None,
            snr_db: None,
            tx_rate_mbps: None,
            phy_mode: None,
            channel: None,
            channel_width_mhz: None,
            channel_band: None,
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM wifi_sample \
                 WHERE wifi='OK' AND rssi_dbm=-53 AND noise_dbm=-96 AND snr_db=43 \
                 AND phy_mode='11ax' AND channel=48 AND channel_width_mhz=20"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM wifi_sample WHERE wifi='SKIP' AND reason='not associated'"
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn incident_and_asof_query() {
        use types::{BlobRef, GwVerdict, Incident, LinkSample, ProxySample, Sample, TcpVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        // a gw-drop at t=2000 and a proxy tun failure at t=1990 (nearest-before)
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 2000,
            gw: GwVerdict::Fail,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
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
        s.write_sample(&Sample::Proxy(ProxySample {
            ts_us: 1990,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(0),
            selector: Some("a".into()),
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
            urltest_absent_since_us: None,
        }))
        .unwrap();
        s.open_incident(&Incident {
            id: "i1".into(),
            opened_us: 2000,
            closed_us: None,
            trigger_id: "gw-drop".into(),
            signature: "gw=FAIL".into(),
        })
        .unwrap();
        s.close_incident("i1", 2500).unwrap();
        s.write_blob_ref(&BlobRef {
            id: "b1".into(),
            incident_id: "i1".into(),
            ts_us: 2000,
            kind: "pcap".into(),
            path: "/x.pcap".into(),
        })
        .unwrap();
        // ASOF: for each link_sample, the nearest proxy tun_code at or before it
        let n = s
            .query_scalar_i64(
                "SELECT count(*) FROM link_sample l ASOF JOIN proxy_sample p ON l.ts_us >= p.ts_us",
            )
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            s.query_scalar_i64("SELECT closed_us FROM incident WHERE id='i1'")
                .unwrap(),
            2500
        );
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM blob_ref").unwrap(),
            1
        );
    }

    #[test]
    fn list_incidents_returns_rows_newest_first() {
        use types::Incident;
        let s = DuckdbStore::in_memory().unwrap();
        s.open_incident(&Incident {
            id: "old".into(),
            opened_us: 1000,
            closed_us: Some(2000),
            trigger_id: "gw-drop".into(),
            signature: "gw=FAIL".into(),
        })
        .unwrap();
        s.open_incident(&Incident {
            id: "new".into(),
            opened_us: 3000,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        })
        .unwrap();
        let rows = s.list_incidents().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("wedge".into(), 3000, None));
        assert_eq!(rows[1], ("gw-drop".into(), 1000, Some(2000)));
    }

    #[test]
    fn write_observing_edge_round_trips() {
        use types::ObservingEdge;
        let s = DuckdbStore::in_memory().unwrap();
        s.write_observing_edge(&ObservingEdge {
            ts_us: 1000,
            observing: false,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        })
        .unwrap();
        s.write_observing_edge(&ObservingEdge {
            ts_us: 2000,
            observing: true,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        })
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM observing_edge WHERE observing = false AND peer_uid = 501"
            )
            .unwrap(),
            1
        );
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            2
        );
    }

    /// A database file written by the daemon that shipped before `cause`
    /// existed must still open — the CLI's offline `query` path opens whatever
    /// file it is handed. The column is added on open and the pre-existing rows
    /// read back with a NULL cause, which the gap derivation reads as
    /// `control`: what they in fact were.
    #[test]
    fn an_old_three_column_database_opens_and_keeps_its_rows() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use types::ObservingEdge;
        let path = std::env::temp_dir().join(format!(
            "net-observer-schema-{}-{}.duckdb",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path_str = path.to_str().unwrap().to_string();

        // The pre-`cause` table, written by the daemon of the day — and the
        // five-column `experiment` table of the daemon that shipped the window
        // before its freeze directories were recorded.
        {
            let conn = Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE observing_edge (ts_us BIGINT, observing BOOLEAN, peer_uid BIGINT);
                 INSERT INTO observing_edge VALUES (1000, false, 501);
                 CREATE TABLE experiment (
                   id VARCHAR PRIMARY KEY, start_us BIGINT, end_us BIGINT,
                   tier_before VARCHAR, report_json VARCHAR);
                 INSERT INTO experiment VALUES ('experiment-1', 1, 2, 'active', '{}');",
            )
            .unwrap();
        }

        let s = DuckdbStore::open(&path_str).unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM observing_edge WHERE cause IS NULL")
                .unwrap(),
            1,
            "the old row must survive the added column"
        );
        // And the new daemon can keep writing into the migrated table.
        s.write_observing_edge(&ObservingEdge {
            ts_us: 2000,
            observing: true,
            peer_uid: None,
            cause: types::ObservingCause::Startup,
        })
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM observing_edge WHERE cause = 'startup'")
                .unwrap(),
            1
        );
        // The five-column window reads back with no freeze directory — none
        // was recorded — and the migrated table takes a full row.
        let old = s
            .experiment("experiment-1")
            .unwrap()
            .expect("the old window must survive the added columns");
        assert_eq!(old.freeze_start_dir, None);
        assert_eq!(old.freeze_end_dir, None);
        assert_eq!(old.report_json, "{}");
        s.write_experiment(&ExperimentRecord {
            id: "experiment-2".into(),
            start_us: 3,
            end_us: 4,
            tier_before: ProbingTier::Passive,
            freeze_start_dir: Some("/blobs/freeze-experiment-3-start".into()),
            freeze_end_dir: None,
            report_json: "{}".into(),
        })
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM experiment WHERE freeze_start_dir IS NOT NULL"
            )
            .unwrap(),
            1
        );
        drop(s);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn observing_edge_accepts_a_null_peer() {
        use types::ObservingEdge;
        let s = DuckdbStore::in_memory().unwrap();
        s.write_observing_edge(&ObservingEdge {
            ts_us: 1000,
            observing: false,
            peer_uid: None,
            cause: types::ObservingCause::Control,
        })
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM observing_edge WHERE peer_uid IS NULL")
                .unwrap(),
            1
        );
    }

    /// A tier switch lands as one row carrying the tier's token and the peer;
    /// the startup edge (no peer) stores a NULL, so the two are told apart in
    /// SQL exactly like `observing_edge`.
    #[test]
    fn write_probing_edge_round_trips_in_ts_order() {
        use types::{ProbingEdge, ProbingTier};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_probing_edge(&ProbingEdge {
            ts_us: 100,
            tier: ProbingTier::Passive,
            peer_uid: None,
            reason: types::ProbingReason::Startup,
        })
        .unwrap();
        s.write_probing_edge(&ProbingEdge {
            ts_us: 200,
            tier: ProbingTier::Active,
            peer_uid: Some(501),
            reason: types::ProbingReason::Control,
        })
        .unwrap();
        s.write_probing_edge(&ProbingEdge {
            ts_us: 300,
            tier: ProbingTier::Passive,
            peer_uid: Some(501),
            reason: types::ProbingReason::Experiment,
        })
        .unwrap();
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM probing_edge WHERE tier = 'passive' AND peer_uid IS NULL"
            )
            .unwrap(),
            1,
            "the startup default is a peerless edge"
        );
        let t = s
            .query_table("SELECT ts_us, tier, peer_uid, reason FROM probing_edge ORDER BY ts_us")
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec![
                    "100".to_string(),
                    "passive".to_string(),
                    String::new(),
                    "startup".to_string()
                ],
                vec![
                    "200".to_string(),
                    "active".to_string(),
                    "501".to_string(),
                    "control".to_string()
                ],
                vec![
                    "300".to_string(),
                    "passive".to_string(),
                    "501".to_string(),
                    "experiment".to_string()
                ],
            ]
        );
    }

    /// A finished window's record survives a round trip whole — the JSON is
    /// stored as text and read back byte for byte — a second write of the
    /// same id replaces, and an id never written is `None`, never an error.
    #[test]
    fn write_experiment_round_trips_and_replaces() {
        let s = DuckdbStore::in_memory().unwrap();
        assert_eq!(s.experiment("experiment-1").unwrap(), None);
        let first = ExperimentRecord {
            id: "experiment-1".into(),
            start_us: 1,
            end_us: 300_000_001,
            tier_before: ProbingTier::Active,
            freeze_start_dir: Some("/blobs/freeze-experiment-1-start".into()),
            freeze_end_dir: None,
            report_json: r#"{"id":"experiment-1","notes":[]}"#.into(),
        };
        s.write_experiment(&first).unwrap();
        assert_eq!(s.experiment("experiment-1").unwrap(), Some(first.clone()));
        let again = ExperimentRecord {
            report_json: r#"{"id":"experiment-1","notes":["retried"]}"#.into(),
            tier_before: ProbingTier::Passive,
            freeze_end_dir: Some("/blobs/freeze-experiment-1-end".into()),
            ..first
        };
        s.write_experiment(&again).unwrap();
        assert_eq!(s.experiment("experiment-1").unwrap(), Some(again));
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM experiment")
                .unwrap(),
            1
        );
        assert_eq!(s.experiment("experiment-2").unwrap(), None);
    }

    #[test]
    fn observing_edges_read_back_in_ts_order() {
        use types::ObservingEdge;
        let s = DuckdbStore::in_memory().unwrap();
        s.write_observing_edge(&ObservingEdge {
            ts_us: 100,
            observing: false,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        })
        .unwrap();
        s.write_observing_edge(&ObservingEdge {
            ts_us: 200,
            observing: true,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        })
        .unwrap();
        // The pause must read back before the resume: the interval between the
        // two rows is exactly the window in which the daemon collected nothing.
        let t = s
            .query_table("SELECT ts_us, observing FROM observing_edge ORDER BY ts_us")
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec!["100".to_string(), "false".to_string()],
                vec!["200".to_string(), "true".to_string()],
            ]
        );
    }

    #[test]
    fn query_table_returns_columns_and_stringified_rows() {
        use types::{GwVerdict, LinkSample, Sample, TcpVerdict};
        let s = DuckdbStore::in_memory().unwrap();
        s.write_sample(&Sample::Link(LinkSample {
            ts_us: 42,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
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
        let t = s.query_table("SELECT ts_us, gw FROM link_sample").unwrap();
        assert_eq!(t.columns, vec!["ts_us".to_string(), "gw".to_string()]);
        assert_eq!(t.rows, vec![vec!["42".to_string(), "OK".to_string()]]);
    }

    /// A query past its budget is INTERRUPTED — the connection comes back, the
    /// call returns the interruption as itself, and the store is whole
    /// afterwards: the next statement runs, which is what the daemon's writer
    /// needs the moment the diagnosis lets go of the lock. The cross join is
    /// effectively unbounded (10^13 rows), so it can only end by interruption.
    #[test]
    fn a_query_past_its_budget_is_interrupted_and_the_store_survives() {
        let s = DuckdbStore::in_memory().unwrap();
        let slow = PreparedSql::plain(
            "SELECT count(*) FROM range(10000000) t1, range(1000000) t2".to_string(),
        );
        let budget = std::time::Duration::from_millis(100);
        let started = std::time::Instant::now();
        match s.query_prepared_within(&slow, budget) {
            Err(StoreError::Interrupted { budget: b }) => assert_eq!(b, budget),
            other => panic!("expected Interrupted, got {other:?}"),
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the interrupt must land near the deadline, not at the cross join's end"
        );
        // Whole afterwards: no poisoned mutex, no stale interrupt on the next statement.
        let t = s.query_table("SELECT 1 AS one").unwrap();
        assert_eq!(t.rows, vec![vec!["1".to_string()]]);
    }

    /// A query inside its budget answers normally and the watchdog stands down
    /// without ever interrupting — the common case must cost nothing visible.
    #[test]
    fn a_query_inside_its_budget_answers_normally() {
        let s = DuckdbStore::in_memory().unwrap();
        let quick = PreparedSql::plain("SELECT 2 AS two".to_string());
        let t = s
            .query_prepared_within(&quick, std::time::Duration::from_secs(30))
            .unwrap();
        assert_eq!(t.columns, vec!["two".to_string()]);
        assert_eq!(t.rows, vec![vec!["2".to_string()]]);
        // And the flag the watchdog never set does not haunt the next statement.
        assert_eq!(
            s.query_table("SELECT 3").unwrap().rows,
            vec![vec!["3".to_string()]]
        );
    }

    /// A panic under the connection lock is caught and returned as an error, so
    /// the guard is released UNPOISONED: the writer's next `lock().unwrap()`
    /// must not panic the consumer loop because a read blew up.
    #[test]
    fn a_panic_under_the_lock_is_an_error_and_does_not_poison_the_mutex() {
        let s = DuckdbStore::in_memory().unwrap();
        let r: Result<(), StoreError> = s.with_conn(|_| panic!("boom under the lock"));
        match r {
            Err(StoreError::Panicked(m)) => assert!(m.contains("boom"), "{m}"),
            other => panic!("expected Panicked, got {other:?}"),
        }
        assert!(!s.conn.is_poisoned(), "the guard must be released normally");
        assert_eq!(
            s.query_table("SELECT 4").unwrap().rows,
            vec![vec!["4".to_string()]]
        );
    }

    /// A file this build itself shaped has no drift: every positional INSERT
    /// binds exactly the columns `SCHEMA_SQL` gives its table — which also
    /// pins that `information_schema.columns` answers, per table, on this
    /// DuckDB. The pairing guard is what lets the count stand for the table
    /// it names: two four-column tables would otherwise cover each other.
    #[test]
    fn a_store_this_build_shaped_reports_no_schema_drift() {
        for (table, insert) in POSITIONAL_INSERTS {
            assert!(
                insert.starts_with(&format!("INSERT INTO {table} VALUES (")),
                "{table} is paired with another table's statement: {insert}"
            );
        }
        let s = DuckdbStore::in_memory().unwrap();
        assert_eq!(s.schema_drift().unwrap(), Vec::new());
        // The count reads the table, not the whole catalogue.
        assert_eq!(
            s.query_scalar_i64(
                "SELECT count(*) FROM information_schema.columns WHERE table_name = 'host_sample'"
            )
            .unwrap(),
            i64::try_from(INSERT_HOST_SAMPLE.matches('?').count()).unwrap()
        );
    }

    /// The failure observed live (realm net-observer, node #150): a newer
    /// build's ALTER widened a table, and this build's positional INSERT no
    /// longer binds. The drift names that table and only it, with the count
    /// the file has against the count this build writes — and the write it
    /// foretells really is refused.
    #[test]
    fn a_table_a_newer_build_widened_is_reported_as_drift_and_its_writes_are_refused() {
        use types::HostSample;
        let s = DuckdbStore::in_memory().unwrap();
        s.with_conn(|c| Ok(c.execute_batch("ALTER TABLE host_sample ADD COLUMN extra INTEGER")?))
            .unwrap();
        let expected = INSERT_HOST_SAMPLE.matches('?').count();
        assert_eq!(
            s.schema_drift().unwrap(),
            vec![SchemaDrift {
                table: "host_sample".to_string(),
                expected,
                actual: expected + 1,
            }]
        );
        let refused = s.write_sample(&Sample::Host(HostSample {
            ts_us: 1,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
        }));
        match refused {
            Err(StoreError::Duckdb(e)) => assert!(
                e.to_string().contains("columns but"),
                "the binder's own refusal, not another failure: {e}"
            ),
            other => panic!("a widened table must refuse the positional write, got {other:?}"),
        }
    }
}
