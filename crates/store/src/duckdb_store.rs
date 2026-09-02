use crate::{Store, schema::SCHEMA_SQL};
use duckdb::{Connection, params};
use std::sync::Mutex;
use types::{BlobRef, Incident, ObservingEdge, Sample, TriggerFired};

/// `network_key` for a segment whose gateway MAC could not be read. Neighbours
/// still get recorded — under a key that says plainly the network was not
/// identified, rather than being silently merged into someone else's.
const UNKNOWN_NETWORK: &str = "unknown";

/// One open port found on a neighbour, as written to `neighbor_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborPort {
    pub network_key: Option<String>,
    pub mac: String,
    pub ip: String,
    pub port: u16,
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

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StoreError(#[from] pub duckdb::Error);

pub struct DuckdbStore {
    conn: Mutex<Connection>,
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

impl DuckdbStore {
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_conn(Connection::open_in_memory()?)
    }
    pub fn open(path: &str) -> Result<Self, StoreError> {
        Self::from_conn(Connection::open(path)?)
    }
    fn from_conn(conn: Connection) -> Result<Self, StoreError> {
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
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

    /// Run an arbitrary query and return its column names plus stringified rows.
    pub fn query_table(&self, sql: &str) -> Result<QueryTable, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(sql)?;
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

impl Store for DuckdbStore {
    fn write_sample(&self, s: &Sample) -> Result<(), StoreError> {
        let c = self.conn.lock().unwrap();
        match s {
            Sample::Link(l) => c.execute(
                "INSERT INTO link_sample VALUES (?,?,?,?,?,?,?,?,?,?)",
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
                    l.wifi_capture_present
                ],
            )?,
            Sample::Proxy(p) => c.execute(
                "INSERT INTO proxy_sample VALUES (?,?,?,?,?,?)",
                params![
                    p.ts_us,
                    p.server_ip,
                    p.tcp.to_string(),
                    p.rtt_ms,
                    p.tun_code,
                    p.selector
                ],
            )?,
            Sample::Dns(d) => c.execute(
                "INSERT INTO dns_sample VALUES (?,?,?,?,?,?)",
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
                "INSERT INTO route_event VALUES (?,?,?,?)",
                params![r.ts_us, r.kind, r.iface, r.detail],
            )?,
            Sample::Host(h) => c.execute(
                "INSERT INTO host_sample VALUES (?,?,?,?)",
                params![h.ts_us, h.load1, h.load5, h.load15],
            )?,
            Sample::Wifi(w) => c.execute(
                "INSERT INTO wifi_sample VALUES (?,?,?,?,?,?,?,?,?,?,?)",
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
            // Two writes, not one: the tick's own row (so a SKIP leaves a trace)
            // and an upsert per neighbour into the long-lived entity table.
            Sample::Neighbors(n) => {
                c.execute(
                    "INSERT INTO neighbor_sample VALUES (?,?,?,?,?,?)",
                    params![
                        n.ts_us,
                        n.network_key,
                        n.iface,
                        n.verdict.to_string(),
                        n.reason,
                        i32::try_from(n.neighbors.len()).unwrap_or(i32::MAX)
                    ],
                )?;
                let key = n.network_key.as_deref().unwrap_or(UNKNOWN_NETWORK);
                for nb in &n.neighbors {
                    c.execute(
                        // `first_seen_us` is never overwritten — it is the whole
                        // point of the row. A hostname already known is kept when
                        // the new sighting carries none (a passive ARP read never
                        // has one, and must not erase what a scan learned).
                        "INSERT INTO neighbor VALUES (?,?,?,?,?,?,?,?,?)
                         ON CONFLICT (network_key, mac) DO UPDATE SET
                           ip = excluded.ip,
                           iface = excluded.iface,
                           hostname = coalesce(excluded.hostname, neighbor.hostname),
                           source = excluded.source,
                           last_seen_us = excluded.last_seen_us",
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
                0
            }
        };
        Ok(())
    }

    fn write_neighbor_scan(&self, s: &NeighborScan) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO neighbor_scan VALUES (?,?,?,?,?,?,?,?)",
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
            "INSERT INTO neighbor_port VALUES (?,?,?,?,?,?)
             ON CONFLICT (network_key, mac, port) DO UPDATE SET
               ip = excluded.ip,
               last_seen_us = excluded.last_seen_us",
            params![key, p.mac, p.ip, p.port, p.ts_us, p.ts_us],
        )?;
        Ok(())
    }
    fn open_incident(&self, i: &Incident) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO incident VALUES (?,?,?,?,?)",
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
            "INSERT INTO blob_ref VALUES (?,?,?,?,?)",
            params![b.id, b.incident_id, b.ts_us, b.kind, b.path],
        )?;
        Ok(())
    }
    fn write_trigger_fired(&self, t: &TriggerFired) -> Result<(), StoreError> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO trigger_fired VALUES (?,?,?,?)",
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
    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError> {
        Ok(self.conn.lock().unwrap().query_row(sql, [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use types::{
        GwVerdict, LinkSample, NeighborObs, NeighborSource, NeighborsSample, NeighborsVerdict,
        Sample, TcpVerdict,
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
            }],
        })
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
            wifi_capture_present: false,
        });
        s.write_sample(&sample).unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM link_sample WHERE gw='FAIL'")
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
        }))
        .unwrap();
        assert_eq!(
            s.query_scalar_i64("SELECT count(*) FROM host_sample WHERE load1 > 10")
                .unwrap(),
            1
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
            wifi_capture_present: false,
        }))
        .unwrap();
        s.write_sample(&Sample::Proxy(ProxySample {
            ts_us: 1990,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(0),
            selector: Some("a".into()),
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

        // The pre-`cause` table, written by the daemon of the day.
        {
            let conn = Connection::open(&path_str).unwrap();
            conn.execute_batch(
                "CREATE TABLE observing_edge (ts_us BIGINT, observing BOOLEAN, peer_uid BIGINT);
                 INSERT INTO observing_edge VALUES (1000, false, 501);",
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
            wifi_capture_present: false,
        }))
        .unwrap();
        let t = s.query_table("SELECT ts_us, gw FROM link_sample").unwrap();
        assert_eq!(t.columns, vec!["ts_us".to_string(), "gw".to_string()]);
        assert_eq!(t.rows, vec![vec!["42".to_string(), "OK".to_string()]]);
    }
}
