use crate::{Store, schema::SCHEMA_SQL};
use duckdb::{Connection, params};
use std::sync::Mutex;
use types::{BlobRef, Incident, Sample, TriggerFired};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StoreError(#[from] pub duckdb::Error);

pub struct DuckdbStore {
    conn: Mutex<Connection>,
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
        };
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
    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError> {
        Ok(self.conn.lock().unwrap().query_row(sql, [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use types::{GwVerdict, LinkSample, Sample, TcpVerdict};

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
}
