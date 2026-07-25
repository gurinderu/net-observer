//! Read-only data layer for `observer-bar`: a [`Status`] snapshot built from the
//! observer DuckDB store plus a pure [`render_status`] renderer.
//!
//! This is the load-bearing, unit-tested part of the menu-bar app. It never
//! writes: it reads the latest `link_sample`, the latest `proxy_sample`, and the
//! most recent `incident` rows with plain `SELECT`s (each bounded by a SQL
//! `LIMIT`) through the [`QuerySource`] read surface. `QuerySource` is
//! implemented both by the writable [`store::DuckdbStore`] (used by these unit
//! tests) and by the genuinely read-only [`ReadOnlyDb`](crate::db::ReadOnlyDb)
//! (used in production), so the snapshot logic is tested here yet runs against a
//! read-only connection in the real app. Everything worth testing lives here.

use store::{DuckdbStore, QueryTable, StoreError};

/// The minimal read surface [`read_status`] needs: run a query and get back
/// column names plus stringified rows. Implemented by the writable
/// [`store::DuckdbStore`] (tests) and the read-only
/// [`ReadOnlyDb`](crate::db::ReadOnlyDb) (production).
pub trait QuerySource {
    fn query_table(&self, sql: &str) -> Result<QueryTable, StoreError>;
}

impl QuerySource for DuckdbStore {
    fn query_table(&self, sql: &str) -> Result<QueryTable, StoreError> {
        // Delegate to the inherent method (fully qualified to avoid recursing
        // into this trait impl).
        DuckdbStore::query_table(self, sql)
    }
}

/// A read-only glance at the observer store for the menu-bar: the latest
/// link/proxy tick and the most recent incidents.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Status {
    /// Latest `link_sample`, if any.
    pub link: Option<LinkGlance>,
    /// Latest `proxy_sample`, if any.
    pub proxy: Option<ProxyGlance>,
    /// Most recent incidents, newest first.
    pub incidents: Vec<IncidentGlance>,
}

/// The gateway/direct verdicts from the newest `link_sample`.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkGlance {
    pub ts_us: i64,
    pub gw: String,
    pub direct: String,
}

/// The tun code / selector from the newest `proxy_sample`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyGlance {
    pub ts_us: i64,
    pub tun_code: Option<u16>,
    pub selector: Option<String>,
}

/// A single incident row (trigger + open/close timestamps).
#[derive(Debug, Clone, PartialEq)]
pub struct IncidentGlance {
    pub trigger_id: String,
    pub opened_us: i64,
    pub closed_us: Option<i64>,
}

/// Build a [`Status`] snapshot from the store: latest link/proxy tick + up to
/// `incident_limit` most-recent incidents. Read-only — issues only `SELECT`s,
/// each bounded by a SQL `LIMIT` so nothing unbounded is fetched.
pub fn read_status<S: QuerySource>(store: &S, incident_limit: usize) -> Result<Status, StoreError> {
    let link = read_link(store)?;
    let proxy = read_proxy(store)?;
    let incidents = read_incidents(store, incident_limit)?;
    Ok(Status {
        link,
        proxy,
        incidents,
    })
}

fn read_link<S: QuerySource>(store: &S) -> Result<Option<LinkGlance>, StoreError> {
    let table = store
        .query_table("SELECT ts_us, gw, direct FROM link_sample ORDER BY ts_us DESC LIMIT 1")?;
    Ok(table.rows.into_iter().next().map(|row| LinkGlance {
        ts_us: cell(&row, 0).parse().unwrap_or(0),
        gw: cell(&row, 1).to_string(),
        direct: cell(&row, 2).to_string(),
    }))
}

/// Newest `incident_limit` incidents, newest first. The bound is pushed into SQL
/// (`ORDER BY opened_us DESC LIMIT n`) so the store never materializes every
/// incident row on a long-lived forensics DB. `incident_limit` is a trusted
/// numeric constant, so inlining it into the SQL is injection-safe.
fn read_incidents<S: QuerySource>(
    store: &S,
    incident_limit: usize,
) -> Result<Vec<IncidentGlance>, StoreError> {
    let sql = format!(
        "SELECT trigger_id, opened_us, closed_us FROM incident \
         ORDER BY opened_us DESC LIMIT {incident_limit}"
    );
    let table = store.query_table(&sql)?;
    Ok(table
        .rows
        .into_iter()
        .map(|row| IncidentGlance {
            trigger_id: cell(&row, 0).to_string(),
            opened_us: cell(&row, 1).parse().unwrap_or(0),
            // `closed_us` is a nullable BIGINT; SQL NULL renders as "" -> None.
            closed_us: cell(&row, 2).parse().ok(),
        })
        .collect())
}

fn read_proxy<S: QuerySource>(store: &S) -> Result<Option<ProxyGlance>, StoreError> {
    let table = store.query_table(
        "SELECT ts_us, tun_code, selector FROM proxy_sample ORDER BY ts_us DESC LIMIT 1",
    )?;
    Ok(table.rows.into_iter().next().map(|row| ProxyGlance {
        ts_us: cell(&row, 0).parse().unwrap_or(0),
        // `tun_code` is USMALLINT; NULL renders as "" which fails to parse -> None.
        tun_code: cell(&row, 1).parse().ok(),
        selector: opt_cell(cell(&row, 2)),
    }))
}

/// Nth cell of a stringified query row, or `""` if the row is short.
fn cell(row: &[String], i: usize) -> &str {
    row.get(i).map(String::as_str).unwrap_or("")
}

/// `""` (a SQL NULL rendered by the store) becomes `None`.
fn opt_cell(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Render a [`Status`] as a compact, human-readable multi-line glance. Pure over
/// its input so it can be unit-tested without a store or a GUI.
pub fn render_status(status: &Status) -> String {
    let mut out = String::from("observer\n");

    match &status.link {
        Some(l) => out.push_str(&format!(
            "link   gw={} direct={} ts_us={}\n",
            l.gw, l.direct, l.ts_us
        )),
        None => out.push_str("link   (no data)\n"),
    }

    match &status.proxy {
        Some(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "proxy  tun={tun} selector={sel} ts_us={}\n",
                p.ts_us
            ));
        }
        None => out.push_str("proxy  (no data)\n"),
    }

    if status.incidents.is_empty() {
        out.push_str("incidents (none)\n");
    } else {
        out.push_str("incidents\n");
        for i in &status.incidents {
            let closed = i
                .closed_us
                .map(|c| c.to_string())
                .unwrap_or_else(|| "open".to_string());
            out.push_str(&format!(
                "  {} opened={} closed={}\n",
                i.trigger_id, i.opened_us, closed
            ));
        }
    }

    out
}

/// The three-state health of a [`Status`], derived from the gateway verdict and
/// the tun probe code. The single source of truth for both the menu-bar glyph
/// ([`status_glyph`]) and the panel's header dot (`ui::health_dot`), so the two
/// can never drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// No link and no proxy tick yet — nothing to judge.
    NoData,
    /// Gateway `OK` and the tun probe returned HTTP 204.
    Ok,
    /// Gateway or tun is bad / degraded.
    Bad,
}

/// Classify a [`Status`] into a [`Health`]: [`Health::NoData`] when there is no
/// link *and* no proxy tick, [`Health::Ok`] when the gateway verdict is `OK`
/// *and* the tun probe returned HTTP 204 (the healthy reachability code), and
/// [`Health::Bad`] otherwise (gw or tun bad / degraded — e.g. tun `0` = wedge).
/// Pure over its input, so it is unit-tested without a store or a GUI.
pub fn health(status: &Status) -> Health {
    if status.link.is_none() && status.proxy.is_none() {
        return Health::NoData;
    }
    let gw_ok = status.link.as_ref().is_some_and(|l| l.gw == "OK");
    // The tun HTTP 204 probe: 204 means the tunnel path is reachable; anything
    // else (0 = wedge, other codes, or missing) is not healthy.
    let tun_ok = status.proxy.as_ref().and_then(|p| p.tun_code) == Some(204);
    if gw_ok && tun_ok {
        Health::Ok
    } else {
        Health::Bad
    }
}

/// A compact, single-line health glyph for the menu-bar status item, derived
/// from a [`Status`]: a colored dot plus `gw:<verdict> tun:<code>`. Pure over
/// its input so it can be unit-tested without a store or a GUI.
///
/// - green (`🟢`) when the gateway verdict is `OK` and the tun probe returned
///   HTTP 204 (the healthy reachability code),
/// - white (`⚪`) when there is no data at all yet,
/// - red (`🔴`) otherwise (gw or tun is bad / degraded).
///
/// The dot follows [`health`], the shared classifier the panel header dot uses.
pub fn status_glyph(status: &Status) -> String {
    let dot = match health(status) {
        Health::NoData => "⚪",
        Health::Ok => "🟢",
        Health::Bad => "🔴",
    };

    let gw = status
        .link
        .as_ref()
        .map(|l| l.gw.clone())
        .unwrap_or_else(|| "?".to_string());
    let tun = status
        .proxy
        .as_ref()
        .and_then(|p| p.tun_code)
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());

    format!("{dot} gw:{gw} tun:{tun}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use store::Store;
    use types::{GwVerdict, Incident, LinkSample, ProxySample, Sample, TcpVerdict};

    #[test]
    fn glyph_green_when_gw_ok_and_tun_204() {
        let status = Status {
            link: Some(LinkGlance {
                ts_us: 1,
                gw: "OK".into(),
                direct: "OK".into(),
            }),
            proxy: Some(ProxyGlance {
                ts_us: 1,
                tun_code: Some(204),
                selector: Some("auto".into()),
            }),
            ..Default::default()
        };
        assert_eq!(status_glyph(&status), "🟢 gw:OK tun:204");
    }

    #[test]
    fn glyph_red_when_gw_fail_or_tun_wedged() {
        let wedged = Status {
            link: Some(LinkGlance {
                ts_us: 1,
                gw: "OK".into(),
                direct: "OK".into(),
            }),
            proxy: Some(ProxyGlance {
                ts_us: 1,
                tun_code: Some(0),
                selector: None,
            }),
            ..Default::default()
        };
        // tun=0 is the wedge signature -> red, and the raw code must render.
        assert_eq!(status_glyph(&wedged), "🔴 gw:OK tun:0");

        let gw_down = Status {
            link: Some(LinkGlance {
                ts_us: 1,
                gw: "FAIL".into(),
                direct: "OK".into(),
            }),
            proxy: Some(ProxyGlance {
                ts_us: 1,
                tun_code: Some(204),
                selector: None,
            }),
            ..Default::default()
        };
        assert_eq!(status_glyph(&gw_down), "🔴 gw:FAIL tun:204");
    }

    #[test]
    fn glyph_white_and_placeholders_when_no_data() {
        assert_eq!(status_glyph(&Status::default()), "⚪ gw:? tun:-");
    }

    #[test]
    fn health_classifier_matches_glyph_states() {
        // No data at all -> NoData.
        assert_eq!(health(&Status::default()), Health::NoData);

        // gw OK + tun 204 -> Ok.
        let ok = Status {
            link: Some(LinkGlance {
                ts_us: 1,
                gw: "OK".into(),
                direct: "OK".into(),
            }),
            proxy: Some(ProxyGlance {
                ts_us: 1,
                tun_code: Some(204),
                selector: None,
            }),
            ..Default::default()
        };
        assert_eq!(health(&ok), Health::Ok);

        // tun wedged (0) -> Bad, even with gw OK.
        let wedged = Status {
            proxy: Some(ProxyGlance {
                ts_us: 1,
                tun_code: Some(0),
                selector: None,
            }),
            ..ok.clone()
        };
        assert_eq!(health(&wedged), Health::Bad);

        // gw FAIL -> Bad, even with tun 204.
        let gw_down = Status {
            link: Some(LinkGlance {
                ts_us: 1,
                gw: "FAIL".into(),
                direct: "OK".into(),
            }),
            ..ok
        };
        assert_eq!(health(&gw_down), Health::Bad);
    }

    #[test]
    fn render_full_status_lists_link_proxy_and_incidents() {
        let status = Status {
            link: Some(LinkGlance {
                ts_us: 100,
                gw: "OK".into(),
                direct: "OK".into(),
            }),
            proxy: Some(ProxyGlance {
                ts_us: 90,
                tun_code: Some(204),
                selector: Some("auto".into()),
            }),
            incidents: vec![IncidentGlance {
                trigger_id: "wedge".into(),
                opened_us: 80,
                closed_us: None,
            }],
        };
        let out = render_status(&status);
        assert!(out.contains("gw=OK direct=OK"));
        assert!(out.contains("tun=204 selector=auto"));
        assert!(out.contains("wedge opened=80 closed=open"));
    }

    #[test]
    fn render_empty_status_shows_placeholders() {
        let out = render_status(&Status::default());
        assert!(out.contains("link   (no data)"));
        assert!(out.contains("proxy  (no data)"));
        assert!(out.contains("incidents (none)"));
    }

    #[test]
    fn render_shows_dead_tun_code_zero() {
        let status = Status {
            proxy: Some(ProxyGlance {
                ts_us: 1,
                tun_code: Some(0),
                selector: None,
            }),
            ..Default::default()
        };
        // tun=000 is the wedge signature; a zero code must render, not vanish.
        assert!(render_status(&status).contains("tun=0 selector=-"));
    }

    #[test]
    fn read_status_returns_latest_tick_and_recent_incidents() {
        let store = DuckdbStore::in_memory().unwrap();
        // two link ticks; the newer one must win
        for (ts, gw) in [(100i64, GwVerdict::Ok), (200, GwVerdict::Fail)] {
            store
                .write_sample(&Sample::Link(LinkSample {
                    ts_us: ts,
                    gw,
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
        }
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
        for (id, opened, closed) in [
            ("old", 10i64, Some(20i64)),
            ("mid", 30, None),
            ("new", 50, None),
        ] {
            store
                .open_incident(&Incident {
                    id: id.into(),
                    opened_us: opened,
                    closed_us: closed,
                    trigger_id: id.into(),
                    signature: "sig".into(),
                })
                .unwrap();
        }

        let status = read_status(&store, 2).unwrap();

        let link = status.link.expect("link present");
        assert_eq!(link.ts_us, 200);
        assert_eq!(link.gw, "FAIL");

        let proxy = status.proxy.expect("proxy present");
        assert_eq!(proxy.ts_us, 150);
        assert_eq!(proxy.tun_code, Some(0));
        assert_eq!(proxy.selector.as_deref(), Some("auto"));

        // limit=2, newest first
        assert_eq!(status.incidents.len(), 2);
        assert_eq!(status.incidents[0].trigger_id, "new");
        assert_eq!(status.incidents[1].trigger_id, "mid");
    }

    #[test]
    fn read_status_on_empty_store_is_all_none() {
        let store = DuckdbStore::in_memory().unwrap();
        let status = read_status(&store, 10).unwrap();
        assert_eq!(status, Status::default());
        assert!(status.link.is_none());
        assert!(status.proxy.is_none());
        assert!(status.incidents.is_empty());
    }
}
