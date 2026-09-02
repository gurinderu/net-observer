//! Canned diagnosis queries: turning the record into "which layer failed".
//!
//! The daemon writes evidence into one table per subsystem; the conclusion is
//! drawn by correlating them at a moment in time. `ARCHITECTURE.md` states the
//! rules in prose — this module is those rules expressed as SQL, so that the
//! reading of an outage is reproducible instead of re-derived by hand.
//!
//! The rules, verbatim from the docs:
//!
//! - `gw=FAIL` ⇒ the local network or Wi-Fi died: infrastructure, not us.
//! - `gw=OK`, `direct=OK`, `vless=OK`, `tun=000` ⇒ the proxy is wedged; a
//!   restart cures it.
//! - `vless=FAIL` with the rest OK ⇒ that proxy server is dead or blocked from
//!   this path.
//! - `tun=000` **with `load1` in the tens** ⇒ host starvation, NOT a wedge: a
//!   restart does not cure it and tears down live flows.
//! - A `.ru` name answered from the fakeip range is ALWAYS a bug.
//! - `SKIP` means the probe did not run — neither health nor fault.
//!
//! ## How `SKIP` is handled
//!
//! No query here counts a `SKIP` as healthy or as failed. Wherever a layer's
//! verdict is `SKIP` (or the layer has no sample at all at that moment), the
//! diagnosis is `unknown`: the record does not say. That is deliberate — a
//! confident wrong answer costs more than an admitted gap. The same holds for a
//! missing `load1`: without it a dead tun cannot be told apart from starvation,
//! so the verdict is `unknown` rather than a guess at `wedge`.
//!
//! ## Layer labels
//!
//! | label | meaning |
//! | --- | --- |
//! | `link` | gateway `FAIL`/`NOGW` — local network or Wi-Fi |
//! | `vless` | the proxy server is unreachable from this path |
//! | `proxy` | tun dead while every layer under it is healthy — a wedge |
//! | `host` | tun dead under host load — starvation, not a wedge |
//! | `healthy` | every measured layer answered |
//! | `unknown` | a layer did not report (`SKIP`, no sample, no `load1`) |
//! | `gap` | the moment asked about lies inside an operator pause |
//!
//! ## Observation gaps
//!
//! A paused daemon collects nothing at all — the one sanctioned exception to
//! "SKIP, never silence" — and brackets that silence with an `observing_edge`
//! row per pause/resume edge. The write side bounds the gap; these queries are
//! the read side, and without them an `ASOF JOIN` would honestly hand back the
//! newest sample *before* the pause as if it were a reading taken at the moment
//! asked about. It is not one, and nothing in the row would say so.
//!
//! So a moment inside a gap gets no measurement at all. Every per-moment query
//! blanks its measurement columns, reports `layer = 'gap'`, and carries the
//! bounds of the gap (`gap_opened_us`, `gap_closed_us`) so the reader can see
//! which silence they landed in. `gateway_ramp` refuses the slope instead: a
//! least-squares fit across an interval that was never sampled is a line drawn
//! through absent data, so its `slope_ms_per_s` is `NULL` whenever the window
//! overlaps a gap, and `observation_gap_us` says by how much.
//!
//! The edge sequence is not assumed to be well-formed pairs. The observing
//! state is process-scoped and never persisted, so the record can begin
//! mid-story:
//!
//! - A resume with no preceding pause opens no gap: only a `false` edge does.
//! - A pause with no resume row closes where the record shows collection
//!   demonstrably resumed anyway — at the first sample of any stream written
//!   after it — because a daemon that died while paused comes back collecting
//!   and writes no resume edge. Only when nothing at all follows the pause does
//!   the gap stay open-ended, which is the truth: the record ends there.
//!
//! ## Correlation
//!
//! Streams have their own cadences, so correlation is by DuckDB `ASOF JOIN`:
//! "the nearest proxy/host sample at or before this link sample". That is the
//! join the whole storage choice was made for.

use crate::{DuckdbStore, QueryTable, StoreError};

/// Host `load1` above which a dead tun reads as starvation rather than a wedge.
///
/// Mirrors the daemon's `STARVATION_LOAD`, and like the `starvation` trigger the
/// comparison is strict (`load1 > threshold`).
pub const DEFAULT_STARVATION_LOAD: f64 = 10.0;

/// Longest gap between two consecutive tun-dead proxy ticks that still counts as
/// one episode (30 s — several polling ticks).
pub const DEFAULT_EPISODE_GAP_US: i64 = 30_000_000;

/// How far back the gateway ramp is plotted before a drop, by default (2 min —
/// comfortably longer than the ~40 s climb of the coworking gateway signature).
pub const DEFAULT_RAMP_WINDOW_US: i64 = 120_000_000;

/// One row per proxy polling tick, collapsing the per-server rows.
///
/// `vless` is `OK` if any server answered, `FAIL` if none did and at least one
/// failed, `SKIP` if the probe did not run, `NULL` if the tick has no verdict at
/// all. `tun_code` is tun-wide, so any non-null row of the tick carries it.
const PROXY_TICK_CTE: &str = "\
proxy_tick AS (
  SELECT ts_us,
         CASE WHEN max(CASE WHEN tcp = 'OK' THEN 1 ELSE 0 END) = 1 THEN 'OK'
              WHEN max(CASE WHEN tcp = 'FAIL' THEN 1 ELSE 0 END) = 1 THEN 'FAIL'
              WHEN max(CASE WHEN tcp = 'SKIP' THEN 1 ELSE 0 END) = 1 THEN 'SKIP'
              ELSE NULL END AS vless,
         max(tun_code) AS tun_code
  FROM proxy_sample
  GROUP BY ts_us
)";

/// Every stream's tick timestamps in one column — the evidence that the daemon
/// was collecting at all. Used to close a pause that has no resume edge.
const SAMPLE_TS_CTE: &str = "\
sample_ts AS (
  SELECT ts_us FROM link_sample
  UNION ALL SELECT ts_us FROM proxy_sample
  UNION ALL SELECT ts_us FROM host_sample
  UNION ALL SELECT ts_us FROM dns_sample
  UNION ALL SELECT ts_us FROM route_event
)";

/// One row per interval in which the daemon deliberately collected nothing.
///
/// A gap opens at each `observing = false` edge and is half-open
/// `[gap_opened_us, gap_closed_us)`: the pause instant is inside it, the resume
/// instant is not. It closes at whichever comes first — the next resume edge, or
/// the first sample of any stream — and `gap_closed_us` is `NULL` when neither
/// exists, meaning the record simply ends inside the pause.
const OBSERVATION_GAP_CTE: &str = "\
observation_gap AS (
  SELECT p.ts_us AS gap_opened_us, min(e.ts_us) AS gap_closed_us
  FROM (SELECT ts_us FROM observing_edge WHERE NOT observing) p
  LEFT JOIN (
    SELECT ts_us FROM observing_edge WHERE observing
    UNION ALL SELECT ts_us FROM sample_ts
  ) e ON e.ts_us > p.ts_us
  GROUP BY p.ts_us
)";

/// The gap containing `ts_expr`, or no row at all. At most one row.
fn gap_at_cte(ts_expr: &str) -> String {
    format!(
        "gap_at AS (
  SELECT gap_opened_us, gap_closed_us
  FROM observation_gap
  WHERE gap_opened_us <= {ts_expr}
    AND (gap_closed_us IS NULL OR gap_closed_us > {ts_expr})
  ORDER BY gap_opened_us DESC
  LIMIT 1
)"
    )
}

/// **Observation gaps** — every interval the operator paused collection for.
///
/// The read side of the bracketed silence: one row per gap, open-ended
/// (`gap_closed_us` `NULL`) only when the record ends inside the pause.
pub fn observation_gaps_sql() -> String {
    format!(
        "WITH {SAMPLE_TS_CTE},
{OBSERVATION_GAP_CTE}
SELECT gap_opened_us, gap_closed_us FROM observation_gap ORDER BY gap_opened_us"
    )
}

/// The `WITH` clause shared by the per-moment queries: one row per link sample,
/// carrying every layer's state as of that moment plus the diagnosed layer, and
/// the observation gaps that say when such a row is not a reading at all.
fn layer_state_with(load_threshold: f64) -> String {
    format!(
        "WITH {PROXY_TICK_CTE},
layer_state AS (
  SELECT l.ts_us,
         l.gw,
         l.gw_rtt_ms,
         l.direct,
         p.vless,
         p.tun_code,
         h.load1,
         CASE
           -- The local network died: infrastructure, not us.
           WHEN l.gw IN ('FAIL', 'NOGW') THEN 'link'
           -- A probe that did not run is neither health nor fault.
           WHEN l.gw = 'SKIP' OR l.direct = 'SKIP' THEN 'unknown'
           WHEN p.vless IS NULL OR p.vless = 'SKIP' OR p.tun_code IS NULL THEN 'unknown'
           -- The proxy server is dead or blocked from this path.
           WHEN p.vless = 'FAIL' THEN 'vless'
           -- tun=000, but without load there is no telling wedge from starvation.
           WHEN p.tun_code = 0 AND h.load1 IS NULL THEN 'unknown'
           WHEN p.tun_code = 0 AND h.load1 > {load_threshold} THEN 'host'
           WHEN p.tun_code = 0 THEN 'proxy'
           WHEN l.gw <> 'OK' OR l.direct <> 'OK' THEN 'unknown'
           ELSE 'healthy'
         END AS layer
  FROM link_sample l
  ASOF LEFT JOIN proxy_tick p ON l.ts_us >= p.ts_us
  ASOF LEFT JOIN host_sample h ON l.ts_us >= h.ts_us
),
{SAMPLE_TS_CTE},
{OBSERVATION_GAP_CTE}"
    )
}

/// **Verdict at a moment** — the state of every layer as of `ts_us`, and the
/// layer the record blames.
///
/// Takes the newest link sample at or before `ts_us` and correlates the nearest
/// proxy tick and host sample at or before it.
///
/// Unless `ts_us` falls inside an observation gap, in which case there is no
/// such state to report and the query refuses to invent one: the single row it
/// returns carries `layer = 'gap'`, every measurement column `NULL`, and the
/// bounds of the gap in `gap_opened_us` / `gap_closed_us`. The newest sample
/// before the pause is a reading from before the pause, not a reading at
/// `ts_us`, and it is withheld rather than labelled.
pub fn verdict_at_sql(ts_us: i64, load_threshold: f64) -> String {
    format!(
        "{},
{}
SELECT ts_us, gw, gw_rtt_ms, direct, vless, tun_code, load1, layer,
       CAST(NULL AS BIGINT) AS gap_opened_us, CAST(NULL AS BIGINT) AS gap_closed_us
FROM (
  SELECT ts_us, gw, gw_rtt_ms, direct, vless, tun_code, load1, layer
  FROM layer_state
  WHERE ts_us <= {ts_us}
  ORDER BY ts_us DESC
  LIMIT 1
)
WHERE NOT EXISTS (SELECT 1 FROM gap_at)
UNION ALL
SELECT CAST(NULL AS BIGINT), CAST(NULL AS VARCHAR), CAST(NULL AS DOUBLE),
       CAST(NULL AS VARCHAR), CAST(NULL AS VARCHAR), CAST(NULL AS USMALLINT),
       CAST(NULL AS DOUBLE), 'gap', gap_opened_us, gap_closed_us
FROM gap_at",
        layer_state_with(load_threshold),
        gap_at_cte(&ts_us.to_string())
    )
}

/// **Incident with its context** — for every incident, the layer state at or
/// just before it opened.
///
/// An incident whose `opened_us` falls inside an observation gap gets no
/// context at all: its state columns are `NULL`, its `layer` is `'gap'`, and
/// `gap_opened_us` / `gap_closed_us` bound the silence it opened in. The layer
/// state from before the pause is not context for it.
pub fn incident_context_sql(load_threshold: f64) -> String {
    format!(
        "{},
ctx AS (
  SELECT i.id,
         i.trigger_id,
         i.opened_us,
         i.closed_us,
         s.ts_us AS state_ts_us,
         s.gw,
         s.direct,
         s.vless,
         s.tun_code,
         s.load1,
         s.layer
  FROM incident i
  ASOF LEFT JOIN layer_state s ON i.opened_us >= s.ts_us
)
SELECT c.id,
       c.trigger_id,
       c.opened_us,
       c.closed_us,
       CASE WHEN g.gap_opened_us IS NULL THEN c.state_ts_us END AS state_ts_us,
       CASE WHEN g.gap_opened_us IS NULL THEN c.gw END AS gw,
       CASE WHEN g.gap_opened_us IS NULL THEN c.direct END AS direct,
       CASE WHEN g.gap_opened_us IS NULL THEN c.vless END AS vless,
       CASE WHEN g.gap_opened_us IS NULL THEN c.tun_code END AS tun_code,
       CASE WHEN g.gap_opened_us IS NULL THEN c.load1 END AS load1,
       CASE WHEN g.gap_opened_us IS NULL THEN c.layer ELSE 'gap' END AS layer,
       g.gap_opened_us,
       g.gap_closed_us
FROM ctx c
LEFT JOIN observation_gap g
  ON g.gap_opened_us <= c.opened_us
 AND (g.gap_closed_us IS NULL OR g.gap_closed_us > c.opened_us)
ORDER BY c.opened_us",
        layer_state_with(load_threshold)
    )
}

/// **Wedge vs starvation** — the discriminator the project paid nine hours to
/// learn, on 2026-07-27.
///
/// Groups contiguous `tun=000` proxy ticks (gap ≤ `gap_us`) into episodes and
/// names each one:
///
/// - `link` — the gateway was down through it: not a proxy fault at all;
/// - `vless` — the proxy server was unreachable: a restart is not the cure;
/// - `starvation` — `load1 > load_threshold`: a restart does NOT cure it and
///   tears down live flows;
/// - `wedge` — every layer under the tun was healthy and the host was idle: a
///   restart cures it;
/// - `unknown` — no `load1` (or no link sample) covering the episode, so the
///   record cannot tell the two apart.
///
/// Ticks with a `NULL` `tun_code` (the probe did not run) are not episodes.
pub fn wedge_vs_starvation_sql(load_threshold: f64, gap_us: i64) -> String {
    format!(
        "WITH {PROXY_TICK_CTE},
dead AS (
  SELECT ts_us, vless FROM proxy_tick WHERE tun_code = 0
),
marked AS (
  SELECT ts_us,
         vless,
         CASE WHEN lag(ts_us) OVER (ORDER BY ts_us) IS NULL
                OR ts_us - lag(ts_us) OVER (ORDER BY ts_us) > {gap_us}
              THEN 1 ELSE 0 END AS starts_episode
  FROM dead
),
grouped AS (
  SELECT ts_us, vless, sum(starts_episode) OVER (ORDER BY ts_us) AS episode
  FROM marked
),
ctx AS (
  SELECT g.episode, g.ts_us, g.vless, h.load1, l.gw, l.direct
  FROM grouped g
  ASOF LEFT JOIN host_sample h ON g.ts_us >= h.ts_us
  ASOF LEFT JOIN link_sample l ON g.ts_us >= l.ts_us
)
SELECT episode,
       min(ts_us) AS opened_us,
       max(ts_us) AS closed_us,
       count(*) AS ticks,
       max(load1) AS max_load1,
       CASE
         WHEN max(CASE WHEN gw IN ('FAIL', 'NOGW') THEN 1 ELSE 0 END) = 1 THEN 'link'
         WHEN max(CASE WHEN vless = 'FAIL' THEN 1 ELSE 0 END) = 1 THEN 'vless'
         WHEN max(CASE WHEN coalesce(gw, 'MISSING') <> 'OK'
                         OR coalesce(direct, 'MISSING') <> 'OK'
                       THEN 1 ELSE 0 END) = 1 THEN 'unknown'
         WHEN count(load1) = 0 THEN 'unknown'
         WHEN max(load1) > {load_threshold} THEN 'starvation'
         ELSE 'wedge'
       END AS verdict
FROM ctx
GROUP BY episode
ORDER BY opened_us"
    )
}

/// **Gateway drops** — the first link sample of each run of `FAIL`/`NOGW`.
///
/// `SKIP` ticks are removed before the sequence is walked, so an operator's
/// quiet run cannot manufacture an edge. Feed a `ts_us` from here to
/// [`gateway_ramp_sql`].
pub const GW_DROPS_SQL: &str = "\
SELECT ts_us, gw
FROM (
  SELECT ts_us, gw, lag(gw) OVER (ORDER BY ts_us) AS prev
  FROM link_sample
  WHERE gw <> 'SKIP'
)
WHERE gw IN ('FAIL', 'NOGW')
  AND (prev IS NULL OR prev NOT IN ('FAIL', 'NOGW'))
ORDER BY ts_us";

/// **Gateway ramp** — gateway RTT over the `window_us` before a drop, so the
/// ~40 s linear climb of the coworking gateway is visible as data.
///
/// Every row of the window is listed, `SKIP` and `FAIL` ticks included (their
/// `gw_rtt_ms` is `NULL`), but the least-squares fit is taken over the answered
/// (`gw = 'OK'`) samples only: a probe that did not run contributes no slope.
/// `slope_ms_per_s` is repeated on each row; a coworking ramp shows a clearly
/// positive slope over a handful of `fitted_samples`, a clean drop ~0.
///
/// If any part of the window falls inside an observation gap, there is no
/// slope: a fit across an interval that was never sampled is a line through
/// absent data, and it would read exactly like a measured climb. Both
/// `slope_ms_per_s` and `fitted_samples` come back `NULL`, and
/// `observation_gap_us` — present on every row — says how many microseconds of
/// the window the daemon was paused for. The listed rows are still real
/// samples, so the shape can be read by eye; only the number is withheld.
pub fn gateway_ramp_sql(drop_ts_us: i64, window_us: i64) -> String {
    format!(
        "WITH {SAMPLE_TS_CTE},
{OBSERVATION_GAP_CTE},
win AS (
  SELECT ts_us, gw, gw_rtt_ms
  FROM link_sample
  WHERE ts_us <= {drop_ts_us} AND ts_us >= {drop_ts_us} - {window_us}
),
fit AS (
  SELECT regr_slope(gw_rtt_ms, ts_us) * 1000000.0 AS slope_ms_per_s,
         count(gw_rtt_ms) AS fitted_samples
  FROM win
  WHERE gw = 'OK'
),
overlap AS (
  SELECT CAST(coalesce(sum(greatest(
           0,
           least(coalesce(gap_closed_us, {drop_ts_us}), {drop_ts_us})
             - greatest(gap_opened_us, {drop_ts_us} - {window_us})
         )), 0) AS BIGINT) AS observation_gap_us
  FROM observation_gap
)
SELECT w.ts_us,
       {drop_ts_us} - w.ts_us AS us_before_drop,
       w.gw,
       w.gw_rtt_ms,
       CASE WHEN o.observation_gap_us = 0 THEN f.slope_ms_per_s END AS slope_ms_per_s,
       CASE WHEN o.observation_gap_us = 0 THEN f.fitted_samples END AS fitted_samples,
       o.observation_gap_us
FROM win w, fit f, overlap o
ORDER BY w.ts_us"
    )
}

/// **Fakeip on a `.ru` name** — always a bug, per the oracle.
///
/// Matches the `fakeip` trigger's name rule: the short `ru` probe label or a
/// fully-qualified `*.ru` name. Any other verdict, `SKIP` included, is not a hit.
pub const FAKEIP_BUGS_SQL: &str = "\
SELECT ts_us, probe, server, ip, rtt_ms
FROM dns_sample
WHERE verdict = 'FAKEIP' AND (probe = 'ru' OR probe LIKE '%.ru')
ORDER BY ts_us";

impl DuckdbStore {
    /// Run [`verdict_at_sql`] with [`DEFAULT_STARVATION_LOAD`].
    pub fn verdict_at(&self, ts_us: i64) -> Result<QueryTable, StoreError> {
        self.query_table(&verdict_at_sql(ts_us, DEFAULT_STARVATION_LOAD))
    }

    /// Run [`incident_context_sql`] with [`DEFAULT_STARVATION_LOAD`].
    pub fn incident_context(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&incident_context_sql(DEFAULT_STARVATION_LOAD))
    }

    /// Run [`wedge_vs_starvation_sql`] with the defaults.
    pub fn wedge_vs_starvation(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&wedge_vs_starvation_sql(
            DEFAULT_STARVATION_LOAD,
            DEFAULT_EPISODE_GAP_US,
        ))
    }

    /// Run [`GW_DROPS_SQL`].
    pub fn gw_drops(&self) -> Result<QueryTable, StoreError> {
        self.query_table(GW_DROPS_SQL)
    }

    /// Run [`gateway_ramp_sql`] with [`DEFAULT_RAMP_WINDOW_US`].
    pub fn gateway_ramp(&self, drop_ts_us: i64) -> Result<QueryTable, StoreError> {
        self.query_table(&gateway_ramp_sql(drop_ts_us, DEFAULT_RAMP_WINDOW_US))
    }

    /// Run [`FAKEIP_BUGS_SQL`].
    pub fn fakeip_bugs(&self) -> Result<QueryTable, StoreError> {
        self.query_table(FAKEIP_BUGS_SQL)
    }

    /// Run [`observation_gaps_sql`].
    pub fn observation_gaps(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&observation_gaps_sql())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, Incident, LinkSample, ObservingEdge,
        ProxySample, Sample, TcpVerdict,
    };

    const SEC: i64 = 1_000_000;

    /// A link tick. `rtt` is `None` for anything that did not answer.
    fn link(s: &DuckdbStore, ts_us: i64, gw: GwVerdict, rtt: Option<f64>, direct: TcpVerdict) {
        s.write_sample(&Sample::Link(LinkSample {
            ts_us,
            gw,
            gw_rtt_ms: rtt,
            direct,
            direct_rtt_ms: None,
            dhcp_router: Some("10.20.0.1".into()),
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: Some("cowork".into()),
            wifi_capture_present: false,
        }))
        .unwrap();
    }

    fn proxy(s: &DuckdbStore, ts_us: i64, tcp: TcpVerdict, tun: Option<u16>) {
        s.write_sample(&Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "1.2.3.4".into(),
            tcp,
            rtt_ms: None,
            tun_code: tun,
            selector: Some("auto".into()),
        }))
        .unwrap();
    }

    fn host(s: &DuckdbStore, ts_us: i64, load1: f64) {
        s.write_sample(&Sample::Host(HostSample {
            ts_us,
            load1,
            load5: load1,
            load15: load1,
        }))
        .unwrap();
    }

    fn dns(s: &DuckdbStore, ts_us: i64, probe: &str, verdict: DnsVerdict, ip: Option<&str>) {
        s.write_sample(&Sample::Dns(DnsSample {
            ts_us,
            probe: probe.into(),
            server: "sb".into(),
            verdict,
            ip: ip.map(str::to_string),
            rtt_ms: Some(3.0),
        }))
        .unwrap();
    }

    /// One healthy tick of every stream at `ts_us`.
    fn healthy_tick(s: &DuckdbStore, ts_us: i64) {
        link(s, ts_us, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(s, ts_us, TcpVerdict::Ok, Some(204));
        host(s, ts_us, 1.5);
    }

    /// One pause/resume boundary, as the daemon's control socket writes it.
    fn edge(s: &DuckdbStore, ts_us: i64, observing: bool) {
        s.write_observing_edge(&ObservingEdge {
            ts_us,
            observing,
            peer_uid: Some(501),
        })
        .unwrap();
    }

    fn cell(t: &QueryTable, row: usize, column: &str) -> String {
        let i = t
            .columns
            .iter()
            .position(|c| c == column)
            .unwrap_or_else(|| panic!("no column {column} in {:?}", t.columns));
        t.rows[row][i].clone()
    }

    // ---- 1. verdict at a moment -------------------------------------------

    #[test]
    fn verdict_at_blames_the_link_when_the_gateway_died() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        // The gateway stops answering while everything above it is still fine.
        link(&s, 20 * SEC, GwVerdict::Fail, None, TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(204));
        host(&s, 20 * SEC, 1.5);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "layer"), "link");
        assert_eq!(cell(&t, 0, "gw"), "FAIL");
    }

    #[test]
    fn verdict_at_blames_the_proxy_on_a_wedge() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(0));
        host(&s, 20 * SEC, 1.2);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "proxy");
    }

    /// The negative twin of the case above: the identical `tun=000` shape, but
    /// under load. It must NOT read as a wedge.
    #[test]
    fn verdict_at_blames_the_host_when_the_same_shape_runs_under_load() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(0));
        host(&s, 20 * SEC, 31.0);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "host");
        assert_ne!(cell(&t, 0, "layer"), "proxy");
    }

    #[test]
    fn verdict_at_blames_the_vless_server_when_only_it_is_down() {
        let s = DuckdbStore::in_memory().unwrap();
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Fail, Some(0));
        host(&s, 20 * SEC, 1.0);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "vless");
    }

    #[test]
    fn verdict_at_calls_a_whole_healthy_tick_healthy() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        let t = s.verdict_at(10 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "healthy");
    }

    /// `SKIP` is neither health nor fault: it must not be blamed and must not be
    /// cleared.
    #[test]
    fn verdict_at_reports_unknown_for_skipped_probes() {
        let s = DuckdbStore::in_memory().unwrap();
        // Gateway echo suppressed; everything above it looks fine.
        link(&s, 10 * SEC, GwVerdict::Skip, None, TcpVerdict::Ok);
        proxy(&s, 10 * SEC, TcpVerdict::Ok, Some(204));
        host(&s, 10 * SEC, 1.0);
        let t = s.verdict_at(10 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "unknown");

        // And the mirror: the proxy probe did not run over a healthy link.
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Skip, None);
        host(&s, 20 * SEC, 1.0);
        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "unknown");
        assert_eq!(cell(&t, 0, "vless"), "SKIP");
    }

    /// A dead tun with no host sample cannot be told from starvation, and the
    /// query says so rather than guessing.
    #[test]
    fn verdict_at_will_not_call_a_wedge_without_load() {
        let s = DuckdbStore::in_memory().unwrap();
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(0));
        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "unknown");
    }

    /// The moment asked for is not necessarily a moment that was sampled: the
    /// answer is the newest state at or before it.
    #[test]
    fn verdict_at_reads_the_newest_state_at_or_before_the_moment() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        link(&s, 20 * SEC, GwVerdict::Fail, None, TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(204));
        host(&s, 20 * SEC, 1.0);

        // Between the ticks: still the healthy one.
        let t = s.verdict_at(15 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "ts_us"), (10 * SEC).to_string());
        assert_eq!(cell(&t, 0, "layer"), "healthy");
        // After the drop: the drop.
        let t = s.verdict_at(25 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "ts_us"), (20 * SEC).to_string());
        assert_eq!(cell(&t, 0, "layer"), "link");
    }

    // ---- 2. incident with its context --------------------------------------

    #[test]
    fn incident_context_carries_the_layer_state_that_opened_it() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        // Coworking gateway stops answering; the incident opens on that tick.
        link(&s, 20 * SEC, GwVerdict::Fail, None, TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(204));
        host(&s, 20 * SEC, 1.1);
        s.open_incident(&Incident {
            id: "i1".into(),
            opened_us: 20 * SEC + 500_000,
            closed_us: None,
            trigger_id: "gw-drop".into(),
            signature: "gw=FAIL".into(),
        })
        .unwrap();

        let t = s.incident_context().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "trigger_id"), "gw-drop");
        assert_eq!(cell(&t, 0, "state_ts_us"), (20 * SEC).to_string());
        assert_eq!(cell(&t, 0, "layer"), "link");
    }

    /// The negative case: an incident opened while the record shows a starving
    /// host must not be attributed to the link or to a wedge.
    #[test]
    fn incident_context_does_not_blame_the_link_for_a_starvation_incident() {
        let s = DuckdbStore::in_memory().unwrap();
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(0));
        host(&s, 20 * SEC, 42.0);
        s.open_incident(&Incident {
            id: "i2".into(),
            opened_us: 21 * SEC,
            closed_us: Some(30 * SEC),
            trigger_id: "starvation".into(),
            signature: "tun dead under load".into(),
        })
        .unwrap();

        let t = s.incident_context().unwrap();
        assert_eq!(cell(&t, 0, "layer"), "host");
        assert_ne!(cell(&t, 0, "layer"), "link");
        assert_ne!(cell(&t, 0, "layer"), "proxy");
        assert_eq!(cell(&t, 0, "load1"), "42");
    }

    #[test]
    fn incident_context_admits_it_when_nothing_was_sampled_before_the_incident() {
        let s = DuckdbStore::in_memory().unwrap();
        s.open_incident(&Incident {
            id: "i3".into(),
            opened_us: 5 * SEC,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        })
        .unwrap();
        let t = s.incident_context().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "layer"), "");
        assert_eq!(cell(&t, 0, "state_ts_us"), "");
    }

    // ---- 3. wedge vs starvation --------------------------------------------

    /// Push `n` ticks of a dead tun over a healthy link, at `load1`.
    fn tun_dead_episode(s: &DuckdbStore, from_us: i64, n: i64, load1: f64) {
        for i in 0..n {
            let ts = from_us + i * SEC;
            link(s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(s, ts, TcpVerdict::Ok, Some(0));
            host(s, ts, load1);
        }
    }

    #[test]
    fn a_dead_tun_on_an_idle_host_is_a_wedge() {
        let s = DuckdbStore::in_memory().unwrap();
        tun_dead_episode(&s, 10 * SEC, 4, 1.3);
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "wedge");
        assert_eq!(cell(&t, 0, "ticks"), "4");
        assert_eq!(cell(&t, 0, "opened_us"), (10 * SEC).to_string());
        assert_eq!(cell(&t, 0, "closed_us"), (13 * SEC).to_string());
    }

    /// The nine-hour lesson of 2026-07-27: the same shape under load is NOT a
    /// wedge, and a restart does not cure it.
    #[test]
    fn the_same_dead_tun_under_load_is_starvation_not_a_wedge() {
        let s = DuckdbStore::in_memory().unwrap();
        tun_dead_episode(&s, 10 * SEC, 4, 31.0);
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "starvation");
        assert_ne!(cell(&t, 0, "verdict"), "wedge");
        assert_eq!(cell(&t, 0, "max_load1"), "31");
    }

    /// Both episodes in one record, told apart by `load1` alone.
    #[test]
    fn the_two_episodes_are_separated_and_named_individually() {
        let s = DuckdbStore::in_memory().unwrap();
        tun_dead_episode(&s, 10 * SEC, 3, 1.0);
        healthy_tick(&s, 60 * SEC);
        tun_dead_episode(&s, 120 * SEC, 3, 25.0);
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(t.rows.len(), 2);
        assert_eq!(cell(&t, 0, "verdict"), "wedge");
        assert_eq!(cell(&t, 1, "verdict"), "starvation");
    }

    /// A dead tun during a gateway outage is not a proxy fault at all — the
    /// superficially similar shape that must not be called a wedge.
    #[test]
    fn a_dead_tun_behind_a_dead_gateway_is_not_a_wedge() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..3 {
            let ts = 10 * SEC + i * SEC;
            link(&s, ts, GwVerdict::Fail, None, TcpVerdict::Ok);
            proxy(&s, ts, TcpVerdict::Fail, Some(0));
            host(&s, ts, 1.0);
        }
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(cell(&t, 0, "verdict"), "link");
    }

    #[test]
    fn a_dead_tun_with_an_unreachable_server_is_blamed_on_the_server() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..3 {
            let ts = 10 * SEC + i * SEC;
            link(&s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(&s, ts, TcpVerdict::Fail, Some(0));
            host(&s, ts, 1.0);
        }
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(cell(&t, 0, "verdict"), "vless");
        assert_ne!(cell(&t, 0, "verdict"), "wedge");
    }

    #[test]
    fn a_dead_tun_without_load_data_is_not_called_either_way() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..3 {
            let ts = 10 * SEC + i * SEC;
            link(&s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(&s, ts, TcpVerdict::Ok, Some(0));
        }
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(cell(&t, 0, "verdict"), "unknown");
    }

    /// A tun probe that did not run is not a dead tun.
    #[test]
    fn skipped_tun_probes_are_not_episodes() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..4 {
            let ts = 10 * SEC + i * SEC;
            link(&s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(&s, ts, TcpVerdict::Skip, None);
            host(&s, ts, 30.0);
        }
        let t = s.wedge_vs_starvation().unwrap();
        assert!(t.rows.is_empty(), "SKIP became an episode: {:?}", t.rows);
    }

    #[test]
    fn a_healthy_record_yields_no_episode() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..5 {
            healthy_tick(&s, (10 + i) * SEC);
        }
        assert!(s.wedge_vs_starvation().unwrap().rows.is_empty());
    }

    // ---- 4. gateway ramp ----------------------------------------------------

    /// The coworking signature: gateway RTT climbing linearly for ~40 s, then
    /// the gateway stops answering.
    fn coworking_ramp(s: &DuckdbStore, start_us: i64) -> i64 {
        for i in 0..40 {
            let ts = start_us + i * SEC;
            link(
                s,
                ts,
                GwVerdict::Ok,
                Some(3.0 + 20.0 * i as f64),
                TcpVerdict::Ok,
            );
        }
        let drop_ts = start_us + 40 * SEC;
        link(s, drop_ts, GwVerdict::Fail, None, TcpVerdict::Ok);
        drop_ts
    }

    #[test]
    fn the_gateway_ramp_shows_the_climb_before_the_drop() {
        let s = DuckdbStore::in_memory().unwrap();
        let drop_ts = coworking_ramp(&s, 100 * SEC);

        let drops = s.gw_drops().unwrap();
        assert_eq!(drops.rows.len(), 1);
        assert_eq!(cell(&drops, 0, "ts_us"), drop_ts.to_string());

        let t = s.gateway_ramp(drop_ts).unwrap();
        assert_eq!(t.rows.len(), 41, "the whole window, drop included");
        // Rising RTT, and the drop itself last with no RTT at all.
        assert_eq!(cell(&t, 0, "gw_rtt_ms"), "3");
        assert_eq!(cell(&t, 40, "gw"), "FAIL");
        assert_eq!(cell(&t, 40, "gw_rtt_ms"), "");
        assert_eq!(cell(&t, 40, "us_before_drop"), "0");
        // 20 ms per 1 s tick, fitted over the 40 answered samples only.
        let slope: f64 = cell(&t, 0, "slope_ms_per_s").parse().unwrap();
        assert!((slope - 20.0).abs() < 0.001, "slope was {slope}");
        assert_eq!(cell(&t, 0, "fitted_samples"), "40");
    }

    /// The negative case: a gateway that answered flat and then vanished. Same
    /// drop, no ramp — the query must not manufacture a climb.
    #[test]
    fn a_flat_gateway_that_simply_vanishes_shows_no_ramp() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..40 {
            link(
                &s,
                100 * SEC + i * SEC,
                GwVerdict::Ok,
                Some(3.0),
                TcpVerdict::Ok,
            );
        }
        let drop_ts = 140 * SEC;
        link(&s, drop_ts, GwVerdict::Fail, None, TcpVerdict::Ok);

        let t = s.gateway_ramp(drop_ts).unwrap();
        let slope: f64 = cell(&t, 0, "slope_ms_per_s").parse().unwrap();
        assert!(slope.abs() < 0.001, "flat gateway got slope {slope}");
    }

    /// Suppressed echoes carry no RTT, so they must not enter the fit — and must
    /// not be read as a drop either.
    #[test]
    fn skipped_ticks_are_listed_but_do_not_enter_the_fit() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..10 {
            link(
                &s,
                100 * SEC + i * SEC,
                GwVerdict::Ok,
                Some(3.0 + 20.0 * i as f64),
                TcpVerdict::Ok,
            );
        }
        // A quiet run, then the drop.
        for i in 10..13 {
            link(
                &s,
                100 * SEC + i * SEC,
                GwVerdict::Skip,
                None,
                TcpVerdict::Ok,
            );
        }
        let drop_ts = 113 * SEC;
        link(&s, drop_ts, GwVerdict::Fail, None, TcpVerdict::Ok);

        // The quiet run is not an edge; the FAIL is the one drop.
        let drops = s.gw_drops().unwrap();
        assert_eq!(drops.rows.len(), 1);
        assert_eq!(cell(&drops, 0, "ts_us"), drop_ts.to_string());

        let t = s.gateway_ramp(drop_ts).unwrap();
        assert_eq!(t.rows.len(), 14);
        assert_eq!(cell(&t, 0, "fitted_samples"), "10");
        let slope: f64 = cell(&t, 0, "slope_ms_per_s").parse().unwrap();
        assert!((slope - 20.0).abs() < 0.001, "slope was {slope}");
    }

    #[test]
    fn the_ramp_window_does_not_reach_past_an_earlier_run() {
        let s = DuckdbStore::in_memory().unwrap();
        // Old, unrelated samples well outside the default window.
        for i in 0..5 {
            link(&s, i * SEC, GwVerdict::Ok, Some(999.0), TcpVerdict::Ok);
        }
        let drop_ts = coworking_ramp(&s, 1_000 * SEC);
        let t = s.gateway_ramp(drop_ts).unwrap();
        assert_eq!(cell(&t, 0, "fitted_samples"), "40");
    }

    // ---- 5. fakeip on a .ru name -------------------------------------------

    #[test]
    fn a_fakeip_answer_on_a_ru_name_is_reported() {
        let s = DuckdbStore::in_memory().unwrap();
        dns(&s, 10 * SEC, "ru", DnsVerdict::FakeIp, Some("198.18.0.7"));
        dns(
            &s,
            11 * SEC,
            "gosuslugi.ru",
            DnsVerdict::FakeIp,
            Some("198.18.0.8"),
        );
        let t = s.fakeip_bugs().unwrap();
        assert_eq!(t.rows.len(), 2);
        assert_eq!(cell(&t, 0, "probe"), "ru");
        assert_eq!(cell(&t, 1, "probe"), "gosuslugi.ru");
    }

    /// The negative case: fakeip on a non-`.ru` name is how the proxy is
    /// supposed to work, and a `.ru` name that was answered normally — or not
    /// probed at all — is not a bug either.
    #[test]
    fn fakeip_elsewhere_and_skips_are_not_bugs() {
        let s = DuckdbStore::in_memory().unwrap();
        dns(&s, 10 * SEC, "nks", DnsVerdict::FakeIp, Some("198.18.0.1"));
        dns(&s, 11 * SEC, "example.rules", DnsVerdict::FakeIp, None);
        dns(&s, 12 * SEC, "ru", DnsVerdict::Ok, Some("5.255.255.70"));
        dns(&s, 13 * SEC, "ru", DnsVerdict::Skip, None);
        assert!(s.fakeip_bugs().unwrap().rows.is_empty());
    }
    // ---- 6. observation gaps -------------------------------------------------

    /// The defect this section exists for: the newest sample before a pause is a
    /// reading from before the pause. Asked about a moment inside the pause, the
    /// query withholds it rather than passing it off as a measurement.
    #[test]
    fn verdict_at_declines_to_answer_for_a_moment_inside_a_pause() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 40 * SEC, true);
        healthy_tick(&s, 40 * SEC);

        let t = s.verdict_at(30 * SEC).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "layer"), "gap");
        // No measurement leaks out with it.
        assert_eq!(cell(&t, 0, "ts_us"), "");
        assert_eq!(cell(&t, 0, "gw"), "");
        assert_eq!(cell(&t, 0, "vless"), "");
        assert_eq!(cell(&t, 0, "load1"), "");
        // The silence is bounded, and the row says by what.
        assert_eq!(cell(&t, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&t, 0, "gap_closed_us"), (40 * SEC).to_string());
    }

    /// And the pause does not poison its neighbourhood: on either side of it the
    /// record answers exactly as before.
    #[test]
    fn verdict_at_answers_normally_on_both_sides_of_a_pause() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 40 * SEC, true);
        link(&s, 40 * SEC, GwVerdict::Fail, None, TcpVerdict::Ok);
        proxy(&s, 40 * SEC, TcpVerdict::Ok, Some(204));
        host(&s, 40 * SEC, 1.0);

        // Just before the pause opened.
        let t = s.verdict_at(20 * SEC - 1).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "healthy");
        assert_eq!(cell(&t, 0, "ts_us"), (10 * SEC).to_string());
        assert_eq!(cell(&t, 0, "gap_opened_us"), "");

        // The resume instant is already outside the gap.
        let t = s.verdict_at(40 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "link");
        assert_eq!(cell(&t, 0, "ts_us"), (40 * SEC).to_string());
        assert_eq!(cell(&t, 0, "gap_opened_us"), "");
    }

    /// The daemon died while paused: it comes back collecting and writes no
    /// resume edge, because the observing state is never persisted. The gap must
    /// close where the samples resume, or one crash would make the whole rest of
    /// the record unanswerable.
    #[test]
    fn an_unterminated_pause_ends_where_the_record_shows_collecting_resumed() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        // No resume edge — a restart. Samples simply start again.
        healthy_tick(&s, 40 * SEC);
        healthy_tick(&s, 50 * SEC);

        // Inside the real silence: still refused.
        let t = s.verdict_at(30 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "gap");
        assert_eq!(cell(&t, 0, "gap_closed_us"), (40 * SEC).to_string());

        // After it: answered, and from the post-restart samples.
        let t = s.verdict_at(55 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "healthy");
        assert_eq!(cell(&t, 0, "ts_us"), (50 * SEC).to_string());
    }

    /// The one case where a pause does swallow every later instant, and
    /// deliberately: nothing at all was recorded after it, so the record really
    /// does end inside the silence. The gap is reported open-ended rather than
    /// guessed shut.
    #[test]
    fn a_pause_with_nothing_recorded_after_it_stays_open_ended_on_purpose() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);

        let gaps = s.observation_gaps().unwrap();
        assert_eq!(gaps.rows.len(), 1);
        assert_eq!(cell(&gaps, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&gaps, 0, "gap_closed_us"), "");

        for ts in [21 * SEC, 10_000 * SEC] {
            let t = s.verdict_at(ts).unwrap();
            assert_eq!(cell(&t, 0, "layer"), "gap", "at {ts}");
            assert_eq!(cell(&t, 0, "gap_closed_us"), "", "at {ts}");
        }
    }

    /// The mirror unpaired edge: the record begins after a pause the daemon took
    /// in a previous life, so the first edge seen is a resume. Only a `false`
    /// edge opens a gap, so nothing before it is widened into one.
    #[test]
    fn a_resume_with_no_preceding_pause_opens_no_gap() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, true);
        healthy_tick(&s, 30 * SEC);

        assert!(s.observation_gaps().unwrap().rows.is_empty());
        for ts in [15 * SEC, 25 * SEC, 35 * SEC] {
            let t = s.verdict_at(ts).unwrap();
            assert_eq!(cell(&t, 0, "layer"), "healthy", "at {ts}");
        }
        // Before anything was recorded there is still no answer — and no gap
        // invented to explain the emptiness either.
        assert!(s.verdict_at(5 * SEC).unwrap().rows.is_empty());
    }

    /// An incident that opened inside a pause has no layer context, and the
    /// pre-pause state is not offered as one.
    #[test]
    fn incident_context_declines_context_for_an_incident_opened_inside_a_pause() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 40 * SEC, true);
        healthy_tick(&s, 40 * SEC);
        s.open_incident(&Incident {
            id: "i-paused".into(),
            opened_us: 30 * SEC,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        })
        .unwrap();

        let t = s.incident_context().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "layer"), "gap");
        assert_eq!(cell(&t, 0, "state_ts_us"), "");
        assert_eq!(cell(&t, 0, "gw"), "");
        assert_eq!(cell(&t, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&t, 0, "gap_closed_us"), (40 * SEC).to_string());
        // The incident's own identity survives — only the context is withheld.
        assert_eq!(cell(&t, 0, "id"), "i-paused");
        assert_eq!(cell(&t, 0, "opened_us"), (30 * SEC).to_string());
    }

    /// An incident outside any pause keeps the context it always had.
    #[test]
    fn incident_context_outside_a_pause_is_unaffected_by_one() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 40 * SEC, true);
        link(&s, 40 * SEC, GwVerdict::Fail, None, TcpVerdict::Ok);
        proxy(&s, 40 * SEC, TcpVerdict::Ok, Some(204));
        host(&s, 40 * SEC, 1.0);
        s.open_incident(&Incident {
            id: "i-live".into(),
            opened_us: 41 * SEC,
            closed_us: None,
            trigger_id: "gw-drop".into(),
            signature: "gw=FAIL".into(),
        })
        .unwrap();

        let t = s.incident_context().unwrap();
        assert_eq!(cell(&t, 0, "layer"), "link");
        assert_eq!(cell(&t, 0, "state_ts_us"), (40 * SEC).to_string());
        assert_eq!(cell(&t, 0, "gap_opened_us"), "");
    }

    /// A slope fitted across an interval that was never sampled is a line drawn
    /// through absent data, and it reads exactly like a measured climb. The
    /// samples are still listed; the number is withheld.
    #[test]
    fn the_gateway_ramp_withholds_its_slope_when_the_window_crosses_a_pause() {
        let s = DuckdbStore::in_memory().unwrap();
        let drop_ts = coworking_ramp(&s, 100 * SEC);
        // A pause well inside the default 120 s window, before the ramp began.
        edge(&s, 50 * SEC, false);
        edge(&s, 60 * SEC, true);

        let t = s.gateway_ramp(drop_ts).unwrap();
        assert_eq!(t.rows.len(), 41, "the samples are still listed");
        assert_eq!(cell(&t, 0, "slope_ms_per_s"), "");
        assert_eq!(cell(&t, 0, "fitted_samples"), "");
        assert_eq!(cell(&t, 0, "observation_gap_us"), (10 * SEC).to_string());
    }

    /// The negative twin: a pause entirely outside the window changes nothing.
    #[test]
    fn a_pause_outside_the_ramp_window_leaves_the_slope_alone() {
        let s = DuckdbStore::in_memory().unwrap();
        edge(&s, 5 * SEC, false);
        edge(&s, 8 * SEC, true);
        let drop_ts = coworking_ramp(&s, 100 * SEC);

        let t = s.gateway_ramp(drop_ts).unwrap();
        assert_eq!(cell(&t, 0, "observation_gap_us"), "0");
        assert_eq!(cell(&t, 0, "fitted_samples"), "40");
        let slope: f64 = cell(&t, 0, "slope_ms_per_s").parse().unwrap();
        assert!((slope - 20.0).abs() < 0.001, "slope was {slope}");
    }

    /// Consecutive gaps are listed in order and stay separate.
    #[test]
    fn every_pause_is_listed_as_its_own_bounded_gap() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 30 * SEC, true);
        healthy_tick(&s, 30 * SEC);
        edge(&s, 40 * SEC, false);
        edge(&s, 55 * SEC, true);
        healthy_tick(&s, 55 * SEC);

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 2);
        assert_eq!(cell(&g, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (30 * SEC).to_string());
        assert_eq!(cell(&g, 1, "gap_opened_us"), (40 * SEC).to_string());
        assert_eq!(cell(&g, 1, "gap_closed_us"), (55 * SEC).to_string());
    }
}
