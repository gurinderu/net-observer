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
//! - A pause with no resume row closes at the next RECORDED startup edge when
//!   there is one: a daemon that died while paused comes back collecting and
//!   writes no resume edge, but it does write "this process began collecting
//!   at this instant", and that is a fact rather than an inference.
//! - Only failing that does the gap close where the record shows collection
//!   demonstrably resumed anyway — at the first sample of any stream written
//!   after it. Records written before the startup edge existed have nothing
//!   else, so the inference stays; `gap_closed_by` says which case was taken.
//!   Only when nothing at all follows the pause does the gap stay open-ended,
//!   which is the truth: the record ends there.
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
/// instant is not. It closes at the earliest of three candidates, and
/// `gap_closed_by` names which one it took:
///
/// | `gap_closed_by` | what closed the gap |
/// | --- | --- |
/// | `resume` | an operator `observing = true` edge (`cause` `control`) |
/// | `startup` | a recorded startup edge — this process began collecting |
/// | `sample` | no edge at all: the first sample of any stream, inferred |
///
/// A recorded edge WINS a tie with a sample at the same instant, because it is
/// the fact and the sample is only evidence of it.
///
/// `gap_closed_us` (and `gap_closed_by`) is `NULL` when nothing at all follows
/// the pause: the record simply ends inside it.
const OBSERVATION_GAP_CTE: &str = "\
observation_gap AS (
  SELECT gap_opened_us, gap_closed_us, gap_closed_by
  FROM (
    SELECT p.ts_us AS gap_opened_us,
           e.ts_us AS gap_closed_us,
           e.closed_by AS gap_closed_by,
           row_number() OVER (PARTITION BY p.ts_us ORDER BY e.ts_us, e.prio) AS rn
    FROM (SELECT ts_us FROM observing_edge WHERE NOT observing) p
    LEFT JOIN (
      SELECT ts_us,
             CASE WHEN cause = 'startup' THEN 'startup' ELSE 'resume' END AS closed_by,
             0 AS prio
      FROM observing_edge WHERE observing
      UNION ALL SELECT ts_us, 'sample' AS closed_by, 1 AS prio FROM sample_ts
    ) e ON e.ts_us > p.ts_us
  )
  WHERE rn = 1
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
SELECT gap_opened_us, gap_closed_us, gap_closed_by
FROM observation_gap ORDER BY gap_opened_us"
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

/// **Who is on the segment** — the neighbour entities, newest sighting first.
///
/// Reads the long-lived `neighbor` table, not the per-tick readings: the
/// question is "who is here / who was here", and the answer is one row per
/// device per segment. `network` filters to one segment by its `network_key`.
///
/// `source` is the honest part: `arp`/`ndp` means the daemon merely read a cache
/// the OS had filled, `sweep`/`mdns` that an operator sent it looking.
///
/// Returns `Err` for a key that cannot exist rather than a query that matches
/// nothing: an empty table is the answer to "this segment has no neighbours",
/// and a rejected filter must not borrow it.
pub fn neighbors_sql(network: Option<&str>) -> Result<String, BadNetworkKey> {
    let filter = match network {
        None => String::new(),
        Some(n) => {
            validate_network_key(n)?;
            format!("WHERE network_key = '{n}'")
        }
    };
    Ok(format!(
        "SELECT network_key, mac, ip, oui, hostname, source, iface, first_seen_us, last_seen_us
FROM neighbor
{filter}
ORDER BY last_seen_us DESC, mac"
    ))
}

/// **The CVEs the record hypothesises for open ports** — newest sighting first.
///
/// Reads `neighbor_vuln`, joined to `neighbor_port` for the address the port was
/// found on, so the operator sees mac, ip, port, cve, and how much to trust it
/// without writing SQL. `network` filters to one segment by its `network_key`.
///
/// Every row is a HYPOTHESIS, not an asserted fact: `confidence`
/// (low|medium|high) and `known_exploited` say how much to weigh it, `cvss` the
/// severity when the record carried one.
///
/// Returns `Err` for a key that cannot exist rather than a query that matches
/// nothing, exactly like [`neighbors_sql`].
pub fn vulns_sql(network: Option<&str>) -> Result<String, BadNetworkKey> {
    let filter = match network {
        None => String::new(),
        Some(n) => {
            validate_network_key(n)?;
            format!("WHERE v.network_key = '{n}'")
        }
    };
    Ok(format!(
        "SELECT v.mac, p.ip, v.port, v.cve_id, v.confidence, v.known_exploited, v.cvss
FROM neighbor_vuln v
LEFT JOIN neighbor_port p
  ON v.network_key = p.network_key AND v.mac = p.mac AND v.port = p.port
{filter}
ORDER BY v.last_seen_us DESC, v.mac, v.port, v.cve_id"
    ))
}

/// **Where I have been** — every network segment the record has ever seen, most
/// recent activity first.
///
/// One row per `network_key` (the gateway MAC, or the literal `unknown` when it
/// could not be read). A segment's span is the widest reach of its own rows:
/// `min`/`max` over the `neighbor` first/last-seen columns and the
/// `neighbor_sample` tick timestamps. `neighbors` counts the distinct devices
/// the segment ever held.
///
/// Two of the columns are recovered rather than stored, and neither is asserted:
///
/// - `gateway_ip` is the address of the gateway's own `neighbor` entry — the row
///   whose `mac` equals the segment key. It is present only when the daemon
///   happened to record the gateway as a neighbour, and `NULL` otherwise (always
///   `NULL` for the `unknown` segment, whose key is not a MAC).
/// - `ssid_guess` is a BEST-EFFORT label, not a fact: the daemon never joins an
///   SSID to a `network_key`, so this is the most recent `link_sample.ssid` whose
///   tick falls inside the segment's span — a TIME-overlap guess. The column name
///   says `guess` on purpose; a segment with no overlapping named `link_sample`
///   leaves it blank rather than inventing one.
///
/// A segment recorded under `unknown` is listed like any other: during an outage
/// the gateway MAC is often exactly what could not be read, so that segment is
/// the one most likely to matter.
pub fn segments_sql() -> String {
    "WITH span AS (
  SELECT network_key, min(t) AS first_seen_us, max(t) AS last_seen_us
  FROM (
    SELECT network_key, first_seen_us AS t FROM neighbor
    UNION ALL SELECT network_key, last_seen_us AS t FROM neighbor
    -- `neighbor_sample` stores a NULL key where the entity table writes the
    -- 'unknown' sentinel; fold them together so one segment is one row.
    UNION ALL SELECT coalesce(network_key, 'unknown') AS network_key, ts_us AS t
              FROM neighbor_sample
  )
  GROUP BY network_key
),
cnt AS (
  SELECT network_key, count(*) AS neighbors FROM neighbor GROUP BY network_key
)
SELECT s.network_key,
       (SELECT n.ip FROM neighbor n
        WHERE n.network_key = s.network_key AND n.mac = s.network_key
        LIMIT 1) AS gateway_ip,
       (SELECT ls.ssid FROM link_sample ls
        WHERE ls.ssid IS NOT NULL
          AND ls.ts_us >= s.first_seen_us AND ls.ts_us <= s.last_seen_us
        ORDER BY ls.ts_us DESC
        LIMIT 1) AS ssid_guess,
       s.first_seen_us,
       s.last_seen_us,
       coalesce(c.neighbors, 0) AS neighbors
FROM span s
LEFT JOIN cnt c ON c.network_key = s.network_key
ORDER BY s.last_seen_us DESC, s.network_key"
        .to_string()
}

/// Which slice of one segment's history to read: a single instant, or a window.
#[derive(Debug, Clone, Copy)]
pub enum HistoryWindow {
    /// The neighbours (and their ports/vulns) live at exactly this `ts_us`:
    /// `first_seen_us <= at <= last_seen_us`.
    At(i64),
    /// The neighbours (and their ports/vulns) whose lifetime overlaps
    /// `[since, until]`: `first_seen_us <= until AND last_seen_us >= since`.
    Range { since: i64, until: i64 },
}

impl HistoryWindow {
    /// The activity predicate for a table carrying `first_seen_us` /
    /// `last_seen_us`, with those columns qualified by `alias`.
    fn predicate(self, alias: &str) -> String {
        match self {
            HistoryWindow::At(at) => {
                format!("{alias}.first_seen_us <= {at} AND {alias}.last_seen_us >= {at}")
            }
            HistoryWindow::Range { since, until } => {
                format!("{alias}.first_seen_us <= {until} AND {alias}.last_seen_us >= {since}")
            }
        }
    }
}

/// **One segment's recorded state** — the neighbours of `network` that were live
/// at an instant, or active over a window, newest last-seen first.
///
/// Each row is a device (`neighbor`), carried with a count of its open ports and
/// hypothesised vulns that were themselves active over the same slice — so "who
/// was on this segment, and what was open on them" reads in one table without SQL.
///
/// `network` is validated exactly as [`neighbors_sql`] validates it: a gateway
/// MAC or the literal `unknown`, and anything else is an `Err`, never a query
/// that silently matches nothing. The `unknown` segment is as reachable here as
/// in the segment list.
pub fn history_sql(network: &str, window: HistoryWindow) -> Result<String, BadNetworkKey> {
    validate_network_key(network)?;
    let neighbor_pred = window.predicate("n");
    let port_pred = window.predicate("p");
    let vuln_pred = window.predicate("v");
    Ok(format!(
        "SELECT n.mac, n.ip, n.oui, n.hostname, n.source, n.iface,
       n.first_seen_us, n.last_seen_us,
       (SELECT count(*) FROM neighbor_port p
        WHERE p.network_key = n.network_key AND p.mac = n.mac AND {port_pred}) AS open_ports,
       (SELECT count(*) FROM neighbor_vuln v
        WHERE v.network_key = n.network_key AND v.mac = n.mac AND {vuln_pred}) AS vulns
FROM neighbor n
WHERE n.network_key = '{network}' AND {neighbor_pred}
ORDER BY n.last_seen_us DESC, n.mac"
    ))
}

/// **The switch-topology links** — which switch/AP each interface uplinks to,
/// newest sighting first.
///
/// Reads the long-lived `topology_link` table: one row per
/// `(iface, remote_chassis, remote_port)` with first/last seen, the remote's
/// advertised system name and capabilities, and whether LLDP or CDP carried it.
/// `iface` filters to one local interface.
///
/// Every row is a HYPOTHESIS, never an asserted fact: LLDP/CDP are
/// unauthenticated and trivially spoofable, so a link says "a device *claiming*
/// this identity was heard on this interface", not "this is the switch".
///
/// Returns `Err` for an interface name the store could never have written rather
/// than a query that matches nothing, exactly like [`neighbors_sql`].
pub fn topology_sql(iface: Option<&str>) -> Result<String, BadIface> {
    let filter = match iface {
        None => String::new(),
        Some(i) => {
            validate_iface(i)?;
            format!("WHERE iface = '{i}'")
        }
    };
    Ok(format!(
        "SELECT iface, remote_chassis, remote_port, remote_system_name, capabilities, \
learned_via, first_seen_us, last_seen_us
FROM topology_link
{filter}
ORDER BY last_seen_us DESC, iface, remote_chassis, remote_port"
    ))
}

/// An interface name the store could never have written into `topology_link`.
#[derive(Debug, thiserror::Error)]
#[error("not an interface name: {0} (expected something like en0, en1 or utun3)")]
pub struct BadIface(pub String);

/// Accept a plausible network-interface name: a short run of ASCII letters,
/// digits, `.` or `:` (BSD names like `en0`, `utun3`, `vlan0.10`). The point is
/// the same as [`validate_network_key`]: a filter is interpolated into the SQL,
/// so it must be constrained to what an interface name can actually be — never a
/// vehicle for arbitrary text.
fn validate_iface(i: &str) -> Result<(), BadIface> {
    let ok = !i.is_empty()
        && i.len() <= 32
        && i.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(BadIface(i.to_string()))
    }
}

/// A `network_key` the store could never have written.
#[derive(Debug, thiserror::Error)]
#[error(
    "not a segment key: {0} (expected a gateway MAC such as a4:83:e7:1b:2c:3d, or `unknown` for a segment whose gateway MAC was unreadable)"
)]
pub struct BadNetworkKey(pub String);

/// Accept exactly what the store writes as a `network_key`: a MAC, or the
/// literal sentinel it uses when the gateway's MAC could not be read.
///
/// That sentinel is the whole reason this is a named check rather than a
/// character class. During an outage the gateway is often exactly what cannot be
/// read, so `unknown` is the segment most likely to matter — and a filter that
/// silently matched nothing would answer "no such segment" about the one
/// recorded because identification failed.
fn validate_network_key(n: &str) -> Result<(), BadNetworkKey> {
    if n == "unknown" {
        return Ok(());
    }
    let looks_like_mac = n.len() == 17
        && n.split(':').count() == 6
        && n.split(':')
            .all(|o| o.len() == 2 && o.chars().all(|c| c.is_ascii_hexdigit()));
    if looks_like_mac {
        Ok(())
    } else {
        Err(BadNetworkKey(n.to_string()))
    }
}

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

    /// Run [`neighbors_sql`] for every segment.
    pub fn neighbors(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&neighbors_sql(None).expect("no filter cannot be invalid"))
    }

    /// Run [`vulns_sql`] for every segment.
    pub fn vulns(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&vulns_sql(None).expect("no filter cannot be invalid"))
    }

    /// Run [`observation_gaps_sql`].
    pub fn observation_gaps(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&observation_gaps_sql())
    }

    /// Run [`segments_sql`].
    pub fn segments(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&segments_sql())
    }

    /// Run [`history_sql`] for one segment over `window`.
    ///
    /// `network` must already be a valid key; the CLI validates it at the
    /// boundary (via [`history_sql`], whose `Err` it surfaces), so an invalid key
    /// reaching here is a caller bug, not user input — hence the `expect`, the
    /// same idiom [`DuckdbStore::neighbors`] uses for its own always-valid input.
    pub fn history(&self, network: &str, window: HistoryWindow) -> Result<QueryTable, StoreError> {
        self.query_table(&history_sql(network, window).expect("network key must be pre-validated"))
    }
}

#[cfg(test)]
mod tests {

    /// The sentinel the store writes when the gateway MAC is unreadable must be
    /// a reachable filter: during an outage that is often the interesting
    /// segment, and it was silently rejected before.
    #[test]
    fn the_unknown_segment_is_reachable_by_name() {
        let sql = neighbors_sql(Some("unknown")).expect("unknown is a real key");
        assert!(sql.contains("WHERE network_key = 'unknown'"), "{sql}");
    }

    #[test]
    fn a_gateway_mac_is_accepted_and_a_non_key_is_an_error() {
        assert!(neighbors_sql(Some("a4:83:e7:1b:2c:3d")).is_ok());
        for bad in ["'; DROP TABLE neighbor; --", "a4:83", "не мак", ""] {
            assert!(
                neighbors_sql(Some(bad)).is_err(),
                "{bad:?} must be an error, not a query that matches nothing"
            );
        }
    }

    #[test]
    fn no_filter_selects_every_segment() {
        let sql = neighbors_sql(None).unwrap();
        assert!(!sql.contains("WHERE"), "{sql}");
    }

    #[test]
    fn vulns_sql_validates_the_network_key_like_neighbors() {
        assert!(!vulns_sql(None).unwrap().contains("WHERE"));
        assert!(vulns_sql(Some("a4:83:e7:1b:2c:3d")).is_ok());
        assert!(vulns_sql(Some("unknown")).is_ok());
        for bad in ["'; DROP TABLE neighbor_vuln; --", "a4:83", ""] {
            assert!(
                vulns_sql(Some(bad)).is_err(),
                "{bad:?} must be an error, not a query that matches nothing"
            );
        }
    }
    /// The topology reader validates its interface filter the same way, and
    /// rejects an interpolation attempt rather than matching nothing.
    #[test]
    fn topology_sql_validates_the_iface_filter() {
        assert!(!topology_sql(None).unwrap().contains("WHERE"));
        assert!(topology_sql(Some("en0")).is_ok());
        assert!(topology_sql(Some("utun3")).is_ok());
        assert!(topology_sql(Some("vlan0.10")).is_ok());
        for bad in ["'; DROP TABLE topology_link; --", "en 0", "", "имя"] {
            assert!(
                topology_sql(Some(bad)).is_err(),
                "{bad:?} must be an error, not a query that matches nothing"
            );
        }
    }
    use super::*;
    use crate::{NeighborPort, NeighborVuln, Store};
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, Incident, LinkSample, NeighborObs,
        NeighborRole, NeighborSource, NeighborsSample, NeighborsVerdict, ObservingEdge,
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
            cause: types::ObservingCause::Control,
        })
        .unwrap();
    }

    /// The boundary a booting daemon writes: it began collecting, and no peer
    /// asked for it.
    fn startup_edge(s: &DuckdbStore, ts_us: i64) {
        s.write_observing_edge(&ObservingEdge {
            ts_us,
            observing: true,
            peer_uid: None,
            cause: types::ObservingCause::Startup,
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

    /// The recorded fact beats the inference: a daemon that died while paused
    /// comes back collecting and writes a STARTUP edge, so the gap closes at
    /// that edge — the instant the record actually names — rather than at the
    /// first sample the restarted process happened to take.
    #[test]
    fn a_startup_edge_closes_the_gap_at_the_edge_not_at_the_first_sample() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        // The daemon died paused and booted again at 35 s; its first tick is
        // five seconds later.
        startup_edge(&s, 35 * SEC);
        healthy_tick(&s, 40 * SEC);

        let gaps = s.observation_gaps().unwrap();
        assert_eq!(gaps.rows.len(), 1);
        assert_eq!(cell(&gaps, 0, "gap_closed_us"), (35 * SEC).to_string());
        assert_eq!(cell(&gaps, 0, "gap_closed_by"), "startup");

        // The instant between the startup edge and the first sample is no
        // longer inside the silence: the record says collection had resumed.
        let t = s.verdict_at(37 * SEC).unwrap();
        assert_ne!(cell(&t, 0, "layer"), "gap");
        // Inside the real silence, nothing changed.
        assert_eq!(cell(&s.verdict_at(30 * SEC).unwrap(), 0, "layer"), "gap");
    }

    /// The fallback stays, and says so: with no startup edge the gap still
    /// closes at the first sample, reported as the inference it is.
    #[test]
    fn without_a_startup_edge_the_gap_still_closes_at_the_first_sample() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        healthy_tick(&s, 40 * SEC);

        let gaps = s.observation_gaps().unwrap();
        assert_eq!(gaps.rows.len(), 1);
        assert_eq!(cell(&gaps, 0, "gap_closed_us"), (40 * SEC).to_string());
        assert_eq!(cell(&gaps, 0, "gap_closed_by"), "sample");
    }

    /// A startup edge on its own is not a transition out of anything: the
    /// daemon simply booted. It must not open a gap (only a `false` edge does)
    /// nor close one that was never opened.
    #[test]
    fn a_startup_edge_with_no_preceding_pause_changes_nothing() {
        let s = DuckdbStore::in_memory().unwrap();
        startup_edge(&s, 5 * SEC);
        healthy_tick(&s, 10 * SEC);
        healthy_tick(&s, 20 * SEC);

        assert!(s.observation_gaps().unwrap().rows.is_empty());
        // (before 10 s nothing was recorded at all, so there is no row there —
        // and no gap invented to explain the emptiness either.)
        assert!(s.verdict_at(6 * SEC).unwrap().rows.is_empty());
        for ts in [15 * SEC, 25 * SEC] {
            let t = s.verdict_at(ts).unwrap();
            assert_eq!(cell(&t, 0, "layer"), "healthy", "at {ts}");
        }
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

    // ---- 7. segments (where have I been) and one segment's history ----------

    /// One neighbour sighting on a segment. `key` is the `network_key`; `None`
    /// records under the `unknown` sentinel, exactly as a live tick would.
    fn neigh(s: &DuckdbStore, ts_us: i64, key: Option<&str>, mac: &str, ip: &str) {
        s.write_sample(&Sample::Neighbors(NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: key.map(str::to_string),
            iface: Some("en0".into()),
            neighbors: vec![NeighborObs {
                mac: mac.into(),
                ip: ip.into(),
                source: NeighborSource::Arp,
                hostname: None,
                role: NeighborRole::Unknown,
            }],
        }))
        .unwrap();
    }

    const K1: &str = "a4:83:e7:1b:2c:3d";
    const K2: &str = "b8:27:eb:11:22:33";

    #[test]
    fn a_segment_appears_with_its_span_and_neighbour_count() {
        let s = DuckdbStore::in_memory().unwrap();
        // Two devices, first seen at different ticks: the span is the widest
        // reach of the segment's rows, the count is the distinct devices.
        neigh(&s, 10 * SEC, Some(K1), "11:22:33:44:55:66", "10.0.0.5");
        neigh(&s, 30 * SEC, Some(K1), "11:22:33:44:55:77", "10.0.0.6");

        let t = s.segments().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "network_key"), K1);
        assert_eq!(cell(&t, 0, "first_seen_us"), (10 * SEC).to_string());
        assert_eq!(cell(&t, 0, "last_seen_us"), (30 * SEC).to_string());
        assert_eq!(cell(&t, 0, "neighbors"), "2");
    }

    #[test]
    fn two_network_keys_list_as_two_segments_newest_first() {
        let s = DuckdbStore::in_memory().unwrap();
        neigh(&s, 10 * SEC, Some(K1), "11:22:33:44:55:66", "10.0.0.5");
        neigh(&s, 50 * SEC, Some(K2), "22:33:44:55:66:77", "192.168.1.9");

        let t = s.segments().unwrap();
        assert_eq!(t.rows.len(), 2);
        // Newest activity first.
        assert_eq!(cell(&t, 0, "network_key"), K2);
        assert_eq!(cell(&t, 1, "network_key"), K1);
    }

    /// The gateway MAC is often exactly what an outage makes unreadable, so the
    /// segment recorded under `unknown` must be listable, not hidden.
    #[test]
    fn the_unknown_segment_is_listed_like_any_other() {
        let s = DuckdbStore::in_memory().unwrap();
        neigh(&s, 10 * SEC, None, "11:22:33:44:55:66", "10.0.0.5");

        let t = s.segments().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "network_key"), "unknown");
        assert_eq!(cell(&t, 0, "neighbors"), "1");
        // Its key is not a MAC, so no gateway-own row can back a gateway_ip.
        assert_eq!(cell(&t, 0, "gateway_ip"), "");
    }

    /// The SSID is a best-effort time-overlap guess: present when a named
    /// `link_sample` falls inside the segment's span, blank otherwise. Never
    /// asserted.
    #[test]
    fn the_ssid_label_is_best_effort_present_only_on_time_overlap() {
        let s = DuckdbStore::in_memory().unwrap();
        // K1 is active [10s, 30s] and a named link tick lands inside it.
        neigh(&s, 10 * SEC, Some(K1), "11:22:33:44:55:66", "10.0.0.5");
        neigh(&s, 30 * SEC, Some(K1), "11:22:33:44:55:66", "10.0.0.5");
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok); // ssid "cowork"
        // K2 is active far later, with no link tick overlapping its span.
        neigh(&s, 100 * SEC, Some(K2), "22:33:44:55:66:77", "192.168.1.9");

        let t = s.segments().unwrap();
        let k1_ssid = (0..t.rows.len())
            .find(|&i| cell(&t, i, "network_key") == K1)
            .map(|i| cell(&t, i, "ssid_guess"))
            .unwrap();
        let k2_ssid = (0..t.rows.len())
            .find(|&i| cell(&t, i, "network_key") == K2)
            .map(|i| cell(&t, i, "ssid_guess"))
            .unwrap();
        assert_eq!(
            k1_ssid, "cowork",
            "overlapping link tick supplies the guess"
        );
        assert_eq!(k2_ssid, "", "no overlap leaves it blank, not invented");
    }

    #[test]
    fn history_at_selects_only_the_neighbours_live_at_that_instant() {
        let s = DuckdbStore::in_memory().unwrap();
        // A: live [10s, 50s]. B: live [60s, 80s].
        neigh(&s, 10 * SEC, Some(K1), "aa:aa:aa:aa:aa:aa", "10.0.0.5");
        neigh(&s, 50 * SEC, Some(K1), "aa:aa:aa:aa:aa:aa", "10.0.0.5");
        neigh(&s, 60 * SEC, Some(K1), "bb:bb:bb:bb:bb:bb", "10.0.0.6");
        neigh(&s, 80 * SEC, Some(K1), "bb:bb:bb:bb:bb:bb", "10.0.0.6");

        // At 30s only A is live.
        let t = s.history(K1, HistoryWindow::At(30 * SEC)).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "mac"), "aa:aa:aa:aa:aa:aa");

        // A window that spans both catches both.
        let t = s
            .history(
                K1,
                HistoryWindow::Range {
                    since: 10 * SEC,
                    until: 80 * SEC,
                },
            )
            .unwrap();
        assert_eq!(t.rows.len(), 2);
    }

    /// A window carries the count of ports and vulns active over the same slice,
    /// so "who was here and what was open" reads in one table.
    #[test]
    fn history_carries_ports_and_vulns_active_in_the_window() {
        let s = DuckdbStore::in_memory().unwrap();
        neigh(&s, 10 * SEC, Some(K1), "aa:aa:aa:aa:aa:aa", "10.0.0.5");
        neigh(&s, 50 * SEC, Some(K1), "aa:aa:aa:aa:aa:aa", "10.0.0.5");
        s.write_neighbor_port(&NeighborPort {
            network_key: Some(K1.into()),
            mac: "aa:aa:aa:aa:aa:aa".into(),
            ip: "10.0.0.5".into(),
            port: 445,
            ts_us: 20 * SEC,
            banner: None,
        })
        .unwrap();
        s.write_neighbor_vuln(&NeighborVuln {
            network_key: Some(K1.into()),
            mac: "aa:aa:aa:aa:aa:aa".into(),
            port: 445,
            cve_id: "CVE-2020-0796".into(),
            confidence: "high".into(),
            known_exploited: true,
            cvss: Some(10.0),
            ts_us: 20 * SEC,
        })
        .unwrap();

        let t = s
            .history(
                K1,
                HistoryWindow::Range {
                    since: 10 * SEC,
                    until: 50 * SEC,
                },
            )
            .unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "open_ports"), "1");
        assert_eq!(cell(&t, 0, "vulns"), "1");
    }

    /// The `unknown` segment is as reachable in `history` as in the list.
    #[test]
    fn history_reaches_the_unknown_segment() {
        let s = DuckdbStore::in_memory().unwrap();
        neigh(&s, 10 * SEC, None, "aa:aa:aa:aa:aa:aa", "10.0.0.5");
        let t = s.history("unknown", HistoryWindow::At(10 * SEC)).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "mac"), "aa:aa:aa:aa:aa:aa");
    }

    /// A non-key filter is an error, never a query that matches nothing — the
    /// same discipline as `neighbors_sql`.
    #[test]
    fn history_rejects_a_non_key_network() {
        assert!(history_sql(K1, HistoryWindow::At(0)).is_ok());
        assert!(history_sql("unknown", HistoryWindow::At(0)).is_ok());
        for bad in ["'; DROP TABLE neighbor; --", "a4:83", "не мак", ""] {
            assert!(
                history_sql(bad, HistoryWindow::At(0)).is_err(),
                "{bad:?} must be an error, not a query that matches nothing"
            );
        }
    }
}
