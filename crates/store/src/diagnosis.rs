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
//! - `gw=OK`, `direct=OK`, `vless=OK`, tun answered anything but 204 (`000` =
//!   no status at all, a captive portal's 200, a 5xx) ⇒ the proxy is wedged; a
//!   restart cures it (realm net-observer, node #122).
//! - `vless=FAIL` with the rest OK ⇒ that proxy server is dead or blocked from
//!   this path.
//! - `tun=000` **with `load1` in the tens** ⇒ host starvation, NOT a wedge: a
//!   restart does not cure it and tears down live flows. Only a silent probe
//!   reads as starvation — an answered non-204 under load is still the proxy's.
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
//! | `gap` | the moment asked about lies inside an observation gap (pause, stop, or sleep) |
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
//! An operator pause is not the only hole the record can name this way. A
//! **stop** is a startup edge with no preceding pause: the daemon died or was
//! killed outright, so the record simply stops, and the gap runs from the
//! newest sample before that edge to the edge itself — unless a pause gap
//! already closes at that same edge, in which case the pause already names
//! the hole. A **sleep** is two consecutive POINTS — a sample of any
//! stream, or a recorded pause/resume/startup edge — further apart than
//! [`DEFAULT_SLEEP_THRESHOLD_US`] and not both inside one recorded
//! pause/stop gap: the machine slept while the daemon kept running. Edges
//! count as points so a stride can never straddle a gap's own boundary,
//! which is what lets the residual after a short pause still surface as its
//! own sleep instead of being swallowed whole. Both are derived the same
//! way as a pause — in SQL, never stored — and read as `gap` identically;
//! only `observation_gaps`/`silences`'s `kind` column tells the three apart
//! (realm net-observer, node #109).
//!
//! ## Passive stretches
//!
//! The second bracket, and a different one: while the probing tier is
//! `passive` the daemon puts nothing on the wire but keeps writing a row per
//! tick, every probe verdict `SKIP` (realm net-observer, node #88). The
//! per-moment queries need no special case for it — a `SKIP` already reads as
//! `unknown` — but a reader of a long run of `SKIP`s must be able to tell
//! "withheld" from "could not run", so `gaps` lists each stretch from the
//! `probing_edge` rows next to the pauses, marked `kind = 'passive'`. Samples
//! never close a stretch (they land throughout); only an `active` edge does.
//!
//! ## Correlation
//!
//! Streams have their own cadences, so correlation is by DuckDB `ASOF JOIN`:
//! "the nearest proxy/host sample at or before this link sample". That is the
//! join the whole storage choice was made for.

use crate::{DuckdbStore, QueryTable, Store, StoreError};
use duckdb::types::{ToSql, Value};
pub use types::{ConnectionsGroupBy, HistoryWindow};

/// A prepared query alongside the values bound to its `?` placeholders, in the
/// order those placeholders appear in the SQL text.
///
/// Values leave the SQL text: `?` goes into the string, the value it stands for
/// goes into `params`, and the driver binds it without re-parsing it as SQL.
/// Why the builders were moved off `format!`: (realm net-observer, node #29).
pub struct PreparedSql {
    sql: String,
    params: Vec<Value>,
}

impl PreparedSql {
    /// A statement with no placeholders, so a plain query can go down the
    /// same path as a parameterized one — the daemon runs every diagnosis
    /// through one budgeted call.
    pub fn plain(sql: String) -> Self {
        Self {
            sql,
            params: Vec::new(),
        }
    }

    pub(crate) fn sql(&self) -> &str {
        &self.sql
    }

    pub(crate) fn params_as_dyn(&self) -> Vec<&dyn ToSql> {
        self.params.iter().map(|v| v as &dyn ToSql).collect()
    }
}

/// Host `load1` above which a dead tun reads as starvation rather than a wedge.
///
/// The ONE source: the daemon's `STARVATION_LOAD` is this constant, so the
/// trigger that records an incident and the diagnosis that reads it back use
/// the same number by construction. Like the `starvation` trigger the
/// comparison is strict (`load1 > threshold`).
pub const DEFAULT_STARVATION_LOAD: f64 = 10.0;

/// Longest gap between two consecutive tun-dead proxy ticks that still counts as
/// one episode (30 s — several polling ticks).
pub const DEFAULT_EPISODE_GAP_US: i64 = 30_000_000;

/// How far back the gateway ramp is plotted before a drop, by default (2 min —
/// comfortably longer than the ~40 s climb of the coworking gateway signature).
pub const DEFAULT_RAMP_WINDOW_US: i64 = 120_000_000;

/// The gap between two consecutive samples (of any stream) above which the
/// record reads a `sleep` rather than a lost tick: 3x the link collector's
/// default 15 s interval. Embedded as a literal into [`observation_gap_cte`]
/// rather than threaded as a bind parameter — the CTE feeds four call sites,
/// each with its own already-verified `?` order, and a config knob (the CLI's
/// `--sleep-threshold`, the daemon's `cfg.collectors.link.interval`) is a
/// later step (realm net-observer, node #109).
pub const DEFAULT_SLEEP_THRESHOLD_US: i64 = 45_000_000;

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

/// One row per interval the record cannot vouch for, with `cause` naming
/// which of three openers produced it (realm net-observer, node #109). Every
/// interval is half-open `[gap_opened_us, gap_closed_us)`; `gap_closed_us`
/// (and `gap_closed_by`) is `NULL` only when nothing at all follows the
/// opener — the record simply ends inside it.
///
/// - **`pause`** — an `observing = false` edge. Closes at the earliest of
///   three candidates, `gap_closed_by` naming which:
///
///   | `gap_closed_by` | what closed the gap |
///   | --- | --- |
///   | `resume` | an operator `observing = true` edge (`cause` `control`) |
///   | `startup` | a recorded startup edge — this process began collecting |
///   | `sample` | no edge at all: the first sample of any stream, inferred |
///
///   A recorded edge WINS a tie with a sample at the same instant, because it
///   is the fact and the sample is only evidence of it.
/// - **`stop`** — a recorded startup edge (`observing_edge` with
///   `observing AND cause = 'startup'`) that no `pause` gap already explains:
///   the daemon died or was killed with no pause edge, so the record simply
///   stops, and the startup edge is the next fact it carries. Opens at the
///   newest sample strictly before that edge (`gap_closed_by` always
///   `startup`, closing at the edge itself); a startup edge that already
///   closes an open `pause` gap opens nothing here (the pause already names
///   the hole), and neither does the very first startup a record ever sees —
///   no earlier sample means no "before" to bound.
/// - **`sleep`** — two consecutive POINTS more than `sleep_threshold_us`
///   apart and not both inside one recorded `pause`/`stop` gap, where a point
///   is a sample of any stream OR a recorded `observing_edge` (pause, resume,
///   or startup). Edges are points, not just interval endpoints elsewhere, so
///   a stride between two consecutive points can never straddle a gap's own
///   boundary — it is either fully inside one gap (excluded: the gap already
///   names it) or fully outside every one (a real sleep). That is why the
///   exclusion is containment (`gap.opened <= a AND gap.closed >= b`), not
///   mere overlap: a 185 s residual right after a 5 s pause is still a sleep
///   of its own, not swallowed by the pause that happens to sit inside the
///   same wider stride between two real samples. Always closes `sample` at
///   the later of the pair — even when that point happens to be an edge, the
///   sleep itself has no dedicated closing edge, only the record's next
///   instant.
///
/// A function rather than a `const`, because the sleep opener embeds its
/// threshold as a SQL literal — no new `?` placeholder, so the four call
/// sites keep their already-verified `params` order
/// ([`DEFAULT_SLEEP_THRESHOLD_US`]).
/// Expands to several comma-joined sibling CTEs (`pauses`, `stops_raw`,
/// `stops`, `closed_gap`, `sleeps`, `observation_gap`) — a fragment spliced
/// into a caller's own `WITH` list right after [`SAMPLE_TS_CTE`], exactly
/// where the single `observation_gap` CTE used to sit. Each later CTE only
/// references sibling CTEs already defined earlier in the same list (the
/// pattern [`SAMPLE_TS_CTE`] itself already relies on), so no nested `WITH`
/// is needed.
fn observation_gap_cte(sleep_threshold_us: i64) -> String {
    format!(
        "\
pauses AS (
  SELECT gap_opened_us, gap_closed_us, gap_closed_by, 'pause' AS cause
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
),
-- Every recorded startup edge, opened at the newest earlier sample — before
-- the check below drops the ones a `pause` gap already explains.
stops_raw AS (
  SELECT
    (SELECT max(t.ts_us) FROM sample_ts t WHERE t.ts_us < su.ts_us) AS gap_opened_us,
    su.ts_us AS gap_closed_us,
    'startup' AS gap_closed_by,
    'stop' AS cause
  FROM (SELECT ts_us FROM observing_edge WHERE observing AND cause = 'startup') su
),
stops AS (
  SELECT gap_opened_us, gap_closed_us, gap_closed_by, cause
  FROM stops_raw
  WHERE gap_opened_us IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM pauses p
      WHERE p.gap_closed_by = 'startup' AND p.gap_closed_us = stops_raw.gap_closed_us
    )
),
-- The finished pause/stop intervals, for the sleep opener to stay clear of.
closed_gap AS (
  SELECT gap_opened_us, gap_closed_us FROM pauses
  UNION ALL SELECT gap_opened_us, gap_closed_us FROM stops
),
-- Every instant the record can anchor a stride to: a sample OF ANY STREAM,
-- or a recorded pause/resume/startup edge. Edges are points too (not just
-- interval endpoints elsewhere), so a stride between two consecutive points
-- can never straddle a gap's own boundary — it either sits entirely inside
-- one recorded pause/stop gap, or entirely outside every one (realm
-- net-observer, node #109): excluding only the strides fully CONTAINED by a
-- gap, rather than merely overlapping one, is what lets the residual after a
-- pause or a stop still surface as its own sleep.
points AS (
  SELECT ts_us FROM sample_ts
  UNION SELECT ts_us FROM observing_edge
),
sleeps AS (
  SELECT a AS gap_opened_us, b AS gap_closed_us, 'sample' AS gap_closed_by, 'sleep' AS cause
  FROM (
    SELECT ts_us AS b, lag(ts_us) OVER (ORDER BY ts_us) AS a
    FROM points
  ) stride
  WHERE a IS NOT NULL AND b - a > {sleep_threshold_us}
    AND NOT EXISTS (
      SELECT 1 FROM closed_gap c
      WHERE c.gap_opened_us <= stride.a AND c.gap_closed_us >= stride.b
    )
),
observation_gap AS (
  SELECT gap_opened_us, gap_closed_us, gap_closed_by, cause FROM pauses
  UNION ALL SELECT gap_opened_us, gap_closed_us, gap_closed_by, cause FROM stops
  UNION ALL SELECT gap_opened_us, gap_closed_us, gap_closed_by, cause FROM sleeps
)"
    )
}

/// The gap containing the moment bound at its two `?` placeholders (the same
/// value goes to both), or no row at all. At most one row. Reads
/// [`observation_gap_cte`]'s output generically — any `cause` answers `gap`,
/// so a stop or a sleep is refused exactly like a pause.
const GAP_AT_CTE: &str = "\
gap_at AS (
  SELECT gap_opened_us, gap_closed_us
  FROM observation_gap
  WHERE gap_opened_us <= ?
    AND (gap_closed_us IS NULL OR gap_closed_us > ?)
  ORDER BY gap_opened_us DESC
  LIMIT 1
)";

/// One row per stretch in which the daemon withheld every probe — the second
/// kind of bracket, read from `probing_edge` (realm net-observer, node #88).
///
/// NOT an observation gap, and deliberately not folded into
/// [`observation_gap_cte`]: a passive daemon keeps writing a row per tick, so
/// the per-moment queries already answer `unknown` from the `SKIP`s they find
/// there, and a moment inside a passive stretch must not read as `gap` — the
/// record does exist, it just carries no measurement. This CTE only names the
/// stretches so a reader knows the `SKIP`s were withheld, not failed.
///
/// A stretch opens at a `passive` edge whose predecessor is not `passive` (a
/// startup edge re-declaring passive after a crash continues the stretch
/// rather than opening a second one) and is half-open
/// `[gap_opened_us, gap_closed_us)`. It closes at the first later `active`
/// edge, and `gap_closed_by` says which kind:
///
/// | `gap_closed_by` | what closed the stretch |
/// | --- | --- |
/// | `active` | an operator `SetProbing(active)` (a peer asked) |
/// | `startup` | a startup edge whose configured default is `active` |
///
/// Samples never close it — they keep landing throughout — so `gap_closed_us`
/// is `NULL` exactly when the record ends still passive.
const PROBING_STRETCH_CTE: &str = "\
probing_stretch AS (
  SELECT gap_opened_us, gap_closed_us, gap_closed_by
  FROM (
    SELECT p.ts_us AS gap_opened_us,
           e.ts_us AS gap_closed_us,
           e.closed_by AS gap_closed_by,
           row_number() OVER (PARTITION BY p.ts_us ORDER BY e.ts_us) AS rn
    FROM (
      SELECT ts_us
      FROM (SELECT ts_us, tier, lag(tier) OVER (ORDER BY ts_us) AS prev_tier
            FROM probing_edge)
      WHERE tier = 'passive' AND (prev_tier IS NULL OR prev_tier <> 'passive')
    ) p
    LEFT JOIN (
      SELECT ts_us,
             CASE WHEN peer_uid IS NULL THEN 'startup' ELSE 'active' END AS closed_by
      FROM probing_edge WHERE tier = 'active'
    ) e ON e.ts_us > p.ts_us
  )
  WHERE rn = 1
)";

/// **Observation gaps** — every interval the record cannot vouch for at all:
/// an operator pause, a stop before a startup, or a sleep between ticks.
///
/// The read side of [`observation_gap_cte`]: one row per gap, carrying `kind`
/// (`pause` | `stop` | `sleep`), open-ended (`gap_closed_us` `NULL`) only when
/// the record ends inside it.
///
/// Never `passive`: a passive stretch still writes a sample every tick (its
/// probe verdicts `SKIP`), so it is not a hole in the record the way these
/// three are — this is what a reader built before the probing tier asks for
/// as `DiagnosticQuery::Gaps`, and a passive stretch listed here would be
/// printed by that reader as a pause. The passive stretches ride alongside in
/// [`silences_sql`], under a query id that reader has never heard of.
pub fn observation_gaps_sql() -> String {
    let gap = observation_gap_cte(DEFAULT_SLEEP_THRESHOLD_US);
    format!(
        "WITH {SAMPLE_TS_CTE},
{gap}
SELECT cause AS kind, gap_opened_us, gap_closed_us, gap_closed_by
FROM observation_gap ORDER BY gap_opened_us"
    )
}

/// **Silences** — every bracketed silence the record contains: each
/// [`observation_gap_cte`] gap (pause, stop, sleep), and each stretch the
/// daemon spent withholding its probes.
///
/// The read side of both brackets, told apart by `kind`: `pause`/`stop`/
/// `sleep` rows are [`observation_gap_cte`]'s own `cause` (no samples at
/// all — exactly the rows of [`observation_gaps_sql`]), `passive` rows the
/// withheld probes of [`PROBING_STRETCH_CTE`] (samples every tick, verdicts
/// `SKIP`). Each is open-ended (`gap_closed_us` `NULL`) only when the record
/// ends inside it. (realm net-observer, node #88, node #109)
pub fn silences_sql() -> String {
    let gap = observation_gap_cte(DEFAULT_SLEEP_THRESHOLD_US);
    format!(
        "WITH {SAMPLE_TS_CTE},
{gap},
{PROBING_STRETCH_CTE}
SELECT cause AS kind, gap_opened_us, gap_closed_us, gap_closed_by FROM observation_gap
UNION ALL
SELECT 'passive' AS kind, gap_opened_us, gap_closed_us, gap_closed_by FROM probing_stretch
ORDER BY gap_opened_us, kind"
    )
}

/// The `WITH` clause shared by the per-moment queries: one row per link sample,
/// carrying every layer's state as of that moment plus the diagnosed layer, and
/// the observation gaps that say when such a row is not a reading at all.
///
/// Binds one `?` — the starvation threshold — in `layer`'s `CASE`.
fn layer_state_with() -> String {
    let gap = observation_gap_cte(DEFAULT_SLEEP_THRESHOLD_US);
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
           WHEN p.tun_code = 0 AND h.load1 > ? THEN 'host'
           -- Any answer but 204 means the tunnel did not reach its far end
           -- (a captive portal answers 200) — the shell oracle's `tun != 204`
           -- vocabulary (realm net-observer, node #122).
           WHEN p.tun_code <> 204 THEN 'proxy'
           WHEN l.gw <> 'OK' OR l.direct <> 'OK' THEN 'unknown'
           ELSE 'healthy'
         END AS layer
  FROM link_sample l
  ASOF LEFT JOIN proxy_tick p ON l.ts_us >= p.ts_us
  ASOF LEFT JOIN host_sample h ON l.ts_us >= h.ts_us
),
{SAMPLE_TS_CTE},
{gap}"
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
pub fn verdict_at_sql(ts_us: i64, load_threshold: f64) -> PreparedSql {
    let sql = format!(
        "{},
{GAP_AT_CTE}
SELECT ts_us, gw, gw_rtt_ms, direct, vless, tun_code, load1, layer,
       CAST(NULL AS BIGINT) AS gap_opened_us, CAST(NULL AS BIGINT) AS gap_closed_us
FROM (
  SELECT ts_us, gw, gw_rtt_ms, direct, vless, tun_code, load1, layer
  FROM layer_state
  WHERE ts_us <= ?
  ORDER BY ts_us DESC
  LIMIT 1
)
WHERE NOT EXISTS (SELECT 1 FROM gap_at)
UNION ALL
SELECT CAST(NULL AS BIGINT), CAST(NULL AS VARCHAR), CAST(NULL AS DOUBLE),
       CAST(NULL AS VARCHAR), CAST(NULL AS VARCHAR), CAST(NULL AS USMALLINT),
       CAST(NULL AS DOUBLE), 'gap', gap_opened_us, gap_closed_us
FROM gap_at",
        layer_state_with(),
    );
    // Bound in the order their `?` appear: the threshold in `layer_state_with`,
    // then the moment twice in `GAP_AT_CTE`, then the moment once more in the
    // final `WHERE`.
    PreparedSql {
        sql,
        params: vec![
            Value::Double(load_threshold),
            Value::BigInt(ts_us),
            Value::BigInt(ts_us),
            Value::BigInt(ts_us),
        ],
    }
}

/// **Incident with its context** — for every incident, the layer state at or
/// just before it opened.
///
/// An incident whose `opened_us` falls inside an observation gap gets no
/// context at all: its state columns are `NULL`, its `layer` is `'gap'`, and
/// `gap_opened_us` / `gap_closed_us` bound the silence it opened in. The layer
/// state from before the pause is not context for it.
pub fn incident_context_sql(load_threshold: f64) -> PreparedSql {
    let sql = format!(
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
        layer_state_with()
    );
    PreparedSql {
        sql,
        params: vec![Value::Double(load_threshold)],
    }
}

/// **Wedge vs starvation** — the discriminator the project paid nine hours to
/// learn, on 2026-07-27.
///
/// Groups contiguous dead proxy ticks — `tun_code IS NOT NULL AND tun_code <>
/// 204`, the oracle's dead-tun vocabulary (realm net-observer, node #122) —
/// (gap ≤ `gap_us`) into episodes and names each one:
///
/// - `link` — the gateway was down through it: not a proxy fault at all;
/// - `vless` — the proxy server was unreachable: a restart is not the cure;
/// - `starvation` — `load1 > load_threshold` AND every tick in the episode
///   went unanswered (`tun_code = 0` throughout, i.e. the probe timed out): a
///   restart does NOT cure it and tears down live flows;
/// - `wedge` — either the host was idle while the tun was dead, or the tun
///   answered with something other than 204 (a captive portal's 200
///   included) at any point in the episode even under load: the tunnel
///   answered, wrongly, and load does not explain a wrong answer — a
///   restart cures it;
/// - `unknown` — no `load1` (or no link sample) covering the episode, so the
///   record cannot tell the two apart.
///
/// Ticks with a `NULL` `tun_code` (the probe did not run) are not episodes.
pub fn wedge_vs_starvation_sql(load_threshold: f64, gap_us: i64) -> PreparedSql {
    let sql = format!(
        "WITH {PROXY_TICK_CTE},
dead AS (
  SELECT ts_us, vless, tun_code FROM proxy_tick
  WHERE tun_code IS NOT NULL AND tun_code <> 204
),
marked AS (
  SELECT ts_us,
         vless,
         tun_code,
         CASE WHEN lag(ts_us) OVER (ORDER BY ts_us) IS NULL
                OR ts_us - lag(ts_us) OVER (ORDER BY ts_us) > ?
              THEN 1 ELSE 0 END AS starts_episode
  FROM dead
),
grouped AS (
  SELECT ts_us, vless, tun_code, sum(starts_episode) OVER (ORDER BY ts_us) AS episode
  FROM marked
),
ctx AS (
  SELECT g.episode, g.ts_us, g.vless, g.tun_code, h.load1, l.gw, l.direct
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
         -- Starvation is a silent probe: any answered (non-204) code under
         -- load is a wedge instead — the tunnel answered, wrongly.
         WHEN max(load1) > ? AND max(tun_code) = 0 THEN 'starvation'
         ELSE 'wedge'
       END AS verdict
FROM ctx
GROUP BY episode
ORDER BY opened_us"
    );
    PreparedSql {
        sql,
        params: vec![Value::BigInt(gap_us), Value::Double(load_threshold)],
    }
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
pub fn gateway_ramp_sql(drop_ts_us: i64, window_us: i64) -> PreparedSql {
    let gap = observation_gap_cte(DEFAULT_SLEEP_THRESHOLD_US);
    let sql = format!(
        "WITH {SAMPLE_TS_CTE},
{gap},
win AS (
  SELECT ts_us, gw, gw_rtt_ms
  FROM link_sample
  WHERE ts_us <= ? AND ts_us >= ? - ?
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
           least(coalesce(gap_closed_us, ?), ?)
             - greatest(gap_opened_us, ? - ?)
         )), 0) AS BIGINT) AS observation_gap_us
  FROM observation_gap
)
SELECT w.ts_us,
       ? - w.ts_us AS us_before_drop,
       w.gw,
       w.gw_rtt_ms,
       CASE WHEN o.observation_gap_us = 0 THEN f.slope_ms_per_s END AS slope_ms_per_s,
       CASE WHEN o.observation_gap_us = 0 THEN f.fitted_samples END AS fitted_samples,
       o.observation_gap_us
FROM win w, fit f, overlap o
ORDER BY w.ts_us"
    );
    // Bound in text order: win's (drop, drop, window), overlap's
    // (drop, drop, drop, window), then the final SELECT's drop.
    PreparedSql {
        sql,
        params: vec![
            Value::BigInt(drop_ts_us),
            Value::BigInt(drop_ts_us),
            Value::BigInt(window_us),
            Value::BigInt(drop_ts_us),
            Value::BigInt(drop_ts_us),
            Value::BigInt(drop_ts_us),
            Value::BigInt(window_us),
            Value::BigInt(drop_ts_us),
        ],
    }
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
/// the OS had filled, `sweep`/`mdns` that an operator sent it looking, and
/// `announce` that the device said so itself — a frame it put on the segment,
/// heard by the passive listener (realm net-observer, node #92).
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
       -- `network_key` is the gateway's ARP-resolved MAC (realm net-observer,
       -- node #94); this is a plain string comparison, so a `network_key`
       -- written before the source-side normalisation (raw, unpadded octets)
       -- will not join against `neighbor.mac`, which `parse_arp_table`
       -- always normalises — form-sensitive for pre-fix rows, not rewritten
       -- this round.
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

/// The activity predicate of a [`HistoryWindow`] for a table carrying
/// `first_seen_us` / `last_seen_us`, with those columns qualified by `alias`.
///
/// The window type itself lives in `types` (it travels over the socket); only
/// its SQL rendering is this crate's business.
fn window_predicate(window: HistoryWindow, alias: &str) -> String {
    match window {
        HistoryWindow::At(at) => {
            format!("{alias}.first_seen_us <= {at} AND {alias}.last_seen_us >= {at}")
        }
        HistoryWindow::Range { since, until } => {
            format!("{alias}.first_seen_us <= {until} AND {alias}.last_seen_us >= {since}")
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
    let neighbor_pred = window_predicate(window, "n");
    let port_pred = window_predicate(window, "p");
    let vuln_pred = window_predicate(window, "v");
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

/// **What this machine talks to** — the newest tick of the live flow table,
/// grouped by `group_by` (realm net-observer, node #75).
///
/// Reads the newest `connection_sample` tick only: the table is a present-tense
/// question ("what is talking right now"), and the per-tick rows are already
/// the aggregate the collector folded. Columns: `ts_us` and `verdict` (the
/// tick's, replicated on every row), `key` (the group), `count` (live flows in
/// the group), `upload` / `download` (their bytes summed), and `hosts` — the
/// distinct names seen in the group, so an address grouping still says which
/// names sat behind the address. Ordered by `count DESC`.
///
/// The key of a flow with the grouped fact missing falls back to the next best
/// (a bare-address flow is keyed by its address under `host`; a flow whose
/// address the proxy never learned is keyed by its name under `ip`), and to
/// `-` when nothing is known — never dropped, never a NULL group.
///
/// **The refusal is preserved.** A tick with no rows — the API did not answer
/// (`SKIP`) or it listed nothing (`OK`) — answers ONE row carrying `ts_us`
/// and `verdict` with every other column NULL, so a reader sees "could not
/// look" and "nothing is talking" as different answers, and neither as an
/// empty table indistinguishable from a record with no ticks at all.
pub fn connections_sql(group_by: ConnectionsGroupBy) -> String {
    let key = match group_by {
        ConnectionsGroupBy::Host => "coalesce(host, dst_ip, '-')",
        ConnectionsGroupBy::Ip => "coalesce(dst_ip, host, '-')",
        // A v6 address carries colons of its own, so it is bracketed the way
        // a socket address is written (`[2a00::1]:443`); a name never is.
        ConnectionsGroupBy::IpPort => {
            "CASE WHEN dst_ip LIKE '%:%' THEN '[' || dst_ip || ']' \
             ELSE coalesce(dst_ip, host, '-') END \
             || ':' || coalesce(CAST(dst_port AS VARCHAR), '-')"
        }
        ConnectionsGroupBy::Process => "coalesce(process, '-')",
    };
    format!(
        "WITH tick AS (
  SELECT * FROM connection_sample
  WHERE ts_us = (SELECT max(ts_us) FROM connection_sample)
)
SELECT ts_us, verdict, {key} AS key,
       sum(count) AS count, sum(upload) AS upload, sum(download) AS download,
       string_agg(DISTINCT host, ',' ORDER BY host) AS hosts
FROM tick
WHERE network IS NOT NULL
GROUP BY ts_us, verdict, key
UNION ALL
SELECT ts_us, verdict, NULL, NULL, NULL, NULL, NULL
FROM tick
WHERE network IS NULL
ORDER BY count DESC NULLS LAST, key"
    )
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

/// The canned diagnoses with their default thresholds, each one call. The
/// read primitives they run on (`query_table` / `query_prepared`) are on the
/// [`Store`] trait, so a caller holding `dyn Store` — the daemon's socket
/// server — can run the same builders without naming this type.
impl DuckdbStore {
    /// Run [`verdict_at_sql`] with [`DEFAULT_STARVATION_LOAD`].
    pub fn verdict_at(&self, ts_us: i64) -> Result<QueryTable, StoreError> {
        self.query_prepared(&verdict_at_sql(ts_us, DEFAULT_STARVATION_LOAD))
    }

    /// Run [`incident_context_sql`] with [`DEFAULT_STARVATION_LOAD`].
    pub fn incident_context(&self) -> Result<QueryTable, StoreError> {
        self.query_prepared(&incident_context_sql(DEFAULT_STARVATION_LOAD))
    }

    /// Run [`wedge_vs_starvation_sql`] with the defaults.
    pub fn wedge_vs_starvation(&self) -> Result<QueryTable, StoreError> {
        self.query_prepared(&wedge_vs_starvation_sql(
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
        self.query_prepared(&gateway_ramp_sql(drop_ts_us, DEFAULT_RAMP_WINDOW_US))
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

    /// Run [`silences_sql`].
    pub fn silences(&self) -> Result<QueryTable, StoreError> {
        self.query_table(&silences_sql())
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

    /// Run [`connections_sql`] grouped by `group_by`.
    pub fn connections(&self, group_by: ConnectionsGroupBy) -> Result<QueryTable, StoreError> {
        self.query_table(&connections_sql(group_by))
    }
}

/// **The latest air scan itself** — when it ran, its verdict, why it was skipped
/// if it was, and how many access points it heard.
///
/// Read FIRST, its `ts_us` then pinning [`air_aps_at_sql`]: a `SKIP` row means
/// the scan could not look, and its empty AP list must never be presented as an
/// empty air (realm net-observer, node #48).
pub const AIR_LATEST_SCAN_SQL: &str = "\
SELECT ts_us, air, reason, ap_count
FROM air_sample
ORDER BY ts_us DESC
LIMIT 1";

/// **The access points one specific air scan heard** — one row each, as
/// reported, filtered to the scan the caller already read
/// (`WHERE ts_us = ?`, bound rather than re-selected as `max(ts_us)`) so a
/// scan the collector writes between two round trips over the live socket can
/// never pair its header with a different scan's AP list (realm net-observer,
/// node #99).
///
/// A slice, not a history: the report carries no BSSID, so an AP here cannot be
/// matched to one in any other scan (realm net-observer, node #47). Ordered
/// loudest first as a stable fallback; the reader re-orders by the overlap
/// hypothesis it computes against our own channel.
pub fn air_aps_at_sql(scan_ts_us: i64) -> PreparedSql {
    PreparedSql {
        sql: "\
SELECT channel, channel_band, channel_width_mhz, phy_mode, security, rssi_dbm, noise_dbm
FROM air_ap
WHERE ts_us = ?
ORDER BY rssi_dbm DESC NULLS LAST, channel"
            .to_string(),
        params: vec![Value::BigInt(scan_ts_us)],
    }
}

/// **Our own channel**, from the most recent `wifi_sample` that actually carried
/// one — the band the overlap hypothesis is computed against.
///
/// Returns no row when the radio has never reported a channel (never associated,
/// or the `wifi` collector disabled), and the reader must then say the overlap
/// cannot be computed rather than showing a column of zeroes.
pub const AIR_SELF_CHANNEL_SQL: &str = "\
SELECT ts_us, channel, channel_band, channel_width_mhz
FROM wifi_sample
WHERE wifi = 'OK' AND channel IS NOT NULL AND channel_band IS NOT NULL
ORDER BY ts_us DESC
LIMIT 1";

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
        ProbingEdge, ProbingTier, ProxySample, Sample, TcpVerdict,
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

    fn proxy(s: &DuckdbStore, ts_us: i64, tcp: TcpVerdict, tun: Option<u16>) {
        s.write_sample(&Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "1.2.3.4".into(),
            tcp,
            rtt_ms: None,
            tun_code: tun,
            selector: Some("auto".into()),
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
        }))
        .unwrap();
    }

    fn host(s: &DuckdbStore, ts_us: i64, load1: f64) {
        s.write_sample(&Sample::Host(HostSample {
            ts_us,
            load1,
            load5: load1,
            load15: load1,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
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

    /// One switch of the probing tier. `peer` is `None` for the startup edge
    /// that applies the configured default, `Some(uid)` for an operator's.
    fn probing_edge(s: &DuckdbStore, ts_us: i64, tier: ProbingTier, peer: Option<u32>) {
        s.write_probing_edge(&ProbingEdge {
            ts_us,
            tier,
            peer_uid: peer,
        })
        .unwrap();
    }

    /// A tick every stream writes while the tier is passive: the probes are
    /// withheld, so their verdicts are `SKIP`, and the row still lands.
    fn passive_tick(s: &DuckdbStore, ts_us: i64) {
        link(s, ts_us, GwVerdict::Skip, None, TcpVerdict::Skip);
        proxy(s, ts_us, TcpVerdict::Skip, None);
        host(s, ts_us, 1.5);
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

    /// A captive portal's 200 is an answer, not a health check pass: the tun
    /// reached something, but not its far end (realm net-observer, node
    /// #122). It must read as `proxy`, not `healthy`.
    #[test]
    fn verdict_at_blames_the_proxy_on_a_captive_portal_answer() {
        let s = DuckdbStore::in_memory().unwrap();
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(200));
        host(&s, 20 * SEC, 1.2);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "proxy");
    }

    /// The same captive-portal answer under load is still the proxy's fault,
    /// not starvation: the tunnel answered, wrongly, and load does not
    /// explain a wrong answer. Only a silent probe (`tun_code = 0`) reads as
    /// `host`.
    #[test]
    fn verdict_at_blames_the_proxy_not_the_host_for_a_captive_portal_under_load() {
        let s = DuckdbStore::in_memory().unwrap();
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, Some(200));
        host(&s, 20 * SEC, 31.0);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "proxy");
        assert_ne!(cell(&t, 0, "layer"), "host");
    }

    /// A tun code that never arrived (not `SKIP`, just absent) is unknown,
    /// the same as a probe that did not run at all.
    #[test]
    fn verdict_at_reports_unknown_when_tun_code_is_null() {
        let s = DuckdbStore::in_memory().unwrap();
        link(&s, 20 * SEC, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
        proxy(&s, 20 * SEC, TcpVerdict::Ok, None);
        host(&s, 20 * SEC, 1.0);

        let t = s.verdict_at(20 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "unknown");
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

    /// Push `n` ticks of a dead tun (answering `code`, anything but 204) over
    /// a healthy link, at `load1`.
    fn tun_dead_episode(s: &DuckdbStore, from_us: i64, n: i64, code: u16, load1: f64) {
        for i in 0..n {
            let ts = from_us + i * SEC;
            link(s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(s, ts, TcpVerdict::Ok, Some(code));
            host(s, ts, load1);
        }
    }

    #[test]
    fn a_dead_tun_on_an_idle_host_is_a_wedge() {
        let s = DuckdbStore::in_memory().unwrap();
        tun_dead_episode(&s, 10 * SEC, 4, 0, 1.3);
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
        tun_dead_episode(&s, 10 * SEC, 4, 0, 31.0);
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "starvation");
        assert_ne!(cell(&t, 0, "verdict"), "wedge");
        assert_eq!(cell(&t, 0, "max_load1"), "31");
    }

    /// A captive portal's 200 under load is still a wedge, not starvation:
    /// the tunnel answered, wrongly, and load does not explain a wrong
    /// answer — only an episode of silent probes (`tun_code = 0` throughout)
    /// reads as starvation (realm net-observer, node #122).
    #[test]
    fn a_captive_portal_answer_under_load_is_a_wedge_not_starvation() {
        let s = DuckdbStore::in_memory().unwrap();
        tun_dead_episode(&s, 10 * SEC, 4, 200, 31.0);
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "wedge");
        assert_ne!(cell(&t, 0, "verdict"), "starvation");
    }

    /// A single answered tick breaks silence for the whole episode: `max(tun_code)`
    /// is taken over a `USMALLINT` column, so one `200` among three `0`s is
    /// enough to read the episode as a wedge, not starvation, even under load.
    #[test]
    fn one_answered_tick_in_a_silent_episode_makes_it_a_wedge() {
        let s = DuckdbStore::in_memory().unwrap();
        for (i, code) in [0u16, 0, 200, 0].into_iter().enumerate() {
            let ts = 10 * SEC + i as i64 * SEC;
            link(&s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(&s, ts, TcpVerdict::Ok, Some(code));
            host(&s, ts, 31.0);
        }
        let t = s.wedge_vs_starvation().unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "wedge");
        assert_ne!(cell(&t, 0, "verdict"), "starvation");
    }

    /// Both episodes in one record, told apart by `load1` alone.
    #[test]
    fn the_two_episodes_are_separated_and_named_individually() {
        let s = DuckdbStore::in_memory().unwrap();
        tun_dead_episode(&s, 10 * SEC, 3, 0, 1.0);
        healthy_tick(&s, 60 * SEC);
        tun_dead_episode(&s, 120 * SEC, 3, 0, 25.0);
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

    /// A tick with no tun code at all (not `SKIP`, just absent) is not an
    /// episode either — the same NULL-is-unknown rule as `verdict_at`.
    #[test]
    fn a_null_tun_code_is_not_an_episode() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..4 {
            let ts = 10 * SEC + i * SEC;
            link(&s, ts, GwVerdict::Ok, Some(2.0), TcpVerdict::Ok);
            proxy(&s, ts, TcpVerdict::Ok, None);
            host(&s, ts, 30.0);
        }
        let t = s.wedge_vs_starvation().unwrap();
        assert!(
            t.rows.is_empty(),
            "NULL tun_code became an episode: {:?}",
            t.rows
        );
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

    /// Old, unrelated samples well outside the default window never leak into
    /// the fitted rows — the `win` CTE's own `ts_us` range excludes them, same
    /// as before this test's sibling `sleep` opener existed. But the ~996 s
    /// stride from the last of them to the ramp's first sample is now itself a
    /// named hole (realm net-observer, node #109): nothing bridges it, so it
    /// reads as a `sleep`, and its tail overlaps the window — the slope is
    /// withheld for the same reason a pause would withhold it, not because
    /// the orphan samples were counted.
    #[test]
    fn an_earlier_runs_orphan_samples_become_a_sleep_that_withholds_the_slope() {
        let s = DuckdbStore::in_memory().unwrap();
        for i in 0..5 {
            link(&s, i * SEC, GwVerdict::Ok, Some(999.0), TcpVerdict::Ok);
        }
        let drop_ts = coworking_ramp(&s, 1_000 * SEC);
        let t = s.gateway_ramp(drop_ts).unwrap();
        // The orphan samples themselves are still excluded from the window's
        // own rows — only the ramp's 40 climb ticks plus the drop.
        assert_eq!(t.rows.len(), 41, "the orphan samples must not appear here");
        assert_eq!(cell(&t, 0, "fitted_samples"), "");
        assert_eq!(cell(&t, 0, "slope_ms_per_s"), "");
        assert_eq!(cell(&t, 0, "observation_gap_us"), "80000000");

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 1, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "sleep");
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

    // ---- 5b. two more holes the record names on its own: a stop, a sleep ----
    // (realm net-observer, node #109)

    /// The daemon died or was killed with no pause edge at all: the record
    /// simply stops, and the next fact it carries is the startup edge. The gap
    /// runs from the newest sample before that edge to the edge itself, named
    /// `stop` — and a moment inside it answers `gap` exactly like a pause.
    #[test]
    fn a_stop_before_a_startup_opens_a_gap_named_stop() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        healthy_tick(&s, 20 * SEC);
        startup_edge(&s, 100 * SEC);
        healthy_tick(&s, 110 * SEC);

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 1, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "stop");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (100 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_by"), "startup");

        // Inside the stop gap the record refuses exactly like inside a pause.
        assert_eq!(cell(&s.verdict_at(50 * SEC).unwrap(), 0, "layer"), "gap");
    }

    /// A startup edge that closes an already-open pause names no stop of its
    /// own: the pause already explains the hole, so listing a second gap for
    /// the same edge would double-count it.
    #[test]
    fn a_stop_is_not_counted_when_a_pause_already_closes_at_the_startup() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        healthy_tick(&s, 20 * SEC);
        edge(&s, 25 * SEC, false);
        startup_edge(&s, 100 * SEC);
        healthy_tick(&s, 110 * SEC);

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 1, "no separate stop gap: {:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "pause");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (25 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (100 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_by"), "startup");
    }

    /// Two consecutive samples further apart than the sleep threshold, with
    /// nothing pausing or stopping the daemon between them: the machine slept.
    #[test]
    fn a_sleep_between_two_ticks_opens_a_gap_named_sleep() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        healthy_tick(&s, 20 * SEC);
        healthy_tick(&s, 100_000_000);
        healthy_tick(&s, 100_000_010);

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 1, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "sleep");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), "100000000");
        assert_eq!(cell(&g, 0, "gap_closed_by"), "sample");
    }

    /// The same huge stride between two samples, but already bracketed by an
    /// operator pause: the sleep opener must not double-count what the pause
    /// already names.
    #[test]
    fn a_sleep_already_covered_by_a_pause_is_not_counted_twice() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 100_000_000, true);
        healthy_tick(&s, 100_000_010);

        let g = s.observation_gaps().unwrap();
        assert_eq!(
            g.rows.len(),
            1,
            "only the pause, no extra sleep: {:?}",
            g.rows
        );
        assert_eq!(cell(&g, 0, "kind"), "pause");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), "100000000");
    }

    /// A pause does not swallow the whole stride it happens to sit inside:
    /// the residual after it resumes still surfaces as its own sleep, because
    /// the sleep opener strides over points (samples AND edges), so a stride
    /// can never straddle a gap's own boundary — only lie fully inside one
    /// (excluded) or fully outside every one (a sleep of its own) (realm
    /// net-observer, node #109).
    #[test]
    fn a_residual_stride_after_a_short_pause_is_still_a_sleep() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 0);
        edge(&s, 10 * SEC, false);
        edge(&s, 15 * SEC, true);
        healthy_tick(&s, 200 * SEC);

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 2, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "pause");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (10 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (15 * SEC).to_string());
        assert_eq!(cell(&g, 1, "kind"), "sleep");
        assert_eq!(cell(&g, 1, "gap_opened_us"), (15 * SEC).to_string());
        assert_eq!(cell(&g, 1, "gap_closed_us"), (200 * SEC).to_string());

        // The moment squarely inside the residual answers `gap`, exactly as
        // inside the pause itself.
        assert_eq!(cell(&s.verdict_at(100 * SEC).unwrap(), 0, "layer"), "gap");
    }

    /// The two residuals around a short pause are named separately, and only
    /// where each on its own exceeds the threshold — not one sleep spanning
    /// the whole stride the pause sits inside.
    #[test]
    fn a_pause_inside_a_long_stride_leaves_two_sleeps_when_both_residuals_exceed_the_threshold() {
        let s = DuckdbStore::in_memory().unwrap();
        healthy_tick(&s, 0);
        edge(&s, 400 * SEC, false);
        edge(&s, 410 * SEC, true);
        healthy_tick(&s, 1000 * SEC);

        let g = s.observation_gaps().unwrap();
        assert_eq!(g.rows.len(), 3, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "sleep");
        assert_eq!(cell(&g, 0, "gap_opened_us"), "0");
        assert_eq!(cell(&g, 0, "gap_closed_us"), (400 * SEC).to_string());
        assert_eq!(cell(&g, 1, "kind"), "pause");
        assert_eq!(cell(&g, 1, "gap_opened_us"), (400 * SEC).to_string());
        assert_eq!(cell(&g, 1, "gap_closed_us"), (410 * SEC).to_string());
        assert_eq!(cell(&g, 2, "kind"), "sleep");
        assert_eq!(cell(&g, 2, "gap_opened_us"), (410 * SEC).to_string());
        assert_eq!(cell(&g, 2, "gap_closed_us"), (1000 * SEC).to_string());
    }

    /// All four causes together, in one record: `silences` lists a passive
    /// stretch, a pause, a stop and a sleep, each under its own `kind`.
    #[test]
    fn silences_lists_pause_stop_sleep_and_passive_kinds_together() {
        let s = DuckdbStore::in_memory().unwrap();
        // A passive stretch, closed by an operator switch to active.
        probing_edge(&s, 5 * SEC, ProbingTier::Passive, None);
        passive_tick(&s, 10 * SEC);
        // A pause inside it, closed by resume.
        edge(&s, 20 * SEC, false);
        edge(&s, 30 * SEC, true);
        passive_tick(&s, 30 * SEC);
        probing_edge(&s, 60 * SEC, ProbingTier::Active, Some(501));
        healthy_tick(&s, 65 * SEC);
        // A stop: the daemon dies with no pause edge and boots again.
        startup_edge(&s, 500 * SEC);
        healthy_tick(&s, 505 * SEC);
        // A sleep: a huge stride between two ticks with nothing bracketing it.
        healthy_tick(&s, 505 * SEC + 100_000_000);

        let g = s.silences().unwrap();
        let kinds: std::collections::HashSet<String> =
            (0..g.rows.len()).map(|i| cell(&g, i, "kind")).collect();
        assert_eq!(
            kinds,
            ["pause", "stop", "sleep", "passive"]
                .into_iter()
                .map(String::from)
                .collect(),
            "{:?}",
            g.rows
        );
        assert_eq!(
            cell(&g, 0, "kind"),
            "passive",
            "listed by open time: {:?}",
            g.rows
        );
        assert_eq!(cell(&g, 1, "kind"), "pause");
        assert_eq!(cell(&g, 2, "kind"), "stop");
        assert_eq!(cell(&g, 3, "kind"), "sleep");
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

    /// A pause entirely outside the window used to leave the slope alone —
    /// before the sleep opener counted edges as points, nothing bridged its
    /// 8 s resume to the ramp's first sample 92 s later. Now that residual is
    /// itself a named `sleep` (realm net-observer, node #109), and its tail
    /// reaches into the window: the slope is withheld for the same reason a
    /// gap reaching into the window always withholds it. The pause itself
    /// still never touches the window — only the sleep after it does.
    #[test]
    fn a_pause_outside_the_ramp_window_still_leaves_a_sleep_that_reaches_into_it() {
        let s = DuckdbStore::in_memory().unwrap();
        edge(&s, 5 * SEC, false);
        edge(&s, 8 * SEC, true);
        let drop_ts = coworking_ramp(&s, 100 * SEC);

        let t = s.gateway_ramp(drop_ts).unwrap();
        assert_eq!(cell(&t, 0, "observation_gap_us"), "80000000");
        assert_eq!(cell(&t, 0, "fitted_samples"), "");
        assert_eq!(cell(&t, 0, "slope_ms_per_s"), "");

        let g = s.observation_gaps().unwrap();
        assert_eq!(
            g.rows.len(),
            2,
            "the pause itself, and the sleep after it: {:?}",
            g.rows
        );
        assert_eq!(cell(&g, 0, "kind"), "pause");
        assert_eq!(cell(&g, 1, "kind"), "sleep");
        assert_eq!(cell(&g, 1, "gap_opened_us"), (8 * SEC).to_string());
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
        // The same rows, as `silences` lists them: every one a pause.
        let all = s.silences().unwrap();
        assert_eq!(all.rows.len(), 2);
        assert!(
            all.rows.iter().all(|r| r[0] == "pause"),
            "with no probing edge, every silence is a pause: {:?}",
            all.rows
        );
    }

    // ---- 6b. passive stretches: the second bracket ---------------------------

    /// A daemon that boots passive (the configured default, written as a
    /// peerless edge) and is switched to active by an operator: one `passive`
    /// row, closed by `active`, listed by `silences` next to the pauses. The
    /// `SKIP` ticks in between do NOT close it — samples keep landing under
    /// passive — and a moment inside it reads `unknown` from those `SKIP`s,
    /// never `gap`.
    ///
    /// `observation_gaps` (the `Gaps` query a pre-tier reader still asks for)
    /// carries `kind` too (pause/stop/sleep), but the stretch is NOT among its
    /// rows — that reader would print it as a pause.
    #[test]
    fn a_passive_stretch_is_a_silence_of_its_own_kind_and_is_not_a_gap() {
        let s = DuckdbStore::in_memory().unwrap();
        probing_edge(&s, 5 * SEC, ProbingTier::Passive, None);
        passive_tick(&s, 10 * SEC);
        passive_tick(&s, 25 * SEC);
        probing_edge(&s, 30 * SEC, ProbingTier::Active, Some(501));
        healthy_tick(&s, 40 * SEC);

        let g = s.silences().unwrap();
        assert_eq!(g.rows.len(), 1, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "passive");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (5 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (30 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_by"), "active");

        let gaps = s.observation_gaps().unwrap();
        assert_eq!(
            gaps.columns,
            vec!["kind", "gap_opened_us", "gap_closed_us", "gap_closed_by"],
            "`Gaps` now carries `kind` (pause/stop/sleep), but never `passive`"
        );
        assert!(
            gaps.rows.is_empty(),
            "a passive stretch is not a pause and must not reach a pre-tier reader as one: {:?}",
            gaps.rows
        );

        // Not a gap: the record exists and says "no measurement".
        let t = s.verdict_at(25 * SEC).unwrap();
        assert_eq!(cell(&t, 0, "layer"), "unknown");
        assert_eq!(cell(&t, 0, "gw"), "SKIP");
        assert_eq!(
            cell(&s.verdict_at(40 * SEC).unwrap(), 0, "layer"),
            "healthy"
        );
    }

    /// The record ends passive: the stretch is open-ended, and the ticks after
    /// the edge are exactly what must not be read as closing it.
    #[test]
    fn a_stretch_the_record_ends_inside_stays_open_ended() {
        let s = DuckdbStore::in_memory().unwrap();
        probing_edge(&s, 5 * SEC, ProbingTier::Passive, None);
        passive_tick(&s, 10 * SEC);
        passive_tick(&s, 25 * SEC);

        let g = s.silences().unwrap();
        assert_eq!(g.rows.len(), 1);
        assert_eq!(cell(&g, 0, "kind"), "passive");
        assert_eq!(cell(&g, 0, "gap_closed_us"), "");
        assert_eq!(cell(&g, 0, "gap_closed_by"), "");
    }

    /// A crash while passive: the next boot writes its passive default as a
    /// second `passive` edge, which CONTINUES the stretch rather than opening
    /// another — until a boot whose default is active (a peerless `active`
    /// edge) closes it, named as `startup`.
    #[test]
    fn a_restart_that_stays_passive_continues_the_stretch_and_an_active_boot_closes_it() {
        let s = DuckdbStore::in_memory().unwrap();
        probing_edge(&s, 5 * SEC, ProbingTier::Passive, None);
        passive_tick(&s, 10 * SEC);
        // Died, came back with the same default.
        probing_edge(&s, 30 * SEC, ProbingTier::Passive, None);
        passive_tick(&s, 35 * SEC);
        // Reconfigured to active, restarted.
        probing_edge(&s, 60 * SEC, ProbingTier::Active, None);
        healthy_tick(&s, 65 * SEC);

        let g = s.silences().unwrap();
        assert_eq!(g.rows.len(), 1, "one stretch, not two: {:?}", g.rows);
        assert_eq!(cell(&g, 0, "gap_opened_us"), (5 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (60 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_by"), "startup");
    }

    /// Both brackets in one record, interleaved: a pause inside a passive
    /// stretch is listed as its own `pause` row, the stretch as `passive`, in
    /// time order. Neither swallows the other.
    #[test]
    fn a_pause_inside_a_passive_stretch_is_listed_as_both() {
        let s = DuckdbStore::in_memory().unwrap();
        probing_edge(&s, 5 * SEC, ProbingTier::Passive, None);
        passive_tick(&s, 10 * SEC);
        edge(&s, 20 * SEC, false);
        edge(&s, 30 * SEC, true);
        passive_tick(&s, 30 * SEC);
        probing_edge(&s, 45 * SEC, ProbingTier::Active, Some(501));
        healthy_tick(&s, 50 * SEC);

        let g = s.silences().unwrap();
        assert_eq!(g.rows.len(), 2, "{:?}", g.rows);
        assert_eq!(cell(&g, 0, "kind"), "passive");
        assert_eq!(cell(&g, 0, "gap_opened_us"), (5 * SEC).to_string());
        assert_eq!(cell(&g, 0, "gap_closed_us"), (45 * SEC).to_string());
        assert_eq!(cell(&g, 1, "kind"), "pause");
        assert_eq!(cell(&g, 1, "gap_opened_us"), (20 * SEC).to_string());
        assert_eq!(cell(&g, 1, "gap_closed_us"), (30 * SEC).to_string());
        assert_eq!(cell(&g, 1, "gap_closed_by"), "resume");
        // The pause is still a gap for the per-moment reader.
        assert_eq!(cell(&s.verdict_at(25 * SEC).unwrap(), 0, "layer"), "gap");
    }

    /// An active daemon opens no stretch: only a `passive` edge does, and a
    /// record that begins with an active startup edge lists nothing.
    #[test]
    fn an_active_default_opens_no_stretch() {
        let s = DuckdbStore::in_memory().unwrap();
        probing_edge(&s, 5 * SEC, ProbingTier::Active, None);
        healthy_tick(&s, 10 * SEC);
        assert!(s.silences().unwrap().rows.is_empty());
        assert!(s.observation_gaps().unwrap().rows.is_empty());
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
            services: Vec::new(),
            heard: None,
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

    // ---- connections: what this machine talks to ---------------------------

    fn conn_row(
        host: Option<&str>,
        dst_ip: Option<&str>,
        dst_port: Option<u16>,
        process: Option<&str>,
        count: u32,
        upload: u64,
    ) -> types::ConnectionRow {
        types::ConnectionRow {
            host: host.map(str::to_string),
            dst_ip: dst_ip.map(str::to_string),
            dst_port,
            process: process.map(str::to_string),
            network: "tcp".into(),
            chain: Some("vless-out-6".into()),
            count,
            upload,
            download: 0,
        }
    }

    fn connections(
        s: &DuckdbStore,
        ts_us: i64,
        verdict: types::ConnectionsVerdict,
        rows: Vec<types::ConnectionRow>,
    ) {
        s.write_sample(&Sample::Connections(types::ConnectionsSample {
            ts_us,
            verdict,
            rows,
        }))
        .unwrap();
    }

    /// The fixture tick: two Telegram flows to one address (a spoofed
    /// `www.google.com` SNI on one of them), a nameless direct flow, and two
    /// flows to names the proxy resolves itself (no address known here).
    fn fixture_tick(s: &DuckdbStore, ts_us: i64) {
        connections(
            s,
            ts_us,
            types::ConnectionsVerdict::Ok,
            vec![
                conn_row(
                    Some("www.google.com"),
                    Some("194.221.250.50"),
                    Some(5222),
                    Some("Telegram"),
                    1,
                    10,
                ),
                conn_row(
                    None,
                    Some("194.221.250.50"),
                    Some(443),
                    Some("Telegram"),
                    1,
                    20,
                ),
                conn_row(None, Some("149.154.167.41"), Some(80), None, 1, 1),
                conn_row(Some("claude.ai"), None, Some(443), Some("stable"), 2, 100),
                conn_row(
                    Some("o540343.ingest.sentry.io"),
                    None,
                    Some(443),
                    Some("stable"),
                    1,
                    4,
                ),
            ],
        );
    }

    /// Only the newest tick answers, and by host the nameless flow is keyed by
    /// its address rather than dropped.
    #[test]
    fn connections_by_host_read_the_newest_tick_and_key_nameless_flows_by_address() {
        let s = DuckdbStore::in_memory().unwrap();
        connections(
            &s,
            10 * SEC,
            types::ConnectionsVerdict::Ok,
            vec![conn_row(Some("stale.example"), None, Some(443), None, 9, 0)],
        );
        fixture_tick(&s, 20 * SEC);

        let t = s.connections(ConnectionsGroupBy::Host).unwrap();
        let keys: Vec<String> = (0..t.rows.len()).map(|i| cell(&t, i, "key")).collect();
        assert!(!keys.iter().any(|k| k == "stale.example"), "{keys:?}");
        assert_eq!(cell(&t, 0, "key"), "claude.ai");
        assert_eq!(cell(&t, 0, "count"), "2");
        assert_eq!(cell(&t, 0, "upload"), "100");
        assert_eq!(cell(&t, 0, "ts_us"), (20 * SEC).to_string());
        assert_eq!(cell(&t, 0, "verdict"), "OK");
        assert!(keys.contains(&"149.154.167.41".to_string()), "{keys:?}");
        assert!(keys.contains(&"194.221.250.50".to_string()), "{keys:?}");
        assert_eq!(keys.len(), 5, "{keys:?}");
    }

    /// By address, the two Telegram flows fold into one row that still names
    /// the SNI seen behind the address, and a flow with no address is keyed by
    /// its name.
    #[test]
    fn connections_by_ip_fold_flows_and_list_the_names_behind_an_address() {
        let s = DuckdbStore::in_memory().unwrap();
        fixture_tick(&s, 20 * SEC);

        let t = s.connections(ConnectionsGroupBy::Ip).unwrap();
        let row = (0..t.rows.len())
            .find(|&i| cell(&t, i, "key") == "194.221.250.50")
            .expect("the Telegram address is a key");
        assert_eq!(cell(&t, row, "count"), "2");
        assert_eq!(cell(&t, row, "upload"), "30");
        assert_eq!(cell(&t, row, "hosts"), "www.google.com");
        let keys: Vec<String> = (0..t.rows.len()).map(|i| cell(&t, i, "key")).collect();
        assert!(keys.contains(&"claude.ai".to_string()), "{keys:?}");
        assert_eq!(keys.len(), 4, "{keys:?}");
    }

    /// By address and port the two Telegram flows are two rows again, and the
    /// order is by flow count.
    #[test]
    fn connections_by_ip_port_split_the_ports_and_order_by_count() {
        let s = DuckdbStore::in_memory().unwrap();
        fixture_tick(&s, 20 * SEC);

        let t = s.connections(ConnectionsGroupBy::IpPort).unwrap();
        let keys: Vec<String> = (0..t.rows.len()).map(|i| cell(&t, i, "key")).collect();
        assert_eq!(keys[0], "claude.ai:443", "{keys:?}");
        assert!(
            keys.contains(&"194.221.250.50:5222".to_string()),
            "{keys:?}"
        );
        assert!(keys.contains(&"194.221.250.50:443".to_string()), "{keys:?}");
        assert_eq!(keys.len(), 5, "{keys:?}");
    }

    /// A v6 destination is bracketed in the address:port key, so its own
    /// colons cannot be read as the port separator.
    #[test]
    fn connections_by_ip_port_bracket_a_v6_address() {
        let s = DuckdbStore::in_memory().unwrap();
        connections(
            &s,
            20 * SEC,
            types::ConnectionsVerdict::Ok,
            vec![
                conn_row(
                    Some("claude.ai"),
                    Some("2606:4700::6810:84e5"),
                    Some(443),
                    None,
                    1,
                    1,
                ),
                conn_row(None, Some("1.1.1.1"), Some(53), None, 1, 1),
            ],
        );
        let t = s.connections(ConnectionsGroupBy::IpPort).unwrap();
        let keys: Vec<String> = (0..t.rows.len()).map(|i| cell(&t, i, "key")).collect();
        assert!(
            keys.contains(&"[2606:4700::6810:84e5]:443".to_string()),
            "{keys:?}"
        );
        assert!(keys.contains(&"1.1.1.1:53".to_string()), "{keys:?}");
        assert_eq!(keys.len(), 2, "{keys:?}");
    }

    /// By process, the two `stable` flows fold with both their names listed,
    /// and a flow the proxy could not attribute is keyed `-`, not dropped.
    #[test]
    fn connections_by_process_fold_flows_and_keep_the_unattributed() {
        let s = DuckdbStore::in_memory().unwrap();
        fixture_tick(&s, 20 * SEC);

        let t = s.connections(ConnectionsGroupBy::Process).unwrap();
        assert_eq!(cell(&t, 0, "key"), "stable");
        assert_eq!(cell(&t, 0, "count"), "3");
        assert_eq!(cell(&t, 0, "hosts"), "claude.ai,o540343.ingest.sentry.io");
        let keys: Vec<String> = (0..t.rows.len()).map(|i| cell(&t, i, "key")).collect();
        assert!(keys.contains(&"Telegram".to_string()), "{keys:?}");
        assert!(keys.contains(&"-".to_string()), "{keys:?}");
        assert_eq!(keys.len(), 3, "{keys:?}");
    }

    /// The refusal survives the read: a newest tick on which the API did not
    /// answer is one row saying SKIP, a newest tick that listed nothing is one
    /// row saying OK — and a record with no tick at all is no row. Three
    /// different answers, none of them an empty table by accident.
    #[test]
    fn connections_keep_a_skip_and_an_empty_tick_apart_from_no_record() {
        let s = DuckdbStore::in_memory().unwrap();
        assert!(
            s.connections(ConnectionsGroupBy::Host)
                .unwrap()
                .rows
                .is_empty()
        );

        connections(&s, 10 * SEC, types::ConnectionsVerdict::Skip, Vec::new());
        let t = s.connections(ConnectionsGroupBy::Host).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "SKIP");
        assert_eq!(cell(&t, 0, "ts_us"), (10 * SEC).to_string());
        assert_eq!(cell(&t, 0, "key"), "");
        assert_eq!(cell(&t, 0, "count"), "");

        connections(&s, 20 * SEC, types::ConnectionsVerdict::Ok, Vec::new());
        let t = s.connections(ConnectionsGroupBy::Process).unwrap();
        assert_eq!(t.rows.len(), 1);
        assert_eq!(cell(&t, 0, "verdict"), "OK");
        assert_eq!(cell(&t, 0, "key"), "");
    }

    // ---- air: pin the AP list to the scan the reader saw --------------------

    fn air_scan(s: &DuckdbStore, ts_us: i64, channel: i32) {
        use types::{AirObservation, AirSample, AirVerdict};
        s.write_sample(&Sample::Air(AirSample {
            ts_us,
            air: AirVerdict::Ok,
            reason: None,
            aps: vec![AirObservation {
                channel: Some(channel),
                channel_band: Some("5ghz".into()),
                channel_width_mhz: Some(80),
                phy_mode: Some("802.11a/n/ac/ax".into()),
                security: Some("wpa2_personal".into()),
                rssi_dbm: Some(-60),
                noise_dbm: Some(-90),
            }],
        }))
        .unwrap();
    }

    /// Two scans in the record, each with its own AP: pinning by `ts_us`
    /// returns only the named scan's row, never the other one's — the race
    /// [`air_aps_at_sql`] exists to close (realm net-observer, node #99).
    #[test]
    fn air_aps_at_sql_returns_only_the_pinned_scans_rows() {
        let s = DuckdbStore::in_memory().unwrap();
        air_scan(&s, 10 * SEC, 36);
        air_scan(&s, 20 * SEC, 149);

        let older = s.query_prepared(&air_aps_at_sql(10 * SEC)).unwrap();
        assert_eq!(older.rows.len(), 1);
        assert_eq!(cell(&older, 0, "channel"), "36");

        let newer = s.query_prepared(&air_aps_at_sql(20 * SEC)).unwrap();
        assert_eq!(newer.rows.len(), 1);
        assert_eq!(cell(&newer, 0, "channel"), "149");
    }
}
