//! The offline diagnosis commands: `store::diagnosis` made reachable by a human.
//!
//! `crates/store/src/diagnosis.rs` already answers "which layer failed" in SQL.
//! This module is the reading side of that: it parses the one human argument
//! those queries need (a moment in time) and renders their results.
//!
//! ## Refusals are rendered as refusals
//!
//! The queries deliberately decline to answer in three places, and each refusal
//! is a finding — never a blank:
//!
//! - a moment inside an **observation gap** yields `layer = 'gap'` with every
//!   measurement column `NULL`;
//! - an episode the record cannot classify (no `load1`, no link sample) yields
//!   `verdict = 'unknown'`;
//! - a ramp window overlapping a gap yields a `NULL` slope.
//!
//! `QueryTable` stringifies SQL `NULL` as the empty string, which prints as
//! whitespace and reads as a measurement that happened to be blank. So nothing
//! here goes through the generic table printer: a withheld cell prints
//! [`WITHHELD`] (a value exists in the record but is not a reading at this
//! moment) and an absent one prints [`ABSENT`], and every table that used one
//! explains it in a legend underneath.
//!
//! ## The `--at` / `--drop` time format
//!
//! Deliberately small, and always echoed back resolved so a mis-typed moment is
//! visible immediately:
//!
//! | form | meaning |
//! | --- | --- |
//! | `now` | the current instant (the default for `--at`) |
//! | `1756731900000000` | raw epoch microseconds — the `ts_us` the record uses |
//! | `2026-09-01T14:05` / `2026-09-01 14:05:30` | a local-time civil instant |
//! | `2026-09-01T14:05:00Z` / `...+03:00` | an ISO instant with an explicit offset |
//! | `14:05` / `14:05:30` | that time **today**, local |
//!
//! Anything else is an error naming these forms; nothing silently defaults.

use anyhow::{Result, anyhow};
use store::QueryTable;

/// Printed for a value the record withheld because the moment lies inside an
/// observation gap. Not a measurement, and not a missing one either.
pub(crate) const WITHHELD: &str = "(gap)";

/// Printed for a value the record simply does not carry (SQL `NULL`).
pub(crate) const ABSENT: &str = "(none)";

/// The accepted `--at` / `--drop` forms, quoted in every parse error.
const TIME_FORMS: &str = "expected `now`, epoch microseconds (e.g. 1756731900000000), \
     `YYYY-MM-DDTHH:MM[:SS]` or `YYYY-MM-DD HH:MM[:SS]` (local time), \
     an ISO instant with an offset (`2026-09-01T14:05:00Z`), \
     or `HH:MM[:SS]` for that time today (local)";

/// Parse one human moment into the record's `ts_us` (epoch microseconds).
///
/// See the module docs for the accepted forms. Garbage is an error naming them
/// — never a silent fallback to "now".
pub(crate) fn parse_at(input: &str) -> Result<i64> {
    let s = input.trim();
    let bad = || anyhow!("unrecognized time `{input}`: {TIME_FORMS}");

    if s.eq_ignore_ascii_case("now") {
        return Ok(jiff::Timestamp::now().as_microsecond());
    }
    // Raw `ts_us`, so a value copied out of any other output can be pasted back.
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s.parse::<i64>().map_err(|_| bad());
    }
    // An instant that carries its own offset needs no timezone guess.
    if let Ok(ts) = s.parse::<jiff::Timestamp>() {
        return Ok(ts.as_microsecond());
    }
    let tz = jiff::tz::TimeZone::system();
    let normalized = s.replace(' ', "T");
    if let Some((date, time)) = normalized.split_once('T') {
        let dt: jiff::civil::DateTime = format!("{date}T{}", pad_seconds(time))
            .parse()
            .map_err(|_| bad())?;
        return Ok(dt
            .to_zoned(tz)
            .map_err(|_| bad())?
            .timestamp()
            .as_microsecond());
    }
    if normalized.contains(':') {
        let t: jiff::civil::Time = pad_seconds(&normalized).parse().map_err(|_| bad())?;
        let today = jiff::Zoned::now().date();
        return Ok(today
            .to_datetime(t)
            .to_zoned(tz)
            .map_err(|_| bad())?
            .timestamp()
            .as_microsecond());
    }
    Err(bad())
}

/// `HH:MM` -> `HH:MM:00`; anything else is passed through for the real parser to
/// accept or reject.
fn pad_seconds(time: &str) -> String {
    if time.bytes().filter(|b| *b == b':').count() == 1 {
        format!("{time}:00")
    } else {
        time.to_string()
    }
}

/// Render a `ts_us` as a local ISO instant, so the moment the CLI actually used
/// is visible next to the raw number. Out-of-range never panics.
pub(crate) fn fmt_instant(ts_us: i64) -> String {
    match jiff::Timestamp::from_microsecond(ts_us) {
        Ok(ts) => ts
            .to_zoned(jiff::tz::TimeZone::system())
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string(),
        Err(_) => "(timestamp out of range)".to_string(),
    }
}

/// A `ts_us` cell as `<raw> (<local ISO>)`, or [`ABSENT`] when it is `NULL`.
fn stamp(cell: &str) -> String {
    match cell.parse::<i64>() {
        Ok(ts) => format!("{ts} ({})", fmt_instant(ts)),
        Err(_) => ABSENT.to_string(),
    }
}

/// Column lookup by name, so a query's column order is not baked in here.
struct Cols<'a>(&'a [String]);

impl Cols<'_> {
    fn idx(&self, name: &str) -> Result<usize> {
        self.0
            .iter()
            .position(|c| c == name)
            .ok_or_else(|| anyhow!("diagnosis query returned no `{name}` column"))
    }
}

/// One cell, or `""` when the row is short.
fn at(row: &[String], i: usize) -> &str {
    row.get(i).map(String::as_str).unwrap_or_default()
}

/// A measurement cell: the value, or `null_token` when SQL said `NULL`
/// (`QueryTable` renders `NULL` as the empty string).
fn measured(row: &[String], i: usize, null_token: &str) -> String {
    let c = at(row, i);
    if c.is_empty() {
        null_token.to_string()
    } else {
        c.to_string()
    }
}

/// A space-padded table in the style of the CLI's other output.
fn aligned(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.len()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let mut out = String::new();
    let header: Vec<String> = header.iter().map(|h| (*h).to_string()).collect();
    push(&mut out, &header, &widths);
    for row in rows {
        push(&mut out, row, &widths);
    }
    out
}

fn push(out: &mut String, cells: &[String], widths: &[usize]) {
    for (i, cell) in cells.iter().enumerate() {
        let width = widths.get(i).copied().unwrap_or(0);
        out.push_str(cell);
        for _ in cell.len()..width {
            out.push(' ');
        }
        out.push_str("  ");
    }
    out.push('\n');
}

/// A `key   value` line, matching `format_status`'s two-column shape.
fn kv(out: &mut String, key: &str, value: &str) {
    out.push_str(&format!("{key:<14} {value}\n"));
}

/// Describe a gap's bounds, saying plainly when the record ends inside it.
fn gap_bounds(opened: &str, closed: &str) -> String {
    let from = if opened.is_empty() {
        ABSENT.to_string()
    } else {
        stamp(opened)
    };
    if closed.is_empty() {
        format!("opened {from}, still open (the record ends inside the pause)")
    } else {
        format!("opened {from}, closed {}", stamp(closed))
    }
}

/// **Which layer failed at a moment** — renders [`store::diagnosis::verdict_at_sql`].
///
/// A moment inside an observation gap is rendered as the refusal it is: no
/// measurement lines at all, the gap's bounds, and why nothing is reported.
pub(crate) fn format_verdict_at(table: &QueryTable, asked_ts_us: i64) -> Result<String> {
    let c = Cols(&table.columns);
    let (ts, layer) = (c.idx("ts_us")?, c.idx("layer")?);
    let (go, gc) = (c.idx("gap_opened_us")?, c.idx("gap_closed_us")?);

    let mut out = String::new();
    kv(
        &mut out,
        "asked_at",
        &format!("{asked_ts_us} ({})", fmt_instant(asked_ts_us)),
    );

    let Some(row) = table.rows.first() else {
        kv(&mut out, "layer", "(no record)");
        out.push_str(
            "\nThe record holds no link sample at or before this moment, and no \
             observation gap\ncovers it.\n",
        );
        return Ok(out);
    };

    if at(row, layer) == "gap" {
        kv(
            &mut out,
            "layer",
            "gap - REFUSED, the daemon was not observing",
        );
        kv(&mut out, "gap", &gap_bounds(at(row, go), at(row, gc)));
        out.push_str(
            "\nNo measurement is reported for a moment inside an observation gap. The \
             newest\nsample before the pause is a reading from before the pause, not a \
             reading at this\nmoment, so it is withheld rather than labelled.\n",
        );
        return Ok(out);
    }

    kv(&mut out, "sample_ts", &stamp(at(row, ts)));
    for col in ["gw", "gw_rtt_ms", "direct", "vless", "tun_code", "load1"] {
        let i = c.idx(col)?;
        kv(&mut out, col, &measured(row, i, ABSENT));
    }
    let verdict = at(row, layer);
    if verdict == "unknown" {
        kv(
            &mut out,
            "layer",
            "unknown - REFUSED, the record does not say",
        );
        out.push_str(&format!(
            "\nA layer did not report (SKIP, no sample, or no load1), so no blame is \
             assigned.\n{ABSENT} above marks a value the record does not carry.\n"
        ));
    } else {
        kv(&mut out, "layer", verdict);
    }
    Ok(out)
}

/// **Incidents with the layer state just before each opened** — renders
/// [`store::diagnosis::incident_context_sql`].
pub(crate) fn format_incident_context(table: &QueryTable) -> Result<String> {
    let c = Cols(&table.columns);
    let (id, trg) = (c.idx("id")?, c.idx("trigger_id")?);
    let (opened, closed) = (c.idx("opened_us")?, c.idx("closed_us")?);
    let state_ts = c.idx("state_ts_us")?;
    let layer = c.idx("layer")?;
    let (go, gc) = (c.idx("gap_opened_us")?, c.idx("gap_closed_us")?);
    let cols = [
        c.idx("gw")?,
        c.idx("direct")?,
        c.idx("vless")?,
        c.idx("tun_code")?,
        c.idx("load1")?,
    ];

    let mut rows = Vec::new();
    let (mut any_gap, mut any_absent) = (false, false);
    for row in &table.rows {
        let in_gap = at(row, layer) == "gap";
        any_gap |= in_gap;
        // Inside a gap the state columns are not missing measurements — they are
        // measurements the query refused to attribute to this moment.
        let token = if in_gap { WITHHELD } else { ABSENT };
        let mut cells = vec![
            at(row, id).to_string(),
            at(row, trg).to_string(),
            at(row, opened).to_string(),
            measured(row, closed, "open"),
            if in_gap {
                WITHHELD.to_string()
            } else {
                measured(row, state_ts, ABSENT)
            },
        ];
        for i in cols {
            let cell = measured(row, i, token);
            any_absent |= !in_gap && cell == ABSENT;
            cells.push(cell);
        }
        cells.push(at(row, layer).to_string());
        cells.push(if in_gap {
            gap_bounds(at(row, go), at(row, gc))
        } else {
            String::new()
        });
        rows.push(cells);
    }

    if rows.is_empty() {
        return Ok("no incidents in the record\n".to_string());
    }
    let mut out = aligned(
        &[
            "ID",
            "TRIGGER",
            "OPENED_US",
            "CLOSED_US",
            "STATE_TS_US",
            "GW",
            "DIRECT",
            "VLESS",
            "TUN",
            "LOAD1",
            "LAYER",
            "GAP",
        ],
        &rows,
    );
    if any_gap {
        out.push_str(&format!(
            "\n{WITHHELD}  withheld: this incident opened inside an observation gap, so the \
             state\n       from before the pause is not context for it (bounds in GAP).\n"
        ));
    }
    if any_absent {
        out.push_str(&format!("{ABSENT}  the record carries no value here.\n"));
    }
    Ok(out)
}

/// **Wedge vs starvation** — renders
/// [`store::diagnosis::wedge_vs_starvation_sql`].
pub(crate) fn format_wedge_vs_starvation(table: &QueryTable) -> Result<String> {
    let c = Cols(&table.columns);
    let (ep, opened, closed) = (c.idx("episode")?, c.idx("opened_us")?, c.idx("closed_us")?);
    let (ticks, load, verdict) = (c.idx("ticks")?, c.idx("max_load1")?, c.idx("verdict")?);

    let mut rows = Vec::new();
    let mut any_unknown = false;
    let mut any_absent = false;
    for row in &table.rows {
        any_unknown |= at(row, verdict) == "unknown";
        let load1 = measured(row, load, ABSENT);
        any_absent |= load1 == ABSENT;
        rows.push(vec![
            at(row, ep).to_string(),
            at(row, opened).to_string(),
            at(row, closed).to_string(),
            at(row, ticks).to_string(),
            load1,
            at(row, verdict).to_string(),
        ]);
    }
    if rows.is_empty() {
        return Ok("no tun=000 episodes in the record\n".to_string());
    }
    let mut out = aligned(
        &[
            "EPISODE",
            "OPENED_US",
            "CLOSED_US",
            "TICKS",
            "MAX_LOAD1",
            "VERDICT",
        ],
        &rows,
    );
    if any_unknown {
        out.push_str(
            "\nunknown  REFUSED: the record cannot tell a wedge from starvation for this \
             episode\n         (no load1, or no healthy link sample covering it). A restart \
             is not\n         indicated on this evidence.\n",
        );
    }
    if any_absent {
        out.push_str(&format!(
            "{ABSENT}   no host load was recorded for the episode.\n"
        ));
    }
    Ok(out)
}

/// **The gateway RTT ramp before a drop** — renders
/// [`store::diagnosis::gateway_ramp_sql`].
///
/// A `NULL` slope is stated as "not computed", never as flat.
pub(crate) fn format_gateway_ramp(
    table: &QueryTable,
    drop_ts_us: i64,
    window_us: i64,
) -> Result<String> {
    let c = Cols(&table.columns);
    let (ts, before) = (c.idx("ts_us")?, c.idx("us_before_drop")?);
    let (gw, rtt) = (c.idx("gw")?, c.idx("gw_rtt_ms")?);
    let (slope, fitted, gap) = (
        c.idx("slope_ms_per_s")?,
        c.idx("fitted_samples")?,
        c.idx("observation_gap_us")?,
    );

    let mut out = String::new();
    kv(
        &mut out,
        "drop_at",
        &format!("{drop_ts_us} ({})", fmt_instant(drop_ts_us)),
    );
    kv(&mut out, "window_us", &window_us.to_string());

    let Some(first) = table.rows.first() else {
        kv(
            &mut out,
            "slope",
            "not computed - no link samples in the window",
        );
        return Ok(out);
    };
    let gap_us: i64 = at(first, gap).parse().unwrap_or(0);
    match (at(first, slope), gap_us) {
        (_, g) if g > 0 => kv(
            &mut out,
            "slope",
            &format!(
                "not computed - the window crosses {g} us of observation gap \
                 (a fit across an unsampled interval is a line through absent data)"
            ),
        ),
        ("", _) => kv(
            &mut out,
            "slope",
            "not computed - no answered (gw=OK) samples in the window",
        ),
        (s, _) => kv(
            &mut out,
            "slope",
            &format!(
                "{s} ms/s over {} fitted samples",
                measured(first, fitted, ABSENT)
            ),
        ),
    }

    let rows: Vec<Vec<String>> = table
        .rows
        .iter()
        .map(|row| {
            vec![
                at(row, ts).to_string(),
                at(row, before).to_string(),
                at(row, gw).to_string(),
                measured(row, rtt, "(no answer)"),
            ]
        })
        .collect();
    out.push('\n');
    out.push_str(&aligned(
        &["TS_US", "US_BEFORE_DROP", "GW", "GW_RTT_MS"],
        &rows,
    ));
    out.push_str("\n(no answer)  the probe did not answer at this tick, so it feeds no slope.\n");
    Ok(out)
}

/// **The observation gaps the record contains** — renders
/// [`store::diagnosis::observation_gaps_sql`].
pub(crate) fn format_observation_gaps(table: &QueryTable) -> Result<String> {
    let c = Cols(&table.columns);
    let (go, gc, by) = (
        c.idx("gap_opened_us")?,
        c.idx("gap_closed_us")?,
        c.idx("gap_closed_by")?,
    );
    let mut rows = Vec::new();
    let mut open_ended = false;
    for row in &table.rows {
        let closed = at(row, gc);
        open_ended |= closed.is_empty();
        rows.push(vec![
            stamp(at(row, go)),
            if closed.is_empty() {
                "(still open)".to_string()
            } else {
                stamp(closed)
            },
            measured(row, by, "(still open)"),
        ]);
    }
    if rows.is_empty() {
        return Ok("no observation gaps: the record is unbroken\n".to_string());
    }
    let mut out = aligned(&["OPENED", "CLOSED", "CLOSED_BY"], &rows);
    if open_ended {
        out.push_str(
            "\n(still open)  the record ends inside this pause - nothing at all follows it.\n",
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `QueryTable` from column names and rows, with `""` standing for
    /// SQL `NULL` exactly as `QueryTable` renders it.
    fn table(columns: &[&str], rows: &[&[&str]]) -> QueryTable {
        QueryTable {
            columns: columns.iter().map(|c| (*c).to_string()).collect(),
            rows: rows
                .iter()
                .map(|r| r.iter().map(|c| (*c).to_string()).collect())
                .collect(),
        }
    }

    const VERDICT_COLS: &[&str] = &[
        "ts_us",
        "gw",
        "gw_rtt_ms",
        "direct",
        "vless",
        "tun_code",
        "load1",
        "layer",
        "gap_opened_us",
        "gap_closed_us",
    ];

    #[test]
    fn verdict_at_renders_a_measured_moment() {
        let t = table(
            VERDICT_COLS,
            &[&[
                "1000", "OK", "3.5", "OK", "OK", "204", "1.2", "healthy", "", "",
            ]],
        );
        let out = format_verdict_at(&t, 1500).unwrap();
        assert!(out.contains("gw             OK"), "{out}");
        assert!(out.contains("gw_rtt_ms      3.5"), "{out}");
        assert!(out.contains("layer          healthy"), "{out}");
        assert!(!out.contains("REFUSED"), "{out}");
        assert!(!out.contains(WITHHELD), "{out}");
    }

    /// The refusal that matters most: a moment inside an observation gap must
    /// read as a refusal, not as a row of empty measurements.
    #[test]
    fn verdict_at_renders_a_gap_as_a_refusal() {
        let t = table(
            VERDICT_COLS,
            &[&["", "", "", "", "", "", "", "gap", "900", "2000"]],
        );
        let out = format_verdict_at(&t, 1500).unwrap();
        assert!(out.contains("REFUSED"), "{out}");
        assert!(out.contains("was not observing"), "{out}");
        assert!(out.contains("opened 900"), "{out}");
        assert!(out.contains("closed 2000"), "{out}");
        // No measurement lines at all — not blank ones.
        for key in ["gw ", "gw_rtt_ms", "direct", "vless", "tun_code", "load1"] {
            assert!(!out.contains(key), "gap output leaked `{key}`: {out}");
        }
    }

    #[test]
    fn verdict_at_names_an_unreported_layer_a_refusal() {
        let t = table(
            VERDICT_COLS,
            &[&["1000", "OK", "", "OK", "SKIP", "", "", "unknown", "", ""]],
        );
        let out = format_verdict_at(&t, 1000).unwrap();
        assert!(out.contains("unknown - REFUSED"), "{out}");
        assert!(out.contains(&format!("gw_rtt_ms      {ABSENT}")), "{out}");
        assert!(out.contains(&format!("load1          {ABSENT}")), "{out}");
    }

    #[test]
    fn verdict_at_says_so_when_the_record_holds_nothing() {
        let out = format_verdict_at(&table(VERDICT_COLS, &[]), 42).unwrap();
        assert!(out.contains("(no record)"), "{out}");
    }

    const CTX_COLS: &[&str] = &[
        "id",
        "trigger_id",
        "opened_us",
        "closed_us",
        "state_ts_us",
        "gw",
        "direct",
        "vless",
        "tun_code",
        "load1",
        "layer",
        "gap_opened_us",
        "gap_closed_us",
    ];

    #[test]
    fn incident_context_marks_a_gap_incident_as_withheld() {
        let t = table(
            CTX_COLS,
            &[
                &[
                    "i1", "gw-drop", "1000", "2000", "990", "FAIL", "OK", "OK", "204", "0.5",
                    "link", "", "",
                ],
                &[
                    "i2", "wedge", "5000", "", "", "", "", "", "", "", "gap", "4000", "6000",
                ],
            ],
        );
        let out = format_incident_context(&t).unwrap();
        assert!(out.contains("withheld"), "{out}");
        assert!(out.contains("opened 4000"), "{out}");
        // The measured incident keeps its values; the gap one shows the token.
        assert!(out.contains("FAIL"), "{out}");
        assert_eq!(out.matches(WITHHELD).count(), 7, "{out}");
        assert!(out.contains("open"), "{out}");
    }

    #[test]
    fn incident_context_reports_an_empty_record() {
        let out = format_incident_context(&table(CTX_COLS, &[])).unwrap();
        assert!(out.contains("no incidents"), "{out}");
    }

    const EPISODE_COLS: &[&str] = &[
        "episode",
        "opened_us",
        "closed_us",
        "ticks",
        "max_load1",
        "verdict",
    ];

    #[test]
    fn wedge_vs_starvation_explains_an_unknown_verdict() {
        let t = table(
            EPISODE_COLS,
            &[
                &["1", "10", "20", "3", "24.0", "starvation"],
                &["2", "30", "40", "2", "", "unknown"],
            ],
        );
        let out = format_wedge_vs_starvation(&t).unwrap();
        assert!(out.contains("starvation"), "{out}");
        assert!(out.contains("REFUSED"), "{out}");
        assert!(out.contains("cannot tell a wedge from starvation"), "{out}");
        assert!(out.contains(ABSENT), "{out}");
    }

    const RAMP_COLS: &[&str] = &[
        "ts_us",
        "us_before_drop",
        "gw",
        "gw_rtt_ms",
        "slope_ms_per_s",
        "fitted_samples",
        "observation_gap_us",
    ];

    #[test]
    fn gateway_ramp_reports_a_computed_slope() {
        let t = table(
            RAMP_COLS,
            &[
                &["100", "900", "OK", "5.0", "12.5", "2", "0"],
                &["500", "500", "OK", "9.0", "12.5", "2", "0"],
            ],
        );
        let out = format_gateway_ramp(&t, 1000, 900).unwrap();
        assert!(out.contains("12.5 ms/s over 2 fitted samples"), "{out}");
        assert!(!out.contains("not computed"), "{out}");
    }

    /// A `NULL` slope over a gapped window is "not computed", never flat.
    #[test]
    fn gateway_ramp_refuses_a_slope_across_a_gap() {
        let t = table(RAMP_COLS, &[&["100", "900", "OK", "5.0", "", "", "400000"]]);
        let out = format_gateway_ramp(&t, 1000, 900).unwrap();
        assert!(out.contains("not computed"), "{out}");
        assert!(out.contains("400000 us of observation gap"), "{out}");
        assert!(!out.contains("0 ms/s"), "{out}");
    }

    #[test]
    fn gateway_ramp_marks_an_unanswered_tick() {
        let t = table(RAMP_COLS, &[&["100", "900", "FAIL", "", "12.5", "2", "0"]]);
        let out = format_gateway_ramp(&t, 1000, 900).unwrap();
        assert!(out.contains("(no answer)"), "{out}");
    }

    const GAP_COLS: &[&str] = &["gap_opened_us", "gap_closed_us", "gap_closed_by"];

    #[test]
    fn observation_gaps_render_an_open_ended_pause() {
        let t = table(GAP_COLS, &[&["1000", "2000", "resume"], &["9000", "", ""]]);
        let out = format_observation_gaps(&t).unwrap();
        assert!(out.contains("resume"), "{out}");
        assert!(out.contains("(still open)"), "{out}");
        assert!(out.contains("nothing at all follows it"), "{out}");
    }

    #[test]
    fn observation_gaps_report_an_unbroken_record() {
        let out = format_observation_gaps(&table(GAP_COLS, &[])).unwrap();
        assert!(out.contains("unbroken"), "{out}");
    }

    #[test]
    fn a_missing_column_is_an_error_not_a_wrong_answer() {
        let err = format_verdict_at(&table(&["ts_us"], &[]), 0).unwrap_err();
        assert!(err.to_string().contains("no `layer` column"), "{err}");
    }

    #[test]
    fn parse_at_accepts_raw_microseconds_and_now() {
        assert_eq!(parse_at("1756731900000000").unwrap(), 1_756_731_900_000_000);
        assert_eq!(parse_at(" 42 ").unwrap(), 42);
        assert!(parse_at("now").unwrap() > 1_700_000_000_000_000);
    }

    #[test]
    fn parse_at_accepts_an_iso_instant_with_an_offset() {
        assert_eq!(
            parse_at("2026-09-01T14:05:00Z").unwrap(),
            parse_at("2026-09-01T17:05:00+03:00").unwrap()
        );
    }

    #[test]
    fn parse_at_accepts_a_local_civil_datetime_with_or_without_seconds() {
        let with_space = parse_at("2026-09-01 14:05").unwrap();
        assert_eq!(with_space, parse_at("2026-09-01T14:05:00").unwrap());
    }

    /// A time of day resolves to that time *today*, so it must land within a day
    /// of now — and must not silently become "now".
    #[test]
    fn parse_at_accepts_a_time_of_day_today() {
        let noon = parse_at("12:00").unwrap();
        let now = jiff::Timestamp::now().as_microsecond();
        assert!((noon - now).abs() < 36 * 3600 * 1_000_000);
    }

    /// Garbage must be rejected with a message naming the accepted forms —
    /// never defaulted to "now".
    #[test]
    fn parse_at_rejects_garbage_with_a_usable_message() {
        for bad in ["yesterday", "", "14h05", "2026-13-45T99:99", "-5"] {
            let err = parse_at(bad).unwrap_err().to_string();
            assert!(err.contains("unrecognized time"), "{bad}: {err}");
            assert!(err.contains("epoch microseconds"), "{bad}: {err}");
            assert!(err.contains("HH:MM"), "{bad}: {err}");
        }
    }
}
