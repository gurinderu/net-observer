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
//! A result `Table` (the wire shape, which the offline `QueryTable` is converted
//! into) stringifies SQL `NULL` as the empty string, which prints as
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
use net_observer_ipc::Table;

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
/// is visible next to the raw number. The one formatter, shared with the
/// daemon's own messages (`types::local_instant`), so a clock the daemon
/// names and a clock the CLI stamps read the same. Out-of-range never panics.
pub(crate) fn fmt_instant(ts_us: i64) -> String {
    types::local_instant(ts_us)
}

/// A microsecond instant as `<raw> (<local ISO>)` — the raw number stays
/// (it is what you paste back into `--at` or a SQL predicate) and the local
/// rendering is what a human reads. `pub(crate)` because the live `status`
/// subcommand prints its instants in exactly this shape. `incidents` prints
/// its own, plainer local rendering instead (`OPENED` as bare
/// `YYYY-MM-DD HH:MM:SS`, directly pasteable into `why --at`) — a table row
/// has no room for the raw number too.
pub(crate) fn stamp_us(ts_us: i64) -> String {
    format!("{ts_us} ({})", fmt_instant(ts_us))
}

/// A `ts_us` cell as `<raw> (<local ISO>)`, or [`ABSENT`] when it is `NULL`.
fn stamp(cell: &str) -> String {
    match cell.parse::<i64>() {
        Ok(ts) => stamp_us(ts),
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
/// (the store renders `NULL` as the empty string).
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
pub(crate) fn format_verdict_at(table: &Table, asked_ts_us: i64) -> Result<String> {
    let c = Cols(&table.columns);
    let (ts, layer) = (c.idx("ts_us")?, c.idx("layer")?);
    let (go, gc) = (c.idx("gap_opened_us")?, c.idx("gap_closed_us")?);

    let mut out = String::new();
    kv(&mut out, "asked_at", &stamp_us(asked_ts_us));

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
    // What sing-box's own log said within ±30 s of the moment, one line per
    // row, newest first (realm net-observer, node #141). The column is
    // optional: a daemon built before the log reader answers without it, and
    // a moment the log said nothing about carries NULL — either way no line.
    if let Ok(i) = c.idx("singbox_log") {
        for line in at(row, i).lines() {
            kv(&mut out, "sing-box log", line);
        }
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
/// [`store::diagnosis::incident_context_sql`]. `is_tty`/`full` gate the row
/// cap ([`crate::cap_rows`]): on an interactive terminal (`is_tty`), without
/// `--full`, only the first `DEFAULT_ROW_LIMIT` incidents render and a
/// trailing note says how many more exist — piping/redirecting
/// (`is_tty = false`) always renders every incident. The caller passes the
/// real `std::io::stdout().is_terminal()`; taking it as a parameter (rather
/// than calling it in here) is what makes the capped branch reachable from a
/// test.
pub(crate) fn format_incident_context(table: &Table, is_tty: bool, full: bool) -> Result<String> {
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

    // Readable timestamps (owner ask): the three absolute-instant columns
    // convert to local time before anything below reads them.
    // `gap_opened_us`/`gap_closed_us` already render through `stamp()` in
    // `gap_bounds` further down, and no other column here is a timestamp.
    let mut source_rows = table.rows.clone();
    for i in [opened, closed, state_ts] {
        crate::convert_epoch_us_column(&mut source_rows, i);
    }
    // Cap BEFORE the loop below, so the legend flags (`any_gap`/`any_absent`)
    // are computed over exactly the incidents actually shown.
    let cap_note = crate::cap_rows(&mut source_rows, is_tty, full);

    let mut rows = Vec::new();
    let (mut any_gap, mut any_absent) = (false, false);
    for row in &source_rows {
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
    if let Some(note) = cap_note {
        out.push_str(&note);
    }
    Ok(out)
}

/// **Wedge vs starvation** — renders
/// [`store::diagnosis::wedge_vs_starvation_sql`]. `is_tty`/`full` gate the
/// row cap the same way [`format_incident_context`] does.
pub(crate) fn format_wedge_vs_starvation(
    table: &Table,
    is_tty: bool,
    full: bool,
) -> Result<String> {
    let c = Cols(&table.columns);
    let (ep, opened, closed) = (c.idx("episode")?, c.idx("opened_us")?, c.idx("closed_us")?);
    let (ticks, load, verdict) = (c.idx("ticks")?, c.idx("max_load1")?, c.idx("verdict")?);

    // Readable timestamps (owner ask): `opened_us`/`closed_us` convert to
    // local time; `ticks`/`max_load1` are counts, never epochs.
    let mut source_rows = table.rows.clone();
    for i in [opened, closed] {
        crate::convert_epoch_us_column(&mut source_rows, i);
    }
    let cap_note = crate::cap_rows(&mut source_rows, is_tty, full);

    let mut rows = Vec::new();
    let mut any_unknown = false;
    let mut any_absent = false;
    for row in &source_rows {
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
    if let Some(note) = cap_note {
        out.push_str(&note);
    }
    Ok(out)
}

/// **The gateway RTT ramp before a drop** — renders
/// [`store::diagnosis::gateway_ramp_sql`].
///
/// A `NULL` slope is stated as "not computed", never as flat. `is_tty`/`full`
/// gate the row cap over the plotted samples the same way
/// [`format_incident_context`] does.
pub(crate) fn format_gateway_ramp(
    table: &Table,
    drop_ts_us: i64,
    window_us: i64,
    is_tty: bool,
    full: bool,
) -> Result<String> {
    let c = Cols(&table.columns);
    let (ts, before) = (c.idx("ts_us")?, c.idx("us_before_drop")?);
    let (gw, rtt) = (c.idx("gw")?, c.idx("gw_rtt_ms")?);
    let (slope, fitted, gap) = (
        c.idx("slope_ms_per_s")?,
        c.idx("fitted_samples")?,
        c.idx("observation_gap_us")?,
    );

    // Readable timestamps (owner ask): only `ts_us` is an absolute instant —
    // `us_before_drop` is a duration before the drop (never converted, and
    // never `_us`-suffixed by name either) and `observation_gap_us` a gap
    // length, both left exactly as the query answered them.
    let mut source_rows = table.rows.clone();
    crate::convert_epoch_us_column(&mut source_rows, ts);
    let cap_note = crate::cap_rows(&mut source_rows, is_tty, full);

    let mut out = String::new();
    kv(
        &mut out,
        "drop_at",
        &format!("{drop_ts_us} ({})", fmt_instant(drop_ts_us)),
    );
    kv(&mut out, "window_us", &window_us.to_string());

    let Some(first) = source_rows.first() else {
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

    let rows: Vec<Vec<String>> = source_rows
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
    if let Some(note) = cap_note {
        out.push_str(&note);
    }
    Ok(out)
}

/// **The bracketed silences the record contains** — renders
/// [`store::diagnosis::silences_sql`]: every operator pause, stop, sleep, and
/// passive stretch, told apart by `KIND`. Also renders the frozen, pauses-only
/// [`store::diagnosis::observation_gaps_sql`]: no `kind` column at all, so
/// every row it has is a pause, whether it came from a current daemon (which
/// filters to pauses itself) or one built before either query existed.
/// `is_tty`/`full` gate the row cap the same way [`format_incident_context`]
/// does.
pub(crate) fn format_observation_gaps(table: &Table, is_tty: bool, full: bool) -> Result<String> {
    let c = Cols(&table.columns);
    let (go, gc, by) = (
        c.idx("gap_opened_us")?,
        c.idx("gap_closed_us")?,
        c.idx("gap_closed_by")?,
    );
    let kind = c.idx("kind").ok();
    let mut source_rows = table.rows.clone();
    let cap_note = crate::cap_rows(&mut source_rows, is_tty, full);
    let mut rows = Vec::new();
    let mut open_ended = false;
    let mut passive = false;
    for row in &source_rows {
        let closed = at(row, gc);
        open_ended |= closed.is_empty();
        let k = kind.map_or("pause", |i| at(row, i));
        passive |= k == "passive";
        rows.push(vec![
            k.to_string(),
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
        return Ok(
            "no observation gaps: the record is unbroken and every probe was sent\n".to_string(),
        );
    }
    let mut out = aligned(&["KIND", "OPENED", "CLOSED", "CLOSED_BY"], &rows);
    if open_ended {
        out.push_str("\n(still open)  the record ends inside this bracket - nothing closes it.\n");
    }
    if passive {
        out.push_str(
            "\npassive  the daemon withheld every probe; the samples of this stretch \
             exist and their probe verdicts read SKIP.\n",
        );
    }
    if let Some(note) = cap_note {
        out.push_str(&note);
    }
    Ok(out)
}

/// Render the latest air slice: what the last scan heard, ranked by how likely
/// each access point is to be sitting on our own band.
///
/// Three refusals, each rendered as one (realm net-observer, nodes #47 and #48):
///
/// - **the scan could not run** — `air = SKIP` prints its reason, and no list at
///   all, because an empty list would read as clear air;
/// - **our own channel is unknown** — the access points still print, but the
///   overlap column says so rather than showing zeroes;
/// - **an access point's channel is unreadable** — its overlap cell is
///   [`ABSENT`], not a nought.
///
/// The wording never claims measured interference. macOS reports no channel
/// occupancy to anybody, so "OVERLAP" is a band-geometry hypothesis and the
/// legend under the table says exactly that.
///
/// Each AP also carries two more marks, computed from the same four columns
/// as OVERLAP but answering different questions (the rubric decided at realm
/// net-observer, node #89): GRADE is the AP's own configuration
/// (security/band/width/generation), never its distance from us; SIGNAL is
/// the RSSI-noise gap, never its configuration. WHY carries the reasons
/// behind both.
///
/// `is_tty`/`full` gate the row cap over the AP list, applied AFTER the rank
/// sort below so a capped view still shows the strongest hypotheses first
/// (see [`crate::cap_rows`]), not an arbitrary prefix of the scan's own
/// order.
pub(crate) fn format_air(
    scan: &Table,
    aps: &Table,
    own: &Table,
    is_tty: bool,
    full: bool,
) -> Result<String> {
    let c = Cols(&scan.columns);
    let (ts_i, air_i, reason_i, count_i) = (
        c.idx("ts_us")?,
        c.idx("air")?,
        c.idx("reason")?,
        c.idx("ap_count")?,
    );
    let Some(row) = scan.rows.first() else {
        return Ok(
            "no air scan in the record: the `air` collector is off, or has not run yet\n"
                .to_string(),
        );
    };
    let mut out = String::new();
    kv(&mut out, "scanned", &stamp(at(row, ts_i)));
    if at(row, air_i) != "OK" {
        kv(&mut out, "air", "SKIP");
        kv(&mut out, "reason", &measured(row, reason_i, ABSENT));
        out.push_str(
            "\nThe scan could not run, so nothing is known about the air at that moment.\n\
             This is NOT an empty radio environment.\n",
        );
        return Ok(out);
    }
    kv(&mut out, "heard", &measured(row, count_i, "0"));

    // Our own channel, and what its absence costs.
    let own_read = own_channel(own)?;
    let own_span = own_read.map(|(s, _)| s);
    match own_read {
        Some((s, read_at)) => {
            let scanned_at = at(row, ts_i).parse::<i64>().ok();
            let lag = match (scanned_at, read_at) {
                (Some(scan_us), Some(own_us)) => Some((scan_us - own_us).abs()),
                _ => None,
            };
            let provenance = match (read_at, lag) {
                (Some(us), Some(lag)) if lag > OWN_CHANNEL_STALE_US => format!(
                    " - read {}, {} BEFORE this scan: we may have roamed since",
                    stamp(&us.to_string()),
                    human_us(lag)
                ),
                (Some(us), _) => format!(" - read {}", stamp(&us.to_string())),
                (None, _) => " - read at an unknown moment".to_string(),
            };
            kv(
                &mut out,
                "our channel",
                &format!(
                    "{} ({}, {} MHz){}",
                    s.channel,
                    s.band.as_str(),
                    s.width_mhz,
                    provenance
                ),
            );
        }
        None => kv(&mut out, "our channel", "(unknown - overlap not computed)"),
    }

    let a = Cols(&aps.columns);
    let (ch_i, band_i, width_i, phy_i, sec_i, rssi_i, noise_i) = (
        a.idx("channel")?,
        a.idx("channel_band")?,
        a.idx("channel_width_mhz")?,
        a.idx("phy_mode")?,
        a.idx("security")?,
        a.idx("rssi_dbm")?,
        a.idx("noise_dbm")?,
    );
    // Build (rank, rendered row) so the ordering is the hypothesis's own — the
    // SQL ordering is only a stable fallback for when there is nothing to rank by.
    let mut ranked: Vec<((i64, i32), Vec<String>)> = Vec::new();
    for row in &aps.rows {
        let channel = at(row, ch_i).parse::<i32>().ok();
        let band = at(row, band_i);
        let width = at(row, width_i).parse::<i32>().ok();
        let phy = at(row, phy_i);
        let sec = at(row, sec_i);
        let rssi = at(row, rssi_i).parse::<i32>().ok();
        let noise = at(row, noise_i).parse::<i32>().ok();
        let their = types::ChannelSpan::new(
            channel,
            if band.is_empty() { None } else { Some(band) },
            width,
        );
        let hypothesis = match (own_span, their) {
            (Some(ours), Some(theirs)) => Some(types::overlap_hypothesis(&ours, &theirs, rssi)),
            _ => None,
        };
        let (overlap_cell, confidence_cell, rank) = match hypothesis {
            Some(h) => (
                if h.overlap > 0.0 && h.overlap < 0.005 {
                    // A real sliver must not print as the same "0%" a disjoint
                    // channel does.
                    "<1%".to_string()
                } else {
                    format!("{:.0}%", h.overlap * 100.0)
                },
                format!("{:?}", h.confidence).to_lowercase(),
                h.rank_key(),
            ),
            // No own channel, or no readable channel on their side: there is
            // nothing to compute, and a zero would read as "does not overlap".
            None => (ABSENT.to_string(), ABSENT.to_string(), (i64::MIN, i32::MIN)),
        };
        // Two more marks, deliberately separate: GRADE is this AP's own
        // configuration, SIGNAL is how loudly it arrives — a wide-open network
        // heard faintly is still wide open, and a pristine one heard faintly is
        // still pristine (realm net-observer, node #89).
        let observation = types::AirObservation {
            channel,
            channel_band: if band.is_empty() {
                None
            } else {
                Some(band.to_string())
            },
            channel_width_mhz: width,
            phy_mode: if phy.is_empty() {
                None
            } else {
                Some(phy.to_string())
            },
            security: if sec.is_empty() {
                None
            } else {
                Some(sec.to_string())
            },
            rssi_dbm: rssi,
            noise_dbm: noise,
        };
        let grade = observation.grade();
        let grade_cell = if grade.confidence == types::Confidence::Low {
            format!("{}?", grade.grade.as_str())
        } else {
            grade.grade.as_str().to_string()
        };
        let signal_cell = observation
            .signal()
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "-".to_string());
        let why_cell = if grade.reasons.is_empty() {
            "-".to_string()
        } else {
            grade.reasons.join("; ")
        };
        ranked.push((
            rank,
            vec![
                measured(row, ch_i, ABSENT),
                measured(row, band_i, ABSENT),
                measured(row, width_i, ABSENT),
                measured(row, rssi_i, ABSENT),
                measured(row, noise_i, ABSENT),
                overlap_cell,
                confidence_cell,
                measured(row, phy_i, ABSENT),
                measured(row, sec_i, ABSENT),
                grade_cell,
                signal_cell,
                why_cell,
            ],
        ));
    }
    if ranked.is_empty() {
        out.push_str("\nThe scan ran and heard no other access point.\n");
        return Ok(out);
    }
    // Descending: the strongest overlap, then the loudest signal, comes first.
    ranked.sort_by_key(|a| std::cmp::Reverse(a.0));
    // Capped AFTER the rank sort, so the rows dropped are the weakest
    // hypotheses, not an arbitrary prefix of the scan's own order.
    let cap_note = crate::cap_rows(&mut ranked, is_tty, full);
    let rows: Vec<Vec<String>> = ranked.into_iter().map(|(_, r)| r).collect();
    out.push('\n');
    out.push_str(&aligned(
        &[
            "CH", "BAND", "WIDTH", "RSSI", "NOISE", "OVERLAP", "CONF", "PHY", "SECURITY", "GRADE",
            "SIGNAL", "WHY",
        ],
        &rows,
    ));
    out.push_str(AIR_LEGEND);
    if let Some(note) = cap_note {
        out.push_str(&note);
    }
    Ok(out)
}

/// What the OVERLAP column is and, more importantly, what it is not.
const AIR_LEGEND: &str = "\n\
OVERLAP is how much of the narrower of the two channels the two bands share, \n\
computed from channel numbers and widths - a HYPOTHESIS about who may be in our \n\
band, ordered loudest-first within equal overlap. It is NOT measured \n\
interference and NOT airtime taken: macOS reports no channel occupancy to any \n\
program, so no such number exists here. CONF says how much of it was reported \n\
rather than assumed. The report also carries no BSSID, so these access points \n\
cannot be matched to those of any other scan.\n\
GRADE is the AP's own configuration (security/band/width/generation), A-F, \n\
never a claim about how far away it is; a `?` suffix means one of those four \n\
inputs was not reported, so the letter is computed from the rest. SIGNAL is the \n\
RSSI-noise gap (good/fair/poor, `-` when either was not reported) - distance, \n\
not configuration. WHY lists the reasons behind both, `-` when there are none.\n";

/// Our own channel as the record last had it, with the moment it was read, or
/// `None` when the radio never reported one (never associated, or the `wifi`
/// collector off).
///
/// The moment travels with the channel on purpose: this reading has no time
/// bound of its own, so a channel the radio left days ago would otherwise be
/// compared against a scan taken now, silently. (realm net-observer, node #48)
fn own_channel(own: &Table) -> Result<Option<(types::ChannelSpan, Option<i64>)>> {
    let Some(row) = own.rows.first() else {
        return Ok(None);
    };
    let c = Cols(&own.columns);
    let channel = at(row, c.idx("channel")?).parse::<i32>().ok();
    let band = at(row, c.idx("channel_band")?).to_string();
    let width = at(row, c.idx("channel_width_mhz")?).parse::<i32>().ok();
    let read_at = at(row, c.idx("ts_us")?).parse::<i64>().ok();
    Ok(types::ChannelSpan::new(
        channel,
        if band.is_empty() { None } else { Some(&band) },
        width,
    )
    .map(|s| (s, read_at)))
}

/// A microsecond span as a short human duration, for saying how stale a reading
/// is without making the reader do arithmetic.
fn human_us(us: i64) -> String {
    let secs = us / 1_000_000;
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 5400 {
        format!("{}m", secs / 60)
    } else if secs < 172_800 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// How far our own channel reading may lag the scan before the comparison stops
/// being about the same association: one minute of ordinary roaming.
const OWN_CHANNEL_STALE_US: i64 = 60_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `Table` from column names and rows, with `""` standing for
    /// SQL `NULL` exactly as the store renders it.
    fn table(columns: &[&str], rows: &[&[&str]]) -> Table {
        Table {
            columns: columns.iter().map(|c| (*c).to_string()).collect(),
            rows: rows
                .iter()
                .map(|r| r.iter().map(|c| (*c).to_string()).collect())
                .collect(),
        }
    }

    const AIR_SCAN_COLS: &[&str] = &["ts_us", "air", "reason", "ap_count"];
    const AIR_AP_COLS: &[&str] = &[
        "channel",
        "channel_band",
        "channel_width_mhz",
        "phy_mode",
        "security",
        "rssi_dbm",
        "noise_dbm",
    ];
    const AIR_OWN_COLS: &[&str] = &["ts_us", "channel", "channel_band", "channel_width_mhz"];

    fn own_on(channel: &str, band: &str, width: &str) -> Table {
        table(AIR_OWN_COLS, &[&["1000", channel, band, width]])
    }

    /// A scan the daemon could not run is a refusal with its reason — and says
    /// in so many words that this is not an empty radio environment.
    #[test]
    fn a_skipped_air_scan_reads_as_a_refusal_not_as_clear_air() {
        let scan = table(
            AIR_SCAN_COLS,
            &[&["1000", "SKIP", "Wi-Fi powered off", "0"]],
        );
        let out = format_air(
            &scan,
            &table(AIR_AP_COLS, &[]),
            &own_on("36", "5ghz", "80"),
            false,
            false,
        )
        .unwrap();
        assert!(out.contains("SKIP"));
        assert!(out.contains("Wi-Fi powered off"));
        assert!(out.contains("NOT an empty radio environment"));
        assert!(
            !out.contains("OVERLAP"),
            "no table for a scan that never ran"
        );
    }

    /// A scan that ran and heard nobody is the OTHER fact, and says so.
    #[test]
    fn a_scan_that_heard_nobody_says_it_ran() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "0"]]);
        let out = format_air(
            &scan,
            &table(AIR_AP_COLS, &[]),
            &own_on("36", "5ghz", "80"),
            false,
            false,
        )
        .unwrap();
        assert!(out.contains("heard no other access point"));
    }

    #[test]
    fn no_scan_at_all_names_the_collector_rather_than_printing_a_blank() {
        let out = format_air(
            &table(AIR_SCAN_COLS, &[]),
            &table(AIR_AP_COLS, &[]),
            &table(AIR_OWN_COLS, &[]),
            false,
            false,
        )
        .unwrap();
        assert!(out.contains("no air scan in the record"));
    }

    /// The ordering is the point of the command: an AP squarely in our band
    /// outranks a louder one that is nowhere near it.
    #[test]
    fn access_points_are_ranked_by_overlap_before_loudness() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "2"]]);
        let aps = table(
            AIR_AP_COLS,
            &[
                // Loud, but on a different band entirely.
                &["6", "2ghz", "20", "802.11n", "wpa2", "-40", "-95"],
                // Quieter, but sharing our exact channel.
                &["36", "5ghz", "80", "802.11ax", "wpa3", "-80", "-95"],
            ],
        );
        let out = format_air(&scan, &aps, &own_on("36", "5ghz", "80"), false, false).unwrap();
        let on_channel = out.find("-80").expect("the on-channel AP is listed");
        let off_channel = out.find("-40").expect("the off-channel AP is listed");
        assert!(
            on_channel < off_channel,
            "the AP in our band must come first:\n{out}"
        );
        assert!(out.contains("100%"));
        assert!(out.contains("0%"));
    }

    /// Our own channel has no time bound of its own: the reading is simply the
    /// newest the wifi collector ever produced. A scan compared against a
    /// channel we left hours ago must say so, or the whole overlap column is
    /// quietly about the wrong band.
    #[test]
    fn a_stale_own_channel_is_labelled_with_its_age() {
        // Scan at 4h; own channel read at 0 — the radio may have roamed since.
        let scan = table(AIR_SCAN_COLS, &[&["14400000000", "OK", "", "1"]]);
        let aps = table(
            AIR_AP_COLS,
            &[&["40", "5ghz", "20", "802.11ax", "wpa3", "-70", "-95"]],
        );
        let own = table(AIR_OWN_COLS, &[&["0", "36", "5ghz", "80"]]);
        let out = format_air(&scan, &aps, &own, false, false).unwrap();
        assert!(
            out.contains("BEFORE this scan"),
            "a stale own channel must be called stale:\n{out}"
        );
        assert!(out.contains("4h"), "and say how stale:\n{out}");

        // A reading from the same minute carries its moment but no warning.
        let own = table(AIR_OWN_COLS, &[&["14400000000", "36", "5ghz", "80"]]);
        let out = format_air(&scan, &aps, &own, false, false).unwrap();
        assert!(out.contains("read "), "the moment is always shown:\n{out}");
        assert!(!out.contains("BEFORE this scan"));
    }

    /// Every wording rule the epistemic boundary imposes, checked on the output
    /// the operator actually reads (realm net-observer, node #48).
    #[test]
    fn the_output_never_claims_measured_interference() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "1"]]);
        let aps = table(
            AIR_AP_COLS,
            &[&["40", "5ghz", "20", "802.11ax", "wpa3", "-70", "-95"]],
        );
        let out = format_air(&scan, &aps, &own_on("36", "5ghz", "80"), false, false).unwrap();
        assert!(out.contains("HYPOTHESIS"));
        assert!(out.contains("NOT measured"));
        assert!(out.contains("no channel occupancy"));
        let lower = out.to_lowercase();
        assert!(!lower.contains("airtime taken by"), "no airtime claim");
        assert!(
            !lower.contains("interfering with"),
            "no asserted interference"
        );
    }

    /// Without our own channel the access points still print — the overlap
    /// column refuses instead of showing a column of zeroes, which would read as
    /// "nobody is near us".
    #[test]
    fn an_unknown_own_channel_withholds_the_overlap_rather_than_zeroing_it() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "1"]]);
        let aps = table(
            AIR_AP_COLS,
            &[&["40", "5ghz", "20", "802.11ax", "wpa3", "-70", "-95"]],
        );
        let out = format_air(&scan, &aps, &table(AIR_OWN_COLS, &[]), false, false).unwrap();
        assert!(out.contains("overlap not computed"));
        assert!(out.contains(ABSENT));
        assert!(!out.contains("0%"));
    }

    /// An AP whose channel the report garbled keeps its row, and its overlap
    /// cell refuses rather than reading as "does not overlap".
    #[test]
    fn an_ap_without_a_readable_channel_withholds_its_overlap() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "2"]]);
        let aps = table(
            AIR_AP_COLS,
            &[
                &["", "", "", "802.11ax", "wpa3", "-55", "-95"],
                &["36", "5ghz", "80", "802.11ax", "wpa3", "-80", "-95"],
            ],
        );
        let out = format_air(&scan, &aps, &own_on("36", "5ghz", "80"), false, false).unwrap();
        assert!(out.contains(ABSENT));
        // And it sorts last, below everything that could be placed at all.
        let unplaceable = out.find("-55").unwrap();
        let placed = out.find("-80").unwrap();
        assert!(placed < unplaceable);
    }

    /// The three new marks, computed from the same columns as OVERLAP but
    /// answering different questions (realm net-observer, node #89): a fully
    /// reported WPA3/5 GHz/80 MHz/ax AP grades A on a good signal, with
    /// nothing in WHY.
    #[test]
    fn format_air_carries_grade_signal_and_why_columns() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "1"]]);
        let aps = table(
            AIR_AP_COLS,
            &[&["36", "5ghz", "80", "802.11ax", "wpa3", "-50", "-90"]],
        );
        let out = format_air(&scan, &aps, &own_on("36", "5ghz", "80"), false, false).unwrap();
        assert!(out.contains("GRADE"), "{out}");
        assert!(out.contains("SIGNAL"), "{out}");
        assert!(out.contains("WHY"), "{out}");
        assert!(out.contains("good"), "SNR 40 must read good:\n{out}");
        // The legend itself explains the `?` hedge marker, so a bare
        // `contains('?')` would always be true; check the row's own grade
        // cell instead.
        assert!(
            !out.contains("A?"),
            "full confidence must not hedge:\n{out}"
        );
    }

    /// A rubric input the scan did not report lowers confidence but never the
    /// grade computed from what remains — the missing input costs nothing
    /// against the AP, and the letter carries a `?` to say so.
    #[test]
    fn format_air_marks_a_low_confidence_grade_with_a_question_mark() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "1"]]);
        let aps = table(
            AIR_AP_COLS,
            // security column blank: the report did not carry it.
            &[&["36", "5ghz", "80", "802.11ax", "", "-50", "-90"]],
        );
        let out = format_air(&scan, &aps, &own_on("36", "5ghz", "80"), false, false).unwrap();
        assert!(out.contains("A?"), "{out}");
        assert!(out.contains("security: unmeasured"), "{out}");
    }

    /// Open or legacy security grades F outright, and WHY says exactly why.
    #[test]
    fn format_air_explains_an_open_or_legacy_grade_in_why() {
        let scan = table(AIR_SCAN_COLS, &[&["1000", "OK", "", "1"]]);
        let aps = table(
            AIR_AP_COLS,
            &[&["6", "2ghz", "20", "802.11n", "open", "-50", "-90"]],
        );
        let out = format_air(&scan, &aps, &own_on("36", "5ghz", "80"), false, false).unwrap();
        assert!(
            out.contains("open, legacy or unrecognised security"),
            "{out}"
        );
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

    /// The sing-box log lines ride the answer as one newline-joined cell and
    /// render one `sing-box log` line each, between the measurements and the
    /// verdict; a NULL cell (the log said nothing then) and a table without the
    /// column (an older daemon) both render no such line.
    #[test]
    fn verdict_at_renders_the_sing_box_log_lines_when_present() {
        let cols: Vec<&str> = VERDICT_COLS
            .iter()
            .copied()
            .chain(["singbox_log"])
            .collect();
        let t = table(
            &cols,
            &[&[
                "1000",
                "OK",
                "3.5",
                "OK",
                "OK",
                "204",
                "1.2",
                "healthy",
                "",
                "",
                "no-route ×3 via vless-out-6 at 2026-09-17T17:56:05Z\nunreadable ×0 at 2026-09-17T17:56:35Z",
            ]],
        );
        let out = format_verdict_at(&t, 1500).unwrap();
        assert!(
            out.contains("sing-box log   no-route ×3 via vless-out-6 at 2026-09-17T17:56:05Z\n"),
            "{out}"
        );
        assert!(
            out.contains("sing-box log   unreadable ×0 at 2026-09-17T17:56:35Z\n"),
            "{out}"
        );
        let log_at = out.find("sing-box log").unwrap();
        assert!(out.find("load1").unwrap() < log_at, "{out}");
        assert!(
            log_at < out.find("layer          healthy").unwrap(),
            "{out}"
        );

        let t = table(
            &cols,
            &[&[
                "1000", "OK", "3.5", "OK", "OK", "204", "1.2", "healthy", "", "", "",
            ]],
        );
        assert!(
            !format_verdict_at(&t, 1500)
                .unwrap()
                .contains("sing-box log")
        );
        let t = table(
            VERDICT_COLS,
            &[&[
                "1000", "OK", "3.5", "OK", "OK", "204", "1.2", "healthy", "", "",
            ]],
        );
        assert!(
            !format_verdict_at(&t, 1500)
                .unwrap()
                .contains("sing-box log")
        );
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
        let out = format_incident_context(&t, false, false).unwrap();
        assert!(out.contains("withheld"), "{out}");
        assert!(out.contains("opened 4000"), "{out}");
        // The measured incident keeps its values; the gap one shows the token.
        assert!(out.contains("FAIL"), "{out}");
        assert_eq!(out.matches(WITHHELD).count(), 7, "{out}");
        assert!(out.contains("open"), "{out}");
    }

    #[test]
    fn incident_context_reports_an_empty_record() {
        let out = format_incident_context(&table(CTX_COLS, &[]), false, false).unwrap();
        assert!(out.contains("no incidents"), "{out}");
    }

    /// The row cap ([`crate::cap_rows`]) reaches `format_incident_context`
    /// through its `is_tty` parameter — taking it as an argument, rather than
    /// calling `std::io::stdout().is_terminal()` inline, is what makes this
    /// branch reachable from a test at all. A simulated interactive terminal
    /// over a record with more than `DEFAULT_ROW_LIMIT` incidents renders
    /// only the first 40 and notes the rest; off a terminal every incident
    /// renders. The other four diagnose.rs renderers wire the same
    /// `crate::cap_rows` call identically.
    #[test]
    fn incident_context_caps_on_a_tty_and_shows_everything_off_one() {
        let n = crate::DEFAULT_ROW_LIMIT + 5;
        let rows: Vec<Vec<String>> = (0..n)
            .map(|i| {
                vec![
                    format!("i{i:02}"),
                    "gw-drop".to_string(),
                    (1000 + i as i64).to_string(),
                    String::new(),
                    String::new(),
                    "OK".to_string(),
                    "OK".to_string(),
                    "OK".to_string(),
                    "0".to_string(),
                    "0.1".to_string(),
                    "link".to_string(),
                    String::new(),
                    String::new(),
                ]
            })
            .collect();
        let t = Table {
            columns: CTX_COLS.iter().map(|c| (*c).to_string()).collect(),
            rows,
        };

        let capped = format_incident_context(&t, true, false).unwrap();
        assert_eq!(
            capped.matches("gw-drop").count(),
            crate::DEFAULT_ROW_LIMIT,
            "{capped}"
        );
        assert!(capped.contains("5 more rows"), "{capped}");

        let full = format_incident_context(&t, false, false).unwrap();
        assert_eq!(full.matches("gw-drop").count(), n, "{full}");
        assert!(!full.contains("more rows"), "{full}");
    }

    /// Readable timestamps (owner ask): `opened_us`/`closed_us`/`state_ts_us`
    /// carry plausible epoch microseconds here, so each renders as local
    /// time — the raw number never leaks into the output — while `ticks`-like
    /// small numbers elsewhere in the row are untouched.
    #[test]
    fn incident_context_converts_absolute_timestamps_to_local_time() {
        let opened_us = 1_700_000_000_000_000i64;
        let closed_us = opened_us + 60_000_000;
        let state_ts_us = opened_us + 5_000_000;
        let (opened, closed, state_ts) = (
            opened_us.to_string(),
            closed_us.to_string(),
            state_ts_us.to_string(),
        );
        let t = table(
            CTX_COLS,
            &[&[
                "i1",
                "gw-drop",
                opened.as_str(),
                closed.as_str(),
                state_ts.as_str(),
                "FAIL",
                "OK",
                "OK",
                "204",
                "0.5",
                "link",
                "",
                "",
            ]],
        );
        let out = format_incident_context(&t, false, false).unwrap();
        assert!(!out.contains(&opened), "raw epoch leaked: {out}");
        assert!(!out.contains(&closed), "raw epoch leaked: {out}");
        assert!(!out.contains(&state_ts), "raw epoch leaked: {out}");
        assert!(out.contains(&crate::opened_local(opened_us)), "{out}");
        assert!(out.contains(&crate::opened_local(closed_us)), "{out}");
        assert!(out.contains(&crate::opened_local(state_ts_us)), "{out}");
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
        let out = format_wedge_vs_starvation(&t, false, false).unwrap();
        assert!(out.contains("starvation"), "{out}");
        assert!(out.contains("REFUSED"), "{out}");
        assert!(out.contains("cannot tell a wedge from starvation"), "{out}");
        assert!(out.contains(ABSENT), "{out}");
    }

    /// Readable timestamps: `opened_us`/`closed_us` convert to local time;
    /// `ticks` and `max_load1` — small numbers in the same row — are left
    /// exactly as the query answered them.
    #[test]
    fn wedge_vs_starvation_converts_opened_and_closed_to_local_time() {
        let opened_us = 2_000_000_000_000_000i64;
        let closed_us = opened_us + 300_000_000;
        let (opened, closed) = (opened_us.to_string(), closed_us.to_string());
        let t = table(
            EPISODE_COLS,
            &[&[
                "1",
                opened.as_str(),
                closed.as_str(),
                "3",
                "24.0",
                "starvation",
            ]],
        );
        let out = format_wedge_vs_starvation(&t, false, false).unwrap();
        assert!(!out.contains(&opened), "raw epoch leaked: {out}");
        assert!(!out.contains(&closed), "raw epoch leaked: {out}");
        assert!(out.contains(&crate::opened_local(opened_us)), "{out}");
        assert!(out.contains(&crate::opened_local(closed_us)), "{out}");
        assert!(out.contains("24.0"), "ticks/load1 stay untouched: {out}");
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
        let out = format_gateway_ramp(&t, 1000, 900, false, false).unwrap();
        assert!(out.contains("12.5 ms/s over 2 fitted samples"), "{out}");
        assert!(!out.contains("not computed"), "{out}");
    }

    /// A `NULL` slope over a gapped window is "not computed", never flat.
    #[test]
    fn gateway_ramp_refuses_a_slope_across_a_gap() {
        let t = table(RAMP_COLS, &[&["100", "900", "OK", "5.0", "", "", "400000"]]);
        let out = format_gateway_ramp(&t, 1000, 900, false, false).unwrap();
        assert!(out.contains("not computed"), "{out}");
        assert!(out.contains("400000 us of observation gap"), "{out}");
        assert!(!out.contains("0 ms/s"), "{out}");
    }

    #[test]
    fn gateway_ramp_marks_an_unanswered_tick() {
        let t = table(RAMP_COLS, &[&["100", "900", "FAIL", "", "12.5", "2", "0"]]);
        let out = format_gateway_ramp(&t, 1000, 900, false, false).unwrap();
        assert!(out.contains("(no answer)"), "{out}");
    }

    /// Readable timestamps: `ts_us` (an absolute instant) converts to local
    /// time; `us_before_drop` (a duration before the drop, never
    /// `_us`-suffixed by name either) stays raw — this fold only ever
    /// converts the column it knows is an absolute instant, never anything
    /// reached by scanning column names.
    #[test]
    fn gateway_ramp_converts_only_the_absolute_ts_us_column() {
        let ts_us = 1_800_000_000_000_000i64;
        let ts = ts_us.to_string();
        let before_drop = "700900";
        let t = table(
            RAMP_COLS,
            &[&[ts.as_str(), before_drop, "OK", "5.0", "12.5", "2", "0"]],
        );
        let out = format_gateway_ramp(&t, 1000, 900, false, false).unwrap();
        assert!(!out.contains(&ts), "raw epoch leaked: {out}");
        assert!(out.contains(&crate::opened_local(ts_us)), "{out}");
        assert!(
            out.contains(before_drop),
            "a duration column must stay raw: {out}"
        );
    }

    const GAP_COLS: &[&str] = &["kind", "gap_opened_us", "gap_closed_us", "gap_closed_by"];

    #[test]
    fn observation_gaps_render_an_open_ended_pause() {
        let t = table(
            GAP_COLS,
            &[
                &["pause", "1000", "2000", "resume"],
                &["pause", "9000", "", ""],
            ],
        );
        let out = format_observation_gaps(&t, false, false).unwrap();
        assert!(out.contains("resume"), "{out}");
        assert!(out.contains("(still open)"), "{out}");
        assert!(out.contains("nothing closes it"), "{out}");
        assert!(!out.contains("withheld every probe"), "{out}");
    }

    /// A passive stretch is listed as its own kind, and the legend says what
    /// its `SKIP`s mean.
    #[test]
    fn observation_gaps_render_a_passive_stretch_with_its_legend() {
        let t = table(
            GAP_COLS,
            &[
                &["passive", "1000", "5000", "active"],
                &["pause", "2000", "3000", "resume"],
            ],
        );
        let out = format_observation_gaps(&t, false, false).unwrap();
        assert!(out.contains("KIND"), "{out}");
        assert!(out.contains("passive"), "{out}");
        assert!(out.contains("withheld every probe"), "{out}");
        assert!(!out.contains("(still open)"), "{out}");
    }

    /// `stop` and `sleep` render like any other kind: no special legend, just
    /// their own label in the KIND column (realm net-observer, node #109).
    #[test]
    fn observation_gaps_render_stop_and_sleep_kinds_plainly() {
        let t = table(
            GAP_COLS,
            &[
                &["stop", "1000", "2000", "startup"],
                &["sleep", "3000", "4000", "sample"],
            ],
        );
        let out = format_observation_gaps(&t, false, false).unwrap();
        assert!(out.contains("stop"), "{out}");
        assert!(out.contains("sleep"), "{out}");
        assert!(!out.contains("withheld every probe"), "{out}");
        assert!(!out.contains("(still open)"), "{out}");
    }

    /// A daemon built before the tier answers without a `kind` column: every
    /// row is a pause, and the renderer must not fail on the missing column.
    #[test]
    fn observation_gaps_from_a_pre_tier_daemon_are_all_pauses() {
        let old = &["gap_opened_us", "gap_closed_us", "gap_closed_by"];
        let t = table(old, &[&["1000", "2000", "resume"]]);
        let out = format_observation_gaps(&t, false, false).unwrap();
        assert!(out.contains("pause"), "{out}");
        assert!(!out.contains("withheld every probe"), "{out}");
    }

    #[test]
    fn observation_gaps_report_an_unbroken_record() {
        let out = format_observation_gaps(&table(GAP_COLS, &[]), false, false).unwrap();
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
