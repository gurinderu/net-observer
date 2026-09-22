//! The **connections** window: what this machine talks to right now, grouped
//! the way the operator asks — by host, by address, by address and port, or by
//! client process.
//!
//! The data is the daemon's answer to `DiagnosticQuery::Connections { group_by }`
//! — the newest tick of the live flow table the daemon records from sing-box's
//! Clash API, already folded into one row per group with the flows counted and
//! their bytes summed (realm net-observer, node #75). This window adds no
//! collection and no timer: it asks once when it opens, once per press of
//! `refresh`, and once per switch of the grouping, each a read-only query on
//! the background executor ([`crate::ui::fetch_connections`]), the way the map
//! window reads its findings.
//!
//! ## Its own window
//!
//! Opened from the menu's **Connections** entry as a normal, resizable window,
//! exactly like the map ([`crate::map`]). [`ConnectionsView`] is the root view;
//! [`open_or_focus`] stashes the live handle on the shared [`Glance`] so a
//! second click focuses the open window instead of duplicating it.
//!
//! ## What the table says, and what it does not
//!
//! Every state has words, never a blank area: not read yet, the daemon's own
//! words for why it could not answer, or a tick that listed nothing — with the
//! tick's verdict, because "the API did not answer" (`SKIP`) and "nothing is
//! talking" (`OK`) are different answers and the daemon keeps them apart. The
//! tick is dated absolutely above the rows, so the reader knows which moment
//! the picture is of rather than taking it for now. The rows are a
//! [`uniform_list`], as the event log's are: an `ip:port` tick from one browser
//! runs to dozens of groups, and a plain column would lay the rest out past the
//! window's bottom edge, where gpui paints nothing.
//!
//! ## External only
//!
//! The daemon's answer carries every group with its `scope` (`internal` /
//! `lan` / `external`, judged once at collection); the fold is this window's.
//! The **external only** box in the toolbar is on when the window opens and
//! remembered for the window's life: with it on, the internal groups (every
//! app's DNS query to sing-box's own listener is a flow — 1023 of 1080 in one
//! measured tick) and the LAN groups are not listed but counted, as flows, on
//! one footer line, `+1023 internal (dns/plumbing) · +4 lan`; with it off,
//! every group is listed. Flipping the box refetches nothing — the answer
//! already holds every row (realm net-observer, node #75).

use std::ops::Range;

use gpui::prelude::*;
use gpui::{
    AnyWindowHandle, App, AsyncApp, Context, Entity, ScrollStrategy, SharedString, TitlebarOptions,
    UniformListScrollHandle, Window, WindowBounds, WindowHandle, WindowKind, WindowOptions, div,
    px, rgb, size, uniform_list,
};

use net_observer_ipc::Table;
use types::{ConnectionScope, ConnectionsGroupBy};

use crate::ui::{Dating, Glance, Theme, column_index, dated, note, separator};

/// Initial size of the connections window (resizable afterwards), gpui logical
/// px. Wider than the map's default by exactly what the table needs: the
/// column widths below plus the section's `px_3` padding, so an `ip:port` row
/// keeps its port and its hosts at the size the window first opens at.
const WIN_W: f32 = 440.0;
const WIN_H: f32 = 320.0;

/// The columns, in gpui logical px. `key` is the widest thing a row must show
/// **without losing a character** — the grouping is the point of the row, and
/// under `ip:port` the port sits at its tail, exactly where an ellipsis would
/// land — so it is floored at a bracketed v6 address with its port and never
/// shrinks; `hosts` is the column that gives way. The count and the two byte
/// columns are fixed at their widest figure (`999.9 KB`).
const KEY_MIN_W: f32 = 170.0;
const FLOWS_W: f32 = 40.0;
const BYTES_W: f32 = 56.0;
const HOSTS_MIN_W: f32 = 80.0;
/// The section's horizontal padding (`px_3` on both sides).
const SIDE_PAD: f32 = 24.0;
// The default window fits the whole row: a window that opened too narrow for
// its own table would cut the hosts column at the edge on first sight.
const _: () = assert!(WIN_W >= SIDE_PAD + KEY_MIN_W + FLOWS_W + 2.0 * BYTES_W + HOSTS_MIN_W);

/// How many names the `hosts` cell spells out before summarising the rest as
/// `+N`: a group by address can sit behind dozens of names, and the row is one
/// line.
const MAX_HOSTS: usize = 3;

/// The word the toolbar and the caption use for a grouping — the same tokens
/// the CLI's `--by` takes, so the two readers name one thing one way.
fn group_label(group_by: ConnectionsGroupBy) -> &'static str {
    match group_by {
        ConnectionsGroupBy::Host => "host",
        ConnectionsGroupBy::Ip => "ip",
        ConnectionsGroupBy::IpPort => "ip:port",
        ConnectionsGroupBy::Process => "process",
        // No toolbar toggle asks for this grouping yet (CLI-only so far,
        // realm net-observer, node #168) — the arm exists so the match
        // stays exhaustive against a wire variant this window can receive.
        ConnectionsGroupBy::ProcessHost => "process+host",
    }
}

/// Whether the `hosts` column is drawn under `group_by`: under `host` it would
/// repeat the key on every row, so it is not.
fn shows_hosts(group_by: ConnectionsGroupBy) -> bool {
    group_by != ConnectionsGroupBy::Host
}

/// A byte count as a reader-sized figure: `999 B`, `12.3 KB`, `4.0 MB` —
/// decimal units, one decimal above bytes. The unit is picked AFTER rounding:
/// a figure that would print as `1000.0 KB` is `1.0 MB`. Pure, so the spelling
/// is a testable fact.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 1;
    // Anything at or above 999.95 rounds to `1000.0` at one decimal, which is
    // `1.0` of the next unit — unless there is no next unit.
    while value >= 999.95 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// A byte cell of the table as the row draws it: the figure, or `-` for a cell
/// that is not a number (the store spells NULL as the empty string).
fn bytes_cell(cell: &str) -> String {
    cell.parse::<u64>()
        .map_or_else(|_| "-".to_string(), human_bytes)
}

/// A count cell as the row draws it: the number, or `-` when the store spelled
/// none.
fn count_cell(cell: &str) -> String {
    if cell.is_empty() {
        "-".to_string()
    } else {
        cell.to_string()
    }
}

/// The `hosts` cell — the daemon's comma-joined distinct names — as the row
/// draws it: the first [`MAX_HOSTS`] names and `+N` for the rest, `-` when the
/// group carried no name at all.
fn hosts_cell(cell: &str) -> String {
    let names: Vec<&str> = cell.split(',').filter(|n| !n.is_empty()).collect();
    if names.is_empty() {
        return "-".to_string();
    }
    let shown = names[..names.len().min(MAX_HOSTS)].join(", ");
    match names.len().saturating_sub(MAX_HOSTS) {
        0 => shown,
        more => format!("{shown} +{more}"),
    }
}

/// One group of the newest tick, as the window draws it: every cell already
/// worded, so the render carries no parsing — plus the two facts the fold
/// reads, the scope and the count as a number.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowRow {
    /// The group — a name, an address, `address:port` or a process name; the
    /// daemon never leaves it empty (a group with nothing known is `-`).
    key: String,
    flows: String,
    up: String,
    down: String,
    hosts: String,
    /// Where the group's destinations lie, as the daemon judged it; a table
    /// without the column (an older daemon's) is all `external` — shown,
    /// never hidden.
    scope: ConnectionScope,
    /// The live flows in the group, for the footer's sum; `0` when the
    /// daemon spelled none.
    count: u64,
}

/// Whether a row is listed under the box's state: every row with the box
/// off, the external ones with it on.
fn is_shown(row: &FlowRow, external_only: bool) -> bool {
    !external_only || row.scope == ConnectionScope::External
}

/// What the box hides: the flows (not the groups) of the rows it keeps off
/// the list, by scope — `[internal, lan]`. Nothing with the box off.
fn hidden_flows(rows: &[FlowRow], external_only: bool) -> [u64; 2] {
    let mut hidden = [0u64; 2];
    for row in rows.iter().filter(|r| !is_shown(r, external_only)) {
        let i = match row.scope {
            ConnectionScope::Internal => 0,
            ConnectionScope::Lan => 1,
            ConnectionScope::External => continue,
        };
        hidden[i] = hidden[i].saturating_add(row.count);
    }
    hidden
}

/// The footer line for what the box hides: `+1023 internal (dns/plumbing) ·
/// +4 lan`, each part only when it counts something; `None` when nothing is
/// hidden, so the table stands alone.
fn hidden_line(hidden: [u64; 2]) -> Option<String> {
    let [internal, lan] = hidden;
    let mut parts = Vec::new();
    if internal > 0 {
        parts.push(format!("+{internal} internal (dns/plumbing)"));
    }
    if lan > 0 {
        parts.push(format!("+{lan} lan"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" \u{00b7} "))
    }
}

/// The newest tick, reduced from the daemon's `Connections` table to what the
/// window draws.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tick {
    /// The tick listed flows: its moment and one row per group, in the
    /// daemon's order (most flows first).
    Flows { ts_us: i64, rows: Vec<FlowRow> },
    /// The tick listed nothing — the daemon answers such a tick as ONE row
    /// carrying only its moment and verdict, so `SKIP` (could not look) and
    /// `OK` (nothing is talking) stay two different answers here too.
    Empty { ts_us: i64, verdict: String },
    /// The record holds no connections tick at all.
    Absent,
}

/// Reduce the daemon's `Connections` table to what the window draws.
///
/// Columns are found by NAME, never by position ([`column_index`]): a table
/// missing one of the seven is an `Err` naming it, so a daemon whose diagnosis
/// grew or shrank is reported rather than drawn misaligned. The eighth,
/// `scope`, is the one a daemon may lack (it predates the column): then every
/// group is `external`, which is what the wire type defaults to as well. A
/// row with an empty `key` is the daemon's empty-tick marker, never a group.
/// Pure over its input so the reduction is testable without a window.
fn tick_rows(table: &Table) -> Result<Tick, String> {
    let col = |name: &str| column_index(table, name);
    let ts_us = col("ts_us")?;
    let verdict = col("verdict")?;
    let key = col("key")?;
    let count = col("count")?;
    let upload = col("upload")?;
    let download = col("download")?;
    let hosts = col("hosts")?;
    let scope = col("scope").ok();

    let Some(first) = table.rows.first() else {
        return Ok(Tick::Absent);
    };
    // A cell by position, the empty string for a row shorter than its header.
    // An item, not a closure: a closure cannot return a borrow of its own
    // argument.
    fn cell(row: &[String], i: usize) -> &str {
        row.get(i).map_or("", String::as_str)
    }
    let ts = cell(first, ts_us).parse::<i64>().unwrap_or(0);
    let rows: Vec<FlowRow> = table
        .rows
        .iter()
        .filter(|row| !cell(row, key).is_empty())
        .map(|row| FlowRow {
            key: cell(row, key).to_string(),
            flows: count_cell(cell(row, count)),
            up: bytes_cell(cell(row, upload)),
            down: bytes_cell(cell(row, download)),
            hosts: hosts_cell(cell(row, hosts)),
            scope: scope
                .and_then(|i| cell(row, i).parse::<ConnectionScope>().ok())
                .unwrap_or_default(),
            count: cell(row, count).parse::<u64>().unwrap_or(0),
        })
        .collect();
    if rows.is_empty() {
        return Ok(Tick::Empty {
            ts_us: ts,
            verdict: cell(first, verdict).to_string(),
        });
    }
    Ok(Tick::Flows { ts_us: ts, rows })
}

/// The daemon's answer, reduced to what the window draws — or the words for
/// why there is none: the daemon's own ([`crate::ui::fetch_connections`]), or
/// a table whose shape this window cannot read ([`tick_rows`]).
fn reduce(answer: Result<Table, String>) -> Result<Tick, String> {
    answer.and_then(|table| tick_rows(&table))
}

/// The line that dates the picture: the tick's moment, absolutely — the
/// reading is presented, so it gets the clock rather than an age (see the
/// vocabulary rule in `ui::parts`). A tick with no usable stamp says so rather
/// than borrowing "now".
fn tick_line(ts_us: i64, now_us: i64) -> String {
    if ts_us > 0 {
        format!("tick at {}", dated(Dating::Presented, ts_us, now_us))
    } else {
        "tick at an unreported moment".to_string()
    }
}

/// The caption over a tick that listed flows: when, how many groups, and by
/// what — so the rows below are never read under the wrong grouping.
fn caption(ts_us: i64, now_us: i64, group_by: ConnectionsGroupBy, groups: usize) -> String {
    format!(
        "{} \u{00b7} {groups} group{} by {}",
        tick_line(ts_us, now_us),
        if groups == 1 { "" } else { "s" },
        group_label(group_by)
    )
}

/// The words for a tick that listed nothing, with the verdict that says which
/// kind of nothing it was.
fn empty_line(verdict: &str) -> String {
    format!("no flows in the last tick ({verdict})")
}

/// The words for a table with no tick at all.
const NO_TICK: &str = "no connections tick in the record";

/// The words shown before the first read returns.
const PENDING: &str = "connections not read yet";

/// The header over the rows, on the same column widths as [`flow_row`]. The
/// key and hosts cells carry selectors: the rows are built lazily and carry
/// only their key, so the header is where a headless test reads the columns'
/// widths and which of them are drawn.
fn header_row(show_hosts: bool, theme: Theme) -> impl IntoElement {
    div()
        .flex()
        .w_full()
        .pb_1()
        .text_size(px(10.0))
        .text_color(rgb(theme.muted))
        .child(
            div()
                .debug_selector(|| "connections-col-key".into())
                .flex_1()
                .min_w(px(KEY_MIN_W))
                .flex_shrink_0()
                .child("key"),
        )
        .child(div().w(px(FLOWS_W)).flex_shrink_0().child("flows"))
        .child(div().w(px(BYTES_W)).flex_shrink_0().child("up"))
        .child(div().w(px(BYTES_W)).flex_shrink_0().child("down"))
        .children(show_hosts.then(|| {
            div()
                .debug_selector(|| "connections-col-hosts".into())
                .flex_1()
                .min_w(px(HOSTS_MIN_W))
                .child("hosts")
        }))
}

/// One row of the table. Single-line and uniform-height, which is what the
/// [`uniform_list`] requires.
///
/// `use<>` (capture nothing) is load-bearing, as it is for the event log's row:
/// every cell is *cloned* out of `row`, so the element holds no borrow of the
/// view — but without precise capturing the opaque type would still carry
/// `row`'s lifetime, and the `uniform_list` closure cannot return elements tied
/// to the view it was handed.
fn flow_row(row: &FlowRow, show_hosts: bool, theme: Theme) -> impl IntoElement + use<> {
    // Test handle only: the selector carries the key, so a headless test can
    // assert which groups were drawn.
    let selector = format!("connections-row:{}", row.key);
    let hosts = show_hosts.then(|| {
        div()
            .flex_1()
            .min_w(px(HOSTS_MIN_W))
            .overflow_hidden()
            .whitespace_nowrap()
            .text_ellipsis()
            .text_color(rgb(theme.muted))
            .child(row.hosts.clone())
    });
    div()
        .debug_selector(move || selector)
        .flex()
        .w_full()
        .py_0p5()
        .text_size(px(11.0))
        .child(
            div()
                .flex_1()
                .min_w(px(KEY_MIN_W))
                .flex_shrink_0()
                .overflow_hidden()
                .whitespace_nowrap()
                .text_ellipsis()
                .child(row.key.clone()),
        )
        .child(
            div()
                .w(px(FLOWS_W))
                .flex_shrink_0()
                .child(row.flows.clone()),
        )
        .child(div().w(px(BYTES_W)).flex_shrink_0().child(row.up.clone()))
        .child(div().w(px(BYTES_W)).flex_shrink_0().child(row.down.clone()))
        .children(hosts)
}

/// The root view of the **connections window**. Holds a handle to the shared
/// [`Glance`] for the socket path only: the table is the one thing this window
/// draws, and it comes from the window's own reads, never from the snapshot.
pub(crate) struct ConnectionsView {
    model: Entity<Glance>,
    /// How the daemon is asked to fold the tick. Set by the toolbar; every
    /// switch refetches.
    group_by: ConnectionsGroupBy,
    /// The **external only** box: on when the window opens, remembered for
    /// the window's life. Flipping it refetches nothing — the reading holds
    /// every row and the fold is done at draw time ([`is_shown`]).
    external_only: bool,
    /// The daemon's last answer to `DiagnosticQuery::Connections`, already
    /// reduced to what the window draws ([`reduce`]): `None` until the first
    /// read returns (and again while a switched grouping is being read), then
    /// the tick or the words for why there is none. Reduced once on arrival,
    /// not per frame, because the list renders rows by index on every scroll.
    reading: Option<Result<Tick, String>>,
    /// The list's scroll state — the event log's shape. Held so a switch of
    /// the grouping can put the new table at its top rather than at wherever
    /// the old one was scrolled to.
    scroll: UniformListScrollHandle,
}

impl ConnectionsView {
    fn new(model: Entity<Glance>) -> Self {
        Self {
            model,
            group_by: ConnectionsGroupBy::Host,
            external_only: true,
            reading: None,
            scroll: UniformListScrollHandle::new(),
        }
    }

    /// Flip the **external only** box. No read goes out: the reading holds
    /// every row. The list goes back to its top, because a scroll position
    /// into one fold means nothing in the other.
    fn toggle_external_only(&mut self, cx: &mut Context<Self>) {
        self.external_only = !self.external_only;
        self.scroll.scroll_to_item(0, ScrollStrategy::Top);
        cx.notify();
    }

    /// Ask the daemon for the newest tick, grouped as the view is set, on the
    /// background executor, and keep the answer (see
    /// [`crate::ui::fetch_connections`]) — the same shape as the map's findings
    /// read: never on the gpui main thread, written back through a weak handle
    /// so a closed window just drops it. An answer to a grouping the view has
    /// since left is dropped too: a table drawn under the wrong label would be
    /// a silent wrong datum.
    ///
    /// Not part of [`ConnectionsView::new`]: the open path ([`open_window`])
    /// calls it, so a headless test can build the view with an injected
    /// `reading` that no socket read then races to overwrite.
    fn spawn_fetch(&self, cx: &mut Context<Self>) {
        let socket = self.model.read(cx).socket_path.clone();
        let group_by = self.group_by;
        cx.spawn(async move |view, acx: &mut AsyncApp| {
            let answer = acx
                .background_spawn(async move { crate::ui::fetch_connections(&socket, group_by) })
                .await;
            view.update(acx, |v, cx| {
                if v.group_by == group_by {
                    v.reading = Some(reduce(answer));
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    /// Switch the grouping and read the tick again under it. The old reading
    /// is dropped first: rows folded by host must not stand under the `process`
    /// label while the new answer is on its way — and the list goes back to
    /// its top, because a scroll position into the old table means nothing in
    /// the new one. A click on the grouping already selected is not a switch;
    /// `refresh` is the button for that.
    fn set_group_by(&mut self, group_by: ConnectionsGroupBy, cx: &mut Context<Self>) {
        if self.group_by == group_by {
            return;
        }
        self.group_by = group_by;
        self.reading = None;
        self.scroll.scroll_to_item(0, ScrollStrategy::Top);
        self.spawn_fetch(cx);
        cx.notify();
    }
}

impl Render for ConnectionsView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let group_by = self.group_by;
        let external_only = self.external_only;
        let show_hosts = shows_hosts(group_by);
        let now = crate::ui::now_us();

        // What stands above the rows — a state in words, or the caption and
        // the header — how many rows the list below it has (the shown ones:
        // the box's fold), and what the box hides. `flex_none`, because the
        // list is the one child allowed to take the slack.
        let head = div().flex().flex_col().flex_none().px_3().py_2();
        let (head, count, hidden) = match &self.reading {
            None => (
                head.child(note("connections-pending", PENDING, theme.muted)),
                0,
                None,
            ),
            Some(Err(why)) => (
                head.child(note(
                    "connections-error",
                    format!("connections unavailable: {why}"),
                    theme.warn,
                )),
                0,
                None,
            ),
            Some(Ok(Tick::Absent)) => (
                head.child(note("connections-empty", NO_TICK, theme.muted)),
                0,
                None,
            ),
            Some(Ok(Tick::Empty { ts_us, verdict })) => (
                head.child(note(
                    "connections-caption",
                    tick_line(*ts_us, now),
                    theme.muted,
                ))
                .child(note(
                    "connections-empty",
                    empty_line(verdict),
                    theme.muted,
                )),
                0,
                None,
            ),
            Some(Ok(Tick::Flows { ts_us, rows })) => {
                let shown = rows.iter().filter(|r| is_shown(r, external_only)).count();
                (
                    head.child(note(
                        "connections-caption",
                        caption(*ts_us, now, group_by, shown),
                        theme.muted,
                    ))
                    .child(header_row(show_hosts, theme))
                    .child(separator(theme)),
                    shown,
                    hidden_line(hidden_flows(rows, external_only)),
                )
            }
        };

        // Only the rows in `range` are ever built, from the reading the view
        // holds — the event log's shape — and only the shown ones are
        // indexed: the fold walks the rows rather than copying them, so a
        // flip of the box costs no reduction. No list at all when there is
        // no row: the words above already say why.
        let list = (count > 0).then(|| {
            uniform_list(
                "connections-list",
                count,
                cx.processor(move |this, range: Range<usize>, _window, _cx| {
                    let Some(Ok(Tick::Flows { rows, .. })) = &this.reading else {
                        return Vec::new();
                    };
                    rows.iter()
                        .filter(|r| is_shown(r, external_only))
                        .skip(range.start)
                        .take(range.len())
                        .map(|row| flow_row(row, show_hosts, theme))
                        .collect::<Vec<_>>()
                }),
            )
            // Test handle only: the rows past the viewport are never built, so
            // the list itself is what a headless test can find.
            .debug_selector(|| "connections-list".into())
            .track_scroll(self.scroll.clone())
            .flex_1()
            .px_3()
        });

        // The footer: what the box keeps off the list, as flows by scope.
        // The same `note` element as every other state line, so its words
        // are a selector a headless test can name.
        let footer = hidden.map(|line| {
            div().flex_none().px_3().child(separator(theme)).child(note(
                "connections-hidden",
                line,
                theme.muted,
            ))
        });

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .child(toolbar(group_by, external_only, theme, cx))
            .child(separator(theme))
            .child(head)
            .children(list)
            .children(footer)
    }
}

/// The **external only** box: a small square, filled with the accent and
/// ticked when on, with its label beside it. A click flips the fold and
/// nothing else — no read goes out.
fn external_only_box(
    on: bool,
    theme: Theme,
    cx: &mut Context<ConnectionsView>,
) -> impl IntoElement {
    let mut square = div()
        .flex()
        .items_center()
        .justify_center()
        .size(px(12.0))
        .rounded_sm()
        .border_1()
        .border_color(rgb(if on { theme.accent } else { theme.edge }));
    if on {
        square = square
            .bg(rgb(theme.accent))
            .text_color(rgb(theme.knob))
            .text_size(px(9.0))
            .child("\u{2713}");
    }
    div()
        .id("connections-external-only")
        // Test handle only: the selector carries the box's state, so a
        // headless test can read it without reaching into the view.
        .debug_selector(move || {
            format!(
                "connections-external-only:{}",
                if on { "on" } else { "off" }
            )
        })
        .flex()
        .items_center()
        .gap_1()
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(theme.muted))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child(square)
        .child("external only")
        .on_click(cx.listener(|view, _, _window, cx| {
            view.toggle_external_only(cx);
        }))
}

/// The window's controls: the grouping switch — four toggles, the selected one
/// filled the way the map's reading tabs are — the **external only** box, and
/// `refresh`. Every press is a read-only query or a fold of the answer already
/// held; nothing here touches the daemon's state or the network.
fn toolbar(
    group_by: ConnectionsGroupBy,
    external_only: bool,
    theme: Theme,
    cx: &mut Context<ConnectionsView>,
) -> impl IntoElement {
    let group = |id: &'static str,
                 this: ConnectionsGroupBy,
                 theme: Theme,
                 cx: &mut Context<ConnectionsView>| {
        let selected = group_by == this;
        div()
            .id(id)
            // Test handle only: the switch is the window's control surface, so
            // a headless test must be able to find each toggle by name.
            .debug_selector(move || id.into())
            .px_2()
            .py_1()
            .rounded_md()
            .text_size(px(12.0))
            .cursor_pointer()
            .text_color(rgb(if selected { theme.accent } else { theme.muted }))
            .when(selected, |d| d.bg(rgb(theme.hover)))
            .hover(|s| s.bg(rgb(theme.hover)))
            .child(group_label(this))
            .on_click(cx.listener(move |view, _, _window, cx| {
                view.set_group_by(this, cx);
            }))
    };

    let refresh = div()
        .id("connections-refresh")
        .debug_selector(|| "connections-refresh".into())
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .cursor_pointer()
        .text_color(rgb(theme.accent))
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("refresh")
        .on_click(cx.listener(|view, _, _window, cx| {
            view.spawn_fetch(cx);
        }));

    div()
        .flex()
        .items_center()
        .gap_1()
        .px_3()
        .py_1()
        .child(group(
            "connections-group-host",
            ConnectionsGroupBy::Host,
            theme,
            cx,
        ))
        .child(group(
            "connections-group-ip",
            ConnectionsGroupBy::Ip,
            theme,
            cx,
        ))
        .child(group(
            "connections-group-ip-port",
            ConnectionsGroupBy::IpPort,
            theme,
            cx,
        ))
        .child(group(
            "connections-group-process",
            ConnectionsGroupBy::Process,
            theme,
            cx,
        ))
        .child(div().flex_1())
        .child(external_only_box(external_only, theme, cx))
        .child(refresh)
}

/// Open the connections window, or bring the already-open one to the front.
///
/// The live window handle is stashed on the shared [`Glance`] so a second click
/// focuses the existing window instead of opening a duplicate. A stale handle
/// (window since closed) falls through to a fresh open. Modeled exactly on
/// [`crate::map::open_or_focus`]; never panics — a failed open is logged, not
/// fatal.
pub(crate) fn open_or_focus(cx: &mut App, glance: &Entity<Glance>) {
    if let Some(existing) = glance.read(cx).connections_window {
        // `update` succeeds only while the window is still open.
        if existing
            .update(cx, |_view, window, _cx| window.activate_window())
            .is_ok()
        {
            cx.activate(true);
            return;
        }
    }

    if let Some(handle) = open_window(cx, glance.clone()) {
        let any: AnyWindowHandle = handle.into();
        glance.update(cx, |g, _| g.connections_window = Some(any));
        // Accessory apps don't get key focus for free; bring the new window forward.
        cx.activate(true);
    }
}

/// Create the connections window over the shared [`Glance`]. Returns the
/// window handle, or `None` if the window failed to open.
fn open_window(cx: &mut App, model: Entity<Glance>) -> Option<WindowHandle<ConnectionsView>> {
    let options = window_options(cx);
    match cx.open_window(options, move |_window, cx| {
        cx.new(|cx| {
            let view = ConnectionsView::new(model);
            // The first read belongs to the open, not to the constructor (see
            // `ConnectionsView::spawn_fetch`).
            view.spawn_fetch(cx);
            view
        })
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("net-observer-bar: failed to open connections window: {e}");
            None
        }
    }
}

/// Window options for the connections window: a normal, resizable, closable
/// window with a native titlebar ("net-observer — connections"), centered on
/// the primary display — mirroring the map window's options.
fn window_options(cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(WIN_W), px(WIN_H)), cx)),
        titlebar: Some(TitlebarOptions {
            title: Some(SharedString::from("net-observer — connections")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        kind: WindowKind::Normal,
        is_movable: true,
        is_resizable: true,
        is_minimizable: true,
        focus: true,
        show: true,
        window_min_size: Some(size(px(320.0), px(260.0))),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon's `Connections` table: its seven columns, in its order.
    pub(super) fn connections_table(rows: Vec<[&str; 7]>) -> Table {
        Table {
            columns: [
                "ts_us", "verdict", "key", "count", "upload", "download", "hosts",
            ]
            .map(String::from)
            .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    /// Bytes are spelled for a reader: whole bytes below a thousand, one
    /// decimal above, decimal units — and the unit is picked after rounding,
    /// so no figure ever reads `1000.0` of anything with a unit above it.
    #[test]
    fn bytes_are_spelled_for_a_reader() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1_000), "1.0 KB");
        assert_eq!(human_bytes(12_300), "12.3 KB");
        assert_eq!(human_bytes(999_949), "999.9 KB");
        assert_eq!(human_bytes(999_950), "1.0 MB");
        assert_eq!(human_bytes(4_000_000), "4.0 MB");
        assert_eq!(human_bytes(999_950_000), "1.0 GB");
        assert_eq!(human_bytes(2_500_000_000), "2.5 GB");
        assert_eq!(human_bytes(7_000_000_000_000), "7.0 TB");
        // The last unit has nothing above it to round into.
        assert_eq!(human_bytes(1_500_000_000_000_000), "1500.0 TB");
        assert_eq!(bytes_cell("5006"), "5.0 KB");
        assert_eq!(bytes_cell(""), "-");
        assert_eq!(bytes_cell("many"), "-");
    }

    /// The hosts cell shows three names and counts the rest; a group with no
    /// name says so rather than drawing a blank.
    #[test]
    fn hosts_are_truncated_to_three_with_a_count() {
        assert_eq!(hosts_cell(""), "-");
        assert_eq!(hosts_cell("a.example"), "a.example");
        assert_eq!(hosts_cell("a,b,c"), "a, b, c");
        assert_eq!(hosts_cell("a,b,c,d"), "a, b, c +1");
        assert_eq!(hosts_cell("a,b,c,d,e,f"), "a, b, c +3");
        // A stray separator is not a name.
        assert_eq!(hosts_cell("a,,b"), "a, b");
    }

    /// The hosts column repeats the key under `host` and is dropped there;
    /// every other grouping keeps it.
    #[test]
    fn the_hosts_column_is_dropped_only_under_host() {
        assert!(!shows_hosts(ConnectionsGroupBy::Host));
        assert!(shows_hosts(ConnectionsGroupBy::Ip));
        assert!(shows_hosts(ConnectionsGroupBy::IpPort));
        assert!(shows_hosts(ConnectionsGroupBy::Process));
    }

    /// A tick with flows becomes one worded row per group, in the daemon's
    /// order, dated by the tick.
    #[test]
    fn a_tick_with_flows_becomes_one_row_per_group() {
        let table = connections_table(vec![
            [
                "1700000000000000",
                "OK",
                "194.221.250.50",
                "2",
                "30",
                "0",
                "www.google.com",
            ],
            [
                "1700000000000000",
                "OK",
                "claude.ai",
                "1",
                "100",
                "5006",
                "",
            ],
        ]);
        assert_eq!(
            tick_rows(&table),
            Ok(Tick::Flows {
                ts_us: 1_700_000_000_000_000,
                rows: vec![
                    FlowRow {
                        key: "194.221.250.50".to_string(),
                        flows: "2".to_string(),
                        up: "30 B".to_string(),
                        down: "0 B".to_string(),
                        hosts: "www.google.com".to_string(),
                        scope: ConnectionScope::External,
                        count: 2,
                    },
                    FlowRow {
                        key: "claude.ai".to_string(),
                        flows: "1".to_string(),
                        up: "100 B".to_string(),
                        down: "5.0 KB".to_string(),
                        hosts: "-".to_string(),
                        scope: ConnectionScope::External,
                        count: 1,
                    },
                ],
            })
        );
    }

    /// The daemon's `Connections` table with its `scope` column — the tick
    /// measured on the owner's Mac in miniature: 1023 DNS flows to the TUN
    /// address, four LAN flows, the tunnel's own traffic.
    pub(super) fn scoped_table(rows: Vec<[&str; 8]>) -> Table {
        Table {
            columns: [
                "ts_us", "verdict", "key", "scope", "count", "upload", "download", "hosts",
            ]
            .map(String::from)
            .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    pub(super) fn measured_tick() -> Table {
        scoped_table(vec![
            [
                "1700000000000000",
                "OK",
                "172.19.0.1",
                "internal",
                "1023",
                "1",
                "1",
                "",
            ],
            [
                "1700000000000000",
                "OK",
                "printer.local",
                "lan",
                "4",
                "1",
                "1",
                "",
            ],
            [
                "1700000000000000",
                "OK",
                "claude.ai",
                "external",
                "3",
                "100",
                "5006",
                "",
            ],
            [
                "1700000000000000",
                "OK",
                "149.154.167.41",
                "external",
                "2",
                "30",
                "0",
                "",
            ],
        ])
    }

    /// Each row carries the daemon's scope and its count as a number; a
    /// table without the column — an older daemon's — is all `external`,
    /// and a scope the reader does not know is `external` too: shown, never
    /// hidden.
    #[test]
    fn rows_carry_their_scope_and_an_absent_column_is_all_external() {
        let Ok(Tick::Flows { rows, .. }) = tick_rows(&measured_tick()) else {
            panic!("the measured tick has flows");
        };
        let scoped: Vec<(ConnectionScope, u64)> = rows.iter().map(|r| (r.scope, r.count)).collect();
        assert_eq!(
            scoped,
            vec![
                (ConnectionScope::Internal, 1023),
                (ConnectionScope::Lan, 4),
                (ConnectionScope::External, 3),
                (ConnectionScope::External, 2),
            ]
        );
        let older = connections_table(vec![[
            "1700000000000000",
            "OK",
            "172.19.0.1",
            "1023",
            "1",
            "1",
            "",
        ]]);
        let Ok(Tick::Flows { rows, .. }) = tick_rows(&older) else {
            panic!("the older tick has flows");
        };
        assert_eq!(rows[0].scope, ConnectionScope::External);
        let odd = scoped_table(vec![["7", "OK", "x", "vpn", "1", "0", "0", ""]]);
        let Ok(Tick::Flows { rows, .. }) = tick_rows(&odd) else {
            panic!("the odd tick has flows");
        };
        assert_eq!(rows[0].scope, ConnectionScope::External);
    }

    /// With the box on, only the external rows are shown and the rest are
    /// counted as flows on the footer line in the brief's words; with it
    /// off, every row is shown and nothing is hidden. A tick with nothing to
    /// hide has no footer either way.
    #[test]
    fn the_box_folds_the_internal_and_lan_flows_into_the_footer() {
        let Ok(Tick::Flows { rows, .. }) = tick_rows(&measured_tick()) else {
            panic!("the measured tick has flows");
        };
        let shown: Vec<&str> = rows
            .iter()
            .filter(|r| is_shown(r, true))
            .map(|r| r.key.as_str())
            .collect();
        assert_eq!(shown, ["claude.ai", "149.154.167.41"]);
        assert_eq!(hidden_flows(&rows, true), [1023, 4]);
        assert_eq!(
            hidden_line(hidden_flows(&rows, true)).as_deref(),
            Some("+1023 internal (dns/plumbing) \u{00b7} +4 lan")
        );

        assert!(rows.iter().all(|r| is_shown(r, false)));
        assert_eq!(hidden_flows(&rows, false), [0, 0]);
        assert_eq!(hidden_line([0, 0]), None);

        assert_eq!(
            hidden_line([1023, 0]).as_deref(),
            Some("+1023 internal (dns/plumbing)")
        );
        assert_eq!(hidden_line([0, 4]).as_deref(), Some("+4 lan"));
    }

    /// The daemon's one-row empty tick keeps its verdict — `SKIP` and `OK`
    /// are two different kinds of nothing — and a table with no row at all is
    /// a third state, not an empty tick.
    #[test]
    fn an_empty_tick_keeps_its_verdict_and_no_tick_is_named() {
        let skipped = connections_table(vec![["7", "SKIP", "", "", "", "", ""]]);
        assert_eq!(
            tick_rows(&skipped),
            Ok(Tick::Empty {
                ts_us: 7,
                verdict: "SKIP".to_string()
            })
        );
        let quiet = connections_table(vec![["7", "OK", "", "", "", "", ""]]);
        assert_eq!(
            tick_rows(&quiet),
            Ok(Tick::Empty {
                ts_us: 7,
                verdict: "OK".to_string()
            })
        );
        assert_eq!(tick_rows(&connections_table(vec![])), Ok(Tick::Absent));
        assert_eq!(empty_line("SKIP"), "no flows in the last tick (SKIP)");
    }

    /// A table missing a column is named, not misread by position — and the
    /// daemon's own words pass through [`reduce`] untouched.
    #[test]
    fn a_table_missing_a_column_is_named_not_misread() {
        let table = Table {
            columns: ["ts_us", "verdict", "key"].map(String::from).to_vec(),
            rows: vec![["1", "OK", "x"].map(String::from).to_vec()],
        };
        assert_eq!(
            tick_rows(&table),
            Err("table has no `count` column".to_string())
        );
        assert_eq!(
            reduce(Ok(table)),
            Err("table has no `count` column".to_string())
        );
        assert_eq!(
            reduce(Err("no socket".to_string())),
            Err("no socket".to_string())
        );
    }

    /// The caption dates the tick absolutely and names the grouping the rows
    /// are folded by; a tick without a stamp says so.
    #[test]
    fn the_caption_dates_the_tick_and_names_the_grouping() {
        let now = 1_700_000_100_000_000;
        let line = caption(1_700_000_000_000_000, now, ConnectionsGroupBy::IpPort, 2);
        assert!(line.starts_with("tick at "), "{line}");
        assert!(
            !line.contains("ago"),
            "a presented reading is not an age: {line}"
        );
        assert!(line.ends_with(" \u{00b7} 2 groups by ip:port"), "{line}");
        assert!(
            caption(1_700_000_000_000_000, now, ConnectionsGroupBy::Host, 1)
                .ends_with(" \u{00b7} 1 group by host")
        );
        assert!(
            caption(1_700_000_000_000_000, now, ConnectionsGroupBy::Host, 40)
                .ends_with(" \u{00b7} 40 groups by host")
        );
        assert_eq!(tick_line(0, now), "tick at an unreported moment");
    }

    /// The toolbar's words are the CLI's `--by` tokens.
    #[test]
    fn the_group_labels_are_the_cli_tokens() {
        assert_eq!(group_label(ConnectionsGroupBy::Host), "host");
        assert_eq!(group_label(ConnectionsGroupBy::Ip), "ip");
        assert_eq!(group_label(ConnectionsGroupBy::IpPort), "ip:port");
        assert_eq!(group_label(ConnectionsGroupBy::Process), "process");
    }
}

/// Headless UI tests: the window drawn on gpui's own test platform, whose
/// window runs layout and scene construction for real and implements
/// `draw(&Scene)` as a no-op. No display, no daemon, no root — see `map.rs` for
/// the sibling suite this one is modelled on.
#[cfg(test)]
mod headless_tests {
    use super::tests::{connections_table, measured_tick};
    use super::*;
    use crate::ui::Glance;
    use gpui::{Modifiers, Size, TestAppContext, VisualTestContext};
    use net_observer_ipc::StatusSnapshot;

    /// The tick every drawn-rows test dates its rows with.
    const TS_US: i64 = 1_700_000_000_000_000;

    /// `inner` lies wholly inside a viewport of `outer` anchored at the origin.
    fn contains(outer: Size<gpui::Pixels>, inner: gpui::Bounds<gpui::Pixels>) -> bool {
        inner.origin.x >= px(0.0)
            && inner.origin.y >= px(0.0)
            && inner.origin.x + inner.size.width <= outer.width
            && inner.origin.y + inner.size.height <= outer.height
    }

    /// A selector built at run time, in the shape `debug_bounds` takes.
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// A fresh window over an injected answer, grouped as `group_by`, with the
    /// **external only** box as the view opens it (on) — all set before the
    /// first paint, like the map's findings window, and for the same reason:
    /// gpui's debug-bounds map only grows over a window's life, so only a
    /// window that never drew a row can say there is none. The socket is
    /// never driven: `ConnectionsView::new` fetches nothing (the open path
    /// does), so what the window draws is exactly what was injected.
    fn connections_window(
        cx: &mut TestAppContext,
        answer: Option<Result<Table, String>>,
        group_by: ConnectionsGroupBy,
    ) -> (WindowHandle<ConnectionsView>, VisualTestContext) {
        connections_window_folded(cx, answer, group_by, true)
    }

    /// [`connections_window`] with the box set as `external_only`.
    fn connections_window_folded(
        cx: &mut TestAppContext,
        answer: Option<Result<Table, String>>,
        group_by: ConnectionsGroupBy,
        external_only: bool,
    ) -> (WindowHandle<ConnectionsView>, VisualTestContext) {
        let model = cx.update(|cx| {
            cx.new(|_| {
                Glance::new(
                    StatusSnapshot::default(),
                    None,
                    "/tmp/net-observer-connections-test.sock".to_string(),
                )
            })
        });
        let window = cx.add_window(|_, _| {
            let mut view = ConnectionsView::new(model);
            view.group_by = group_by;
            view.external_only = external_only;
            view.reading = answer.map(reduce);
            view
        });
        let vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.simulate_resize(size(px(WIN_W), px(WIN_H)));
        vcx.run_until_parked();
        (window, vcx)
    }

    /// The two groups the drawn-rows tests inject, and the selectors the body
    /// must draw them under — shared so the absence test names the very
    /// selectors the presence test found.
    fn two_groups() -> (Table, [&'static str; 2]) {
        (
            connections_table(vec![
                [
                    "1700000000000000",
                    "OK",
                    "194.221.250.50",
                    "2",
                    "30",
                    "0",
                    "www.google.com",
                ],
                [
                    "1700000000000000",
                    "OK",
                    "claude.ai",
                    "1",
                    "100",
                    "5006",
                    "",
                ],
            ]),
            [
                "connections-row:194.221.250.50",
                "connections-row:claude.ai",
            ],
        )
    }

    /// The grouping switch, the **external only** box (on, as the window
    /// opens) and refresh are the window's control surface: all six are
    /// drawn, and none is laid out past the window's edge where nothing is
    /// painted.
    #[gpui::test]
    fn the_four_group_buttons_and_refresh_are_drawn(cx: &mut TestAppContext) {
        let viewport = size(px(WIN_W), px(WIN_H));
        let (_window, mut vcx) = connections_window(cx, None, ConnectionsGroupBy::Host);
        for control in [
            "connections-group-host",
            "connections-group-ip",
            "connections-group-ip-port",
            "connections-group-process",
            "connections-external-only:on",
            "connections-refresh",
        ] {
            let bounds = vcx
                .debug_bounds(control)
                .unwrap_or_else(|| panic!("the window did not draw `{control}`"));
            assert!(
                contains(viewport, bounds),
                "`{control}` leaves the window: {bounds:?}"
            );
        }
        assert!(
            vcx.debug_bounds(leak(format!("connections-pending:{PENDING}")))
                .is_some(),
            "before the first read the window must say it has not read yet"
        );
    }

    /// A tick with two groups draws two rows, each under its key, inside the
    /// list, and the caption counts them.
    #[gpui::test]
    fn a_table_with_two_groups_draws_two_rows(cx: &mut TestAppContext) {
        let (table, rows) = two_groups();
        let (_window, mut vcx) = connections_window(cx, Some(Ok(table)), ConnectionsGroupBy::Ip);
        assert!(
            vcx.debug_bounds("connections-list").is_some(),
            "the rows must be drawn by the list"
        );
        for row in rows {
            assert!(
                vcx.debug_bounds(row).is_some(),
                "the window did not draw `{row}`"
            );
        }
        let caption = leak(format!(
            "connections-caption:{}",
            caption(TS_US, 0, ConnectionsGroupBy::Ip, 2)
        ));
        assert!(
            vcx.debug_bounds(caption).is_some(),
            "the caption must count the two groups: `{caption}`"
        );
        assert!(
            vcx.debug_bounds(leak(format!("connections-empty:{NO_TICK}")))
                .is_none(),
            "a tick with flows must not also say there is no tick"
        );
    }

    /// The daemon's one-row `SKIP` tick says so — the exact sentence, with the
    /// verdict — in a FRESH window (gpui's debug-bounds map only grows over a
    /// window's life, so only a window that never drew a row can say there is
    /// none), and draws no row and no list.
    #[gpui::test]
    fn a_skip_tick_says_no_flows_and_draws_no_row(cx: &mut TestAppContext) {
        let (_table, rows) = two_groups();
        let skipped = connections_table(vec![["7", "SKIP", "", "", "", "", ""]]);
        let (_window, mut vcx) =
            connections_window(cx, Some(Ok(skipped)), ConnectionsGroupBy::Host);
        assert!(
            vcx.debug_bounds("connections-empty:no flows in the last tick (SKIP)")
                .is_some(),
            "a SKIP tick must say `no flows in the last tick (SKIP)`"
        );
        for row in rows {
            assert!(
                vcx.debug_bounds(row).is_none(),
                "a SKIP tick drew a row: `{row}`"
            );
        }
        assert!(
            vcx.debug_bounds("connections-list").is_none(),
            "a SKIP tick has no rows to list"
        );
    }

    /// A record with no connections tick at all is a third state, and its own
    /// sentence — in a fresh window, for the reason above.
    #[gpui::test]
    fn an_absent_tick_says_so(cx: &mut TestAppContext) {
        let (_window, mut vcx) = connections_window(
            cx,
            Some(Ok(connections_table(vec![]))),
            ConnectionsGroupBy::Host,
        );
        assert!(
            vcx.debug_bounds(leak(format!("connections-empty:{NO_TICK}")))
                .is_some(),
            "an empty table must say `{NO_TICK}`"
        );
        assert!(
            vcx.debug_bounds("connections-empty:no flows in the last tick (SKIP)")
                .is_none(),
            "an absent tick is not a skipped one"
        );
    }

    /// A read the daemon could not answer shows the daemon's own words, never
    /// a blank section and never a crash.
    #[gpui::test]
    fn a_failed_read_shows_the_daemons_words(cx: &mut TestAppContext) {
        let why = "daemon cannot answer Connections (older daemon): bad request: unknown variant";
        let (_window, mut vcx) =
            connections_window(cx, Some(Err(why.to_string())), ConnectionsGroupBy::Host);
        let selector = leak(format!("connections-error:connections unavailable: {why}"));
        assert!(
            vcx.debug_bounds(selector).is_some(),
            "the window did not show the daemon's words: `{why}`"
        );
    }

    /// Forty groups: the list is drawn and the caption counts all forty, while
    /// the rows are built lazily — the first is on screen; whether the fortieth
    /// is depends on the viewport, and a plain column would have laid it out
    /// past the bottom edge where nothing is painted.
    #[gpui::test]
    fn forty_groups_are_listed_and_counted(cx: &mut TestAppContext) {
        let ts = TS_US.to_string();
        let keys: Vec<String> = (1..=40).map(|i| format!("10.0.0.{i}:443")).collect();
        let rows: Vec<[&str; 7]> = keys
            .iter()
            .map(|key| [ts.as_str(), "OK", key.as_str(), "1", "10", "20", ""])
            .collect();
        let (_window, mut vcx) = connections_window(
            cx,
            Some(Ok(connections_table(rows))),
            ConnectionsGroupBy::IpPort,
        );
        let list = vcx
            .debug_bounds("connections-list")
            .expect("forty groups must be drawn as a list");
        assert!(
            contains(size(px(WIN_W), px(WIN_H)), list),
            "the list must lie inside the window: {list:?}"
        );
        assert!(
            vcx.debug_bounds("connections-row:10.0.0.1:443").is_some(),
            "the first row must be on screen"
        );
        let caption = leak(format!(
            "connections-caption:{}",
            caption(TS_US, 0, ConnectionsGroupBy::IpPort, 40)
        ));
        assert!(
            vcx.debug_bounds(caption).is_some(),
            "the caption must say 40 groups: `{caption}`"
        );
    }

    /// The key column keeps its floor at the window's default width, in every
    /// grouping — an `ip:port` key ellipsised at its tail would lose the port,
    /// the one thing that grouping shows — and under `host` the hosts column,
    /// which would repeat the key, is not drawn at all. Each grouping gets a
    /// fresh window, because a window that once drew the hosts cell can never
    /// say it is gone.
    #[gpui::test]
    fn the_key_keeps_its_width_and_hosts_hides_under_host(cx: &mut TestAppContext) {
        let viewport = size(px(WIN_W), px(WIN_H));
        let (table, _rows) = two_groups();
        for (group_by, hosts_drawn) in [
            (ConnectionsGroupBy::Host, false),
            (ConnectionsGroupBy::IpPort, true),
        ] {
            let (_window, mut vcx) = connections_window(cx, Some(Ok(table.clone())), group_by);
            let key = vcx
                .debug_bounds("connections-col-key")
                .unwrap_or_else(|| panic!("no key column under {group_by:?}"));
            assert!(
                key.size.width >= px(KEY_MIN_W),
                "the key column gave way under {group_by:?}: {key:?}"
            );
            assert!(
                contains(viewport, key),
                "the key column leaves the window under {group_by:?}: {key:?}"
            );
            assert_eq!(
                vcx.debug_bounds("connections-col-hosts").is_some(),
                hosts_drawn,
                "the hosts column under {group_by:?}"
            );
        }
    }

    /// Pressing a grouping toggle switches the view's grouping and reads the
    /// tick again under it: with no daemon at the test socket the read comes
    /// back as words, which is how a read that went out is observable at all.
    #[gpui::test]
    fn clicking_a_group_button_switches_the_grouping_and_refetches(cx: &mut TestAppContext) {
        let (window, mut vcx) = connections_window(cx, None, ConnectionsGroupBy::Host);
        vcx.update(|window, _| window.activate_window());
        vcx.run_until_parked();
        assert_eq!(
            window
                .update(&mut vcx, |view, _window, _cx| view.group_by)
                .expect("the window is open"),
            ConnectionsGroupBy::Host,
            "precondition: a fresh window groups by host"
        );

        let button = vcx
            .debug_bounds("connections-group-process")
            .expect("the process toggle is drawn");
        vcx.simulate_click(button.center(), Modifiers::none());
        vcx.run_until_parked();

        let (group_by, reading) = window
            .update(&mut vcx, |view, _window, _cx| {
                (view.group_by, view.reading.clone())
            })
            .expect("the window is open");
        assert_eq!(
            group_by,
            ConnectionsGroupBy::Process,
            "the click must set the grouping"
        );
        assert!(
            matches!(reading, Some(Err(_))),
            "the switch must read the tick again — with no daemon, as words: {reading:?}"
        );
    }

    /// The footer line the measured tick folds to with the box on.
    const FOLDED: &str = "connections-hidden:+1023 internal (dns/plumbing) \u{00b7} +4 lan";

    /// With the box on — as the window opens — the internal group is NOT
    /// drawn and the LAN one is not either, the external ones are, the
    /// caption counts the two shown, and the footer says what was folded.
    /// A fresh window, because a window that once drew a row can never say
    /// it is gone.
    #[gpui::test]
    fn with_the_box_on_the_internal_row_is_not_drawn_and_the_footer_is(cx: &mut TestAppContext) {
        let (_window, mut vcx) =
            connections_window(cx, Some(Ok(measured_tick())), ConnectionsGroupBy::Host);
        assert!(
            vcx.debug_bounds("connections-row:172.19.0.1").is_none(),
            "the internal group must not be listed with the box on"
        );
        assert!(
            vcx.debug_bounds("connections-row:printer.local").is_none(),
            "the LAN group must not be listed with the box on"
        );
        for row in [
            "connections-row:claude.ai",
            "connections-row:149.154.167.41",
        ] {
            assert!(
                vcx.debug_bounds(row).is_some(),
                "the window did not draw `{row}`"
            );
        }
        let footer = vcx
            .debug_bounds(FOLDED)
            .unwrap_or_else(|| panic!("the footer must say `{FOLDED}`"));
        assert!(
            contains(size(px(WIN_W), px(WIN_H)), footer),
            "the footer leaves the window: {footer:?}"
        );
        let caption = leak(format!(
            "connections-caption:{}",
            caption(TS_US, 0, ConnectionsGroupBy::Host, 2)
        ));
        assert!(
            vcx.debug_bounds(caption).is_some(),
            "the caption must count the two shown groups: `{caption}`"
        );
    }

    /// With the box off, every group is drawn — the internal one included —
    /// and there is no footer, in a fresh window opened already unfolded.
    #[gpui::test]
    fn with_the_box_off_every_row_is_drawn_and_there_is_no_footer(cx: &mut TestAppContext) {
        let (_window, mut vcx) = connections_window_folded(
            cx,
            Some(Ok(measured_tick())),
            ConnectionsGroupBy::Host,
            false,
        );
        for row in [
            "connections-row:172.19.0.1",
            "connections-row:printer.local",
            "connections-row:claude.ai",
            "connections-row:149.154.167.41",
        ] {
            assert!(
                vcx.debug_bounds(row).is_some(),
                "the window did not draw `{row}`"
            );
        }
        assert!(
            vcx.debug_bounds(FOLDED).is_none(),
            "nothing is hidden with the box off, so no footer"
        );
        assert!(
            vcx.debug_bounds("connections-external-only:off").is_some(),
            "the box must show itself off"
        );
        let caption = leak(format!(
            "connections-caption:{}",
            caption(TS_US, 0, ConnectionsGroupBy::Host, 4)
        ));
        assert!(
            vcx.debug_bounds(caption).is_some(),
            "the caption must count all four groups: `{caption}`"
        );
    }

    /// Clicking the box flips the fold without a read: the box is off and the
    /// reading the view holds is the one it drew from before. What each
    /// state draws is the two fresh-window tests above — a window that once
    /// drew a row can never say it is gone, so neither fold is asserted
    /// through a click.
    #[gpui::test]
    fn clicking_the_box_unfolds_without_a_refetch(cx: &mut TestAppContext) {
        let (window, mut vcx) =
            connections_window(cx, Some(Ok(measured_tick())), ConnectionsGroupBy::Host);
        vcx.update(|window, _| window.activate_window());
        vcx.run_until_parked();
        let before = window
            .update(&mut vcx, |view, _window, _cx| view.reading.clone())
            .expect("the window is open");

        let button = vcx
            .debug_bounds("connections-external-only:on")
            .expect("the box is drawn on");
        vcx.simulate_click(button.center(), Modifiers::none());
        vcx.run_until_parked();

        let (external_only, after) = window
            .update(&mut vcx, |view, _window, _cx| {
                (view.external_only, view.reading.clone())
            })
            .expect("the window is open");
        assert!(!external_only, "the click must flip the box off");
        assert_eq!(after, before, "the flip must not read the tick again");
    }
}
