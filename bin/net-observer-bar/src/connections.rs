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

use std::ops::Range;

use gpui::prelude::*;
use gpui::{
    AnyWindowHandle, App, AsyncApp, Context, Entity, ScrollStrategy, SharedString, TitlebarOptions,
    UniformListScrollHandle, Window, WindowBounds, WindowHandle, WindowKind, WindowOptions, div,
    px, rgb, size, uniform_list,
};

use net_observer_ipc::Table;
use types::ConnectionsGroupBy;

use crate::ui::{Dating, Glance, Theme, dated, note, separator};

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
/// worded, so the render carries no parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FlowRow {
    /// The group — a name, an address, `address:port` or a process name; the
    /// daemon never leaves it empty (a group with nothing known is `-`).
    key: String,
    flows: String,
    up: String,
    down: String,
    hosts: String,
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
/// Columns are found by NAME, never by position: a table missing one of the
/// seven is an `Err` naming it, so a daemon whose diagnosis grew or shrank is
/// reported rather than drawn misaligned. A row with an empty `key` is the
/// daemon's empty-tick marker, never a group. Pure over its input so the
/// reduction is testable without a window.
fn tick_rows(table: &Table) -> Result<Tick, String> {
    let col = |name: &str| {
        table
            .columns
            .iter()
            .position(|c| c == name)
            .ok_or_else(|| format!("connections table has no `{name}` column"))
    };
    let ts_us = col("ts_us")?;
    let verdict = col("verdict")?;
    let key = col("key")?;
    let count = col("count")?;
    let upload = col("upload")?;
    let download = col("download")?;
    let hosts = col("hosts")?;

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
            reading: None,
            scroll: UniformListScrollHandle::new(),
        }
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
        let show_hosts = shows_hosts(group_by);
        let now = crate::ui::now_us();

        // What stands above the rows — a state in words, or the caption and
        // the header — and how many rows the list below it has. `flex_none`,
        // because the list is the one child allowed to take the slack.
        let head = div().flex().flex_col().flex_none().px_3().py_2();
        let (head, count) = match &self.reading {
            None => (
                head.child(note("connections-pending", PENDING, theme.muted)),
                0,
            ),
            Some(Err(why)) => (
                head.child(note(
                    "connections-error",
                    format!("connections unavailable: {why}"),
                    theme.warn,
                )),
                0,
            ),
            Some(Ok(Tick::Absent)) => (
                head.child(note("connections-empty", NO_TICK, theme.muted)),
                0,
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
            ),
            Some(Ok(Tick::Flows { ts_us, rows })) => (
                head.child(note(
                    "connections-caption",
                    caption(*ts_us, now, group_by, rows.len()),
                    theme.muted,
                ))
                .child(header_row(show_hosts, theme))
                .child(separator(theme)),
                rows.len(),
            ),
        };

        // Only the rows in `range` are ever built, from the reading the view
        // holds — the event log's shape. No list at all when there is no row:
        // the words above already say why.
        let list = (count > 0).then(|| {
            uniform_list(
                "connections-list",
                count,
                cx.processor(move |this, range: Range<usize>, _window, _cx| {
                    let Some(Ok(Tick::Flows { rows, .. })) = &this.reading else {
                        return Vec::new();
                    };
                    range
                        .filter_map(|i| rows.get(i))
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

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .child(toolbar(group_by, theme, cx))
            .child(separator(theme))
            .child(head)
            .children(list)
    }
}

/// The window's controls: the grouping switch — four toggles, the selected one
/// filled the way the map's reading tabs are — and `refresh`. Every press is a
/// read-only query; nothing here touches the daemon's state or the network.
fn toolbar(
    group_by: ConnectionsGroupBy,
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
                    },
                    FlowRow {
                        key: "claude.ai".to_string(),
                        flows: "1".to_string(),
                        up: "100 B".to_string(),
                        down: "5.0 KB".to_string(),
                        hosts: "-".to_string(),
                    },
                ],
            })
        );
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
            Err("connections table has no `count` column".to_string())
        );
        assert_eq!(
            reduce(Ok(table)),
            Err("connections table has no `count` column".to_string())
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
    use super::tests::connections_table;
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

    /// A fresh window over an injected answer, grouped as `group_by` — both set
    /// before the first paint, like the map's findings window, and for the
    /// same reason: gpui's debug-bounds map only grows over a window's life, so
    /// only a window that never drew a row can say there is none. The socket
    /// is never driven: `ConnectionsView::new` fetches nothing (the open path
    /// does), so what the window draws is exactly what was injected.
    fn connections_window(
        cx: &mut TestAppContext,
        answer: Option<Result<Table, String>>,
        group_by: ConnectionsGroupBy,
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

    /// The grouping switch and refresh are the window's control surface: all
    /// five are drawn, and none is laid out past the window's edge where
    /// nothing is painted.
    #[gpui::test]
    fn the_four_group_buttons_and_refresh_are_drawn(cx: &mut TestAppContext) {
        let viewport = size(px(WIN_W), px(WIN_H));
        let (_window, mut vcx) = connections_window(cx, None, ConnectionsGroupBy::Host);
        for control in [
            "connections-group-host",
            "connections-group-ip",
            "connections-group-ip-port",
            "connections-group-process",
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
}
