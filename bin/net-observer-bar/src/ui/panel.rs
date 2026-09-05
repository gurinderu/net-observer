//! The panel window's layout: header, body, sparklines, status rows, footer.

use std::collections::VecDeque;

use gpui::prelude::*;
use gpui::{
    AsyncApp, Context, Entity, Rgba, SharedString, Subscription, Window, div, px, rgb, rgba,
};

use net_observer_ipc::{IncidentSummary, StatusSnapshot};

use crate::status::{Health, health};

use super::control::{GlanceError, toggle_round_trip};
use super::model::{Glance, HistoryPoint};
use super::parts::{age_str, now_us, row, separator};
use super::theme::{MENU_CHEVRON, MENU_ROW_H, MENU_ROW_PX, MENU_ROW_RADIUS, MENU_ROW_TEXT, Theme};

/// The root view of the panel window. Holds a handle to the shared [`Glance`]
/// and re-renders whenever it changes.
pub struct PanelView {
    model: Entity<Glance>,
    _observe: Subscription,
}

impl PanelView {
    pub fn new(model: Entity<Glance>, cx: &mut Context<Self>) -> Self {
        // Re-render this view whenever the shared model is notified (timer tick
        // or manual refresh).
        let observe = cx.observe(&model, |_, _, cx| cx.notify());
        Self {
            model,
            _observe: observe,
        }
    }
}

impl Render for PanelView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Adapt to the system appearance instead of hardcoding a palette.
        let theme = Theme::for_appearance(window.appearance());

        let glance = self.model.read(cx);
        let snapshot = glance.snapshot.clone();
        let control_msg = glance.control_msg.clone();
        let history = glance.history.clone();
        let now_us = now_us();
        // Offline (daemon down / socket absent) ⇒ we cannot be observing, so the
        // switch reads OFF and is non-interactive regardless of the stale snapshot.
        // A protocol failure is NOT offline: the daemon answered, so the toggle
        // stays live and the message goes to the footer instead.
        let online = glance.online();
        // Read from the shared model rather than kept as view state: the flyout
        // window clears `menu_window` when it dismisses itself, so the parent
        // row's highlight goes out with the menu instead of outliving it.
        let menu_open = glance.menu_window.is_some();
        let (offline_msg, protocol_msg) = match &glance.error {
            Some(GlanceError::Unreachable(m)) => (Some(m.clone()), None),
            Some(GlanceError::Protocol(m)) => (None, Some(m.clone())),
            None => (None, None),
        };

        div()
            .flex()
            .flex_col()
            .size_full()
            // A native menu is rounded and rimmed, not a square slab. Both need
            // the window to be non-opaque: with an opaque window the corners are
            // filled by the window server and the rounding is invisible.
            .rounded(px(10.0))
            .border_1()
            .border_color(rgba(theme.edge))
            .bg(rgba(theme.surface))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .rounded_lg()
            .overflow_hidden()
            .child(header_row(&snapshot, online, offline_msg, theme, cx))
            .child(separator(theme))
            .child(status_body(&snapshot, &history, now_us, theme))
            .child(separator(theme))
            .child(div().flex_shrink_0().child(footer(
                &snapshot,
                now_us,
                control_msg,
                protocol_msg,
                menu_open,
                theme,
                cx,
            )))
    }
}

/// The middle of the panel: the status glance — trend sparklines over the current
/// verdict rows, then recent incidents. The live network map is no longer a tab
/// here; it opens as its own window from the footer "Map" control (see
/// [`crate::map`]).
fn status_body(
    snapshot: &StatusSnapshot,
    history: &VecDeque<HistoryPoint>,
    now_us: i64,
    theme: Theme,
) -> impl IntoElement {
    div()
        .id("panel-body")
        .flex()
        .flex_col()
        // The panel's height is fixed, so a long body used to push the footer —
        // and with it the only way to reach any action — past the bottom edge.
        // The body takes the leftover room and scrolls inside it instead.
        .flex_1()
        .overflow_y_scroll()
        // Trend before state: the gateway fails as a ramp, so the slope is
        // read first and the current verdicts underneath it.
        .child(sparklines_section(history, theme))
        .child(separator(theme))
        .child(status_rows(snapshot, now_us, theme))
        .child(separator(theme))
        .child(incidents_section(&snapshot.incidents, now_us, theme))
}

/// The header row: a health dot + the app name on the left, the observing toggle
/// switch on the right. When paused, a muted "paused" label sits after the name
/// and the dot is grey.
///
/// `online` is [`Glance::online`] — false only when the daemon is unreachable, in
/// which case `offline` carries the reason for the warning glyph's tooltip. A
/// protocol failure is not offline (see [`GlanceError`]): the header stays live and
/// the footer states it.
fn header_row(
    snapshot: &StatusSnapshot,
    online: bool,
    offline: Option<String>,
    theme: Theme,
    cx: &mut Context<PanelView>,
) -> impl IntoElement {
    let (dot, dot_color) = header_dot(snapshot, online, theme);

    let mut left = div()
        .flex()
        .items_center()
        .gap_2()
        .child(div().text_color(dot_color).text_size(px(10.0)).child(dot))
        .child(
            div()
                .text_size(px(15.0))
                .font_weight(gpui::FontWeight::BOLD)
                .child("net-observer"),
        );
    // Only a muted "paused" label when the daemon is up but collection is off.
    // Offline is conveyed by a warning glyph next to the (disabled) toggle — no text.
    // Paused and quiet are DIFFERENT states and must never be rendered as one: a
    // paused daemon collects nothing, a quiet daemon is still collecting and still
    // recording — it just sends nothing at the gateway. Paused wins the label when
    // both hold, because it is the stronger claim about what is being recorded.
    let sub = match (online, snapshot.observing, snapshot.quiet) {
        (true, false, _) => Some("paused"),
        (true, true, true) => Some("quiet"),
        _ => None,
    };
    if let Some(label) = sub {
        left = left.child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(label),
        );
    }

    div()
        .flex()
        .items_center()
        .px_3()
        .py_2p5()
        .child(left)
        .child(div().flex_1())
        // Offline: a warning glyph with a tooltip, next to the (disabled) toggle.
        .children(offline.map(|reason| warn_offline(reason, theme)))
        // ON only if actually observing AND connected; interactive only online.
        .child(toggle_switch(
            snapshot.observing && online,
            online,
            theme,
            cx,
        ))
}

/// A warning glyph shown in the header when the daemon is unreachable. Hovering it
/// explains why the observing toggle is disabled — instead of a loud offline
/// banner. Replaces the old yellow offline row.
///
/// `reason` is the real transport error (the panel deleted the row that used to
/// print it), so the tooltip says *why* nothing answered rather than asserting a
/// canned diagnosis.
fn warn_offline(reason: String, theme: Theme) -> impl IntoElement {
    let tip = SharedString::from(format!(
        "net-observer offline — can't toggle collection ({reason})"
    ));
    div()
        .id("offline-warn")
        // Test handle only: lets a headless test say the hint is drawn — and,
        // in a window opened online, that it is not.
        .debug_selector(|| "offline-warn".into())
        .text_size(px(13.0))
        .text_color(rgb(theme.warn))
        .child("\u{26A0}") // ⚠
        .tooltip(move |_window, cx| {
            let tip = tip.clone();
            cx.new(|_| WarnTooltip(tip)).into()
        })
}

/// A minimal tooltip view: a small dark chip with a message. gpui 0.2.2 has no
/// built-in tooltip element, so `.tooltip(..)` builds this `AnyView`.
struct WarnTooltip(SharedString);

impl Render for WarnTooltip {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .bg(rgb(0x1f1f22))
            .text_color(rgb(0xe8e8ec))
            .text_size(px(12.0))
            .px_2()
            .py_1()
            .rounded_md()
            .child(self.0.clone())
    }
}

/// The header health dot glyph + color. When paused, a grey dot regardless of the
/// underlying health (collection is off, so there is nothing live to judge);
/// otherwise it follows the shared [`health`] classifier so the panel dot and the
/// menu-bar dot can never disagree.
fn header_dot(snapshot: &StatusSnapshot, online: bool, theme: Theme) -> (&'static str, Rgba) {
    if !online || !snapshot.observing {
        // Offline or paused: nothing live to judge — a muted dot.
        return ("\u{25CF}", rgb(theme.muted));
    }
    let color = match health(snapshot) {
        Health::NoData => rgb(theme.muted),
        Health::Ok => rgb(theme.ok),
        Health::Bad => rgb(theme.bad),
    };
    ("\u{25CF}", color)
}

/// A Tailscale-style toggle switch bound to `observing`: a pill track
/// (`rounded_full`) with a circular knob that sits left (off) or right (on). Green
/// track when observing, grey when paused. Clicking it flips the observer's
/// collection via [`toggle_round_trip`] on the background executor and re-renders
/// when the result lands (see [`Glance::apply_toggle_result`]).
fn toggle_switch(
    on: bool,
    interactive: bool,
    theme: Theme,
    cx: &mut Context<PanelView>,
) -> impl IntoElement {
    let track_color = if on { theme.track_on } else { theme.track_off };

    let mut track = div()
        .id("observing-toggle")
        // Test handle only: a no-op unless gpui's `test-support` is on
        // (dev-dependency), where it makes this element's laid-out bounds
        // readable by the headless UI tests (see `headless_ui.rs`).
        .debug_selector(|| "observing-toggle".into())
        .flex()
        .items_center()
        .w(px(40.0))
        .h(px(24.0))
        .p_0p5()
        .rounded_full()
        .bg(rgb(track_color))
        .child(div().size(px(20.0)).rounded_full().bg(rgb(theme.knob)));

    // Only clickable while the daemon is reachable — you cannot toggle collection
    // on a daemon that is not there. Offline renders OFF and inert.
    if interactive {
        track = track
            .cursor_pointer()
            .on_click(cx.listener(|this, _, _window, cx| {
                let model = this.model.downgrade();
                let socket = this.model.read(cx).socket_path.clone();
                // The three socket round-trips run on the background executor: a
                // daemon that accepts the connection but never answers must not
                // park the bar (status item, panel, event window). The result is
                // written back on the foreground, through a weak handle so a
                // shut-down app just drops it.
                cx.spawn(async move |_view, acx: &mut AsyncApp| {
                    let (control, fresh) = acx
                        .background_spawn(async move { toggle_round_trip(&socket) })
                        .await;
                    model
                        .update(acx, |g, cx| {
                            g.apply_toggle_result(control, fresh);
                            cx.notify();
                        })
                        .ok();
                })
                .detach();
            }));
    }

    // Knob left when off, right when on.
    track = if on {
        track.justify_end()
    } else {
        track.justify_start()
    };
    track
}

/// The label→value list: the latest link tick (gw, direct) and proxy tick (tun,
/// selector), each pair followed by a muted age row for the collector that
/// produced it. Missing collectors render a muted "-". Values carry semantic
/// color; labels are muted.
///
/// The per-collector age rows matter because the collectors are independent: their
/// intervals are separately configurable and one stalling while the others keep
/// ticking is an expected state (the isolation rule). The footer's single
/// freshness line is a `max` over both, so on its own it would date a stalled
/// collector's stale verdicts by its neighbour's tick.
fn status_rows(snapshot: &StatusSnapshot, now_us: i64, theme: Theme) -> impl IntoElement {
    let (gw, gw_color, direct, direct_color) = match &snapshot.link {
        Some(l) => (
            l.gw.to_string(),
            gw_verdict_color(l.gw, theme),
            l.direct.to_string(),
            tcp_verdict_color(l.direct, theme),
        ),
        None => (
            "-".to_string(),
            rgb(theme.muted),
            "-".to_string(),
            rgb(theme.muted),
        ),
    };
    let link_age = match &snapshot.link {
        Some(l) => age_str(l.ts_us, now_us),
        None => "-".to_string(),
    };

    let (tun, tun_color, sel) = match &snapshot.proxy {
        Some(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let tun_color = match p.tun_code {
                Some(204) => rgb(theme.ok),
                Some(_) => rgb(theme.bad),
                None => rgb(theme.muted),
            };
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
            (tun, tun_color, sel)
        }
        None => ("-".to_string(), rgb(theme.muted), "-".to_string()),
    };
    let proxy_age = match &snapshot.proxy {
        Some(p) => age_str(p.ts_us, now_us),
        None => "-".to_string(),
    };

    div()
        .flex()
        .flex_col()
        .px_3()
        .py_1()
        .child(row("gw", gw, gw_color, theme))
        .child(row("direct", direct, direct_color, theme))
        .child(row("link", link_age, rgb(theme.muted), theme))
        .child(row("tun", tun, tun_color, theme))
        .child(row("selector", sel, rgb(theme.fg), theme))
        .child(row("proxy", proxy_age, rgb(theme.muted), theme))
}

/// The incidents section: a compact list of `trigger_id → state · age` rows, or a
/// single muted "no recent incidents" line when there are none.
fn incidents_section(incidents: &[IncidentSummary], now_us: i64, theme: Theme) -> impl IntoElement {
    let base = div().flex().flex_col().px_3().py_1();
    if incidents.is_empty() {
        base.child(
            div()
                .py_1()
                .text_color(rgb(theme.muted))
                .child("no recent incidents"),
        )
    } else {
        // The glance is a glance: a long run of incidents belongs in the events
        // window, not in a panel whose height is fixed. What does not fit is
        // counted rather than dropped, so the tail is never silently absent.
        let shown = incidents.len().min(INCIDENTS_IN_GLANCE);
        let hidden = incidents.len() - shown;
        let listed = base.children(incidents.iter().take(shown).map(move |i| {
            let (state, color) = match i.closed_us {
                Some(_) => ("closed", theme.muted),
                None => ("open", theme.bad),
            };
            let value = format!("{state} \u{00b7} {}", age_str(i.opened_us, now_us));
            row(i.trigger_id.clone(), value, rgb(color), theme)
        }));
        if hidden == 0 {
            listed
        } else {
            listed.child(
                div()
                    .py_1()
                    .text_size(px(11.0))
                    .text_color(rgb(theme.muted))
                    .child(format!("+{hidden} older \u{2014} see Events")),
            )
        }
    }
}

/// How many incidents the glance itself lists before deferring to the events
/// window. The panel is a fixed height; beyond this the rest is counted.
const INCIDENTS_IN_GLANCE: usize = 5;

/// The footer (pinned at the bottom of the panel): a muted freshness line (+ the
/// last control-action outcome and any protocol error, if present), and subtle
/// text actions — "Events" (opens the live event-log window), "Refresh", and
/// "Quit".
///
/// `protocol_msg` is a [`GlanceError::Protocol`] message: the daemon answered, so
/// the header stays online and this warn-colored line is where the failure is
/// stated — otherwise it would be visible nowhere in the panel.
fn footer(
    snapshot: &StatusSnapshot,
    now_us: i64,
    control_msg: Option<String>,
    protocol_msg: Option<String>,
    menu_open: bool,
    theme: Theme,
    cx: &mut Context<PanelView>,
) -> impl IntoElement {
    // The panel is a fixed 320 logical pixels wide and the controls outgrew one
    // row: laid out in a single line the last of them fall outside the panel and
    // simply do not appear, and a control that cannot be seen is a control that
    // does not exist. They live in the flyout menu window ([`crate::menu`]) now —
    // this trigger stays one row tall however many actions there are.
    //
    // It is drawn as a full-width menu row rather than a chip, on the metrics
    // every row of the flyout uses: a native submenu opens from a row of its
    // parent menu, highlighted edge to edge, with a chevron saying which way the
    // submenu comes out. While the menu is open the row keeps that highlight, so
    // where the flyout came from stays visible.
    let trigger_ink = if menu_open { theme.knob } else { theme.accent };
    let mut trigger = div()
        .id("menu-trigger")
        // Test handle only; see `observing-toggle` above.
        .debug_selector(|| "menu-trigger".into())
        .flex()
        .items_center()
        .justify_between()
        .w_full()
        .h(px(MENU_ROW_H))
        .px(px(MENU_ROW_PX))
        .rounded(px(MENU_ROW_RADIUS))
        .text_size(px(MENU_ROW_TEXT))
        .text_color(rgb(trigger_ink))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.accent)).text_color(rgb(theme.knob)))
        .child("Menu")
        .child(MENU_CHEVRON)
        .on_click(cx.listener(|this, _, window, cx| {
            // The menu is its own window, so it needs where this one is and how
            // much display there is to fly out into. Without a display there is
            // no room to compute against: falling back to the panel's own bounds
            // makes "no space on the right" true by construction and clamps the
            // menu onto the panel's own coordinates, i.e. silently on top of it.
            // So the menu does not open, and says why.
            let panel = window.bounds();
            let Some(display) = window.display(cx) else {
                eprintln!(
                    "net-observer-bar: not opening the actions menu — the panel reports no display, so there is no room to place it against"
                );
                return;
            };
            let screen = display.bounds().map(|p| px(f32::from(p)));
            let model = this.model.clone();
            crate::menu::open_or_focus(cx, &model, panel, screen);
        }));
    if menu_open {
        trigger = trigger.bg(rgb(theme.accent));
    }

    let mut meta = div().flex().flex_col().gap_0p5().child(
        div()
            .text_size(px(11.0))
            .text_color(rgb(theme.muted))
            .child(freshness_line(snapshot, now_us)),
    );
    if let Some(msg) = control_msg {
        meta = meta.child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(SharedString::from(msg)),
        );
    }
    if let Some(msg) = protocol_msg {
        meta = meta.child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child(SharedString::from(format!("protocol error: {msg}"))),
        );
    }

    div()
        .flex()
        .flex_col()
        .gap_1()
        .px_2()
        .py_2()
        .child(trigger)
        .child(meta)
}

// ---- sparklines ------------------------------------------------------------

/// Gateway RTT, in ms, above which the panel calls the gateway slow. The
/// coworking gateway's failure is a ramp, not a drop: crossing this line while
/// still answering is the early warning a single current number hides.
const RTT_THRESHOLD_MS: f64 = 300.0;

/// Host 1-minute load above which the panel calls the host starved — the same
/// number the daemon's `Starvation` condition uses (`STARVATION_LOAD`,
/// `bin/net-observerd/src/main.rs`), so the line the operator watches and the
/// line the trigger fires on are one line.
///
/// 16 belongs to a different daemon: the shell LaunchDaemon this project
/// replaces gates its watchdog at `load1 < 16`. Reading that number off the
/// oracle and drawing it here would put the panel a whole failure-band away from
/// the trigger it is supposed to preview.
const LOAD_THRESHOLD: f64 = 10.0;

/// Height of a sparkline's plot area, in gpui logical pixels.
const SPARK_H: f32 = 28.0;
/// Width of one column, and of the gap after it. One point is 1px of ink plus 1px
/// of air, so [`HISTORY_LEN`] columns occupy 240pt and fit the 320pt panel's
/// content width without downsampling.
const SPARK_COL_W: f32 = 1.0;
const SPARK_GAP: f32 = 1.0;

/// The scale a sparkline is drawn against: the largest of the observed values and
/// the threshold, so the threshold rule is always on-screen and no bar ever
/// overflows the plot area. Pure, and tested.
fn spark_scale(values: &[Option<f64>], threshold: f64) -> f64 {
    values
        .iter()
        .flatten()
        .copied()
        .filter(|v| v.is_finite() && *v > 0.0)
        .fold(threshold, f64::max)
}

/// The two stacked sparklines — gateway RTT over host load — drawn from the
/// panel's own bounded history (see [`HISTORY_LEN`]: this is the bar's window, not
/// the daemon's record).
fn sparklines_section(history: &VecDeque<HistoryPoint>, theme: Theme) -> impl IntoElement {
    let rtt: Vec<Option<f64>> = history.iter().map(|p| p.gw_rtt_ms).collect();
    let load: Vec<Option<f64>> = history.iter().map(|p| p.load1).collect();
    div()
        .flex()
        .flex_col()
        .px_3()
        .py_1()
        .gap_1()
        .child(sparkline("gw rtt", "ms", &rtt, RTT_THRESHOLD_MS, theme))
        .child(sparkline("load", "", &load, LOAD_THRESHOLD, theme))
}

/// One labelled sparkline: a caption row (name, latest value) over a plot area.
///
/// gpui 0.2.2 has no chart primitive, so the plot is literally a row of thin
/// `div`s whose heights encode the values, newest on the right, with a 1px
/// `separator` hairline sitting at the threshold — subordinate to the data, which
/// is the only thing carrying colour.
///
/// A `None` entry renders as an **empty column**, not a zero-height bar on the
/// baseline: a tick that measured nothing must read as a gap in the line.
fn sparkline(
    label: &'static str,
    unit: &'static str,
    values: &[Option<f64>],
    threshold: f64,
    theme: Theme,
) -> impl IntoElement {
    let scale = spark_scale(values, threshold);
    let latest = values.iter().rev().flatten().next().copied();
    let (latest_text, latest_color) = match latest {
        Some(v) => (
            format!("{v:.1}{}{unit}", if unit.is_empty() { "" } else { " " }),
            spark_color(v, threshold, theme),
        ),
        // Nothing measured in the whole window — say so, do not show a stale value.
        None => ("no data".to_string(), rgb(theme.muted)),
    };

    // The threshold hairline, positioned by the same scale as the bars.
    let rule_bottom = px((threshold / scale) as f32 * SPARK_H);

    let bars = values.iter().map(move |v| {
        let col = div()
            .w(px(SPARK_COL_W))
            .h_full()
            .flex()
            .flex_col()
            .justify_end();
        match v {
            // A measured value: a bar at least 1px tall, so a real near-zero
            // reading is still visible as ink rather than as a gap.
            Some(value) => col.child(
                div()
                    .w_full()
                    .h(px((((value / scale) as f32) * SPARK_H).clamp(1.0, SPARK_H)))
                    .bg(spark_color(*value, threshold, theme)),
            ),
            // A gap: the column stays empty.
            None => col,
        }
    });

    div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(rgb(theme.muted))
                        .child(label),
                )
                .child(
                    div()
                        .text_size(px(11.0))
                        .text_color(latest_color)
                        .child(latest_text),
                ),
        )
        .child(
            div()
                .relative()
                .h(px(SPARK_H))
                .w_full()
                .child(
                    div()
                        .absolute()
                        .left_0()
                        .bottom(rule_bottom)
                        .w_full()
                        .h(px(1.0))
                        .bg(rgb(theme.separator)),
                )
                .child(
                    div()
                        .flex()
                        .items_end()
                        .h_full()
                        .gap(px(SPARK_GAP))
                        .children(bars),
                ),
        )
}

/// Colour for one plotted value, using the panel's existing health tokens: over
/// the threshold is `bad`, the approach to it (from 60% up) is `warn`, below that
/// is `ok`. No new palette — the sparkline agrees with the rows beneath it.
fn spark_color(value: f64, threshold: f64, theme: Theme) -> Rgba {
    if value >= threshold {
        rgb(theme.bad)
    } else if value >= threshold * 0.6 {
        rgb(theme.warn)
    } else {
        rgb(theme.ok)
    }
}

/// Semantic color for a [`types::TcpVerdict`]. Exhaustive over the typed verdict —
/// no wildcard arm — so a probe that could not run (`SKIP`) reads as muted rather
/// than as a failure, and a new token added to the enum fails to compile *here*
/// instead of silently painting itself red.
fn tcp_verdict_color(v: types::TcpVerdict, theme: Theme) -> Rgba {
    match v {
        types::TcpVerdict::Ok => rgb(theme.ok),
        types::TcpVerdict::Skip => rgb(theme.muted),
        types::TcpVerdict::Fail => rgb(theme.bad),
    }
}

/// Semantic color for a [`types::GwVerdict`]. Exhaustive for the same reason as
/// [`tcp_verdict_color`]: a probe that did not run (`SKIP`, quiet mode) reads as
/// muted rather than as a failure.
fn gw_verdict_color(v: types::GwVerdict, theme: Theme) -> Rgba {
    match v {
        types::GwVerdict::Ok => rgb(theme.ok),
        types::GwVerdict::Skip => rgb(theme.muted),
        types::GwVerdict::Fail | types::GwVerdict::NoGw => rgb(theme.bad),
    }
}

fn freshness_line(snapshot: &StatusSnapshot, now_us: i64) -> String {
    let newest = [
        snapshot.link.as_ref().map(|l| l.ts_us),
        snapshot.proxy.as_ref().map(|p| p.ts_us),
    ]
    .into_iter()
    .flatten()
    .max();
    match newest {
        Some(ts) => format!("updated {}", age_str(ts, now_us)),
        None => "no data".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plot scale never falls below the threshold (so the rule is always
    /// visible) and never below the data (so no bar overflows the plot area).
    #[test]
    fn spark_scale_covers_threshold_and_data() {
        assert_eq!(spark_scale(&[], 300.0), 300.0);
        assert_eq!(spark_scale(&[Some(10.0), None], 300.0), 300.0);
        assert_eq!(spark_scale(&[Some(10.0), Some(900.0)], 300.0), 900.0);
        // Gaps and non-finite readings must not poison the scale.
        assert_eq!(spark_scale(&[None, Some(f64::NAN)], 16.0), 16.0);
    }

    #[test]
    fn freshness_prefers_newest_tick() {
        let mut s = StatusSnapshot::default();
        assert_eq!(freshness_line(&s, 10_000_000), "no data");
        s.link = Some(types::LinkSample {
            ts_us: 1_000_000,
            gw: types::GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: types::TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        });
        s.proxy = Some(types::ProxySample {
            ts_us: 4_000_000,
            server_ip: "1.2.3.4".into(),
            tcp: types::TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
        });
        // newest is the proxy tick at 4s -> 6s ago at now=10s.
        assert_eq!(freshness_line(&s, 10_000_000), "updated 6s ago");
    }

    /// "SKIP, never silence": a probe that could not run is not a failure, so it
    /// must not be painted with the failure color. Both mappings are exhaustive
    /// over the typed verdicts, so a new token cannot quietly land in "bad".
    #[test]
    fn skip_verdict_is_muted_not_bad() {
        for theme in [Theme::light(), Theme::dark()] {
            assert_eq!(
                tcp_verdict_color(types::TcpVerdict::Skip, theme),
                rgb(theme.muted),
                "SKIP is 'could not run', not 'failed'"
            );
            assert_ne!(
                tcp_verdict_color(types::TcpVerdict::Skip, theme),
                rgb(theme.bad)
            );
            assert_eq!(
                tcp_verdict_color(types::TcpVerdict::Ok, theme),
                rgb(theme.ok)
            );
            assert_eq!(
                tcp_verdict_color(types::TcpVerdict::Fail, theme),
                rgb(theme.bad)
            );
            assert_eq!(gw_verdict_color(types::GwVerdict::Ok, theme), rgb(theme.ok));
            assert_eq!(
                gw_verdict_color(types::GwVerdict::NoGw, theme),
                rgb(theme.bad)
            );
            assert_eq!(
                gw_verdict_color(types::GwVerdict::Fail, theme),
                rgb(theme.bad)
            );
        }
    }
}
