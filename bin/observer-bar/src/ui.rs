//! The gpui panel view for the menu-bar app.
//!
//! [`Glance`] is a shared entity holding the most recent
//! [`StatusSnapshot`](observer_ipc::StatusSnapshot) fetched from `observerd` over
//! the local socket (plus the last fetch error and the socket path used to
//! refresh). The menu-bar refresh timer writes into it (see [`crate::menubar`]);
//! [`PanelView`] observes it and re-renders whenever it changes, so an open panel
//! updates live on the same ~3s cadence as the status-item dot.
//!
//! The bar is a pure socket client — it never opens the DuckDB store (the daemon
//! is the sole DB owner). When the daemon is down / the socket is absent,
//! [`read_fresh`] returns `Err` and the panel renders a graceful "observer
//! offline" state instead of crashing.
//!
//! ## Look — a Tailscale-style menu
//!
//! The panel is drawn as a clean, system-native dropdown (not bordered cards): a
//! rounded surface, a header row with the app name and a toggle switch, hairline
//! separators, and label→value list rows. It **adapts to the system appearance**
//! ([`Theme::for_appearance`] reads gpui's [`gpui::WindowAppearance`]) — a
//! near-white light theme or a dark-grey dark theme — rather than hardcoding one.
//!
//! The header **toggle switch** is bound to `snapshot.observing`: green when the
//! observer is collecting, grey when paused. Clicking it sends
//! `Control(SetObserving(!observing))` to the daemon (see [`send_set_observing`])
//! and refreshes. This is benign **self-control** — it pauses/resumes the
//! observer's OWN collection only; it never touches the proxy or the network and is
//! not gated by `acting.enabled`. While paused the header shows a muted "paused"
//! state and the daemon stays alive so the switch can turn collection back on.

use std::time::{SystemTime, UNIX_EPOCH};

use gpui::prelude::*;
use gpui::{
    App, Context, Entity, Rgba, SharedString, Subscription, Window, WindowAppearance, div, px, rgb,
};

use observer_ipc::{ControlCmd, ControlResult, IncidentSummary, Request, Response, StatusSnapshot};

use crate::status::{Health, health};

/// A light/dark token set for the panel. Adapts to the system appearance so the
/// menu reads as native in either mode (see [`Theme::for_appearance`]); the view
/// never hardcodes a single palette. Colors are 24-bit RGB hex.
///
/// Shared crate-wide (also used by the event-log window in [`crate::events`]) so
/// the panel and the window read as one consistent, appearance-aware surface.
#[derive(Clone, Copy)]
pub(crate) struct Theme {
    /// The popover surface.
    pub(crate) bg: u32,
    /// Primary ink (labels, app name).
    pub(crate) fg: u32,
    /// Secondary text and disabled/muted values.
    pub(crate) muted: u32,
    /// Hairline separator between sections.
    pub(crate) separator: u32,
    /// Semantic "good" (healthy verdicts).
    pub(crate) ok: u32,
    /// Semantic "bad" (failed/degraded verdicts, open incidents).
    pub(crate) bad: u32,
    /// Semantic "warn" (control action / offline banner).
    pub(crate) warn: u32,
    /// Accent for the neutral text action (Refresh) and the selected chip.
    pub(crate) accent: u32,
    /// The toggle track when observing (on) — green.
    pub(crate) track_on: u32,
    /// The toggle track when paused (off) — grey.
    pub(crate) track_off: u32,
    /// The toggle knob (also the ink on a filled/selected accent chip).
    pub(crate) knob: u32,
    /// Hover wash under a text action.
    pub(crate) hover: u32,
}

impl Theme {
    /// Pick the light or dark token set from the window's system appearance.
    /// Vibrant variants collapse onto their plain light/dark counterparts.
    pub(crate) fn for_appearance(appearance: WindowAppearance) -> Self {
        match appearance {
            WindowAppearance::Dark | WindowAppearance::VibrantDark => Self::dark(),
            WindowAppearance::Light | WindowAppearance::VibrantLight => Self::light(),
        }
    }

    /// Near-white surface, dark ink, hairline separators — the macOS light menu.
    fn light() -> Self {
        Self {
            bg: 0xf6f6f7,
            fg: 0x1d1d1f,
            muted: 0x86868b,
            separator: 0xe4e4e7,
            ok: 0x1f9d4d,
            bad: 0xd93a3a,
            warn: 0xb26a00,
            accent: 0x0a6cff,
            track_on: 0x34c759,
            track_off: 0xcfcfd4,
            knob: 0xffffff,
            hover: 0xececef,
        }
    }

    /// Dark-grey surface, light ink — the macOS dark menu.
    fn dark() -> Self {
        Self {
            bg: 0x1f1f22,
            fg: 0xe8e8ec,
            muted: 0x9a9aa2,
            separator: 0x38383d,
            ok: 0x4fce6e,
            bad: 0xff5c5c,
            warn: 0xe6b450,
            accent: 0x6ea8fe,
            track_on: 0x34c759,
            track_off: 0x4a4a50,
            knob: 0xffffff,
            hover: 0x2c2c31,
        }
    }
}

/// Fetch the live [`StatusSnapshot`] from `observerd` over the local socket.
///
/// The bar owns no DB — the daemon does — so every refresh is a blocking
/// [`observer_ipc::query`] round-trip. Re-querying each tick means the glance
/// recovers on its own once the daemon comes back, and fails gracefully when it
/// is not there: a missing socket, connection-refused (daemon down), or a
/// protocol error all map to `Err(String)`, which the panel surfaces as
/// "observer offline" and the status item as a grey dot — retried on the next
/// tick instead of crashing.
pub fn read_fresh(socket_path: &str) -> Result<StatusSnapshot, String> {
    match observer_ipc::query(socket_path, &Request::Status) {
        Ok(Response::Status(snap)) => Ok(snap),
        Ok(Response::Error(msg)) => Err(msg),
        Ok(_) => Err("unexpected response from observerd".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Ask `observerd` to turn its OWN collection on (`true`) or off (`false`) over
/// the local socket (`Control(SetObserving(on))`) and return its [`ControlResult`].
///
/// Like the other requests this maps to a `Control` command on the wire, but it is
/// benign **self-control**: it pauses/resumes the observer's own collection only —
/// it does NOT touch the proxy or the network, and the daemon does not gate it on
/// `acting.enabled`.
/// The daemon stays alive and the socket keeps serving while paused, so the switch
/// can turn collection back on. As with every request, a missing socket /
/// connection-refused (daemon down) or a protocol error maps to `Err(String)` so
/// the panel can surface it as a transient line instead of crashing — never a
/// panic.
pub fn send_set_observing(socket_path: &str, on: bool) -> Result<ControlResult, String> {
    match observer_ipc::query(socket_path, &Request::Control(ControlCmd::SetObserving(on))) {
        Ok(Response::Control(result)) => Ok(result),
        Ok(Response::Error(msg)) => Err(msg),
        Ok(_) => Err("unexpected response from observerd".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Shared, app-scoped model: the latest snapshot the UI renders.
pub struct Glance {
    pub snapshot: StatusSnapshot,
    /// The most recent fetch error, if the last refresh failed (daemon offline).
    pub error: Option<String>,
    /// Config socket path, so the panel's manual "Refresh" can re-query and the
    /// event-log window can open its subscription.
    pub socket_path: String,
    /// The most recent control-action outcome (e.g. the observing toggle outcome
    /// or `"acting disabled"`), surfaced as a transient line in the panel. `None`
    /// until the operator triggers a control action.
    pub control_msg: Option<String>,
    /// The live event-log window, if one is open. Stashed here (persists across
    /// panel re-opens) so a second "Events" click focuses the existing window
    /// instead of opening a duplicate subscription; a stale handle re-opens.
    pub events_window: Option<gpui::AnyWindowHandle>,
}

impl Glance {
    pub fn new(snapshot: StatusSnapshot, error: Option<String>, socket_path: String) -> Self {
        Self {
            snapshot,
            error,
            socket_path,
            control_msg: None,
            events_window: None,
        }
    }

    /// Re-query the daemon into this model. Used by the manual refresh button; the
    /// timer path in [`crate::menubar`] mutates the same fields directly.
    pub fn refresh(&mut self) {
        match read_fresh(&self.socket_path) {
            Ok(s) => {
                self.snapshot = s;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Flip the observer's collection on/off (the header toggle switch): send
    /// `Control(SetObserving(!observing))`, record the outcome line, then refresh
    /// so the switch reflects the daemon's real state. Benign self-control — never
    /// touches the proxy or the network. Never panics: a daemon-down / refused
    /// socket or a failed action becomes a readable `control_msg` line and the
    /// refresh surfaces the offline state.
    pub fn toggle_observing(&mut self) {
        let target = !self.snapshot.observing;
        self.control_msg = Some(match send_set_observing(&self.socket_path, target) {
            Ok(result) => {
                let tag = if result.ok { "ok" } else { "failed" };
                format!("{tag}: {}", result.message)
            }
            Err(e) => format!("failed: {e}"),
        });
        // Reflect the daemon's real observing state after the toggle.
        self.refresh();
    }
}

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
        let error = glance.error.clone();
        let control_msg = glance.control_msg.clone();
        let now_us = now_us();
        // Offline (daemon down / socket absent) ⇒ we cannot be observing, so the
        // switch reads OFF and is non-interactive regardless of the stale snapshot.
        let online = error.is_none();

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .rounded_lg()
            .overflow_hidden()
            .child(header_row(&snapshot, online, theme, cx))
            .child(separator(theme))
            .children(error.map(|e| offline_row(e, theme)))
            .child(status_rows(&snapshot, theme))
            .child(separator(theme))
            .child(incidents_section(&snapshot.incidents, now_us, theme))
            .child(separator(theme))
            .child(footer(&snapshot, now_us, control_msg, theme, cx))
    }
}

/// The header row: a health dot + the app name on the left, the observing toggle
/// switch on the right. When paused, a muted "paused" label sits after the name
/// and the dot is grey.
fn header_row(
    snapshot: &StatusSnapshot,
    online: bool,
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
                .child("observer"),
        );
    // Show "offline" when the daemon is unreachable, else "paused" when the
    // daemon is up but collection is off.
    let sub = if !online {
        Some("offline")
    } else if !snapshot.observing {
        Some("paused")
    } else {
        None
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
        // ON only if actually observing AND connected; interactive only online.
        .child(toggle_switch(
            snapshot.observing && online,
            online,
            theme,
            cx,
        ))
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
/// collection via [`Glance::toggle_observing`] and re-renders.
fn toggle_switch(
    on: bool,
    interactive: bool,
    theme: Theme,
    cx: &mut Context<PanelView>,
) -> impl IntoElement {
    let track_color = if on { theme.track_on } else { theme.track_off };

    let mut track = div()
        .id("observing-toggle")
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
                this.model.update(cx, |g, cx| {
                    g.toggle_observing();
                    cx.notify();
                });
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

/// The offline banner shown when the last fetch failed (daemon down / socket
/// absent): a warn-colored title + the error, rather than showing stale data as
/// if it were live.
fn offline_row(msg: String, theme: Theme) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_0p5()
        .px_3()
        .py_2()
        .child(
            div()
                .text_color(rgb(theme.warn))
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child("observer offline"),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child(SharedString::from(msg)),
        )
}

/// The label→value list: the latest link tick (gw, direct) and proxy tick (tun,
/// selector). Missing collectors render a muted "-". Values carry semantic color;
/// labels are muted.
fn status_rows(snapshot: &StatusSnapshot, theme: Theme) -> impl IntoElement {
    let (gw, gw_color, direct, direct_color) = match &snapshot.link {
        Some(l) => {
            let gw = l.gw.to_string();
            let direct = l.direct.to_string();
            let gw_color = verdict_color(&gw, theme);
            let direct_color = verdict_color(&direct, theme);
            (gw, gw_color, direct, direct_color)
        }
        None => (
            "-".to_string(),
            rgb(theme.muted),
            "-".to_string(),
            rgb(theme.muted),
        ),
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

    div()
        .flex()
        .flex_col()
        .px_3()
        .py_1()
        .child(row("gw", &gw, gw_color, theme))
        .child(row("direct", &direct, direct_color, theme))
        .child(row("tun", &tun, tun_color, theme))
        .child(row("selector", &sel, rgb(theme.fg), theme))
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
        base.children(incidents.iter().map(move |i| {
            let (state, color) = match i.closed_us {
                Some(_) => ("closed", theme.muted),
                None => ("open", theme.bad),
            };
            let value = format!("{state} \u{00b7} {}", age_str(i.opened_us, now_us));
            row(&i.trigger_id, &value, rgb(color), theme)
        }))
    }
}

/// The footer (pinned at the bottom of the panel): a muted freshness line (+ the
/// last control-action outcome, if any), and subtle text actions — "Events"
/// (opens the live event-log window), "Refresh", and "Quit".
fn footer(
    snapshot: &StatusSnapshot,
    now_us: i64,
    control_msg: Option<String>,
    theme: Theme,
    cx: &mut Context<PanelView>,
) -> impl IntoElement {
    let events = div()
        .id("events")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(theme.accent))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("Events")
        .on_click(cx.listener(|this, _, _window, cx| {
            let socket = this.model.read(cx).socket_path.clone();
            let model = this.model.clone();
            crate::events::open_or_focus(cx, &model, socket);
        }));

    let refresh = div()
        .id("refresh")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(theme.accent))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("Refresh")
        .on_click(cx.listener(|this, _, _window, cx| {
            this.model.update(cx, |g, cx| {
                g.refresh();
                cx.notify();
            });
        }));

    let quit = div()
        .id("quit")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(theme.bad))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("Quit")
        .on_click(|_, _window, cx: &mut App| cx.quit());

    let actions = div()
        .flex()
        .items_center()
        .justify_between()
        .child(events)
        .child(
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(refresh)
                .child(quit),
        );

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

    div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .py_2()
        .child(actions)
        .child(meta)
}

// ---- small element helpers -------------------------------------------------

/// A hairline separator between sections — a 1px full-width rule, no borders.
fn separator(theme: Theme) -> impl IntoElement {
    div().h(px(1.0)).w_full().bg(rgb(theme.separator))
}

/// One label→value list row: a muted label on the left, a colored value on the
/// right (the Tailscale-style clean list, not a bordered card).
///
/// `+ use<>` opts the returned element out of capturing the `&str` argument
/// lifetimes (Rust 2024's default): the row copies both into owned
/// [`SharedString`]s, so it borrows neither — letting callers build rows from
/// short-lived locals (e.g. a formatted incident line).
fn row(key: &str, value: &str, value_color: Rgba, theme: Theme) -> impl IntoElement + use<> {
    div()
        .flex()
        .items_center()
        .justify_between()
        .py_1()
        .child(
            div()
                .text_color(rgb(theme.muted))
                .child(SharedString::from(key.to_string())),
        )
        .child(
            div()
                .text_color(value_color)
                .child(SharedString::from(value.to_string())),
        )
}

/// Semantic color for a verdict string: `OK` → good, empty → muted, anything else
/// → bad.
fn verdict_color(verdict: &str, theme: Theme) -> Rgba {
    match verdict {
        "OK" => rgb(theme.ok),
        "" => rgb(theme.muted),
        _ => rgb(theme.bad),
    }
}

/// Current wall-clock time in microseconds since the Unix epoch.
pub fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// A short "12s ago" / "3m ago" string from a microsecond timestamp.
fn age_str(ts_us: i64, now_us: i64) -> String {
    if ts_us <= 0 {
        return "-".to_string();
    }
    let secs = (now_us - ts_us) / 1_000_000;
    if secs < 0 {
        return "just now".to_string();
    }
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
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

    #[test]
    fn age_str_buckets() {
        let now = 1_000_000_000i64;
        assert_eq!(age_str(0, now), "-");
        assert_eq!(age_str(now, now), "0s ago");
        assert_eq!(age_str(now - 5_000_000, now), "5s ago");
        assert_eq!(age_str(now - 120_000_000, now), "2m ago");
        assert_eq!(age_str(now + 5_000_000, now), "just now");
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

    /// Daemon down / socket absent must map to a graceful `Err`, never a panic —
    /// this is the "observer offline" path the panel renders.
    #[test]
    fn read_fresh_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let res = read_fresh(missing.to_str().unwrap());
        assert!(res.is_err(), "absent socket must yield an offline Err");
    }

    /// The observing self-control path degrades gracefully too: an absent socket
    /// (daemon down) yields an `Err`, never a panic — and nothing is executed
    /// locally (the bar only sends a request; the daemon owns the state).
    #[test]
    fn send_set_observing_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        assert!(
            send_set_observing(missing.to_str().unwrap(), false).is_err(),
            "absent socket must yield a control Err (turning off)"
        );
        assert!(
            send_set_observing(missing.to_str().unwrap(), true).is_err(),
            "absent socket must yield a control Err (turning on)"
        );
    }

    /// `Glance::toggle_observing` on a down daemon records a readable failure line
    /// instead of panicking, and its trailing refresh surfaces the offline state
    /// (the switch reflects the daemon's real, unreachable state — never a
    /// silently-flipped local bool).
    #[test]
    fn glance_toggle_observing_records_failure_when_daemon_down() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            None,
            missing.to_str().unwrap().to_string(),
        );
        // A fresh snapshot reads as observing; the daemon is down.
        assert!(glance.snapshot.observing);
        glance.toggle_observing();
        let msg = glance
            .control_msg
            .clone()
            .expect("toggle must record a message");
        assert!(
            msg.starts_with("failed:"),
            "daemon-down must be a failure: {msg}"
        );
        // The trailing refresh failed against the absent socket -> offline error,
        // and the (unreached) snapshot state is left as-is rather than flipped.
        assert!(glance.error.is_some(), "refresh must surface offline");
        assert!(glance.snapshot.observing, "state not flipped locally");
    }
}
