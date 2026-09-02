//! The gpui panel view for the menu-bar app.
//!
//! [`Glance`] is a shared entity holding the most recent
//! [`StatusSnapshot`](net_observer_ipc::StatusSnapshot) fetched from `net-observerd` over
//! the local socket (plus the last fetch error and the socket path used to
//! refresh). The menu-bar refresh timer writes into it (see [`crate::menubar`]);
//! [`PanelView`] observes it and re-renders whenever it changes, so an open panel
//! updates live on the same ~3s cadence as the status-item dot.
//!
//! The bar is a pure socket client — it never opens the DuckDB store (the daemon
//! is the sole DB owner). When the daemon is down / the socket is absent,
//! [`read_fresh`] returns [`GlanceError::Unreachable`] and the panel renders a
//! graceful "net-observer offline" state instead of crashing. A daemon that *does*
//! answer but whose answer we cannot use ([`GlanceError::Protocol`]) is a
//! different state: the panel stays online and shows the message rather than
//! claiming the daemon is not there.
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
//! observer is collecting, grey when paused. Clicking it runs [`toggle_round_trip`]
//! — read the live state, send `Control(SetObserving(!live))` (see
//! [`send_set_observing`]), read it back — **on a background thread**, then applies
//! the outcome with [`Glance::apply_toggle_result`]. The socket round-trips never
//! run on the gpui main thread, so a daemon that accepts but does not answer cannot
//! park the bar. This is benign **self-control** — it pauses/resumes the observer's
//! OWN collection only; it never touches the proxy or the network and is not gated
//! by `acting.enabled`. While paused the header shows a muted "paused" state and the
//! daemon stays alive so the switch can turn collection back on.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use gpui::prelude::*;
use gpui::{
    App, AsyncApp, Context, Entity, Rgba, SharedString, Subscription, Window, WindowAppearance,
    div, px, rgb, rgba,
};

use net_observer_ipc::{
    ControlCmd, ControlResult, IncidentSummary, Request, Response, StatusSnapshot,
};

use crate::status::{Health, health};

/// A light/dark token set for the panel. Adapts to the system appearance so the
/// menu reads as native in either mode (see [`Theme::for_appearance`]); the view
/// never hardcodes a single palette. Colors are 24-bit RGB hex.
///
/// Shared crate-wide (also used by the event-log window in [`crate::events`]) so
/// the panel and the window read as one consistent, appearance-aware surface.
#[derive(Clone, Copy)]
pub(crate) struct Theme {
    /// Opaque surface, for the windows that are ordinary windows — the event
    /// log. Never the popover: see `surface`.
    pub(crate) bg: u32,
    /// The popover surface, **`0xRRGGBBAA`**. Deliberately translucent: the
    /// panel window is opened `Blurred`, which puts an `NSVisualEffectView`
    /// behind it, and a fully opaque fill would hide the very material that
    /// makes a menu-bar popover look like part of the menu bar. This is also
    /// why the base colour is lighter than instinct suggests — Apple's dark
    /// menu reads mid-grey, not near-black, because the desktop shows through
    /// it. Darkening the fill walks away from the target instead of toward it.
    pub(crate) surface: u32,
    /// Primary ink (labels, app name).
    pub(crate) fg: u32,
    /// Secondary text and disabled/muted values.
    pub(crate) muted: u32,
    /// Hairline separator between sections.
    pub(crate) separator: u32,
    /// The popover's outer edge, `0xRRGGBBAA`. A native menu is not a flat
    /// rectangle: it carries a faint light rim that lifts it off whatever is
    /// behind. Without it the panel reads as a hole rather than a surface.
    pub(crate) edge: u32,
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
            surface: 0xf2f2f4f2,
            edge: 0x00000026,
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

    /// Near-black surface, light ink — the macOS dark menu. The surface is
    /// deliberately darker than the app chrome around it: a menu-bar popover
    /// reads as part of the menu bar, not as a window, and a mid-grey panel
    /// floats away from it. `separator` and `hover` are pinned to this surface
    /// rather than chosen independently — lighten the background without them
    /// and the hairlines turn into visible bars.
    fn dark() -> Self {
        Self {
            bg: 0x1f1f22,
            // Landed by bisection against a native NSMenu shown side by side:
            // #0d0d0f read darker than the system menu, #1e1e20 read lighter,
            // so the surface sits between them. Do not "correct" this by eye
            // against the app chrome — the reference is a real menu on the same
            // display, and both directions were tried and rejected.
            surface: 0x161618f2,
            edge: 0xffffff1f,
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

/// Why a fetch failed — the distinction the panel must not blur.
///
/// "Daemon not reachable" is an assertion about the world, so it may only be made
/// when nothing answered. A daemon that accepts the connection and replies, but
/// whose reply we cannot use (an `Error` frame, an unexpected variant, or a decode
/// failure — e.g. a new bar against an older daemon), is *up*: reporting it as
/// offline would be a false statement, and the real message would be nowhere to be
/// seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlanceError {
    /// Nothing answered: the socket is absent, the connection was refused, or the
    /// connect/round-trip timed out. The daemon is down — the panel goes offline.
    Unreachable(String),
    /// The daemon answered but the exchange failed. It is reachable, so the panel
    /// stays online and surfaces the message.
    Protocol(String),
}

impl GlanceError {
    /// The underlying message, without the reachable/unreachable framing.
    pub fn message(&self) -> &str {
        match self {
            Self::Unreachable(m) | Self::Protocol(m) => m,
        }
    }
}

impl std::fmt::Display for GlanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Classify a transport failure from [`net_observer_ipc::query`]. Only the kinds that
/// mean "nobody was there" are [`GlanceError::Unreachable`]; everything else
/// (`InvalidData` from a frame we cannot decode, a broken pipe mid-exchange, …)
/// happened *with* a daemon on the other end.
fn classify_io(e: std::io::Error) -> GlanceError {
    match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::TimedOut => GlanceError::Unreachable(e.to_string()),
        _ => GlanceError::Protocol(e.to_string()),
    }
}

/// Fetch the live [`StatusSnapshot`] from `net-observerd` over the local socket.
///
/// The bar owns no DB — the daemon does — so every refresh is a blocking
/// [`net_observer_ipc::query`] round-trip. Re-querying each tick means the glance
/// recovers on its own once the daemon comes back, and fails gracefully when it
/// is not there: a missing socket, connection-refused or a timeout map to
/// [`GlanceError::Unreachable`], which the panel surfaces as "net-observer offline"
/// and the status item as a grey dot. An `Error` frame, an unexpected variant or a
/// decode failure map to [`GlanceError::Protocol`] — the daemon is up, so the
/// panel stays online and shows the message. Either way it is retried on the next
/// tick instead of crashing.
pub fn read_fresh(socket_path: &str) -> Result<StatusSnapshot, GlanceError> {
    match net_observer_ipc::query(socket_path, &Request::Status) {
        Ok(Response::Status(snap)) => Ok(snap),
        Ok(Response::Error(msg)) => Err(GlanceError::Protocol(msg)),
        Ok(_) => Err(GlanceError::Protocol(
            "unexpected response from net-observerd".to_string(),
        )),
        Err(e) => Err(classify_io(e)),
    }
}

/// Ask `net-observerd` to turn its OWN collection on (`true`) or off (`false`) over
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
/// Ask `net-observerd` to enter (`true`) or leave (`false`) **quiet** mode over
/// the local socket (`Control(SetQuiet(on))`).
///
/// Quiet is not a pause: the daemon keeps collecting and keeps emitting one link
/// sample per tick — it just addresses no packet at the gateway, so the gateway
/// verdict reads `SKIP`. Benign **self-control**, not gated by `acting.enabled`.
/// Transport failures map to `Err(String)` for the panel to surface, never a panic.
pub fn send_set_quiet(socket_path: &str, on: bool) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::SetQuiet(on))
}

/// Ask `net-observerd` to copy its pcap ring out NOW
/// (`Control(FreezePcap)`) — the same passive artifact the `gw-change` trigger
/// produces, on operator demand. A daemon with no ring running answers
/// `ok: false` with a reason, which the panel shows like any other control
/// outcome; a daemon that is not there maps to `Err(String)`.
pub fn send_freeze_pcap(socket_path: &str) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::FreezePcap)
}

/// Ask `net-observerd` to go and find who is on this segment NOW
/// (`Control(ScanNeighbors)`): a sweep of the local subnet plus an mDNS browse.
///
/// The one control action in the panel that puts packets on the wire towards
/// machines that are not this one, so it is **acting-class** — a daemon without
/// `acting.enabled` answers `ok: false` with a reason, shown like any other
/// control outcome.
pub fn send_scan_neighbors(socket_path: &str) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::ScanNeighbors)
}

/// The one blocking control round-trip every control action goes through, so the
/// bar has exactly one socket client (`net_observer_ipc::query`) and one mapping
/// from its answers to a `Result`.
fn control_query(socket_path: &str, cmd: ControlCmd) -> Result<ControlResult, String> {
    match net_observer_ipc::query(socket_path, &Request::Control(cmd)) {
        Ok(Response::Control(result)) => Ok(result),
        Ok(Response::Error(msg)) => Err(msg),
        Ok(_) => Err("unexpected response from net-observerd".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn send_set_observing(socket_path: &str, on: bool) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::SetObserving(on))
}

/// How many refresh ticks the panel's own sparkline history keeps.
///
/// 120 points at the menu-bar's `REFRESH` cadence of 3s (see [`crate::menubar`])
/// is a 6-minute window. That length is chosen against the failure this panel
/// exists to catch: the coworking gateway does not drop, it *ramps* — the reply
/// time climbs for roughly 40 seconds before the gateway stops answering at all.
/// Six minutes shows that ramp with several minutes of quiet baseline in front of
/// it, so the slope is legible as a departure rather than filling the whole chart;
/// it is also short enough that 120 one-pixel columns fit the 320pt panel width
/// without downsampling, so every point drawn is a point measured.
///
/// **This history is the bar's own, and it is not a record.** It starts empty when
/// the bar launches and dies with the process — the daemon's DuckDB store is the
/// record, and the bar never opens it (the daemon is the sole DB owner). A short
/// line after a restart means "the bar just started", never "the network was
/// fine".
pub const HISTORY_LEN: usize = 120;

/// One refresh tick's worth of plottable values.
///
/// Both fields are `Option` on purpose. A tick where the measurement did not
/// happen — no sample yet, a paused daemon, quiet mode (`gw = SKIP`), a gateway
/// that failed or is absent, or an unreachable daemon — is a **gap**, and a gap is
/// not a zero. Plotting a missing measurement as a value on the floor is the same
/// lie the `SKIP` verdict exists to prevent (see `AGENTS.md`, "SKIP, never
/// silence"): it would draw a flat healthy-looking 0ms line for a gateway that was
/// never asked.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct HistoryPoint {
    /// Gateway round-trip time, `None` when nothing was measured this tick.
    pub gw_rtt_ms: Option<f64>,
    /// Host 1-minute load average, `None` when there is no host sample.
    pub load1: Option<f64>,
}

/// Reduce a snapshot to the one plottable point for this tick.
///
/// Pure over its inputs, so the gap rules above are directly testable. `online` is
/// [`Glance::online`]: an unreachable daemon measured nothing, whatever the stale
/// snapshot still says.
pub fn history_point(snapshot: &StatusSnapshot, online: bool) -> HistoryPoint {
    if !online || !snapshot.observing {
        // Offline or paused: collection is not running. Nothing was measured.
        return HistoryPoint::default();
    }
    let gw_rtt_ms = snapshot.link.as_ref().and_then(|l| match l.gw {
        // Only an answered echo carries a time. FAIL/NOGW have no RTT to plot and
        // SKIP means quiet mode — the echo was deliberately not sent.
        types::GwVerdict::Ok => l.gw_rtt_ms,
        types::GwVerdict::Fail | types::GwVerdict::NoGw | types::GwVerdict::Skip => None,
    });
    HistoryPoint {
        gw_rtt_ms,
        load1: snapshot.host.as_ref().map(|h| h.load1),
    }
}

/// Shared, app-scoped model: the latest snapshot the UI renders.
pub struct Glance {
    pub snapshot: StatusSnapshot,
    /// The most recent fetch error, if the last refresh failed — classified into
    /// "nothing answered" vs "the daemon answered badly" (see [`GlanceError`]).
    pub error: Option<GlanceError>,
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
    /// The panel's own bounded history of the last [`HISTORY_LEN`] refresh ticks,
    /// oldest first — the series behind the sparklines. Appended by
    /// [`Glance::record_tick`] from the refresh timer *only*, so one column is one
    /// `REFRESH` interval and the window length is a real duration.
    pub history: VecDeque<HistoryPoint>,
}

impl Glance {
    pub fn new(snapshot: StatusSnapshot, error: Option<GlanceError>, socket_path: String) -> Self {
        Self {
            snapshot,
            error,
            socket_path,
            control_msg: None,
            events_window: None,
            history: VecDeque::with_capacity(HISTORY_LEN),
        }
    }

    /// Append the current state as one sparkline point, evicting the oldest once
    /// [`HISTORY_LEN`] is reached — the ring never grows past that bound.
    ///
    /// Called from the refresh timer after it has applied the tick's read, and
    /// from nowhere else: the manual "Refresh" button and the observing toggle
    /// also re-read the daemon, but appending there would compress the time axis
    /// (two columns a second apart drawn as one interval), so they update the
    /// snapshot without adding a column.
    pub fn record_tick(&mut self) {
        if self.history.len() == HISTORY_LEN {
            self.history.pop_front();
        }
        self.history
            .push_back(history_point(&self.snapshot, self.online()));
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

    /// Whether the daemon is reachable. Only [`GlanceError::Unreachable`] means
    /// "not there": a protocol failure came *from* a live daemon, so the panel
    /// stays online (the toggle keeps working, the message is shown instead).
    pub fn online(&self) -> bool {
        !matches!(self.error, Some(GlanceError::Unreachable(_)))
    }

    /// Apply the outcome of a toggle round-trip (see [`toggle_round_trip`]) to this
    /// model. Pure state application — it performs no I/O, so it is safe to run on
    /// the gpui main thread and is directly testable.
    ///
    /// `control` becomes the transient `control_msg` line; `fresh` is applied
    /// exactly the way [`Glance::refresh`] applies its own read, so the switch
    /// reflects the daemon's real state (or goes offline) rather than a
    /// silently-flipped local bool.
    pub fn apply_toggle_result(
        &mut self,
        control: Result<ControlResult, String>,
        fresh: Result<StatusSnapshot, GlanceError>,
    ) {
        self.control_msg = Some(match control {
            Ok(result) => {
                let tag = if result.ok { "ok" } else { "failed" };
                format!("{tag}: {}", result.message)
            }
            Err(e) => format!("failed: {e}"),
        });
        match fresh {
            Ok(s) => {
                self.snapshot = s;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }
}

/// The blocking half of the header toggle: read the live state, flip it, read it
/// back. Returns the control outcome and the post-toggle snapshot for
/// [`Glance::apply_toggle_result`].
///
/// **Never call this on the gpui main thread** — it is three blocking socket
/// round-trips (see the click wiring in `toggle_switch`, which runs it on the
/// background executor).
///
/// The *leading* read is the point: `SetObserving(bool)` is absolute on the wire
/// and a second controller genuinely exists (`net-observer-cli observe on|off`), so a
/// cached snapshot up to one refresh tick old is not a safe premise — a state
/// change inside that window would be silently overwritten. The target is derived
/// from the freshly-read state instead. If that read fails there is no premise, so
/// no command is sent and the error is reported on both channels (as its message
/// on the control half, as the classified [`GlanceError`] on the read half). Never
/// panics — every failure is a readable `Err`.
pub fn toggle_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let before = match read_fresh(socket_path) {
        Ok(s) => s,
        Err(e) => return (Err(e.to_string()), Err(e)),
    };
    let control = send_set_observing(socket_path, !before.observing);
    // Reflect the daemon's real observing state after the toggle.
    (control, read_fresh(socket_path))
}

/// The blocking half of the quiet toggle, built exactly like
/// [`toggle_round_trip`] and for the same reason: `SetQuiet(bool)` is absolute on
/// the wire, so the target is derived from a freshly-read state rather than from a
/// snapshot up to one refresh tick old. Never call it on the gpui main thread.
pub fn quiet_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let before = match read_fresh(socket_path) {
        Ok(s) => s,
        Err(e) => return (Err(e.to_string()), Err(e)),
    };
    let control = send_set_quiet(socket_path, !before.quiet);
    (control, read_fresh(socket_path))
}

/// The blocking half of the "Freeze pcap now" action: send the command, then
/// re-read the snapshot so the panel's freshness/offline state stays truthful.
/// No leading read — unlike the two toggles this command carries no state to
/// derive. Never call it on the gpui main thread.
pub fn freeze_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let control = send_freeze_pcap(socket_path);
    (control, read_fresh(socket_path))
}

/// The blocking half of the "Scan" action: send the command, then re-read the
/// snapshot so the neighbour count the panel shows is the one the scan just
/// produced. Never call it on the gpui main thread — the scan takes seconds by
/// design (a settle wait plus an mDNS budget).
pub fn scan_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let control = send_scan_neighbors(socket_path);
    (control, read_fresh(socket_path))
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
        let control_msg = glance.control_msg.clone();
        let history = glance.history.clone();
        let now_us = now_us();
        // Offline (daemon down / socket absent) ⇒ we cannot be observing, so the
        // switch reads OFF and is non-interactive regardless of the stale snapshot.
        // A protocol failure is NOT offline: the daemon answered, so the toggle
        // stays live and the message goes to the footer instead.
        let online = glance.online();
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
            // Trend before state: the gateway fails as a ramp, so the slope is
            // read first and the current verdicts underneath it.
            .child(sparklines_section(&history, theme))
            .child(separator(theme))
            .child(status_rows(&snapshot, now_us, theme))
            .child(separator(theme))
            .child(incidents_section(&snapshot.incidents, now_us, theme))
            .child(separator(theme))
            .child(footer(
                &snapshot,
                now_us,
                control_msg,
                protocol_msg,
                theme,
                cx,
            ))
    }
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
        base.children(incidents.iter().map(move |i| {
            let (state, color) = match i.closed_us {
                Some(_) => ("closed", theme.muted),
                None => ("open", theme.bad),
            };
            let value = format!("{state} \u{00b7} {}", age_str(i.opened_us, now_us));
            row(i.trigger_id.clone(), value, rgb(color), theme)
        }))
    }
}

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

    // "Freeze pcap now" and the quiet toggle: the two operator control actions
    // besides pause/resume. Both are benign self-control — the freeze copies files
    // the daemon already owns, quiet only suppresses a probe the daemon itself
    // sends — so neither is gated by `acting.enabled`, and both run their socket
    // round-trips on the background executor for the same reason the header
    // toggle does: a daemon that accepts but never answers must not park the bar.
    let freeze = div()
        .id("freeze-pcap")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(theme.accent))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("Freeze pcap")
        .on_click(cx.listener(|this, _, _window, cx| {
            spawn_control(this, cx, freeze_round_trip);
        }));

    // The label states what the click will DO, and the color states which state
    // the daemon is in now: warn-colored while quiet, because a suppressed probe
    // is a deliberate hole in the measurement and should not look routine.
    let quiet_on = snapshot.quiet;
    let quiet = div()
        .id("quiet-toggle")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(if quiet_on { theme.warn } else { theme.accent }))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child(if quiet_on { "Unquiet" } else { "Quiet" })
        .on_click(cx.listener(|this, _, _window, cx| {
            spawn_control(this, cx, quiet_round_trip);
        }));

    // Scan sits apart from the two above: it is the only button here that
    // addresses other machines, so it is acting-class and refused by default.
    // Warn-colored for the same reason the quiet toggle is — this one is not
    // routine either.
    let scan = div()
        .id("scan-neighbors")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(theme.warn))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("Scan")
        .on_click(cx.listener(|this, _, _window, cx| {
            spawn_control(this, cx, scan_round_trip);
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
        .child(
            div()
                .flex()
                .items_center()
                .gap_1()
                .child(events)
                .child(freeze)
                .child(quiet)
                .child(scan),
        )
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
        .px_3()
        .py_2()
        .child(actions)
        .child(meta)
}

/// One blocking control round-trip: send a command, then re-read status so the
/// panel shows what the daemon actually holds rather than what the click asked
/// for. Both halves are fallible and fail differently — the command can be
/// refused (`String`) while the follow-up read can find no daemon at all
/// (`GlanceError`) — so neither collapses into the other.
type ControlRoundTrip = fn(
    &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
);

/// Run one blocking control round-trip on the background executor and apply its
/// outcome to the shared model on the foreground.
///
/// The single place the panel's control actions touch the socket, so "never block
/// the gpui main thread" and "a daemon that is not there is a message, not a
/// crash" are decided once rather than per button. The model is held weakly, so a
/// shut-down app just drops the result.
fn spawn_control(view: &PanelView, cx: &mut Context<PanelView>, round_trip: ControlRoundTrip) {
    let model = view.model.downgrade();
    let socket = view.model.read(cx).socket_path.clone();
    cx.spawn(async move |_view, acx: &mut AsyncApp| {
        let (control, fresh) = acx
            .background_spawn(async move { round_trip(&socket) })
            .await;
        model
            .update(acx, |g, cx| {
                g.apply_toggle_result(control, fresh);
                cx.notify();
            })
            .ok();
    })
    .detach();
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

// ---- small element helpers -------------------------------------------------

/// A hairline separator between sections — a 1px full-width rule, no borders.
fn separator(theme: Theme) -> impl IntoElement {
    div().h(px(1.0)).w_full().bg(rgb(theme.separator))
}

/// One label→value list row: a muted label on the left, a colored value on the
/// right (the Tailscale-style clean list, not a bordered card).
///
/// Both sides take anything convertible into a [`SharedString`], so a `&'static
/// str` label costs no allocation at all and an owned `String` local is *moved*
/// in rather than copied — a render runs this once per row, every tick.
fn row<K: Into<SharedString>, V: Into<SharedString>>(
    key: K,
    value: V,
    value_color: Rgba,
    theme: Theme,
) -> impl IntoElement {
    let key: SharedString = key.into();
    let value: SharedString = value.into();
    div()
        .flex()
        .items_center()
        .justify_between()
        .py_1()
        .child(div().text_color(rgb(theme.muted)).child(key))
        .child(div().text_color(value_color).child(value))
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

    fn link(gw: types::GwVerdict, rtt: Option<f64>) -> types::LinkSample {
        types::LinkSample {
            ts_us: 1_000_000,
            gw,
            gw_rtt_ms: rtt,
            direct: types::TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        }
    }

    fn glance() -> Glance {
        Glance::new(StatusSnapshot::default(), None, "/nonexistent.sock".into())
    }

    /// The ring is bounded: it never exceeds `HISTORY_LEN`, and it evicts the
    /// oldest column rather than the newest — the sparkline must keep showing the
    /// present, not freeze on the first six minutes after launch.
    #[test]
    fn history_ring_stays_bounded_and_drops_the_oldest() {
        let mut g = glance();
        for i in 0..(HISTORY_LEN * 2) {
            g.snapshot.host = Some(types::HostSample {
                ts_us: i as i64,
                load1: i as f64,
                load5: 0.0,
                load15: 0.0,
            });
            g.record_tick();
            assert!(
                g.history.len() <= HISTORY_LEN,
                "ring grew past its bound at tick {i}"
            );
        }
        assert_eq!(g.history.len(), HISTORY_LEN);
        // The window holds the LAST HISTORY_LEN ticks, oldest first.
        assert_eq!(
            g.history.front().unwrap().load1,
            Some(HISTORY_LEN as f64),
            "oldest retained column must be the (2N - N)th tick"
        );
        assert_eq!(
            g.history.back().unwrap().load1,
            Some((HISTORY_LEN * 2 - 1) as f64),
            "newest column must be the most recent tick"
        );
    }

    /// A gap is not a zero. Every way a measurement can fail to happen must land
    /// as `None`, never as a value on the floor.
    #[test]
    fn unmeasured_ticks_stay_gaps() {
        // No sample at all.
        let empty = StatusSnapshot::default();
        assert_eq!(history_point(&empty, true), HistoryPoint::default());

        // Gateway verdicts that carry no measured reply time. SKIP is quiet mode:
        // the echo was deliberately never sent.
        for gw in [
            types::GwVerdict::Fail,
            types::GwVerdict::NoGw,
            types::GwVerdict::Skip,
        ] {
            // Even with an RTT field set, a non-OK verdict is not a measurement.
            let s = StatusSnapshot {
                link: Some(link(gw, Some(42.0))),
                ..Default::default()
            };
            assert_eq!(
                history_point(&s, true).gw_rtt_ms,
                None,
                "{gw} must be a gap, not a plotted value"
            );
        }

        // An OK verdict with no time is still a gap.
        let s = StatusSnapshot {
            link: Some(link(types::GwVerdict::Ok, None)),
            ..Default::default()
        };
        assert_eq!(history_point(&s, true).gw_rtt_ms, None);

        // A paused daemon collects nothing, however healthy the retained snapshot
        // looks; and an unreachable daemon measured nothing at all.
        let live = StatusSnapshot {
            link: Some(link(types::GwVerdict::Ok, Some(12.0))),
            host: Some(types::HostSample {
                ts_us: 1,
                load1: 3.0,
                load5: 0.0,
                load15: 0.0,
            }),
            ..Default::default()
        };
        assert_eq!(
            history_point(&live, true),
            HistoryPoint {
                gw_rtt_ms: Some(12.0),
                load1: Some(3.0)
            },
            "a live, observing daemon plots both series"
        );
        let mut paused = live.clone();
        paused.observing = false;
        assert_eq!(history_point(&paused, true), HistoryPoint::default());
        assert_eq!(history_point(&live, false), HistoryPoint::default());
    }

    /// The bar's own reachability, not the stale snapshot, decides: a `Glance`
    /// holding an `Unreachable` error records a gap.
    #[test]
    fn offline_glance_records_a_gap() {
        let mut g = glance();
        g.snapshot.link = Some(link(types::GwVerdict::Ok, Some(99.0)));
        g.error = Some(GlanceError::Unreachable("no socket".into()));
        g.record_tick();
        assert_eq!(g.history.back().copied(), Some(HistoryPoint::default()));
    }

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
    /// this is the "net-observer offline" path the panel renders. It is specifically
    /// `Unreachable`: nothing answered, so "daemon not reachable" is true.
    #[test]
    fn read_fresh_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let err = read_fresh(missing.to_str().unwrap())
            .expect_err("absent socket must yield an offline Err");
        assert!(
            matches!(err, GlanceError::Unreachable(_)),
            "absent socket is unreachable, not a protocol failure: {err:?}"
        );
    }

    /// Only the kinds that mean "nobody was there" are unreachable; a decode
    /// failure (a new bar against an older daemon) happened *with* a live daemon on
    /// the other end.
    #[test]
    fn classify_io_separates_unreachable_from_protocol() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
        ] {
            assert!(
                matches!(
                    classify_io(Error::new(kind, "nope")),
                    GlanceError::Unreachable(_)
                ),
                "{kind:?} means nothing answered"
            );
        }
        assert!(
            matches!(
                classify_io(Error::new(ErrorKind::InvalidData, "bad frame")),
                GlanceError::Protocol(_)
            ),
            "an undecodable answer still came from a live daemon"
        );
    }

    /// A protocol failure must NOT read as offline: the daemon answered, so the
    /// panel stays online (toggle live) and the message goes to the footer.
    #[test]
    fn protocol_error_keeps_the_panel_online() {
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            None,
            "/nonexistent.sock".to_string(),
        );
        assert!(glance.online(), "no error is online");

        glance.error = Some(GlanceError::Protocol("missing field `observing`".into()));
        assert!(
            glance.online(),
            "a daemon that answered badly is still reachable"
        );
        assert_eq!(
            glance.error.as_ref().map(GlanceError::message),
            Some("missing field `observing`"),
            "the real message must survive for the footer line"
        );

        glance.error = Some(GlanceError::Unreachable("No such file".into()));
        assert!(!glance.online(), "nothing answered -> offline");
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

    /// Applying a toggle outcome from a down daemon records a readable failure line
    /// instead of panicking, and the failed read surfaces the offline state (the
    /// switch reflects the daemon's real, unreachable state — never a
    /// silently-flipped local bool).
    #[test]
    fn glance_toggle_observing_records_failure_when_daemon_down() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let socket = missing.to_str().unwrap();
        let mut glance = Glance::new(StatusSnapshot::default(), None, socket.to_string());
        // A fresh snapshot reads as observing; the daemon is down.
        assert!(glance.snapshot.observing);
        // The real errors the background round-trip would hand back.
        glance.apply_toggle_result(send_set_observing(socket, false), read_fresh(socket));
        let msg = glance
            .control_msg
            .clone()
            .expect("toggle must record a message");
        assert!(
            msg.starts_with("failed:"),
            "daemon-down must be a failure: {msg}"
        );
        // The read failed against the absent socket -> offline (unreachable, since
        // nothing answered), and the (unreached) snapshot state is left as-is
        // rather than flipped.
        assert!(
            matches!(glance.error, Some(GlanceError::Unreachable(_))),
            "refresh must surface offline: {:?}",
            glance.error
        );
        assert!(!glance.online(), "the panel reads as offline");
        assert!(glance.snapshot.observing, "state not flipped locally");
    }

    /// A successful toggle applies the daemon's post-toggle snapshot and clears a
    /// previous offline error — the switch follows the daemon, not a local guess.
    #[test]
    fn apply_toggle_result_adopts_fresh_snapshot_and_clears_error() {
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            Some(GlanceError::Unreachable("was offline".to_string())),
            "/nonexistent.sock".to_string(),
        );
        let paused = StatusSnapshot {
            observing: false,
            ..StatusSnapshot::default()
        };
        glance.apply_toggle_result(
            Ok(ControlResult {
                ok: true,
                message: "observing off".to_string(),
            }),
            Ok(paused),
        );
        assert_eq!(glance.control_msg.as_deref(), Some("ok: observing off"));
        assert!(!glance.snapshot.observing, "switch follows the daemon");
        assert!(glance.error.is_none(), "a good read clears offline");
    }

    /// A refusal (`ok: false`) reads as a failure line even though the round-trip
    /// itself succeeded.
    #[test]
    fn apply_toggle_result_marks_refusal_as_failed() {
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            None,
            "/nonexistent.sock".to_string(),
        );
        glance.apply_toggle_result(
            Ok(ControlResult {
                ok: false,
                message: "refused".to_string(),
            }),
            Err(GlanceError::Unreachable("offline".to_string())),
        );
        assert_eq!(glance.control_msg.as_deref(), Some("failed: refused"));
        assert_eq!(
            glance.error,
            Some(GlanceError::Unreachable("offline".to_string()))
        );
    }

    /// The leading read is the toggle's premise: when it fails there is nothing to
    /// flip, so no `SetObserving` is sent and both halves report the error.
    #[test]
    fn toggle_round_trip_skips_control_when_leading_read_fails() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let (control, fresh) = toggle_round_trip(missing.to_str().unwrap());
        let err = control.expect_err("no premise -> no command, just the error");
        let fresh = fresh.expect_err("the leading read failed");
        assert!(
            matches!(fresh, GlanceError::Unreachable(_)),
            "an absent socket is unreachable: {fresh:?}"
        );
        assert_eq!(
            err,
            fresh.to_string(),
            "both halves report the same offline error"
        );
    }
}
