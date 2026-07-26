//! The realtime **event-log window** — a resizable, closable
//! [`WindowKind::Normal`] window that shows live events (samples + incidents) as
//! they happen, pushed over the daemon's local socket (pub/sub, never polling).
//!
//! ## Push, not poll
//!
//! `observerd` runs an internal broadcast bus and answers a held-open
//! [`Request::Subscribe`] by streaming newline-JSON [`Event`] frames until the
//! client disconnects. This window opens **one** persistent subscription for its
//! whole lifetime — it never re-subscribes and never polls. When collection is
//! paused, no samples flow, so the stream naturally goes quiet.
//!
//! ## The bridge (blocking socket → gpui model)
//!
//! [`observer_ipc`] is deliberately tokio-free: [`observer_ipc::subscribe`] is a
//! blocking iterator over a plain `UnixStream`. So a dedicated OS thread
//! ([`run_subscription`]) drives it, forwarding each frame down an `mpsc` channel
//! as a [`BridgeMsg`]. A gpui foreground task drains that channel every
//! [`DRAIN_POLL`] into the shared [`EventLog`] model (a capped [`VecDeque`] of the
//! last [`EVENT_CAP`] events), and the [`EventLogView`] observes the model and
//! re-renders. The task holds only a [`gpui::WeakEntity`], so closing the window
//! drops the model, ends the task, and — once the receiver is gone — ends the
//! thread. On disconnect / daemon-down the thread surfaces an "offline" note and
//! retries the subscription; it never panics.
//!
//! ## Filtering
//!
//! The subscription is always for **all** kinds (`kinds: None`); the type selector
//! at the top filters the displayed rows client-side by [`EventKind`], so changing
//! it never touches the socket.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use gpui::prelude::*;
use gpui::{
    AnyElement, AnyWindowHandle, App, AsyncApp, Context, Entity, ScrollHandle, SharedString,
    Subscription, Timer, TitlebarOptions, Window, WindowBounds, WindowHandle, WindowKind,
    WindowOptions, div, px, rgb, size,
};

use observer_ipc::{Event, EventKind, Request};

use crate::ui::{Glance, Theme};

/// Maximum number of events retained in the live list (oldest dropped past this).
const EVENT_CAP: usize = 1000;
/// How often the foreground bridge task drains the channel into the model. Small
/// enough that the tail feels live, cheap enough to leave the CPU idle otherwise.
const DRAIN_POLL: Duration = Duration::from_millis(150);
/// How long the subscription thread waits before retrying after the daemon is down
/// or the stream drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Initial size of the event-log window (resizable afterwards), gpui logical px.
const WIN_W: f32 = 560.0;
const WIN_H: f32 = 600.0;

/// A message from the subscription thread to the gpui bridge task.
enum BridgeMsg {
    /// A live event frame from the daemon.
    Event(Event),
    /// The subscription (re)connected — clear any offline note.
    Online,
    /// The daemon is down or the stream dropped; the thread will retry.
    Offline(String),
}

/// The shared, window-scoped model: the capped live event list plus the current
/// connection state. Written by the bridge task, read by [`EventLogView`].
pub struct EventLog {
    events: VecDeque<Event>,
    /// `Some(reason)` while disconnected / reconnecting; `None` when live.
    offline: Option<String>,
}

impl EventLog {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            offline: None,
        }
    }

    /// Apply one [`BridgeMsg`] to the model: append (and cap) an event, or update
    /// the connection state.
    fn apply(&mut self, msg: BridgeMsg) {
        match msg {
            BridgeMsg::Event(ev) => {
                self.offline = None;
                if self.events.len() >= EVENT_CAP {
                    self.events.pop_front();
                }
                self.events.push_back(ev);
            }
            BridgeMsg::Online => self.offline = None,
            BridgeMsg::Offline(reason) => self.offline = Some(reason),
        }
    }
}

/// The root view of the event-log window. Observes the shared [`EventLog`] and
/// re-renders on change; keeps the client-side type filter and the list's scroll
/// state.
pub struct EventLogView {
    log: Entity<EventLog>,
    /// The selected type filter; `None` = all kinds.
    filter: Option<EventKind>,
    scroll: ScrollHandle,
    /// Set when the model changed (or the filter changed) so the next render
    /// autoscrolls to the tail; cleared once applied.
    want_scroll: bool,
    _observe: Subscription,
}

impl EventLogView {
    fn new(log: Entity<EventLog>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&log, |this, _, cx| {
            this.want_scroll = true;
            cx.notify();
        });
        Self {
            log,
            filter: None,
            scroll: ScrollHandle::new(),
            want_scroll: true,
            _observe: observe,
        }
    }
}

impl Render for EventLogView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let filter = self.filter;

        // Snapshot what we render, then drop the model borrow before touching `cx`
        // mutably (the selector's listeners) or `self` (the scroll handle).
        let (offline, rows) = {
            let log = self.log.read(cx);
            let offline = log.offline.clone();
            let rows: Vec<AnyElement> = log
                .events
                .iter()
                .filter(|e| filter.is_none_or(|k| e.kind() == k))
                .map(|e| event_row(e, theme).into_any_element())
                .collect();
            (offline, rows)
        };

        // Autoscroll to the newest row when the model or filter changed.
        if self.want_scroll {
            self.scroll.scroll_to_bottom();
            self.want_scroll = false;
        }

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .child(selector_row(filter, theme, cx))
            .child(separator(theme))
            .children(offline.map(|reason| offline_row(reason, theme)))
            .child(
                div()
                    .id("event-list")
                    .flex()
                    .flex_col()
                    .flex_1()
                    .overflow_y_scroll()
                    .track_scroll(&self.scroll)
                    .px_3()
                    .py_1()
                    .gap_0p5()
                    .children(rows),
            )
    }
}

/// The type selector: a wrapping row of toggle chips
/// (`All · incident · route · dns · link · proxy · host`). Selecting one sets the
/// client-side [`EventLogView::filter`] — no re-subscribe.
fn selector_row(
    filter: Option<EventKind>,
    theme: Theme,
    cx: &mut Context<EventLogView>,
) -> impl IntoElement {
    let options: [(&'static str, &'static str, Option<EventKind>); 7] = [
        ("chip-all", "All", None),
        ("chip-incident", "incident", Some(EventKind::Incident)),
        ("chip-route", "route", Some(EventKind::Route)),
        ("chip-dns", "dns", Some(EventKind::Dns)),
        ("chip-link", "link", Some(EventKind::Link)),
        ("chip-proxy", "proxy", Some(EventKind::Proxy)),
        ("chip-host", "host", Some(EventKind::Host)),
    ];

    let mut row = div()
        .flex()
        .flex_wrap()
        .items_center()
        .gap_1()
        .px_3()
        .py_2();
    for (id, label, kind) in options {
        row = row.child(chip(id, label, kind, filter == kind, theme, cx));
    }
    row
}

/// One selector chip: filled with the accent when selected, a muted hover target
/// otherwise. Clicking it sets the filter and requests an autoscroll.
fn chip(
    id: &'static str,
    label: &'static str,
    kind: Option<EventKind>,
    selected: bool,
    theme: Theme,
    cx: &mut Context<EventLogView>,
) -> impl IntoElement {
    let mut el = div()
        .id(id)
        .px_2()
        .py_0p5()
        .rounded_md()
        .text_size(px(12.0))
        .cursor_pointer();
    if selected {
        el = el.bg(rgb(theme.accent)).text_color(rgb(theme.knob));
    } else {
        el = el
            .text_color(rgb(theme.muted))
            .hover(|s| s.bg(rgb(theme.hover)));
    }
    el.child(label)
        .on_click(cx.listener(move |this, _, _window, cx| {
            this.filter = kind;
            this.want_scroll = true;
            cx.notify();
        }))
}

/// One event row: a muted local `HH:MM:SS` clock, then the one-line
/// [`format_event`] detail. Incidents are drawn in the "bad" color.
fn event_row(ev: &Event, theme: Theme) -> impl IntoElement {
    let value_color = if ev.kind() == EventKind::Incident {
        theme.bad
    } else {
        theme.fg
    };
    div()
        .flex()
        .items_center()
        .gap_2()
        .py_0p5()
        .child(
            div()
                .w(px(66.0))
                .text_color(rgb(theme.muted))
                .text_size(px(11.0))
                .child(SharedString::from(clock(ev.ts_us()))),
        )
        .child(
            div()
                .flex_1()
                .text_color(rgb(value_color))
                .text_size(px(12.0))
                .child(SharedString::from(format_event(ev))),
        )
}

/// The "offline — reconnecting" banner shown while the subscription is down.
fn offline_row(reason: String, theme: Theme) -> impl IntoElement {
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
                .child("offline — reconnecting"),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child(SharedString::from(reason)),
        )
}

/// A hairline separator — a 1px full-width rule.
fn separator(theme: Theme) -> impl IntoElement {
    div().h(px(1.0)).w_full().bg(rgb(theme.separator))
}

/// Format one [`Event`] as its one-line log detail: `"<kind>  <detail>"`. Pure
/// over its input (no clock, no locale), so it is unit-tested directly; the row
/// renders the timestamp separately (see [`clock`]).
pub fn format_event(ev: &Event) -> String {
    format!("{}  {}", kind_label(ev.kind()), event_detail(ev))
}

/// The short lowercase label for an [`EventKind`], matching the selector chips.
fn kind_label(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Link => "link",
        EventKind::Proxy => "proxy",
        EventKind::Dns => "dns",
        EventKind::Route => "route",
        EventKind::Host => "host",
        EventKind::Incident => "incident",
    }
}

/// The per-variant one-line detail for an event.
fn event_detail(ev: &Event) -> String {
    match ev {
        Event::Link(l) => format!("gw={} direct={}", l.gw, l.direct),
        Event::Proxy(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
            format!("tun={tun} sel={sel}")
        }
        Event::Dns(d) => {
            let ip = d.ip.clone().unwrap_or_else(|| "-".to_string());
            format!("{}/{} {} {}", d.probe, d.server, d.verdict, ip)
        }
        Event::Route(r) => {
            let iface = r.iface.clone().unwrap_or_else(|| "-".to_string());
            format!("{} {} {}", r.kind, iface, r.detail)
        }
        Event::Host(h) => format!("load {:.2}/{:.2}/{:.2}", h.load1, h.load5, h.load15),
        Event::Incident(i) => format!("{} {}", i.trigger_id, i.signature),
    }
}

/// Format an epoch-microsecond timestamp as a local `HH:MM:SS` wall clock. Falls
/// back to `--:--:--` on an out-of-range timestamp (never panics).
fn clock(ts_us: i64) -> String {
    match jiff::Timestamp::from_microsecond(ts_us) {
        Ok(ts) => {
            let z = ts.to_zoned(jiff::tz::TimeZone::system());
            format!("{:02}:{:02}:{:02}", z.hour(), z.minute(), z.second())
        }
        Err(_) => "--:--:--".to_string(),
    }
}

/// Open the event-log window, or bring the already-open one to the front.
///
/// The live window handle is stashed on the shared [`Glance`] so a second click
/// focuses the existing window instead of opening a duplicate (which would spawn a
/// second subscription). A stale handle (window since closed) falls through to a
/// fresh open. Never panics: a failed open is logged, not fatal.
pub fn open_or_focus(cx: &mut App, glance: &Entity<Glance>, socket_path: String) {
    if let Some(existing) = glance.read(cx).events_window {
        // `update` succeeds only while the window is still open.
        if existing
            .update(cx, |_view, window, _cx| window.activate_window())
            .is_ok()
        {
            cx.activate(true);
            return;
        }
    }

    if let Some(handle) = open_window(cx, socket_path) {
        let any: AnyWindowHandle = handle.into();
        glance.update(cx, |g, _| g.events_window = Some(any));
        // Accessory apps don't get key focus for free; bring the new window forward.
        cx.activate(true);
    }
}

/// Create the event-log window and wire its subscription bridge. Returns the
/// window handle, or `None` if the window failed to open.
fn open_window(cx: &mut App, socket_path: String) -> Option<WindowHandle<EventLogView>> {
    let log = cx.new(|_| EventLog::new());
    let (tx, rx) = mpsc::channel::<BridgeMsg>();

    // Background OS thread: drive the blocking subscription; reconnect on drop.
    // Spawn failure is non-fatal — the window still opens (just without live data).
    if let Err(e) = thread::Builder::new()
        .name("observer-events".to_string())
        .spawn(move || run_subscription(&socket_path, &tx))
    {
        eprintln!("observer-bar: failed to spawn events subscription thread: {e}");
    }

    // Foreground task: drain the channel into the model until the window closes
    // (the weak handle stops upgrading) or the app shuts down.
    let weak = log.downgrade();
    cx.spawn(async move |acx: &mut AsyncApp| {
        loop {
            Timer::after(DRAIN_POLL).await;
            let mut batch = Vec::new();
            loop {
                match rx.try_recv() {
                    Ok(msg) => batch.push(msg),
                    Err(mpsc::TryRecvError::Empty) => break,
                    // The thread ended; nothing more will arrive on this channel.
                    Err(mpsc::TryRecvError::Disconnected) => break,
                }
            }
            let alive = weak.update(acx, |log, cx| {
                if !batch.is_empty() {
                    for msg in batch {
                        log.apply(msg);
                    }
                    cx.notify();
                }
            });
            if alive.is_err() {
                break; // window closed or app shutting down
            }
        }
    })
    .detach();

    let options = window_options(cx);
    match cx.open_window(options, move |_window, cx| {
        cx.new(|cx| EventLogView::new(log, cx))
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("observer-bar: failed to open events window: {e}");
            None
        }
    }
}

/// Window options for the event log: a normal, resizable, closable window with a
/// native titlebar ("observer — events"), centered on the primary display.
fn window_options(cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(WIN_W), px(WIN_H)), cx)),
        titlebar: Some(TitlebarOptions {
            title: Some(SharedString::from("observer — events")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        kind: WindowKind::Normal,
        is_movable: true,
        is_resizable: true,
        is_minimizable: true,
        focus: true,
        show: true,
        window_min_size: Some(size(px(360.0), px(240.0))),
        ..Default::default()
    }
}

/// The subscription thread body: hold one [`Request::Subscribe`] open, forward
/// every [`Event`] down `tx`, and reconnect (after [`RECONNECT_DELAY`]) whenever
/// the daemon is down or the stream drops. Stops as soon as the receiver is gone
/// (the window closed). Never panics.
fn run_subscription(sock_path: &str, tx: &mpsc::Sender<BridgeMsg>) {
    loop {
        match observer_ipc::subscribe(sock_path, &Request::Subscribe { kinds: None }) {
            Ok(sub) => {
                if tx.send(BridgeMsg::Online).is_err() {
                    return; // receiver gone — the window closed
                }
                for item in sub {
                    match item {
                        Ok(ev) => {
                            if tx.send(BridgeMsg::Event(ev)).is_err() {
                                return;
                            }
                        }
                        // A read/decode error ends this stream; reconnect below.
                        Err(_) => break,
                    }
                }
                // The daemon closed the connection cleanly; note it and reconnect.
                if tx
                    .send(BridgeMsg::Offline("connection closed".to_string()))
                    .is_err()
                {
                    return;
                }
            }
            Err(e) => {
                // Daemon down / socket absent: surface it, then retry.
                if tx.send(BridgeMsg::Offline(e.to_string())).is_err() {
                    return;
                }
            }
        }
        thread::sleep(RECONNECT_DELAY);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use observer_ipc::IncidentSummary;
    use types::{DnsSample, DnsVerdict, GwVerdict, HostSample, LinkSample, TcpVerdict};

    #[test]
    fn format_event_renders_kind_and_detail() {
        let link = Event::Link(LinkSample {
            ts_us: 1,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Fail,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        });
        assert_eq!(format_event(&link), "link  gw=OK direct=FAIL");

        let dns = Event::Dns(DnsSample {
            ts_us: 2,
            probe: "nks".into(),
            server: "sb".into(),
            verdict: DnsVerdict::FakeIp,
            ip: Some("198.18.0.1".into()),
            rtt_ms: None,
        });
        assert_eq!(format_event(&dns), "dns  nks/sb FAKEIP 198.18.0.1");

        let inc = Event::Incident(IncidentSummary {
            id: "i1".into(),
            opened_us: 5,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        });
        assert_eq!(format_event(&inc), "incident  wedge tun dead");
    }

    /// The live list is bounded: past [`EVENT_CAP`], the oldest events are dropped.
    #[test]
    fn event_log_caps_at_capacity() {
        let mut log = EventLog::new();
        for i in 0..(EVENT_CAP + 50) {
            log.apply(BridgeMsg::Event(Event::Host(HostSample {
                ts_us: i as i64,
                load1: 0.0,
                load5: 0.0,
                load15: 0.0,
            })));
        }
        assert_eq!(log.events.len(), EVENT_CAP);
        // The 50 oldest were dropped, so the front is now ts=50.
        assert_eq!(log.events.front().unwrap().ts_us(), 50);
    }

    /// A live event clears any offline note; an offline message sets it.
    #[test]
    fn offline_state_tracks_connection() {
        let mut log = EventLog::new();
        log.apply(BridgeMsg::Offline("daemon down".to_string()));
        assert_eq!(log.offline.as_deref(), Some("daemon down"));

        log.apply(BridgeMsg::Event(Event::Host(HostSample {
            ts_us: 1,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        })));
        assert!(
            log.offline.is_none(),
            "an event marks the stream live again"
        );

        log.apply(BridgeMsg::Offline("closed".to_string()));
        log.apply(BridgeMsg::Online);
        assert!(log.offline.is_none(), "Online clears the offline note");
    }
}
