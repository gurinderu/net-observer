//! The realtime **event-log window** — a resizable, closable
//! [`WindowKind::Normal`] window that shows live events (samples + incidents) as
//! they happen, pushed over the daemon's local socket (pub/sub, never polling).
//!
//! ## Push, not poll
//!
//! `net-observerd` runs an internal broadcast bus and answers a held-open
//! [`net_observer_ipc::Request::Subscribe`] by writing a mandatory
//! [`StreamFrame::Ready`] ack — created *after* its bus receiver exists, so
//! nothing published once the subscription is up can be lost — and then
//! streaming newline-JSON [`StreamFrame`]s until the client disconnects. This
//! window opens **one** persistent subscription for its whole lifetime — it
//! never re-subscribes and never polls.
//!
//! ## Everything the stream says is a row
//!
//! The stream is no longer "naturally quiet when paused": a pause is an explicit
//! [`StreamFrame::Observing`] frame, a subscriber that fell behind the bus gets a
//! [`StreamFrame::Gap`], and a daemon-side refusal (e.g. the subscriber cap)
//! arrives in band as [`StreamFrame::Error`] instead of a bare close. All of
//! them become visible rows, so a silence in the list is never something the
//! window knows about but does not say.
//!
//! ## The bridge (blocking socket → gpui model)
//!
//! [`net_observer_ipc`] is deliberately tokio-free: [`net_observer_ipc::subscribe`] is a
//! blocking iterator over a plain `UnixStream`. So a dedicated OS thread
//! ([`run_subscription`]) drives it, forwarding each frame down a **bounded**
//! `mpsc` channel as a [`BridgeMsg`]. The bound is deliberate — the reader drains
//! the socket at full speed while the drain runs only every [`DRAIN_POLL`], so the
//! bridge is lossy under load: overflow frames are dropped and reported as a
//! count, never queued without limit. A gpui foreground task drains that channel
//! into the shared [`EventLog`] model (a capped [`VecDeque`] of the last
//! [`EVENT_CAP`] [`Row`]s), and the [`EventLogView`] observes the model and
//! re-renders. The task holds only a [`gpui::WeakEntity`], so closing the window
//! drops the model and ends the task; the thread is stopped explicitly by the
//! [`Shutdown`] cell (it is parked in a blocking read and cannot notice the
//! receiver going away on its own). On disconnect / daemon-down the thread
//! surfaces an "offline" note and retries the subscription; it never panics.
//!
//! ## Filtering
//!
//! The subscription is always for **all** kinds (`kinds: None`); the type selector
//! at the top filters the displayed rows client-side by [`EventKind`], so changing
//! it never touches the socket. Stream-integrity frames (the ack, gaps, observing
//! transitions, daemon errors) carry no [`EventKind`] and are **never** filtered
//! out, mirroring the daemon's own always-delivered rule: a subscriber filtered to
//! `link` that never learns collection was paused would render a silence it cannot
//! explain.
//!
//! ## Rendering
//!
//! Every non-empty drain re-renders, so nothing per-frame may be paid per frame:
//! each [`StreamFrame`] is formatted into a [`Row`] of [`SharedString`]s **once**,
//! on arrival, and the list is a [`uniform_list`] over the filtered indices, so
//! only the visible rows are built.

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;

use gpui::prelude::*;
use gpui::{
    AnyWindowHandle, App, AsyncApp, Context, Entity, ScrollStrategy, SharedString, Subscription,
    Timer, TitlebarOptions, UniformListScrollHandle, Window, WindowBounds, WindowHandle,
    WindowKind, WindowOptions, div, px, rgb, size, uniform_list,
};

use net_observer_ipc::{Event, EventKind, StreamFrame, SubscriptionHandle};

use crate::ui::{Glance, Theme, separator};

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
#[derive(Debug)]
enum BridgeMsg {
    /// One decoded frame from the daemon — the opening ack, an event, a gap, an
    /// observing transition, or a server-side error. All five become rows, so a
    /// hole in the stream and a pause are visible in the log rather than
    /// inferred from silence.
    Frame(StreamFrame),
    /// The daemon is down or the stream dropped; the thread will retry.
    Offline(String),
}

/// The window-scoped cancellation cell shared with the subscription thread.
///
/// The thread spends nearly all of its life parked in a blocking `read(2)` on the
/// subscription socket, so dropping the bridge receiver cannot stop it — it would
/// only notice on the next frame, which on a quiet (or paused) daemon may never
/// come. [`Shutdown::trip`] therefore does two things: it latches a flag the
/// reconnect loop checks, and it shuts the live socket down underneath the parked
/// read so it returns immediately.
#[derive(Default)]
struct Shutdown {
    stop: AtomicBool,
    /// The live subscription's handle, published by the thread after each
    /// successful `subscribe` so [`Shutdown::trip`] can reach it.
    handle: Mutex<Option<SubscriptionHandle>>,
}

impl Shutdown {
    /// Stop the subscription thread: latch the flag, then close the live socket.
    fn trip(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.lock().take() {
            handle.close();
        }
    }

    /// Whether [`Shutdown::trip`] has been called (the window closed).
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Publish the live subscription's handle. Returns `false` if the window
    /// closed while we were connecting — the fresh socket is closed here rather
    /// than stored, because the [`Shutdown::trip`] that raced us is already gone.
    fn arm(&self, handle: Option<SubscriptionHandle>) -> bool {
        let mut slot = self.lock();
        if self.stopped() {
            if let Some(handle) = handle {
                handle.close();
            }
            *slot = None;
            return false;
        }
        *slot = handle;
        true
    }

    /// Drop the handle of a stream that has already ended (releases its fd).
    fn disarm(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> MutexGuard<'_, Option<SubscriptionHandle>> {
        // A panic elsewhere must never wedge the shutdown path.
        self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One retained frame, already rendered to text.
///
/// Formatting happens once, when the frame arrives, so a render is a refcount
/// clone of two [`SharedString`]s rather than two fresh allocations per row per
/// frame. The raw timestamp is not kept: [`Row::clock`] is the only form anything
/// here renders.
#[derive(Debug)]
struct Row {
    /// `Some(kind)` for a collector/incident event — what the chip filter
    /// matches. `None` for a stream-integrity frame (ack / gap / observing /
    /// error), which is never filtered out, mirroring the daemon's
    /// always-delivered rule.
    kind: Option<EventKind>,
    /// Local `HH:MM:SS` wall clock (see [`clock`]).
    clock: SharedString,
    /// The one-line `"<label>  <detail>"` body (see [`format_frame`]).
    line: SharedString,
    /// Drawn in an attention colour: incidents, gaps and server errors.
    alert: bool,
}

impl Row {
    fn new(f: &StreamFrame) -> Self {
        Self {
            kind: f.event_kind(),
            clock: clock(f.ts_us()).into(),
            line: format_frame(f).into(),
            alert: matches!(
                f,
                StreamFrame::Gap(_)
                    | StreamFrame::Error(_)
                    | StreamFrame::Unrecognized(_)
                    | StreamFrame::Event(Event::Incident(_))
            ),
        }
    }
}

/// Whether a row survives the client-side type filter.
///
/// The predicate the list render uses, kept as one named function so the rule —
/// a stream-integrity frame (`kind: None`) is admitted whatever the filter is —
/// is stated once and testable directly.
fn admits(filter: Option<EventKind>, row: &Row) -> bool {
    row.kind.is_none() || filter.is_none_or(|k| row.kind == Some(k))
}

/// The shared, window-scoped model: the capped live row list plus the current
/// connection state. Written by the bridge task, read by [`EventLogView`].
#[derive(Debug)]
pub(crate) struct EventLog {
    events: VecDeque<Row>,
    /// `Some(reason)` while disconnected / reconnecting; `None` when live.
    offline: Option<SharedString>,
}

impl EventLog {
    fn new() -> Self {
        Self {
            events: VecDeque::new(),
            offline: None,
        }
    }

    /// Apply one [`BridgeMsg`] to the model: append (and cap) a frame, or update
    /// the connection state. This is where a [`StreamFrame`] becomes a [`Row`] —
    /// the one place its text is formatted.
    ///
    /// Any frame clears the offline note: the stream's opening
    /// [`StreamFrame::Ready`] ack is what marks a (re)connection, so there is no
    /// separate "online" message to keep in step with it.
    fn apply(&mut self, msg: BridgeMsg) {
        match msg {
            BridgeMsg::Frame(frame) => {
                self.offline = None;
                if self.events.len() >= EVENT_CAP {
                    self.events.pop_front();
                }
                self.events.push_back(Row::new(&frame));
            }
            BridgeMsg::Offline(reason) => self.offline = Some(reason.into()),
        }
    }
}

/// The root view of the event-log window. Observes the shared [`EventLog`] and
/// re-renders on change; keeps the client-side type filter and the list's scroll
/// state.
pub(crate) struct EventLogView {
    log: Entity<EventLog>,
    /// The selected type filter; `None` = all kinds.
    filter: Option<EventKind>,
    scroll: UniformListScrollHandle,
    /// Set when the model changed (or the filter changed) so the next render
    /// autoscrolls to the tail; cleared once applied.
    want_scroll: bool,
    _observe: Subscription,
    /// Held so the release hook stays registered for the view's whole life
    /// (dropping a [`Subscription`] unregisters it).
    _release: Subscription,
}

impl EventLogView {
    fn new(log: Entity<EventLog>, shutdown: Arc<Shutdown>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&log, |this, _, cx| {
            this.want_scroll = true;
            cx.notify();
        });
        // Closing the window releases this view; that is the one point where we
        // can tell the blocking subscription thread to stop (see [`Shutdown`]).
        let release = cx.on_release(move |_view, _cx| shutdown.trip());
        Self {
            log,
            filter: None,
            scroll: UniformListScrollHandle::new(),
            want_scroll: true,
            _observe: observe,
            _release: release,
        }
    }
}

impl Render for EventLogView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let filter = self.filter;

        // Snapshot only what the frame needs — the offline note (a refcount bump)
        // and the indices the filter admits — then drop the model borrow before
        // touching `cx` mutably (the selector's listeners) or `self` (the scroll
        // handle). The rows themselves are built lazily, per *visible* index.
        let (offline, visible) = {
            let log = self.log.read(cx);
            let offline = log.offline.clone();
            let visible: Vec<usize> = log
                .events
                .iter()
                .enumerate()
                .filter(|(_, row)| admits(filter, row))
                .map(|(ix, _)| ix)
                .collect();
            (offline, visible)
        };

        let count = visible.len();

        // Autoscroll to the newest visible row when the model or filter changed.
        // The request is deferred to the list's next layout, which is why it can
        // be issued before the element exists.
        if self.want_scroll {
            if let Some(last) = count.checked_sub(1) {
                self.scroll.scroll_to_item(last, ScrollStrategy::Bottom);
            }
            self.want_scroll = false;
        }

        // Only the rows in `range` are ever built; `visible` maps a list index to
        // the model index behind it.
        let list = uniform_list(
            "event-list",
            count,
            cx.processor(move |this, range: Range<usize>, _window, cx| {
                let log = this.log.read(cx);
                range
                    .filter_map(|i| visible.get(i).and_then(|&ix| log.events.get(ix)))
                    .map(|row| event_row(row, theme))
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(self.scroll.clone())
        .flex_1()
        .px_3()
        .py_1();

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
            .child(list)
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

/// One event row: a muted local `HH:MM:SS` clock, then the one-line detail. Both
/// strings were formatted when the frame arrived (see [`Row`]), so this is two
/// refcount bumps. Rows the daemon flagged as needing attention — incidents, but
/// also stream gaps and server-side errors — are drawn in the "bad" color.
/// Single-line and uniform-height, which is what the [`uniform_list`] above
/// requires.
///
/// `use<>` (capture nothing) is load-bearing: both strings are *cloned* out of the
/// row, so the element holds no borrow of the model — but without precise capturing
/// the opaque type would still carry `row`'s lifetime, and the `uniform_list`
/// closure cannot return elements tied to the `&mut Context` it was handed.
fn event_row(row: &Row, theme: Theme) -> impl IntoElement + use<> {
    let value_color = if row.alert { theme.bad } else { theme.fg };
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
                .child(row.clock.clone()),
        )
        .child(
            div()
                .flex_1()
                .text_color(rgb(value_color))
                .text_size(px(12.0))
                .child(row.line.clone()),
        )
}

/// The "offline — reconnecting" banner shown while the subscription is down. The
/// reason is a [`SharedString`] held by the model, so re-rendering it is free.
fn offline_row(reason: SharedString, theme: Theme) -> impl IntoElement {
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
                .child(reason),
        )
}

/// Format one [`StreamFrame`] as its one-line log body: `"<label>  <detail>"`.
/// Both halves live on the wire types in [`net_observer_ipc`], so this window and the
/// CLI tail cannot drift apart. Pure over its input (no clock, no locale), so it is
/// unit-tested directly; the row renders the timestamp separately (see [`clock`]).
pub(crate) fn format_frame(f: &StreamFrame) -> String {
    format!("{}  {}", f.label(), f.detail())
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
pub(crate) fn open_or_focus(cx: &mut App, glance: &Entity<Glance>, socket_path: String) {
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
    // Bounded on purpose: the reader thread drains the socket at full speed while
    // the drain below runs only every DRAIN_POLL, and the model keeps just
    // EVENT_CAP events anyway. Overflow is dropped and counted (see `bridge_send`).
    let (tx, rx) = mpsc::sync_channel::<BridgeMsg>(EVENT_CAP);
    let shutdown = Arc::new(Shutdown::default());

    // Background OS thread: drive the blocking subscription; reconnect on drop.
    // Spawn failure is non-fatal — the window still opens (just without live data);
    // dropping `tx` with the closure disconnects the bridge, which the drain
    // reports below.
    let thread_shutdown = Arc::clone(&shutdown);
    if let Err(e) = thread::Builder::new()
        .name("observer-events".to_string())
        .spawn(move || run_subscription(&socket_path, &tx, &thread_shutdown))
    {
        eprintln!("net-observer-bar: failed to spawn events subscription thread: {e}");
    }

    // Foreground task: drain the channel into the model until the window closes
    // (the weak handle stops upgrading) or the app shuts down.
    let weak = log.downgrade();
    cx.spawn(async move |acx: &mut AsyncApp| {
        loop {
            Timer::after(DRAIN_POLL).await;
            let mut batch = Vec::new();
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(msg) => batch.push(msg),
                    Err(mpsc::TryRecvError::Empty) => break,
                    // The thread ended (or never started); nothing more will ever
                    // arrive, so this poll is the last one.
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
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
            if disconnected {
                // Say so rather than leaving an empty list looking live and idle.
                let _ = weak.update(acx, |log, cx| {
                    log.apply(BridgeMsg::Offline("event bridge stopped".to_string()));
                    cx.notify();
                });
                break;
            }
        }
    })
    .detach();

    let options = window_options(cx);
    match cx.open_window(options, move |_window, cx| {
        cx.new(|cx| EventLogView::new(log, shutdown, cx))
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("net-observer-bar: failed to open events window: {e}");
            None
        }
    }
}

/// Window options for the event log: a normal, resizable, closable window with a
/// native titlebar ("net-observer — events"), centered on the primary display.
fn window_options(cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(WIN_W), px(WIN_H)), cx)),
        titlebar: Some(TitlebarOptions {
            title: Some(SharedString::from("net-observer — events")),
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

/// The subscription thread body: hold one subscription (every kind) open, forward
/// every [`StreamFrame`] down `tx`, and reconnect (after [`RECONNECT_DELAY`])
/// whenever the daemon is down or the stream drops. Stops when `shutdown` is
/// tripped (the window closed) — or, if the receiver is already gone, on the next
/// frame it tries to forward. Never panics.
fn run_subscription(sock_path: &str, tx: &mpsc::SyncSender<BridgeMsg>, shutdown: &Shutdown) {
    // Frames dropped because the bridge was full, not yet reported to the model.
    let mut dropped: u64 = 0;
    loop {
        if shutdown.stopped() {
            return;
        }
        match net_observer_ipc::subscribe(sock_path, None) {
            Ok(sub) => {
                // Publish the handle before reading: a close arriving mid-stream
                // must be able to unblock the parked read below.
                if !shutdown.arm(sub.handle().ok()) {
                    return; // the window closed while we were connecting
                }
                // The ack the handshake already consumed is the (re)connection
                // marker — replayed as a row so the log opens by stating the
                // daemon's collection state, and so the model's offline note is
                // cleared by a frame rather than by a separate "online" message
                // that could disagree with the stream.
                let ready = BridgeMsg::Frame(StreamFrame::Ready(sub.ready().clone()));
                if !bridge_send(tx, ready, &mut dropped) {
                    return; // receiver gone — the window closed
                }
                // Why the stream ended, carried out of the loop: a protocol or
                // decode failure must not read as a clean daemon shutdown.
                let mut reason = "connection closed".to_string();
                for item in sub {
                    match item {
                        Ok(frame) => {
                            if !bridge_send(tx, BridgeMsg::Frame(frame), &mut dropped) {
                                return;
                            }
                        }
                        // `net_observer_ipc` funnels every non-EOF failure here
                        // (truncated frame, decode error, an error response
                        // mis-decoded as a frame), so keep the detail.
                        Err(e) => {
                            reason = format!("stream error: {e}");
                            break;
                        }
                    }
                }
                shutdown.disarm();
                if !bridge_send(tx, BridgeMsg::Offline(reason), &mut dropped) {
                    return;
                }
            }
            Err(e) => {
                // Daemon down / socket absent, or a daemon-side refusal of the
                // subscription itself (the subscriber cap), which `subscribe`
                // decodes out of the stream's error frame and reports here with
                // the daemon's own message. Surface it, then retry.
                if !bridge_send(tx, BridgeMsg::Offline(e.to_string()), &mut dropped) {
                    return;
                }
            }
        }
        if shutdown.stopped() {
            return;
        }
        thread::sleep(RECONNECT_DELAY);
    }
}

/// Forward one message over the bounded bridge; `false` means the receiver is gone
/// and the caller must stop.
///
/// A full channel means the foreground drain is behind, so the message is dropped
/// and counted rather than queued — the first send that fits again is preceded by
/// a note saying how many were lost.
fn bridge_send(tx: &mpsc::SyncSender<BridgeMsg>, msg: BridgeMsg, dropped: &mut u64) -> bool {
    if *dropped > 0 {
        let note = BridgeMsg::Offline(format!("{dropped} events dropped (UI behind)"));
        match tx.try_send(note) {
            Ok(()) => *dropped = 0,
            Err(mpsc::TrySendError::Full(_)) => {}
            Err(mpsc::TrySendError::Disconnected(_)) => return false,
        }
    }
    match tx.try_send(msg) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(_)) => {
            *dropped += 1;
            true
        }
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_observer_ipc::{Gap, IncidentSummary, Ready, StreamError, StreamErrorCode};
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, LinkSample, ObservingEdge, TcpVerdict,
    };

    /// A link event, the plainest filterable frame.
    fn link_event() -> Event {
        Event::Link(LinkSample {
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
        })
    }

    /// An incident event — the one event kind rendered as an alert.
    fn incident_event() -> Event {
        Event::Incident(IncidentSummary {
            id: "i1".into(),
            opened_us: 5,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        })
    }

    #[test]
    fn format_frame_renders_label_and_detail() {
        assert_eq!(
            format_frame(&StreamFrame::Event(link_event())),
            "link  gw=OK direct=FAIL"
        );

        let dns = Event::Dns(DnsSample {
            ts_us: 2,
            probe: "nks".into(),
            server: "sb".into(),
            verdict: DnsVerdict::FakeIp,
            ip: Some("198.18.0.1".into()),
            rtt_ms: None,
        });
        assert_eq!(
            format_frame(&StreamFrame::Event(dns)),
            "dns  nks/sb FAKEIP 198.18.0.1"
        );

        assert_eq!(
            format_frame(&StreamFrame::Event(incident_event())),
            "incident  wedge tun dead"
        );

        // Stream-integrity frames name themselves rather than borrowing a kind.
        assert_eq!(
            format_frame(&StreamFrame::Gap(Gap {
                ts_us: 3,
                skipped: 7
            })),
            "gap  7 events dropped (subscriber lagged)"
        );
        assert_eq!(
            format_frame(&StreamFrame::Observing(ObservingEdge {
                ts_us: 4,
                observing: false,
                peer_uid: Some(501),
                cause: types::ObservingCause::Control,
            })),
            "observing  collection off"
        );
        assert_eq!(
            format_frame(&StreamFrame::Error(StreamError {
                ts_us: 5,
                code: StreamErrorCode::TooManySubscribers,
                message: "subscriber limit reached (256 concurrent)".to_string(),
            })),
            "error  too-many-subscribers: subscriber limit reached (256 concurrent)"
        );
    }

    /// The live list is bounded: past [`EVENT_CAP`], the oldest events are dropped.
    #[test]
    fn event_log_caps_at_capacity() {
        let mut log = EventLog::new();
        for i in 0..(EVENT_CAP + 50) {
            log.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Host(
                HostSample {
                    ts_us: i as i64,
                    // Carried into the rendered line so the front row is
                    // identifiable (rows keep their formatted text, not the raw
                    // sample).
                    load1: i as f64,
                    load5: 0.0,
                    load15: 0.0,
                },
            ))));
        }
        assert_eq!(log.events.len(), EVENT_CAP);
        // The 50 oldest were dropped, so the front is now the i=50 event.
        assert_eq!(
            log.events.front().unwrap().line,
            "host  load 50.00/0.00/0.00"
        );
    }

    /// Rows are formatted once, on arrival: the model keeps the rendered strings
    /// and the kind the filter matches on, not the frame.
    #[test]
    fn apply_formats_the_row_once() {
        let mut log = EventLog::new();
        let frame = StreamFrame::Event(incident_event());
        log.apply(BridgeMsg::Frame(frame.clone()));

        let row = log.events.front().unwrap();
        assert_eq!(row.kind, Some(EventKind::Incident));
        assert_eq!(row.line, format_frame(&frame));
        assert_eq!(row.clock, clock(frame.ts_us()));
    }

    /// Any frame clears the offline note; an offline message sets it. The stream's
    /// opening `Ready` ack is what marks a reconnection — there is no separate
    /// "online" message that could disagree with the stream.
    #[test]
    fn offline_state_tracks_connection() {
        let mut log = EventLog::new();
        log.apply(BridgeMsg::Offline("daemon down".to_string()));
        // `SharedString` derefs to its inner `ArcCow`, not to `str`, so go through
        // `as_str` rather than `Option::as_deref`.
        assert_eq!(offline_note(&log), Some("daemon down"));

        log.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Host(
            HostSample {
                ts_us: 1,
                load1: 0.0,
                load5: 0.0,
                load15: 0.0,
            },
        ))));
        assert!(
            log.offline.is_none(),
            "an event marks the stream live again"
        );

        log.apply(BridgeMsg::Offline("closed".to_string()));
        log.apply(BridgeMsg::Frame(StreamFrame::Ready(Ready {
            ts_us: 2,
            kinds: None,
            observing: true,
        })));
        assert!(
            log.offline.is_none(),
            "the subscription ack clears the offline note"
        );
    }

    /// A stream-integrity frame carries no [`EventKind`] and is therefore admitted
    /// by every setting of the type filter — the daemon's always-delivered rule,
    /// mirrored client-side. A subscriber filtered to `link` that never learned the
    /// stream had a hole would render a silence it cannot explain.
    #[test]
    fn gap_frame_is_never_filtered_out() {
        let row = Row::new(&StreamFrame::Gap(Gap {
            ts_us: 9,
            skipped: 3,
        }));
        assert!(row.kind.is_none(), "a gap is not an event kind");

        for filter in [
            None,
            Some(EventKind::Link),
            Some(EventKind::Proxy),
            Some(EventKind::Dns),
            Some(EventKind::Route),
            Some(EventKind::Host),
            Some(EventKind::Incident),
        ] {
            assert!(admits(filter, &row), "a gap must survive filter {filter:?}");
        }

        // The filter still bites on real events.
        let link = Row::new(&StreamFrame::Event(link_event()));
        assert!(admits(Some(EventKind::Link), &link));
        assert!(!admits(Some(EventKind::Dns), &link));
    }

    /// The first row of a (re)connected log states whether the daemon is
    /// collecting, so a paused daemon reads as paused rather than as an idle one.
    #[test]
    fn ready_row_states_the_initial_collection_state() {
        let row = Row::new(&StreamFrame::Ready(Ready {
            ts_us: 1,
            kinds: None,
            observing: false,
        }));
        assert_eq!(row.line, "subscribed  collection off; kinds: all");
        assert!(row.kind.is_none());
        assert!(!row.alert, "an ack is not an alert");
    }

    /// Holes, daemon-side errors and incidents are the rows drawn in the attention
    /// colour; an ordinary sample is not.
    #[test]
    fn observing_and_error_frames_are_alert_rows() {
        let gap = Row::new(&StreamFrame::Gap(Gap {
            ts_us: 1,
            skipped: 2,
        }));
        assert!(gap.alert, "a hole in the stream must stand out");

        let err = Row::new(&StreamFrame::Error(StreamError {
            ts_us: 2,
            code: StreamErrorCode::TooManySubscribers,
            message: "subscriber limit reached (256 concurrent)".to_string(),
        }));
        assert!(err.alert, "a daemon-side refusal must stand out");

        let inc = Row::new(&StreamFrame::Event(incident_event()));
        assert!(inc.alert, "incidents keep their attention colour");

        let link = Row::new(&StreamFrame::Event(link_event()));
        assert!(!link.alert, "an ordinary sample is not an alert");

        // A pause is information, not an alarm: the daemon was asked to stop.
        let edge = Row::new(&StreamFrame::Observing(ObservingEdge {
            ts_us: 3,
            observing: false,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        }));
        assert!(!edge.alert);
        assert_eq!(edge.line, "observing  collection off");
    }

    /// A dead bridge (the reader thread ended, or never spawned) must show as
    /// offline rather than as a live, idle log — the drain's last act is this
    /// message.
    #[test]
    fn bridge_stop_shows_as_offline() {
        let mut log = EventLog::new();
        log.apply(BridgeMsg::Offline("event bridge stopped".to_string()));
        assert_eq!(offline_note(&log), Some("event bridge stopped"));
    }

    /// The model's offline note as a plain `&str`.
    fn offline_note(log: &EventLog) -> Option<&str> {
        log.offline.as_ref().map(SharedString::as_str)
    }
}
