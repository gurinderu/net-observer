//! The **air map** window: the foreign access points this radio can hear, drawn
//! as bands on a channel axis, with our own association drawn underneath them.
//!
//! A map of its own, deliberately not a layer on the network map: that one shows
//! L2 devices, this one shows frequency bands, and mixing them hides the one
//! thing this map exists to show (realm net-observer, node #48).
//!
//! ## What this map is NOT
//!
//! It does not measure interference. macOS hands out no channel-occupancy (CCA /
//! airtime) figure to any process, so "that AP is eating my air" cannot be
//! observed here at all. What is computable is how far a foreign band overlaps
//! ours and how loud it arrives — a *hypothesis*, computed by
//! [`types::overlap_hypothesis`] and carrying its own confidence. The caveat is
//! rendered in the window, not just written here, and nothing in the drawing is
//! coloured by severity: the geometry makes the claim, so no element can read as
//! a measured quantity (realm net-observer, nodes #47 and #48).
//!
//! Foreign APs also carry **no BSSID** in the system report, so two APs on one
//! channel are indistinguishable between scans. Each scan is a slice; this window
//! therefore draws the latest slice only and never a history of "that neighbour".
//!
//! ## Where the data comes from
//!
//! The bar is a pure socket client and never touches the database. This window
//! opens ONE [`net_observer_ipc::Request::Subscribe`] stream filtered to
//! [`EventKind::Air`] and [`EventKind::Wifi`] — the air scan itself, and our own
//! association, which is what the overlap is computed against — and keeps only
//! the latest of each. The bridge (blocking socket thread → bounded channel →
//! gpui foreground drain) is the same shape as the event-log window's; see
//! [`crate::events`] for the reasoning behind it.
//!
//! ## SKIP, never silence
//!
//! Three states are distinguished, because collapsing them would be the exact
//! lie this daemon exists to avoid: no scan has arrived yet (the collector is off
//! by default), the scan ran and failed (`Skip` + its reason), and the scan ran
//! and heard nobody. Only the last one is empty air.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::Duration;

use gpui::prelude::*;
use gpui::{
    AnyWindowHandle, App, AsyncApp, Context, Entity, SharedString, Subscription, Timer,
    TitlebarOptions, Window, WindowBounds, WindowHandle, WindowKind, WindowOptions, div, px, rgb,
    rgba, size,
};

use net_observer_ipc::{Event, EventKind, StreamFrame, SubscriptionHandle};
use types::{
    AirObservation, AirSample, AirVerdict, Band, ChannelOverlapHypothesis, ChannelSpan,
    OverlapConfidence, WifiSample, WifiVerdict, overlap_hypothesis,
};

use crate::ui::{Glance, Theme};

/// How often the foreground bridge task drains the channel into the model. The
/// air scan is a slow period (seconds per scan), so this only has to feel prompt.
const DRAIN_POLL: Duration = Duration::from_millis(250);
/// How long the subscription thread waits before retrying a dropped stream.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Bridge depth. Small on purpose: only the LATEST sample of each kind is kept,
/// so a backlog has no value — dropping is as correct as queueing.
const BRIDGE_DEPTH: usize = 32;

/// Initial window size (resizable afterwards), gpui logical px.
const WIN_W: f32 = 620.0;
const WIN_H: f32 = 560.0;
/// Width of the drawn channel axis, px. Fixed so band placement is arithmetic on
/// a known width rather than a layout query.
const AXIS_W: f32 = 560.0;
/// Height of the lane a foreign AP is drawn in, and of our own band's lane.
const LANE_H: f32 = 18.0;
const OWN_LANE_H: f32 = 24.0;
/// How many foreign APs are drawn per band before the rest become a count.
const MAX_ROWS_PER_BAND: usize = 14;

/// A message from the subscription thread to the gpui bridge task.
#[derive(Debug)]
enum BridgeMsg {
    Frame(StreamFrame),
    /// The daemon is down or the stream dropped; the thread will retry.
    Offline(String),
}

/// The window-scoped cancellation cell shared with the subscription thread.
///
/// Same reasoning as [`crate::events`]: the thread parks in a blocking read that
/// dropping the receiver cannot interrupt, so closing the window both latches a
/// flag and shuts the live socket down underneath the read.
#[derive(Default)]
struct Shutdown {
    stop: AtomicBool,
    handle: Mutex<Option<SubscriptionHandle>>,
}

impl Shutdown {
    fn trip(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.lock().take() {
            handle.close();
        }
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Publish the live subscription's handle; `false` means the window closed
    /// while we were connecting and the fresh socket was closed here instead.
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

    fn disarm(&self) {
        *self.lock() = None;
    }

    fn lock(&self) -> MutexGuard<'_, Option<SubscriptionHandle>> {
        self.handle.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The shared, window-scoped model: the latest air scan, the latest own
/// association, and the connection state.
///
/// Only the latest of each is kept — a foreign AP cannot be followed between
/// scans (no BSSID), so a backlog of scans would be a series of unrelated
/// slices, not a history.
#[derive(Debug, Default)]
pub(crate) struct AirFeed {
    air: Option<AirSample>,
    own: Option<WifiSample>,
    /// `Some(reason)` while disconnected / reconnecting; `None` when live.
    offline: Option<SharedString>,
    /// Whether the daemon reported collection paused. A pause explains an air
    /// map that stops updating, so it is said rather than left to be inferred.
    paused: bool,
}

impl AirFeed {
    fn apply(&mut self, msg: BridgeMsg) {
        match msg {
            BridgeMsg::Frame(frame) => {
                self.offline = None;
                match frame {
                    StreamFrame::Event(Event::Air(a)) => self.air = Some(a),
                    StreamFrame::Event(Event::Wifi(w)) => self.own = Some(w),
                    StreamFrame::Ready(r) => self.paused = !r.observing,
                    StreamFrame::Observing(e) => self.paused = !e.observing,
                    StreamFrame::Gap(_) | StreamFrame::Error(_) | StreamFrame::Event(_) => {}
                }
            }
            BridgeMsg::Offline(reason) => self.offline = Some(reason.into()),
        }
    }

    /// Our own channel, when the last Wi-Fi reading placed us on one. `None`
    /// means the overlap hypothesis cannot be computed at all — which the window
    /// says, instead of drawing foreign bands against an invisible reference.
    fn own_span(&self) -> Option<ChannelSpan> {
        let w = self.own.as_ref()?;
        if w.wifi != WifiVerdict::Ok {
            return None;
        }
        ChannelSpan::new(w.channel, w.channel_band.as_deref(), w.channel_width_mhz)
    }
}

/// One foreign AP prepared for drawing: where it sits, how it was heard, and the
/// overlap hypothesis against our own band (absent when we have no own band).
#[derive(Debug, Clone)]
struct Lane {
    span: ChannelSpan,
    rssi_dbm: Option<i32>,
    phy_mode: Option<String>,
    security: Option<String>,
    hypothesis: Option<ChannelOverlapHypothesis>,
}

/// One band's worth of the map: the axis it is drawn on, our own band if we are
/// on this one, and the foreign lanes over it.
///
/// Bands are separate sections and never share an axis: 2.4, 5 and 6 GHz are not
/// commensurable, and one axis across them would place neighbours that cannot
/// touch on top of each other (realm net-observer, node #48).
#[derive(Debug)]
struct BandGroup {
    band: Band,
    own: Option<ChannelSpan>,
    lanes: Vec<Lane>,
    /// Lanes beyond [`MAX_ROWS_PER_BAND`], reported as a count.
    dropped: usize,
}

/// Group one scan into per-band sections, ranked by the overlap hypothesis.
///
/// Ordering is [`ChannelOverlapHypothesis::rank_key`] — overlap first, loudness
/// second — so no composite "interference score" is invented here. Without an
/// own band there is no hypothesis to rank by, and lanes fall back to loudest
/// first, which is a property of the reading rather than a claim about us.
fn group(sample: &AirSample, own: Option<ChannelSpan>) -> Vec<BandGroup> {
    let mut groups: Vec<BandGroup> = Vec::new();
    if let Some(own) = own {
        groups.push(BandGroup {
            band: own.band,
            own: Some(own),
            lanes: Vec::new(),
            dropped: 0,
        });
    }
    for ap in &sample.aps {
        let Some(span) = span_of(ap) else { continue };
        let hypothesis = own
            .filter(|o| o.band == span.band)
            .map(|o| overlap_hypothesis(&o, &span, ap.rssi_dbm));
        let lane = Lane {
            span,
            rssi_dbm: ap.rssi_dbm,
            phy_mode: ap.phy_mode.clone(),
            security: ap.security.clone(),
            hypothesis,
        };
        match groups.iter_mut().find(|g| g.band == span.band) {
            Some(g) => g.lanes.push(lane),
            None => groups.push(BandGroup {
                band: span.band,
                own: None,
                lanes: vec![lane],
                dropped: 0,
            }),
        }
    }
    for g in &mut groups {
        g.lanes.sort_by(|a, b| match (a.hypothesis, b.hypothesis) {
            (Some(x), Some(y)) => y.rank_key().cmp(&x.rank_key()),
            _ => b
                .rssi_dbm
                .unwrap_or(i32::MIN)
                .cmp(&a.rssi_dbm.unwrap_or(i32::MIN)),
        });
        if g.lanes.len() > MAX_ROWS_PER_BAND {
            g.dropped = g.lanes.len() - MAX_ROWS_PER_BAND;
            g.lanes.truncate(MAX_ROWS_PER_BAND);
        }
    }
    groups.sort_by_key(|g| g.band as u8);
    groups
}

/// Place one observation on the frequency axis, or `None` when the report gave
/// no channel and band to place it with.
fn span_of(ap: &AirObservation) -> Option<ChannelSpan> {
    ChannelSpan::new(ap.channel, ap.channel_band.as_deref(), ap.channel_width_mhz)
}

/// The frequency window a band's section is drawn across: the union of every
/// span in it, padded so an edge band is not flush against the frame.
///
/// Returns `None` when nothing in the group could be placed on the axis at all.
fn axis_range(group: &BandGroup) -> Option<(f64, f64)> {
    let mut lo = f64::MAX;
    let mut hi = f64::MIN;
    let spans = group
        .own
        .iter()
        .chain(group.lanes.iter().map(|l| &l.span))
        .copied();
    for s in spans {
        if let Some(e) = s.frequency_extent() {
            lo = lo.min(e.lo_mhz);
            hi = hi.max(e.hi_mhz);
        }
    }
    if lo > hi {
        return None;
    }
    // A single 20 MHz span would otherwise fill the axis edge to edge and read
    // as "the whole band"; the pad keeps the drawing honest about scale.
    let pad = ((hi - lo) * 0.08).max(10.0);
    Some((lo - pad, hi + pad))
}

/// Where a span is drawn inside an axis: `(left_px, width_px)`, clamped to the
/// axis so a partly out-of-range span is still visible at the edge.
fn place(span: ChannelSpan, axis: (f64, f64)) -> Option<(f32, f32)> {
    let e = span.frequency_extent()?;
    let (lo, hi) = axis;
    let width = hi - lo;
    if width <= 0.0 {
        return None;
    }
    let to_px = |mhz: f64| (((mhz - lo) / width) * f64::from(AXIS_W)).clamp(0.0, f64::from(AXIS_W));
    let left = to_px(e.lo_mhz);
    // A 1.5 px floor: a span narrower than a pixel must still be drawn, or a
    // real neighbour would vanish from the map at some zoom levels.
    let w = (to_px(e.hi_mhz) - left).max(1.5);
    #[allow(clippy::cast_possible_truncation)]
    Some((left as f32, w as f32))
}

/// How loud a foreign AP arrives, as an opacity in `0.20..=0.85`.
///
/// A rendering of the reported RSSI and nothing else: `-90 dBm` is barely there,
/// `-35 dBm` is next door. An AP whose signal was not reported gets the floor,
/// and its label says the signal is unknown rather than letting a faint bar be
/// read as a weak one.
fn weight(rssi_dbm: Option<i32>) -> f32 {
    let Some(rssi) = rssi_dbm else { return 0.20 };
    let t = ((f64::from(rssi) + 90.0) / 55.0).clamp(0.0, 1.0);
    #[allow(clippy::cast_possible_truncation)]
    {
        (0.25 + t * 0.60) as f32
    }
}

/// Pack an `0xRRGGBB` ink and an opacity into gpui's `0xRRGGBBAA`.
fn with_alpha(color: u32, alpha: f32) -> u32 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let a = (alpha.clamp(0.0, 1.0) * 255.0) as u32;
    (color << 8) | a
}

/// The human label for a confidence level — always phrased as a belief.
fn confidence_label(c: OverlapConfidence) -> &'static str {
    match c {
        OverlapConfidence::Low => "low confidence (a channel width or bonding was assumed)",
        OverlapConfidence::Medium => "medium confidence (signal strength not reported)",
        OverlapConfidence::High => "high confidence (still a hypothesis, not a measurement)",
    }
}

fn band_label(b: Band) -> &'static str {
    match b {
        Band::TwoGhz => "2.4 GHz",
        Band::FiveGhz => "5 GHz",
        Band::SixGhz => "6 GHz",
    }
}

/// The one-line description of a foreign AP. Never a name: the report redacts
/// the SSID and carries no BSSID, so there is no identity to print.
fn lane_label(lane: &Lane) -> String {
    let mut s = format!("ch {} · {} MHz", lane.span.channel, lane.span.width_mhz);
    if lane.span.width_assumed {
        s.push_str(" (assumed)");
    }
    match lane.rssi_dbm {
        Some(r) => s.push_str(&format!(" · {r} dBm")),
        None => s.push_str(" · signal not reported"),
    }
    if let Some(phy) = &lane.phy_mode {
        s.push_str(&format!(" · {phy}"));
    }
    if let Some(sec) = &lane.security {
        s.push_str(&format!(" · {sec}"));
    }
    s
}

/// The overlap line under a lane: the hypothesis, said as a hypothesis.
fn overlap_label(lane: &Lane) -> String {
    match lane.hypothesis {
        None => "overlap not computable — this Mac's own channel is unknown".to_string(),
        Some(h) if h.overlap <= 0.0 => "no band overlap with our channel".to_string(),
        Some(h) => format!(
            "hypothesis: covers {:.0}% of our channel · {}",
            h.overlap * 100.0,
            confidence_label(h.confidence)
        ),
    }
}

/// The root view of the air-map window.
pub(crate) struct AirView {
    feed: Entity<AirFeed>,
    _observe: Subscription,
    /// Held so the release hook stays registered for the view's whole life.
    _release: Subscription,
}

impl AirView {
    fn new(feed: Entity<AirFeed>, shutdown: Arc<Shutdown>, cx: &mut Context<Self>) -> Self {
        let observe = cx.observe(&feed, |_this, _, cx| cx.notify());
        let release = cx.on_release(move |_view, _cx| shutdown.trip());
        Self {
            feed,
            _observe: observe,
            _release: release,
        }
    }
}

impl Render for AirView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let feed = self.feed.read(cx);
        let offline = feed.offline.clone();
        let paused = feed.paused;
        let own = feed.own_span();

        let body = match &feed.air {
            // No scan has arrived. NOT empty air: the air collector is off by
            // default, so this is the state the window must name outright.
            None => note(
                "No air scan yet.",
                "Nothing has been heard because nothing has scanned: the air collector is \
                 off by default, and a scan is a slow, separate period rather than a tick. \
                 This is not a reading of empty air.",
                theme.muted,
                theme,
            )
            .into_any_element(),
            // The scan ran and failed. Also not empty air.
            Some(a) if a.air == AirVerdict::Skip => note(
                "The last scan could not run.",
                &format!(
                    "SKIP: {}. The radio environment is unknown for this period — this is \
                     not a reading of empty air.",
                    a.reason.as_deref().unwrap_or("no reason reported")
                ),
                theme.warn,
                theme,
            )
            .into_any_element(),
            // The scan ran and heard nobody. This one IS empty air.
            Some(a) if a.aps.is_empty() => note(
                "The scan ran and heard no other access point.",
                "A real reading: nobody else was audible here.",
                theme.ok,
                theme,
            )
            .into_any_element(),
            Some(a) => {
                let mut col = div().flex().flex_col().gap_4().px_3().py_2();
                for g in group(a, own) {
                    col = col.child(band_section(&g, theme));
                }
                col.into_any_element()
            }
        };

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .child(header(own, paused, theme))
            .children(offline.map(|reason| {
                div()
                    .px_3()
                    .py_1()
                    .text_size(px(11.0))
                    .text_color(rgb(theme.warn))
                    .child(format!("offline: {reason}"))
            }))
            .child(separator(theme))
            .child(div().flex().flex_col().flex_1().child(body))
    }
}

/// The window header: what this map is, our own association, and the caveat that
/// governs every number below it (realm net-observer, node #48).
fn header(own: Option<ChannelSpan>, paused: bool, theme: Theme) -> impl IntoElement {
    let own_line = match own {
        Some(s) => format!(
            "this Mac: {} · ch {} · {} MHz{}",
            band_label(s.band),
            s.channel,
            s.width_mhz,
            if s.width_assumed { " (assumed)" } else { "" }
        ),
        None => "this Mac: not associated, or the channel was not reported".to_string(),
    };
    div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .py_2()
        .child(
            div()
                .text_size(px(14.0))
                .text_color(rgb(theme.fg))
                .child("Air map"),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(own_line),
        )
        // The epistemic boundary, stated in the window and not only in the docs.
        .child(div().text_size(px(11.0)).text_color(rgb(theme.warn)).child(
            "Overlap is a HYPOTHESIS about where the bands sit, not measured \
                     interference: macOS reports channel occupancy (CCA / airtime) to \
                     nobody. Foreign APs carry no BSSID, so this is one slice — the same \
                     AP cannot be followed between scans.",
        ))
        .children(paused.then(|| {
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child("Collection is paused — this slice will not update.")
        }))
}

/// One band's section: its own axis, our band drawn on it, and the foreign bands
/// over it.
fn band_section(group: &BandGroup, theme: Theme) -> impl IntoElement + use<> {
    let Some(axis) = axis_range(group) else {
        return div()
            .text_size(px(11.0))
            .text_color(rgb(theme.muted))
            .child(format!(
                "{}: nothing could be placed on the axis",
                band_label(group.band)
            ))
            .into_any_element();
    };

    let mut section = div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_size(px(12.0))
                .text_color(rgb(theme.fg))
                .child(band_label(group.band)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(rgb(theme.muted))
                .child(format!("{:.0}–{:.0} MHz", axis.0, axis.1)),
        );

    // Our own band first, as the reference every lane above it is placed against.
    section = section.child(match group.own.and_then(|s| place(s, axis)) {
        Some((left, w)) => div()
            .relative()
            .w(px(AXIS_W))
            .h(px(OWN_LANE_H))
            .child(
                div()
                    .absolute()
                    .left(px(left))
                    .top(px(2.0))
                    .w(px(w))
                    .h(px(OWN_LANE_H - 4.0))
                    .rounded_md()
                    .bg(rgb(theme.accent)),
            )
            .into_any_element(),
        None => div()
            .text_size(px(11.0))
            .text_color(rgb(theme.muted))
            .child("our own channel is not on this band")
            .into_any_element(),
    });

    for lane in &group.lanes {
        section = section.child(lane_row(lane, axis, theme));
    }
    if group.dropped > 0 {
        section = section.child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(format!("+{} more heard, not drawn", group.dropped)),
        );
    }
    section.into_any_element()
}

/// One foreign AP: its band drawn over the axis, then its label and the overlap
/// hypothesis. The bar's ink is one neutral colour at an opacity set by signal
/// strength — deliberately not a severity palette, which would read as a
/// measured verdict about interference.
fn lane_row(lane: &Lane, axis: (f64, f64), theme: Theme) -> impl IntoElement + use<> {
    let bar = match place(lane.span, axis) {
        Some((left, w)) => div()
            .relative()
            .w(px(AXIS_W))
            .h(px(LANE_H))
            .child(
                div()
                    .absolute()
                    .left(px(left))
                    .top(px(3.0))
                    .w(px(w))
                    .h(px(LANE_H - 6.0))
                    .rounded_sm()
                    .bg(rgba(with_alpha(theme.fg, weight(lane.rssi_dbm)))),
            )
            .into_any_element(),
        None => div().h(px(LANE_H)).into_any_element(),
    };
    div()
        .flex()
        .flex_col()
        .child(bar)
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.fg))
                .child(lane_label(lane)),
        )
        .child(
            div()
                .text_size(px(10.0))
                .text_color(rgb(theme.muted))
                .child(overlap_label(lane)),
        )
}

/// A stated state of the map: a headline in a semantic colour and the sentence
/// that keeps it from being read as empty air.
fn note(head: &str, body: &str, color: u32, theme: Theme) -> impl IntoElement + use<> {
    div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .py_3()
        .child(
            div()
                .text_size(px(13.0))
                .text_color(rgb(color))
                .child(head.to_string()),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(body.to_string()),
        )
}

fn separator(theme: Theme) -> impl IntoElement {
    div().h(px(1.0)).w_full().bg(rgb(theme.separator))
}

/// Open the air map, or focus it if it is already open. Mirrors
/// [`crate::events::open_or_focus`]; a failed open is logged, never fatal.
pub(crate) fn open_or_focus(cx: &mut App, glance: &Entity<Glance>, socket_path: String) {
    if let Some(existing) = glance.read(cx).air_window
        && existing
            .update(cx, |_view, window, _cx| window.activate_window())
            .is_ok()
    {
        cx.activate(true);
        return;
    }
    if let Some(handle) = open_window(cx, socket_path) {
        let any: AnyWindowHandle = handle.into();
        glance.update(cx, |g, _| g.air_window = Some(any));
        cx.activate(true);
    }
}

/// Create the air-map window and wire its subscription bridge.
fn open_window(cx: &mut App, socket_path: String) -> Option<WindowHandle<AirView>> {
    let feed = cx.new(|_| AirFeed::default());
    let (tx, rx) = mpsc::sync_channel::<BridgeMsg>(BRIDGE_DEPTH);
    let shutdown = Arc::new(Shutdown::default());

    let thread_shutdown = Arc::clone(&shutdown);
    if let Err(e) = thread::Builder::new()
        .name("observer-air".to_string())
        .spawn(move || run_subscription(&socket_path, &tx, &thread_shutdown))
    {
        eprintln!("net-observer-bar: failed to spawn air subscription thread: {e}");
    }

    let weak = feed.downgrade();
    cx.spawn(async move |acx: &mut AsyncApp| {
        loop {
            Timer::after(DRAIN_POLL).await;
            let mut batch = Vec::new();
            let mut disconnected = false;
            loop {
                match rx.try_recv() {
                    Ok(msg) => batch.push(msg),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
            let alive = weak.update(acx, |feed, cx| {
                if !batch.is_empty() {
                    for msg in batch {
                        feed.apply(msg);
                    }
                    cx.notify();
                }
            });
            if alive.is_err() {
                break; // window closed or app shutting down
            }
            if disconnected {
                let _ = weak.update(acx, |feed, cx| {
                    feed.apply(BridgeMsg::Offline("air bridge stopped".to_string()));
                    cx.notify();
                });
                break;
            }
        }
    })
    .detach();

    let options = window_options(cx);
    match cx.open_window(options, move |_window, cx| {
        cx.new(|cx| AirView::new(feed, shutdown, cx))
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("net-observer-bar: failed to open air window: {e}");
            None
        }
    }
}

fn window_options(cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(WIN_W), px(WIN_H)), cx)),
        titlebar: Some(TitlebarOptions {
            title: Some(SharedString::from("net-observer — air")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        kind: WindowKind::Normal,
        is_movable: true,
        is_resizable: true,
        is_minimizable: true,
        focus: true,
        show: true,
        window_min_size: Some(size(px(380.0), px(260.0))),
        ..Default::default()
    }
}

/// The subscription thread body: hold one air+wifi subscription open, forward
/// every frame, and reconnect after [`RECONNECT_DELAY`] when the stream drops.
///
/// The filter is server-side and deliberately narrow: this window renders one
/// slice of the radio environment and our own association, and nothing else on
/// the bus concerns it. Stream-integrity frames (gap, observing, error) are
/// delivered regardless of the filter by the daemon's own rule.
fn run_subscription(sock_path: &str, tx: &mpsc::SyncSender<BridgeMsg>, shutdown: &Shutdown) {
    let kinds = [EventKind::Air, EventKind::Wifi];
    loop {
        if shutdown.stopped() {
            return;
        }
        match net_observer_ipc::subscribe(sock_path, Some(&kinds)) {
            Ok(sub) => {
                if !shutdown.arm(sub.handle().ok()) {
                    return; // the window closed while we were connecting
                }
                // The ack carries the daemon's collection state, which is what
                // tells the window a stalled map is a pause and not a hang.
                let ready = BridgeMsg::Frame(StreamFrame::Ready(sub.ready().clone()));
                if !bridge_send(tx, ready) {
                    return;
                }
                let mut reason = "connection closed".to_string();
                for item in sub {
                    match item {
                        Ok(frame) => {
                            if !bridge_send(tx, BridgeMsg::Frame(frame)) {
                                return;
                            }
                        }
                        Err(e) => {
                            reason = format!("stream error: {e}");
                            break;
                        }
                    }
                }
                shutdown.disarm();
                if !bridge_send(tx, BridgeMsg::Offline(reason)) {
                    return;
                }
            }
            Err(e) => {
                if !bridge_send(tx, BridgeMsg::Offline(e.to_string())) {
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

/// Forward one message; `false` means the receiver is gone and the caller must
/// stop.
///
/// A full bridge drops the message rather than blocking the reader: only the
/// latest sample of each kind is ever rendered, so a queued backlog would be
/// discarded on arrival anyway.
fn bridge_send(tx: &mpsc::SyncSender<BridgeMsg>, msg: BridgeMsg) -> bool {
    match tx.try_send(msg) {
        Ok(()) | Err(mpsc::TrySendError::Full(_)) => true,
        Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_observer_ipc::Ready;
    use types::{ObservingCause, ObservingEdge};

    fn ap(channel: i32, band: &str, width: Option<i32>, rssi: Option<i32>) -> AirObservation {
        AirObservation {
            channel: Some(channel),
            channel_band: Some(band.to_string()),
            channel_width_mhz: width,
            rssi_dbm: rssi,
            ..Default::default()
        }
    }

    fn scan(aps: Vec<AirObservation>) -> AirSample {
        AirSample {
            ts_us: 1,
            air: AirVerdict::Ok,
            reason: None,
            aps,
        }
    }

    fn own(channel: i32, band: &str, width: i32) -> ChannelSpan {
        ChannelSpan::new(Some(channel), Some(band), Some(width)).unwrap()
    }

    /// Bands are separate sections: a 2.4 GHz neighbour never lands on the 5 GHz
    /// axis, where the drawing would place it next to channels it cannot touch.
    #[test]
    fn bands_are_grouped_separately() {
        let s = scan(vec![
            ap(6, "2ghz", Some(20), Some(-50)),
            ap(36, "5ghz", Some(80), Some(-60)),
            ap(37, "6ghz", Some(80), Some(-70)),
        ]);
        let groups = group(&s, Some(own(36, "5ghz", 80)));
        assert_eq!(groups.len(), 3);
        let bands: Vec<Band> = groups.iter().map(|g| g.band).collect();
        assert_eq!(bands, vec![Band::TwoGhz, Band::FiveGhz, Band::SixGhz]);
        // Our own band is marked on exactly the group it belongs to.
        assert!(groups.iter().filter(|g| g.own.is_some()).count() == 1);
        assert!(
            groups
                .iter()
                .find(|g| g.band == Band::FiveGhz)
                .unwrap()
                .own
                .is_some()
        );
    }

    /// Our own band gets a section even when nobody else is on it — the map must
    /// show where we sit, not only who else is around.
    #[test]
    fn own_band_is_shown_even_with_no_neighbour_on_it() {
        let groups = group(
            &scan(vec![ap(6, "2ghz", Some(20), Some(-50))]),
            Some(own(36, "5ghz", 80)),
        );
        let five = groups.iter().find(|g| g.band == Band::FiveGhz).unwrap();
        assert!(five.own.is_some());
        assert!(five.lanes.is_empty());
    }

    /// Ranking is the hypothesis's own key (overlap, then loudness) — the loud
    /// neighbour on a disjoint block must not outrank the quiet one on ours.
    #[test]
    fn lanes_rank_by_overlap_then_signal() {
        let s = scan(vec![
            ap(44, "5ghz", Some(80), Some(-40)), // loud, disjoint block
            ap(56, "5ghz", Some(80), Some(-85)), // quiet, our block
        ]);
        let groups = group(&s, Some(own(56, "5ghz", 80)));
        let five = groups.iter().find(|g| g.band == Band::FiveGhz).unwrap();
        assert_eq!(five.lanes[0].span.channel, 56);
        assert!(five.lanes[0].hypothesis.unwrap().overlap > 0.0);
        assert_eq!(five.lanes[1].hypothesis.unwrap().overlap, 0.0);
    }

    /// Without an own association there is no overlap to hypothesise about, and
    /// the lane says so instead of showing a fabricated zero.
    #[test]
    fn no_own_channel_means_no_overlap_claim() {
        let groups = group(&scan(vec![ap(36, "5ghz", Some(80), Some(-60))]), None);
        let lane = &groups[0].lanes[0];
        assert!(lane.hypothesis.is_none());
        assert!(overlap_label(lane).contains("not computable"));
    }

    /// An AP the report could not place (no channel) is dropped rather than
    /// drawn somewhere invented.
    #[test]
    fn unplaceable_aps_are_not_drawn() {
        let mut a = ap(36, "5ghz", Some(80), Some(-60));
        a.channel = None;
        let groups = group(&scan(vec![a]), Some(own(36, "5ghz", 80)));
        assert!(groups.iter().all(|g| g.lanes.is_empty()));
    }

    /// The drawing places a span inside the axis, and a narrower channel is
    /// drawn narrower than a wider one on the same axis.
    #[test]
    fn placement_is_inside_the_axis_and_proportional() {
        let g = BandGroup {
            band: Band::FiveGhz,
            own: Some(own(36, "5ghz", 80)),
            lanes: vec![Lane {
                span: own(149, "5ghz", 20),
                rssi_dbm: Some(-60),
                phy_mode: None,
                security: None,
                hypothesis: None,
            }],
            dropped: 0,
        };
        let axis = axis_range(&g).unwrap();
        let (wide_left, wide_w) = place(own(36, "5ghz", 80), axis).unwrap();
        let (narrow_left, narrow_w) = place(own(149, "5ghz", 20), axis).unwrap();
        assert!(wide_w > narrow_w);
        assert!(wide_left < narrow_left, "36 sits left of 149");
        for (l, w) in [(wide_left, wide_w), (narrow_left, narrow_w)] {
            assert!(l >= 0.0 && l + w <= AXIS_W + 0.01, "{l} + {w}");
        }
    }

    /// Signal strength is the only thing the bar's weight encodes, and an
    /// unreported signal gets the floor rather than a plausible middle.
    #[test]
    fn weight_tracks_signal_and_floors_the_unknown() {
        assert!(weight(Some(-40)) > weight(Some(-80)));
        assert!(weight(None) <= weight(Some(-90)));
        for r in [-120, -90, -60, -30, 0] {
            let w = weight(Some(r));
            assert!((0.20..=0.90).contains(&w), "{r} → {w}");
        }
    }

    /// Every overlap sentence names itself a hypothesis or denies the claim —
    /// none of them can be read as a measurement of interference.
    #[test]
    fn overlap_sentences_never_assert_measured_interference() {
        let lane = |ch: i32| Lane {
            span: own(ch, "5ghz", 80),
            rssi_dbm: Some(-60),
            phy_mode: None,
            security: None,
            hypothesis: Some(overlap_hypothesis(
                &own(36, "5ghz", 80),
                &own(ch, "5ghz", 80),
                Some(-60),
            )),
        };
        let on = overlap_label(&lane(36));
        assert!(on.starts_with("hypothesis:"), "{on}");
        assert!(on.contains("confidence"), "{on}");
        let off = overlap_label(&lane(149));
        assert!(off.contains("no band overlap"), "{off}");
    }

    /// A foreign AP has no name and no BSSID, so no label may print one.
    #[test]
    fn lane_labels_carry_no_identity() {
        let l = Lane {
            span: own(36, "5ghz", 80),
            rssi_dbm: None,
            phy_mode: Some("802.11ax".to_string()),
            security: Some("wpa2_personal".to_string()),
            hypothesis: None,
        };
        let s = lane_label(&l);
        assert!(s.contains("ch 36"));
        assert!(s.contains("signal not reported"));
    }

    /// The feed keeps the latest of each kind and nothing else: a scan is a
    /// slice, and stacking slices would imply a history no BSSID supports.
    #[test]
    fn feed_keeps_only_the_latest_slice_and_own_reading() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Air(scan(
            vec![ap(36, "5ghz", Some(80), Some(-60))],
        )))));
        feed.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Air(scan(
            vec![],
        )))));
        assert!(feed.air.as_ref().unwrap().aps.is_empty());
        assert!(feed.own_span().is_none());

        feed.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Wifi(
            WifiSample {
                ts_us: 2,
                wifi: WifiVerdict::Ok,
                reason: None,
                rssi_dbm: Some(-55),
                noise_dbm: Some(-90),
                snr_db: Some(35),
                tx_rate_mbps: None,
                phy_mode: None,
                channel: Some(56),
                channel_width_mhz: Some(80),
                channel_band: Some("5ghz".to_string()),
            },
        ))));
        let own = feed.own_span().unwrap();
        assert_eq!(own.channel, 56);
        assert_eq!(own.band, Band::FiveGhz);
    }

    /// A SKIPped Wi-Fi reading places us nowhere — it must not be turned into an
    /// own channel the overlap would then be computed against.
    #[test]
    fn a_skipped_wifi_reading_gives_no_own_channel() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Wifi(
            WifiSample {
                ts_us: 2,
                wifi: WifiVerdict::Skip,
                reason: Some("radio off".to_string()),
                rssi_dbm: None,
                noise_dbm: None,
                snr_db: None,
                tx_rate_mbps: None,
                phy_mode: None,
                channel: Some(56),
                channel_width_mhz: Some(80),
                channel_band: Some("5ghz".to_string()),
            },
        ))));
        assert!(feed.own_span().is_none());
    }

    /// A pause is carried by the ack and by the transition frame, so a map that
    /// stops updating can say why.
    #[test]
    fn pause_state_comes_from_the_stream() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Frame(StreamFrame::Ready(Ready {
            ts_us: 1,
            kinds: None,
            observing: false,
        })));
        assert!(feed.paused);
        feed.apply(BridgeMsg::Frame(StreamFrame::Observing(ObservingEdge {
            ts_us: 2,
            observing: true,
            peer_uid: Some(501),
            cause: ObservingCause::Control,
        })));
        assert!(!feed.paused);
    }

    /// Any frame clears the offline note, and an offline message survives until
    /// one arrives.
    #[test]
    fn offline_is_cleared_by_the_next_frame() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Offline("daemon down".to_string()));
        assert!(feed.offline.is_some());
        feed.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Air(scan(
            vec![],
        )))));
        assert!(feed.offline.is_none());
    }
}
