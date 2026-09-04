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
//! ## Talking to a daemon older than this bar
//!
//! A daemon built before `EventKind::Air` existed cannot decode that filter and
//! rejects the WHOLE subscription — so a bar that just gave up would lose the
//! `Wifi` frames too, and could not even say what channel this Mac is on.
//! [`net_observer_ipc::subscribe_or_widen`] therefore retries unfiltered (a
//! request naming no kind at all, which no daemon can fail to read) and this
//! window filters client-side instead, exactly as the event log already does.
//!
//! The narrowing is remembered rather than swallowed: such a daemon cannot
//! collect the air at all, and the window says THAT instead of "no scan yet".
//!
//! ## SKIP, never silence
//!
//! Four states are distinguished, because collapsing them would be the exact
//! lie this daemon exists to avoid: this daemon cannot collect the air at all,
//! no scan has arrived yet (the collector is off by default), the scan ran and
//! failed (`Skip` + its reason), and the scan ran and heard nobody. Only the last
//! one is empty air.
//!
//! ## Scanning on demand
//!
//! "Scan now" sends [`ControlCmd::ScanAir`] — self-control, not acting: the
//! daemon reads its own radio's report and puts nothing on the air. The button
//! reports only what the daemon said: its refusal verbatim, or the fact that this
//! daemon does not know the command, which is a different statement from a
//! refusal.

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

use net_observer_ipc::{
    ControlCmd, ControlOutcome, Event, EventKind, StreamFrame, SubscriptionHandle,
};
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
    /// This daemon could not read our filter, so the subscription was widened to
    /// every kind and the air kinds are filtered here instead. It also means the
    /// daemon predates `EventKind::Air` and therefore cannot scan the air at all
    /// — a different fact from "no scan has happened yet". `false` on a
    /// subscription the daemon accepted as asked, so an upgraded daemon stops
    /// being reported as one that cannot scan.
    Widened(bool),
    /// What came back from pressing "scan now".
    Scan(ScanState),
}

/// Where the operator-pressed scan has got to. Every state is something the
/// window can say out loud; none of them is a silent button.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) enum ScanState {
    /// Nothing asked for.
    #[default]
    Idle,
    /// The command is on its way to the daemon.
    Asking,
    /// The daemon accepted it; the slice is being read (seconds).
    Scanning,
    /// The daemon declined, in its own words — never paraphrased here.
    Refused(SharedString),
    /// This daemon does not know the command at all. Not a refusal: it cannot,
    /// rather than will not.
    Unsupported(SharedString),
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
    /// Set when this daemon could not read a filter naming `EventKind::Air`, so
    /// it predates the air collector outright.
    ///
    /// The window must never render that as "no scan yet": one says the collector
    /// has produced nothing, the other says this daemon cannot produce anything.
    /// Reporting the second as the first is a falsehood the operator would act on.
    air_unsupported: bool,
    /// Where the operator-pressed scan has got to.
    scan: ScanState,
}

impl AirFeed {
    fn apply(&mut self, msg: BridgeMsg) {
        match msg {
            BridgeMsg::Frame(frame) => {
                match frame {
                    StreamFrame::Event(Event::Air(a)) => {
                        self.offline = None;
                        self.air = Some(a);
                        // The slice we were waiting for arrived: the button stops
                        // claiming a scan is in progress.
                        if matches!(self.scan, ScanState::Asking | ScanState::Scanning) {
                            self.scan = ScanState::Idle;
                        }
                    }
                    StreamFrame::Event(Event::Wifi(w)) => {
                        self.offline = None;
                        self.own = Some(w);
                    }
                    StreamFrame::Ready(r) => {
                        self.offline = None;
                        self.paused = !r.observing;
                    }
                    StreamFrame::Observing(e) => {
                        self.offline = None;
                        self.paused = !e.observing;
                    }
                    // An error frame is the daemon refusing, not the daemon
                    // working: clearing the note here would leave a stale slice
                    // looking live.
                    StreamFrame::Error(e) => {
                        self.offline = Some(format!("daemon: {}", e.message).into())
                    }
                    // A frame from a newer daemon than this bar. One frame is
                    // lost, and it is named rather than passed off as silence.
                    StreamFrame::Unrecognized(u) => {
                        self.offline = Some(
                            format!("skipped a frame this bar cannot read: {}", u.detail).into(),
                        );
                    }
                    StreamFrame::Gap(_) | StreamFrame::Event(_) => self.offline = None,
                }
            }
            BridgeMsg::Offline(reason) => self.offline = Some(reason.into()),
            BridgeMsg::Widened(widened) => self.air_unsupported = widened,
            BridgeMsg::Scan(state) => self.scan = state,
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

/// How loud a foreign AP arrives, as an opacity: `0.25..=0.85` for a reported
/// signal, and `0.20` — below the whole reported range — when there is none.
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
    if lane
        .span
        .frequency_extent()
        .is_some_and(|e| e.drawn_as_union)
    {
        // The bar is drawn wider than the radio: 2.4 GHz bonding direction is
        // not reported, so the band shown is every placement it could have.
        s.push_str(" · bonding unknown, drawn as widest possible");
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
        Some(h) => {
            // A real sliver must not print as the same 0% a disjoint channel
            // does — the reader already settled this wording.
            let share = if h.overlap < 0.005 {
                "<1%".to_string()
            } else {
                format!("{:.0}%", h.overlap * 100.0)
            };
            format!(
                "hypothesis: covers {share} of our channel · {}",
                confidence_label(h.confidence)
            )
        }
    }
}

/// The root view of the air-map window.
pub(crate) struct AirView {
    feed: Entity<AirFeed>,
    /// Where to send the scan command. The bar is a pure socket client: it takes
    /// the reading itself nowhere near the radio.
    socket_path: String,
    /// The bridge back into the model, so a pressed button reports through the
    /// same path frames arrive on.
    tx: mpsc::SyncSender<BridgeMsg>,
    _observe: Subscription,
    /// Held so the release hook stays registered for the view's whole life.
    _release: Subscription,
}

impl AirView {
    fn new(
        feed: Entity<AirFeed>,
        shutdown: Arc<Shutdown>,
        socket_path: String,
        tx: mpsc::SyncSender<BridgeMsg>,
        cx: &mut Context<Self>,
    ) -> Self {
        let observe = cx.observe(&feed, |_this, _, cx| cx.notify());
        let release = cx.on_release(move |_view, _cx| shutdown.trip());
        Self {
            feed,
            socket_path,
            tx,
            _observe: observe,
            _release: release,
        }
    }

    /// Ask the daemon for one slice, now.
    ///
    /// Off the UI thread: `control` opens a socket and waits on the answer, and
    /// the gpui main thread must not park on either. The answer comes back
    /// through the bridge, so the button's state is set by what the daemon said
    /// and never by optimism here.
    fn request_scan(&self, cx: &mut Context<Self>) {
        self.feed.update(cx, |feed, cx| {
            feed.scan = ScanState::Asking;
            cx.notify();
        });
        let sock = self.socket_path.clone();
        let tx = self.tx.clone();
        if let Err(e) = thread::Builder::new()
            .name("observer-air-scan".to_string())
            .spawn(move || {
                let state = match net_observer_ipc::control(&sock, ControlCmd::ScanAir) {
                    // The daemon's own words, both ways. A refusal here is a
                    // sentence it wrote — "quiet is on", "try again in 9s" — and
                    // paraphrasing it would lose the reason.
                    Ok(ControlOutcome::Ran(r)) if r.ok => ScanState::Scanning,
                    Ok(ControlOutcome::Ran(r)) => ScanState::Refused(r.message.into()),
                    Ok(ControlOutcome::Unsupported(m)) => ScanState::Unsupported(m.into()),
                    Err(e) => ScanState::Refused(format!("could not ask: {e}").into()),
                };
                bridge_send(&tx, BridgeMsg::Scan(state));
            })
        {
            self.feed.update(cx, |feed, cx| {
                feed.scan = ScanState::Refused(format!("could not ask: {e}").into());
                cx.notify();
            });
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
        let scanned_at = feed.air.as_ref().map(|a| a.ts_us);
        let own_read_at = feed.own.as_ref().map(|w| w.ts_us);
        let air_unsupported = feed.air_unsupported;
        let scan = feed.scan.clone();

        let body = match &feed.air {
            // The daemon itself predates the air collector. Distinct from "no
            // scan yet", which would claim a capability this daemon lacks.
            None if feed.air_unsupported => note(
                "This daemon cannot collect the air.",
                "It was built before the air collector existed — it rejected a subscription \
                 naming that kind of event, so the window fell back to everything else it \
                 does serve. Nothing here is a reading of the radio environment: no scan \
                 can have happened, which is not the same as one having found nothing.",
                theme.warn,
                theme,
            )
            .into_any_element(),
            // No scan has arrived. NOT empty air: the air collector is off by
            // default, so this is the state the window must name outright.
            None => note(
                "No air scan yet.",
                "Nothing has been heard because nothing has scanned: the air collector is \
                 off by default, and a scan is a slow, separate period rather than a tick. \
                 This is not a reading of empty air. Press \"Scan now\" to take one slice.",
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
            .child(header(
                own,
                paused,
                scanned_at,
                own_read_at,
                air_unsupported,
                theme,
            ))
            .child(scan_bar(&scan, air_unsupported, theme, cx))
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

/// How far our own channel reading may lag the scan before the pairing stops
/// being about the same association: one minute of ordinary roaming.
const OWN_CHANNEL_STALE_US: i64 = 60_000_000;

/// Wall-clock time of a microsecond stamp, in the system zone.
fn clock(ts_us: i64) -> String {
    match jiff::Timestamp::from_microsecond(ts_us) {
        Ok(ts) => {
            let z = ts.to_zoned(jiff::tz::TimeZone::system());
            format!("{:02}:{:02}:{:02}", z.hour(), z.minute(), z.second())
        }
        Err(_) => "--:--:--".to_string(),
    }
}

/// A microsecond span as a short duration, for saying how far apart two
/// readings are without making the reader do arithmetic.
fn gap_label(us: i64) -> String {
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

/// The two provenance lines under the header: when the slice was taken, and
/// when the channel it is compared against was read.
struct ProvenanceLines {
    scanned: String,
    /// `Some` when our own channel has a moment of its own; carries a warning
    /// instead of a note when the two readings are far enough apart that we may
    /// have roamed between them.
    pairing: Option<String>,
}

/// Say when each half of the picture was read.
///
/// The scan and our own association come from different readings on different
/// cadences; pairing them silently would compute the overlap against a band we
/// had already left (realm net-observer, node #48).
fn provenance_lines(
    scanned_at: Option<i64>,
    own_read_at: Option<i64>,
    air_unsupported: bool,
) -> ProvenanceLines {
    // "Unknown moment" was a lie in the one case it was reached: with no scan at
    // all there is no moment to be unknown ABOUT. Three states, three sentences —
    // a scan with a time, no scan yet, and a daemon that cannot scan.
    let scanned = match (scanned_at, air_unsupported) {
        (Some(us), _) => format!("scanned at {}", clock(us)),
        (None, true) => "not scanned: this daemon cannot collect the air".to_string(),
        (None, false) => "not scanned yet".to_string(),
    };
    let pairing = match (scanned_at, own_read_at) {
        (Some(scan), Some(own_us)) if (scan - own_us).abs() > OWN_CHANNEL_STALE_US => {
            Some(format!(
                "our channel was read at {} — {} apart from the scan, so we may have roamed between them",
                clock(own_us),
                gap_label((scan - own_us).abs())
            ))
        }
        (_, Some(own_us)) => Some(format!("our channel read at {}", clock(own_us))),
        (_, None) => None,
    };
    ProvenanceLines { scanned, pairing }
}

/// The scan strip under the header: one button and one honest sentence about it.
///
/// The button never claims an outcome it has not been told. It says "asking"
/// while the command is in flight, "scanning" only after the daemon accepted,
/// and shows the daemon's own words on a refusal. A daemon that does not know
/// the command says so instead of the button going quiet.
fn scan_bar(
    scan: &ScanState,
    air_unsupported: bool,
    theme: Theme,
    cx: &mut Context<AirView>,
) -> impl IntoElement {
    // A daemon that could not read a filter naming `Air` cannot have the command
    // either: offer no button rather than one that exists to be refused.
    let busy = matches!(scan, ScanState::Asking | ScanState::Scanning);
    let pressable = !air_unsupported && !busy;
    let label = match scan {
        _ if air_unsupported => "Scan unavailable",
        ScanState::Asking => "Asking…",
        ScanState::Scanning => "Scanning… (a few seconds)",
        _ => "Scan now",
    };
    let note_line: Option<(SharedString, u32)> = match scan {
        ScanState::Idle | ScanState::Asking => None,
        ScanState::Scanning => Some((
            "the daemon accepted; the slice arrives when the radio has been read".into(),
            theme.muted,
        )),
        ScanState::Refused(m) => Some((format!("the daemon declined: {m}").into(), theme.warn)),
        ScanState::Unsupported(m) => Some((
            format!("this daemon does not know how to scan the air on demand: {m}").into(),
            theme.warn,
        )),
    };
    let mut button = div()
        .id("air-scan-now")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        .text_color(rgb(if pressable { theme.accent } else { theme.muted }))
        .child(label);
    if pressable {
        button = button
            .cursor_pointer()
            .hover(|s| s.bg(rgb(theme.hover)))
            .on_click(cx.listener(|this, _, _window, cx| this.request_scan(cx)));
    }
    div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .pb_2()
        .child(button)
        .children(note_line.map(|(line, colour)| {
            div()
                .text_size(px(11.0))
                .text_color(rgb(colour))
                .child(line)
        }))
}

/// The window header: what this map is, our own association, and the caveat that
/// governs every number below it (realm net-observer, node #48).
fn header(
    own: Option<ChannelSpan>,
    paused: bool,
    scanned_at: Option<i64>,
    own_read_at: Option<i64>,
    air_unsupported: bool,
    theme: Theme,
) -> impl IntoElement {
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
    // A scan is a slice, and a slice with no moment on it cannot deny being
    // "the air right now" — the one claim this window must never make when the
    // socket has been quiet for an hour (realm net-observer, node #48).
    let lines = provenance_lines(scanned_at, own_read_at, air_unsupported);
    let scanned_line = lines.scanned;
    let pairing_line = lines.pairing;
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
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(scanned_line),
        )
        .children(pairing_line.map(|line| {
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child(line)
        }))
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
    // The button needs a way back into the model too, so it reports through the
    // same bridge frames arrive on rather than a second path that could disagree.
    let button_tx = tx.clone();
    let button_socket = socket_path.clone();
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
        cx.new(|cx| AirView::new(feed, shutdown, button_socket, button_tx, cx))
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
        match net_observer_ipc::subscribe_or_widen(sock_path, &kinds) {
            Ok((sub, widened)) => {
                // A daemon that cannot read `EventKind::Air` predates the air
                // collector. Say so, rather than letting the window imply the
                // collector merely has not run — and say the opposite on a
                // reconnect that succeeded unfiltered, so a daemon upgraded under
                // a running bar stops being reported as one that cannot scan.
                if !bridge_send(tx, BridgeMsg::Widened(widened)) {
                    return;
                }
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
                            // Client-side filter. It is redundant while the
                            // daemon honoured our `kinds`, and load-bearing once
                            // the subscription was widened: without it a busy link
                            // stream would crowd the air frames out of a
                            // 32-deep bridge that drops rather than blocks.
                            if !concerns_this_window(&frame) {
                                continue;
                            }
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

/// Whether this window has any use for `frame`.
///
/// The same rule the daemon applies server-side, restated here for the widened
/// subscription: an event of a kind this window does not draw is dropped, and
/// every stream-integrity frame (ack, gap, observing edge, error, and a frame
/// this build cannot read) is kept whatever the filter — a window that stops
/// updating needs the reason more than the data.
fn concerns_this_window(frame: &StreamFrame) -> bool {
    match frame.event_kind() {
        None => true,
        Some(k) => k == EventKind::Air || k == EventKind::Wifi,
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

    /// A slice with no moment on it cannot deny being "the air right now", and
    /// after a socket drop that is exactly what a stale one would claim.
    #[test]
    fn the_header_carries_the_moment_of_the_scan_and_of_our_channel() {
        let scanned = 4_000_000_000_i64;
        let l = provenance_lines(Some(scanned), Some(scanned), false);
        let out: Vec<String> = std::iter::once(l.scanned).chain(l.pairing).collect();
        assert!(
            out.iter().any(|l| l.starts_with("scanned at ")),
            "the scan's moment is always shown: {out:?}"
        );
        assert!(
            out.iter().any(|l| l.starts_with("our channel read at ")),
            "and so is our own reading's: {out:?}"
        );
        // Far apart: the pairing itself becomes the warning.
        let l = provenance_lines(Some(scanned), Some(scanned - 4 * 3600 * 1_000_000), false);
        let out: Vec<String> = std::iter::once(l.scanned).chain(l.pairing).collect();
        assert!(
            out.iter().any(|l| l.contains("we may have roamed")),
            "a scan paired with a four-hour-old channel must say so: {out:?}"
        );
        assert!(out.iter().any(|l| l.contains("4h")), "{out:?}");
    }

    /// An error frame is the daemon refusing, not the daemon working: it must
    /// not clear the offline note and leave a stale slice looking live.
    #[test]
    fn an_error_frame_is_surfaced_rather_than_swallowed() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Frame(StreamFrame::Error(
            net_observer_ipc::StreamError {
                ts_us: 1,
                code: net_observer_ipc::StreamErrorCode::TooManySubscribers,
                message: "too many subscribers".to_string(),
            },
        )));
        let note = feed.offline.clone().expect("the refusal is shown");
        assert!(note.contains("too many subscribers"), "{note}");
    }

    /// The three states the provenance line must keep apart. "Scanned at an
    /// unknown moment" was reached only when there was no scan at all — where
    /// there is no moment to be unknown ABOUT, and where a daemon that cannot
    /// scan read exactly like one that simply had not yet.
    #[test]
    fn a_missing_scan_is_not_a_scan_at_an_unknown_moment() {
        let none_yet = provenance_lines(None, None, false).scanned;
        let cannot = provenance_lines(None, None, true).scanned;
        let scanned = provenance_lines(Some(4_000_000_000), None, false).scanned;

        assert!(!none_yet.contains("unknown moment"), "{none_yet}");
        assert!(!cannot.contains("unknown moment"), "{cannot}");
        assert!(none_yet.contains("not scanned yet"), "{none_yet}");
        assert!(cannot.contains("cannot collect the air"), "{cannot}");
        assert_ne!(none_yet, cannot, "the two facts must not read the same");
        assert!(scanned.starts_with("scanned at "), "{scanned}");
    }

    /// A daemon that could not read a filter naming `Air` predates the air
    /// collector. That fact must reach the model, because the window says
    /// something different about it than about "nothing has scanned yet".
    #[test]
    fn a_widened_subscription_records_that_this_daemon_cannot_collect_air() {
        let mut feed = AirFeed::default();
        assert!(!feed.air_unsupported);
        feed.apply(BridgeMsg::Widened(true));
        assert!(feed.air_unsupported);
        // ...and a later reconnect the daemon accepted as asked takes it back:
        // an upgraded daemon must stop being reported as one that cannot scan.
        feed.apply(BridgeMsg::Widened(false));
        assert!(!feed.air_unsupported);
    }

    /// Once the subscription is widened the daemon sends every kind. The window
    /// keeps only what it draws — and every stream-integrity frame, because a
    /// window that stops updating needs the reason more than the data.
    #[test]
    fn the_widened_stream_is_filtered_down_to_what_this_window_draws() {
        assert!(concerns_this_window(&StreamFrame::Event(Event::Air(scan(
            vec![]
        )))));
        assert!(concerns_this_window(&StreamFrame::Gap(
            net_observer_ipc::Gap {
                ts_us: 1,
                skipped: 3,
            }
        )));
        assert!(concerns_this_window(&StreamFrame::Unrecognized(
            net_observer_ipc::Unrecognized {
                ts_us: 1,
                detail: "unknown variant".to_string(),
            }
        )));
        assert!(!concerns_this_window(&StreamFrame::Event(Event::Incident(
            net_observer_ipc::IncidentSummary::default()
        ))));
    }

    /// The button must never claim an outcome it was not told. A refusal shows
    /// the daemon's own sentence; an unknown command is `Unsupported`, which is
    /// a different statement from a refusal and must not be flattened into one.
    #[test]
    fn the_scan_button_reports_what_the_daemon_said() {
        let mut feed = AirFeed::default();
        assert_eq!(feed.scan, ScanState::Idle);

        feed.apply(BridgeMsg::Scan(ScanState::Refused(
            "an air scan ran moments ago; try again in 9s".into(),
        )));
        match &feed.scan {
            ScanState::Refused(m) => assert!(m.contains("9s"), "{m}"),
            other => panic!("expected Refused, got {other:?}"),
        }

        feed.apply(BridgeMsg::Scan(ScanState::Unsupported(
            "bad request: unknown variant `ScanAir`".into(),
        )));
        assert!(matches!(feed.scan, ScanState::Unsupported(_)));
    }

    /// While a scan is in flight the window says so — and stops saying so the
    /// moment the slice it was waiting for arrives, rather than on a timer.
    #[test]
    fn an_arriving_slice_ends_the_scanning_state() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Scan(ScanState::Scanning));
        assert_eq!(feed.scan, ScanState::Scanning);
        feed.apply(BridgeMsg::Frame(StreamFrame::Event(Event::Air(scan(
            vec![],
        )))));
        assert_eq!(feed.scan, ScanState::Idle);
        assert!(feed.air.is_some());
    }

    /// A frame from a newer daemon costs one frame, and the window says which —
    /// it must not pass for a quiet stream.
    #[test]
    fn an_unreadable_frame_is_named_rather_than_swallowed() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Frame(StreamFrame::Unrecognized(
            net_observer_ipc::Unrecognized {
                ts_us: 1,
                detail: "unknown variant `Ether`".to_string(),
            },
        )));
        let note = feed.offline.clone().expect("the lost frame is named");
        assert!(note.contains("Ether"), "{note}");
    }

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
