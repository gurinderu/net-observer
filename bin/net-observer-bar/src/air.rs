//! The **air map** window: the foreign access points this radio can hear, drawn
//! as bands on a shared channel axis with our own association highlighted across
//! it.
//!
//! ## The form, and why it is this one
//!
//! Each band gets ONE axis, labelled with the channel numbers a person changes
//! an access point to (2.4 GHz: 1…13; 5 GHz: 36, 40, 44, …), and every neighbour
//! heard in that band is a band on it, packed into shared rows so that two of
//! them cross on the page exactly where they cross in the air. The frequency
//! range stays a small caption: the geometry is linear in MHz — the same
//! arithmetic the overlap hypothesis is computed from — while the labels are
//! channels, so the picture and the number cannot disagree.
//!
//! The first form was one private strip per access point, one under another.
//! With fifteen neighbours audible that is a screen and a half of scrolling, and
//! the question the map exists for — who is standing in *my* channel — was not
//! answerable from it at all. The details are now one line each, under the
//! drawing, ordered by who is most likely in our band; and the caveat below is
//! said once in the header rather than under every neighbour, where repetition
//! turned it into furniture (realm net-observer, node #48).
//!
//! A map of its own, deliberately not a layer on the network map: that one shows
//! L2 devices, this one shows frequency bands, and mixing them hides the one
//! thing this map exists to show (realm net-observer, node #48).
//!
//! ## Two readings of one slice
//!
//! A switch at the top offers the same sample as **channels** (the axis above)
//! or as **signal rings**: this Mac in the centre, concentric rings labelled in
//! dBm, one mark per audible neighbour on the ring its measured signal puts it
//! on. The rings answer a different question — how loud, and therefore roughly
//! how far. Two hard limits are drawn on the screen and not merely written
//! here: the ANGLE of a mark carries nothing at all (one antenna gives no
//! bearing, marks are spread by rank), and the metres are a bracket out of a
//! path-loss model with an invented transmit power, wrong by factors rather
//! than by percentages. The measured quantity is the dBm; metres are its
//! caption. See [`rings_section`] and [`distance_hypothesis`].
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
use std::time::{Duration, Instant};

use gpui::prelude::*;
use gpui::{
    AnyWindowHandle, App, AsyncApp, Context, Entity, SharedString, Subscription, Timer,
    TitlebarOptions, Window, WindowBounds, WindowHandle, WindowKind, WindowOptions, div, px, rgb,
    rgba, size,
};

use net_observer_ipc::{
    CollectorAvailability, ControlCmd, ControlOutcome, Event, EventKind, StreamFrame,
    SubscriptionHandle,
};
use types::{
    AirObservation, AirSample, AirVerdict, Band, ChannelOverlapHypothesis, ChannelSpan,
    OverlapConfidence, WifiSample, WifiVerdict, overlap_hypothesis,
};

use crate::ui::{Glance, Theme, separator};

/// How often the foreground bridge task drains the channel into the model. The
/// air scan is a slow period (seconds per scan), so this only has to feel prompt.
const DRAIN_POLL: Duration = Duration::from_millis(250);
/// How long the subscription thread waits before retrying a dropped stream.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// Bridge depth. Small on purpose: only the LATEST sample of each kind is kept,
/// so a backlog has no value — dropping is as correct as queueing.
const BRIDGE_DEPTH: usize = 32;
/// How long the button may claim a scan is in progress with nothing arriving.
///
/// Both ends of the wait can be lost without a trace: the answer to the press
/// travels the same bridge as the samples and is dropped when it is full, and the
/// slice itself is an ordinary event that a subscription drop-and-reconnect can
/// step over. Neither has a successor to correct it — the air collector is off by
/// default, so no later event arrives to unstick the button. The deadline is the
/// only thing that guarantees the busy state ends.
///
/// Generous on purpose: the daemon's own minimum gap between scans is 15s and the
/// radio read costs seconds, so this must never fire on a scan that is merely
/// slow.
const SCAN_BUSY_TIMEOUT: Duration = Duration::from_secs(60);

/// Initial window size (resizable afterwards), gpui logical px.
const WIN_W: f32 = 620.0;
const WIN_H: f32 = 560.0;
/// Width of the drawn channel axis, px. Fixed so band placement is arithmetic on
/// a known width rather than a layout query.
const AXIS_W: f32 = 560.0;
/// Height of one drawn foreign band, and the gap between the rows they are
/// packed into.
const BAR_H: f32 = 9.0;
const BAR_GAP: f32 = 2.0;
/// Height of our own association's band, drawn thicker than a foreign one
/// directly above the axis: it is the reference everything else is read against.
const OWN_LANE_H: f32 = 13.0;
/// The axis rule, the tick marks below it, and the room the channel numbers get.
const AXIS_RULE_H: f32 = 1.0;
const TICK_H: f32 = 4.0;
const TICK_LABEL_H: f32 = 13.0;
/// Half the box a channel number is drawn in, px. The number is centred on its
/// tick, so it may reach this far either side of it.
const TICK_LABEL_HALF_W: f32 = 11.0;
/// Closest two *labelled* ticks may sit before the numbers would collide. Ticks
/// nearer than this still get a mark; only the number is dropped.
const MIN_TICK_LABEL_GAP: f32 = 24.0;
/// How many foreign APs are drawn per band before the rest become a count.
/// Bands are packed into shared rows now, so the drawing costs a row only where
/// two of them actually cross.
const MAX_ROWS_PER_BAND: usize = 24;

/// The side of the square the signal rings are drawn in, gpui logical px:
/// clamped to this range and otherwise fitted to the window (see
/// [`rings_diameter`]). Marker placement is arithmetic on that known box rather
/// than a layout query, exactly as the channel axis is on [`AXIS_W`].
const RINGS_D_MIN: f32 = 340.0;
const RINGS_D_MAX: f32 = 520.0;
/// Vertical space the rings view's own chrome (header, tabs, scan bar and the
/// two standing caveats) takes before the plot gets any.
const RINGS_CHROME_H: f32 = 300.0;
/// Horizontal padding the section applies (`px_3` on both sides).
const RINGS_SIDE_PAD: f32 = 24.0;
/// The dBm levels the rings are drawn and labelled at. The rings are the ruler
/// of that view, and the ruler is the *measured* quantity — never metres.
const RING_LEVELS: [i32; 4] = [-40, -55, -70, -85];
/// The signal mapped to the centre and to the outer edge of the plot. Anything
/// louder than the first or fainter than the second is clamped onto the box
/// rather than drawn outside it.
const RING_STRONG_DBM: f64 = -30.0;
const RING_WEAK_DBM: f64 = -95.0;
/// The box one marker's dot and its caption are laid out in. Markers are clamped
/// into the plot by this size, so no caption can leave the drawing.
const MARK_W: f32 = 168.0;
const MARK_H: f32 = 30.0;
/// The angular step between consecutive markers, in degrees — the golden angle.
///
/// The angle carries NO information (see [`rings_section`]); this constant only
/// has to be deterministic and to spread markers evenly, so that the same scan
/// always draws the same picture and two neighbours rarely land on top of each
/// other. The index it multiplies is the neighbour's rank, which is a property
/// of the reading, not of the drawing.
const GOLDEN_ANGLE_DEG: f64 = 137.507_764_05;

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
    /// The bar waited [`SCAN_BUSY_TIMEOUT`] and no answer or slice arrived, so it
    /// stopped claiming a scan is in progress. This is the WINDOW speaking, not
    /// the daemon: the answer may have been dropped by a full bridge, or the
    /// slice may have fallen into a subscription reconnect. Saying so is honest;
    /// a button stuck on "Scanning…" for the life of the window is not.
    LostTrack(SharedString),
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
    /// When the current busy state stops being believed. `Some` exactly while
    /// `scan` is `Asking` or `Scanning`; see [`SCAN_BUSY_TIMEOUT`].
    scan_deadline: Option<Instant>,
}

impl AirFeed {
    /// The ONLY writer of `scan`, so a busy state can never be entered without
    /// the deadline that ends it.
    fn set_scan(&mut self, state: ScanState) {
        self.scan_deadline = match state {
            ScanState::Asking | ScanState::Scanning => Some(Instant::now() + SCAN_BUSY_TIMEOUT),
            _ => None,
        };
        self.scan = state;
    }

    /// Give up on a busy state whose deadline has passed. Called on every drain
    /// tick, so the button cannot outlive the answer it is waiting for.
    fn expire_scan(&mut self, now: Instant) -> bool {
        let Some(deadline) = self.scan_deadline else {
            return false;
        };
        if now < deadline {
            return false;
        }
        self.set_scan(ScanState::LostTrack(
            "no answer and no slice arrived; the scan may still have run".into(),
        ));
        true
    }

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
                            self.set_scan(ScanState::Idle);
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
            BridgeMsg::Scan(state) => self.set_scan(state),
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

/// What can be said about a foreign AP and our own channel.
///
/// Three cases, and they are three because the window once collapsed the first
/// two: with our channel plainly named in the header, every 2.4 GHz neighbour
/// still carried "this Mac's own channel is unknown" underneath it. That is not
/// a hedge, it is a false statement — the channel was known, the neighbour was
/// simply in another band (realm net-observer, node #48).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Overlap {
    /// We are not associated, or the channel was not reported: nothing can be
    /// computed against anything.
    OwnChannelUnknown,
    /// Our channel is known and sits in another band, which is *why* there is no
    /// overlap — a fact about the neighbour, not a gap in what we know.
    OwnBandElsewhere(Band),
    /// Both radios are in this band, so the hypothesis is computable.
    Computed(ChannelOverlapHypothesis),
}

impl Overlap {
    /// The hypothesis when there is one — the ranking key's only input.
    fn hypothesis(self) -> Option<ChannelOverlapHypothesis> {
        match self {
            Overlap::Computed(h) => Some(h),
            _ => None,
        }
    }
}

/// One foreign AP prepared for drawing: where it sits, how it was heard, and
/// what can be said about it and our own band.
#[derive(Debug, Clone)]
struct Lane {
    span: ChannelSpan,
    rssi_dbm: Option<i32>,
    phy_mode: Option<String>,
    security: Option<String>,
    overlap: Overlap,
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
    /// Where this Mac actually is, even when that is another band — so the
    /// section can say *why* nothing here overlaps us, once, instead of every
    /// lane repeating a hedge about an unknown channel.
    own_elsewhere: Option<Band>,
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
            own_elsewhere: None,
            lanes: Vec::new(),
            dropped: 0,
        });
    }
    for ap in &sample.aps {
        let Some(span) = span_of(ap) else { continue };
        let overlap = match own {
            None => Overlap::OwnChannelUnknown,
            Some(o) if o.band == span.band => {
                Overlap::Computed(overlap_hypothesis(&o, &span, ap.rssi_dbm))
            }
            Some(o) => Overlap::OwnBandElsewhere(o.band),
        };
        let lane = Lane {
            span,
            rssi_dbm: ap.rssi_dbm,
            phy_mode: ap.phy_mode.clone(),
            security: ap.security.clone(),
            overlap,
        };
        match groups.iter_mut().find(|g| g.band == span.band) {
            Some(g) => g.lanes.push(lane),
            None => groups.push(BandGroup {
                band: span.band,
                own: None,
                own_elsewhere: own.map(|o| o.band),
                lanes: vec![lane],
                dropped: 0,
            }),
        }
    }
    for g in &mut groups {
        g.lanes.sort_by(
            |a, b| match (a.overlap.hypothesis(), b.overlap.hypothesis()) {
                (Some(x), Some(y)) => y.rank_key().cmp(&x.rank_key()),
                _ => b
                    .rssi_dbm
                    .unwrap_or(i32::MIN)
                    .cmp(&a.rssi_dbm.unwrap_or(i32::MIN)),
            },
        );
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
    // 2.4 GHz is small enough to draw whole, and drawn whole it is the picture
    // people already have of it: the thirteen overlapping channels, 1 / 6 / 11
    // where they always are. Framing it to whatever happens to be audible would
    // move the numbers between scans.
    if group.band == Band::TwoGhz {
        lo = lo.min(2402.0);
        hi = hi.max(2482.0);
    }
    // A single 20 MHz span would otherwise fill the axis edge to edge and read
    // as "the whole band"; the pad keeps the drawing honest about scale.
    let pad = ((hi - lo) * 0.08).max(10.0);
    Some((lo - pad, hi + pad))
}

/// The channel numbers a band is labelled with: the 20 MHz grid the operator's
/// access point offers in its own settings, not a frequency ruler.
///
/// The axis stays linear in MHz — that is the geometry the overlap is computed
/// from — and only its *labels* are channels, so the two never disagree.
fn band_channels(band: Band) -> Vec<i32> {
    match band {
        Band::TwoGhz => (1..=14).collect(),
        Band::FiveGhz => vec![
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
            144, 149, 153, 157, 161, 165,
        ],
        // 6 GHz numbers its 20 MHz channels 1, 5, 9, … 233.
        Band::SixGhz => (0..59).map(|i| 1 + 4 * i).collect(),
    }
}

/// Where a channel number's own 20 MHz slot is centred on the axis, in px, or
/// `None` when the channel is off the drawn window.
///
/// Placed through [`ChannelSpan::frequency_extent`] — the same arithmetic every
/// band on this axis is drawn with, so a tick cannot drift away from the bands
/// it is labelling.
fn channel_centre_px(band: Band, channel: i32, axis: (f64, f64)) -> Option<f32> {
    let span = ChannelSpan {
        channel,
        band,
        width_mhz: 20,
        width_assumed: false,
    };
    let e = span.frequency_extent()?;
    let centre = f64::midpoint(e.lo_mhz, e.hi_mhz);
    let (lo, hi) = axis;
    if hi <= lo || centre < lo || centre > hi {
        return None;
    }
    #[allow(clippy::cast_possible_truncation)]
    Some((((centre - lo) / (hi - lo)) * f64::from(AXIS_W)) as f32)
}

/// One tick on the channel axis: which channel, where, and whether its number is
/// printed.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Tick {
    channel: i32,
    x: f32,
    labelled: bool,
}

/// The ticks a band's axis carries, thinned so two printed numbers never touch.
///
/// Our own channel is labelled first and unconditionally: it is the one number
/// the reader came for, and a thinning pass that dropped it would leave the
/// highlight on the axis unexplained. Everything else is taken left to right and
/// kept only where it clears every number already printed.
fn axis_ticks(band: Band, axis: (f64, f64), own_channel: Option<i32>) -> Vec<Tick> {
    let mut ticks: Vec<Tick> = band_channels(band)
        .into_iter()
        .filter_map(|c| channel_centre_px(band, c, axis).map(|x| (c, x)))
        .map(|(channel, x)| Tick {
            channel,
            x,
            labelled: false,
        })
        .collect();
    let mut printed: Vec<f32> = Vec::new();
    if let Some(own) = own_channel
        && let Some(t) = ticks.iter_mut().find(|t| t.channel == own)
    {
        t.labelled = true;
        printed.push(t.x);
    }
    for t in &mut ticks {
        if t.labelled {
            continue;
        }
        if printed
            .iter()
            .all(|p| (t.x - p).abs() >= MIN_TICK_LABEL_GAP)
        {
            t.labelled = true;
            printed.push(t.x);
        }
    }
    ticks
}

/// Assign each placed band a row, so that two bands share a row only when they
/// do not cross on the axis.
///
/// The point of the map is "who is standing in my channel", so bands that
/// overlap must be visibly stacked over the same stretch of axis rather than
/// listed one per line. `placed` is indexed as given (ranked order); the returned
/// row numbers are parallel to it.
fn pack_rows(placed: &[(f32, f32)]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..placed.len()).collect();
    order.sort_by(|a, b| {
        placed[*a]
            .0
            .partial_cmp(&placed[*b].0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut ends: Vec<f32> = Vec::new();
    let mut rows = vec![0usize; placed.len()];
    for i in order {
        let (left, w) = placed[i];
        let row = ends
            .iter()
            .position(|e| left >= e + BAR_GAP)
            .unwrap_or(ends.len());
        if row == ends.len() {
            ends.push(f32::MIN);
        }
        ends[row] = ends[row].max(left + w);
        rows[i] = row;
    }
    rows
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
///
/// Short on purpose. What *lowers* confidence, and that even the highest is a
/// hypothesis, is said once in the header; repeated under fifteen neighbours the
/// same sentence stops being read at all (realm net-observer, node #48).
fn confidence_label(c: OverlapConfidence) -> &'static str {
    match c {
        OverlapConfidence::Low => "low confidence",
        OverlapConfidence::Medium => "medium confidence",
        OverlapConfidence::High => "high confidence",
    }
}

/// Turn one of the platform report's own tokens into a word a person reads.
///
/// `system_profiler` answers in identifiers — `spairport_security_mode_wpa2_
/// personal_mixed`, `spairport_network_type_station` — and one of them reached
/// the window verbatim, minus a letter, because a single hard-coded prefix did
/// not match what the report actually spelled. The scaffolding is therefore
/// dropped by *segment*, so no spelling of the prefix can survive as a fragment:
/// leading `spairport` / `pairport` / `network` / `security` / `mode` / `type`
/// segments are stripped, and what is left is spaced and capitalised.
///
/// Anything that is not one of those tokens (`802.11a/n/ac/ax`) passes through
/// unchanged.
fn humanize_token(raw: &str) -> Option<String> {
    const SCAFFOLD: [&str; 6] = [
        "spairport",
        "pairport",
        "network",
        "security",
        "mode",
        "type",
    ];
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let words: Vec<&str> = raw
        .split('_')
        .skip_while(|w| SCAFFOLD.contains(&w.to_ascii_lowercase().as_str()))
        .collect();
    if words.is_empty() {
        return None;
    }
    let pretty: Vec<String> = words
        .iter()
        .map(|w| match w.to_ascii_lowercase().as_str() {
            "wpa" => "WPA".to_string(),
            "wpa2" => "WPA2".to_string(),
            "wpa3" => "WPA3".to_string(),
            "wep" => "WEP".to_string(),
            "none" | "open" => "open".to_string(),
            _ => (*w).to_string(),
        })
        .collect();
    Some(pretty.join(" "))
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
///
/// One line, not three. Fifteen neighbours at three lines each is a screen and a
/// half of scrolling in which the picture above never appears; the details are a
/// table under the drawing and read as one (realm net-observer, node #48).
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
        s.push_str(" · bonding unknown, drawn widest");
    }
    match lane.rssi_dbm {
        Some(r) => s.push_str(&format!(" · {r} dBm")),
        None => s.push_str(" · signal not reported"),
    }
    if let Some(phy) = lane.phy_mode.as_deref().and_then(humanize_token) {
        s.push_str(&format!(" · {phy}"));
    }
    if let Some(sec) = lane.security.as_deref().and_then(humanize_token) {
        s.push_str(&format!(" · {sec}"));
    }
    s
}

/// The overlap statement for one lane, said as what it is.
///
/// Four outcomes and no fewer. "Our channel is unknown" and "our channel is
/// known and in another band" are different facts, and printing the first for
/// the second told the reader the header was lying to him.
fn overlap_label(lane: &Lane) -> String {
    match lane.overlap {
        Overlap::OwnChannelUnknown => {
            "overlap not computable — this Mac's own channel is unknown".to_string()
        }
        Overlap::OwnBandElsewhere(b) => {
            format!(
                "different band from ours — this Mac is on {}, so these cannot overlap",
                band_label(b)
            )
        }
        Overlap::Computed(h) if h.overlap <= 0.0 => "no band overlap with our channel".to_string(),
        Overlap::Computed(h) => {
            // A real sliver must not print as the same 0% a disjoint channel
            // does — the reader already settled this wording.
            format!(
                "hypothesis: covers {} of our channel · {}",
                share_label(h.overlap),
                confidence_label(h.confidence)
            )
        }
    }
}

/// The overlap as a percentage, with a real sliver kept distinct from nothing.
fn share_label(overlap: f64) -> String {
    if overlap < 0.005 {
        "<1%".to_string()
    } else {
        format!("{:.0}%", overlap * 100.0)
    }
}

/// The overlap cell in a band section's table.
///
/// `None` where no overlap is computable — because our channel is unknown, or
/// because the neighbour is in another band. Both of those are facts about the
/// whole section, said once at its top by [`band_relation`]; repeating either
/// under every one of fifteen neighbours is how the window came to state, under
/// each of them, something its own header contradicted.
///
/// Where an overlap *is* computable the sentence is [`overlap_label`]'s, so
/// there is one wording and not two that can drift apart.
fn overlap_cell(lane: &Lane) -> Option<String> {
    match lane.overlap {
        Overlap::OwnChannelUnknown | Overlap::OwnBandElsewhere(_) => None,
        Overlap::Computed(_) => Some(overlap_label(lane)),
    }
}

/// The one sentence a band section says about itself and us — said once, at the
/// top of the section, instead of under every neighbour in it.
fn band_relation(group: &BandGroup) -> Option<String> {
    match (group.own, group.own_elsewhere) {
        (Some(s), _) => Some(format!(
            "this Mac is here, on ch {} — the highlighted column",
            s.channel
        )),
        (None, Some(b)) => Some(format!(
            "this Mac is on {}, not on this band: nothing here can overlap our channel",
            band_label(b)
        )),
        (None, None) => Some(
            "this Mac's own channel is unknown, so no overlap can be computed against it"
                .to_string(),
        ),
    }
}

/// The two readings of one air slice this window offers.
///
/// Same shape as the network map's graph/list switch: one sample, two questions.
/// The channel axis answers "who is standing in my channel"; the rings answer
/// "how loud is each of them", which is the only spatial-ish question a single
/// antenna can be asked at all — and even then only along one dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AirMode {
    /// The shared per-band channel axis (see [`band_section`]).
    Channels,
    /// Concentric rings of measured signal (see [`rings_section`]).
    Rings,
}

/// The distance hypothesis for one neighbour — a RANGE in metres, never a
/// number, and never a measurement.
#[derive(Debug, Clone, Copy, PartialEq)]
struct DistanceHypothesis {
    near_m: f64,
    far_m: f64,
}

/// The transmit power assumed for every foreign AP, dBm EIRP.
///
/// It is **not observed**: the scan report carries no transmitter power, and
/// nothing in the 802.11 beacon this Mac hears is obliged to state one either.
/// 20 dBm is the ordinary ceiling a consumer access point is configured to in
/// most regulatory domains. A neighbour running at 10 dBm is really about a
/// third of the estimated distance; one at 30 dBm about three times it.
const ASSUMED_TX_DBM: f64 = 20.0;
/// The indoor path-loss exponent bracket. Free space is 2.0; a floor of offices,
/// walls and furniture reaches 3–4. The whole spread of the answer comes from
/// not knowing which of these the signal actually travelled through.
const PATH_LOSS_EXPONENT_MIN: f64 = 2.0;
const PATH_LOSS_EXPONENT_MAX: f64 = 4.0;
/// The window the model is allowed to answer inside. Below the floor the model
/// has no resolution left (near field, body loss, an AP on this desk); above the
/// ceiling an indoor estimate is arithmetic without meaning.
const DISTANCE_FLOOR_M: f64 = 1.0;
const DISTANCE_CEILING_M: f64 = 300.0;
/// The narrowest range this function will report, as a ratio. Below it the two
/// ends would round to the same number and the answer would *look* like a
/// measurement, which is the one thing it must never look like.
const MIN_DISTANCE_SPREAD: f64 = 1.5;

/// How far away a neighbour heard at `rssi_dbm` on a carrier of `centre_mhz`
/// **might** be — as a bracket, from the log-distance path-loss model.
///
/// # The model, so that it can be argued with
///
/// One-metre free-space reference, then a log-distance tail:
///
/// ```text
/// FSPL(1 m) [dB] = 20·log10(f_MHz) − 27.55
/// L          [dB] = P_tx − P_rx − FSPL(1 m)
/// d(n)        [m] = 10 ^ ( L / (10·n) )
/// ```
///
/// The bracket is `d(4) … d(2)`: the same reading, believed to have crossed
/// free space at one end and a cluttered indoor floor at the other.
///
/// # What is assumed, and therefore what can be wrong
///
/// 1. **`P_tx` is invented** ([`ASSUMED_TX_DBM`]) — it is not in the scan report
///    and cannot be. Every 10 dB the real transmitter differs by moves the whole
///    bracket by a factor of ~3 (at n = 2) and is NOT reflected in its width.
/// 2. **The exponent is a guess bracketed by** [`PATH_LOSS_EXPONENT_MIN`] and
///    [`PATH_LOSS_EXPONENT_MAX`]. This is the only uncertainty the reported
///    width actually expresses.
/// 3. **`P_rx` is one sample of a fading channel.** Multipath moves an RSSI by
///    ±5 dB with nothing at all moving in the room.
/// 4. **Antenna gain and orientation are ignored** on both ends.
/// 5. **Walls are not modelled** as walls — a single concrete floor can cost
///    more than the whole 2→4 bracket does.
///
/// So this is a hypothesis with an error measured in *factors*, not per cent,
/// and the caller must render it as a range with an estimate mark on it. The
/// leading quantity of this view is the measured dBm; metres are its caption.
///
/// `None` when the carrier frequency is unknown, i.e. the AP could not be placed
/// on a frequency axis at all — no invented centre stands in for it.
fn distance_hypothesis(rssi_dbm: i32, centre_mhz: f64) -> Option<DistanceHypothesis> {
    if !(centre_mhz.is_finite() && centre_mhz > 0.0) {
        return None;
    }
    let fspl_1m = 20.0 * centre_mhz.log10() - 27.55;
    let loss = ASSUMED_TX_DBM - f64::from(rssi_dbm) - fspl_1m;
    let d = |n: f64| (10.0_f64.powf(loss / (10.0 * n))).clamp(DISTANCE_FLOOR_M, DISTANCE_CEILING_M);
    let near_m = d(PATH_LOSS_EXPONENT_MAX);
    let far_m = d(PATH_LOSS_EXPONENT_MIN)
        .max(near_m * MIN_DISTANCE_SPREAD)
        .min(DISTANCE_CEILING_M);
    Some(DistanceHypothesis { near_m, far_m })
}

/// The centre frequency a span sits on, from the same extent the axis view
/// draws — no second arithmetic for the same fact.
fn centre_mhz(span: ChannelSpan) -> Option<f64> {
    span.frequency_extent().map(|e| (e.lo_mhz + e.hi_mhz) / 2.0)
}

/// One metre figure, rounded to what the model can carry: no decimals above
/// 10 m, one below it. Never more precision than a factor-wide guess deserves.
fn metres(m: f64) -> String {
    if m < 10.0 {
        format!("{m:.1}")
    } else {
        format!("{:.0}", m.round())
    }
}

/// The distance bracket as the reader sees it: always two ends, always marked
/// as an estimate.
fn distance_label(d: DistanceHypothesis) -> String {
    format!("est. {}–{} m", metres(d.near_m), metres(d.far_m))
}

/// The distance bracket for one lane, when its signal and its carrier are both
/// known.
fn lane_distance(lane: &Lane) -> Option<DistanceHypothesis> {
    distance_hypothesis(lane.rssi_dbm?, centre_mhz(lane.span)?)
}

/// The sentence that governs the whole rings view, kept on screen rather than
/// in a tooltip: the angle of a mark carries nothing at all.
const ANGLE_MEANS_NOTHING: &str = "The angle of a mark means nothing: one antenna gives no \
     bearing, so a neighbour's direction is not observable here. Marks are spread around each \
     ring by rank alone. Only the distance from the centre — the ring, in dBm — is a reading.";

/// The sentence that governs the metres under every mark.
const METRES_ARE_A_GUESS: &str = "Metres are a hypothesis, not a measurement: a path-loss model \
     with an assumed transmit power and an indoor exponent between 2 and 4. Wrong by factors, \
     not by percentages — the ring (dBm) is the measured quantity.";

/// The side of the rings plot for a window of this size — the same fitting the
/// network map does for its star, so the drawing is sized to the room it has.
fn rings_diameter(avail_w: f32, avail_h: f32) -> f32 {
    avail_w.min(avail_h).clamp(RINGS_D_MIN, RINGS_D_MAX)
}

/// The radius the outermost ring may reach in a plot of side `d`, leaving
/// exactly the room one marker box needs vertically so that no mark can be
/// pushed off the plot.
fn ring_max_r(d: f32) -> f32 {
    d / 2.0 - MARK_H / 2.0
}

/// Where a signal sits between the centre and the outer edge, px.
fn ring_radius(rssi_dbm: f64, d: f32) -> f32 {
    let t = ((RING_STRONG_DBM - rssi_dbm) / (RING_STRONG_DBM - RING_WEAK_DBM)).clamp(0.0, 1.0);
    #[allow(clippy::cast_possible_truncation)]
    {
        (t * f64::from(ring_max_r(d))) as f32
    }
}

/// The top-left corner of marker `index`'s box inside the plot.
///
/// The radius is the reading; the angle is [`GOLDEN_ANGLE_DEG`] times the rank
/// and says nothing (see [`ANGLE_MEANS_NOTHING`]). The caption is laid towards
/// the centre — leftwards on the right half, rightwards on the left half — which
/// is what keeps every box inside the plot without clamping the radius, and so
/// without a layout constraint ever distorting the one quantity that is real.
fn mark_origin(index: usize, rssi_dbm: i32, d: f32) -> (f32, f32) {
    #[allow(clippy::cast_precision_loss)]
    let turn = (index as f64) * GOLDEN_ANGLE_DEG;
    let rad = turn.to_radians();
    let r = f64::from(ring_radius(f64::from(rssi_dbm), d));
    let centre = f64::from(d) / 2.0;
    let x = centre + r * rad.cos();
    let y = centre + r * rad.sin();
    #[allow(clippy::cast_possible_truncation)]
    let (x, y) = (x as f32, y as f32);
    // The dot sits on the point; the caption runs inwards from it.
    let left = if x > d / 2.0 {
        x - MARK_W + 4.0
    } else {
        x - 4.0
    };
    // A last-resort clamp: on the narrowest allowed plot a caption laid inwards
    // still fits, but the invariant "no mark leaves the drawing" is enforced
    // here rather than inferred. It can only move a mark along the angle, which
    // carries nothing; the radius the clamp would distort is already inside.
    let left = left.clamp(0.0, (d - MARK_W).max(0.0));
    let top = (y - MARK_H / 2.0).clamp(0.0, (d - MARK_H).max(0.0));
    (left, top)
}

/// The one-line caption beside a mark: the measured signal first, then the
/// channel and width, then the distance bracket as a bracket.
fn ring_mark_label(lane: &Lane) -> String {
    let mut s = match lane.rssi_dbm {
        Some(r) => format!("{r} dBm"),
        None => "signal not reported".to_string(),
    };
    s.push_str(&format!(
        " · ch {} · {} MHz",
        lane.span.channel, lane.span.width_mhz
    ));
    if lane.span.width_assumed {
        s.push_str(" (assumed)");
    }
    match lane_distance(lane) {
        Some(d) => s.push_str(&format!(" · {}", distance_label(d))),
        None => s.push_str(" · distance not estimable"),
    }
    s
}

/// One neighbour as the rings view handles it: the band it was heard in, and
/// the lane carrying its reading.
type BandLane = (Band, Lane);

/// The split [`ring_marks`] returns.
struct RingMarks {
    /// Neighbours with a reported signal — each has a ring to sit on.
    placed: Vec<BandLane>,
    /// Neighbours with no reported signal — no ring can carry them, so they are
    /// named outside the drawing instead.
    unplaceable: Vec<BandLane>,
}

/// The neighbours the rings can carry, in the window's own ranking order, and
/// the ones that must be named outside the drawing instead.
///
/// A neighbour with no reported signal has no ring to sit on. Drawing it
/// anywhere would be inventing the reading the whole view is made of, so it is
/// counted and said instead — SKIP, never silence.
fn ring_marks(sample: &AirSample, own: Option<ChannelSpan>) -> RingMarks {
    let mut placed = Vec::new();
    let mut unplaceable = Vec::new();
    for g in group(sample, own) {
        for lane in g.lanes {
            if lane.rssi_dbm.is_some() {
                placed.push((g.band, lane));
            } else {
                unplaceable.push((g.band, lane));
            }
        }
    }
    RingMarks {
        placed,
        unplaceable,
    }
}

/// The rings view: this Mac at the centre, concentric rings labelled in dBm, and
/// one mark per audible neighbour on the ring its measured signal puts it on.
///
/// What this view is and is NOT, said here once and on the screen permanently:
/// the ring is a reading, the angle is nothing, the metres are a hypothesis with
/// a factor-wide error ([`distance_hypothesis`]). There is no height, no floor,
/// no movement and no identity here — foreign APs carry no BSSID, so this is one
/// slice and never a track (realm net-observer, nodes #47 and #48).
fn rings_section(
    sample: &AirSample,
    own: Option<ChannelSpan>,
    d: f32,
    theme: Theme,
) -> impl IntoElement {
    let RingMarks {
        placed,
        unplaceable,
    } = ring_marks(sample, own);

    let mut plot = div()
        .debug_selector(|| "air-rings".to_string())
        .relative()
        .w(px(d))
        .h(px(d));

    let centre = d / 2.0;
    for level in RING_LEVELS {
        let r = ring_radius(f64::from(level), d);
        plot = plot.child(
            div()
                .debug_selector({
                    let sel = format!("air-ring:{level}");
                    move || sel
                })
                .absolute()
                .left(px(centre - r))
                .top(px(centre - r))
                .w(px(r * 2.0))
                .h(px(r * 2.0))
                .rounded_full()
                .border_1()
                .border_color(rgba(with_alpha(theme.fg, 0.18))),
        );
        plot = plot.child(
            div()
                .absolute()
                .left(px(centre + 6.0))
                .top(px(centre - r))
                .text_size(px(10.0))
                .text_color(rgb(theme.muted))
                .child(format!("{level} dBm")),
        );
    }

    // This Mac. The rings are read outward from here and from nowhere else.
    plot = plot.child(
        div()
            .debug_selector(|| "air-rings-centre".to_string())
            .absolute()
            .left(px(centre - 4.0))
            .top(px(centre - 4.0))
            .w(px(8.0))
            .h(px(8.0))
            .rounded_full()
            .bg(rgb(theme.accent)),
    );

    for (i, (band, lane)) in placed.iter().enumerate() {
        // `placed` holds only lanes whose signal was reported; a lane without one
        // has no ring, and is named below the drawing rather than invented onto it.
        let Some(rssi) = lane.rssi_dbm else { continue };
        let (left, top) = mark_origin(i, rssi, d);
        let towards_centre = left < d / 2.0;
        let dot = div()
            .flex_none()
            .w(px(7.0))
            .h(px(7.0))
            .rounded_full()
            .bg(rgba(with_alpha(theme.fg, weight(lane.rssi_dbm))));
        let caption = div()
            .flex_1()
            .overflow_hidden()
            .text_size(px(10.0))
            .text_color(rgb(theme.muted))
            .child(format!("{} · {}", band_label(*band), ring_mark_label(lane)));
        let mut row = div()
            .debug_selector({
                let sel = format!("air-ring-mark:{i}");
                move || sel
            })
            .absolute()
            .left(px(left))
            .top(px(top))
            .w(px(MARK_W))
            .h(px(MARK_H))
            .flex()
            .items_center()
            .gap_1()
            .overflow_hidden();
        row = if towards_centre {
            row.child(dot).child(caption)
        } else {
            row.child(caption).child(dot)
        };
        plot = plot.child(row);
    }

    div()
        .flex()
        .flex_col()
        .gap_2()
        .px_3()
        .py_2()
        .child(
            div()
                .debug_selector(|| "air-rings-angle-caveat".to_string())
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child(ANGLE_MEANS_NOTHING),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(METRES_ARE_A_GUESS),
        )
        .child(plot)
        .children((!unplaceable.is_empty()).then(|| {
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(format!(
                    "{} further access point(s) reported no signal and sit on no ring — heard, \
                     but not placeable here.",
                    unplaceable.len()
                ))
        }))
}

/// The root view of the air-map window.
pub(crate) struct AirView {
    feed: Entity<AirFeed>,
    /// The panel's shared model, read for ONE thing: what the daemon says it can
    /// collect. Read live on every render rather than captured at open, so a
    /// daemon upgraded or a collector enabled under an open window is reflected
    /// here without reopening it.
    glance: Entity<Glance>,
    /// Where to send the scan command. The bar is a pure socket client: it takes
    /// the reading itself nowhere near the radio.
    socket_path: String,
    /// The bridge back into the model, so a pressed button reports through the
    /// same path frames arrive on.
    tx: mpsc::SyncSender<BridgeMsg>,
    _observe: Subscription,
    /// Re-render when the panel's snapshot changes, so the capability sentence
    /// below follows the daemon instead of the moment this window opened.
    _observe_glance: Subscription,
    /// Held so the release hook stays registered for the view's whole life.
    _release: Subscription,
    /// Which reading of the same slice is on screen. Purely a view state: the
    /// feed is untouched by it, so switching cannot lose or re-fetch anything.
    mode: AirMode,
}

impl AirView {
    fn new(
        feed: Entity<AirFeed>,
        glance: Entity<Glance>,
        shutdown: Arc<Shutdown>,
        socket_path: String,
        tx: mpsc::SyncSender<BridgeMsg>,
        cx: &mut Context<Self>,
    ) -> Self {
        let observe = cx.observe(&feed, |_this, _, cx| cx.notify());
        let observe_glance = cx.observe(&glance, |_this, _, cx| cx.notify());
        let release = cx.on_release(move |_view, _cx| shutdown.trip());
        Self {
            feed,
            glance,
            socket_path,
            tx,
            _observe: observe,
            _observe_glance: observe_glance,
            _release: release,
            mode: AirMode::Channels,
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
            feed.set_scan(ScanState::Asking);
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
                // BLOCKING send, unlike the frame path: a sample dropped by a
                // full bridge is corrected by the next sample, but this state
                // transition has no successor — dropping it strands the button on
                // "Asking…". This thread exists only to carry this one answer,
                // and the drain empties the bridge every DRAIN_POLL, so waiting
                // here costs nothing anyone can see.
                let _ = tx.send(BridgeMsg::Scan(state));
            })
        {
            self.feed.update(cx, |feed, cx| {
                feed.set_scan(ScanState::Refused(format!("could not ask: {e}").into()));
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

        // What the daemon says about the air collector. Only consulted while no
        // scan has arrived: once a slice exists the collector plainly works, and a
        // stale capability line must not talk over real data.
        let capability = self.glance.read(cx).snapshot.collector(EventKind::Air);

        let body = match &feed.air {
            // The daemon HAS the air collector and its config switched it off.
            // Never folded into "no scan yet" (which would blame the absence on
            // timing) nor into "cannot collect" (which would tell the operator
            // there is nothing to turn on). This is the one state that names the
            // switch.
            None if capability == CollectorAvailability::Disabled => note(
                "The air collector is switched off.",
                "This daemon can read the radio environment; its configuration does not let \
                 it. Nothing here is a reading of the air. Set `collectors.air.enabled = \
                 true` in the daemon's config (or `NET_OBSERVER_COLLECTORS__AIR__ENABLED=1`) \
                 and restart it — or press \"Scan now\" for a single slice, which the daemon \
                 serves on demand regardless.",
                theme.warn,
                theme,
            )
            .into_any_element(),
            // The daemon named its collectors and the air is not among them —
            // the same fact `air_unsupported` reports from the other direction
            // (a daemon too old to read a filter naming that kind).
            None if capability == CollectorAvailability::Absent => note(
                "This daemon cannot collect the air.",
                "It listed the collectors it has and the air is not one of them. No scan can \
                 have happened, which is not the same as one having found nothing.",
                theme.warn,
                theme,
            )
            .into_any_element(),
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
            Some(a) => match self.mode {
                AirMode::Channels => {
                    let mut col = div().flex().flex_col().gap_4().px_3().py_2();
                    for g in group(a, own) {
                        col = col.child(band_section(&g, theme));
                    }
                    col.into_any_element()
                }
                AirMode::Rings => {
                    let viewport = window.viewport_size();
                    let d = rings_diameter(
                        f32::from(viewport.width) - RINGS_SIDE_PAD,
                        f32::from(viewport.height) - RINGS_CHROME_H,
                    );
                    rings_section(a, own, d, theme).into_any_element()
                }
            },
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
            .child(mode_tabs(self.mode, theme, cx))
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
/// The window's view switch — the same two-tab control the network map uses for
/// its graph/list pair ([`crate::map`]), because it is the same act: one sample,
/// two readings, and no data behind either of them.
fn mode_tabs(mode: AirMode, theme: Theme, cx: &mut Context<AirView>) -> impl IntoElement {
    let tab = |label: &'static str, this: AirMode, cx: &mut Context<AirView>| {
        let selected = mode == this;
        div()
            .id(label)
            .debug_selector({
                let sel = format!("air-tab:{label}");
                move || sel
            })
            .px_2()
            .py_1()
            .rounded_md()
            .text_size(px(12.0))
            .cursor_pointer()
            .text_color(rgb(if selected { theme.accent } else { theme.muted }))
            .when(selected, |d| d.bg(rgb(theme.hover)))
            .hover(|s| s.bg(rgb(theme.hover)))
            .child(label)
            .on_click(cx.listener(move |view, _, _window, cx| {
                view.mode = this;
                cx.notify();
            }))
    };
    div()
        .flex()
        .items_center()
        .gap_1()
        .px_3()
        .pb_1()
        .child(tab("Channels", AirMode::Channels, cx))
        .child(tab("Signal rings", AirMode::Rings, cx))
}

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
        ScanState::LostTrack(m) => Some((format!("stopped waiting: {m}").into(), theme.warn)),
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
                     nobody. Confidence drops when a channel width or a 2.4 GHz bonding \
                     direction had to be assumed, or when a signal strength was not \
                     reported — and the highest confidence is still a hypothesis. Foreign \
                     APs carry no BSSID, so this is one slice — the same AP cannot be \
                     followed between scans. Said once here, not under every neighbour.",
        ))
        .children(paused.then(|| {
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.warn))
                .child("Collection is paused — this slice will not update.")
        }))
}

/// One band's section: ONE channel axis, every band in this band drawn on it,
/// and a compact table under it ordered by who is most likely in our channel.
///
/// The window used to give each neighbour its own miniature axis and its own
/// three lines of prose; fifteen of them read as a list, and the question the
/// map exists for — who is standing in *my* channel — was not answerable from
/// the picture at all. One axis, our own channel highlighted across it, and
/// bands packed into shared rows so a crossing is a crossing on the page
/// (realm net-observer, node #48).
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

    let band = band_label(group.band);
    // Placed in ranked order, so a row's index in the table is the same index as
    // its band on the axis and the two can be read against each other.
    let placed: Vec<Option<(f32, f32)>> = group.lanes.iter().map(|l| place(l.span, axis)).collect();
    let drawable: Vec<(f32, f32)> = placed.iter().filter_map(|p| *p).collect();
    let rows = pack_rows(&drawable);
    let row_count = rows.iter().copied().max().map_or(0, |r| r + 1);

    let bars_h = if row_count == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        let n = row_count as f32;
        n * BAR_H + (n - 1.0) * BAR_GAP
    };
    // Bands, then our own band, then the rule, its ticks and their numbers.
    let plot_h = bars_h + BAR_GAP + OWN_LANE_H + AXIS_RULE_H + TICK_H + TICK_LABEL_H;
    let own_top = bars_h + BAR_GAP;
    let rule_top = own_top + OWN_LANE_H;

    let mut plot = div()
        .debug_selector({
            let sel = format!("air-axis:{band}");
            move || sel
        })
        .relative()
        .w(px(AXIS_W))
        .h(px(plot_h));

    // The highlight goes down first, so every band is drawn over it: it is the
    // question ("who is in here?"), not an answer about any one neighbour.
    if let Some((left, w)) = group.own.and_then(|s| place(s, axis)) {
        plot = plot.child(
            div()
                .debug_selector({
                    let sel = format!("air-own-column:{band}");
                    move || sel
                })
                .absolute()
                .left(px(left))
                .top(px(0.0))
                .w(px(w))
                .h(px(rule_top))
                .bg(rgba(with_alpha(theme.accent, 0.16))),
        );
        plot = plot.child(
            div()
                .debug_selector({
                    let sel = format!("air-own:{band}");
                    move || sel
                })
                .absolute()
                .left(px(left))
                .top(px(own_top))
                .w(px(w))
                .h(px(OWN_LANE_H))
                .rounded_sm()
                .bg(rgb(theme.accent)),
        );
    }

    let mut drawn = 0usize;
    for (i, p) in placed.iter().enumerate() {
        let Some((left, w)) = *p else { continue };
        let row = rows[drawn];
        drawn += 1;
        #[allow(clippy::cast_precision_loss)]
        let top = bars_h - (row as f32 + 1.0) * BAR_H - row as f32 * BAR_GAP;
        plot = plot.child(
            div()
                .debug_selector({
                    let sel = format!("air-band:{band}:{i}");
                    move || sel
                })
                .absolute()
                .left(px(left))
                .top(px(top))
                .w(px(w))
                .h(px(BAR_H))
                .rounded_sm()
                .bg(rgba(with_alpha(theme.fg, weight(group.lanes[i].rssi_dbm)))),
        );
    }

    plot = plot.child(
        div()
            .absolute()
            .left(px(0.0))
            .top(px(rule_top))
            .w(px(AXIS_W))
            .h(px(AXIS_RULE_H))
            .bg(rgb(theme.separator)),
    );

    for tick in axis_ticks(group.band, axis, group.own.map(|s| s.channel)) {
        plot = plot.child(
            div()
                .absolute()
                .left(px(tick.x))
                .top(px(rule_top))
                .w(px(1.0))
                .h(px(if tick.labelled { TICK_H } else { TICK_H / 2.0 }))
                .bg(rgb(theme.separator)),
        );
        if !tick.labelled {
            continue;
        }
        let own = group.own.is_some_and(|s| s.channel == tick.channel);
        // Centred on its tick and clamped to the axis, so the leftmost and
        // rightmost numbers stay inside the drawing rather than hanging off it.
        let left = (tick.x - TICK_LABEL_HALF_W).clamp(0.0, AXIS_W - 2.0 * TICK_LABEL_HALF_W);
        plot = plot.child(
            div()
                .debug_selector({
                    let sel = format!("air-tick:{band}:{}", tick.channel);
                    move || sel
                })
                .absolute()
                .left(px(left))
                .top(px(rule_top + TICK_H))
                .w(px(2.0 * TICK_LABEL_HALF_W))
                .h(px(TICK_LABEL_H))
                .flex()
                .justify_center()
                .text_size(px(9.0))
                .text_color(rgb(if own { theme.accent } else { theme.muted }))
                .child(tick.channel.to_string()),
        );
    }

    let mut section = div()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .flex()
                .items_baseline()
                .gap_2()
                .child(
                    div()
                        .text_size(px(12.0))
                        .text_color(rgb(theme.fg))
                        .child(format!("{band} · channels")),
                )
                .child(
                    div()
                        .text_size(px(9.0))
                        .text_color(rgb(theme.muted))
                        .child(format!("{:.0}–{:.0} MHz", axis.0, axis.1)),
                ),
        )
        .children(band_relation(group).map(|line| {
            div()
                .text_size(px(10.0))
                .text_color(rgb(theme.muted))
                .child(line)
        }))
        .child(plot);

    for (i, lane) in group.lanes.iter().enumerate() {
        section = section.child(lane_row(group.band, i, lane, theme));
    }
    if group.dropped > 0 {
        section = section.child(
            div()
                .text_size(px(10.0))
                .text_color(rgb(theme.muted))
                .child(format!("+{} more heard, not drawn", group.dropped)),
        );
    }
    section.into_any_element()
}

/// One row of a band section's table: everything known about one foreign AP on a
/// single line, with the overlap cell present only where an overlap is
/// computable at all.
///
/// The ink is one neutral colour — deliberately not a severity palette, which
/// would read as a measured verdict about interference.
fn lane_row(band: Band, i: usize, lane: &Lane, theme: Theme) -> impl IntoElement + use<> {
    let sel = format!("air-row:{}:{i}", band_label(band));
    div()
        .debug_selector(move || sel)
        .flex()
        .items_baseline()
        .gap_2()
        .w(px(AXIS_W))
        .overflow_hidden()
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .text_size(px(11.0))
                .text_color(rgb(theme.fg))
                .child(lane_label(lane)),
        )
        .children(overlap_cell(lane).map(|cell| {
            div()
                .flex_none()
                .text_size(px(10.0))
                .text_color(rgb(theme.muted))
                .child(cell)
        }))
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
    if let Some(handle) = open_window(cx, glance.clone(), socket_path) {
        let any: AnyWindowHandle = handle.into();
        glance.update(cx, |g, _| g.air_window = Some(any));
        cx.activate(true);
    }
}

/// Create the air-map window and wire its subscription bridge.
fn open_window(
    cx: &mut App,
    glance: Entity<Glance>,
    socket_path: String,
) -> Option<WindowHandle<AirView>> {
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
                let empty = batch.is_empty();
                for msg in batch {
                    feed.apply(msg);
                }
                // Checked on EVERY tick, batch or no batch: the failure this
                // guards against is precisely the one where nothing arrives.
                let expired = feed.expire_scan(Instant::now());
                if !empty || expired {
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
        cx.new(|cx| AirView::new(feed, glance, shutdown, button_socket, button_tx, cx))
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
        // ...and the window is no longer waiting for anything.
        assert!(feed.scan_deadline.is_none());
    }

    /// The busy state is bounded. Both things it waits for can vanish without a
    /// successor — the answer dropped by a full bridge, the slice lost in a
    /// subscription reconnect — and the air collector is off by default, so no
    /// later event arrives to unstick the button. After the deadline the window
    /// says it stopped waiting instead of claiming a scan forever.
    #[test]
    fn a_busy_button_cannot_wait_forever() {
        for busy in [ScanState::Asking, ScanState::Scanning] {
            let mut feed = AirFeed::default();
            feed.apply(BridgeMsg::Scan(busy.clone()));
            assert_eq!(feed.scan, busy);
            // Nothing arrives; well inside the deadline the state still stands.
            assert!(!feed.expire_scan(Instant::now()));
            assert_eq!(feed.scan, busy);
            // Past it, the button is released and says why.
            assert!(feed.expire_scan(Instant::now() + SCAN_BUSY_TIMEOUT + Duration::from_secs(1)));
            assert!(
                matches!(feed.scan, ScanState::LostTrack(_)),
                "expected LostTrack, got {:?}",
                feed.scan
            );
            assert!(feed.scan_deadline.is_none());
            // And it stays released: an expired state is not re-expired.
            assert!(!feed.expire_scan(Instant::now() + SCAN_BUSY_TIMEOUT * 10));
        }
    }

    /// A settled state carries no deadline at all — the timeout guards only the
    /// waiting, never a refusal the daemon already delivered.
    #[test]
    fn a_settled_scan_state_is_never_expired() {
        let mut feed = AirFeed::default();
        feed.apply(BridgeMsg::Scan(ScanState::Refused("quiet is on".into())));
        assert!(feed.scan_deadline.is_none());
        assert!(!feed.expire_scan(Instant::now() + SCAN_BUSY_TIMEOUT * 10));
        assert!(matches!(feed.scan, ScanState::Refused(_)));
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
        assert!(five.lanes[0].overlap.hypothesis().unwrap().overlap > 0.0);
        assert_eq!(five.lanes[1].overlap.hypothesis().unwrap().overlap, 0.0);
    }

    /// Without an own association there is no overlap to hypothesise about, and
    /// the lane says so instead of showing a fabricated zero.
    #[test]
    fn no_own_channel_means_no_overlap_claim() {
        let groups = group(&scan(vec![ap(36, "5ghz", Some(80), Some(-60))]), None);
        let lane = &groups[0].lanes[0];
        assert_eq!(lane.overlap, Overlap::OwnChannelUnknown);
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
            own_elsewhere: None,
            lanes: vec![Lane {
                span: own(149, "5ghz", 20),
                rssi_dbm: Some(-60),
                phy_mode: None,
                security: None,
                overlap: Overlap::OwnChannelUnknown,
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
            overlap: Overlap::Computed(overlap_hypothesis(
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
            overlap: Overlap::OwnChannelUnknown,
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
    #[test]
    fn the_distance_hypothesis_shrinks_as_the_signal_grows() {
        let f = 5200.0;
        let mut last: Option<DistanceHypothesis> = None;
        for rssi in [-90, -80, -70, -60, -50, -40] {
            let d = distance_hypothesis(rssi, f).expect("a placeable carrier");
            if let Some(prev) = last {
                assert!(
                    d.near_m <= prev.near_m && d.far_m <= prev.far_m,
                    "a louder neighbour was estimated further away: {rssi} dBm -> {d:?} \
                     after {prev:?}"
                );
            }
            last = Some(d);
        }
        // And somewhere in the ordinary range the shrinking is real, not a plateau
        // of clamps.
        let far = distance_hypothesis(-80, f).unwrap();
        let near = distance_hypothesis(-50, f).unwrap();
        assert!(near.far_m < far.far_m, "{near:?} vs {far:?}");
    }

    #[test]
    fn the_distance_hypothesis_is_always_a_bracket_inside_its_own_window() {
        for rssi in -100..=-10 {
            for f in [2437.0, 5200.0, 6135.0] {
                let d = distance_hypothesis(rssi, f).expect("a placeable carrier");
                assert!(
                    d.near_m >= DISTANCE_FLOOR_M && d.far_m <= DISTANCE_CEILING_M,
                    "{rssi} dBm at {f} MHz left the model's window: {d:?}"
                );
                assert!(
                    d.far_m >= d.near_m * MIN_DISTANCE_SPREAD,
                    "{rssi} dBm at {f} MHz was answered too narrowly to be a guess: {d:?}"
                );
                let label = distance_label(d);
                assert!(
                    label.starts_with("est. ") && label.contains('\u{2013}'),
                    "the distance was not offered as a marked range: {label}"
                );
                let ends: Vec<&str> = label
                    .trim_start_matches("est. ")
                    .trim_end_matches(" m")
                    .split('\u{2013}')
                    .collect();
                assert_eq!(ends.len(), 2, "not two ends: {label}");
                assert_ne!(ends[0], ends[1], "the range rounded to one number: {label}");
            }
        }
    }

    #[test]
    fn an_unplaceable_carrier_gets_no_distance_at_all() {
        assert!(distance_hypothesis(-60, 0.0).is_none());
        assert!(distance_hypothesis(-60, f64::NAN).is_none());
    }

    #[test]
    fn a_neighbour_without_a_signal_sits_on_no_ring() {
        let sample = scan(vec![
            ap(36, "5ghz", Some(80), Some(-55)),
            ap(40, "5ghz", Some(20), None),
        ]);
        let RingMarks {
            placed,
            unplaceable,
        } = ring_marks(&sample, Some(own(36, "5ghz", 80)));
        assert_eq!(placed.len(), 1);
        assert_eq!(unplaceable.len(), 1, "it must be counted, never dropped");
        assert!(
            ring_mark_label(&unplaceable[0].1).contains("signal not reported"),
            "an unheard signal must be said, not implied"
        );
    }

    #[test]
    fn a_mark_names_its_channel_its_width_and_a_distance_range() {
        let sample = scan(vec![ap(36, "5ghz", Some(80), Some(-62))]);
        let RingMarks { placed, .. } = ring_marks(&sample, Some(own(36, "5ghz", 80)));
        let label = ring_mark_label(&placed[0].1);
        assert!(label.contains("-62 dBm"), "{label}");
        assert!(label.contains("ch 36"), "{label}");
        assert!(label.contains("80 MHz"), "{label}");
        assert!(
            label.contains("est. ") && label.contains('\u{2013}'),
            "{label}"
        );
    }

    #[test]
    fn the_rings_are_ordered_outward_by_falling_signal() {
        let d = 520.0;
        let mut last = -1.0_f32;
        for level in RING_LEVELS {
            let r = ring_radius(f64::from(level), d);
            assert!(r > last, "ring {level} dBm is not outside the louder one");
            assert!(r <= ring_max_r(d) + 0.01);
            last = r;
        }
    }
}

/// Headless UI tests for the air map, on gpui's own test platform: layout and
/// scene construction run for real, rasterization does not.
///
/// **What this carrier cannot say.** gpui's debug-bounds map only ever grows
/// over a window's life: `Frame::clear()` clears every other per-frame table and
/// leaves `debug_bounds` alone, so a selector drawn once stays findable in that
/// window forever. Presence is therefore assertable anywhere; **absence is
/// assertable only in a window that never drew the element** — open a fresh one
/// in the mode under test rather than switching an existing one into it.
///
/// The fixture is a verbatim `system_profiler -json SPAirPortDataType` slice
/// taken from this Mac while it was associated on 5 GHz channel 48 — fifteen
/// audible foreign access points, ten in 2.4 GHz and five in 5 GHz. It is the
/// slice the window was first run against, and the one it was unreadable on. It
/// is parsed by `macos::air::parse_air_report`, the daemon's own parser, so what
/// these tests draw is what production would hand the window.
#[cfg(test)]
mod headless_tests {
    use super::*;
    use crate::ui::Glance;
    use gpui::{Bounds, Pixels, Size, TestAppContext, VisualTestContext};
    use net_observer_ipc::StatusSnapshot;

    /// The captured report.
    const LIVE_REPORT: &str = include_str!("../tests/fixtures/air_live.json");

    /// Every foreign AP in the fixture, through the daemon's own parser.
    fn live_aps() -> Vec<AirObservation> {
        macos::air::parse_air_report(LIVE_REPORT).expect("the fixture is a readable report")
    }

    /// This Mac's own association as the same fixture states it, read with the
    /// same channel parser — never retyped, or the test would prove the window
    /// against a channel the report does not carry.
    fn live_own() -> ChannelSpan {
        let v: serde_json::Value = serde_json::from_str(LIVE_REPORT).expect("the fixture is JSON");
        let current = v["SPAirPortDataType"][0]["spairport_airport_interfaces"][0]
            ["spairport_current_network_information"]["spairport_network_channel"]
            .as_str()
            .expect("the fixture names our own channel");
        let (ch, band, width) = macos::air::parse_channel(current);
        ChannelSpan::new(ch, band.as_deref(), width).expect("our own channel is placeable")
    }

    fn live_sample() -> AirSample {
        AirSample {
            ts_us: 1_700_000_000_000_000,
            air: AirVerdict::Ok,
            reason: None,
            aps: live_aps(),
        }
    }

    /// A window showing the live slice, ready to be measured.
    fn live_window(cx: &mut TestAppContext) -> (VisualTestContext, Size<Pixels>) {
        let (vcx, viewport, _handle) = live_window_at(cx, size(px(WIN_W), px(WIN_H)));
        (vcx, viewport)
    }

    /// The same window at a chosen size, keeping the handle so a test can drive
    /// the view switch the way a click does. Opens on the channel axis, the mode
    /// the window opens in for real.
    fn live_window_at(
        cx: &mut TestAppContext,
        viewport: Size<Pixels>,
    ) -> (VisualTestContext, Size<Pixels>, WindowHandle<AirView>) {
        live_window_in(cx, viewport, AirMode::Channels)
    }

    /// A window that opens ALREADY in `mode` and has therefore never drawn any
    /// other mode's elements. This is the only window an absence can be asserted
    /// in — see the note on the debug-bounds map at the top of this module.
    fn live_window_in(
        cx: &mut TestAppContext,
        viewport: Size<Pixels>,
        mode: AirMode,
    ) -> (VisualTestContext, Size<Pixels>, WindowHandle<AirView>) {
        let own = live_own();
        let glance = cx.update(|cx| {
            cx.new(|_| {
                Glance::new(
                    StatusSnapshot::default(),
                    None,
                    "/tmp/net-observer-air-test.sock".to_string(),
                )
            })
        });
        let feed = cx.update(|cx| {
            cx.new(|_| AirFeed {
                air: Some(live_sample()),
                own: Some(WifiSample {
                    ts_us: 1_700_000_000_000_000,
                    wifi: WifiVerdict::Ok,
                    reason: None,
                    rssi_dbm: Some(-50),
                    noise_dbm: Some(-96),
                    snr_db: Some(46),
                    tx_rate_mbps: Some(216.0),
                    phy_mode: Some("11ax".to_string()),
                    channel: Some(own.channel),
                    channel_width_mhz: Some(own.width_mhz),
                    channel_band: Some(own.band.as_str().to_string()),
                }),
                ..Default::default()
            })
        });
        // A bridge that goes nowhere: the window under test is fed from the
        // fixture, not from a socket, and nothing here presses "scan now".
        let (tx, _rx) = mpsc::sync_channel(BRIDGE_DEPTH);
        let window = cx.add_window(|_, cx| {
            let mut view = AirView::new(
                feed,
                glance,
                Arc::new(Shutdown::default()),
                "/tmp/net-observer-air-test.sock".to_string(),
                tx,
                cx,
            );
            // Set before the first paint, so this window never draws any other
            // mode.
            view.mode = mode;
            view
        });
        let vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.simulate_resize(viewport);
        vcx.run_until_parked();
        (vcx, viewport, window)
    }

    /// Switch the view the way the tab does, then let the frame settle.
    fn switch_to(cx: &mut VisualTestContext, window: WindowHandle<AirView>, mode: AirMode) {
        window
            .update(cx, |view, _window, cx| {
                view.mode = mode;
                cx.notify();
            })
            .expect("the window is open");
        cx.run_until_parked();
    }

    /// A window big enough for the rings to be drawn whole — the size this view
    /// is meant to be read at.
    fn rings_viewport() -> Size<Pixels> {
        size(px(760.0), px(980.0))
    }

    fn bounds(cx: &mut VisualTestContext, selector: &str) -> Option<Bounds<Pixels>> {
        let sel: &'static str = Box::leak(selector.to_string().into_boxed_str());
        cx.debug_bounds(sel)
    }

    /// Each band section draws ONE axis, and every band and every channel number
    /// in that section lies inside it — the axis is the section, not a decoration
    /// beside it.
    ///
    /// The failure this pins is the shape the window shipped with: no shared
    /// axis at all, one private strip per access point. There is then no
    /// `air-axis:*` to find and no tick to measure, so this test cannot pass on a
    /// per-AP list however that list is laid out.
    #[gpui::test]
    fn every_band_and_channel_number_sits_inside_its_band_axis(cx: &mut TestAppContext) {
        let (mut cx, _viewport) = live_window(cx);
        let own = live_own();
        let groups = group(&live_sample(), Some(own));
        assert_eq!(groups.len(), 2, "the fixture is heard in exactly two bands");

        for g in &groups {
            let band = band_label(g.band);
            let axis = bounds(&mut cx, &format!("air-axis:{band}"))
                .unwrap_or_else(|| panic!("the {band} section drew no shared axis"));
            assert!(
                (axis.size.width - px(AXIS_W)).abs() < px(0.51),
                "the {band} axis is not the full drawn width: {axis:?}"
            );

            let mut ticks = 0;
            for ch in band_channels(g.band) {
                if let Some(t) = bounds(&mut cx, &format!("air-tick:{band}:{ch}")) {
                    ticks += 1;
                    assert!(
                        within(axis, t),
                        "the channel number {ch} spills out of the {band} axis: \
                         {t:?} vs {axis:?}"
                    );
                }
            }
            assert!(
                ticks >= 4,
                "the {band} axis carries only {ticks} channel numbers — an axis \
                 nobody can read a channel off"
            );

            for i in 0..g.lanes.len() {
                let bar = bounds(&mut cx, &format!("air-band:{band}:{i}"))
                    .unwrap_or_else(|| panic!("{band} band {i} was not drawn on the axis"));
                assert!(
                    within(axis, bar),
                    "{band} band {i} leaves its own axis: {bar:?} vs {axis:?}"
                );
            }
        }
    }

    /// Our own association is drawn on the SAME axis as the neighbours, inside
    /// its band's section and nowhere else — so "who is standing in my channel"
    /// is a question the picture answers.
    #[gpui::test]
    fn our_own_channel_is_marked_on_the_axis_it_shares_with_the_neighbours(
        cx: &mut TestAppContext,
    ) {
        let (mut cx, _viewport) = live_window(cx);
        let own = live_own();
        let here = band_label(own.band);
        let axis = bounds(&mut cx, &format!("air-axis:{here}")).expect("our band drew its axis");
        let mark = bounds(&mut cx, &format!("air-own:{here}"))
            .expect("our own association is drawn on our band's axis");
        assert!(within(axis, mark), "{mark:?} vs {axis:?}");
        let column = bounds(&mut cx, &format!("air-own-column:{here}"))
            .expect("our channel is highlighted across the axis");
        assert!(within(axis, column));
        assert!(
            column.size.height > mark.size.height,
            "the highlight must run up through the neighbours' rows, not sit beside them"
        );
        assert!(
            bounds(&mut cx, &format!("air-tick:{here}:{}", own.channel)).is_some(),
            "our own channel number must be printed even where ticks are thinned"
        );

        let other = other_band(&live_sample(), own);
        assert!(
            bounds(&mut cx, &format!("air-own:{}", band_label(other))).is_none(),
            "our band must not be drawn on a band we are not in"
        );
    }

    /// The band a neighbour was heard in that is NOT ours.
    fn other_band(sample: &AirSample, own: ChannelSpan) -> Band {
        group(sample, Some(own))
            .into_iter()
            .map(|g| g.band)
            .find(|b| *b != own.band)
            .expect("the fixture is heard in a second band")
    }

    /// Every word the window puts on screen for the live slice, gathered from
    /// the functions that produce it.
    fn live_text() -> Vec<String> {
        let own = live_own();
        let mut out = Vec::new();
        for g in group(&live_sample(), Some(own)) {
            out.push(band_label(g.band).to_string());
            out.extend(band_relation(&g));
            for lane in &g.lanes {
                out.push(lane_label(lane));
                out.push(overlap_label(lane));
                out.extend(overlap_cell(lane));
            }
        }
        out
    }

    /// No platform token reaches the reader.
    ///
    /// The live report spells one security mode
    /// `pairport_security_mode_wpa3_transition` — the documented token with its
    /// leading `s` missing — and the window printed it verbatim under five of the
    /// fifteen access points. The substring test is on `pairport`, so BOTH
    /// spellings fail it: matching the documented prefix alone is exactly the bug.
    #[test]
    fn no_platform_token_reaches_the_reader() {
        let text = live_text();
        assert!(
            !text.is_empty(),
            "the fixture must produce labels for this to prove anything"
        );
        // The token itself first, so a failure names the defect rather than
        // whichever line happened to be ranked first.
        for line in &text {
            assert!(
                !line.contains("pairport"),
                "a raw system_profiler token reached the window: {line}"
            );
        }
        for line in &text {
            assert!(
                !line.contains('_'),
                "a platform identifier reached the window unspaced: {line}"
            );
        }
        // Not merely absent: the fact the token carried is still said.
        assert!(
            text.iter().any(|l| l.contains("WPA3")),
            "the WPA3-transition networks lost their security mode entirely"
        );
        assert!(
            text.iter().any(|l| l.contains("WPA2")),
            "the WPA2 networks lost their security mode entirely"
        );
    }

    /// With our own channel known, a neighbour in the other band is described as
    /// being in another band — never as evidence that our channel is unknown.
    ///
    /// This is the contradiction the window shipped with: the header said
    /// "this Mac: 5 GHz · ch 48 · 20 MHz" while every 2.4 GHz neighbour under it
    /// said our channel was unknown.
    #[test]
    fn a_neighbour_in_another_band_never_calls_our_channel_unknown() {
        let own = live_own();
        let groups = group(&live_sample(), Some(own));
        let elsewhere = groups
            .iter()
            .find(|g| g.band != own.band)
            .expect("the fixture is heard in a second band");
        assert!(
            !elsewhere.lanes.is_empty(),
            "the other band must carry neighbours"
        );
        assert_eq!(elsewhere.own_elsewhere, Some(own.band));

        let relation = band_relation(elsewhere).expect("the section states its relation to us");
        assert!(
            !relation.contains("unknown"),
            "the section calls our known channel unknown: {relation}"
        );
        assert!(
            relation.contains(band_label(own.band)),
            "the section must name where this Mac actually is: {relation}"
        );

        for lane in &elsewhere.lanes {
            assert_eq!(lane.overlap, Overlap::OwnBandElsewhere(own.band));
            let line = overlap_label(lane);
            assert!(
                !line.contains("unknown"),
                "a cross-band neighbour claims our channel is unknown: {line}"
            );
            assert!(
                line.contains("different band"),
                "a cross-band neighbour must say why there is no overlap: {line}"
            );
            assert!(
                overlap_cell(lane).is_none(),
                "no overlap figure may be offered where none is computable"
            );
        }

        // And the hedge that IS about an unknown channel still exists, for the
        // case that really is one: without an association, nothing is computable.
        let blind = group(&live_sample(), None);
        assert!(
            overlap_label(&blind[0].lanes[0]).contains("unknown"),
            "an actually unknown own channel must still say so"
        );
    }

    /// Every mark of the rings view lies inside the drawing, and the drawing
    /// inside the window — no neighbour is pushed off the page by a caption.
    #[gpui::test]
    fn every_ring_mark_sits_inside_the_drawing_and_inside_the_window(cx: &mut TestAppContext) {
        let (mut cx, viewport, window) = live_window_at(cx, rings_viewport());
        switch_to(&mut cx, window, AirMode::Rings);

        let plot = bounds(&mut cx, "air-rings").expect("the rings view drew its plot");
        let page = Bounds {
            origin: gpui::Point {
                x: px(0.0),
                y: px(0.0),
            },
            size: viewport,
        };
        assert!(within(page, plot), "the plot leaves the window: {plot:?}");
        assert!(
            bounds(&mut cx, "air-rings-centre").is_some_and(|c| within(plot, c)),
            "this Mac must be drawn at the centre of its own rings"
        );
        for level in RING_LEVELS {
            let ring = bounds(&mut cx, &format!("air-ring:{level}"))
                .unwrap_or_else(|| panic!("the {level} dBm ring was not drawn"));
            assert!(within(plot, ring), "the {level} dBm ring spills: {ring:?}");
        }

        let RingMarks { placed, .. } = ring_marks(&live_sample(), Some(live_own()));
        assert!(
            placed.len() > 5,
            "the fixture must be crowded to prove this"
        );
        for i in 0..placed.len() {
            let mark = bounds(&mut cx, &format!("air-ring-mark:{i}"))
                .unwrap_or_else(|| panic!("neighbour {i} was not marked on any ring"));
            assert!(
                within(plot, mark),
                "mark {i} leaves the drawing: {mark:?} vs {plot:?}"
            );
            assert!(
                within(page, mark),
                "mark {i} leaves the window: {mark:?} vs {page:?}"
            );
        }
    }

    /// The one thing this view could be misread as — a direction finder — is
    /// denied on the page itself, permanently, not in a tooltip.
    #[gpui::test]
    fn the_rings_say_on_the_page_that_the_angle_means_nothing(cx: &mut TestAppContext) {
        let (mut cx, _viewport, window) = live_window_at(cx, rings_viewport());
        switch_to(&mut cx, window, AirMode::Rings);
        assert!(
            bounds(&mut cx, "air-rings-angle-caveat").is_some(),
            "the standing line about the angle is not on the page"
        );
        let line = ANGLE_MEANS_NOTHING;
        assert!(line.contains("angle"), "{line}");
        assert!(
            line.contains("means nothing") || line.contains("arbitrary"),
            "the line hedges instead of denying: {line}"
        );
        assert!(
            METRES_ARE_A_GUESS.contains("hypothesis")
                && METRES_ARE_A_GUESS.contains(
                    "not a \
             measurement"
                ),
            "the metres are not marked as a guess: {METRES_ARE_A_GUESS}"
        );
    }

    /// Distance reaches the reader as a bracket with an estimate mark, never as
    /// one number that could be read as a measurement.
    #[test]
    fn every_drawn_neighbour_is_given_a_distance_range_and_never_a_figure() {
        let RingMarks { placed, .. } = ring_marks(&live_sample(), Some(live_own()));
        assert!(!placed.is_empty(), "the fixture must place neighbours");
        for (_band, lane) in &placed {
            let label = ring_mark_label(lane);
            assert!(
                label.contains("est. "),
                "a distance was offered unmarked: {label}"
            );
            let tail = label.rsplit("est. ").next().unwrap();
            assert!(
                tail.contains('\u{2013}') && tail.ends_with(" m"),
                "the distance is not a range: {label}"
            );
            let ends: Vec<&str> = tail.trim_end_matches(" m").split('\u{2013}').collect();
            assert_eq!(ends.len(), 2, "{label}");
            assert_ne!(ends[0], ends[1], "the range collapsed to a number: {label}");
            // The measured quantity leads; metres follow it.
            let dbm = label.find("dBm").expect("the reading leads the caption");
            assert!(dbm < label.find("est. ").unwrap(), "{label}");
        }
    }

    /// A round trip through the rings and back loses nothing: the channel axis is
    /// whole again with every band on it, and the rings carry exactly the
    /// neighbours the axis does.
    ///
    /// It says nothing about what the rings view does NOT draw: this window drew
    /// the axis on the way in, so its debug bounds keep the axis findable for the
    /// rest of its life whatever is on screen. That absence is asserted in
    /// `a_window_opened_on_the_rings_never_draws_the_channel_axis`, in a window
    /// that never drew one.
    #[gpui::test]
    fn a_round_trip_through_the_rings_and_back_keeps_the_whole_slice(cx: &mut TestAppContext) {
        let (mut cx, _viewport, window) = live_window_at(cx, rings_viewport());
        let own = live_own();
        let groups = group(&live_sample(), Some(own));
        let here = band_label(own.band);

        let axis_before =
            bounds(&mut cx, &format!("air-axis:{here}")).expect("the channel axis is drawn first");

        switch_to(&mut cx, window, AirMode::Rings);
        let RingMarks {
            placed,
            unplaceable,
        } = ring_marks(&live_sample(), Some(own));
        let drawn: usize = groups.iter().map(|g| g.lanes.len()).sum();
        assert_eq!(
            placed.len() + unplaceable.len(),
            drawn,
            "the rings view lost neighbours the axis view had"
        );
        for i in 0..placed.len() {
            assert!(
                bounds(&mut cx, &format!("air-ring-mark:{i}")).is_some(),
                "neighbour {i} vanished on the rings"
            );
        }

        switch_to(&mut cx, window, AirMode::Channels);
        let axis_after = bounds(&mut cx, &format!("air-axis:{here}"))
            .expect("the channel axis came back with its data");
        assert_eq!(axis_before.size, axis_after.size);
        for g in &groups {
            let band = band_label(g.band);
            for i in 0..g.lanes.len() {
                assert!(
                    bounds(&mut cx, &format!("air-band:{band}:{i}")).is_some(),
                    "{band} band {i} was lost by the round trip through the rings"
                );
            }
        }
    }

    /// A window that opens on the rings draws the rings and no channel axis.
    ///
    /// The absence half of the round-trip test, and it lives here because it can
    /// only be said here: this window has never drawn an axis, so a found
    /// `air-axis:*` would be one the rings view drew now.
    #[gpui::test]
    fn a_window_opened_on_the_rings_never_draws_the_channel_axis(cx: &mut TestAppContext) {
        let (mut cx, _viewport, _window) = live_window_in(cx, rings_viewport(), AirMode::Rings);
        for g in group(&live_sample(), Some(live_own())) {
            let band = band_label(g.band);
            assert!(
                bounds(&mut cx, &format!("air-axis:{band}")).is_none(),
                "the {band} channel axis is drawn under the rings"
            );
        }
        for level in RING_LEVELS {
            assert!(
                bounds(&mut cx, &format!("air-ring:{level}")).is_some(),
                "the {level} m ring is missing from the view that is only rings"
            );
        }
    }

    /// And the other way: a window that opens on the channel axis draws the axis
    /// and no rings. Same reason it is a separate window.
    #[gpui::test]
    fn a_window_opened_on_the_channels_never_draws_the_rings(cx: &mut TestAppContext) {
        let (mut cx, _viewport, _window) = live_window_in(cx, rings_viewport(), AirMode::Channels);
        for level in RING_LEVELS {
            assert!(
                bounds(&mut cx, &format!("air-ring:{level}")).is_none(),
                "the {level} m ring is drawn over the channel axis"
            );
        }
        let here = band_label(live_own().band);
        assert!(
            bounds(&mut cx, &format!("air-axis:{here}")).is_some(),
            "the view that is only the axis drew no axis"
        );
    }

    /// `inner` lies wholly inside `outer`, both in absolute window coordinates.
    /// A half-pixel of slack absorbs the rounding of a flex layout, not a spill.
    fn within(outer: Bounds<Pixels>, inner: Bounds<Pixels>) -> bool {
        let slack = px(0.5);
        inner.origin.x + slack >= outer.origin.x
            && inner.origin.y + slack >= outer.origin.y
            && inner.origin.x + inner.size.width <= outer.origin.x + outer.size.width + slack
            && inner.origin.y + inner.size.height <= outer.origin.y + outer.size.height + slack
    }
}
