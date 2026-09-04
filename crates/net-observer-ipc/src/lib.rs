//! Local socket protocol shared by `net-observerd` (server) and `net-observer-bar` (client).
//!
//! The daemon is the sole owner of the DuckDB file; every other process reads
//! live status through a Unix-domain socket. This crate defines the wire types
//! and the newline-delimited JSON framing so both sides agree on the format.
//!
//! Two paths share that one framing:
//!
//! * **Request/response** — one [`Request`] in, one [`Response`] out, then the
//!   connection closes. The blocking [`query`] client drives it.
//! * **Subscribe stream** — a [`Request::Subscribe`] connection is held open and
//!   carries [`StreamFrame`]s, never a [`Response`]. The daemon **acks the
//!   subscription** with a mandatory [`StreamFrame::Ready`] written only *after*
//!   its broadcast receiver exists, so nothing published once [`subscribe`] has
//!   returned can fall into a publish-before-subscribe window. Only
//!   [`StreamFrame::Event`] frames are subject to a subscriber's `kinds` filter;
//!   the stream-integrity frames (ack, [`Gap`], observing transition,
//!   [`StreamError`]) are **always** delivered — a filtered subscriber has more
//!   need to know about a hole or a pause, not less. That rule lives in exactly
//!   one place, [`EncodedFrame::passes`].
//!
//! Deliberately runtime-agnostic: there is **no** tokio dependency here. The
//! blocking [`query`]/[`subscribe`] clients are all the bar needs; the async
//! server in `net-observerd` reuses
//! [`encode_frame`]/[`write_frame`]/[`read_frame`]/[`EncodedFrame`] over its own
//! runtime.
//!
//! This crate deliberately keeps plain `io::Result` instead of the `thiserror`
//! enum the workspace mandates for libraries: it *is* the transport boundary, and
//! callers already switch on `io::ErrorKind` — `InvalidData` for a bad frame vs
//! `NotFound`/`ConnectionRefused`/`TimedOut` for a daemon that is not there. A
//! bespoke error type would add a dependency to the one crate whose entire job is
//! the wire format, without telling callers anything the kind does not.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use serde::{Serialize, de::DeserializeOwned};
use types::{
    AirSample, DnsSample, HostSample, LinkSample, NeighborLifetime, NeighborsSample, ObservingEdge,
    ProxySample, RouteEvent, TopologyLifetime, TopologyLink, WifiSample,
};

/// A request from a client (the bar or cli) to the daemon.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Request {
    /// Fetch the current live [`StatusSnapshot`].
    Status,
    /// Fetch the most recent incidents, newest first, capped at `limit`.
    Incidents { limit: usize },
    /// Ask the daemon to run a write/control action (the "acting" path). The
    /// daemon executes it as root **only** when `acting.enabled` is set (off by
    /// default); otherwise the request is refused without running anything.
    Control(ControlCmd),
    /// Open a live event subscription. Unlike the one-shot requests above, a
    /// `Subscribe` connection is **not** answered by a single [`Response`]: the
    /// daemon writes a mandatory [`StreamFrame::Ready`] ack (created *after* its
    /// bus receiver exists, so nothing published afterwards can be lost), then
    /// holds the connection open and streams newline-JSON [`StreamFrame`]s until
    /// the client disconnects. `kinds` filters only [`StreamFrame::Event`]
    /// frames server-side — `None` subscribes to every [`EventKind`]. Gap,
    /// observing and error frames are delivered regardless of the filter. The
    /// blocking [`subscribe`] helper drives this path.
    Subscribe { kinds: Option<Vec<EventKind>> },
}

/// A write/control command the client asks the daemon to execute.
///
/// Extensible — one conservative, human-in-the-loop action for now. The daemon
/// (never a client) is the only process that executes these, and only when
/// acting is explicitly enabled in its config.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ControlCmd {
    /// Restart the sing-box proxy service (`launchctl kickstart -k <service>`),
    /// the same recovery net-observer's watchdog used — but triggered manually.
    KickstartProxy,
    /// Turn the observer's OWN collection on (`true`) or off (`false`) —
    /// pause/resume. This is benign **self-control**: it does NOT touch sing-box
    /// or the network, and is NOT gated by `acting.enabled`. While paused the
    /// daemon stays alive and the socket keeps serving so the switch can turn
    /// collection back on.
    SetObserving(bool),
    /// Copy the pcap ring out NOW, into a fresh freeze directory — the same
    /// passive artifact the `gw-change` trigger produces, but operator-initiated.
    /// **Self-control**: it touches only files the daemon already owns and sends
    /// nothing on the network, so it is NOT gated by `acting.enabled`. Refused
    /// (`ok: false`) when the ring is disabled or never started.
    FreezePcap,
    /// Turn "quiet" on (`true`) or off (`false`): while quiet the daemon
    /// addresses NO packet AT the gateway — in this daemon that is the link
    /// collector's ICMP echo, and only that. Passive facts (ARP table, DHCP
    /// lease) keep being read, and the link collector keeps emitting one sample
    /// per tick with `gw = SKIP` — quiet silences the wire, never the record.
    /// **Self-control**, like [`ControlCmd::SetObserving`], and process-scoped:
    /// a restart resumes normal probing.
    SetQuiet(bool),
    /// Go and find out who else is on this segment NOW: sweep the local IPv4
    /// subnet so the kernel resolves every address, and browse mDNS for names.
    ///
    /// The one command in this daemon that deliberately addresses machines that
    /// are not this one, which is why it is **acting-class** and refused unless
    /// `acting.enabled` is set — and why every run writes a `neighbor_scan` row
    /// saying what was probed. The passive `neighbors` collector needs none of
    /// this: it only ever reads caches the OS already filled.
    ///
    /// Carries [`ScanOptions`]: which rungs of the scan this run should include.
    /// The daemon runs a rung only when it is BOTH requested here and permitted
    /// by config; a requested-but-unpermitted rung is dropped and the result
    /// message says so.
    ScanNeighbors(ScanOptions),
    /// Read the radio environment ONCE, now — the same slice the `air` collector
    /// produces on its slow period, taken on operator demand instead.
    ///
    /// **Self-control, like [`ControlCmd::FreezePcap`] and [`ControlCmd::SetQuiet`],
    /// and deliberately NOT acting-class.** The daemon asks the operating system
    /// for its own radio's report; it addresses no host and originates no frame of
    /// its own on the air. That is the whole difference from
    /// [`ControlCmd::ScanNeighbors`], which speaks to machines that are not this
    /// one and therefore takes the stronger gate.
    ///
    /// One press, one scan: the daemon starts at most one on-demand scan at a
    /// time and refuses a second while the first runs, or too soon after it — the
    /// report costs seconds. The command returns as soon as the scan is
    /// *accepted*, not when it finishes; the resulting sample arrives on the bus
    /// as an ordinary [`Event::Air`] (a `Skip` one, with its reason, when the
    /// radio could not be read — never silence).
    ScanAir,
}

/// Which rungs of an operator-pressed scan a single run should include.
///
/// The base scan (subnet sweep + mDNS) always runs; these are the additions,
/// each defaulting to `false`. `serde(default)` covers forward growth WITHIN this
/// struct — a newer daemon adding a rung field still decodes an older client's
/// `ScanOptions` that omits it. It does NOT rescue the enclosing variant's shape
/// change (`ScanNeighbors` went from a unit variant to this newtype): a
/// pre-options client that emits the bare string `"ScanNeighbors"` hard-errors
/// against a daemon expecting `{"ScanNeighbors": {...}}`. That is acceptable on a
/// single-host coordinated deploy, where the daemon and its clients ship
/// together, but it is a decode failure, not a silent base-scan fallback.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanOptions {
    /// Probe discovered neighbours' TCP ports.
    #[serde(default)]
    pub ports: bool,
    /// Grab banners from the open ports the port scan found. Needs `ports` in
    /// the same run to have anything to grab from; the daemon enforces the
    /// effective intersection.
    #[serde(default)]
    pub banners: bool,
    /// Match the grabbed banners against the daemon's local CVE snapshot. Needs
    /// `banners` in the same run (a match parses a banner) and a provisioned
    /// snapshot; without either the daemon drops it and says so. Each stored
    /// match is a hypothesis carrying its confidence, never an asserted fact.
    #[serde(default)]
    pub cve: bool,
}

/// The outcome of a [`ControlCmd`]: whether the action ran successfully plus a
/// human-readable message the client surfaces to the operator.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ControlResult {
    /// `true` iff the action ran and succeeded. A refusal (acting disabled) or a
    /// failed action is `false`.
    pub ok: bool,
    /// A readable explanation (e.g. `"acting disabled"`, or the actuator output).
    pub message: String,
}

/// A compact, serializable view of one incident for the live API.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IncidentSummary {
    pub id: String,
    pub opened_us: i64,
    pub closed_us: Option<i64>,
    pub trigger_id: String,
    pub signature: String,
}

/// The category of a live [`Event`]. Used both to tag events and, in a
/// [`Request::Subscribe`], to filter which kinds the daemon streams.
///
/// `Copy` so a filter list is cheap to test against per event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EventKind {
    Link,
    Proxy,
    Dns,
    Route,
    Host,
    Wifi,
    Neighbors,
    /// The radio environment: one scan of the foreign access points audible here.
    Air,
    Incident,
}

impl EventKind {
    /// The short lowercase label for this kind — the same vocabulary the CLI's
    /// `--kind` flag accepts and the bar's selector chips render. Lives here so
    /// every consumer spells the kinds identically.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Link => "link",
            EventKind::Proxy => "proxy",
            EventKind::Dns => "dns",
            EventKind::Route => "route",
            EventKind::Host => "host",
            EventKind::Wifi => "wifi",
            EventKind::Neighbors => "neighbors",
            EventKind::Air => "air",
            EventKind::Incident => "incident",
        }
    }
}

/// One live event pushed over a [`Request::Subscribe`] stream: either a fresh
/// collector [`Sample`](types::Sample) or a newly recorded incident. Each frame
/// carries its own payload so subscribers can render it without a second lookup.
///
/// Sized like [`Response`]: the `Link` variant dominates, but this is the shared
/// wire type the daemon constructs directly and boxing would add an allocation on
/// the hot publish path, so the `large_enum_variant` lint is allowed here too.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Event {
    Link(LinkSample),
    Proxy(ProxySample),
    Dns(DnsSample),
    Route(RouteEvent),
    Host(HostSample),
    Wifi(WifiSample),
    Neighbors(NeighborsSample),
    Air(AirSample),
    Incident(IncidentSummary),
}

impl Event {
    /// The [`EventKind`] this event belongs to — the discriminator subscribers
    /// filter on.
    pub fn kind(&self) -> EventKind {
        match self {
            Event::Link(_) => EventKind::Link,
            Event::Proxy(_) => EventKind::Proxy,
            Event::Dns(_) => EventKind::Dns,
            Event::Route(_) => EventKind::Route,
            Event::Host(_) => EventKind::Host,
            Event::Wifi(_) => EventKind::Wifi,
            Event::Neighbors(_) => EventKind::Neighbors,
            Event::Air(_) => EventKind::Air,
            Event::Incident(_) => EventKind::Incident,
        }
    }

    /// The event's timestamp in epoch microseconds. Samples expose their own
    /// `ts_us`; an incident uses its `opened_us`.
    pub fn ts_us(&self) -> i64 {
        match self {
            Event::Link(l) => l.ts_us,
            Event::Proxy(p) => p.ts_us,
            Event::Dns(d) => d.ts_us,
            Event::Route(r) => r.ts_us,
            Event::Host(h) => h.ts_us,
            Event::Wifi(w) => w.ts_us,
            Event::Neighbors(n) => n.ts_us,
            Event::Air(a) => a.ts_us,
            Event::Incident(i) => i.opened_us,
        }
    }

    /// The per-variant one-line detail rendered next to the kind label. Pure over
    /// its input (no clock, no locale), so both the CLI tail and the bar's event
    /// log share one formatting of every variant instead of drifting copies.
    /// Absent optional fields render as a `-` placeholder.
    pub fn detail(&self) -> String {
        match self {
            Event::Link(l) => format!("gw={} direct={}", l.gw, l.direct),
            Event::Proxy(p) => {
                let tun = p
                    .tun_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string());
                let sel = p.selector.as_deref().unwrap_or("-");
                format!("tun={tun} sel={sel}")
            }
            Event::Dns(d) => {
                let ip = d.ip.as_deref().unwrap_or("-");
                format!("{}/{} {} {}", d.probe, d.server, d.verdict, ip)
            }
            Event::Route(r) => {
                let iface = r.iface.as_deref().unwrap_or("-");
                format!("{} {} {}", r.kind, iface, r.detail)
            }
            Event::Host(h) => format!("load {:.2}/{:.2}/{:.2}", h.load1, h.load5, h.load15),
            // A SKIP renders as its reason, so a reader never sees a row of
            // dashes with no explanation for them.
            Event::Wifi(w) => match w.wifi {
                types::WifiVerdict::Skip => {
                    format!("SKIP {}", w.reason.as_deref().unwrap_or("-"))
                }
                types::WifiVerdict::Ok => {
                    let fmt_i = |v: Option<i32>| {
                        v.map(|n| n.to_string()).unwrap_or_else(|| "-".to_string())
                    };
                    let rate = w
                        .tx_rate_mbps
                        .map(|r| format!("{r:.0}"))
                        .unwrap_or_else(|| "-".to_string());
                    format!(
                        "rssi={} noise={} snr={} tx={}Mbps {}",
                        fmt_i(w.rssi_dbm),
                        fmt_i(w.noise_dbm),
                        fmt_i(w.snr_db),
                        rate,
                        w.phy_mode.as_deref().unwrap_or("-")
                    )
                }
            },
            Event::Neighbors(n) => match n.verdict {
                types::NeighborsVerdict::Skip => {
                    format!("SKIP {}", n.reason.as_deref().unwrap_or("-"))
                }
                types::NeighborsVerdict::Ok => format!(
                    "{} on {} net={}",
                    n.neighbors.len(),
                    n.iface.as_deref().unwrap_or("-"),
                    n.network_key.as_deref().unwrap_or("-")
                ),
            },
            // The line says how many access points were HEARD, never anything
            // about interference: no channel-occupancy figure exists on this
            // platform, so the overlap with our own band is computed by a reader
            // and presented as a hypothesis (realm net-observer, node #48).
            Event::Air(a) => match a.air {
                types::AirVerdict::Skip => {
                    format!("SKIP {}", a.reason.as_deref().unwrap_or("-"))
                }
                types::AirVerdict::Ok => format!("{} AP heard", a.aps.len()),
            },
            Event::Incident(i) => format!("{} {}", i.trigger_id, i.signature),
        }
    }
}

/// One frame on a held-open [`Request::Subscribe`] stream: the ONLY thing the
/// daemon ever writes on such a connection.
///
/// A subscription is not answered by a [`Response`]. The daemon writes exactly
/// one [`StreamFrame::Ready`] and then pushes frames until either side goes
/// away. The envelope exists so a hole in the stream and a daemon-side refusal
/// are *decodable outcomes* rather than a contiguous-looking stream or a bare
/// close read as "connection closed".
///
/// Only [`StreamFrame::Event`] is subject to a subscriber's `kinds` filter;
/// every other variant is stream-integrity information and is ALWAYS delivered —
/// a filtered subscriber has more need to know about a hole or a pause, not
/// less. That rule lives in exactly one place, [`EncodedFrame::passes`].
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum StreamFrame {
    /// The mandatory first frame; never appears again on a connection.
    Ready(Ready),
    /// A live event.
    Event(Event),
    /// This subscriber fell behind the bus and lost frames.
    Gap(Gap),
    /// Collection was paused or resumed. Always a real transition — the state at
    /// subscribe time rides on [`Ready::observing`] instead, so a state report
    /// can never be mistaken for an edge that never happened.
    Observing(ObservingEdge),
    /// A daemon-side failure, reported IN BAND instead of a bare close.
    Error(StreamError),
    /// A well-formed JSON frame this build cannot name — typically an
    /// [`Event`] kind a NEWER daemon knows and this client does not.
    ///
    /// **Never sent by anyone.** It is produced by [`decode_stream_frame`] on the
    /// receiving side, so a forward-compatible client renders "one frame I could
    /// not read" instead of tearing the whole stream down over an enum variant it
    /// has never heard of. Absence of a signal is itself diagnostic: the frame is
    /// counted and named, never silently dropped.
    #[serde(skip)]
    Unrecognized(Unrecognized),
}

/// One frame that decoded as JSON but not as any [`StreamFrame`] this build
/// knows. Constructed only by [`decode_stream_frame`]; it never travels the wire.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Unrecognized {
    /// The receiving client's clock when the frame arrived — the frame's own
    /// timestamp is inside a shape we could not read.
    pub ts_us: i64,
    /// The decoder's complaint, kept verbatim so an operator can see WHICH
    /// variant was unknown.
    pub detail: String,
}

/// The daemon's acknowledgement of a subscription — the first frame on every
/// stream.
///
/// Written only AFTER the daemon has created its broadcast receiver, so a client
/// holding a [`Subscription`] is guaranteed to receive every event published
/// from that moment on. That guarantee is what lets the daemon's own tests stop
/// spinning on `receiver_count()`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Ready {
    /// Server clock when the subscription was created (epoch microseconds).
    pub ts_us: i64,
    /// The filter the daemon actually applied, echoed back. `None` = every kind.
    /// Frames that are not [`StreamFrame::Event`] are delivered regardless.
    pub kinds: Option<Vec<EventKind>>,
    /// The daemon's CURRENT collection state — a state report, NOT a transition.
    /// This is the "initial frame on subscribe" that lets a fresh subscriber
    /// learn whether collection is live immediately instead of inferring it from
    /// silence. Read after the receiver was created, so a pause racing this
    /// subscribe is also delivered as a `StreamFrame::Observing` (a redundant
    /// but consistent repeat) rather than lost.
    pub observing: bool,
}

/// A hole in ONE subscriber's stream: `skipped` events were dropped because it
/// fell behind the bus (`tokio::sync::broadcast::error::RecvError::Lagged`).
///
/// Per-subscriber by nature, so it never travels on the bus — it is built and
/// written by the connection task that lagged. Delivered regardless of the
/// `kinds` filter: rendering a contiguous timeline across a real hole is, for a
/// forensics tool, a lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Gap {
    /// When the daemon noticed the gap (epoch microseconds).
    pub ts_us: i64,
    /// How many events this subscriber missed.
    pub skipped: u64,
}

/// A daemon-side failure reported on a stream, in place of a bare close.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamError {
    pub ts_us: i64,
    pub code: StreamErrorCode,
    /// Human-readable detail, safe to show an operator verbatim.
    pub message: String,
}

/// Machine-readable classification of a [`StreamError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StreamErrorCode {
    /// The daemon already holds its maximum number of concurrent subscribers.
    TooManySubscribers,
}

impl StreamErrorCode {
    /// The stable lowercase label both clients print.
    pub fn as_str(self) -> &'static str {
        match self {
            StreamErrorCode::TooManySubscribers => "too-many-subscribers",
        }
    }
}

impl Ready {
    /// `"all"`, or the comma-joined kind labels the daemon accepted.
    pub fn kinds_label(&self) -> String {
        match &self.kinds {
            None => "all".to_string(),
            Some(ks) => ks.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(","),
        }
    }
}

impl StreamFrame {
    /// The frame's epoch-microsecond timestamp.
    pub fn ts_us(&self) -> i64 {
        match self {
            StreamFrame::Ready(r) => r.ts_us,
            StreamFrame::Event(e) => e.ts_us(),
            StreamFrame::Gap(g) => g.ts_us,
            StreamFrame::Observing(o) => o.ts_us,
            StreamFrame::Error(e) => e.ts_us,
            StreamFrame::Unrecognized(u) => u.ts_us,
        }
    }

    /// The short lowercase label every client prints: an event frame borrows its
    /// kind label, everything else names itself.
    pub fn label(&self) -> &'static str {
        match self {
            StreamFrame::Ready(_) => "subscribed",
            StreamFrame::Event(e) => e.kind().as_str(),
            StreamFrame::Gap(_) => "gap",
            StreamFrame::Observing(_) => "observing",
            StreamFrame::Error(_) => "error",
            StreamFrame::Unrecognized(_) => "unrecognized",
        }
    }

    /// The one-line detail every client prints next to [`StreamFrame::label`].
    /// Pure over its input (no clock, no locale), so the CLI tail and the bar's
    /// event log share one rendering of every frame instead of drifting copies.
    pub fn detail(&self) -> String {
        match self {
            StreamFrame::Ready(r) => format!(
                "collection {}; kinds: {}",
                if r.observing { "on" } else { "off" },
                r.kinds_label()
            ),
            StreamFrame::Event(e) => e.detail(),
            StreamFrame::Gap(g) => {
                format!("{} events dropped (subscriber lagged)", g.skipped)
            }
            StreamFrame::Observing(o) => {
                format!("collection {}", if o.observing { "on" } else { "off" })
            }
            StreamFrame::Error(e) => format!("{}: {}", e.code.as_str(), e.message),
            StreamFrame::Unrecognized(u) => {
                format!("a frame this build cannot read: {}", u.detail)
            }
        }
    }

    /// The [`EventKind`] a filter matches on: `Some` only for a real event.
    /// Stream-integrity frames are `None` and are never filtered out.
    pub fn event_kind(&self) -> Option<EventKind> {
        match self {
            StreamFrame::Event(e) => Some(e.kind()),
            StreamFrame::Ready(_)
            | StreamFrame::Gap(_)
            | StreamFrame::Observing(_)
            | StreamFrame::Error(_)
            | StreamFrame::Unrecognized(_) => None,
        }
    }
}

/// One [`StreamFrame`] serialised **once** for fan-out to every subscriber.
///
/// This is the daemon's broadcast-bus payload type. Cloning it per subscriber is
/// an `Arc` refcount bump, not a second `serde_json` pass, so N subscribers cost
/// one encode instead of N — which is what `broadcast` requires of its payload
/// and what makes a 256-subscriber cap affordable.
///
/// The routing metadata is derived FROM THE FRAME at encode time rather than
/// passed in alongside it, so a stream-integrity frame can never accidentally be
/// filtered away and an event can never accidentally bypass a filter: the rule
/// lives here, in one place, and is tested here rather than in the server loop.
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    kind: Option<EventKind>,
    bytes: Arc<[u8]>,
}

impl EncodedFrame {
    /// Encode `frame` as one newline-terminated JSON frame — byte-identical to
    /// [`encode_frame`] — and capture its routing metadata.
    pub fn encode(frame: &StreamFrame) -> serde_json::Result<Self> {
        Ok(Self {
            kind: frame.event_kind(),
            bytes: Arc::from(encode_frame(frame)?.into_boxed_slice()),
        })
    }

    /// `Some(kind)` only for an event frame; `None` for every stream-integrity
    /// frame.
    pub fn kind(&self) -> Option<EventKind> {
        self.kind
    }

    /// The encoded frame, trailing newline included — write these bytes verbatim.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether a subscriber filtered to `kinds` must receive this frame.
    /// `None` = subscribed to everything. A frame with no [`EventKind`] (ack,
    /// gap, observing edge, error) is ALWAYS delivered.
    pub fn passes(&self, kinds: Option<&[EventKind]>) -> bool {
        match (self.kind, kinds) {
            (_, None) => true,
            (None, Some(_)) => true,
            (Some(k), Some(ks)) => ks.contains(&k),
        }
    }
}

/// What one collector is to this daemon: present in the build, and permitted to
/// run by its config.
///
/// `kind` is a **string**, deliberately not an [`EventKind`]: this list is the
/// one place where a NEWER daemon names collectors an OLDER reader has never
/// heard of, and an unknown enum variant would fail the whole `Response` decode
/// — the exact failure mode this crate already carries two mitigations for. A
/// string an old reader does not recognise is simply a capability it does not
/// ask about. The vocabulary is [`EventKind::as_str`], so both sides spell the
/// kinds identically.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollectorCapability {
    /// The collector's lowercase label, in the [`EventKind::as_str`] vocabulary.
    pub kind: String,
    /// `true` iff this daemon's config permits the collector to run. `false`
    /// means the daemon CAN collect this and was told not to — a fact a reader
    /// must show rather than hide, or the operator cannot find what to turn on.
    pub enabled: bool,
}

/// What this daemon can collect at all — the build's collectors, each with
/// whether config permits it to run.
///
/// The list is closed for this daemon: a collector absent from it is one this
/// build does not have. That is what makes [`StatusSnapshot::collector`] able to
/// tell "cannot" from "switched off", which a reader must never collapse.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capabilities {
    /// Every collector this build has, in a stable order.
    #[serde(default)]
    pub collectors: Vec<CollectorCapability>,
}

impl Capabilities {
    /// Build a declaration from `(label, enabled)` pairs.
    pub fn from_pairs<I: IntoIterator<Item = (&'static str, bool)>>(pairs: I) -> Self {
        Self {
            collectors: pairs
                .into_iter()
                .map(|(kind, enabled)| CollectorCapability {
                    kind: kind.to_string(),
                    enabled,
                })
                .collect(),
        }
    }
}

/// What a reader may say about one collector on the daemon it is talking to.
///
/// Four states, and collapsing any two of them is a lie of exactly the kind this
/// project exists to avoid:
///
/// * [`Unknown`](CollectorAvailability::Unknown) — the daemon declared nothing at
///   all (a build older than [`StatusSnapshot::capabilities`]). We do not know.
/// * [`Absent`](CollectorAvailability::Absent) — the daemon declared its
///   collectors and this one is not among them: this build CANNOT collect it.
/// * [`Disabled`](CollectorAvailability::Disabled) — the daemon has it and config
///   switched it off. It can be turned on.
/// * [`Enabled`](CollectorAvailability::Enabled) — it is running; whether it has
///   produced anything yet is an ordinary data question, not a capability one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorAvailability {
    Unknown,
    Absent,
    Disabled,
    Enabled,
}

/// The live, in-memory status the daemon serves. Each collector's latest sample
/// plus a bounded ring of recent incidents.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusSnapshot {
    pub generated_us: i64,
    pub link: Option<LinkSample>,
    pub proxy: Option<ProxySample>,
    pub dns: Option<DnsSample>,
    pub host: Option<HostSample>,
    /// The latest Wi-Fi air-quality reading.
    ///
    /// `serde(default)` for the same forward-compatibility reason as `observing`:
    /// a pre-wifi daemon emits no such field, and without the default the whole
    /// `Response` would fail to decode — a live daemon rendered as "offline".
    #[serde(default)]
    pub wifi: Option<WifiSample>,
    /// The latest neighbour reading — how many devices the segment showed and
    /// whether the caches were readable at all.
    ///
    /// `serde(default)`, like `wifi`, so a pre-neighbours daemon's answer still
    /// decodes in a newer bar.
    #[serde(default)]
    pub neighbors: Option<NeighborsSample>,
    /// The switch-topology uplinks discovered from received LLDP/CDP frames —
    /// which switch/AP this machine's interfaces connect to. The map draws these
    /// as distinctly-marked nodes off the star. Each is a hypothesis (LLDP/CDP
    /// are spoofable), not a hard claim. (realm net-observer, node #42)
    ///
    /// `serde(default)`, like `neighbors`, so a pre-topology daemon's answer
    /// still decodes in a newer bar — an empty list, never a decode failure.
    #[serde(default)]
    pub topology: Vec<TopologyLink>,
    /// Since-when for each neighbour in [`Self::neighbors`], read from the
    /// store's long-lived `neighbor` rows.
    ///
    /// The reading and the record answer different questions, so they are
    /// different fields: `neighbors` is what this tick saw, this is what the
    /// database remembers across restarts. Joined by MAC.
    ///
    /// A neighbour with no entry here has an **unknown** lifetime — a store
    /// write may have failed, or the peer may predate this field. A reader must
    /// never render that as "first seen now". (realm net-observer, node #43)
    ///
    /// `serde(default)` — an empty list — so a pre-lifetimes daemon's answer
    /// still decodes in a newer bar, and a newer daemon's extra field does not
    /// break an older one.
    #[serde(default)]
    pub neighbor_lifetimes: Vec<NeighborLifetime>,
    /// Since-when for each uplink in [`Self::topology`], read from the store's
    /// `topology_link` rows. The same shape and the same rules as
    /// [`Self::neighbor_lifetimes`], joined by the identity triple
    /// (`iface`, `remote_chassis`, `remote_port`) via
    /// [`TopologyLifetime::bounds`]. `TopologyLink::ts_us` is a *sighting*, not
    /// a first-seen — this field is the only thing that carries first-seen onto
    /// the socket. (realm net-observer, node #43)
    #[serde(default)]
    pub topology_lifetimes: Vec<TopologyLifetime>,
    pub incidents: Vec<IncidentSummary>,
    /// Whether the daemon is actively collecting. `true` (the default) = collectors
    /// run and samples flow; `false` = collection is paused (the daemon stays alive
    /// and the socket keeps serving, the last snapshot retained but marked paused).
    ///
    /// `serde(default)` for forward compatibility: a pre-pause daemon emits a
    /// frame without this field, and without the default the whole `Response`
    /// would fail to decode — a live daemon rendered as "offline" by the bar.
    #[serde(default = "observing_default")]
    pub observing: bool,
    /// Whether the daemon is in "quiet" mode: still collecting, but addressing no
    /// packet at the gateway (the link collector's ICMP echo is suppressed and
    /// its gateway verdict reads `SKIP`). Distinct from `observing == false`,
    /// which stops collection altogether.
    ///
    /// `serde(default)` — `false` — for the same forward-compatibility reason as
    /// `observing`: a pre-quiet daemon emits no such field and the bar must still
    /// decode its answer.
    #[serde(default)]
    pub quiet: bool,
    /// What this daemon can collect at all — the collectors in its build, each
    /// with whether config permits it to run.
    ///
    /// `None` is a THIRD value, not a fallback: it means the daemon said nothing,
    /// because it predates this field. A reader must not read that as "no
    /// collectors" — see [`CollectorAvailability`].
    ///
    /// `serde(default)`, like every field above it, so a pre-capabilities
    /// daemon's answer still decodes; and because the collector labels are
    /// strings, a NEWER daemon naming a collector this build never heard of does
    /// not break the decode in the other direction either.
    #[serde(default)]
    pub capabilities: Option<Capabilities>,
}

impl StatusSnapshot {
    /// What this daemon can say about `kind`: the four-way distinction of
    /// [`CollectorAvailability`], derived from the declaration it sent.
    ///
    /// This is the ONLY place the four states are decided, so no consumer can
    /// quietly fold "cannot" into "switched off".
    pub fn collector(&self, kind: EventKind) -> CollectorAvailability {
        let Some(caps) = self.capabilities.as_ref() else {
            return CollectorAvailability::Unknown;
        };
        match caps.collectors.iter().find(|c| c.kind == kind.as_str()) {
            None => CollectorAvailability::Absent,
            Some(c) if c.enabled => CollectorAvailability::Enabled,
            Some(_) => CollectorAvailability::Disabled,
        }
    }
}

/// The serde/`Default` value for [`StatusSnapshot::observing`]: `true`, matching a
/// pre-pause daemon, which was always collecting.
fn observing_default() -> bool {
    true
}

/// Hand-written so a fresh snapshot reads `observing: true` — deriving `Default`
/// would give `false` for the `bool`, which would misreport a healthy daemon as
/// paused.
impl Default for StatusSnapshot {
    fn default() -> Self {
        Self {
            generated_us: 0,
            link: None,
            proxy: None,
            dns: None,
            host: None,
            wifi: None,
            neighbors: None,
            topology: Vec::new(),
            neighbor_lifetimes: Vec::new(),
            topology_lifetimes: Vec::new(),
            incidents: Vec::new(),
            observing: observing_default(),
            quiet: false,
            capabilities: None,
        }
    }
}

/// A response from the daemon to a client.
///
/// `Status` is the large, hot variant; `Error`/`Incidents` are small. Clippy's
/// `large_enum_variant` would suggest boxing `StatusSnapshot`, but this is the
/// shared wire type both `net-observerd` (which constructs `Response::Status(..)`
/// directly) and `net-observer-bar` depend on, so introducing `Box` here would be a
/// cross-crate contract change and add an allocation on the common response path.
/// The size difference is intentional and harmless for a single-response socket
/// reply, so the lint is allowed rather than the type reshaped.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Response {
    Status(StatusSnapshot),
    Incidents(Vec<IncidentSummary>),
    /// The outcome of a [`Request::Control`] command.
    Control(ControlResult),
    Error(String),
}

/// How long a one-shot [`query`] waits on each half of the exchange before giving
/// up with `ErrorKind::TimedOut`/`WouldBlock`. The bar calls `query` from its gpui
/// main thread, so an unbounded wait on a daemon that accepts but never answers
/// would park the whole UI.
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Blocking client for the bar: connect, write one newline-JSON request, read one
/// newline-JSON response. Framing = serde_json + `'\n'`. Connection-refused / no
/// socket ⇒ `Err` (the caller renders an "offline" state).
///
/// Bounded: both the write and the read get a 2s budget, so a daemon that accepts
/// the connection but never answers fails the call instead of hanging the caller's
/// thread forever.
pub fn query(sock_path: &str, req: &Request) -> std::io::Result<Response> {
    let stream = UnixStream::connect(sock_path)?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT))?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT))?;
    let mut writer = &stream;
    write_frame(&mut writer, req)?;
    let mut reader = BufReader::new(&stream);
    read_frame(&mut reader)
}

/// A held-open live stream from the daemon, returned by [`subscribe`].
///
/// Wraps the buffered socket and yields decoded [`StreamFrame`]s as an iterator.
/// The daemon pushes frames as they happen — iterating simply blocks until the
/// next one arrives. A clean close by the daemon ends iteration (`None`); a
/// decode/read failure surfaces as `Some(Err(..))`, and a daemon-side failure
/// arrives as a decodable `Ok(StreamFrame::Error(..))` rather than looking like
/// a corrupt frame. No tokio: a plain blocking [`UnixStream`].
///
/// A quiet daemon sends nothing, so the reader parks in `read(2)` indefinitely —
/// take a [`SubscriptionHandle`] before handing the subscription to a thread if
/// you ever need to wake it.
#[derive(Debug)]
pub struct Subscription {
    reader: BufReader<UnixStream>,
    ready: Ready,
}

impl Subscription {
    /// A cancellation handle for this stream, usable from another thread.
    ///
    /// The subscription itself is consumed by the reader thread; this dups the
    /// underlying socket so a UI thread can still shut it down. See
    /// [`SubscriptionHandle::close`].
    pub fn handle(&self) -> std::io::Result<SubscriptionHandle> {
        Ok(SubscriptionHandle(self.reader.get_ref().try_clone()?))
    }

    /// The daemon's opening [`Ready`] ack: the filter it accepted and its
    /// collection state at subscribe time. Already consumed by [`subscribe`], so
    /// a client learns the current state without inferring it from silence.
    pub fn ready(&self) -> &Ready {
        &self.ready
    }
}

/// A `Send` cancellation handle for a [`Subscription`], obtained from
/// [`Subscription::handle`]. Holding one lets a thread other than the reader end
/// a stream that is parked waiting on a silent daemon.
#[derive(Debug)]
pub struct SubscriptionHandle(UnixStream);

impl SubscriptionHandle {
    /// Shut the subscription's socket down in both directions.
    ///
    /// This is the cancellation mechanism (deliberately *not* a read timeout: a
    /// timeout would abandon `read_line` mid-frame). A parked [`read_frame`] on the
    /// peer returns `Ok(0)`, which becomes `UnexpectedEof`, which
    /// [`Subscription::next`] reports as a clean end of stream (`None`).
    /// Idempotent: shutting an already-closed socket down is ignored.
    pub fn close(&self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

impl Iterator for Subscription {
    type Item = std::io::Result<StreamFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        match read_stream_frame(&mut self.reader) {
            Ok(frame) => Some(Ok(frame)),
            // The daemon closed the connection cleanly — the stream is over.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Blocking client for a live event stream: connect, send one
/// [`Request::Subscribe`] for `kinds` (`None` = every [`EventKind`]), then
/// **complete the handshake** by reading the mandatory [`StreamFrame::Ready`]
/// before returning.
///
/// That ack is the contract: the daemon creates its broadcast receiver *before*
/// writing it, so a caller holding a [`Subscription`] is guaranteed to receive
/// every event published from then on — closing the publish-before-subscribe
/// window the old fire-and-forget subscribe had.
///
/// Taking `kinds` rather than a `Request` makes the precondition unrepresentable:
/// no caller can hand this a one-shot request whose single `Response` frame the
/// handshake would then mis-decode as a [`StreamFrame`].
///
/// Both halves are bounded by [`QUERY_TIMEOUT`] **for the handshake only**; both
/// timeouts are cleared before returning, because a live stream is idle by
/// nature and a read timeout would strand `read_line` holding a partial frame.
/// Use [`Subscription::handle`] to cancel a parked reader instead.
///
/// Errors:
/// - daemon down / socket absent ⇒ `NotFound` / `ConnectionRefused` (both
///   clients already render this as "offline");
/// - the daemon refused the subscription in band (e.g. the subscriber cap) ⇒
///   `ErrorKind::Other` carrying the daemon's own message. Deliberately NOT
///   `ConnectionRefused`: that kind already means "net-observerd is not running" to
///   both clients, and a refusal is not a dead daemon;
/// - anything else undecodable ⇒ `InvalidData`.
pub fn subscribe(sock_path: &str, kinds: Option<&[EventKind]>) -> std::io::Result<Subscription> {
    let stream = UnixStream::connect(sock_path)?;
    stream.set_write_timeout(Some(QUERY_TIMEOUT))?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT))?;
    let req = Request::Subscribe {
        kinds: kinds.map(<[_]>::to_vec),
    };
    let mut writer = &stream;
    write_frame(&mut writer, &req)?;
    let mut reader = BufReader::new(stream);
    let line = read_line(&mut reader)?;
    // Handshake over: a live stream must block, not time out.
    reader.get_ref().set_read_timeout(None)?;
    reader.get_ref().set_write_timeout(None)?;
    match decode_handshake(&line) {
        Handshake::Ready(ready) => Ok(Subscription { reader, ready }),
        Handshake::Refused(e) => Err(std::io::Error::other(format!(
            "net-observerd refused the subscription ({}): {}",
            e.code.as_str(),
            e.message
        ))),
        // The daemon could not READ the request. Its own words, verbatim — this
        // is the one place a client used to substitute its deserializer's
        // complaint about `StreamError` for what the daemon actually said.
        Handshake::BadRequest(message) => Err(std::io::Error::other(format!(
            "{BAD_REQUEST_PREFIX}{message}"
        ))),
        Handshake::Unexpected(what) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected a Ready ack as the first frame, got {what}"),
        )),
    }
}

/// What the daemon's FIRST line on a `Subscribe` connection turned out to be.
///
/// A subscription is answered by a [`StreamFrame`] when the daemon understood the
/// request — and by a one-shot [`Response::Error`] when it did not, because a
/// request it cannot decode never reaches the streaming path at all. Both shapes
/// spell `Error` on the wire (`{"Error": …}`), one carrying a [`StreamError`]
/// struct and one a bare string, so a client that tries only the former reports
/// its own deserializer's complaint and buries the daemon's message inside it.
/// Deciding between them lives here, once.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Handshake {
    Ready(Ready),
    Refused(StreamError),
    /// The daemon answered `Response::Error`: it could not decode the request —
    /// an [`EventKind`] added after that daemon was built, most likely. Carries
    /// the daemon's own message.
    BadRequest(String),
    /// Something decodable but not an opening: names what arrived.
    Unexpected(String),
}

/// Classify the first line of a `Subscribe` connection: stream frame first, then
/// the one-shot [`Response`] an older daemon answers a request it cannot read
/// with.
fn decode_handshake(line: &str) -> Handshake {
    if let Ok(frame) = serde_json::from_str::<StreamFrame>(line) {
        return match frame {
            StreamFrame::Ready(r) => Handshake::Ready(r),
            StreamFrame::Error(e) => Handshake::Refused(e),
            other => Handshake::Unexpected(format!("a {} frame", other.label())),
        };
    }
    match serde_json::from_str::<Response>(line) {
        Ok(Response::Error(message)) => Handshake::BadRequest(message),
        Ok(other) => Handshake::Unexpected(format!("a one-shot {other:?} response")),
        Err(e) => Handshake::Unexpected(format!("an undecodable frame: {e}")),
    }
}

/// Subscribe to `kinds`, and if this daemon cannot READ that filter, subscribe to
/// everything instead rather than going silent.
///
/// The failure this exists for: a client built after a new [`EventKind`] was added
/// sends it in the filter, and a daemon built before it rejects the WHOLE
/// subscription — so the window loses not just the new kind but every kind it
/// asked for. `serde(default)` rescues a new *field*; nothing rescues a new
/// *variant* travelling from a new sender to an old receiver, so the client must
/// notice the refusal and narrow its own ask.
///
/// The fallback is `kinds: None`, deliberately, rather than the same list minus
/// the kinds we guess this daemon lacks: `None` carries no [`EventKind`] at all,
/// so no daemon — however old — can fail to decode it. The caller then filters
/// client-side, which the bar's event window already does.
///
/// Returns the subscription and whether the narrowing happened. `true` is a fact
/// worth surfacing: it means this daemon does not know some kind that was asked
/// for, which is a different statement from "that kind has produced nothing yet",
/// and a window that conflates the two tells the operator a falsehood.
pub fn subscribe_or_widen(
    sock_path: &str,
    kinds: &[EventKind],
) -> std::io::Result<(Subscription, bool)> {
    match subscribe(sock_path, Some(kinds)) {
        Ok(sub) => Ok((sub, false)),
        Err(e) if is_bad_request(&e) => subscribe(sock_path, None).map(|sub| (sub, true)),
        Err(e) => Err(e),
    }
}

/// The marker [`subscribe`] puts on a daemon-side "I cannot read this request",
/// so [`subscribe_or_widen`] can recognise it without a second error type.
const BAD_REQUEST_PREFIX: &str = "net-observerd rejected the subscription: ";

/// Whether `e` is the refusal [`subscribe`] raises for a request the daemon could
/// not decode.
fn is_bad_request(e: &std::io::Error) -> bool {
    e.to_string().starts_with(BAD_REQUEST_PREFIX)
}

/// The outcome of a [`Request::Control`]: what the daemon DID, kept apart from
/// what it could not understand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    /// The daemon ran the command (or refused it on its own terms) and said so.
    Ran(ControlResult),
    /// The daemon could not decode the request — the command did not exist when
    /// it was built. Carries the daemon's own message.
    ///
    /// Distinct from `Ran(ControlResult { ok: false, .. })`: "this daemon cannot
    /// do that" and "this daemon declined to do that" are different facts, and a
    /// client that renders them the same misreports an old daemon as a refusing
    /// one.
    Unsupported(String),
}

/// Send one [`ControlCmd`] and classify the answer.
///
/// The forward-compatibility counterpart of [`subscribe_or_widen`] on the
/// one-shot path: a command added after this daemon was built comes back as
/// [`ControlOutcome::Unsupported`] carrying the daemon's own words, never as a
/// client-side deserializer complaint and never as a silent failure.
pub fn control(sock_path: &str, cmd: ControlCmd) -> std::io::Result<ControlOutcome> {
    classify_control(query(sock_path, &Request::Control(cmd))?)
}

/// The pure half of [`control`]: which outcome a given [`Response`] means.
/// Separated so the classification is testable without a socket.
fn classify_control(response: Response) -> std::io::Result<ControlOutcome> {
    match response {
        Response::Control(result) => Ok(ControlOutcome::Ran(result)),
        Response::Error(message) => Ok(ControlOutcome::Unsupported(message)),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected a Control response, got {other:?}"),
        )),
    }
}

/// Encode one value as a single newline-terminated JSON frame.
///
/// The one place the wire format is spelled out; every writer — blocking or async
/// — goes through this.
pub fn encode_frame<T: Serialize>(v: &T) -> serde_json::Result<Vec<u8>> {
    let mut buf = serde_json::to_vec(v)?;
    buf.push(b'\n');
    Ok(buf)
}

/// Write one value as a single newline-terminated JSON frame.
///
/// The *encoding* is shared via [`encode_frame`]; only the write itself is
/// per-runtime (the async server writes the same bytes through `AsyncWriteExt`).
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, v: &T) -> std::io::Result<()> {
    let buf = encode_frame(v)?;
    w.write_all(&buf)?;
    w.flush()
}

/// Decode one already-read line as a [`StreamFrame`], tolerating a variant this
/// build does not know.
///
/// Three outcomes, kept apart on purpose:
/// * a frame this build knows — returned as itself;
/// * valid JSON in a shape this build cannot name (`serde_json::error::Category::Data`
///   — an [`Event`] kind a newer daemon added, say) — returned as
///   [`StreamFrame::Unrecognized`], so ONE frame is lost instead of the stream;
/// * malformed JSON (`Syntax`/`Eof`/`Io`) — an `Err`, because a daemon killed
///   mid-write is a real transport failure and must not be papered over.
///
/// The forward-compatibility rule for the *receiving* side lives here, in one
/// place, the way [`EncodedFrame::passes`] holds the filtering rule.
pub fn decode_stream_frame(line: &str) -> std::io::Result<StreamFrame> {
    match serde_json::from_str::<StreamFrame>(line) {
        Ok(frame) => Ok(frame),
        Err(e) if e.classify() == serde_json::error::Category::Data => {
            Ok(StreamFrame::Unrecognized(Unrecognized {
                ts_us: types::now_us(),
                detail: e.to_string(),
            }))
        }
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}

/// Read one newline-terminated frame from a live subscription, via
/// [`decode_stream_frame`]. `UnexpectedEof` on a clean close, exactly like
/// [`read_frame`].
pub fn read_stream_frame<R: BufRead>(r: &mut R) -> std::io::Result<StreamFrame> {
    decode_stream_frame(&read_line(r)?)
}

/// Read one newline-terminated line, or `UnexpectedEof` if the peer closed first.
fn read_line<R: BufRead>(r: &mut R) -> std::io::Result<String> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before a full frame was read",
        ));
    }
    Ok(line)
}

/// Read one newline-terminated JSON frame into a value.
///
/// Returns an `UnexpectedEof` error if the stream closes before a full frame —
/// and *only* then. A truncated-but-non-empty line is a malformed frame, so it
/// maps to `InvalidData`: serde_json would otherwise report its own `Eof`
/// category as `UnexpectedEof`, which [`Subscription::next`] reads as a clean
/// close and would silently swallow a daemon killed mid-write.
pub fn read_frame<R: BufRead, T: DeserializeOwned>(r: &mut R) -> std::io::Result<T> {
    let line = read_line(r)?;
    serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{DnsVerdict, GwVerdict, TcpVerdict};

    /// The live failure this branch exists for, reproduced without a daemon.
    ///
    /// A bar built after `EventKind::Air` asks an older daemon for it; that
    /// daemon cannot decode the request at all, so it answers the ONE-SHOT
    /// `Response::Error` and closes. The client must read that as the daemon's
    /// own words, never as its own deserializer's complaint about `StreamError`
    /// — both spell `{"Error": …}` on the wire, which is exactly the trap.
    #[test]
    fn an_old_daemons_bad_request_is_read_as_the_daemons_own_words() {
        let line = serde_json::to_string(&Response::Error(
            "bad request: unknown variant `Air`, expected one of `Link`, `Proxy`".to_string(),
        ))
        .unwrap();

        // The naive read — what produced the nested error in the live window.
        assert!(serde_json::from_str::<StreamFrame>(&line).is_err());

        match decode_handshake(&line) {
            Handshake::BadRequest(message) => {
                assert!(
                    message.starts_with("bad request: unknown variant `Air`"),
                    "{message}"
                );
                // The client's own diagnostics must not be what the operator reads.
                assert!(
                    !message.contains("expected struct StreamError"),
                    "{message}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// An in-band `StreamFrame::Error` and a one-shot `Response::Error` share the
    /// `{"Error": …}` shape; they must not be confused for one another.
    #[test]
    fn an_in_band_refusal_is_not_read_as_a_bad_request() {
        let line = serde_json::to_string(&StreamFrame::Error(StreamError {
            ts_us: 7,
            code: StreamErrorCode::TooManySubscribers,
            message: "at the cap".to_string(),
        }))
        .unwrap();
        match decode_handshake(&line) {
            Handshake::Refused(e) => {
                assert_eq!(e.code, StreamErrorCode::TooManySubscribers);
                assert_eq!(e.message, "at the cap");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn a_ready_ack_is_the_ordinary_handshake() {
        let line = serde_json::to_string(&StreamFrame::Ready(Ready {
            ts_us: 1,
            kinds: Some(vec![EventKind::Air, EventKind::Wifi]),
            observing: true,
        }))
        .unwrap();
        match decode_handshake(&line) {
            Handshake::Ready(r) => {
                assert_eq!(r.kinds_label(), "air,wifi");
                assert!(r.observing);
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    /// The reverse direction of the same incompatibility: a NEWER daemon pushes
    /// an event kind this build has never heard of. One frame must be lost, not
    /// the stream — and the loss must be named, never silent.
    #[test]
    fn an_event_kind_the_receiver_does_not_know_costs_one_frame_not_the_stream() {
        let unknown = r#"{"Event":{"Ether":{"ts_us":5}}}"#;
        let frame =
            decode_stream_frame(unknown).expect("a shape we cannot name is not a hard error");
        assert_eq!(frame.label(), "unrecognized");
        assert_eq!(frame.event_kind(), None);
        match frame {
            StreamFrame::Unrecognized(u) => assert!(u.detail.contains("Ether"), "{}", u.detail),
            other => panic!("expected Unrecognized, got {other:?}"),
        }
    }

    /// ...but genuine corruption still fails. A daemon killed mid-write must not
    /// be rendered as "a frame from a newer build".
    #[test]
    fn a_malformed_frame_is_still_a_transport_failure() {
        let e = decode_stream_frame("{\"Event\":{\"Link\"").unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    /// A known frame still decodes untouched through the lenient path.
    #[test]
    fn known_frames_survive_the_lenient_decoder_unchanged() {
        let gap = StreamFrame::Gap(Gap {
            ts_us: 3,
            skipped: 9,
        });
        let line = String::from_utf8(encode_frame(&gap).unwrap()).unwrap();
        let back = decode_stream_frame(&line).unwrap();
        assert_eq!(back.ts_us(), 3);
        assert_eq!(back.label(), "gap");
        assert_eq!(back.event_kind(), None);
    }

    /// An `Unrecognized` frame is a decoding artifact: stream-integrity
    /// information, never filtered away as if it were an event of some kind.
    #[test]
    fn an_unrecognized_frame_is_stream_integrity_not_an_event() {
        let f = StreamFrame::Unrecognized(Unrecognized {
            ts_us: 11,
            detail: "unknown variant `Ether`".to_string(),
        });
        assert_eq!(f.event_kind(), None);
        assert!(f.detail().contains("cannot read"), "{}", f.detail());
        let encoded = EncodedFrame::encode(&StreamFrame::Gap(Gap {
            ts_us: 1,
            skipped: 0,
        }))
        .unwrap();
        assert!(encoded.passes(Some(&[EventKind::Air])));
    }

    /// Every `EventKind` must round-trip, so a filter list never changes meaning
    /// between the client that writes it and the daemon that echoes it back.
    #[test]
    fn every_event_kind_round_trips_in_a_subscribe_request() {
        let all = [
            EventKind::Link,
            EventKind::Proxy,
            EventKind::Dns,
            EventKind::Route,
            EventKind::Host,
            EventKind::Wifi,
            EventKind::Neighbors,
            EventKind::Air,
            EventKind::Incident,
        ];
        let req = Request::Subscribe {
            kinds: Some(all.to_vec()),
        };
        let line = String::from_utf8(encode_frame(&req).unwrap()).unwrap();
        match serde_json::from_str::<Request>(&line).unwrap() {
            Request::Subscribe { kinds: Some(ks) } => assert_eq!(ks, all.to_vec()),
            other => panic!("expected a filtered Subscribe, got {other:?}"),
        }
    }

    /// The widening fallback must be a request NO daemon can fail to decode:
    /// `kinds: None` carries no `EventKind` at all. This guards the CHOICE —
    /// narrowing to a guessed subset would still put a variant on the wire.
    #[test]
    fn the_widened_fallback_carries_no_event_kind_at_all() {
        let line =
            String::from_utf8(encode_frame(&Request::Subscribe { kinds: None }).unwrap()).unwrap();
        for kind in ["Link", "Air", "Wifi", "Incident"] {
            assert!(!line.contains(kind), "{line} must not name {kind}");
        }
    }

    /// A control command this daemon never heard of is `Unsupported`, carrying
    /// the daemon's words — never a refusal, which would claim the daemon CAN do
    /// it and chose not to.
    #[test]
    fn an_unknown_control_command_is_unsupported_not_refused() {
        let refused = Response::Control(ControlResult {
            ok: false,
            message: "acting disabled".to_string(),
        });
        match classify_control(refused).unwrap() {
            ControlOutcome::Ran(r) => assert!(!r.ok),
            other => panic!("expected Ran, got {other:?}"),
        }
        let unknown = Response::Error("bad request: unknown variant `ScanAir`".to_string());
        match classify_control(unknown).unwrap() {
            ControlOutcome::Unsupported(m) => assert!(m.contains("ScanAir"), "{m}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// `ScanAir` must survive the wire intact next to the commands that already
    /// exist — the bar's button and the daemon's dispatch read the same variant.
    #[test]
    fn scan_air_round_trips_as_a_control_command() {
        let line = String::from_utf8(encode_frame(&Request::Control(ControlCmd::ScanAir)).unwrap())
            .unwrap();
        match serde_json::from_str::<Request>(&line).unwrap() {
            Request::Control(ControlCmd::ScanAir) => {}
            other => panic!("expected ScanAir, got {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_status_snapshot() {
        let snap = StatusSnapshot {
            generated_us: 1234,
            link: Some(LinkSample {
                ts_us: 1234,
                gw: GwVerdict::Ok,
                gw_rtt_ms: Some(1.5),
                direct: TcpVerdict::Ok,
                direct_rtt_ms: None,
                dhcp_router: Some("10.0.0.1".into()),
                dhcp_dns: None,
                gw_arp_mac: None,
                ssid: Some("home".into()),
                wifi_capture_present: false,
            }),
            proxy: None,
            dns: None,
            host: None,
            wifi: None,
            neighbors: None,
            topology: Vec::new(),
            neighbor_lifetimes: Vec::new(),
            topology_lifetimes: Vec::new(),
            incidents: vec![IncidentSummary {
                id: "inc-1".into(),
                opened_us: 1000,
                closed_us: Some(2000),
                trigger_id: "fakeip".into(),
                signature: "sig".into(),
            }],
            observing: false,
            // Deliberately `true`: `quiet` carries `serde(default)` = `false`, so
            // a field that silently failed to serialize would still round-trip as
            // `false` and the assertion below would pass on a broken wire format.
            quiet: true,
            // Same trick as `quiet`: `capabilities` defaults to `None`, so a
            // non-default value here is what proves the declaration is actually
            // on the wire rather than being reconstructed by the default.
            capabilities: Some(Capabilities::from_pairs([("air", false)])),
        };

        let mut buf = Vec::new();
        write_frame(&mut buf, &snap).unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);

        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: StatusSnapshot = read_frame(&mut reader).unwrap();

        assert_eq!(back.generated_us, snap.generated_us);
        assert_eq!(back.link, snap.link);
        assert_eq!(back.incidents.len(), 1);
        assert_eq!(back.incidents[0].id, "inc-1");
        assert_eq!(back.incidents[0].closed_us, Some(2000));
        assert!(!back.observing);
        assert!(back.quiet);
        assert_eq!(back.capabilities, snap.capabilities);
        assert_eq!(
            back.collector(EventKind::Air),
            CollectorAvailability::Disabled
        );
    }

    #[test]
    fn status_snapshot_default_is_observing() {
        // A fresh snapshot must read as observing (true), not paused — the
        // hand-written `Default` guards against `derive(Default)`'s `false`.
        assert!(StatusSnapshot::default().observing);
    }

    #[test]
    fn status_snapshot_decodes_pre_pause_frame_as_observing() {
        // A daemon from before the pause switch emits no `observing` field. The
        // frame must still decode (a missing field would fail the whole
        // `Response`, which the bar renders as "offline" for a daemon that is up)
        // and must read as observing, since that daemon always collected.
        let old =
            r#"{"generated_us":1,"link":null,"proxy":null,"dns":null,"host":null,"incidents":[]}"#;
        let snap: StatusSnapshot = serde_json::from_str(old).unwrap();
        assert_eq!(snap.generated_us, 1);
        assert!(snap.observing);
    }

    #[test]
    fn frame_round_trip_request() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Incidents { limit: 7 }).unwrap();
        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Request = read_frame(&mut reader).unwrap();
        match back {
            Request::Incidents { limit } => assert_eq!(limit, 7),
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_control_request() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Control(ControlCmd::KickstartProxy)).unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);

        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Request = read_frame(&mut reader).unwrap();
        match back {
            Request::Control(ControlCmd::KickstartProxy) => {}
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_set_observing_request() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Control(ControlCmd::SetObserving(true))).unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);

        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Request = read_frame(&mut reader).unwrap();
        match back {
            Request::Control(ControlCmd::SetObserving(on)) => assert!(on),
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_control_response() {
        let res = ControlResult {
            ok: false,
            message: "acting disabled".into(),
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &Response::Control(res)).unwrap();
        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Response = read_frame(&mut reader).unwrap();
        match back {
            Response::Control(r) => {
                assert!(!r.ok);
                assert_eq!(r.message, "acting disabled");
            }
            other => panic!("unexpected response variant: {other:?}"),
        }
    }

    #[test]
    fn read_frame_empty_stream_is_eof() {
        let empty: &[u8] = b"";
        let mut reader = std::io::BufReader::new(empty);
        let res: std::io::Result<Request> = read_frame(&mut reader);
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_frame_truncated_frame_is_invalid_data() {
        // A daemon SIGKILLed mid-`write_all` leaves a non-empty but truncated
        // line. serde_json calls that its own `Eof` category; mapping it through
        // `Error::from` would produce `UnexpectedEof`, which `Subscription::next`
        // reads as a clean close — losing the failure. Only `n == 0` may look
        // like end-of-stream. This split is what the CLI's exit code rests on:
        // a clean close is success, a torn frame is a failure.
        let truncated: &[u8] = br#"{"Event":{"Link":"#;
        let mut reader = std::io::BufReader::new(truncated);
        let res: std::io::Result<StreamFrame> = read_frame(&mut reader);
        assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn frame_round_trip_event_incident() {
        let ev = Event::Incident(IncidentSummary {
            id: "inc-9".into(),
            opened_us: 5000,
            closed_us: None,
            trigger_id: "fakeip".into(),
            signature: "sig".into(),
        });

        let mut buf = Vec::new();
        write_frame(&mut buf, &ev).unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);

        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Event = read_frame(&mut reader).unwrap();
        match back {
            Event::Incident(inc) => {
                assert_eq!(inc.id, "inc-9");
                assert_eq!(inc.opened_us, 5000);
                assert_eq!(inc.closed_us, None);
            }
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_subscribe_request() {
        let mut buf = Vec::new();
        write_frame(
            &mut buf,
            &Request::Subscribe {
                kinds: Some(vec![EventKind::Route]),
            },
        )
        .unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);

        let mut reader = std::io::BufReader::new(&buf[..]);
        let back: Request = read_frame(&mut reader).unwrap();
        match back {
            Request::Subscribe { kinds } => assert_eq!(kinds, Some(vec![EventKind::Route])),
            other => panic!("unexpected request variant: {other:?}"),
        }
    }

    #[test]
    fn event_kind_and_ts_us() {
        let ev = Event::Route(RouteEvent {
            ts_us: 314,
            kind: "iface".into(),
            iface: Some("en0".into()),
            detail: "up".into(),
        });
        assert_eq!(ev.kind(), EventKind::Route);
        assert_eq!(ev.ts_us(), 314);

        // The Incident variant borrows its timestamp from `opened_us`.
        let inc = Event::Incident(IncidentSummary {
            id: "inc-1".into(),
            opened_us: 42,
            closed_us: None,
            trigger_id: "t".into(),
            signature: "s".into(),
        });
        assert_eq!(inc.kind(), EventKind::Incident);
        assert_eq!(inc.ts_us(), 42);
    }

    #[test]
    fn event_kind_as_str_covers_every_kind() {
        for (kind, label) in [
            (EventKind::Link, "link"),
            (EventKind::Proxy, "proxy"),
            (EventKind::Dns, "dns"),
            (EventKind::Route, "route"),
            (EventKind::Host, "host"),
            (EventKind::Incident, "incident"),
        ] {
            assert_eq!(kind.as_str(), label);
        }
    }

    #[test]
    fn event_detail_covers_each_variant() {
        let link = Event::Link(LinkSample {
            ts_us: 0,
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
        assert_eq!(link.detail(), "gw=OK direct=FAIL");

        let proxy = Event::Proxy(ProxySample {
            ts_us: 0,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: Some("auto".into()),
        });
        assert_eq!(proxy.detail(), "tun=204 sel=auto");

        // Missing tun_code / selector fall back to a placeholder dash.
        let proxy_bare = Event::Proxy(ProxySample {
            ts_us: 0,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code: None,
            selector: None,
        });
        assert_eq!(proxy_bare.detail(), "tun=- sel=-");

        let dns = Event::Dns(DnsSample {
            ts_us: 0,
            probe: "nks".into(),
            server: "sb".into(),
            verdict: DnsVerdict::FakeIp,
            ip: Some("198.18.0.1".into()),
            rtt_ms: None,
        });
        assert_eq!(dns.detail(), "nks/sb FAKEIP 198.18.0.1");

        let route = Event::Route(RouteEvent {
            ts_us: 0,
            kind: "iface".into(),
            iface: Some("en0".into()),
            detail: "up".into(),
        });
        assert_eq!(route.detail(), "iface en0 up");

        let host = Event::Host(HostSample {
            ts_us: 0,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
        });
        assert_eq!(host.detail(), "load 1.00/2.00/3.00");

        let inc = Event::Incident(IncidentSummary {
            id: "inc-1".into(),
            opened_us: 0,
            closed_us: None,
            trigger_id: "fakeip".into(),
            signature: "sig".into(),
        });
        assert_eq!(inc.detail(), "fakeip sig");
    }

    #[test]
    fn encode_frame_matches_write_frame() {
        // The two must stay byte-identical: `write_frame` is only `encode_frame`
        // plus the blocking write, and the async server encodes with the former.
        let req = Request::Incidents { limit: 3 };
        let mut written = Vec::new();
        write_frame(&mut written, &req).unwrap();
        assert_eq!(encode_frame(&req).unwrap(), written);
        assert_eq!(written.last(), Some(&b'\n'));
    }

    /// One `StreamFrame` through the framing, asserting exactly one trailing
    /// newline, and handing the decoded frame back for a per-variant check.
    fn round_trip_frame(frame: &StreamFrame) -> StreamFrame {
        let mut buf = Vec::new();
        write_frame(&mut buf, frame).unwrap();
        // Exactly one frame => exactly one trailing newline.
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 1);
        let mut reader = std::io::BufReader::new(&buf[..]);
        read_frame(&mut reader).unwrap()
    }

    #[test]
    fn frame_round_trip_stream_frame_ready() {
        let ready = Ready {
            ts_us: 11,
            kinds: Some(vec![EventKind::Route, EventKind::Dns]),
            observing: false,
        };
        match round_trip_frame(&StreamFrame::Ready(ready.clone())) {
            StreamFrame::Ready(back) => assert_eq!(back, ready),
            other => panic!("unexpected frame variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_stream_frame_event() {
        let frame = StreamFrame::Event(Event::Incident(IncidentSummary {
            id: "inc-9".into(),
            opened_us: 5000,
            closed_us: None,
            trigger_id: "fakeip".into(),
            signature: "sig".into(),
        }));
        match round_trip_frame(&frame) {
            StreamFrame::Event(Event::Incident(inc)) => {
                assert_eq!(inc.id, "inc-9");
                assert_eq!(inc.opened_us, 5000);
                assert_eq!(inc.closed_us, None);
            }
            other => panic!("unexpected frame variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_stream_frame_gap() {
        let gap = Gap {
            ts_us: 77,
            skipped: 12,
        };
        match round_trip_frame(&StreamFrame::Gap(gap)) {
            StreamFrame::Gap(back) => assert_eq!(back, gap),
            other => panic!("unexpected frame variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_stream_frame_observing() {
        // The peer uid rides across the wire: a pause is attributable to a *who*.
        let edge = ObservingEdge {
            ts_us: 909,
            observing: false,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        };
        match round_trip_frame(&StreamFrame::Observing(edge)) {
            StreamFrame::Observing(back) => assert_eq!(back, edge),
            other => panic!("unexpected frame variant: {other:?}"),
        }
    }

    #[test]
    fn frame_round_trip_stream_frame_error() {
        let err = StreamError {
            ts_us: 5,
            code: StreamErrorCode::TooManySubscribers,
            message: "subscriber limit reached (2 concurrent)".into(),
        };
        match round_trip_frame(&StreamFrame::Error(err.clone())) {
            StreamFrame::Error(back) => assert_eq!(back, err),
            other => panic!("unexpected frame variant: {other:?}"),
        }
    }

    #[test]
    fn encoded_frame_bytes_match_encode_frame() {
        // The bus payload must be byte-identical to what a per-connection write
        // produces — subscribers cannot tell the two paths apart.
        let event = StreamFrame::Event(Event::Route(RouteEvent {
            ts_us: 1,
            kind: "iface".into(),
            iface: Some("en0".into()),
            detail: "up".into(),
        }));
        assert_eq!(
            EncodedFrame::encode(&event).unwrap().bytes(),
            encode_frame(&event).unwrap()
        );

        let gap = StreamFrame::Gap(Gap {
            ts_us: 2,
            skipped: 3,
        });
        assert_eq!(
            EncodedFrame::encode(&gap).unwrap().bytes(),
            encode_frame(&gap).unwrap()
        );
        assert_eq!(
            EncodedFrame::encode(&gap).unwrap().bytes().last(),
            Some(&b'\n')
        );
    }

    #[test]
    fn encoded_frame_kind_is_some_only_for_events() {
        let event = StreamFrame::Event(Event::Host(HostSample {
            ts_us: 0,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
        }));
        assert_eq!(
            EncodedFrame::encode(&event).unwrap().kind(),
            Some(EventKind::Host)
        );

        // Every stream-integrity frame is kindless, which is what keeps it out of
        // the filter's reach.
        for frame in [
            StreamFrame::Ready(Ready {
                ts_us: 0,
                kinds: None,
                observing: true,
            }),
            StreamFrame::Gap(Gap {
                ts_us: 0,
                skipped: 1,
            }),
            StreamFrame::Observing(ObservingEdge {
                ts_us: 0,
                observing: false,
                peer_uid: Some(0),
                cause: types::ObservingCause::Control,
            }),
            StreamFrame::Error(StreamError {
                ts_us: 0,
                code: StreamErrorCode::TooManySubscribers,
                message: "nope".into(),
            }),
        ] {
            assert_eq!(EncodedFrame::encode(&frame).unwrap().kind(), None);
        }
    }

    #[test]
    fn encoded_frame_passes_delivers_every_non_event_frame() {
        let filter = [EventKind::Route];
        let kinds = Some(&filter[..]);

        let matching = EncodedFrame::encode(&StreamFrame::Event(Event::Route(RouteEvent {
            ts_us: 0,
            kind: "iface".into(),
            iface: None,
            detail: "up".into(),
        })))
        .unwrap();
        assert!(matching.passes(kinds));

        let other_kind = EncodedFrame::encode(&StreamFrame::Event(Event::Host(HostSample {
            ts_us: 0,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        })))
        .unwrap();
        assert!(!other_kind.passes(kinds));

        // A filtered subscriber has MORE need to know about a hole or a pause,
        // not less: every stream-integrity frame is delivered regardless.
        let integrity = [
            StreamFrame::Ready(Ready {
                ts_us: 0,
                kinds: Some(vec![EventKind::Route]),
                observing: true,
            }),
            StreamFrame::Gap(Gap {
                ts_us: 0,
                skipped: 4,
            }),
            StreamFrame::Observing(ObservingEdge {
                ts_us: 0,
                observing: false,
                peer_uid: Some(501),
                cause: types::ObservingCause::Control,
            }),
            StreamFrame::Error(StreamError {
                ts_us: 0,
                code: StreamErrorCode::TooManySubscribers,
                message: "full".into(),
            }),
        ];
        for frame in &integrity {
            assert!(EncodedFrame::encode(frame).unwrap().passes(kinds));
        }

        // `None` = subscribed to everything, events included.
        assert!(matching.passes(None));
        assert!(other_kind.passes(None));
        for frame in &integrity {
            assert!(EncodedFrame::encode(frame).unwrap().passes(None));
        }
    }

    #[test]
    fn stream_frame_label_and_detail_cover_every_variant() {
        // Both clients print these strings verbatim, so they are a contract.
        let ready = StreamFrame::Ready(Ready {
            ts_us: 7,
            kinds: None,
            observing: false,
        });
        assert_eq!(ready.label(), "subscribed");
        assert_eq!(ready.detail(), "collection off; kinds: all");
        assert_eq!(ready.ts_us(), 7);

        let ready_filtered = StreamFrame::Ready(Ready {
            ts_us: 8,
            kinds: Some(vec![EventKind::Route, EventKind::Dns]),
            observing: true,
        });
        assert_eq!(ready_filtered.detail(), "collection on; kinds: route,dns");

        let event = StreamFrame::Event(Event::Incident(IncidentSummary {
            id: "inc-1".into(),
            opened_us: 42,
            closed_us: None,
            trigger_id: "fakeip".into(),
            signature: "sig".into(),
        }));
        assert_eq!(event.label(), "incident");
        assert_eq!(event.detail(), "fakeip sig");
        assert_eq!(event.ts_us(), 42);

        let gap = StreamFrame::Gap(Gap {
            ts_us: 9,
            skipped: 12,
        });
        assert_eq!(gap.label(), "gap");
        assert_eq!(gap.detail(), "12 events dropped (subscriber lagged)");
        assert_eq!(gap.ts_us(), 9);

        let paused = StreamFrame::Observing(ObservingEdge {
            ts_us: 10,
            observing: false,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        });
        assert_eq!(paused.label(), "observing");
        assert_eq!(paused.detail(), "collection off");
        assert_eq!(paused.ts_us(), 10);

        let resumed = StreamFrame::Observing(ObservingEdge {
            ts_us: 11,
            observing: true,
            peer_uid: None,
            cause: types::ObservingCause::Control,
        });
        assert_eq!(resumed.detail(), "collection on");

        let err = StreamFrame::Error(StreamError {
            ts_us: 12,
            code: StreamErrorCode::TooManySubscribers,
            message: "subscriber limit reached (256 concurrent)".into(),
        });
        assert_eq!(err.label(), "error");
        assert_eq!(
            err.detail(),
            "too-many-subscribers: subscriber limit reached (256 concurrent)"
        );
        assert_eq!(err.ts_us(), 12);
    }

    #[test]
    fn ready_kinds_label_joins_kinds() {
        assert_eq!(
            Ready {
                ts_us: 0,
                kinds: None,
                observing: true,
            }
            .kinds_label(),
            "all"
        );
        assert_eq!(
            Ready {
                ts_us: 0,
                kinds: Some(vec![EventKind::Route, EventKind::Dns]),
                observing: true,
            }
            .kinds_label(),
            "route,dns"
        );
    }

    #[test]
    fn stream_error_code_as_str() {
        assert_eq!(
            StreamErrorCode::TooManySubscribers.as_str(),
            "too-many-subscribers"
        );
    }

    #[test]
    fn subscription_handle_is_send() {
        // A UI thread must be able to hold the handle and cancel a reader thread
        // parked on a silent daemon.
        fn assert_send<T: Send>() {}
        assert_send::<SubscriptionHandle>();
    }
    /// The three states a reader must keep apart, plus the fourth that says the
    /// daemon never spoke. Collapsing any pair of them is the falsehood this
    /// distinction exists to prevent: hiding a collector the operator could turn
    /// on, or offering a window onto one the daemon cannot fill.
    #[test]
    fn capability_tells_cannot_from_switched_off_from_running() {
        // 1. A daemon too old to declare anything: unknown, NOT "no collectors".
        let old = StatusSnapshot::default();
        assert_eq!(
            old.collector(EventKind::Air),
            CollectorAvailability::Unknown
        );

        // 2. A daemon that declared its collectors and has no air one at all.
        let without = StatusSnapshot {
            capabilities: Some(Capabilities::from_pairs([("link", true), ("wifi", true)])),
            ..StatusSnapshot::default()
        };
        assert_eq!(
            without.collector(EventKind::Air),
            CollectorAvailability::Absent
        );
        assert_eq!(
            without.collector(EventKind::Wifi),
            CollectorAvailability::Enabled
        );

        // 3. It HAS the collector and config switched it off — a state that must
        //    stay visible, because it is the one the operator can change.
        let off = StatusSnapshot {
            capabilities: Some(Capabilities::from_pairs([("air", false), ("link", true)])),
            ..StatusSnapshot::default()
        };
        assert_eq!(
            off.collector(EventKind::Air),
            CollectorAvailability::Disabled
        );

        // 4. Running. Whether a scan has landed yet is an ordinary data question.
        let on = StatusSnapshot {
            capabilities: Some(Capabilities::from_pairs([("air", true)])),
            ..StatusSnapshot::default()
        };
        assert_eq!(on.collector(EventKind::Air), CollectorAvailability::Enabled);
    }

    /// Both directions of the shared surface, which is what `serde(default)` and
    /// the string collector label buy: an OLD daemon's answer (no such field)
    /// still decodes, and a NEW daemon naming a collector this build never heard
    /// of does not take the whole `Response` down with it.
    #[test]
    fn the_capability_field_is_compatible_in_both_directions() {
        // Old daemon → new reader: the field is simply absent.
        let old_wire = r#"{"generated_us":1,"link":null,"proxy":null,"dns":null,"host":null,
            "incidents":[]}"#;
        let snap: StatusSnapshot = serde_json::from_str(old_wire).expect("old answer must decode");
        assert!(snap.capabilities.is_none());
        assert_eq!(
            snap.collector(EventKind::Air),
            CollectorAvailability::Unknown
        );

        // New daemon → old-ish reader: a collector label this build cannot name.
        let new_wire = r#"{"generated_us":1,"link":null,"proxy":null,"dns":null,"host":null,
            "incidents":[],"capabilities":{"collectors":[
                {"kind":"air","enabled":true},{"kind":"telepathy","enabled":true}]}}"#;
        let snap: StatusSnapshot =
            serde_json::from_str(new_wire).expect("newer answer must decode");
        assert_eq!(
            snap.collector(EventKind::Air),
            CollectorAvailability::Enabled
        );
        // The unknown one is carried, not rejected, and simply never asked about.
        assert_eq!(snap.capabilities.expect("declared").collectors.len(), 2);
    }

    /// A snapshot from a daemon that predates the lifetime lists must still
    /// decode — the OLD-daemon / NEW-bar half of the compatibility contract. The
    /// missing fields become empty lists, which every reader must render as
    /// "unknown", not as "first seen now".
    #[test]
    fn a_pre_lifetimes_snapshot_decodes_with_empty_lists() {
        let older = r#"{"generated_us":7,"link":null,"proxy":null,"dns":null,"host":null,
            "incidents":[],"observing":true}"#;
        let snap: StatusSnapshot = serde_json::from_str(older).expect("must decode");
        assert_eq!(snap.generated_us, 7);
        assert!(snap.neighbor_lifetimes.is_empty());
        assert!(snap.topology_lifetimes.is_empty());
    }

    /// The NEW-daemon / OLD-bar half: an older reader's shape has no lifetime
    /// fields at all, and serde must ignore the extra ones rather than fail the
    /// whole `Response`. Modelled by decoding a new snapshot's JSON into a struct
    /// that lacks them — exactly what an un-upgraded bar's `StatusSnapshot` is.
    #[test]
    fn a_pre_lifetimes_reader_ignores_the_new_fields() {
        #[derive(serde::Deserialize)]
        struct OldSnapshot {
            generated_us: i64,
            observing: bool,
        }
        let snap = StatusSnapshot {
            generated_us: 11,
            neighbor_lifetimes: vec![types::NeighborLifetime {
                mac: "a4:83:e7:1b:2c:3d".into(),
                first_seen_us: 1,
                last_seen_us: 9,
            }],
            topology_lifetimes: vec![types::TopologyLifetime {
                iface: "en0".into(),
                remote_chassis: "sw-1".into(),
                remote_port: "Gi0/1".into(),
                first_seen_us: 2,
                last_seen_us: 8,
            }],
            ..Default::default()
        };
        let wire = serde_json::to_string(&snap).unwrap();
        let old: OldSnapshot = serde_json::from_str(&wire).expect("an older reader must decode");
        assert_eq!(old.generated_us, 11);
        assert!(old.observing);
    }

    /// Round-trip: both lifetime lists survive the wire intact, joined by the
    /// keys their readers join on (MAC; the identity triple).
    #[test]
    fn lifetimes_round_trip_on_the_wire() {
        let lt = types::NeighborLifetime {
            mac: "a4:83:e7:1b:2c:3d".into(),
            first_seen_us: 100,
            last_seen_us: 900,
        };
        let up = types::TopologyLifetime {
            iface: "en0".into(),
            remote_chassis: "sw-1".into(),
            remote_port: "Gi0/1".into(),
            first_seen_us: 5,
            last_seen_us: 50,
        };
        let snap = StatusSnapshot {
            neighbor_lifetimes: vec![lt.clone()],
            topology_lifetimes: vec![up.clone()],
            ..Default::default()
        };
        let back: StatusSnapshot =
            serde_json::from_str(&serde_json::to_string(&snap).unwrap()).unwrap();
        assert_eq!(back.neighbor_lifetimes, vec![lt]);
        assert_eq!(back.topology_lifetimes, vec![up]);
    }
}
