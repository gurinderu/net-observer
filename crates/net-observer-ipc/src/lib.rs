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
use types::{DnsSample, HostSample, LinkSample, ObservingEdge, ProxySample, RouteEvent};

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
}

/// The outcome of a [`ControlCmd`]: whether the action ran successfully plus a
/// human-readable message the client surfaces to the operator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
            | StreamFrame::Error(_) => None,
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

/// The live, in-memory status the daemon serves. Each collector's latest sample
/// plus a bounded ring of recent incidents.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StatusSnapshot {
    pub generated_us: i64,
    pub link: Option<LinkSample>,
    pub proxy: Option<ProxySample>,
    pub dns: Option<DnsSample>,
    pub host: Option<HostSample>,
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
            incidents: Vec::new(),
            observing: observing_default(),
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
        match read_frame(&mut self.reader) {
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
    let first: StreamFrame = read_frame(&mut reader)?;
    // Handshake over: a live stream must block, not time out.
    reader.get_ref().set_read_timeout(None)?;
    reader.get_ref().set_write_timeout(None)?;
    match first {
        StreamFrame::Ready(ready) => Ok(Subscription { reader, ready }),
        StreamFrame::Error(e) => Err(std::io::Error::other(format!(
            "net-observerd refused the subscription ({}): {}",
            e.code.as_str(),
            e.message
        ))),
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "expected a Ready ack as the first frame, got a {} frame",
                other.label()
            ),
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

/// Read one newline-terminated JSON frame into a value.
///
/// Returns an `UnexpectedEof` error if the stream closes before a full frame —
/// and *only* then. A truncated-but-non-empty line is a malformed frame, so it
/// maps to `InvalidData`: serde_json would otherwise report its own `Eof`
/// category as `UnexpectedEof`, which [`Subscription::next`] reads as a clean
/// close and would silently swallow a daemon killed mid-write.
pub fn read_frame<R: BufRead, T: DeserializeOwned>(r: &mut R) -> std::io::Result<T> {
    let mut line = String::new();
    let n = r.read_line(&mut line)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before a full frame was read",
        ));
    }
    serde_json::from_str(&line).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{DnsVerdict, GwVerdict, TcpVerdict};

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
            incidents: vec![IncidentSummary {
                id: "inc-1".into(),
                opened_us: 1000,
                closed_us: Some(2000),
                trigger_id: "fakeip".into(),
                signature: "sig".into(),
            }],
            observing: false,
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
        });
        assert_eq!(paused.label(), "observing");
        assert_eq!(paused.detail(), "collection off");
        assert_eq!(paused.ts_us(), 10);

        let resumed = StreamFrame::Observing(ObservingEdge {
            ts_us: 11,
            observing: true,
            peer_uid: None,
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
}
