//! Local socket protocol shared by `observerd` (server) and `observer-bar` (client).
//!
//! The daemon is the sole owner of the DuckDB file; every other process reads
//! live status through a Unix-domain socket. This crate defines the wire types
//! and the newline-delimited JSON framing so both sides agree on the format.
//!
//! Deliberately runtime-agnostic: there is **no** tokio dependency here. The
//! blocking [`query`] client is all the bar needs; the async server in
//! `observerd` reuses [`write_frame`]/[`read_frame`] over its own runtime.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use serde::{Serialize, de::DeserializeOwned};
use types::{DnsSample, HostSample, LinkSample, ProxySample, RouteEvent};

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
    /// daemon holds it open and streams newline-JSON [`Event`] frames (via
    /// [`write_frame`]) until the client disconnects. `kinds` filters the stream
    /// server-side — `None` subscribes to every [`EventKind`], `Some(list)` only
    /// to the listed kinds. The blocking [`subscribe`] helper drives this path.
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
    pub observing: bool,
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
            observing: true,
        }
    }
}

/// A response from the daemon to a client.
///
/// `Status` is the large, hot variant; `Error`/`Incidents` are small. Clippy's
/// `large_enum_variant` would suggest boxing `StatusSnapshot`, but this is the
/// shared wire type both `observerd` (which constructs `Response::Status(..)`
/// directly) and `observer-bar` depend on, so introducing `Box` here would be a
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

/// Blocking client for the bar: connect, write one newline-JSON request, read one
/// newline-JSON response. Framing = serde_json + `'\n'`. Connection-refused / no
/// socket ⇒ `Err` (the caller renders an "offline" state).
pub fn query(sock_path: &str, req: &Request) -> std::io::Result<Response> {
    let stream = UnixStream::connect(sock_path)?;
    let mut writer = &stream;
    write_frame(&mut writer, req)?;
    let mut reader = BufReader::new(&stream);
    read_frame(&mut reader)
}

/// A held-open live event stream from the daemon, returned by [`subscribe`].
///
/// Wraps the buffered socket and yields decoded [`Event`] frames as an iterator.
/// The daemon pushes frames as they happen — iterating simply blocks until the
/// next one arrives. A clean close by the daemon ends iteration (`None`); a
/// decode/read failure surfaces as `Some(Err(..))`, letting the caller log and
/// reconnect. No tokio: this is a plain blocking [`UnixStream`] the bar drives
/// on its own thread.
pub struct Subscription {
    reader: BufReader<UnixStream>,
}

impl Iterator for Subscription {
    type Item = std::io::Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        match read_frame(&mut self.reader) {
            Ok(ev) => Some(Ok(ev)),
            // The daemon closed the connection cleanly — the stream is over.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// Blocking client for a live event stream: connect, write one newline-JSON
/// [`Request::Subscribe`], then return a [`Subscription`] that yields each pushed
/// [`Event`] frame. Unlike [`query`], this does **not** read a single response —
/// the connection stays open and the daemon streams events until either side
/// disconnects. Connection-refused / no socket ⇒ `Err` (the caller renders an
/// "offline" state and retries).
pub fn subscribe(sock_path: &str, req: &Request) -> std::io::Result<Subscription> {
    // The signature accepts any `Request` (the plan's shape), but only a
    // `Subscribe` yields an `Event` stream — a one-shot request would make the
    // first `next()` mis-decode the daemon's single `Response` frame as an
    // `Event`. Catch that misuse in debug builds; release stays permissive.
    debug_assert!(
        matches!(req, Request::Subscribe { .. }),
        "subscribe() expects a Request::Subscribe, got {req:?}"
    );
    let stream = UnixStream::connect(sock_path)?;
    let mut writer = &stream;
    write_frame(&mut writer, req)?;
    Ok(Subscription {
        reader: BufReader::new(stream),
    })
}

/// Write one value as a single newline-terminated JSON frame.
///
/// Kept in one place so both sides share the exact wire format.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, v: &T) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec(v)?;
    buf.push(b'\n');
    w.write_all(&buf)?;
    w.flush()
}

/// Read one newline-terminated JSON frame into a value.
///
/// Returns an `UnexpectedEof` error if the stream closes before a full frame.
pub fn read_frame<R: BufRead, T: DeserializeOwned>(r: &mut R) -> std::io::Result<T> {
    let mut line = String::new();
    let n = r.read_line(&mut line)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed before a full frame was read",
        ));
    }
    serde_json::from_str(&line).map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{GwVerdict, TcpVerdict};

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
}
