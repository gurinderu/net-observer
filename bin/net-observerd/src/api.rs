//! The local API server (plan Task 2 / spec "Local API").
//!
//! `net-observerd` is the sole DuckDB owner (DuckDB takes a per-process file lock, so
//! a second opener — even read-only — is blocked while the daemon runs). Every
//! other process reads live status over this Unix-domain socket instead of
//! opening the database. `Status`, `Incidents` and `Subscribe` are answered
//! entirely from the in-memory [`StatusSnapshot`] and the bus the pipeline keeps
//! current — no DB read, zero contention with the writer, always live. The one
//! request that DOES read the database is [`Request::Query`], a named diagnosis
//! (`crate::api_query`): read-only, run on the blocking pool because DuckDB is
//! synchronous, and at most ONE in flight ([`MAX_QUERIES_IN_FLIGHT`]) because
//! it holds the store mutex the writer needs. It exists because the daemon's
//! lock leaves no other way to read the record while collection runs.
//!
//! The wire format is `net_observer_ipc`'s: frames are encoded with
//! `net_observer_ipc::encode_frame` (the same bytes `write_frame` produces) — one
//! newline-terminated JSON [`Request`] in, one newline-terminated JSON
//! [`Response`] out, then the connection closes. The one exception is
//! [`Request::Subscribe`], which is answered by a stream of
//! [`StreamFrame`]s instead of a single [`Response`].
//!
//! Reads are open to anyone who can connect (the default `socket_mode` admits
//! the console user's group, `staff`, so the unprivileged menu-bar app can
//! poll a root daemon — realm net-observer, node #110); *control* is not.
//! Every `Request::Control` first passes the peer-credential gate in
//! [`control_request`] — see [`ControlPolicy`].

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use collector_core::ProbingState;
use net_observer_ipc::{
    ControlCmd, ControlResult, DiagnosticQuery, EXPERIMENT_MAX_MINUTES, EncodedFrame, Event,
    EventKind, Gap, Ready, Request, Response, ScanOptions, StatusSnapshot, StreamError,
    StreamErrorCode, StreamFrame, Table, UNDECODABLE_REQUEST_PREFIX, experiment_id,
    experiment_report_json, experiment_running_message,
};
use store::Store;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, broadcast};
use types::{
    ExperimentReport, ExperimentWindow, NeighborsSample, NeighborsVerdict, ObservingCause,
    ObservingEdge, OwnFrames, ProbingEdge, ProbingReason, ProbingTier, Sample,
};

use crate::acting;
use crate::pipeline::{
    AirScanRequest, AirScanner, CveLookupOutcome, NeighborScanner, PcapRingSlot, TopologyScanner,
    confidence_token,
};

/// The uid `root` runs as. Always authorised for control: root can already stop
/// and reconfigure the daemon, so refusing it would be theatre.
const ROOT_UID: u32 = 0;

/// Hard cap on concurrently held-open `Subscribe` streams. A generous backstop,
/// not a tuning knob: each subscriber costs a task, an fd and a broadcast
/// receiver, and the socket is connectable by every process of the console
/// user's group by default (`socket_mode` 0o660, `staff`), so an unprivileged
/// process must not be able to exhaust the daemon by opening subscriptions in
/// a loop. Beyond it the daemon refuses with a decodable `StreamFrame::Error`
/// rather than a bare close.
pub(crate) const MAX_SUBSCRIBERS: usize = 256;

/// Largest request frame the daemon will buffer before giving up on finding a
/// newline. The socket is group-connectable by default (0660 root:staff — every
/// process of the console user), so no client may grow server memory by never
/// terminating its request; an over-long frame is
/// truncated, fails to parse, and is answered `Response::Error`.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// How many named diagnoses (`Request::Query`) may run at once: ONE. A diagnosis
/// holds the store's connection mutex for as long as its `ASOF JOIN` takes, and
/// the pipeline's next sample write waits behind it; on a group-connectable
/// socket that is a stall any of the console user's processes could inflict by
/// looping queries.
/// `MAX_CONNECTIONS` bounds how many such connections exist, not what they cost,
/// so the gate is here: a second concurrent query is refused at once with a
/// decodable `Response::Error` (`try_acquire`, never a queue that would let the
/// backlog itself become the stall). Not a per-peer rate limit — a deliberate
/// non-goal (realm net-observer, node #58).
pub const MAX_QUERIES_IN_FLIGHT: usize = 1;

/// The refusal a `Request::Query` gets while another diagnosis holds the gate.
/// Deliberately NOT spelled with [`UNDECODABLE_REQUEST_PREFIX`]: the CLI reads
/// that prefix as "this daemon cannot answer diagnoses" and falls back to the
/// DB file, which would only meet the lock; this is a daemon that can, and
/// says try again.
pub const QUERY_BUSY: &str = "a diagnosis is already running; retry";

/// The server-side bound on one diagnosis. The client gives up on the socket
/// after its own read budget, but nothing about a closed socket stops a
/// `spawn_blocking` task holding the store mutex — so the daemon interrupts the
/// statement itself at this deadline (`Store::query_prepared_within`), and the
/// permit drops with the task, which is now bounded. The client's read budget
/// (`net_observer_ipc`'s `DIAGNOSIS_TIMEOUT`) is deliberately longer, so what
/// the operator reads is this daemon's "interrupted", not their own timeout.
pub const QUERY_DEADLINE: Duration = Duration::from_secs(30);

/// Hard cap on concurrently handled socket connections, of ANY kind, enforced at
/// accept time. [`MAX_SUBSCRIBERS`] bounds *subscriptions*; a connection that
/// never sends a request never reaches that path at all, so without this cap a
/// local process can pin unbounded tasks, fds and 8 KiB read buffers on a socket
/// that every process of the console user's group can connect to by default
/// (`socket_mode` 0o660, `staff`).
pub(crate) const MAX_CONNECTIONS: usize = 512;

// The subscriber cap must stay the limit a well-behaved client meets FIRST: it
// answers with a decodable `StreamFrame::Error`, while this one can only close.
const _: () = assert!(
    MAX_CONNECTIONS > MAX_SUBSCRIBERS,
    "MAX_CONNECTIONS must exceed MAX_SUBSCRIBERS or the subscriber cap is unreachable"
);

/// How long a freshly accepted connection has to deliver its newline-terminated
/// request. Bounds the WHOLE initial read, so a byte-per-second drip cannot extend
/// it — and only that read: a held-open `Subscribe` stream is idle by design and
/// is watched for EOF instead (see [`stream_events`]). Generous next to any honest
/// client on a local socket; short enough that a silent connection cannot camp on
/// a connection slot.
pub(crate) const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum interval between lines from one rate-limited log site.
pub(crate) const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// One rate-limited line's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Burst {
    /// Events suppressed since the previous line (`0` on the first).
    pub suppressed: u64,
    /// Events since this limiter was created, including this one.
    pub total: u64,
}

/// A log throttle for a line an unprivileged local process can trigger.
///
/// The socket is group-connectable by default (0660 root:staff), so an
/// unauthorised process of the console user can loop connect+`Control` and, at
/// one `warn!` per attempt, grow a ROOT daemon's log at
/// its own pace. At most one line per `interval`, and each line reports how many
/// events were suppressed since the last one — deferred, never lost, so the flood
/// stays visible and countable without being transcribed. Monotonic ([`Instant`])
/// on purpose: a wall-clock step must be able neither to unmute the log nor to
/// mute it for ever.
pub struct RateLimitedLog {
    interval: Duration,
    state: Mutex<RateLimitState>,
}

/// How many events are waiting to be reported, and when the last line went out.
struct RateLimitState {
    last_logged: Option<Instant>,
    suppressed: u64,
    total: u64,
}

impl RateLimitedLog {
    /// A limiter that has never logged, so the FIRST event is always reported —
    /// one genuine misconfiguration stays loud and immediate.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(RateLimitState {
                last_logged: None,
                suppressed: 0,
                total: 0,
            }),
        }
    }

    /// Record one event at `now`. `Some(Burst)` ⇒ the caller should emit its line;
    /// `None` ⇒ counted only, and reported by the next line. `now` is injected so
    /// the throttle is unit tested without sleeping.
    pub fn record(&self, now: Instant) -> Option<Burst> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.total += 1;
        let due = match st.last_logged {
            None => true,
            Some(prev) => now.saturating_duration_since(prev) >= self.interval,
        };
        if !due {
            st.suppressed += 1;
            return None;
        }
        st.last_logged = Some(now);
        let burst = Burst {
            suppressed: st.suppressed,
            total: st.total,
        };
        st.suppressed = 0;
        Some(burst)
    }
}

/// The connected peer's uid, read from the socket itself.
///
/// macOS: tokio implements `UnixStream::peer_cred` with `getpeereid(2)`, and the
/// credentials describe the peer at `connect(2)` time. `None` when the lookup
/// fails, which [`authorize_control`] turns into a refusal: an authority decision
/// whose origin cannot be established fails closed.
fn peer_uid_of(stream: &UnixStream) -> Option<u32> {
    stream.peer_cred().ok().map(|c| c.uid())
}

/// Who may send a `Request::Control`. Built once at start-up from the config.
///
/// Peer credentials are checked on `Request::Control` **only** — `Status`,
/// `Incidents` and `Subscribe` stay open, because the group-open default
/// `socket_mode` exists precisely for unprivileged readers and a read carries no
/// authority.
#[derive(Debug, Clone)]
pub struct ControlPolicy {
    /// The daemon's own effective uid. A process running as the same user can
    /// already signal this one, so it gains no new authority — and this is the
    /// clause that keeps an unprivileged `cargo test` (server and client in one
    /// process) working with no root, no console and no special-casing.
    pub daemon_uid: u32,
    /// `config.socket_owner_uid`: the operator's explicit statement about who
    /// owns the control endpoint (the daemon already `chown`s the socket to it).
    pub socket_owner_uid: Option<u32>,
    /// `config.control_uids`: extra authorised uids, for headless/multi-admin
    /// hosts with no console session.
    pub control_uids: Vec<u32>,
    /// How the console-user clause is resolved. Always [`console_uid`] in
    /// production ([`ControlPolicy::from_config`] is the only constructor outside
    /// this module, so no caller can weaken it). The end-to-end control tests
    /// substitute a stub: on a developer's Mac the test process IS the console
    /// user, and the real lookup would authorise the very peer the refusal arm
    /// needs refused.
    console: fn() -> Option<u32>,
    /// How a connected peer's uid is resolved. Always [`peer_uid_of`] in
    /// production: [`ControlPolicy::from_config`] is the only constructor
    /// reachable outside this module, the field is PRIVATE, and no config key or
    /// CLI flag feeds it — so neither a caller nor an operator can substitute it.
    /// A TEST SEAM, not a policy knob, exactly like `console` above.
    ///
    /// It exists because the end-to-end control tests run server and client in
    /// ONE process, where `getpeereid(2)` and `geteuid(2)` return the same value:
    /// a hardcoded `Some(geteuid())` at the lookup site is indistinguishable from
    /// the real lookup there, while in production — where `daemon_uid` IS
    /// `geteuid()` — it would authorise EVERY peer on the group-connectable
    /// (0660 root:staff by default) socket.
    /// Injecting a uid that is neither this process's, nor root's, nor the
    /// console user's is the only thing that makes that substitution observable.
    peer_uid: fn(&UnixStream) -> Option<u32>,
}

impl ControlPolicy {
    /// Build from config, resolving the daemon's own effective uid once.
    pub fn from_config(socket_owner_uid: Option<u32>, control_uids: Vec<u32>) -> Self {
        // SAFETY: `geteuid` takes no arguments, dereferences nothing and cannot
        // fail (POSIX: "always successful").
        let daemon_uid = unsafe { libc::geteuid() };
        Self {
            daemon_uid,
            socket_owner_uid,
            control_uids,
            console: console_uid,
            peer_uid: peer_uid_of,
        }
    }
}

/// THE control predicate: may `peer_uid` send control commands, given the
/// current console owner `console_uid` (`None` when there is none / it cannot be
/// read)?
///
/// **Pure** — no syscalls, no clock, no filesystem — so the whole policy is unit
/// tested without root, without a socket and without a console session. Allowed:
/// - `root` (uid 0): it can already kill and reconfigure the daemon;
/// - the daemon's own uid: it can already signal this process;
/// - `socket_owner_uid`, when the operator set it;
/// - the **console user** — the logged-in GUI user running `net-observer-bar`, which
///   is the out-of-the-box case for the menu-bar toggle against a root daemon;
/// - any uid explicitly listed in `control_uids`.
///
/// Everything else — an unrelated `staff` uid on the group-connectable socket —
/// is refused. An unidentifiable peer is refused by [`authorize_control`]: an
/// authority decision fails closed.
fn control_authorized(policy: &ControlPolicy, peer_uid: u32, console_uid: Option<u32>) -> bool {
    peer_uid == ROOT_UID
        || peer_uid == policy.daemon_uid
        || policy.socket_owner_uid == Some(peer_uid)
        || console_uid == Some(peer_uid)
        || policy.control_uids.contains(&peer_uid)
}

/// The uid of the user logged in at this Mac's console — the one running the
/// menu-bar app.
///
/// macOS's `loginwindow` keeps `/dev/console` owned by the console-session user
/// (the same fact `stat -f %Su /dev/console` reports), so its owner *is* that
/// user. Plain `std`: no SystemConfiguration binding, no framework link, no new
/// dependency.
///
/// Resolved fresh on every control request, never cached: the daemon is a
/// LaunchDaemon that starts at boot before anyone has logged in, and fast user
/// switching / logout must take effect immediately. `None` when nobody is logged
/// in (root-owned) or the path cannot be read (SSH-only host, CI, container) —
/// which fails closed: a console that is not there authorises nobody.
fn console_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/dev/console").ok()?.uid();
    (uid != ROOT_UID).then_some(uid)
}

/// Proof that the connected peer passed [`control_authorized`], carrying that
/// peer's uid.
///
/// Its field is private and it is constructed ONLY by [`authorize_control`];
/// [`control_response`] requires one by value. No dispatch path can therefore
/// reach a control command without the peer check — the gate is a type, not a
/// convention a future third command could forget.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PeerAuthorized(u32);

impl PeerAuthorized {
    /// The authorised peer's uid — recorded on the `observing_edge` boundary row
    /// so a pause is attributable to a *who*.
    fn uid(self) -> u32 {
        self.0
    }
}

/// Decide whether the peer may send control commands. `peer_uid` is `None` when
/// `getpeereid` failed; a control request whose origin cannot be established is
/// never authorised.
fn authorize_control(
    policy: &ControlPolicy,
    peer_uid: Option<u32>,
) -> Result<PeerAuthorized, ControlResult> {
    match peer_uid {
        // The console clause is resolved LAST, and only when nothing cheaper has
        // already said yes: `control_authorized(.., None)` is exactly "authorised
        // with no console session". An authorised-by-config peer therefore costs
        // no `stat("/dev/console")` at all.
        Some(uid)
            if control_authorized(policy, uid, None)
                || control_authorized(policy, uid, (policy.console)()) =>
        {
            Ok(PeerAuthorized(uid))
        }
        Some(uid) => Err(ControlResult {
            ok: false,
            message: format!(
                "control refused: uid {uid} is not authorised to control net-observerd"
            ),
        }),
        None => Err(ControlResult {
            ok: false,
            message: "control refused: peer credentials unavailable".to_string(),
        }),
    }
}

/// Parameters of the manual actions handed to the socket server. Gates nothing:
/// config may switch off what the daemon does by itself, never a command the
/// operator sends by hand — the invocation is the sanction (realm net-observer,
/// node #91). The one gate on the control path is the peer-credential check
/// ([`ControlPolicy`]), applied to every `Request::Control` before dispatch.
#[derive(Debug, Clone)]
pub struct ActingConfig {
    /// The `launchctl` service target for `ControlCmd::KickstartProxy`.
    pub singbox_service: String,
}

/// One experiment window as the daemon holds it in memory (realm
/// net-observer, node #61): running, with the bound a poll is told; or
/// finished, with the report the `experiment` table also holds. A restart
/// empties this — the table is what outlives the process.
pub enum ExperimentState {
    /// The window is open; `ends_at_us` is when the end task wakes.
    Running { ends_at_us: i64 },
    /// The window closed and its report is computed. Boxed: the report is a
    /// few hundred bytes next to `Running`'s one instant, and the registry
    /// holds one entry per window ever run.
    Finished(Box<ExperimentReport>),
}

/// Every window this process has run, by id. At most one is `Running`.
pub type Experiments = Mutex<HashMap<String, ExperimentState>>;

/// The owned handles an experiment window's end needs once the control
/// connection that opened it is gone: the window runs in the daemon, not on
/// the connection, so a dropped socket loses nothing (realm net-observer,
/// node #61). Cloned per control request — a handful of `Arc`s.
#[derive(Clone)]
pub struct ExperimentHandles {
    pub store: Arc<dyn Store + Send + Sync>,
    pub probing: Arc<ProbingState>,
    pub snapshot: Arc<Mutex<StatusSnapshot>>,
    pub events_tx: broadcast::Sender<EncodedFrame>,
    pub freezer: Arc<PcapRingSlot>,
    pub blob_dir: PathBuf,
    pub resume_at_us: Arc<AtomicI64>,
    pub session_end_us: Arc<AtomicI64>,
    pub experiments: Arc<Experiments>,
    /// The pcap ring's BPF filter, as configured — recorded on the report
    /// as the whole of what its own-frame count can see.
    pub ring_filter: String,
    /// The link collector's tick, as configured — the yardstick for a sleep
    /// inside the window and for the tick that straddled the flip.
    pub link_interval: Duration,
}

impl ExperimentHandles {
    /// The tier switch's sinks, borrowed from the owned handles.
    fn tier_sinks(&self) -> TierSinks<'_> {
        TierSinks {
            probing: &self.probing,
            snapshot: &self.snapshot,
            resume_at_us: &self.resume_at_us,
            session_end_us: &self.session_end_us,
            store: self.store.as_ref(),
            events_tx: &self.events_tx,
        }
    }
}

/// Everything the socket server needs, assembled once by the daemon.
///
/// Bundled rather than passed as eleven positional arguments (which would trip
/// `clippy::too_many_arguments` under `-D warnings`), and cheaper: the accept
/// loop clones one `Arc` per connection instead of six handles.
pub struct ApiServer {
    pub socket_path: String,
    pub socket_mode: u32,
    pub socket_owner_uid: Option<u32>,
    /// The group the socket is `chown`ed to after bind — `staff` by default,
    /// the group `socket_mode`'s group bits open the socket to (realm
    /// net-observer, node #110). `None` leaves the group as bind created it.
    pub socket_gid: Option<u32>,
    /// Concurrent held-open `Subscribe` cap. Production passes
    /// [`MAX_SUBSCRIBERS`]; tests pass a small value so the refusal path is one
    /// extra connection rather than 257.
    pub max_subscribers: usize,
    /// Accept-time cap on concurrently handled connections. Production passes
    /// [`MAX_CONNECTIONS`]; tests pass a small value so the refusal path is one
    /// extra connection rather than 513.
    pub max_connections: usize,
    /// How long a freshly accepted connection has to send its request. Production
    /// passes [`REQUEST_READ_TIMEOUT`]; tests pass milliseconds.
    pub request_timeout: Duration,
    pub acting: ActingConfig,
    /// Who may send a `Request::Control`.
    pub policy: ControlPolicy,
    /// The collectors' pause flag; `SetObserving` is its only writer.
    pub observing: Arc<AtomicBool>,
    /// The probing tier the link, proxy and dns collectors read each tick;
    /// `SetProbing` is its only writer. Shared with the collectors for the same
    /// reason as `observing`. (realm net-observer, node #88)
    pub probing: Arc<ProbingState>,
    /// The slot holding the pcap ring, asked at request time rather than held by
    /// value: the ring can start late (no interface at boot) or die, and
    /// `FreezePcap` must answer about the ring that is running *now*. An empty
    /// slot makes the command a refusal with a message, never a silent success.
    pub freezer: Arc<PcapRingSlot>,
    /// The neighbour scanner, when one could be built for this host. `None`
    /// makes `ScanNeighbors` a refusal with a message, never a silent success.
    pub scanner: Option<Arc<dyn NeighborScanner>>,
    /// The on-demand air scanner, when the platform has one. `None` makes
    /// `ScanAir` a refusal with a message, never a silent success.
    pub air_scanner: Option<Arc<dyn AirScanner>>,
    /// The on-demand topology scanner, when the platform has one. `None` makes
    /// `ScanTopology` a refusal with a message, never a silent success.
    pub topology_scanner: Option<Arc<dyn TopologyScanner>>,
    /// The configured CVE snapshot directory, when one is set. The `cve` rung is
    /// UNAVAILABLE unless this is `Some` AND the directory exists — checked at
    /// scan time so a snapshot removed after boot is honestly reported as
    /// dropped, never pretended present.
    pub scan_cve_snapshot: Option<PathBuf>,
    /// Where a manual freeze writes its copy: the daemon's blob directory, the
    /// same root the `gw-change` freeze handler uses.
    pub blob_dir: PathBuf,
    /// `ts_us` of the most recent window-clearing edge — a RESUME, or a
    /// probing-tier switch in either direction — published here and consumed
    /// by `pipeline::run` to drop its pre-edge trigger window. `0` = no such
    /// edge yet.
    pub resume_at_us: Arc<AtomicI64>,
    /// `ts_us` of the edge that ENDED the observation session the next
    /// `resume_at_us` move re-opens. `SetObserving(false)` and `set_probing`
    /// both write here, and BOTH use `compare_exchange(0, ts_us, ..)`, never a
    /// plain store: the FIRST unconsumed end wins. A tier switch accepted
    /// WHILE PAUSED publishes no sample of its own to consume this atomic, so
    /// an unconditional store would let it push the close point forward — a
    /// pause at `t=10` then a switch at `t=50`, both before the resume at
    /// `t=100`, would otherwise close at `50`, still inside the unobserved gap
    /// the pause opened at `10`. Losing the race is the correct outcome for the
    /// later writer, which is why both call sites ignore the `Result`.
    /// `pipeline::run` CONSUMES this exactly once per edge with `swap(0, ..)` —
    /// reading it and resetting it to `0` atomically, so a value once used
    /// cannot be read again by a later edge — and closes
    /// (`TriggerEngine::close_all`) at that value if it was `> 0`, or at the
    /// edge's own `ts_us` otherwise: `0` means no end was ever recorded for
    /// this edge. The one residual: a pause whose `compare_exchange` lands
    /// between the consumer's `resume_at_us` load and its `swap` FOR THE
    /// PREVIOUS edge loses the race to that still-unconsumed value and is
    /// silently dropped, so the later resume that ends ITS session falls back
    /// to its own `ts_us` instead of this pause's — accepted, since closing
    /// that gap needs an operator toggle inside the consumer's own
    /// load-to-swap window, sub-millisecond and far tighter than a human
    /// hand on the control (realm net-observer, node #124).
    pub session_end_us: Arc<AtomicI64>,
    pub snapshot: Arc<Mutex<StatusSnapshot>>,
    /// Durable sink for pause/resume boundary records.
    pub store: Arc<dyn Store + Send + Sync>,
    /// The one-in-flight gate on `Request::Query` — [`MAX_QUERIES_IN_FLIGHT`]
    /// permits, claimed with `try_acquire` and never awaited. An `Arc` like
    /// the other shared state here (`observing`, `probing`, `store`): one gate
    /// for the server and every connection task it spawns, whichever of them
    /// is holding the permit.
    pub query_gate: Arc<Semaphore>,
    /// The realtime bus, carrying frames already serialised once.
    pub events_tx: broadcast::Sender<EncodedFrame>,
    /// Bounded log for control refusals — attacker-triggerable on a
    /// group-connectable (0660 root:staff by default) socket, so the line is
    /// rate-limited and aggregated, never per attempt.
    pub control_refusals: RateLimitedLog,
    /// Same treatment for subscriber-cap refusals. `MAX_CONNECTIONS` is
    /// deliberately larger than `MAX_SUBSCRIBERS`, so a peer holding the
    /// subscriber cap can still loop connect+`Subscribe` in the remaining
    /// connection slots — one refusal each, and unthrottled that is the same
    /// root-log amplification the control path already defends against.
    pub sub_refusals: RateLimitedLog,
    /// The experiment windows this process has run (realm net-observer,
    /// node #61): `StartExperiment` opens one, its end task closes it, and
    /// `Query(Experiment { id })` reads a running or just-finished one here
    /// before the `experiment` table.
    pub experiments: Arc<Experiments>,
    /// The pcap ring's BPF filter, as configured (`collectors.pcap_ring.filter`)
    /// — what an experiment report says its own-frame count can see.
    pub ring_filter: String,
    /// The link collector's tick, as configured (`collectors.link.interval`)
    /// — an experiment report's yardstick for a sleep and a straddling tick.
    pub link_interval: Duration,
}

impl ApiServer {
    /// The owned handles an experiment window's end task carries.
    fn experiment_handles(&self) -> ExperimentHandles {
        ExperimentHandles {
            store: Arc::clone(&self.store),
            probing: Arc::clone(&self.probing),
            snapshot: Arc::clone(&self.snapshot),
            events_tx: self.events_tx.clone(),
            freezer: Arc::clone(&self.freezer),
            blob_dir: self.blob_dir.clone(),
            resume_at_us: Arc::clone(&self.resume_at_us),
            session_end_us: Arc::clone(&self.session_end_us),
            experiments: Arc::clone(&self.experiments),
            ring_filter: self.ring_filter.clone(),
            link_interval: self.link_interval,
        }
    }

    /// Bind the Unix-domain socket at `socket_path`, `chmod` it to `socket_mode`
    /// and `chown` it to `socket_owner_uid` / `socket_gid` so an unprivileged
    /// client (the bar; the daemon runs as root) can connect through the group
    /// bits (realm net-observer, node #110), and serve [`Request`]s from the
    /// shared snapshot until the task is aborted.
    ///
    /// The peer-credential [`ControlPolicy`] gates the whole of the control
    /// path; `acting` only names the service `KickstartProxy` targets. Only this
    /// daemon runs the actuator, and only on an explicit request — never
    /// automatically.
    ///
    /// A one-shot request (`Status`, `Incidents`, `Query`, `Control`) is answered with a
    /// single [`Response`] then the connection closes; a [`Request::Subscribe`]
    /// instead holds the connection open and streams newline-JSON
    /// [`StreamFrame`]s from a per-connection broadcast receiver until the client
    /// disconnects (see [`stream_events`]).
    ///
    /// Runs forever; the daemon spawns it and `abort()`s it on shutdown. Every
    /// connection task is *owned* by the accept loop (a [`tokio::task::JoinSet`],
    /// not a detached `spawn`), so aborting or dropping this future tears down
    /// the in-flight connections with it — which is also what releases their
    /// subscriber slots. A stale socket file left by a previous run is removed
    /// before binding (otherwise `bind` fails with `EADDRINUSE`).
    pub async fn serve(self) -> std::io::Result<()> {
        // A leftover socket file from a previous run makes bind() fail; clear it.
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)?;
        // The root daemon opens the mode to the group so the logged-in user's UI
        // can connect; bind left it under the process umask.
        std::fs::set_permissions(
            &self.socket_path,
            std::fs::Permissions::from_mode(self.socket_mode),
        )?;
        // One chown for both halves: the group the mode's group bits admit
        // (`staff` by default — who may READ, realm net-observer, node #110)
        // and, when an owner uid is configured, the control-path hardening
        // (operators pair it with mode 0600 so only the owner can even connect
        // to the control endpoint). Best-effort: a chown failure is logged but
        // never takes the daemon down. Note this is belt-and-braces only —
        // authorisation itself is the peer-credential check in
        // `control_request`, not the socket mode or its group.
        if self.socket_owner_uid.is_some() || self.socket_gid.is_some() {
            match std::os::unix::fs::chown(
                &self.socket_path,
                self.socket_owner_uid,
                self.socket_gid,
            ) {
                Ok(()) => tracing::info!(
                    uid = ?self.socket_owner_uid,
                    gid = ?self.socket_gid,
                    path = %self.socket_path,
                    "status socket chowned"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    uid = ?self.socket_owner_uid,
                    gid = ?self.socket_gid,
                    path = %self.socket_path,
                    "failed to chown status socket"
                ),
            }
        }
        tracing::info!(
            path = %self.socket_path,
            mode = format!("{:o}", self.socket_mode),
            max_subscribers = self.max_subscribers,
            "status socket listening"
        );

        let srv = Arc::new(self);
        // One counter shared by every connection task: the daemon's live
        // subscriber tally, guarding `max_subscribers`.
        let subscribers = Arc::new(AtomicUsize::new(0));
        // Live connection tally. Distinct from `subscribers`: every subscriber
        // holds a connection, but most connections are one-shot requests that
        // never reach `stream_events`.
        let connections = Arc::new(AtomicUsize::new(0));
        // Bounded logs for the two lines an unprivileged process can drive at its
        // own rate. Separate limiters so one flood cannot mask the other.
        let conn_refusals = RateLimitedLog::new(REFUSAL_LOG_INTERVAL);
        let accept_errors = RateLimitedLog::new(REFUSAL_LOG_INTERVAL);

        // Connection tasks live in a set owned by this loop rather than detached, so
        // dropping/aborting `serve` aborts them too.
        let mut conns = tokio::task::JoinSet::new();
        loop {
            let accepted = listener.accept().await;
            // Reap finished connection tasks so the set cannot grow without bound.
            while conns.try_join_next().is_some() {}
            match accepted {
                Ok((stream, _addr)) => {
                    // Capped at ACCEPT time. Over the cap the connection is closed
                    // immediately: nothing has been read, so there is no request to
                    // answer and no way to know which frame type the client would
                    // decode — writing the wrong one is strictly worse than a clean
                    // EOF. Accept-and-close, not "stop accepting": leaving
                    // connections in the listen backlog spins this loop and hides
                    // the condition from the log.
                    let Some(slot) = CountedSlot::claim(&connections, srv.max_connections) else {
                        if let Some(burst) = conn_refusals.record(Instant::now()) {
                            tracing::warn!(
                                max = srv.max_connections,
                                suppressed = burst.suppressed,
                                total = burst.total,
                                "connection cap reached; closing new connection"
                            );
                        }
                        drop(stream);
                        continue;
                    };
                    let srv = Arc::clone(&srv);
                    let subscribers = Arc::clone(&subscribers);
                    // One task per connection. One-shot requests reply and close; a
                    // `Subscribe` holds the connection open and streams frames.
                    conns.spawn(async move {
                        // Held for the whole connection, released on every exit
                        // path, exactly like the subscriber slot.
                        let _slot = slot;
                        if let Err(e) = handle_conn(stream, &srv, &subscribers).await {
                            tracing::debug!(error = %e, "status socket connection error");
                        }
                    });
                }
                // Also rate-limited: a persistent accept failure (EMFILE under fd
                // exhaustion) spins this loop at full speed, which is the same
                // unbounded-log path by another route.
                Err(e) => log_accept_error(&accept_errors, &e, Instant::now()),
            }
        }
    }
}

/// Emit the rate-limited "accept failed" line for `error`, or count it toward the
/// next one.
///
/// A named function rather than an inline block for exactly one reason: this is
/// the only one of the daemon's four rate-limited lines whose trigger — an
/// `accept(2)` failure such as `EMFILE` — cannot be provoked from a test without
/// exhausting the whole test process's file descriptors. The other three (control
/// refusals, subscriber-cap refusals, connection-cap refusals) are driven end to
/// end and need no seam. `now` is injected for the same reason
/// [`RateLimitedLog::record`] already takes it: the throttle is exercised without
/// sleeping. No behaviour changes — the message literal and every field stay at
/// one static callsite; only the enclosing function moved.
///
/// Its one honest limit: this pins the LINE's volume, not its call site, because
/// no in-process test can drive a real accept failure. Deleting the call site is
/// caught by the build instead — the only other caller is `#[cfg(test)]`, so a
/// dropped `Err` arm makes this `dead_code` under `-D warnings`.
fn log_accept_error(limiter: &RateLimitedLog, error: &std::io::Error, now: Instant) {
    if let Some(burst) = limiter.record(now) {
        tracing::warn!(
            error = %error,
            suppressed = burst.suppressed,
            total = burst.total,
            "status socket accept failed"
        );
    }
}

/// Handle one client: read a single newline-JSON [`Request`], then dispatch.
///
/// One-shot requests (`Status`, `Incidents`, `Query`, `Control`) are answered with
/// a single newline-JSON [`Response`], then the connection closes — from the
/// in-memory snapshot, except a `Query`, which reads the store on the blocking
/// pool with at most one in flight ([`MAX_QUERIES_IN_FLIGHT`]; a second is
/// refused with [`QUERY_BUSY`]). A [`Request::Subscribe`] instead holds the
/// connection open and streams [`StreamFrame`]s via [`stream_events`] until the
/// client disconnects. The snapshot lock is held only long enough to clone what
/// a response needs — never across an `.await`.
async fn handle_conn(
    stream: UnixStream,
    srv: &ApiServer,
    subscribers: &Arc<AtomicUsize>,
) -> std::io::Result<()> {
    // Peer credentials for the control gate, read from the WHOLE stream before
    // the split (only a `UnixStream` exposes them; on macOS tokio implements
    // this with `getpeereid(2)`). They describe the peer at connect(2) time.
    // Read paths never consult it: the permissive default socket mode exists for
    // unprivileged readers, and a read carries no authority. The resolution goes
    // through the policy's lookup hook — `peer_uid_of` in production, and a
    // second local account's uid injected by the tests that cannot have one.
    let peer_uid = (srv.policy.peer_uid)(&stream);
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    // Bounded in BOTH dimensions: `MAX_REQUEST_BYTES` stops an unterminated
    // request growing server memory, `request_timeout` stops a silent one holding
    // a connection slot, an fd and this task open for ever. Applies to the INITIAL
    // request only — a `Subscribe` stream is idle by design and must never time
    // out (see `stream_events`).
    let read = tokio::time::timeout(
        srv.request_timeout,
        (&mut reader).take(MAX_REQUEST_BYTES).read_line(&mut line),
    )
    .await;
    match read {
        Ok(Ok(0)) => return Ok(()), // client closed without sending a request
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            // A slow or abandoned client is routine; the cap refusal above is the
            // line that matters. `debug!`, matching the connection-error log.
            tracing::debug!(
                timeout_s = srv.request_timeout.as_secs_f64(),
                "no request within the read timeout; closing connection"
            );
            return Ok(());
        }
    }

    let response = match serde_json::from_str::<Request>(&line) {
        // Streaming path: hold the connection open and push frames from a
        // per-connection broadcast receiver until the client goes away. It never
        // produces a single `Response`, so it returns directly.
        Ok(Request::Subscribe { kinds }) => {
            return stream_events(
                &mut reader,
                &mut wr,
                kinds,
                StreamCtx {
                    events_tx: &srv.events_tx,
                    observing: &srv.observing,
                    probing: &srv.probing,
                    subscribers,
                    max_subscribers: srv.max_subscribers,
                    refusals: &srv.sub_refusals,
                },
            )
            .await;
        }
        Ok(Request::Status) => Response::Status(snapshot_clone(&srv.snapshot)),
        Ok(Request::Incidents { limit }) => {
            let incidents = srv
                .snapshot
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .incidents
                .iter()
                .take(limit)
                .cloned()
                .collect();
            Response::Incidents(incidents)
        }
        // An experiment window this process holds in memory — running, or
        // finished and not yet asked for — answers from there, no store read
        // and no gate; only a window this process does not remember goes to
        // the `experiment` table by the gated path below (realm
        // net-observer, node #61).
        Ok(Request::Query(DiagnosticQuery::Experiment { id })) => {
            match experiment_in_memory(&srv.experiments, &id) {
                Some(answer) => answer,
                None => query_store(srv, DiagnosticQuery::Experiment { id }).await,
            }
        }
        // `check-cve --product`: a pure local-index read against whichever
        // `NeighborScanner` is configured, never `query_store` — this never
        // touches the store's connection mutex or DuckDB at all (unlike
        // every other `DiagnosticQuery` variant), so it skips the query gate
        // entirely rather than contending for it.
        Ok(Request::Query(DiagnosticQuery::CveLookup { product, version })) => {
            cve_lookup_response(srv, &product, version.as_deref())
        }
        Ok(Request::Query(q)) => query_store(srv, q).await,
        Ok(Request::Control(cmd)) => {
            let cx = ControlCtx {
                policy: &srv.policy,
                acting: &srv.acting,
                observing: &srv.observing,
                probing: &srv.probing,
                freezer: &srv.freezer,
                scanner: srv.scanner.as_deref(),
                air_scanner: srv.air_scanner.as_deref(),
                topology_scanner: srv.topology_scanner.as_deref(),
                scan_cve_snapshot: srv.scan_cve_snapshot.as_deref(),
                blob_dir: &srv.blob_dir,
                resume_at_us: &srv.resume_at_us,
                session_end_us: &srv.session_end_us,
                snapshot: &srv.snapshot,
                store: srv.store.as_ref(),
                events_tx: &srv.events_tx,
                refusals: &srv.control_refusals,
                experiment: srv.experiment_handles(),
            };
            Response::Control(control_request(cmd, peer_uid, &cx))
        }
        // The one spelling a client may read as "this daemon cannot decode
        // that request" — pinned in the ipc crate so the CLI's fallback rule
        // and this line cannot drift apart.
        Err(e) => Response::Error(format!("{UNDECODABLE_REQUEST_PREFIX}{e}")),
    };

    let buf = net_observer_ipc::encode_frame(&response)?;
    wr.write_all(&buf).await?;
    wr.flush().await
}

/// Run one [`DiagnosticQuery`] against the store and answer it.
///
/// A read, like `Status`: no peer gate. DuckDB is synchronous and a
/// diagnosis walks the whole record, so it runs off the runtime — and at
/// most ONE at a time (`MAX_QUERIES_IN_FLIGHT`): the permit is claimed
/// with `try_acquire`, so a second concurrent query is refused at once
/// rather than queued behind the store mutex, and it is held only for
/// the blocking run, not the reply. That run is itself bounded: the
/// statement is interrupted at `QUERY_DEADLINE`, so a client that gave
/// up cannot leave the mutex — and every write behind it — held for as
/// long as the join takes. The daemon's own starvation load keeps a
/// live reading in step with the incidents it recorded (see `api_query`).
async fn query_store(srv: &ApiServer, q: DiagnosticQuery) -> Response {
    match srv.query_gate.try_acquire() {
        Err(_busy) => {
            // Client-triggerable on a group-connectable socket: never above `debug!`.
            tracing::debug!("query refused: another diagnosis is running");
            Response::Error(QUERY_BUSY.to_string())
        }
        Ok(permit) => {
            let store = Arc::clone(&srv.store);
            let ran = tokio::task::spawn_blocking(move || {
                crate::api_query::run_query(
                    store.as_ref(),
                    q,
                    crate::STARVATION_LOAD,
                    QUERY_DEADLINE,
                )
            })
            .await;
            drop(permit);
            match ran {
                Ok(Ok(table)) => Response::Table(table),
                Ok(Err(message)) => Response::Error(message),
                Err(e) => Response::Error(format!("diagnosis task failed: {e}")),
            }
        }
    }
}

/// Answer `check-cve --product`: ask whichever [`NeighborScanner`] is
/// configured for `cve_lookup` and translate its two outcomes the same way
/// `query_store` translates a diagnosis's — `SnapshotUnavailable` becomes a
/// decoded-but-failed [`Response::Error`] (never the `UNDECODABLE_REQUEST_
/// PREFIX` spelling, which would tell a live client the daemon cannot even
/// READ this request), not a silent empty table. No scanner configured at
/// all answers the same wording `scan_now` already uses for the same
/// condition.
fn cve_lookup_response(srv: &ApiServer, product: &str, version: Option<&str>) -> Response {
    let Some(scanner) = srv.scanner.as_deref() else {
        return Response::Error("neighbour scanning not available".to_string());
    };
    match scanner.cve_lookup(product, version) {
        CveLookupOutcome::Matches(matches) => Response::Table(cve_lookup_table(&matches)),
        CveLookupOutcome::SnapshotUnavailable(note) => Response::Error(note),
    }
}

/// The [`Table`] shape `check-cve --product` renders: one row per
/// [`vuln_db::VulnMatch`], the same `cvss`/`known_exploited`/`confidence`
/// vocabulary `vulns`/`check-cve <ip>` already use ([`confidence_token`] is
/// the same mapping their `confidence` column is written with) minus the
/// per-host columns (`mac`, `ip`, `port`, `last_seen_us`) a name-only lookup
/// carries none of, plus `summary` — reachable there only via a join back to
/// the `cves` catalogue this daemon does not keep, so a name-only lookup
/// carries it directly instead.
fn cve_lookup_table(matches: &[vuln_db::VulnMatch]) -> Table {
    let rows = matches
        .iter()
        .map(|m| {
            vec![
                m.cve_id.clone(),
                m.cvss.map(|c| c.to_string()).unwrap_or_default(),
                m.known_exploited.to_string(),
                confidence_token(m.confidence).to_string(),
                m.summary.clone(),
            ]
        })
        .collect();
    Table {
        columns: ["cve_id", "cvss", "known_exploited", "confidence", "summary"]
            .into_iter()
            .map(String::from)
            .collect(),
        rows,
    }
}

/// The answer for an experiment window this process holds in memory, or
/// `None` when it holds no window of that id and the `experiment` table is
/// the place to look. A running window is a failure the CLI waits through —
/// spelled by `net_observer_ipc::experiment_running_message`, never with
/// [`UNDECODABLE_REQUEST_PREFIX`]; a finished one is its report as a table.
fn experiment_in_memory(experiments: &Experiments, id: &str) -> Option<Response> {
    let map = experiments.lock().unwrap_or_else(|e| e.into_inner());
    Some(match map.get(id)? {
        ExperimentState::Running { ends_at_us } => {
            Response::Error(experiment_running_message(id, *ends_at_us))
        }
        ExperimentState::Finished(report) => Response::Table(Table::from(report.as_ref())),
    })
}

/// One of a bounded pool of slots — connections at accept time, or held-open
/// subscriptions — released on drop, so every exit path (reply sent, read timeout,
/// client gone, write error, task aborted at shutdown) frees it.
struct CountedSlot(Arc<AtomicUsize>);

impl CountedSlot {
    /// Claim a slot, or `None` when the cap is reached. `fetch_update` rather
    /// than check-then-increment: two connections racing at the boundary must
    /// not both see `< max`.
    fn claim(count: &Arc<AtomicUsize>, max: usize) -> Option<Self> {
        count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()?;
        Some(Self(Arc::clone(count)))
    }
}

impl Drop for CountedSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Write one PER-CONNECTION frame (ack, gap, error). Bus frames are never
/// written this way — they arrive already encoded once for everyone (see
/// [`net_observer_ipc::EncodedFrame`]).
async fn write_stream_frame<W: AsyncWrite + Unpin>(
    wr: &mut W,
    frame: &StreamFrame,
) -> std::io::Result<()> {
    let buf = net_observer_ipc::encode_frame(frame)?;
    wr.write_all(&buf).await?;
    wr.flush().await
}

/// Stream live [`StreamFrame`]s to a held-open [`Request::Subscribe`] connection.
///
/// Order is load-bearing:
/// 1. reserve one of `max_subscribers` slots — over the cap the daemon writes a
///    single decodable [`StreamFrame::Error`] and closes, rather than a bare
///    close a client cannot tell from a crash;
/// 2. create the broadcast receiver;
/// 3. only then write the mandatory [`StreamFrame::Ready`] ack. The ack is the
///    client's proof that the receiver exists, so nothing published after
///    `net_observer_ipc::subscribe` returns can vanish into a
///    publish-before-subscribe window.
///
/// Then loop, writing each bus frame's already-encoded bytes to `wr`, filtered by
/// `kinds` (`None` = every kind). The filter applies to events only — the
/// delivery rule lives in [`EncodedFrame::passes`], not here.
///
/// Termination:
/// - the client half-closed or vanished — the probe read on `rd` completes (EOF,
///   an unexpected byte, or a read error); stop. Watching the read half is what
///   makes a dead subscriber detectable while the stream is *quiet*: with
///   collection paused, or a filter no event matches, no write ever happens, so
///   the write error below would never fire and the task would leak its receiver
///   and fd.
/// - [`broadcast::error::RecvError::Lagged`] — the subscriber fell behind; a
///   [`StreamFrame::Gap`] is written in band (always, filter or not) and the
///   stream continues.
/// - [`broadcast::error::RecvError::Closed`] — the bus is gone; stop.
/// - a write/flush error — the client disconnected; log and stop.
///
/// Cancellation: `broadcast::Receiver::recv` is cancel-safe, so a `recv` dropped
/// because the read branch won loses no event; `AsyncReadExt::read` is cancel-safe
/// too, so a lost race the other way reads nothing.
/// The shared state one subscription needs, grouped so the signature stays
/// readable: the bus it reads, the pause flag and the probing tier it reports,
/// and the cap plus its rate-limited refusal log.
struct StreamCtx<'a> {
    events_tx: &'a broadcast::Sender<EncodedFrame>,
    observing: &'a AtomicBool,
    probing: &'a ProbingState,
    subscribers: &'a Arc<AtomicUsize>,
    max_subscribers: usize,
    refusals: &'a RateLimitedLog,
}

async fn stream_events<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    rd: &mut R,
    wr: &mut W,
    kinds: Option<Vec<EventKind>>,
    cx: StreamCtx<'_>,
) -> std::io::Result<()> {
    let StreamCtx {
        events_tx,
        observing,
        probing,
        subscribers,
        max_subscribers,
        refusals,
    } = cx;
    // 1. Reserve a slot. Refused ⇒ ONE decodable error frame, then close.
    // The client always gets its error frame; only the LOG line is throttled, so
    // a peer looping on a full cap cannot grow a root daemon's log at its own rate.
    let Some(_slot) = CountedSlot::claim(subscribers, max_subscribers) else {
        if let Some(burst) = refusals.record(Instant::now()) {
            tracing::warn!(
                max = max_subscribers,
                suppressed = burst.suppressed,
                total = burst.total,
                "subscriber cap reached; refusing subscription"
            );
        }
        return write_stream_frame(
            wr,
            &StreamFrame::Error(StreamError {
                ts_us: types::now_us(),
                code: StreamErrorCode::TooManySubscribers,
                message: format!("subscriber limit reached ({max_subscribers} concurrent)"),
            }),
        )
        .await;
    };

    // 2. Receiver BEFORE the ack: the ack is the client's proof that this
    //    receiver exists, so nothing published after `subscribe()` returns can
    //    vanish into the old publish-before-subscribe window.
    let mut rx = events_tx.subscribe();

    // 3. The mandatory ack, carrying the CURRENT collection state and probing
    //    tier so a fresh subscriber learns them immediately instead of
    //    inferring them from silence (or from a run of SKIPs). Both are read
    //    AFTER subscribing, deliberately: an edge landing in between is then
    //    delivered twice (ack + bus frame) rather than lost, and duplication is
    //    free because the frame carries an absolute state.
    write_stream_frame(
        wr,
        &StreamFrame::Ready(Ready {
            ts_us: types::now_us(),
            kinds: kinds.clone(),
            observing: observing.load(Ordering::Acquire),
            probing: probing.tier(),
        }),
    )
    .await?;

    // A fixed one-byte probe. The read half exists only to notice a subscriber
    // that went away while the stream is quiet, and its content is never
    // inspected — so nothing a client sends can grow the daemon's memory.
    // `read_line` APPENDS, so any growable buffer here (however scoped) is an
    // unbounded-memory hole on a group-connectable socket. `AsyncReadExt::read`
    // is cancel-safe, so a lost race with `recv` reads nothing.
    let mut probe = [0u8; 1];
    loop {
        let recv = tokio::select! {
            recv = rx.recv() => recv,
            // Any completion — Ok(0) EOF, Ok(1) protocol violation, or Err —
            // means this subscriber is done. A `Subscribe` client sends nothing.
            _ = rd.read(&mut probe) => break,
        };
        match recv {
            Ok(frame) => {
                // The delivery rule lives in `net-observer-ipc`, not here: stream
                // frames that are not events are always delivered.
                if !frame.passes(kinds.as_deref()) {
                    continue;
                }
                // A write/flush error means the client is gone — log which and stop.
                if let Err(e) = wr.write_all(frame.bytes()).await {
                    tracing::debug!(error = %e, "subscriber write failed; ending stream");
                    break;
                }
                if let Err(e) = wr.flush().await {
                    tracing::debug!(error = %e, "subscriber flush failed; ending stream");
                    break;
                }
            }
            // The subscriber fell behind: tell it, in band, ALWAYS — a filtered
            // subscriber has more need to know its stream has a hole, not less.
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "event subscriber lagged; dropped old events");
                let gap = StreamFrame::Gap(Gap {
                    ts_us: types::now_us(),
                    skipped: n,
                });
                if write_stream_frame(wr, &gap).await.is_err() {
                    break;
                }
            }
            // The broadcast sender was dropped (daemon shutting down): end the stream.
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

/// The pieces [`control_request`] reads and mutates. Borrowed, so the focused
/// unit tests build one on the stack — no socket, no runtime, no DB file.
pub(crate) struct ControlCtx<'a> {
    pub policy: &'a ControlPolicy,
    pub acting: &'a ActingConfig,
    pub observing: &'a AtomicBool,
    pub probing: &'a ProbingState,
    pub freezer: &'a PcapRingSlot,
    /// The neighbour scanner, when one could be built for this host.
    pub scanner: Option<&'a dyn NeighborScanner>,
    /// The on-demand air scanner, when the platform has one.
    pub air_scanner: Option<&'a dyn AirScanner>,
    /// The on-demand topology scanner, when the platform has one.
    pub topology_scanner: Option<&'a dyn TopologyScanner>,
    /// The configured CVE snapshot directory, when one is set (see the field of
    /// the same name on the server). Checked for existence at scan time.
    pub scan_cve_snapshot: Option<&'a Path>,
    pub blob_dir: &'a Path,
    pub resume_at_us: &'a AtomicI64,
    /// `ts_us` of the edge that ENDED the observation session the next
    /// `resume_at_us` move re-opens. See the field of the same name on
    /// [`ApiServer`] (realm net-observer, node #124).
    pub session_end_us: &'a AtomicI64,
    pub snapshot: &'a Mutex<StatusSnapshot>,
    pub store: &'a (dyn Store + Send + Sync),
    pub events_tx: &'a broadcast::Sender<EncodedFrame>,
    /// The bounded log for the refusal line, so an unauthorised local process
    /// cannot grow a root daemon's log at its own loop rate.
    pub refusals: &'a RateLimitedLog,
    /// The owned handles `StartExperiment` gives its end task, and the
    /// registry it refuses a second window from (realm net-observer, node
    /// #61). Owned, not borrowed: the end task outlives the connection.
    pub experiment: ExperimentHandles,
}

impl ControlCtx<'_> {
    /// The tier switch's sinks, borrowed from the control context.
    fn tier_sinks(&self) -> TierSinks<'_> {
        TierSinks {
            probing: self.probing,
            snapshot: self.snapshot,
            resume_at_us: self.resume_at_us,
            session_end_us: self.session_end_us,
            store: self.store,
            events_tx: self.events_tx,
        }
    }
}

/// What a tier switch flips and the two sinks it writes — borrowed from a
/// [`ControlCtx`] on the control path, and from the owned
/// [`ExperimentHandles`] when an experiment window ends off it.
pub(crate) struct TierSinks<'a> {
    pub probing: &'a ProbingState,
    pub snapshot: &'a Mutex<StatusSnapshot>,
    pub resume_at_us: &'a AtomicI64,
    pub session_end_us: &'a AtomicI64,
    pub store: &'a (dyn Store + Send + Sync),
    pub events_tx: &'a broadcast::Sender<EncodedFrame>,
}

/// Whether a switch to the tier already in force still writes an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdgePolicy {
    /// No change, no edge: an operator's repeated `SetProbing` must not
    /// manufacture a boundary.
    OnChange,
    /// The edge is written regardless: an experiment window marks its bounds
    /// on an already-passive daemon too (realm net-observer, node #61).
    Always,
}

/// A tier switch that wrote an edge.
struct Switched {
    edge: ProbingEdge,
    /// The tier in force when the switch was decided, read under the same
    /// lock that flipped it — the one reading of "before" that cannot be
    /// stale.
    was: ProbingTier,
    /// The store-failure note for the operator's message; empty when the
    /// row landed.
    note: String,
}

/// The single entry point for `Request::Control`: authorise the peer FIRST, then
/// dispatch. Both `ControlCmd` arms are reachable only through here.
pub(crate) fn control_request(
    cmd: ControlCmd,
    peer_uid: Option<u32>,
    cx: &ControlCtx<'_>,
) -> ControlResult {
    match authorize_control(cx.policy, peer_uid) {
        Ok(authorized) => control_response(cmd, authorized, cx),
        Err(refusal) => {
            // Rate-limited: the socket is group-connectable by default (0660
            // root:staff), so an unauthorised process of the console user must
            // not be able to grow a ROOT daemon's log at its own loop rate.
            // Never silent — suppressed refusals are
            // counted and reported by the next line.
            if let Some(burst) = cx.refusals.record(Instant::now()) {
                tracing::warn!(
                    ?peer_uid,
                    ?cmd,
                    suppressed = burst.suppressed,
                    total = burst.total,
                    "control request refused: peer not authorised"
                );
            }
            refusal
        }
    }
}

/// Dispatch an ALREADY-AUTHORISED command. Private, and requires a
/// [`PeerAuthorized`], so "dispatch without a peer check" is unrepresentable.
///
/// No config gate sits here: the peer check in [`control_request`] is the one
/// gate on the control path, because config may switch off what the daemon does
/// by itself, never a command the operator sends by hand — the invocation is the
/// sanction (realm net-observer, node #91). What an arm can still refuse is a
/// contradiction of the daemon's own state (a scan while paused) or a missing
/// dependency (no ring, no scanner, no snapshot) — each with a reason.
fn control_response(
    cmd: ControlCmd,
    authorized: PeerAuthorized,
    cx: &ControlCtx<'_>,
) -> ControlResult {
    match cmd {
        ControlCmd::SetObserving(b) => {
            // Flag + snapshot mirror under one lock: the snapshot mutex is the
            // only thing serialising concurrent control connections and this is
            // the sole writer of both, so no interleaving can leave them
            // disagreeing. The resume epoch is published BEFORE the flag, so a
            // collector that sees `observing == true` has already synchronised
            // with it and no post-resume sample can reach the consumer while it
            // still reads the old epoch. No `.await` inside — the guard must not
            // be held across one, and no store write happens under it.
            //
            // `now_us()` and the bus publish are BOTH inside the guard, and must
            // stay there. Sampling the clock outside it lets two opposite-direction
            // toggles stamp in one order and take the mutex in the other, so the
            // rows read back (`ORDER BY ts_us`) claim the daemon is collecting
            // while it is in fact paused — with the gap invisible, which is the
            // one offline guarantee this boundary record exists to provide.
            // Publishing outside it lets a subscriber latch the opposite state for
            // the same reason. `send` is synchronous, so neither costs an `.await`.
            let transition = {
                let mut snap = cx.snapshot.lock().unwrap_or_else(|e| e.into_inner());
                let was = cx.observing.load(Ordering::Acquire);
                if was == b {
                    None
                } else {
                    let ts_us = types::now_us();
                    if b {
                        cx.resume_at_us.store(ts_us, Ordering::Release);
                    } else {
                        // The session ends HERE, at the pause: a pause moves no
                        // `resume_at_us` of its own (it produces no sample for
                        // `pipeline::run` to react to), so the LATER resume is
                        // what actually triggers the edge. Without this, that
                        // resume would close whatever incident the pre-pause
                        // session left open at the RESUME's `ts_us`, attributing
                        // the whole unobserved gap to it.
                        //
                        // `compare_exchange`, not a store: the FIRST unconsumed
                        // end wins. A tier switch accepted while still paused
                        // publishes no sample to consume this atomic either, so
                        // an unconditional store here would let THAT switch's
                        // later `ts_us` overwrite the pause's — closing inside
                        // the gap the pause itself opened. Losing the race is
                        // correct, so the `Result` is ignored (realm
                        // net-observer, node #124).
                        let _ = cx.session_end_us.compare_exchange(
                            0,
                            ts_us,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                    }
                    cx.observing.store(b, Ordering::Release);
                    snap.observing = b;

                    // ONE value, TWO sinks — built once so the DB row and the wire
                    // frame cannot drift, and stamped with one `ts_us`.
                    let edge = ObservingEdge {
                        ts_us,
                        observing: b,
                        peer_uid: Some(authorized.uid()),
                        // An operator asked for this one. The startup edge is
                        // the other producer, and it is written in `main`.
                        cause: ObservingCause::Control,
                    };

                    // Sink 2, realtime: the same value on the bus for held-open
                    // subscribers. Unconditional — the `receiver_count()` guard the
                    // sample path uses buys nothing for an operator-paced toggle.
                    match EncodedFrame::encode(&StreamFrame::Observing(edge)) {
                        Ok(frame) => {
                            let _ = cx.events_tx.send(frame);
                        }
                        Err(e) => tracing::warn!(error = %e, "failed to encode observing frame"),
                    }
                    Some(edge)
                }
            };
            let label = if b { "on" } else { "off" };
            let Some(edge) = transition else {
                // Not a transition: no boundary row, no bus frame. A no-op click
                // must not manufacture a gap in the record.
                tracing::info!(observing = b, changed = false, "observing state unchanged");
                return ControlResult {
                    ok: true,
                    message: format!("observing {label}"),
                };
            };
            let ts_us = edge.ts_us;

            // Sink 1, durable: the boundary that makes an operator pause
            // attributable offline. A store failure is logged as a gap (never
            // silently dropped) and reported in the message, but never fails the
            // control: the pause really did take effect, and reporting
            // `ok: false` would be a false statement about the daemon's state.
            let mut note = String::new();
            if let Err(e) = cx.store.write_observing_edge(&edge) {
                tracing::error!(error = %e, observing = b,
                    "store write failed; observing edge not recorded (gap logged)");
                note = format!(" (boundary record failed: {e})");
            }

            tracing::info!(
                observing = b,
                ts_us,
                peer_uid = authorized.uid(),
                "observing state changed via control socket"
            );
            ControlResult {
                ok: true,
                message: format!("observing {label}{note}"),
            }
        }
        ControlCmd::SetProbing(tier) => set_probing(tier, authorized, cx),
        ControlCmd::StartExperiment { minutes } => start_experiment(minutes, authorized, cx),
        ControlCmd::FreezePcap => freeze_now(cx),
        ControlCmd::ScanNeighbors(opts) => scan_now(cx, &opts, Some(authorized.uid())),
        ControlCmd::ScanAir => air_scan_now(cx, authorized.uid()),
        ControlCmd::ScanTopology => topology_scan_now(cx, authorized.uid()),
        ControlCmd::KickstartProxy => match acting::kickstart_proxy(&cx.acting.singbox_service) {
            Ok(message) => ControlResult { ok: true, message },
            Err(message) => ControlResult { ok: false, message },
        },
    }
}

/// Switch the probing tier on operator demand (realm net-observer, node #88):
/// [`switch_probing`] with the operator's uid, a `control` reason, and an
/// edge only on a real change.
///
/// A switch to the tier already in force is not an edge: no row, no frame,
/// still `ok` — the requested tier does hold. A store failure is logged as a
/// gap and reported in the message but never fails the control, because the
/// tier really did change and `ok: false` would say otherwise.
fn set_probing(
    tier: ProbingTier,
    authorized: PeerAuthorized,
    cx: &ControlCtx<'_>,
) -> ControlResult {
    // An operator's switch refuses nothing from inside the lock: `Ok` always,
    // so the `Err` arm cannot be reached and is written out rather than
    // unwrapped.
    let switched = match switch_probing(
        |_| Ok(tier),
        Some(authorized.uid()),
        ProbingReason::Control,
        EdgePolicy::OnChange,
        &cx.tier_sinks(),
    ) {
        Ok(Some(switched)) => switched,
        Ok(None) => {
            tracing::info!(probing = %tier, changed = false, "probing tier unchanged");
            return ControlResult {
                ok: true,
                message: format!("probing {tier}"),
            };
        }
        Err(message) => {
            return ControlResult { ok: false, message };
        }
    };
    tracing::info!(
        probing = %tier,
        ts_us = switched.edge.ts_us,
        peer_uid = authorized.uid(),
        "probing tier changed via control socket"
    );
    ControlResult {
        ok: true,
        message: format!("probing {tier}{}", switched.note),
    }
}

/// Switch the probing tier and bracket the switch (realm net-observer,
/// node #88).
///
/// Flip the shared state, mirror it into the snapshot — plus the two sinks
/// `SetObserving` uses, because a tier switch IS bracketed: one
/// `ProbingEdge` built once, written as a `probing_edge` row and published
/// as a `StreamFrame::Probing`. The state flip, the clock and the publish
/// sit under the snapshot lock for the reason `SetObserving` spells out: two
/// opposite switches must stamp and land in one order, or the rows read
/// back claim the daemon was probing while it was not. No `.await` and no
/// store write under the guard.
///
/// `target` names the tier to move into FROM the tier in force, decided
/// under the lock that flips it: an operator's switch ignores what it finds
/// (`|_| Ok(tier)`), an experiment window's close moves back only if what it
/// finds is still its own passive, and a window's OPENING refuses from in
/// here when collection is paused — the same lock `SetObserving` flips the
/// flag under, so a pause cannot land between the check and the edge. An
/// `Err` from `target` is that refusal: nothing is stamped, flipped or
/// written, and the message is the caller's to return. The tier found is
/// returned as [`Switched::was`] — the one reading of "before" that cannot
/// be stale.
///
/// `Ok(None)` when the tier was already in force and `policy` is
/// [`EdgePolicy::OnChange`]; under [`EdgePolicy::Always`] such a switch
/// still stamps and writes the edge (an experiment window's bracket, realm
/// net-observer, node #61) but flips nothing — no epoch moves, no session
/// ends, because nothing changed for the collectors or the triggers. A store
/// failure is logged as a gap and carried in the returned note; the switch
/// itself has already taken effect.
///
/// A real switch, in EITHER direction, closes and re-opens detection exactly
/// as a resume does: it publishes the same `resume_at_us` epoch the observing
/// resume publishes, and `pipeline::run` then clears the recent-sample window
/// (`RecentWindow::clear_for_resume`, gateway-change basis kept), re-arms every
/// trigger (`TriggerEngine::rearm_all`) and keeps the bounded pre-edge drain out
/// of the window; the interval collectors drop a tick that straddled the edge
/// at the source as well. Before either of those two steps, whatever incident
/// was open AT THE SWITCH already closed at the switch's own `ts_us`
/// (`TriggerEngine::close_all`, realm net-observer, node #124) — never at the
/// first post-switch sample's — and that trigger's firing budget closed with
/// it, so the cleared window makes the first post-edge sample judge
/// completely afresh: a fault still present (a `NoGw` gw-drop, a fakeip
/// hijack, both readable under passive) opens a NEW incident of the new
/// session AT ONCE, not once whatever backoff the closed incident had spent
/// happens to expire. The `probing_edge` row at the switch's own `ts_us` is
/// the bracket that names the instant. The probe-fed conditions do not read
/// the first passive `SKIP`s as a recovery, and after a switch back no dead
/// tick from before the stretch can join the ticks after it. Without
/// `close_all`, the switch to passive turned every probe-fed condition to
/// `None` at once and the engine closed open incidents as "recovered" at the
/// FIRST POST-SWITCH sample instead of at the switch itself.
fn switch_probing(
    target: impl FnOnce(ProbingTier) -> Result<ProbingTier, String>,
    peer_uid: Option<u32>,
    reason: ProbingReason,
    policy: EdgePolicy,
    s: &TierSinks<'_>,
) -> Result<Option<Switched>, String> {
    let (edge, was) = {
        let mut snap = s.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        // Read-then-set is safe: the snapshot lock serialises every control
        // connection and the experiment end task, and these are the tier's
        // only writers.
        let was = s.probing.tier();
        let tier = target(was)?;
        let changed = was != tier;
        if !changed && policy == EdgePolicy::OnChange {
            return Ok(None);
        }
        let ts_us = types::now_us();
        if changed {
            // The epoch is published BEFORE the tier flips, as on a resume: a
            // collector that reads the new tier has already synchronised with
            // it, so no sample taken under the new tier can reach the consumer
            // while it still reads the old epoch. The residual, named: a
            // control task preempted between these two stores for longer than
            // a collector's own epoch-read-to-tier-read gap lets ONE old-tier
            // tick, stamped with a post-edge `ts_us`, pass both of the
            // spawner's re-checks. Swapping the order would open the
            // consumer-side hole above instead. Accepted as bounded (one tick,
            // one switch) and left as is.
            //
            // `session_end_us` is written BEFORE `resume_at_us`, same
            // reasoning: the consumer that observes the epoch move must
            // already see the session's end. `compare_exchange`, not a store:
            // the FIRST unconsumed end wins, so a switch accepted while the
            // daemon is PAUSED (no sample flows to consume this atomic before
            // the later resume) cannot push the close point forward past a
            // pause that already opened the gap. Losing the race is correct
            // for this later writer, so the `Result` is ignored (realm
            // net-observer, node #124).
            let _ =
                s.session_end_us
                    .compare_exchange(0, ts_us, Ordering::AcqRel, Ordering::Acquire);
            s.resume_at_us.store(ts_us, Ordering::Release);
            s.probing.set(tier);
            snap.probing = tier;
        }
        let edge = ProbingEdge {
            ts_us,
            tier,
            peer_uid,
            reason,
        };
        match EncodedFrame::encode(&StreamFrame::Probing(edge)) {
            Ok(frame) => {
                let _ = s.events_tx.send(frame);
            }
            Err(e) => tracing::warn!(error = %e, "failed to encode probing frame"),
        }
        (edge, was)
    };

    let mut note = String::new();
    if let Err(e) = s.store.write_probing_edge(&edge) {
        tracing::error!(error = %e, probing = %edge.tier, reason = reason.as_str(),
            "store write failed; probing edge not recorded (gap logged)");
        note = format!(" (boundary record failed: {e})");
    }
    Ok(Some(Switched { edge, was, note }))
}

/// Go and look for neighbours on operator demand.
///
/// Everything the scan learns is written through the same two sinks the passive
/// collector uses — a `Sample::Neighbors` (which upserts the entities and
/// publishes the live event) plus one `neighbor_scan` row per method — so a
/// device found by a sweep is the same row as one seen passively, distinguished
/// only by its `source`. A store failure is logged and reported in the message
/// but does not fail the command: the packets really did go out, and saying
/// otherwise would be a false statement about what this daemon did.
fn scan_now(cx: &ControlCtx<'_>, requested: &ScanOptions, peer_uid: Option<u32>) -> ControlResult {
    // One refusal BEFORE anything is sent: a scan is the one command that
    // contradicts a paused daemon outright.
    //
    // Paused: the pause is bracketed silence — `observing_edge` says the daemon
    // deliberately collected nothing between two instants. A scan would drop
    // rows and publish an event with a timestamp inside that bracket, so the gap
    // record and the data would disagree about the same seconds.
    //
    // The passive probing tier is deliberately NOT a second refusal. Passive
    // promises no emission the daemon makes on its own; an operator's scan is
    // not the daemon's — the command is the sanction (realm net-observer, node
    // #91) — and the scan writes its own `neighbor_scan` row, so the record
    // shows exactly what was sent inside the passive stretch. (node #88)
    if !cx.observing.load(Ordering::Acquire) {
        return ControlResult {
            ok: false,
            message: "observation is paused; resume before scanning".to_string(),
        };
    }
    // Part A boundary decision (realm net-observer, node #154, owner
    // decision node #156): an off-subnet target is ALLOWED, not refused —
    // the operator named the address and owns the responsibility for it; the
    // socket is IP_BOUND_IF-pinned to the physical interface regardless.
    // Only a category that can never be a real neighbour on ANY segment is
    // refused: loopback, multicast, the unspecified address, or (IPv4) the
    // limited-broadcast address. `is_loopback`/`is_multicast`/`is_unspecified`
    // already dispatch correctly for an IPv6 target (no separate IPv6 branch
    // needed); limited broadcast is IPv4-only by definition, hence the extra
    // check. A genuine sing-box fakeip/TUN address is deliberately NOT
    // filtered here — telling it apart from an ordinary off-subnet host
    // would need a live read of the rendered sing-box config, which moves
    // independently of this build (its fakeip pool "has moved four times",
    // per `macos::clash`); pinned to the physical interface, a stray fakeip
    // target simply probes and finds nothing, the same honest outcome as any
    // other unreachable address.
    if let Some(ip) = requested.target
        && (ip.is_loopback()
            || ip.is_multicast()
            || ip.is_unspecified()
            || matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast()))
    {
        return ControlResult {
            ok: false,
            message: format!(
                "{ip} is not a scannable host (loopback, multicast, unspecified, or broadcast)"
            ),
        };
    }
    let Some(scanner) = cx.scanner else {
        return ControlResult {
            ok: false,
            message: "neighbour scanning not available".to_string(),
        };
    };
    // Every requested rung runs — no config permission sits between the
    // operator's request and the scanner (realm net-observer, node #91). What
    // can still drop a rung is a DEPENDENCY it cannot do without, and then the
    // operator is told — never silently, never by running it anyway.
    let ports = requested.ports;
    // A banner grab needs an open port to read from, so it is effective only
    // when the `ports` rung itself is effective.
    let banners = requested.banners && ports;
    // The snapshot is available only when a directory is configured AND present:
    // a path removed after boot is honestly reported as dropped, never faked.
    let snapshot_available = cx.scan_cve_snapshot.is_some_and(|p| p.is_dir());
    // The `cve` rung matches banners against the snapshot: effective only when
    // the `banners` rung is itself effective (a match parses a banner) AND a
    // snapshot is present to match against.
    let cve = requested.cve && banners && snapshot_available;
    // `target`/`slow`/`sweep_max` gate on no other rung — they pass through
    // untouched, unlike ports/banners/cve above (realm net-observer, node
    // #154).
    let effective = ScanOptions {
        ports,
        banners,
        cve,
        target: requested.target,
        slow: requested.slow,
        sweep_max: requested.sweep_max,
    };
    let mut dropped = Vec::new();
    if requested.banners && !banners {
        // Say WHY it was dropped: no effective port scan to grab from.
        dropped.push("banners (needs the ports rung, which is not effective this run)".to_string());
    }
    if requested.cve && !cve {
        // Say WHY, in the order the rung depends on things: an effective banner
        // grab to parse, then a provisioned snapshot to match against. Each is
        // an honest refusal, never a silent skip.
        let why = if !banners {
            "needs the banners rung, which is not effective this run"
        } else {
            "no CVE snapshot; set collectors.neighbors.cve_snapshot_dir to a provisioned directory"
        };
        dropped.push(format!("cve ({why})"));
    }
    let Some(report) = scanner.scan(&effective) else {
        return ControlResult {
            ok: false,
            message: "no interface with an IPv4 subnet to scan".to_string(),
        };
    };

    let mut note = String::new();
    for row in &report.scans {
        if let Err(e) = cx.store.write_neighbor_scan(row) {
            tracing::error!(error = %e, method = %row.method,
                "store write failed; scan row not recorded (gap logged)");
            note = format!(" (scan record failed: {e})");
        }
    }
    for port in &report.ports {
        if let Err(e) = cx.store.write_neighbor_port(port) {
            tracing::error!(error = %e, port = port.port,
                "store write failed; port row not recorded (gap logged)");
            note = format!(" (port record failed: {e})");
        }
    }
    for vuln in &report.vulns {
        if let Err(e) = cx.store.write_neighbor_vuln(vuln) {
            tracing::error!(error = %e, cve = %vuln.cve_id,
                "store write failed; vuln row not recorded (gap logged)");
            note = format!(" (vuln record failed: {e})");
        }
    }
    if !dropped.is_empty() {
        note = format!("{note} [dropped: {}]", dropped.join(", "));
    }
    // The cve rung ran but its snapshot was unusable: say so, so the operator
    // never reads an empty vuln result as a clean "no vulnerabilities found".
    if let Some(cve_note) = &report.cve_note {
        note = format!("{note} [cve: {cve_note}]");
    }

    let sample = Sample::Neighbors(NeighborsSample {
        ts_us: report.ts_us,
        verdict: NeighborsVerdict::Ok,
        reason: None,
        network_key: report.network_key.clone(),
        iface: report.iface.clone(),
        neighbors: report.found.clone(),
        services: Vec::new(),
        heard: None,
    });
    if let Err(e) = cx.store.write_sample(&sample) {
        tracing::error!(error = %e, "store write failed; scan findings not recorded (gap logged)");
        note = format!("{note} (findings not recorded: {e})");
    }
    let Sample::Neighbors(scanned) = &sample else {
        unreachable!("just constructed as Neighbors")
    };
    // Read the record's since-when for what the scan found, BEFORE taking the
    // snapshot lock — the socket path waits on that mutex and a DB read must not
    // happen under it. (realm net-observer, node #43)
    let lifetimes = crate::pipeline::neighbor_lifetimes_for(cx.store, scanned);
    {
        let mut snap = cx.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        snap.generated_us = report.ts_us;
        snap.neighbors = Some(scanned.clone());
        snap.neighbor_lifetimes = lifetimes;
    }
    if cx.events_tx.receiver_count() > 0 {
        let Sample::Neighbors(n) = &sample else {
            unreachable!("just constructed as Neighbors")
        };
        match EncodedFrame::encode(&StreamFrame::Event(Event::Neighbors(n.clone()))) {
            Ok(frame) => {
                let _ = cx.events_tx.send(frame);
            }
            Err(e) => tracing::warn!(error = %e, "failed to encode scan event; not published"),
        }
    }

    tracing::info!(
        found = report.found.len(),
        methods = report.scans.len(),
        ?peer_uid,
        "neighbour scan run via control socket"
    );
    ControlResult {
        ok: true,
        message: format!("{}{note}", report.message),
    }
}

/// Read the radio environment once on operator demand.
///
/// The daemon asks the OS for its own radio's report and puts nothing on the
/// air (realm net-observer, node #47).
///
/// A PAUSE still refuses, for the reason it refuses a neighbour scan: the pause
/// is bracketed silence, and a sample stamped inside that bracket would make the
/// `observing_edge` row and the data disagree about the same seconds.
///
/// Returns as soon as the scan is accepted. Its product is an ordinary
/// `Sample::Air` on the pipeline — persisted, published, `Skip` with a reason if
/// the radio could not be read.
fn air_scan_now(cx: &ControlCtx<'_>, peer_uid: u32) -> ControlResult {
    if !cx.observing.load(Ordering::Acquire) {
        return ControlResult {
            ok: false,
            message: "observation is paused; resume before scanning the air".to_string(),
        };
    }
    let Some(scanner) = cx.air_scanner else {
        return ControlResult {
            ok: false,
            message: "air scanning not available on this host".to_string(),
        };
    };
    let (ok, message) = match scanner.request_scan() {
        AirScanRequest::Started => (
            true,
            "air scan started; the slice will arrive as an air event".to_string(),
        ),
        AirScanRequest::AlreadyRunning => (
            false,
            "an air scan is already running; one press, one scan".to_string(),
        ),
        AirScanRequest::TooSoon { retry_in_s } => (
            false,
            format!("an air scan ran moments ago; try again in {retry_in_s}s"),
        ),
    };
    tracing::info!(ok, peer_uid, %message, "air scan requested via control socket");
    ControlResult { ok, message }
}

/// Force one LLDP/CDP topology capture now, instead of waiting for the next
/// slow patrol tick (`TOPOLOGY_PATROL_INTERVAL`, a 65s capture every 5
/// minutes).
///
/// Mirrors [`air_scan_now`]'s self-control shape, with one difference: the
/// round-trip is SYNCHRONOUS. The capture's own budget (~65s) fits well
/// inside the CLI's `SCAN_TIMEOUT` (180s), so the operator is answered with
/// the real uplink count rather than an "accepted" ack — there is no useful
/// "started" state to report separately for a capture this short. Zero links
/// is reported `ok: true`: absence is the honest SKIP-never-silence answer on
/// a segment with no managed switch or enterprise AP, never a failure.
///
/// A PAUSE still refuses, for the same reason a neighbour/air scan does: the
/// pause is bracketed silence and a link stamped inside that bracket would
/// make the `observing_edge` row and the data disagree about the same
/// seconds.
fn topology_scan_now(cx: &ControlCtx<'_>, peer_uid: u32) -> ControlResult {
    if !cx.observing.load(Ordering::Acquire) {
        return ControlResult {
            ok: false,
            message: "observation is paused; resume before scanning topology".to_string(),
        };
    }
    let Some(scanner) = cx.topology_scanner else {
        return ControlResult {
            ok: false,
            message: "topology scanning not available on this host".to_string(),
        };
    };
    let links = scanner.scan();
    let message = if links.is_empty() {
        "no LLDP/CDP frames seen — only managed switches and enterprise APs advertise these; a \
         consumer Wi-Fi network has none"
            .to_string()
    } else {
        format!("found {} uplink(s) via LLDP/CDP", links.len())
    };
    tracing::info!(
        found = links.len(),
        peer_uid,
        %message,
        "topology scan requested via control socket"
    );
    ControlResult { ok: true, message }
}

/// Copy the pcap ring out on operator demand, into a timestamped freeze
/// directory beside the trigger-driven ones.
///
/// A ring that is not running is a REFUSAL with a reason, never a silent no-op:
/// the operator asked for an artifact and must learn that none exists. A ring
/// that yields no file is also a failure — the command's whole product is the
/// copied files — and both cases say so in the message.
fn freeze_now(cx: &ControlCtx<'_>) -> ControlResult {
    let ts_us = types::now_us();
    let dest = cx.blob_dir.join(format!("freeze-manual-{ts_us}"));
    match freeze_ring(cx.freezer, &dest) {
        Ok(paths) => {
            tracing::info!(dest = %dest.display(), frozen = paths.len(),
                "froze pcap ring on operator request");
            ControlResult {
                ok: true,
                message: format!("froze {} pcap file(s) into {}", paths.len(), dest.display()),
            }
        }
        Err(message) => {
            tracing::warn!(dest = %dest.display(), %message, "manual pcap freeze copied nothing");
            ControlResult { ok: false, message }
        }
    }
}

/// Copy the ring that is running NOW into `dest`, or say why nothing was
/// copied: no ring is running, or the ring yielded no file. Shared by the
/// operator's `FreezePcap` and the experiment window's two freezes, so a
/// missing ring is worded the same wherever it is met.
fn freeze_ring(freezer: &PcapRingSlot, dest: &Path) -> Result<Vec<PathBuf>, String> {
    let Some(ring) = freezer.get() else {
        return Err("pcap ring not running".to_string());
    };
    let paths = ring.freeze(dest);
    if paths.is_empty() {
        return Err(format!("pcap ring froze no files into {}", dest.display()));
    }
    Ok(paths)
}

/// Open an experiment window on operator demand (realm net-observer, node
/// #61): go passive, freeze the ring, and hand the window to a task that
/// closes it after `minutes`.
///
/// Refused for a length outside `1..=EXPERIMENT_MAX_MINUTES` and while
/// another window runs — one window at a time, because two would share one
/// tier and one ring. The opening edge is written under
/// [`EdgePolicy::Always`], so an already-passive daemon still marks where the
/// window began; its `ts_us` is the window's start and names the id. The
/// registry lock is held across the switch so a second `StartExperiment`
/// racing this one meets the running entry, never a second edge. The start
/// freeze may fail (no ring): the window still runs — the record's half of
/// the report needs no ring — and the message and the report say so.
///
/// Answers at once with the id; the report is read later with
/// `Query(Experiment { id })`. Nothing here awaits: the sleep lives in the
/// spawned task, on the daemon's runtime, which is why this arm must run on
/// it (`handle_conn` does; a bare unit test must build one).
fn start_experiment(
    minutes: u32,
    authorized: PeerAuthorized,
    cx: &ControlCtx<'_>,
) -> ControlResult {
    if minutes == 0 || minutes > EXPERIMENT_MAX_MINUTES {
        return ControlResult {
            ok: false,
            message: format!(
                "experiment length must be 1..={EXPERIMENT_MAX_MINUTES} minutes, not {minutes}"
            ),
        };
    }
    let h = &cx.experiment;
    let peer_uid = authorized.uid();
    let (id, start_us, ends_at_us, tier_before, start_note) = {
        let mut map = h.experiments.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((running, ExperimentState::Running { ends_at_us })) = map
            .iter()
            .find(|(_, s)| matches!(s, ExperimentState::Running { .. }))
        {
            return ControlResult {
                ok: false,
                message: experiment_running_message(running, *ends_at_us),
            };
        }
        // Paused: the pause is bracketed silence — `observing_edge` says the
        // daemon deliberately collected nothing between two instants — and a
        // window measured inside it would read its zeros against no record
        // at all. Refused for the reason a scan is (`scan_now`), and read
        // INSIDE the switch's lock: `SetObserving` flips the flag under that
        // same lock, so a pause cannot slip between this check and the
        // opening edge and write its row just before `start_us`.
        let observing = cx.observing;
        let switched = match switch_probing(
            |_| {
                if observing.load(Ordering::Acquire) {
                    Ok(ProbingTier::Passive)
                } else {
                    Err("observation is paused; resume before starting an experiment".to_string())
                }
            },
            Some(peer_uid),
            ProbingReason::Experiment,
            EdgePolicy::Always,
            &h.tier_sinks(),
        ) {
            Ok(Some(switched)) => switched,
            Err(message) => {
                return ControlResult { ok: false, message };
            }
            // Unreachable under `Always`; said rather than unwrapped.
            Ok(None) => {
                return ControlResult {
                    ok: false,
                    message: "experiment could not open: no opening edge".to_string(),
                };
            }
        };
        // The tier in force before the window is the one the switch found
        // under its lock — never a separate read that a racing control
        // could sit between.
        let tier_before = switched.was;
        let start_us = switched.edge.ts_us;
        let id = experiment_id(start_us);
        let ends_at_us = start_us + i64::from(minutes) * 60_000_000;
        map.insert(id.clone(), ExperimentState::Running { ends_at_us });
        (id, start_us, ends_at_us, tier_before, switched.note)
    };

    let start_dir = h
        .blob_dir
        .join(format!("freeze-experiment-{start_us}-start"));
    let start_freeze = freeze_ring(&h.freezer, &start_dir);
    let freeze_note = match &start_freeze {
        Ok(paths) => {
            record_freeze_blobs(h.store.as_ref(), &id, "start", start_us, paths);
            format!("froze {} pcap file(s) at the start", paths.len())
        }
        Err(why) => format!("start freeze: {why}"),
    };

    tracing::info!(
        %id, minutes, start_us, ends_at_us, tier_before = %tier_before, peer_uid,
        %freeze_note, "experiment window opened via control socket"
    );

    let handles = h.clone();
    let task_id = id.clone();
    let start_freeze = start_freeze.ok().map(|paths| (start_dir, paths));
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(u64::from(minutes) * 60)).await;
        finish_experiment(
            handles,
            task_id,
            ExperimentOpen {
                start_us,
                requested_minutes: minutes,
                tier_before,
                peer_uid,
                start_freeze,
            },
        )
        .await;
    });

    ControlResult {
        ok: true,
        message: format!(
            "experiment {id} started: passive for {minutes} min (was {tier_before}); {freeze_note}{start_note}"
        ),
    }
}

/// What `start_experiment` hands its end task: the window as it opened.
struct ExperimentOpen {
    /// The opening edge's `ts_us`.
    start_us: i64,
    /// The length the operator asked for.
    requested_minutes: u32,
    /// The tier the opening switch found in force, under its lock.
    tier_before: ProbingTier,
    /// The operator who opened the window; both edges carry it.
    peer_uid: u32,
    /// The start freeze's directory and copied files, when it copied any.
    start_freeze: Option<(PathBuf, Vec<PathBuf>)>,
}

/// One `blob_ref` row per copied ring file, against the window's id — the
/// shape the incident freeze writes (`pipeline::FreezePcapHandler`), so the
/// record refers to the slice the report was read from. A write that fails
/// is logged as a gap; the files are on disk either way.
fn record_freeze_blobs(store: &dyn Store, id: &str, which: &str, ts_us: i64, paths: &[PathBuf]) {
    for (i, path) in paths.iter().enumerate() {
        let blob = types::BlobRef {
            id: format!("{id}-pcap-{which}-{i}"),
            incident_id: id.to_string(),
            ts_us,
            kind: "pcap".into(),
            path: path.display().to_string(),
        };
        if let Err(e) = store.write_blob_ref(&blob) {
            tracing::warn!(%id, which, error = %e, "failed to write experiment pcap blob_ref");
        }
    }
}

/// Close an experiment window (realm net-observer, node #61): freeze the ring
/// again, read the boundary rows the window holds, restore the tier that was
/// in force — only if it is still the window's own to restore — count what
/// the two freezes and the record hold, and keep the report in memory and in
/// the `experiment` table.
///
/// The end instant is the wall clock, taken BEFORE the end freeze so the
/// slice holds no frame from after the window; against the requested length
/// it is what says the machine slept. The boundary rows are read next:
/// every `observing_edge` and `probing_edge` inside the window, so the
/// report names each, and so the closing edge knows whether an operator
/// moved the tier meanwhile. The closing edge then restores `tier_before`
/// only when the tier it finds is still the passive the window set AND no
/// operator edge landed inside the window — otherwise the operator's choice
/// stands, the edge (reason `experiment-end`, written under
/// [`EdgePolicy::Always`]) merely marks the end, and the report says which.
/// This machine's own MAC is read ONCE here, from the newest link sample the
/// snapshot holds — the same value the link collector read on its last tick,
/// which the passive tier keeps reading. The pcap walk and the store's
/// counts run on the blocking pool. Nothing here fails the window: every
/// count that could not be taken is a note in the report, never a zero and
/// never a missing report.
async fn finish_experiment(h: ExperimentHandles, id: String, open: ExperimentOpen) {
    let ExperimentOpen {
        start_us,
        requested_minutes,
        tier_before,
        peer_uid,
        start_freeze,
    } = open;
    let end_us = types::now_us();
    let end_dir = h.blob_dir.join(format!("freeze-experiment-{start_us}-end"));
    let end_freeze = freeze_ring(&h.freezer, &end_dir);
    let mut notes = Vec::new();
    let end_paths = match end_freeze {
        Ok(paths) => {
            record_freeze_blobs(h.store.as_ref(), &id, "end", end_us, &paths);
            Some(paths)
        }
        Err(why) => {
            notes.push(format!("end freeze: {why}"));
            None
        }
    };

    // The boundary rows inside the window, read before the closing edge is
    // written so that edge is not among them.
    let edge_store = Arc::clone(&h.store);
    let edges = tokio::task::spawn_blocking(move || {
        store::experiment::window_edges(edge_store.as_ref(), start_us, end_us, QUERY_DEADLINE)
            .map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("edge read task failed: {e}")));
    let (edges, edges_read) = match edges {
        Ok(edges) => (edges, true),
        Err(why) => {
            notes.push(format!("boundary rows: {why}"));
            (types::WindowEdges::default(), false)
        }
    };
    let operator_moved_at = edges.operator_probing().next().map(|e| e.ts_us);

    // The closing edge: back to `tier_before` only if the tier is still the
    // window's own passive and nobody moved it meanwhile — a window whose
    // rows could not be read cannot vouch for that, so it keeps its hands
    // off too. Decided under the switch's own lock, from the tier it finds.
    let may_restore = operator_moved_at.is_none() && edges_read;
    // The closing edge refuses nothing: `Ok` always, so `Err` is unreachable
    // and folded into the "no closing edge" arm below rather than unwrapped.
    let closing = switch_probing(
        |was| {
            Ok(if was == ProbingTier::Passive && may_restore {
                tier_before
            } else {
                was
            })
        },
        Some(peer_uid),
        ProbingReason::ExperimentEnd,
        EdgePolicy::Always,
        &h.tier_sinks(),
    );
    let (tier_at_end, restore) = match closing {
        Ok(Some(Switched { edge, was, note })) => {
            if !note.is_empty() {
                notes.push(format!("closing edge{note}"));
            }
            // The operator's switch is named first: it is the usual way the
            // tier stops being the window's passive, and the instant is what
            // the operator will look for.
            let restore = if let Some(at_us) = operator_moved_at {
                types::TierRestore::OperatorMoved { at_us }
            } else if was != ProbingTier::Passive {
                types::TierRestore::NotPassive { found: was }
            } else if !edges_read {
                types::TierRestore::Unverified {
                    why: "the window's boundary rows could not be read".into(),
                }
            } else {
                types::TierRestore::Restored
            };
            (edge.tier, restore)
        }
        // Unreachable under `Always` with an `Ok` target; recorded rather
        // than unwrapped.
        Ok(None) | Err(_) => {
            notes.push("closing edge: none written".into());
            (
                h.probing.tier(),
                types::TierRestore::Unverified {
                    why: "no closing edge".into(),
                },
            )
        }
    };

    let own_mac = h
        .snapshot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .link
        .as_ref()
        .and_then(|l| l.if_mac.clone());
    if start_freeze.is_none() {
        notes.push("start freeze: none taken".to_string());
    }
    let (freeze_start_dir, start_paths) = match start_freeze {
        Some((dir, paths)) => (Some(dir.display().to_string()), Some(paths)),
        None => (None, None),
    };
    let freeze_end_dir = end_paths.as_ref().map(|_| end_dir.display().to_string());

    let record_store = Arc::clone(&h.store);
    let mac_for_count = own_mac.clone();
    let counted = tokio::task::spawn_blocking(move || {
        // The failure crosses the pool as words: the report carries them as a
        // note, and nothing downstream matches on the store's error type.
        let network = store::experiment::window_facts(
            record_store.as_ref(),
            start_us,
            end_us,
            QUERY_DEADLINE,
        )
        .map_err(|e| e.to_string());
        let start_frames = start_paths
            .as_deref()
            .map(|paths| count_slice(paths, mac_for_count.as_deref(), start_us, end_us));
        let end_frames = end_paths
            .as_deref()
            .map(|paths| count_slice(paths, mac_for_count.as_deref(), start_us, end_us));
        (network, start_frames, end_frames)
    })
    .await;

    let (network, frames_pcap_start, our_frames, frames_pcap_end) = match counted {
        Ok((network, start_frames, end_frames)) => {
            let network = match network {
                Ok(n) => Some(n),
                Err(e) => {
                    notes.push(format!("record: {e}"));
                    None
                }
            };
            let frames_pcap_start = match start_frames {
                Some(Ok(f)) => Some(f.records),
                Some(Err(why)) => {
                    notes.push(format!("start slice: {why}"));
                    None
                }
                None => None,
            };
            let (our_frames, frames_pcap_end) = match end_frames {
                Some(Ok(f)) => (own_mac.as_ref().map(|_| f), Some(f.records)),
                Some(Err(why)) => {
                    notes.push(format!("end slice: {why}"));
                    (None, None)
                }
                None => (None, None),
            };
            (network, frames_pcap_start, our_frames, frames_pcap_end)
        }
        Err(e) => {
            notes.push(format!("counting task failed: {e}"));
            (None, None, None, None)
        }
    };
    if own_mac.is_none() {
        notes.push("own MAC unreadable from the newest link sample".to_string());
    }

    let report = ExperimentReport {
        id: id.clone(),
        window: ExperimentWindow {
            start_us,
            end_us,
            requested_minutes,
            link_interval_us: i64::try_from(h.link_interval.as_micros()).unwrap_or(i64::MAX),
            tier_before,
            tier_at_end,
            restore,
            freeze_start_dir: freeze_start_dir.clone(),
            freeze_end_dir: freeze_end_dir.clone(),
            frames_pcap_start,
            frames_pcap_end,
        },
        ring_filter: h.ring_filter.clone(),
        own_mac,
        our_frames,
        network,
        edges,
        notes,
    };
    tracing::info!(%id, verdict = %report.verdict(), "experiment window closed");

    match experiment_report_json(&report) {
        Ok(report_json) => {
            let record = store::ExperimentRecord {
                id: id.clone(),
                start_us,
                end_us,
                tier_before,
                freeze_start_dir,
                freeze_end_dir,
                report_json,
            };
            if let Err(e) = h.store.write_experiment(&record) {
                tracing::error!(error = %e, %id,
                    "store write failed; experiment report not recorded (gap logged)");
            }
        }
        Err(e) => tracing::error!(error = %e, %id, "experiment report could not be serialised"),
    }
    h.experiments
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, ExperimentState::Finished(Box::new(report)));
}

/// Walk every ring file of one freeze and fold the counts. The MAC is
/// `None` when it could not be read: the slice is still walked for its
/// record count and bounds against an address no device carries, so no
/// bucket fills and the caller reports them as not counted. A MAC that is
/// present but not six octets is an error, not a zero count: a zero against
/// the wrong address would read as silence. A file that is not pcap, or
/// cannot be opened, fails the whole slice by name.
fn count_slice(
    paths: &[PathBuf],
    own_mac: Option<&str>,
    start_us: i64,
    end_us: i64,
) -> Result<OwnFrames, String> {
    let mac = match own_mac {
        None => [0u8; 6],
        Some(text) => collector_announce::mac_octets(text)
            .ok_or_else(|| format!("own MAC {text:?} is not six octets"))?,
    };
    let mut total = OwnFrames::default();
    for path in paths {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let counted = collector_announce::count_own_frames(
            std::io::BufReader::new(file),
            &mac,
            start_us,
            end_us,
        )
        .map_err(|e| format!("{}: {e}", path.display()))?;
        total.absorb(&counted);
    }
    Ok(total)
}

/// Clone the live snapshot, recovering the lock if a previous holder panicked.
fn snapshot_clone(snapshot: &Mutex<StatusSnapshot>) -> StatusSnapshot {
    snapshot.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::ScanReport;
    use net_observer_ipc::{DiagnosticQuery, Event, IncidentSummary, QueryOutcome};
    use types::{GwVerdict, HostSample, LinkSample, RouteEvent, TcpVerdict};

    /// The uid the tests' policies claim as the daemon's own — an arbitrary value
    /// no real account on a dev machine or CI runner holds, so an authorised test
    /// peer is authorised by the `daemon_uid` clause and nothing else.
    const TEST_DAEMON_UID: u32 = 4242;

    /// A uid no real account holds, so no policy clause can authorise a test peer
    /// by accident.
    const NOT_A_REAL_UID: u32 = u32::MAX - 1;

    /// The test process's own effective uid — the uid a client connecting from
    /// THIS process presents to `getpeereid(2)`, and therefore the uid the daemon
    /// must act on.
    fn own_uid() -> u32 {
        // SAFETY: `geteuid` takes no arguments, dereferences nothing and cannot
        // fail (POSIX: "always successful").
        unsafe { libc::geteuid() }
    }

    /// A console lookup pinned to "no console session". EVERY test policy uses it:
    /// no test may depend on whether the machine it runs on has a logged-in GUI
    /// user, and the end-to-end refusal arm is impossible without it (on a
    /// developer's Mac the test process IS the console user).
    fn no_console() -> Option<u32> {
        None
    }

    /// A uid the peer-lookup seam injects: not this process's, not root's, and
    /// not the console user's (every test policy pins the console clause to "no
    /// session"), so ONLY `control_uids` can authorise it. Distinct from
    /// [`NOT_A_REAL_UID`], which the same tests use as the daemon's own uid.
    const FOREIGN_UID: u32 = u32::MAX - 2;

    /// The injected stand-in for a second local account, which a single-process
    /// test cannot otherwise have. A plain `fn` item, not a closure, so it matches
    /// the seam's function-pointer type.
    fn foreign_peer(_: &UnixStream) -> Option<u32> {
        Some(FOREIGN_UID)
    }

    /// Events big enough that "one line per interval" and "one line per event"
    /// give different numbers, small enough to stay obvious. The whole burst lands
    /// inside one [`REFUSAL_LOG_INTERVAL`].
    const REFUSAL_BURST: usize = 5;

    /// Messages captured from a scoped `tracing` subscriber.
    ///
    /// The rate-limited logs exist to bound VOLUME, and volume is observable only
    /// at a subscriber: no assertion on `record()`'s return value can tell
    /// `if let Some(b) = lim.record(..) { warn!(..) }` from a `warn!` that ignores
    /// the `Option`. Not a general logging harness — it keeps the `message` field
    /// and nothing else, because the socket server also emits an `info` listening
    /// line and `debug` connection errors on the same thread and a count that
    /// swept those up would be a proxy for the property rather than the property.
    #[derive(Clone, Default)]
    struct EventLog(Arc<Mutex<Vec<String>>>);

    impl EventLog {
        fn push(&self, message: String) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(message);
        }
        /// How many captured messages contain `needle`.
        fn count(&self, needle: &str) -> usize {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|m| m.contains(needle))
                .count()
        }
        /// Everything captured, for a failure message that names what DID arrive.
        fn messages(&self) -> Vec<String> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    /// A minimal `tracing::Subscriber` that records event messages into an
    /// [`EventLog`] and does nothing else. Installed per test with
    /// `tracing::subscriber::with_default` (sync) or `set_default` (async) — both
    /// THREAD-LOCAL, so parallel tests cannot see each other's events and nothing
    /// survives the guard. Spans are unused (the daemon logs bare events), so the
    /// span half of the trait is the minimum that compiles. No new dependency:
    /// `tracing` is already a direct dependency of this binary.
    struct CountingSubscriber(EventLog);

    impl tracing::Subscriber for CountingSubscriber {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor(None);
            event.record(&mut visitor);
            if let Some(message) = visitor.0 {
                self.0.push(message);
            }
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Pulls just the `message` field out of an event. `record_debug` is `Visit`'s
    /// only required method and every other `record_*` defaults to it, so this is
    /// complete: a macro message literal arrives as `fmt::Arguments`, whose Debug
    /// forwards to Display, so the captured string is the message text.
    struct MessageVisitor(Option<String>);

    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = Some(format!("{value:?}"));
            }
        }
    }

    fn test_acting() -> ActingConfig {
        ActingConfig {
            // A sentinel no launchd holds: with no config gate, an authorised
            // `KickstartProxy` in a test would otherwise `launchctl kickstart -k`
            // the REAL sing-box on a developer's Mac.
            singbox_service: "system/net-observer-test-sentinel".into(),
        }
    }

    /// A server wired for tests: an in-memory DuckDB, a small bus, fresh atomics,
    /// and a [`ControlPolicy`] with an EXPLICIT `daemon_uid` — never
    /// [`ControlPolicy::from_config`], so no syscall runs and no test depends on
    /// the uid it happens to be running as. The fields are public, so a test
    /// reads `events_tx` / `snapshot` / `observing` / `store` back off the value.
    fn test_server(socket_path: &str, acting: ActingConfig, daemon_uid: u32) -> ApiServer {
        // The extra receiver is dropped immediately: the subscription tests
        // assert on `receiver_count()`, which must count only the server's own.
        let (events_tx, _rx) = broadcast::channel(16);
        ApiServer {
            socket_path: socket_path.to_string(),
            // The shipped default; the client is this same process, so the
            // owner bits admit it. No chown: `None` twice skips the syscall.
            socket_mode: 0o660,
            socket_owner_uid: None,
            socket_gid: None,
            max_subscribers: MAX_SUBSCRIBERS,
            max_connections: MAX_CONNECTIONS,
            request_timeout: REQUEST_READ_TIMEOUT,
            acting,
            policy: ControlPolicy {
                daemon_uid,
                socket_owner_uid: None,
                control_uids: Vec::new(),
                console: no_console,
                // The REAL lookup: every pre-existing test keeps exercising it,
                // and only the two injected-peer tests below override it.
                peer_uid: peer_uid_of,
            },
            observing: Arc::new(AtomicBool::new(true)),
            // Active, so the pre-tier control tests keep their premises; the
            // `set_probing` test flips it itself.
            probing: Arc::new(ProbingState::new(ProbingTier::Active)),
            freezer: Arc::new(PcapRingSlot::empty()),
            scanner: None,
            air_scanner: None,
            topology_scanner: None,
            scan_cve_snapshot: None,
            blob_dir: std::env::temp_dir().join("net-observerd-test-blobs"),
            resume_at_us: Arc::new(AtomicI64::new(0)),
            session_end_us: Arc::new(AtomicI64::new(0)),
            snapshot: Arc::new(Mutex::new(StatusSnapshot::default())),
            store: Arc::new(store::DuckdbStore::in_memory().unwrap()),
            query_gate: Arc::new(Semaphore::new(MAX_QUERIES_IN_FLIGHT)),
            events_tx,
            control_refusals: RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
            sub_refusals: RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
            experiments: Arc::new(Mutex::new(HashMap::new())),
            ring_filter: "arp or icmp or udp port 67 or udp port 68 or ether broadcast".into(),
            link_interval: Duration::from_secs(15),
        }
    }

    /// Borrow a [`ControlCtx`] out of a test server, so the control tests exercise
    /// exactly the context `handle_conn` builds.
    fn test_ctx(srv: &ApiServer) -> ControlCtx<'_> {
        ControlCtx {
            policy: &srv.policy,
            acting: &srv.acting,
            observing: &srv.observing,
            probing: &srv.probing,
            freezer: &srv.freezer,
            scanner: srv.scanner.as_deref(),
            air_scanner: srv.air_scanner.as_deref(),
            topology_scanner: srv.topology_scanner.as_deref(),
            scan_cve_snapshot: srv.scan_cve_snapshot.as_deref(),
            blob_dir: &srv.blob_dir,
            resume_at_us: &srv.resume_at_us,
            session_end_us: &srv.session_end_us,
            snapshot: &srv.snapshot,
            store: srv.store.as_ref(),
            events_tx: &srv.events_tx,
            refusals: &srv.control_refusals,
            experiment: srv.experiment_handles(),
        }
    }

    /// A scanner that records what it was asked and answers as told.
    struct FakeAirScanner {
        answer: AirScanRequest,
        asked: Arc<AtomicUsize>,
    }

    impl crate::pipeline::AirScanner for FakeAirScanner {
        fn request_scan(&self) -> AirScanRequest {
            self.asked.fetch_add(1, Ordering::AcqRel);
            self.answer.clone()
        }
    }

    fn with_air(srv: &mut ApiServer, answer: AirScanRequest) -> Arc<AtomicUsize> {
        let asked = Arc::new(AtomicUsize::new(0));
        srv.air_scanner = Some(Arc::new(FakeAirScanner {
            answer,
            asked: Arc::clone(&asked),
        }) as Arc<dyn crate::pipeline::AirScanner>);
        asked
    }

    /// An authorised press reaches the scanner on a default server: nothing in
    /// config sits between the operator's command and the radio read.
    #[test]
    fn an_air_scan_reaches_the_scanner() {
        let mut srv = test_server("/tmp/unused-air-1.sock", test_acting(), TEST_DAEMON_UID);
        let asked = with_air(&mut srv, AirScanRequest::Started);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanAir, Some(TEST_DAEMON_UID), &cx);
        assert!(r.ok, "{}", r.message);
        assert_eq!(asked.load(Ordering::Acquire), 1);
    }

    /// A pause DOES refuse: the pause is bracketed silence, and a sample stamped
    /// inside the bracket would make the `observing_edge` row and the data
    /// disagree about the same seconds. Nothing is asked of the radio.
    #[test]
    fn a_paused_daemon_refuses_an_air_scan_without_touching_the_radio() {
        let mut srv = test_server("/tmp/unused-air-3.sock", test_acting(), TEST_DAEMON_UID);
        let asked = with_air(&mut srv, AirScanRequest::Started);
        srv.observing.store(false, Ordering::Release);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanAir, Some(TEST_DAEMON_UID), &cx);
        assert!(!r.ok);
        assert!(r.message.contains("paused"), "{}", r.message);
        assert_eq!(asked.load(Ordering::Acquire), 0);
    }

    /// Every refusal carries the reason, and a rate refusal carries the wait.
    /// The operator pressed a button and is owed a fact, never a silent no-op.
    #[test]
    fn each_air_scan_refusal_says_why() {
        for (answer, needle) in [
            (AirScanRequest::AlreadyRunning, "already running"),
            (AirScanRequest::TooSoon { retry_in_s: 9 }, "9s"),
        ] {
            let mut srv = test_server("/tmp/unused-air-4.sock", test_acting(), TEST_DAEMON_UID);
            with_air(&mut srv, answer.clone());
            let cx = test_ctx(&srv);
            let r = control_request(ControlCmd::ScanAir, Some(TEST_DAEMON_UID), &cx);
            assert!(!r.ok, "{answer:?} must not report success");
            assert!(r.message.contains(needle), "{answer:?}: {}", r.message);
        }
    }

    /// No scanner wired at all is a refusal with a message, never a silent
    /// success — the same rule `FreezePcap` follows for an absent ring.
    #[test]
    fn an_air_scan_without_a_scanner_is_a_refusal_with_a_reason() {
        let srv = test_server("/tmp/unused-air-5.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanAir, Some(TEST_DAEMON_UID), &cx);
        assert!(!r.ok);
        assert!(r.message.contains("not available"), "{}", r.message);
    }

    /// Self-control is not no-control: an unauthorised peer is still refused,
    /// and the radio is not read for it.
    #[test]
    fn an_unauthorised_peer_cannot_scan_the_air() {
        let mut srv = test_server("/tmp/unused-air-6.sock", test_acting(), TEST_DAEMON_UID);
        let asked = with_air(&mut srv, AirScanRequest::Started);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanAir, None, &cx);
        assert!(!r.ok, "{}", r.message);
        assert_eq!(asked.load(Ordering::Acquire), 0);
    }

    /// A scanner that records how many times it was asked and returns a
    /// canned set of links.
    struct FakeTopologyScanner {
        links: Vec<types::TopologyLink>,
        asked: Arc<AtomicUsize>,
    }

    impl crate::pipeline::TopologyScanner for FakeTopologyScanner {
        fn scan(&self) -> Vec<types::TopologyLink> {
            self.asked.fetch_add(1, Ordering::AcqRel);
            self.links.clone()
        }
    }

    fn with_topology(srv: &mut ApiServer, links: Vec<types::TopologyLink>) -> Arc<AtomicUsize> {
        let asked = Arc::new(AtomicUsize::new(0));
        srv.topology_scanner = Some(Arc::new(FakeTopologyScanner {
            links,
            asked: Arc::clone(&asked),
        }) as Arc<dyn crate::pipeline::TopologyScanner>);
        asked
    }

    /// A minimal link for tests that only care about the count, not the
    /// content.
    fn fake_topology_link(n: u8) -> types::TopologyLink {
        types::TopologyLink {
            iface: "en0".to_string(),
            remote_chassis: format!("aa:bb:cc:dd:ee:{n:02x}"),
            remote_port: "1".to_string(),
            remote_system_name: None,
            capabilities: String::new(),
            learned_via: types::LearnedVia::Lldp,
            ts_us: 1,
        }
    }

    /// An authorised press reaches the scanner on a default server, and a
    /// non-empty result is reported ok with the real count — mirrors
    /// `an_air_scan_reaches_the_scanner`, but the answer carries the outcome
    /// itself rather than just an "accepted" ack (the sync-round-trip design,
    /// AGENTS.md realm net-observer node #91).
    #[test]
    fn a_topology_scan_reaches_the_scanner_and_reports_the_count() {
        let mut srv = test_server("/tmp/unused-topo-1.sock", test_acting(), TEST_DAEMON_UID);
        let asked = with_topology(&mut srv, vec![fake_topology_link(1), fake_topology_link(2)]);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanTopology, Some(TEST_DAEMON_UID), &cx);
        assert!(r.ok, "{}", r.message);
        assert!(r.message.contains("2 uplink"), "{}", r.message);
        assert_eq!(asked.load(Ordering::Acquire), 1);
    }

    /// Zero links is reported `ok: true` with the honest "no frames" message —
    /// absence is the SKIP-never-silence answer (a consumer Wi-Fi segment has
    /// no managed switch/AP to hear from), never a failure.
    #[test]
    fn a_topology_scan_with_no_links_is_ok_with_an_honest_message() {
        let mut srv = test_server("/tmp/unused-topo-2.sock", test_acting(), TEST_DAEMON_UID);
        with_topology(&mut srv, Vec::new());
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanTopology, Some(TEST_DAEMON_UID), &cx);
        assert!(r.ok, "{}", r.message);
        assert!(r.message.contains("no LLDP/CDP frames"), "{}", r.message);
    }

    /// A pause DOES refuse, for the same reason a neighbour/air scan does: the
    /// pause is bracketed silence, and a link stamped inside the bracket
    /// would make the `observing_edge` row and the data disagree about the
    /// same seconds. Nothing is asked of the capture.
    #[test]
    fn a_paused_daemon_refuses_a_topology_scan_without_touching_the_capture() {
        let mut srv = test_server("/tmp/unused-topo-3.sock", test_acting(), TEST_DAEMON_UID);
        let asked = with_topology(&mut srv, vec![fake_topology_link(1)]);
        srv.observing.store(false, Ordering::Release);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanTopology, Some(TEST_DAEMON_UID), &cx);
        assert!(!r.ok);
        assert!(r.message.contains("paused"), "{}", r.message);
        assert_eq!(asked.load(Ordering::Acquire), 0);
    }

    /// No scanner wired at all is a refusal with a message, never a silent
    /// success — the same rule `FreezePcap`/`ScanAir` follow for an absent
    /// port.
    #[test]
    fn a_topology_scan_without_a_scanner_is_a_refusal_with_a_reason() {
        let srv = test_server("/tmp/unused-topo-4.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanTopology, Some(TEST_DAEMON_UID), &cx);
        assert!(!r.ok);
        assert!(r.message.contains("not available"), "{}", r.message);
    }

    /// Self-control is not no-control: an unauthorised peer is still
    /// refused, and the capture is not run for it.
    #[test]
    fn an_unauthorised_peer_cannot_scan_topology() {
        let mut srv = test_server("/tmp/unused-topo-5.sock", test_acting(), TEST_DAEMON_UID);
        let asked = with_topology(&mut srv, vec![fake_topology_link(1)]);
        let cx = test_ctx(&srv);
        let r = control_request(ControlCmd::ScanTopology, None, &cx);
        assert!(!r.ok, "{}", r.message);
        assert_eq!(asked.load(Ordering::Acquire), 0);
    }

    /// A scratch directory for a socket-bound test.
    ///
    /// Based directly under `/tmp`, NOT `std::env::temp_dir()`: on macOS
    /// that resolves to a long per-process `/var/folders/xx/.../T/` path,
    /// and `sockaddr_un.sun_path` there is ~104 bytes (vs Linux's 108) — a
    /// long enough `tag` pushes `<dir>/observer.sock` over that limit and
    /// `UnixListener::bind` fails; the test then sees no socket file ever
    /// appear and `wait_for_socket` times out, which reads like the server
    /// never started rather than the real cause (the path was too long).
    /// `/tmp` is short on every runner these tests run on, so even the
    /// longest `tag` in this file stays well under the limit.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::path::PathBuf::from("/tmp").join(format!("nob-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn wait_for_socket(sock: &std::path::Path) {
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(sock.exists(), "socket was never created");
    }

    /// End-to-end round-trip over a real `UnixListener` bound to a temp path,
    /// answered with the blocking `net_observer_ipc::query` client the bar uses.
    #[tokio::test]
    async fn serve_answers_status_and_incidents() {
        let dir = temp_dir("api");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        let snapshot = Arc::clone(&srv.snapshot);
        {
            let mut s = snapshot.lock().unwrap();
            s.generated_us = 42;
            s.link = Some(LinkSample {
                ts_us: 42,
                gw: GwVerdict::Ok,
                gw_rtt_ms: Some(1.5),
                direct: TcpVerdict::Ok,
                direct_rtt_ms: None,
                dhcp_router: None,
                dhcp_dns: None,
                gw_arp_mac: None,
                ssid: Some("home".into()),
                bssid: None,
                if_mac: None,
                medium: None,
                lease_start_us: None,
                lease_secs: None,
                if_mac_private: None,
                wifi_capture_present: false,
                lan_probed: None,
                lan_alive: None,
                fakeip_route_if: None,
                singbox_tun_if: None,
            });
            s.incidents = vec![
                IncidentSummary {
                    id: "gw-drop-3".into(),
                    opened_us: 3,
                    closed_us: None,
                    trigger_id: "gw-drop".into(),
                    signature: "newest".into(),
                },
                IncidentSummary {
                    id: "wedge-2".into(),
                    opened_us: 2,
                    closed_us: None,
                    trigger_id: "wedge".into(),
                    signature: "older".into(),
                },
            ];
        }

        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        // Status: the whole snapshot, cloned from memory.
        let sp = sock_str.clone();
        let status =
            tokio::task::spawn_blocking(move || net_observer_ipc::query(&sp, &Request::Status))
                .await
                .unwrap()
                .unwrap();
        match status {
            Response::Status(s) => {
                assert_eq!(s.generated_us, 42);
                assert_eq!(s.link.unwrap().ts_us, 42);
                assert_eq!(s.incidents.len(), 2);
                assert_eq!(s.incidents[0].id, "gw-drop-3");
            }
            other => panic!("expected Status, got {other:?}"),
        }

        // Incidents{limit}: newest `limit` of the ring.
        let sp = sock_str.clone();
        let inc = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(&sp, &Request::Incidents { limit: 1 })
        })
        .await
        .unwrap()
        .unwrap();
        match inc {
            Response::Incidents(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].id, "gw-drop-3");
            }
            other => panic!("expected Incidents, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The named diagnoses over the socket, against the daemon's OWN store —
    /// the one reader the DuckDB lock does not shut out. `Gaps` is the cheapest
    /// variant (no parameters, one CTE); the columns are the ones the CLI's
    /// renderer looks up by name, and a store nobody paused holds no gap.
    #[tokio::test]
    async fn serve_answers_a_query_from_the_store() {
        let dir = temp_dir("api-query");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let answer = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(&sp, &Request::Query(DiagnosticQuery::Gaps))
        })
        .await
        .unwrap()
        .unwrap();
        match answer {
            Response::Table(t) => {
                // The shape `Gaps` shipped with, and keeps: a pre-tier reader
                // asks for it by this id and prints every row as a pause.
                assert_eq!(
                    t.columns,
                    ["gap_opened_us", "gap_closed_us", "gap_closed_by"]
                );
                assert!(t.rows.is_empty(), "no pause, no gap: {:?}", t.rows);
            }
            other => panic!("expected Table, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `check-cve --product`: a pure local-index read through whichever
    /// `NeighborScanner` is configured — routed BEFORE `query_store`, so it
    /// never touches the query gate or DuckDB at all. `FakeScanner::
    /// cve_lookup` answers a fixed fixture; this pins the exact `Table`
    /// shape the CLI renders it into (`cve_lookup_table`).
    #[tokio::test]
    async fn serve_answers_a_cve_lookup_query() {
        let dir = temp_dir("api-cve-lookup");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let mut srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        srv.scanner = Some(Arc::new(FakeScanner(None)));
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let answer = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(
                &sp,
                &Request::Query(DiagnosticQuery::CveLookup {
                    product: "openssh".to_string(),
                    version: Some("7.2".to_string()),
                }),
            )
        })
        .await
        .unwrap()
        .unwrap();
        match answer {
            Response::Table(t) => {
                assert_eq!(
                    t.columns,
                    ["cve_id", "cvss", "known_exploited", "confidence", "summary"]
                );
                assert_eq!(
                    t.rows,
                    vec![vec![
                        "CVE-2024-0001".to_string(),
                        "9.8".to_string(),
                        "true".to_string(),
                        "high".to_string(),
                        "a fixture finding".to_string(),
                    ]]
                );
            }
            other => panic!("expected Table, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No `NeighborScanner` configured at all (the daemon's default when
    /// neighbour scanning is off) — the SAME wording `scan_now` already
    /// answers for the same condition, not a silent empty table.
    #[tokio::test]
    async fn serve_answers_cve_lookup_with_no_scanner_configured() {
        let dir = temp_dir("api-cve-lookup-no-scanner");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        assert!(srv.scanner.is_none());
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let answer = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(
                &sp,
                &Request::Query(DiagnosticQuery::CveLookup {
                    product: "openssh".to_string(),
                    version: None,
                }),
            )
        })
        .await
        .unwrap()
        .unwrap();
        match answer {
            Response::Error(m) => assert_eq!(m, "neighbour scanning not available"),
            other => panic!("expected Error, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The snapshot cannot be used at all — a decoded-but-failed
    /// `Response::Error`, never a silent empty table that would read as "no
    /// CVEs found" (see `cve_lookup_response`'s doc).
    #[tokio::test]
    async fn serve_answers_cve_lookup_when_the_snapshot_is_unavailable() {
        let dir = temp_dir("api-cve-lookup-unavailable");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let mut srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::new(Mutex::new(None)))));
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let answer = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(
                &sp,
                &Request::Query(DiagnosticQuery::CveLookup {
                    product: "openssh".to_string(),
                    version: None,
                }),
            )
        })
        .await
        .unwrap()
        .unwrap();
        match answer {
            Response::Error(m) => assert_eq!(m, "RecordingScanner carries no CVE snapshot"),
            other => panic!("expected Error, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store whose budgeted read PARKS until the test releases it, so a
    /// diagnosis can be caught in the middle of its blocking run. Everything
    /// else delegates to a real in-memory store — the test is about the gate,
    /// not the SQL.
    ///
    /// `entered` fires when a read has begun (the permit is held from before
    /// this point until the read returns); `release` lets it return.
    struct BlockingStore {
        inner: store::DuckdbStore,
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl Store for BlockingStore {
        fn write_sample(&self, s: &Sample) -> Result<(), store::StoreError> {
            self.inner.write_sample(s)
        }
        fn open_incident(&self, i: &types::Incident) -> Result<(), store::StoreError> {
            self.inner.open_incident(i)
        }
        fn close_incident(&self, id: &str, closed_us: i64) -> Result<(), store::StoreError> {
            self.inner.close_incident(id, closed_us)
        }
        fn write_blob_ref(&self, b: &types::BlobRef) -> Result<(), store::StoreError> {
            self.inner.write_blob_ref(b)
        }
        fn write_trigger_fired(&self, t: &types::TriggerFired) -> Result<(), store::StoreError> {
            self.inner.write_trigger_fired(t)
        }
        fn write_observing_edge(&self, e: &ObservingEdge) -> Result<(), store::StoreError> {
            self.inner.write_observing_edge(e)
        }
        fn write_probing_edge(&self, e: &ProbingEdge) -> Result<(), store::StoreError> {
            self.inner.write_probing_edge(e)
        }
        fn write_experiment(&self, x: &store::ExperimentRecord) -> Result<(), store::StoreError> {
            self.inner.write_experiment(x)
        }
        fn experiment(
            &self,
            id: &str,
        ) -> Result<Option<store::ExperimentRecord>, store::StoreError> {
            self.inner.experiment(id)
        }
        fn write_neighbor_scan(&self, s: &store::NeighborScan) -> Result<(), store::StoreError> {
            self.inner.write_neighbor_scan(s)
        }
        fn write_neighbor_port(&self, p: &store::NeighborPort) -> Result<(), store::StoreError> {
            self.inner.write_neighbor_port(p)
        }
        fn write_neighbor_vuln(&self, v: &store::NeighborVuln) -> Result<(), store::StoreError> {
            self.inner.write_neighbor_vuln(v)
        }
        fn write_topology_link(&self, l: &types::TopologyLink) -> Result<(), store::StoreError> {
            self.inner.write_topology_link(l)
        }
        fn neighbor_lifetimes(
            &self,
            network_key: Option<&str>,
        ) -> Result<Vec<types::NeighborLifetime>, store::StoreError> {
            self.inner.neighbor_lifetimes(network_key)
        }
        fn topology_lifetimes(&self) -> Result<Vec<types::TopologyLifetime>, store::StoreError> {
            self.inner.topology_lifetimes()
        }
        fn query_scalar_i64(&self, sql: &str) -> Result<i64, store::StoreError> {
            self.inner.query_scalar_i64(sql)
        }
        fn query_table(&self, sql: &str) -> Result<store::QueryTable, store::StoreError> {
            self.inner.query_table(sql)
        }
        fn query_prepared(
            &self,
            p: &store::diagnosis::PreparedSql,
        ) -> Result<store::QueryTable, store::StoreError> {
            self.inner.query_prepared(p)
        }
        /// The one the daemon's `Query` path calls: announce, park, then answer.
        fn query_prepared_within(
            &self,
            p: &store::diagnosis::PreparedSql,
            budget: Duration,
        ) -> Result<store::QueryTable, store::StoreError> {
            let _ = self.entered.send(());
            let _ = self
                .release
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv();
            self.inner.query_prepared_within(p, budget)
        }
        fn schema_drift(&self) -> Result<Vec<store::SchemaDrift>, store::StoreError> {
            self.inner.schema_drift()
        }
        fn prune_older_than(&self, table: &str, cutoff_us: i64) -> Result<u64, store::StoreError> {
            self.inner.prune_older_than(table, cutoff_us)
        }
    }

    /// One diagnosis in flight, and a second is refused AT ONCE with
    /// [`QUERY_BUSY`] — which the CLI's classifier must read as a failure to
    /// show, never as "this daemon cannot answer diagnoses" (that would send it
    /// to the DB file, where the lock waits).
    ///
    /// The permit is held by a RUNNING query, not by the test: query A parks
    /// inside the store's read (`BlockingStore`), query B is refused while it
    /// is parked, and only after the test releases A does B's kind of query
    /// run — so what is proved is that the permit spans the whole blocking run.
    /// The store signals "entered" over a channel and nothing sleeps.
    #[tokio::test]
    async fn serve_refuses_a_second_query_while_one_runs() {
        let dir = temp_dir("api-query-busy");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let mut srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        srv.store = Arc::new(BlockingStore {
            inner: store::DuckdbStore::in_memory().unwrap(),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        });
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        // A: starts, and parks inside the store's read with the permit held.
        let sp = sock_str.clone();
        let a = tokio::task::spawn_blocking(move || {
            net_observer_ipc::diagnose(&sp, DiagnosticQuery::Gaps)
        });
        entered_rx.recv().await.expect("query A reached the store");

        // B, while A is parked: refused at once, in the busy spelling.
        let sp = sock_str.clone();
        let refused = tokio::task::spawn_blocking(move || {
            net_observer_ipc::diagnose(&sp, DiagnosticQuery::Gaps)
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(refused, QueryOutcome::Failed(QUERY_BUSY.to_string()));

        // Release A: it answers, and its permit is free for the next one.
        release_tx.send(()).unwrap();
        let answered = a.await.unwrap().unwrap();
        assert!(
            matches!(answered, QueryOutcome::Table(_)),
            "A after release: {answered:?}"
        );
        release_tx.send(()).unwrap();
        let sp = sock_str.clone();
        let next = tokio::task::spawn_blocking(move || {
            net_observer_ipc::diagnose(&sp, DiagnosticQuery::Gaps)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(next, QueryOutcome::Table(_)),
            "after A returned: {next:?}"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D2, the pure core of the policy: every allow rule and the refusal, with no
    /// syscall, no socket, no root and no console session involved.
    #[test]
    fn control_authorized_covers_every_rule() {
        let base = ControlPolicy {
            daemon_uid: 501,
            socket_owner_uid: None,
            control_uids: Vec::new(),
            console: no_console,
            peer_uid: peer_uid_of,
        };

        // root is always allowed; so is the daemon's own uid.
        assert!(control_authorized(&base, 0, None));
        assert!(control_authorized(&base, 501, None));
        // The logged-in console user — the out-of-the-box menu-bar case.
        assert!(control_authorized(&base, 600, Some(600)));
        // An unrelated staff uid on the group-connectable socket is refused.
        assert!(!control_authorized(&base, 502, None));
        assert!(!control_authorized(&base, 502, Some(600)));

        // The operator's explicit socket owner is allowed.
        let owned = ControlPolicy {
            socket_owner_uid: Some(502),
            ..base.clone()
        };
        assert!(control_authorized(&owned, 502, None));

        // The headless escape hatch: an explicitly listed uid.
        let listed = ControlPolicy {
            control_uids: vec![777],
            ..base.clone()
        };
        assert!(control_authorized(&listed, 777, None));
        assert!(!control_authorized(&base, 777, None));

        // With no console session (SSH-only host, CI, container) the console rule
        // authorises nobody: only root and the daemon's own uid remain.
        for uid in [502u32, 600, 777] {
            assert!(
                !control_authorized(&base, uid, None),
                "uid {uid} must be refused with no console session"
            );
        }
        assert!(control_authorized(&base, 0, None));
        assert!(control_authorized(&base, 501, None));
    }

    /// An authority decision fails closed: a peer whose credentials could not be
    /// read (`getpeereid` failed) is refused, and nothing is mutated.
    #[test]
    fn control_refused_when_peer_credentials_unavailable() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        let result = control_request(ControlCmd::SetObserving(false), None, &cx);
        assert!(!result.ok, "an unidentifiable peer must be refused");
        assert!(
            result.message.starts_with("control refused"),
            "unexpected message: {}",
            result.message
        );
        assert!(
            srv.observing.load(Ordering::Acquire),
            "a refused control must not touch the observing flag"
        );
    }

    /// D2: EVERY control command is peer-gated. The peer check is the one gate
    /// on the control path — no command is exempt from it, and no config switch
    /// stands in for it (realm net-observer, node #91).
    /// The `match` inside the loop is exhaustive on purpose — a further
    /// `ControlCmd` variant fails to compile until it is added here and thus
    /// asserted.
    #[test]
    fn every_control_cmd_is_refused_for_an_unauthorised_peer() {
        // No real account holds it, and `test_server` pins the console clause to
        // "no session", so nothing on any host can accidentally authorise it.
        let stranger = Some(NOT_A_REAL_UID);

        for cmd in [
            ControlCmd::SetObserving(false),
            ControlCmd::SetProbing(ProbingTier::Passive),
            ControlCmd::FreezePcap,
            ControlCmd::KickstartProxy,
            ControlCmd::ScanNeighbors(ScanOptions::default()),
            ControlCmd::ScanAir,
            ControlCmd::StartExperiment { minutes: 5 },
        ] {
            // Exhaustive on purpose — a new variant breaks this arm list.
            match cmd {
                ControlCmd::SetObserving(_)
                | ControlCmd::SetProbing(_)
                | ControlCmd::FreezePcap
                | ControlCmd::KickstartProxy
                | ControlCmd::ScanNeighbors(_)
                | ControlCmd::ScanAir
                | ControlCmd::StartExperiment { .. } => {}
            }
            // A refusal here can only come from the peer gate: there is no
            // other gate on the control path.
            let srv = test_server("/nonexistent.sock", test_acting(), 1);
            let cx = test_ctx(&srv);
            let result = control_request(cmd.clone(), stranger, &cx);
            assert!(
                !result.ok,
                "{cmd:?} must be refused for an unauthorised peer"
            );
            assert!(
                result.message.starts_with("control refused"),
                "{cmd:?}: unexpected message {}",
                result.message
            );
            assert!(
                srv.observing.load(Ordering::Acquire),
                "{cmd:?}: a refused control must not touch the observing flag"
            );
            assert_eq!(
                srv.store
                    .query_scalar_i64("SELECT count(*) FROM observing_edge")
                    .unwrap(),
                0,
                "{cmd:?}: a refused pause must leave no boundary row behind"
            );
            assert_eq!(
                srv.probing.tier(),
                ProbingTier::Active,
                "{cmd:?}: a refused control must not touch the probing tier"
            );
            assert_eq!(
                srv.store
                    .query_scalar_i64("SELECT count(*) FROM probing_edge")
                    .unwrap(),
                0,
                "{cmd:?}: a refused tier switch must leave no boundary row behind"
            );
        }
    }

    /// `SetProbing` flips the tier the three emitting collectors read, mirrors
    /// it into the live snapshot, and brackets the switch: one durable
    /// `probing_edge` row and one `Probing` frame describing the
    /// same transition (same `ts_us`, same tier, same peer). A repeat to the
    /// tier already in force is not an edge: no row, no frame, still `ok`.
    #[test]
    fn set_probing_flips_the_tier_and_brackets_the_switch_through_both_sinks() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let mut rx = srv.events_tx.subscribe();
        let cx = test_ctx(&srv);
        assert_eq!(srv.probing.tier(), ProbingTier::Active);

        assert_eq!(srv.resume_at_us.load(Ordering::Acquire), 0);

        let res = control_request(
            ControlCmd::SetProbing(ProbingTier::Passive),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert_eq!(res.message, "probing passive");
        assert_eq!(srv.probing.tier(), ProbingTier::Passive);
        assert_eq!(srv.snapshot.lock().unwrap().probing, ProbingTier::Passive);
        // The tier is orthogonal to the pause.
        assert!(srv.observing.load(Ordering::Acquire));
        // The switch closes and re-opens detection the way a resume does: the
        // window-clearing epoch moves to the edge's own instant, which is what
        // `pipeline::run` keys `clear_for_resume` + `rearm_all` off.
        let epoch_after_passive = srv.resume_at_us.load(Ordering::Acquire);
        assert_ne!(
            epoch_after_passive, 0,
            "a tier switch must publish the epoch"
        );

        // Sink 1: exactly one durable row, attributable to the peer.
        assert_eq!(
            srv.store
                .query_scalar_i64(&format!(
                    "SELECT count(*) FROM probing_edge \
                     WHERE tier = 'passive' AND peer_uid = {TEST_DAEMON_UID}"
                ))
                .unwrap(),
            1
        );
        let row_ts = srv
            .store
            .query_scalar_i64("SELECT ts_us FROM probing_edge")
            .unwrap();
        assert_eq!(
            epoch_after_passive, row_ts,
            "the epoch is the edge's own instant: the probing_edge row is the bracket"
        );
        // The switch also records itself as the session's own end, stamped
        // BEFORE the epoch bump (realm net-observer, node #124).
        assert_eq!(
            srv.session_end_us.load(Ordering::Acquire),
            row_ts,
            "a tier switch must publish the session's end at its own ts_us"
        );
        // Sink 2: exactly one frame, describing the same transition.
        let frame = rx.try_recv().expect("a tier switch must publish one frame");
        let decoded: StreamFrame = serde_json::from_slice(frame.bytes()).unwrap();
        match decoded {
            StreamFrame::Probing(edge) => {
                assert_eq!(
                    edge.ts_us, row_ts,
                    "row and frame disagree on the timestamp"
                );
                assert_eq!(edge.tier, ProbingTier::Passive);
                assert_eq!(edge.peer_uid, Some(TEST_DAEMON_UID));
            }
            other => panic!("expected a Probing frame, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "one edge, one frame");

        // A no-op: the tier holds, nothing is written or published.
        let again = control_request(
            ControlCmd::SetProbing(ProbingTier::Passive),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(again.ok);
        assert_eq!(again.message, "probing passive");
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM probing_edge")
                .unwrap(),
            1,
            "a no-op must not write a second boundary row"
        );
        assert!(rx.try_recv().is_err(), "a no-op must not publish a frame");
        assert_eq!(
            srv.resume_at_us.load(Ordering::Acquire),
            epoch_after_passive,
            "a no-op must not clear the window either"
        );

        // And back: a second real edge.
        let back = control_request(
            ControlCmd::SetProbing(ProbingTier::Active),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(back.ok);
        assert_eq!(back.message, "probing active");
        assert_eq!(srv.probing.tier(), ProbingTier::Active);
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM probing_edge WHERE tier = 'active'")
                .unwrap(),
            1
        );
        assert!(rx.try_recv().is_ok(), "the second edge publishes its frame");
        // Either direction clears: the switch back moves the epoch again, so
        // no dead tick from before the stretch can join the ticks after it.
        assert_eq!(
            srv.resume_at_us.load(Ordering::Acquire),
            srv.store
                .query_scalar_i64("SELECT ts_us FROM probing_edge WHERE tier = 'active'")
                .unwrap()
        );
        // The FIRST unconsumed end wins: nothing ever consumed (swapped) it
        // between the two switches — exactly the "switch during a pause"
        // shape, just with the first edge itself standing in for the pause —
        // so `session_end_us` still holds the FIRST switch's `ts_us`, not this
        // second one's, even though `resume_at_us` moved again.
        assert_eq!(
            srv.session_end_us.load(Ordering::Acquire),
            epoch_after_passive,
            "an unconsumed session_end_us must not be overwritten by a later switch"
        );
        // A tier switch is not a pause: the observing bracket stays untouched.
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            0,
            "a tier switch is not a pause and must not write an observing edge"
        );
    }

    /// `SetObserving` flips the shared flag and mirrors the new state into the
    /// live snapshot so the switch shows reality.
    #[test]
    fn set_observing_flips_the_flag_and_updates_snapshot() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);

        // Pause: flag + snapshot go false.
        let off = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(off.ok, "{}", off.message);
        assert_eq!(off.message, "observing off");
        assert!(!srv.observing.load(Ordering::Acquire));
        assert!(!srv.snapshot.lock().unwrap().observing);

        // Resume: flag + snapshot go true again.
        let on = control_request(ControlCmd::SetObserving(true), Some(TEST_DAEMON_UID), &cx);
        assert!(on.ok);
        assert_eq!(on.message, "observing on");
        assert!(srv.observing.load(Ordering::Acquire));
        assert!(srv.snapshot.lock().unwrap().observing);
    }

    /// A fake scanner, so the control path is exercised without putting a single
    /// packet on a real segment.
    struct FakeScanner(Option<ScanReport>);
    impl NeighborScanner for FakeScanner {
        fn scan(&self, _opts: &ScanOptions) -> Option<ScanReport> {
            self.0.clone()
        }

        /// Not exercised by the scan-mode tests that build this fixture with
        /// `scan` in mind; the one test that asks THIS
        /// (`serve_answers_a_cve_lookup_query`) knows this exact value.
        fn cve_lookup(&self, _product: &str, _version: Option<&str>) -> CveLookupOutcome {
            CveLookupOutcome::Matches(vec![vuln_db::VulnMatch {
                cve_id: "CVE-2024-0001".to_string(),
                summary: "a fixture finding".to_string(),
                confidence: vuln_db::Confidence::High,
                known_exploited: true,
                cvss: Some(9.8),
            }])
        }
    }

    /// A scanner that records the EFFECTIVE options it was handed, so a test can
    /// assert what the intersection in `scan_now` actually turned on.
    struct RecordingScanner(Arc<Mutex<Option<ScanOptions>>>);
    impl NeighborScanner for RecordingScanner {
        fn scan(&self, opts: &ScanOptions) -> Option<ScanReport> {
            *self.0.lock().unwrap() = Some(opts.clone());
            Some(fake_report())
        }

        /// Never asked by any test that builds this fixture (`scan_now`'s
        /// control-path tests, not a `CveLookup` query) — present only to
        /// satisfy the trait.
        fn cve_lookup(&self, _product: &str, _version: Option<&str>) -> CveLookupOutcome {
            CveLookupOutcome::SnapshotUnavailable(
                "RecordingScanner carries no CVE snapshot".to_string(),
            )
        }
    }

    fn fake_report() -> ScanReport {
        ScanReport {
            ts_us: 5000,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            found: vec![types::NeighborObs {
                mac: "11:22:33:44:55:66".into(),
                ip: "192.168.1.5".into(),
                source: types::NeighborSource::Sweep,
                hostname: Some("printer.local".into()),
                role: types::NeighborRole::Unknown,
            }],
            scans: vec![store::NeighborScan {
                ts_us: 5000,
                network_key: Some("aa:bb:cc:dd:ee:ff".into()),
                iface: Some("en0".into()),
                method: "sweep".into(),
                target: "192.168.1.0/24".into(),
                found: 1,
                duration_ms: 2100,
                detail: None,
            }],
            ports: Vec::new(),
            vulns: Vec::new(),
            cve_note: None,
            message: "swept 192.168.1.0/24: 1 neighbours, 1 named".into(),
        }
    }

    /// A scan that runs records both halves: the entities it found AND the row
    /// saying the daemon went looking. The server is a default one: nothing in
    /// config has to be switched on for an authorised operator's scan to run.
    #[test]
    fn a_scan_records_its_findings_and_the_fact_that_it_ran() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.scanner = Some(Arc::new(FakeScanner(Some(fake_report()))));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions::default()),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM neighbor")
                .unwrap(),
            1
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM neighbor_scan WHERE method = 'sweep'")
                .unwrap(),
            1
        );
        // And the live snapshot shows what the operator just asked for.
        let snap = srv.snapshot.lock().unwrap();
        assert_eq!(snap.neighbors.as_ref().unwrap().neighbors.len(), 1);
    }

    /// An unusable cve snapshot (present-but-empty) must be SAID, so an empty
    /// vuln result is never read as a clean "no vulnerabilities". The scanner
    /// reports it via `cve_note`; `scan_now` must surface it in the message.
    #[test]
    fn an_unusable_cve_snapshot_is_surfaced_not_silent() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let mut report = fake_report();
        report.cve_note = Some("snapshot at /tmp/x is empty or wrong layout".to_string());
        srv.scanner = Some(Arc::new(FakeScanner(Some(report))));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions::default()),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(
            res.message.contains("[cve:") && res.message.contains("empty or wrong layout"),
            "the operator must be told the snapshot was unusable: {}",
            res.message
        );
    }

    /// A paused daemon is inside a bracketed gap; a scan would write rows with a
    /// timestamp inside it and make the bracket a false account of the silence.
    #[test]
    fn a_scan_is_refused_while_observation_is_paused() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.scanner = Some(Arc::new(FakeScanner(Some(fake_report()))));
        srv.observing.store(false, Ordering::Release);
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions::default()),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!res.ok, "a paused daemon must not scan");
        assert!(res.message.contains("paused"), "{}", res.message);
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM neighbor_sample")
                .unwrap(),
            0,
            "a refused scan must write nothing into the bracketed gap"
        );
    }

    /// The passive tier promises no emission the daemon makes on its own, and
    /// an operator's scan is not the daemon's — the command is the sanction
    /// (realm net-observer, node #91) and the scan writes its own
    /// `neighbor_scan` row, so passive lets it through and the record shows
    /// what was sent inside the stretch. (realm net-observer, node #88)
    #[test]
    fn a_neighbour_scan_runs_under_the_passive_tier() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.scanner = Some(Arc::new(FakeScanner(Some(fake_report()))));
        srv.probing.set(ProbingTier::Passive);
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions::default()),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(
            res.ok,
            "passive must not refuse a manual scan: {}",
            res.message
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM neighbor_scan WHERE method = 'sweep'")
                .unwrap(),
            1,
            "the scan's own row is what shows the packets were sent inside the stretch"
        );
        assert_eq!(
            srv.probing.tier(),
            ProbingTier::Passive,
            "a scan does not move the tier"
        );
    }

    /// Nothing to scan is a refusal with a reason, never a silent success.
    #[test]
    fn a_scanner_with_nothing_to_scan_refuses() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.scanner = Some(Arc::new(FakeScanner(None)));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions::default()),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!res.ok);
        assert!(res.message.contains("no interface"), "{}", res.message);
    }

    /// Every requested rung runs on a default server with a snapshot present:
    /// no config permission stands between the operator's request and the
    /// scanner, and nothing is reported dropped (realm net-observer, node #91).
    #[test]
    fn every_requested_rung_runs_without_a_config_permission() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let snap = tempfile::tempdir().unwrap();
        srv.scan_cve_snapshot = Some(snap.path().to_path_buf());
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                ports: true,
                banners: true,
                cve: true,
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(
            !res.message.contains("dropped"),
            "a rung with its dependencies met must not be dropped: {}",
            res.message
        );
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert!(eff.ports, "ports was requested");
        assert!(eff.banners, "banners was requested and ports is effective");
        assert!(
            eff.cve,
            "cve was requested, banners is effective and a snapshot is present"
        );
    }

    /// `banners` requested with no effective `ports` rung does nothing: a banner
    /// grab has no open port to read from. A dependency, not a permission — and
    /// the operator is told which.
    #[test]
    fn a_banner_rung_without_an_effective_port_rung_does_nothing() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                ports: false,
                banners: true,
                cve: false,
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert!(!eff.ports, "ports was not requested");
        assert!(
            !eff.banners,
            "banners needs an effective ports rung to do anything"
        );
        assert!(res.message.contains("dropped"), "{}", res.message);
        assert!(res.message.contains("banners"), "{}", res.message);
        assert!(res.message.contains("ports rung"), "{}", res.message);
    }

    /// `cve` requested with no effective `banners` rung does nothing: a match
    /// needs a banner to parse. A dependency, not a permission.
    #[test]
    fn a_cve_rung_without_an_effective_banner_rung_does_nothing() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        // A snapshot is present, so the only thing missing is the banner rung.
        let snap = tempfile::tempdir().unwrap();
        srv.scan_cve_snapshot = Some(snap.path().to_path_buf());
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                ports: true,
                banners: false,
                cve: true,
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(res.message.contains("cve"), "{}", res.message);
        assert!(res.message.contains("banners rung"), "{}", res.message);
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert!(
            !eff.cve,
            "cve needs an effective banners rung to do anything"
        );
    }

    /// `cve` requested with an effective banner grab, but no CVE snapshot
    /// configured, is dropped honestly rather than pretended present.
    #[test]
    fn a_cve_rung_without_a_snapshot_is_dropped_with_a_note() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        // No snapshot directory at all.
        srv.scan_cve_snapshot = None;
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                ports: true,
                banners: true,
                cve: true,
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(res.message.contains("cve"), "{}", res.message);
        assert!(res.message.contains("no CVE snapshot"), "{}", res.message);
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert!(!eff.cve, "cve without a snapshot must not run");
    }

    /// A configured-but-absent snapshot directory is treated as unavailable: a
    /// path that does not exist is not a snapshot, and the rung is dropped.
    #[test]
    fn a_cve_snapshot_path_that_does_not_exist_is_unavailable() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        srv.scan_cve_snapshot = Some(std::path::PathBuf::from("/no/such/snapshot/dir"));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                ports: true,
                banners: true,
                cve: true,
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(res.message.contains("no CVE snapshot"), "{}", res.message);
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert!(
            !eff.cve,
            "an absent snapshot directory means the rung is dropped"
        );
    }

    /// Part A (`--target`, realm net-observer, node #154): `scan_now` passes
    /// the requested target straight through to the scanner, untouched by
    /// the ports/banners/cve dependency ladder — it gates on no other rung.
    /// The decision to skip the whole-segment sweep for a named target is
    /// `SystemScanner`'s, which needs a real interface to exercise at all
    /// (AGENTS.md Reality: a Mac/CI claim from this Linux box); this control
    /// path is what `api::scan_now` itself owns and can test.
    #[test]
    fn scan_now_passes_the_requested_target_straight_through() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        let ip: std::net::IpAddr = "192.168.1.77".parse().unwrap();
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some(ip),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert_eq!(eff.target, Some(ip));
    }

    /// A rung dropped for a missing dependency still reports its message
    /// even when the request also names a `--target` — `target` gates on no
    /// other rung, so the two compose independently.
    #[test]
    fn a_dropped_rung_still_reports_its_message_alongside_a_target_request() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        let ip: std::net::IpAddr = "192.168.1.77".parse().unwrap();
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some(ip),
                banners: true, // no ports: the dependency drop still applies
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(
            res.message.contains("dropped") && res.message.contains("banners"),
            "{}",
            res.message
        );
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert_eq!(eff.target, Some(ip));
        assert!(!eff.banners, "banners needs an effective ports rung");
    }

    /// Part A boundary decision: a target that can never be a real neighbour
    /// on any segment — loopback, multicast, unspecified — is refused before
    /// the scanner ever runs. An ordinary off-subnet address is deliberately
    /// NOT refused here (see `scan_now`'s doc): that one reaches the
    /// scanner, which probes it.
    #[test]
    fn a_loopback_target_is_refused_before_the_scanner_runs() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some("127.0.0.1".parse().unwrap()),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!res.ok, "a loopback target must be refused");
        assert!(res.message.contains("loopback"), "{}", res.message);
        assert!(
            seen.lock().unwrap().is_none(),
            "the scanner must not run for a refused target"
        );
    }

    /// A multicast target is refused the same way, before the scanner runs.
    #[test]
    fn a_multicast_target_is_refused_before_the_scanner_runs() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some("224.0.0.1".parse().unwrap()),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!res.ok, "a multicast target must be refused");
        assert!(res.message.contains("multicast"), "{}", res.message);
        assert!(seen.lock().unwrap().is_none(), "the scanner must not run");
    }

    /// The IPv4 limited-broadcast address (255.255.255.255) can never be a
    /// real neighbour either — refused the same way, before the scanner runs.
    #[test]
    fn a_limited_broadcast_target_is_refused_before_the_scanner_runs() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some("255.255.255.255".parse().unwrap()),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!res.ok, "the limited-broadcast address must be refused");
        assert!(res.message.contains("broadcast"), "{}", res.message);
        assert!(seen.lock().unwrap().is_none(), "the scanner must not run");
    }

    /// An IPv6 loopback/multicast/unspecified target is refused by the same
    /// checks as IPv4 — `IpAddr::is_loopback`/`is_multicast`/`is_unspecified`
    /// dispatch correctly per variant, so no separate IPv6 branch is needed.
    #[test]
    fn an_ipv6_loopback_and_multicast_target_are_refused_too() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);

        let loopback = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some("::1".parse().unwrap()),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!loopback.ok, "an IPv6 loopback target must be refused");
        assert!(
            loopback.message.contains("loopback"),
            "{}",
            loopback.message
        );

        let multicast = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some("ff02::1".parse().unwrap()),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!multicast.ok, "an IPv6 multicast target must be refused");
        assert!(
            multicast.message.contains("multicast"),
            "{}",
            multicast.message
        );
        assert!(
            seen.lock().unwrap().is_none(),
            "the scanner must not run for either refused IPv6 target"
        );
    }

    /// An ordinary off-subnet address (Part A's boundary decision) is NOT
    /// refused: it reaches the scanner like any other named target — the
    /// operator asked for exactly this host, and the socket is pinned to the
    /// physical interface regardless of whether the address shares this
    /// machine's subnet.
    #[test]
    fn an_off_subnet_target_is_not_refused_and_reaches_the_scanner() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let seen = Arc::new(Mutex::new(None));
        srv.scanner = Some(Arc::new(RecordingScanner(Arc::clone(&seen))));
        let cx = test_ctx(&srv);
        // A public, plainly off-segment address — not this machine's subnet.
        let ip: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let res = control_request(
            ControlCmd::ScanNeighbors(ScanOptions {
                target: Some(ip),
                ..ScanOptions::default()
            }),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        let eff = seen.lock().unwrap().clone().expect("scanner ran");
        assert_eq!(eff.target, Some(ip));
    }

    /// With no ring running, `FreezePcap` is a REFUSAL with a reason — never a
    /// silent success that would leave the operator believing an artifact exists.
    #[test]
    fn freeze_pcap_refuses_when_the_ring_is_not_running() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        assert!(srv.freezer.get().is_none());
        let cx = test_ctx(&srv);
        let res = control_request(ControlCmd::FreezePcap, Some(TEST_DAEMON_UID), &cx);
        assert!(!res.ok);
        assert_eq!(res.message, "pcap ring not running");
    }

    /// With a ring running, `FreezePcap` copies it, and the message names the
    /// destination and the file count so the operator can find the artifact.
    #[test]
    fn freeze_pcap_copies_the_ring_and_names_the_destination() {
        /// A freezer that records where it was asked to write and reports two files.
        struct RecordingFreezer(Mutex<Option<std::path::PathBuf>>);
        impl crate::pipeline::PcapFreezer for RecordingFreezer {
            fn freeze(&self, dest_dir: &Path) -> Vec<std::path::PathBuf> {
                *self.0.lock().unwrap() = Some(dest_dir.to_path_buf());
                vec![dest_dir.join("ring.pcap0"), dest_dir.join("ring.pcap1")]
            }
        }

        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let freezer = Arc::new(RecordingFreezer(Mutex::new(None)));
        srv.freezer = Arc::new(PcapRingSlot::with_ring(
            freezer.clone() as Arc<dyn crate::pipeline::PcapFreezer>
        ));
        srv.blob_dir = temp_dir("freeze-manual");
        let blob_dir = srv.blob_dir.clone();
        let cx = test_ctx(&srv);

        let res = control_request(ControlCmd::FreezePcap, Some(TEST_DAEMON_UID), &cx);
        assert!(res.ok, "{}", res.message);
        let dest = freezer.0.lock().unwrap().clone().expect("ring was frozen");
        assert!(
            dest.starts_with(&blob_dir),
            "the freeze must land under the daemon's blob dir: {dest:?}"
        );
        assert!(
            res.message.contains(&dest.display().to_string()),
            "the message must name the destination: {}",
            res.message
        );
        assert!(
            res.message.contains('2'),
            "the message must name the file count: {}",
            res.message
        );
    }

    /// The recovery path the boot-with-no-interface defect needs: the server is
    /// built with an EMPTY slot (no interface at startup), refuses a freeze, and
    /// then — with no restart and no rebuild of the server — starts succeeding
    /// once the supervisor installs a ring into the very same slot.
    #[test]
    fn freeze_pcap_succeeds_once_a_late_ring_lands_in_the_slot() {
        struct CountingFreezer(std::sync::atomic::AtomicUsize);
        impl crate::pipeline::PcapFreezer for CountingFreezer {
            fn freeze(&self, dest_dir: &Path) -> Vec<std::path::PathBuf> {
                self.0.fetch_add(1, Ordering::Release);
                vec![dest_dir.join("ring.pcap0")]
            }
        }

        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.blob_dir = temp_dir("freeze-late-ring");
        let slot = srv.freezer.clone();

        let refused = control_request(
            ControlCmd::FreezePcap,
            Some(TEST_DAEMON_UID),
            &test_ctx(&srv),
        );
        assert!(!refused.ok, "no ring yet: the freeze must be refused");
        assert_eq!(refused.message, "pcap ring not running");

        // The supervisor's write, through the handle the server already holds.
        let ring = Arc::new(CountingFreezer(std::sync::atomic::AtomicUsize::new(0)));
        slot.set(Some(ring.clone() as Arc<dyn crate::pipeline::PcapFreezer>));

        let ok = control_request(
            ControlCmd::FreezePcap,
            Some(TEST_DAEMON_UID),
            &test_ctx(&srv),
        );
        assert!(
            ok.ok,
            "after recovery the freeze must succeed: {}",
            ok.message
        );
        assert_eq!(
            ring.0.load(Ordering::Acquire),
            1,
            "the LIVE ring was frozen"
        );
    }

    /// A window outside `1..=EXPERIMENT_MAX_MINUTES` is refused before
    /// anything moves: no edge, no freeze, no registry entry, the tier held.
    #[test]
    fn an_experiment_of_a_bad_length_is_refused_before_anything_moves() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        for minutes in [0, EXPERIMENT_MAX_MINUTES + 1] {
            let res = control_request(
                ControlCmd::StartExperiment { minutes },
                Some(TEST_DAEMON_UID),
                &cx,
            );
            assert!(!res.ok, "{minutes}: {}", res.message);
            assert!(res.message.contains("minutes"), "{}", res.message);
        }
        assert_eq!(srv.probing.tier(), ProbingTier::Active);
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM probing_edge")
                .unwrap(),
            0
        );
        assert!(srv.experiments.lock().unwrap().is_empty());
    }

    /// Opening a window goes passive and brackets it: one `probing_edge`
    /// row and one frame with reason `experiment`, whose `ts_us` names the
    /// id; the registry holds it as running, a poll for it is told so in the
    /// spelling the CLI waits through, and a second window is refused while
    /// the first runs. On a runtime, because the arm spawns the end task.
    #[tokio::test]
    async fn starting_an_experiment_goes_passive_marks_the_window_and_refuses_a_second() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.blob_dir = temp_dir("experiment-start");
        let mut rx = srv.events_tx.subscribe();
        let cx = test_ctx(&srv);

        let res = control_request(
            ControlCmd::StartExperiment { minutes: 1 },
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(
            res.message.contains("pcap ring not running"),
            "no ring: the message must say the start freeze was not taken: {}",
            res.message
        );
        assert_eq!(srv.probing.tier(), ProbingTier::Passive);

        let t = srv
            .store
            .query_table("SELECT ts_us, tier, peer_uid, reason FROM probing_edge")
            .unwrap();
        assert_eq!(t.rows.len(), 1, "{:?}", t.rows);
        let start_us: i64 = t.rows[0][0].parse().unwrap();
        assert_eq!(t.rows[0][1], "passive");
        assert_eq!(t.rows[0][2], TEST_DAEMON_UID.to_string());
        assert_eq!(t.rows[0][3], "experiment");
        let id = experiment_id(start_us);
        assert!(res.message.contains(&id), "{}", res.message);

        let frame = rx.try_recv().expect("the opening edge publishes one frame");
        match serde_json::from_slice::<StreamFrame>(frame.bytes()).unwrap() {
            StreamFrame::Probing(edge) => {
                assert_eq!(edge.ts_us, start_us);
                assert_eq!(edge.reason, ProbingReason::Experiment);
            }
            other => panic!("expected a Probing frame, got {other:?}"),
        }

        match experiment_in_memory(&srv.experiments, &id) {
            Some(Response::Error(m)) => {
                assert!(net_observer_ipc::is_experiment_running(&m), "{m}");
                assert_eq!(m, experiment_running_message(&id, start_us + 60_000_000));
            }
            other => panic!("a running window answers its poll with still-running: {other:?}"),
        }
        assert!(
            experiment_in_memory(&srv.experiments, "experiment-0").is_none(),
            "an id this process never ran is for the table to answer"
        );

        let second = control_request(
            ControlCmd::StartExperiment { minutes: 1 },
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!second.ok, "{}", second.message);
        assert!(
            net_observer_ipc::is_experiment_running(&second.message),
            "{}",
            second.message
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM probing_edge")
                .unwrap(),
            1,
            "a refused second window writes no edge"
        );
        let _ = std::fs::remove_dir_all(&srv.blob_dir);
    }

    /// A paused daemon refuses to open a window, for the reason it refuses a
    /// scan: the pause is bracketed silence, and a window measured inside it
    /// would read its zeros against no record. Nothing moves.
    #[test]
    fn a_paused_daemon_refuses_an_experiment() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.observing.store(false, Ordering::Release);
        let cx = test_ctx(&srv);
        let res = control_request(
            ControlCmd::StartExperiment { minutes: 1 },
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(!res.ok, "{}", res.message);
        assert_eq!(
            res.message,
            "observation is paused; resume before starting an experiment"
        );
        assert_eq!(srv.probing.tier(), ProbingTier::Active);
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM probing_edge")
                .unwrap(),
            0
        );
        assert!(srv.experiments.lock().unwrap().is_empty());
    }

    /// The window as `start_experiment` hands it to the end task, for a
    /// window the test opens by hand.
    fn opened(start_us: i64, tier_before: ProbingTier) -> ExperimentOpen {
        ExperimentOpen {
            start_us,
            requested_minutes: 1,
            tier_before,
            peer_uid: TEST_DAEMON_UID,
            start_freeze: None,
        }
    }

    /// Closing a window restores the tier in force before it with an
    /// `experiment-end` edge — written even when that restoration changes
    /// nothing — and leaves the report in memory and in the `experiment`
    /// table, with every count that could not be taken named in it, the
    /// ring's filter recorded, and no boundary row inside the window.
    #[tokio::test]
    async fn finishing_an_experiment_restores_the_tier_and_records_the_report() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.blob_dir = temp_dir("experiment-finish");
        srv.probing.set(ProbingTier::Passive);
        let start_us = types::now_us() - 30_000_000;
        let id = experiment_id(start_us);

        finish_experiment(
            srv.experiment_handles(),
            id.clone(),
            opened(start_us, ProbingTier::Passive),
        )
        .await;

        assert_eq!(srv.probing.tier(), ProbingTier::Passive);
        let t = srv
            .store
            .query_table("SELECT tier, reason FROM probing_edge")
            .unwrap();
        assert_eq!(
            t.rows,
            vec![vec!["passive".to_string(), "experiment-end".to_string()]],
            "an already-passive daemon still marks the window's end"
        );

        let record = srv
            .store
            .experiment(&id)
            .unwrap()
            .expect("the report is durable");
        assert_eq!(record.start_us, start_us);
        assert_eq!(record.tier_before, ProbingTier::Passive);
        assert_eq!(record.freeze_start_dir, None);
        assert_eq!(record.freeze_end_dir, None, "no ring: nothing was copied");
        let from_table = net_observer_ipc::experiment_table_from_json(&record.report_json).unwrap();

        let live = match experiment_in_memory(&srv.experiments, &id) {
            Some(Response::Table(t)) => t,
            other => panic!("a finished window answers its table: {other:?}"),
        };
        assert_eq!(live, from_table, "memory and record render the same table");
        assert_eq!(live.columns, vec!["key".to_string(), "value".to_string()]);
        let cell = |k: &str| {
            live.rows
                .iter()
                .find(|r| r[0] == k)
                .map(|r| r[1].clone())
                .unwrap_or_else(|| panic!("no row {k}"))
        };
        assert_eq!(cell("id"), id);
        assert_eq!(cell("tier_before"), "passive");
        assert_eq!(
            cell("tier_at_end"),
            "passive (restored from the window's passive)"
        );
        assert_eq!(cell("requested_minutes"), "1");
        assert_eq!(cell("machine_slept"), "no");
        assert_eq!(cell("ring_filter"), srv.ring_filter);
        assert_eq!(cell("freeze_start_dir"), "none");
        assert_eq!(cell("freeze_end_dir"), "none");
        assert_eq!(cell("own_mac"), "unreadable");
        assert_eq!(cell("our_icmp_echo"), "not counted: own MAC unreadable");
        assert_eq!(cell("route_events"), "0");
        assert_eq!(cell("pauses_inside_window"), "0");
        assert_eq!(cell("probing_edges_inside_window"), "0");
        assert!(
            cell("notes").contains("end freeze: pcap ring not running"),
            "{}",
            cell("notes")
        );
        assert!(
            cell("notes").contains("own MAC unreadable"),
            "{}",
            cell("notes")
        );
        assert!(
            cell("verdict").starts_with("our ICMP echo requests in the ring: not counted"),
            "{}",
            cell("verdict")
        );
        assert!(!cell("verdict").contains("silent"), "{}", cell("verdict"));

        // A window that finished is not a running one: a new window may open.
        let cx = test_ctx(&srv);
        let next = control_request(
            ControlCmd::StartExperiment { minutes: 1 },
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(next.ok, "{}", next.message);
        let _ = std::fs::remove_dir_all(&srv.blob_dir);
    }

    /// An operator's `probe active` inside the window is theirs to keep: the
    /// closing edge marks the end without moving the tier, and the report
    /// names the switch and the skipped restore — with a window opened from
    /// passive, where an unconditional restore would have flipped the
    /// operator's `active` back.
    #[tokio::test]
    async fn an_operator_switch_inside_the_window_is_kept_and_named() {
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.blob_dir = temp_dir("experiment-operator-moved");
        srv.probing.set(ProbingTier::Passive);
        let cx = test_ctx(&srv);

        let res = control_request(
            ControlCmd::StartExperiment { minutes: 1 },
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(res.message.contains("(was passive)"), "{}", res.message);
        let start_us: i64 = srv
            .store
            .query_table("SELECT ts_us FROM probing_edge WHERE reason = 'experiment'")
            .unwrap()
            .rows[0][0]
            .parse()
            .unwrap();
        let id = experiment_id(start_us);

        // The operator, mid-window.
        let moved = control_request(
            ControlCmd::SetProbing(ProbingTier::Active),
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(moved.ok, "{}", moved.message);
        let moved_at: i64 = srv
            .store
            .query_table("SELECT ts_us FROM probing_edge WHERE reason = 'control'")
            .unwrap()
            .rows[0][0]
            .parse()
            .unwrap();
        assert!(moved_at >= start_us);

        // The end task, run by hand instead of after the sleep.
        finish_experiment(
            srv.experiment_handles(),
            id.clone(),
            opened(start_us, ProbingTier::Passive),
        )
        .await;

        assert_eq!(
            srv.probing.tier(),
            ProbingTier::Active,
            "the operator's choice stands; an unconditional restore would have flipped it back"
        );
        let t = srv
            .store
            .query_table("SELECT tier, reason FROM probing_edge ORDER BY ts_us")
            .unwrap();
        assert_eq!(
            t.rows,
            vec![
                vec!["passive".to_string(), "experiment".to_string()],
                vec!["active".to_string(), "control".to_string()],
                vec!["active".to_string(), "experiment-end".to_string()],
            ],
            "the closing edge marks the end at the tier found"
        );
        let live = match experiment_in_memory(&srv.experiments, &id) {
            Some(Response::Table(t)) => t,
            other => panic!("a finished window answers its table: {other:?}"),
        };
        let cell = |k: &str| {
            live.rows
                .iter()
                .find(|r| r[0] == k)
                .map(|r| r[1].clone())
                .unwrap_or_else(|| panic!("no row {k}"))
        };
        // The instant is a clock on the human rows, never a raw epoch.
        let moved_at_clock = types::local_instant(moved_at);
        assert_eq!(
            cell("tier_at_end"),
            format!("active (changed by the operator at {moved_at_clock}; restore skipped)")
        );
        assert_eq!(
            cell("probing_edges_inside_window"),
            format!("1 ({moved_at_clock} active (control))")
        );
        assert!(
            cell("verdict").contains(&format!(
                "the tier was moved inside the window at {moved_at_clock}"
            )),
            "{}",
            cell("verdict")
        );
        assert_eq!(
            cell("pauses_inside_window"),
            "0",
            "collection was on at the start and stayed on"
        );
        let _ = std::fs::remove_dir_all(&srv.blob_dir);
    }

    /// A ring that is running is frozen at both ends into the window's own
    /// directories, each copied file gets a `blob_ref` row against the
    /// window's id, and the report names both directories.
    #[tokio::test]
    async fn an_experiments_freezes_are_recorded_as_blobs_and_named() {
        struct TwoFiles;
        impl crate::pipeline::PcapFreezer for TwoFiles {
            fn freeze(&self, dest_dir: &Path) -> Vec<std::path::PathBuf> {
                std::fs::create_dir_all(dest_dir).unwrap();
                let mut out = Vec::new();
                for name in ["ring.pcap0", "ring.pcap1"] {
                    let p = dest_dir.join(name);
                    // A classic pcap header and no record: readable, empty.
                    let mut header = vec![0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00];
                    header.extend_from_slice(&[0u8; 8]);
                    header.extend_from_slice(&262_144u32.to_le_bytes());
                    header.extend_from_slice(&1u32.to_le_bytes());
                    std::fs::write(&p, header).unwrap();
                    out.push(p);
                }
                out
            }
        }
        let mut srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        srv.blob_dir = temp_dir("experiment-freezes");
        srv.freezer = Arc::new(PcapRingSlot::with_ring(
            Arc::new(TwoFiles) as Arc<dyn crate::pipeline::PcapFreezer>
        ));
        let cx = test_ctx(&srv);

        let res = control_request(
            ControlCmd::StartExperiment { minutes: 1 },
            Some(TEST_DAEMON_UID),
            &cx,
        );
        assert!(res.ok, "{}", res.message);
        assert!(
            res.message.contains("froze 2 pcap file(s) at the start"),
            "{}",
            res.message
        );
        let start_us: i64 = srv
            .store
            .query_table("SELECT ts_us FROM probing_edge WHERE reason = 'experiment'")
            .unwrap()
            .rows[0][0]
            .parse()
            .unwrap();
        let id = experiment_id(start_us);
        let start_dir = srv
            .blob_dir
            .join(format!("freeze-experiment-{start_us}-start"));
        let start_paths = vec![start_dir.join("ring.pcap0"), start_dir.join("ring.pcap1")];

        finish_experiment(
            srv.experiment_handles(),
            id.clone(),
            ExperimentOpen {
                start_freeze: Some((start_dir.clone(), start_paths)),
                ..opened(start_us, ProbingTier::Active)
            },
        )
        .await;

        let blobs = srv
            .store
            .query_table(&format!(
                "SELECT id, kind, path FROM blob_ref WHERE incident_id = '{id}' ORDER BY id"
            ))
            .unwrap();
        assert_eq!(blobs.rows.len(), 4, "{:?}", blobs.rows);
        assert!(blobs.rows.iter().all(|r| r[1] == "pcap"));
        assert!(
            blobs
                .rows
                .iter()
                .any(|r| r[0] == format!("{id}-pcap-start-0"))
        );
        assert!(
            blobs
                .rows
                .iter()
                .any(|r| r[0] == format!("{id}-pcap-end-1"))
        );
        assert!(
            blobs.rows.iter().any(|r| r[2].ends_with("-end/ring.pcap0")),
            "{:?}",
            blobs.rows
        );

        let record = srv.store.experiment(&id).unwrap().expect("durable");
        assert_eq!(
            record.freeze_start_dir.as_deref(),
            Some(start_dir.display().to_string().as_str())
        );
        assert!(
            record
                .freeze_end_dir
                .as_deref()
                .is_some_and(|d| d.ends_with(&format!("freeze-experiment-{start_us}-end"))),
            "{:?}",
            record.freeze_end_dir
        );
        let live = match experiment_in_memory(&srv.experiments, &id) {
            Some(Response::Table(t)) => t,
            other => panic!("a finished window answers its table: {other:?}"),
        };
        let cell = |k: &str| {
            live.rows
                .iter()
                .find(|r| r[0] == k)
                .map(|r| r[1].clone())
                .unwrap_or_else(|| panic!("no row {k}"))
        };
        assert_eq!(cell("freeze_start_dir"), start_dir.display().to_string());
        assert_eq!(cell("frames_pcap_start"), "0");
        assert_eq!(cell("frames_pcap_end"), "0");
        let _ = std::fs::remove_dir_all(&srv.blob_dir);
    }

    /// An unauthorised peer cannot reach the new self-control commands either:
    /// the peer gate runs before the class check, for every variant.
    #[test]
    fn new_self_control_commands_still_need_an_authorised_peer() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        for cmd in [
            ControlCmd::SetProbing(ProbingTier::Passive),
            ControlCmd::FreezePcap,
        ] {
            let res = control_request(cmd.clone(), None, &cx);
            assert!(!res.ok, "{cmd:?} must be refused without peer credentials");
            assert!(res.message.contains("control refused"));
        }
        assert_eq!(
            srv.probing.tier(),
            ProbingTier::Active,
            "the tier must not move"
        );
    }

    /// The D1↔D3 anti-drift test: one real edge produces exactly ONE durable
    /// boundary row and exactly ONE realtime frame, and the two describe the same
    /// transition (same `ts_us`, same state, same peer).
    #[test]
    fn set_observing_edge_writes_one_row_and_publishes_one_frame() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let mut rx = srv.events_tx.subscribe();
        let cx = test_ctx(&srv);

        let res = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(res.ok);
        assert_eq!(res.message, "observing off");

        // Sink 1: exactly one durable row, attributable to the authorised peer.
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            1
        );
        let row_ts = srv
            .store
            .query_scalar_i64("SELECT ts_us FROM observing_edge")
            .unwrap();
        // The pause also records the session's own end — for the LATER resume
        // to close the incident this pause interrupted at, not at the
        // resume's own `ts_us` (realm net-observer, node #124).
        assert_eq!(
            srv.session_end_us.load(Ordering::Acquire),
            row_ts,
            "a pause must publish the session's end for the pipeline to close against"
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT peer_uid FROM observing_edge")
                .unwrap(),
            i64::from(TEST_DAEMON_UID)
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM observing_edge WHERE observing = false")
                .unwrap(),
            1
        );

        // Sink 2: exactly one frame on the bus, describing the same transition.
        let frame = rx.try_recv().expect("an edge must publish one frame");
        let decoded: StreamFrame = serde_json::from_slice(frame.bytes()).unwrap();
        match decoded {
            StreamFrame::Observing(edge) => {
                assert_eq!(
                    edge.ts_us, row_ts,
                    "row and frame disagree on the timestamp"
                );
                assert!(!edge.observing);
                assert_eq!(edge.peer_uid, Some(TEST_DAEMON_UID));
            }
            other => panic!("expected an Observing frame, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "one edge must publish exactly one frame"
        );
    }

    /// A `SetObserving` that does not change the state is not an edge: no row, no
    /// frame — a no-op click must not manufacture a gap in the record. It still
    /// reports success, because the requested state does hold.
    #[test]
    fn repeat_set_observing_writes_nothing_and_publishes_nothing() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let mut rx = srv.events_tx.subscribe();
        let cx = test_ctx(&srv);

        let first = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(first.ok);
        let _ = rx.try_recv().expect("the first call is a real edge");

        let second = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(second.ok, "a no-op still reports the requested state");
        assert_eq!(second.message, "observing off");
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            1,
            "a no-op must not write a second boundary row"
        );
        assert!(
            rx.try_recv().is_err(),
            "a no-op must not publish a second frame"
        );
    }

    /// The resume epoch is published only on a RESUME edge: `pipeline::run` keys
    /// its window clear off this value moving, so a pause must not move it.
    #[test]
    fn resume_edge_publishes_the_resume_epoch() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);

        let off = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(off.ok);
        assert_eq!(
            srv.resume_at_us.load(Ordering::Acquire),
            0,
            "a pause is not a resume and must not move the resume epoch"
        );
        let session_end_at_pause = srv.session_end_us.load(Ordering::Acquire);
        assert!(
            session_end_at_pause > 0,
            "a pause must record the session's end for the eventual resume to close against"
        );

        let on = control_request(ControlCmd::SetObserving(true), Some(TEST_DAEMON_UID), &cx);
        assert!(on.ok);
        assert!(
            srv.resume_at_us.load(Ordering::Acquire) > 0,
            "a resume must publish its epoch for the pipeline to observe"
        );
        assert_eq!(
            srv.session_end_us.load(Ordering::Acquire),
            session_end_at_pause,
            "a resume does not itself end a session; it must not move session_end_us"
        );
    }

    /// D4: over the cap the daemon refuses with ONE decodable
    /// `StreamFrame::Error` rather than a bare close a client cannot distinguish
    /// from a crash — and a refused subscription consumes no slot.
    #[tokio::test]
    async fn subscriber_cap_refuses_with_a_decodable_error() {
        let (events_tx, _rx) = broadcast::channel::<EncodedFrame>(16);
        let observing = AtomicBool::new(true);
        let probing = ProbingState::new(ProbingTier::Active);
        // Cap of 1, already taken.
        let subscribers = Arc::new(AtomicUsize::new(1));

        let (client, mut server) = tokio::io::duplex(4096);
        let mut rd = tokio::io::empty();
        stream_events(
            &mut rd,
            &mut server,
            None,
            StreamCtx {
                events_tx: &events_tx,
                observing: &observing,
                probing: &probing,
                subscribers: &subscribers,
                max_subscribers: 1,
                refusals: &RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
            },
        )
        .await
        .unwrap();
        drop(server);

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let frame: StreamFrame = serde_json::from_str(&line).unwrap();
        match frame {
            StreamFrame::Error(e) => {
                assert_eq!(e.code, StreamErrorCode::TooManySubscribers);
                assert!(!e.message.is_empty());
            }
            other => panic!("expected an Error frame, got {other:?}"),
        }
        assert_eq!(
            subscribers.load(Ordering::Acquire),
            1,
            "a refused subscription must not consume a slot"
        );
    }

    /// A hole in the stream is stream-integrity information, not an event: a
    /// subscriber filtered to one kind must still be told it lost frames, or it
    /// renders a contiguous timeline across a real gap.
    #[tokio::test]
    async fn gap_frame_is_delivered_to_a_filtered_subscriber() {
        // A tiny bus so a burst the server has not been polled for overruns it.
        let (events_tx, rx) = broadcast::channel::<EncodedFrame>(2);
        // Only the server's own receiver may exist, or the burst below would be
        // retained for this one too.
        drop(rx);
        let observing = Arc::new(AtomicBool::new(true));
        let probing = Arc::new(ProbingState::new(ProbingTier::Active));
        let subscribers = Arc::new(AtomicUsize::new(0));

        let (client, server) = tokio::io::duplex(64 * 1024);
        let tx = events_tx.clone();
        let obs = Arc::clone(&observing);
        let tier = Arc::clone(&probing);
        let subs = Arc::clone(&subscribers);
        let task = tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            stream_events(
                &mut rd,
                &mut wr,
                Some(vec![EventKind::Route]),
                StreamCtx {
                    events_tx: &tx,
                    observing: &obs,
                    probing: &tier,
                    subscribers: &subs,
                    max_subscribers: 8,
                    refusals: &RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
                },
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        // The ack: reading it proves the server's receiver exists and the task is
        // parked in `select!`.
        reader.read_line(&mut line).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<StreamFrame>(&line).unwrap(),
            StreamFrame::Ready(_)
        ));

        // A burst with no `.await` in it: on the current-thread test runtime the
        // server task cannot be polled, so it is guaranteed to fall behind.
        for i in 0..8 {
            let frame = EncodedFrame::encode(&StreamFrame::Event(Event::Host(HostSample {
                ts_us: i,
                load1: 0.0,
                load5: 0.0,
                load15: 0.0,
                disk_used_pct: None,
                disk_free_mb: None,
                swap_used_mb: None,
            })))
            .unwrap();
            events_tx.send(frame).unwrap();
        }

        // Every event is a `Host`, which this subscriber filtered out — so the
        // only frame that can arrive is the gap.
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        match serde_json::from_str::<StreamFrame>(&line).unwrap() {
            StreamFrame::Gap(g) => assert!(g.skipped > 0, "a gap must report what was lost"),
            other => panic!("expected a Gap frame, got {other:?}"),
        }

        task.abort();
    }

    /// D3(b): the mandatory ack carries the daemon's CURRENT collection state and
    /// echoes the filter it accepted, so a fresh subscriber never has to infer
    /// "paused" from silence.
    #[tokio::test]
    async fn subscribe_ack_reports_the_current_observing_state() {
        let (events_tx, _rx) = broadcast::channel::<EncodedFrame>(16);
        let observing = Arc::new(AtomicBool::new(false));
        // Passive, so the ack is seen to carry the tier the daemon holds
        // rather than the wire default (`Active`).
        let probing = Arc::new(ProbingState::new(ProbingTier::Passive));
        let subscribers = Arc::new(AtomicUsize::new(0));

        let (client, server) = tokio::io::duplex(4096);
        let tx = events_tx.clone();
        let obs = Arc::clone(&observing);
        let tier = Arc::clone(&probing);
        let subs = Arc::clone(&subscribers);
        let task = tokio::spawn(async move {
            let (mut rd, mut wr) = tokio::io::split(server);
            stream_events(
                &mut rd,
                &mut wr,
                Some(vec![EventKind::Route]),
                StreamCtx {
                    events_tx: &tx,
                    observing: &obs,
                    probing: &tier,
                    subscribers: &subs,
                    max_subscribers: 8,
                    refusals: &RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
                },
            )
            .await
        });

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        match serde_json::from_str::<StreamFrame>(&line).unwrap() {
            StreamFrame::Ready(ready) => {
                assert!(!ready.observing, "the ack must report the paused state");
                assert_eq!(
                    ready.probing,
                    ProbingTier::Passive,
                    "the ack must report the tier in force"
                );
                assert_eq!(ready.kinds, Some(vec![EventKind::Route]));
            }
            other => panic!("expected a Ready ack as the first frame, got {other:?}"),
        }

        task.abort();
    }

    /// End-to-end streaming subscription over a real `UnixListener`: a `Subscribe`
    /// connection is held open and streamed filtered frames pushed on the bus
    /// (push, not poll). The client subscribes once filtered to `Route`; a `Host`
    /// event is dropped server-side by the filter while a `Route` event is
    /// delivered on the same held-open connection.
    ///
    /// There is deliberately NO wait on `events_tx.receiver_count()` here: the
    /// `Ready` ack `net_observer_ipc::subscribe` consumes is written only *after* the
    /// daemon created its receiver, so publishing the instant `subscribe` returns
    /// must reach this subscriber. That absent spin loop IS the regression test
    /// for the old publish-before-subscribe window.
    #[tokio::test]
    async fn serve_streams_filtered_subscription_events() {
        let dir = temp_dir("sub");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        let events_tx = srv.events_tx.clone();
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        // Open a live subscription filtered to Route only, on a blocking thread
        // (the client is deliberately tokio-free).
        let sp = sock_str.clone();
        let sub = tokio::task::spawn_blocking(move || {
            net_observer_ipc::subscribe(&sp, Some(&[EventKind::Route]))
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(sub.ready().kinds, Some(vec![EventKind::Route]));

        // A Host event is filtered out server-side; a Route event passes.
        events_tx
            .send(
                EncodedFrame::encode(&StreamFrame::Event(Event::Host(HostSample {
                    ts_us: 1,
                    load1: 0.0,
                    load5: 0.0,
                    load15: 0.0,
                    disk_used_pct: None,
                    disk_free_mb: None,
                    swap_used_mb: None,
                })))
                .unwrap(),
            )
            .unwrap();
        events_tx
            .send(
                EncodedFrame::encode(&StreamFrame::Event(Event::Route(RouteEvent {
                    ts_us: 7,
                    kind: "iface".into(),
                    iface: Some("en0".into()),
                    detail: "up".into(),
                })))
                .unwrap(),
            )
            .unwrap();

        // The first frame after the ack is the Route event (Host filtered).
        let frame = tokio::task::spawn_blocking(move || {
            let mut sub = sub;
            sub.next()
        })
        .await
        .unwrap()
        .expect("subscription should yield a frame")
        .expect("frame should decode");
        match frame {
            StreamFrame::Event(Event::Route(r)) => assert_eq!(r.ts_us, 7),
            other => panic!("expected a Route event frame, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A subscriber that goes away while the stream is *quiet* must still be
    /// noticed: nothing is ever published here, so the write path never runs and
    /// only the watched read half can see the client's FIN. Dropping the client
    /// must therefore end the server's stream task and release its broadcast
    /// receiver (otherwise every open/close of the bar's events window leaks a
    /// task, a receiver and an fd).
    #[tokio::test]
    async fn serve_drops_subscription_when_client_disconnects() {
        let dir = temp_dir("eof");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        let events_tx = srv.events_tx.clone();
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let sub = tokio::task::spawn_blocking(move || net_observer_ipc::subscribe(&sp, None))
            .await
            .unwrap()
            .unwrap();
        // No spin loop: the ack the client already consumed proves the server's
        // receiver exists.
        assert_eq!(
            events_tx.receiver_count(),
            1,
            "the ack must not be written before the receiver exists"
        );

        // Client goes away. No event is ever published, so the FIN on the read
        // half is the only signal the server can act on.
        drop(sub);

        for _ in 0..200 {
            if events_tx.receiver_count() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            events_tx.receiver_count(),
            0,
            "server kept the subscription alive after the client disconnected"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The throttle itself, driven by INJECTED [`Instant`]s so nothing sleeps: the
    /// first event is always reported (a genuine misconfiguration stays loud), a
    /// burst inside the window is counted rather than transcribed, and the next
    /// line carries what the window swallowed. A flood must stay countable, never
    /// silent — "SKIP, never silence" applied to the log itself.
    #[test]
    fn rate_limited_log_reports_the_first_then_aggregates() {
        let lim = RateLimitedLog::new(REFUSAL_LOG_INTERVAL);
        let t0 = Instant::now();

        assert_eq!(
            lim.record(t0),
            Some(Burst {
                suppressed: 0,
                total: 1
            }),
            "the first event must always be reported"
        );
        for i in 1..=4u64 {
            assert_eq!(
                lim.record(t0 + Duration::from_secs(i)),
                None,
                "a burst inside the window must not log"
            );
        }
        assert_eq!(
            lim.record(t0 + REFUSAL_LOG_INTERVAL),
            Some(Burst {
                suppressed: 4,
                total: 6
            }),
            "the next line must report what the window swallowed"
        );
    }

    /// The refusal path is actually WIRED to the limiter — asserted without
    /// capturing tracing output, by observing the budget the refusal consumed: a
    /// limiter that has already logged returns `None` for the next event inside
    /// its window. A refusal that bypassed the limiter would leave it fresh and
    /// this read would be `Some(..)`.
    #[test]
    fn a_refused_control_request_consumes_the_log_budget() {
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        let result = control_request(ControlCmd::SetObserving(false), Some(NOT_A_REAL_UID), &cx);
        assert!(!result.ok, "an unlisted uid must be refused");
        assert!(
            srv.control_refusals.record(Instant::now()).is_none(),
            "the refusal path must go through the rate limiter"
        );
    }

    /// The accept-time connection cap: a connection over it is closed rather than
    /// served, and its slot is released the instant the holding task ends (not at
    /// the next accept). Only the CONNECTION cap can refuse here —
    /// `max_subscribers` stays at its production value and the read timeout stays
    /// long.
    #[tokio::test]
    async fn serve_refuses_connections_over_the_cap() {
        let dir = temp_dir("conncap");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let mut srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        srv.max_connections = 1;
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        // Take the single slot with a real held-open subscription. The `Ready` ack
        // `subscribe` consumes proves the connection was accepted and parked, so
        // the assertion below cannot race the accept.
        let sp = sock_str.clone();
        let sub = tokio::task::spawn_blocking(move || net_observer_ipc::subscribe(&sp, None))
            .await
            .unwrap()
            .unwrap();

        // Over the cap: closed, not served. `is_err()` rather than a specific
        // kind — a bare EOF surfaces as `UnexpectedEof` or `BrokenPipe` depending
        // on how far the write got.
        let sp = sock_str.clone();
        let refused =
            tokio::task::spawn_blocking(move || net_observer_ipc::query(&sp, &Request::Status))
                .await
                .unwrap();
        assert!(
            refused.is_err(),
            "a connection over the cap is closed, not served"
        );

        // Releasing the slot happens on task end, so a retry must eventually
        // succeed — the same bounded-poll idiom `wait_for_socket` uses.
        drop(sub);
        let mut served = false;
        for _ in 0..200 {
            let sp = sock_str.clone();
            if tokio::task::spawn_blocking(move || net_observer_ipc::query(&sp, &Request::Status))
                .await
                .unwrap()
                .is_ok()
            {
                served = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            served,
            "the connection slot must be released when the holding task ends"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A connection that never speaks must not camp on a slot, an fd and a task
    /// for ever: the daemon closes it when the initial-read budget expires. The
    /// assertion is `Ok(Ok(0))` — a SERVER-side close observed by the client, not
    /// a client-side give-up (which would be the outer timeout firing).
    #[tokio::test]
    async fn serve_closes_a_connection_that_never_sends_a_request() {
        let dir = temp_dir("readtimeout");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let mut srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        srv.request_timeout = Duration::from_millis(50);
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let mut stream = UnixStream::connect(&sock_str).await.unwrap();
        // Send NOTHING. The 2 s guard is far longer than the 50 ms budget, so a
        // clean EOF here can only be the server timing the read out.
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
        assert!(
            matches!(&read, Ok(Ok(0))),
            "a silent connection must be closed by the server, got {read:?}"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Item 5, refusal arm: the daemon acts on the REAL peer uid read from the
    /// socket, not a hardcoded one.
    ///
    /// `console` is pinned to "no console session", so the only clauses left are
    /// root, `daemon_uid` (deliberately set to a uid no account holds) and
    /// `control_uids` (empty) — a refusal can therefore come from the peer gate
    /// and nowhere else.
    ///
    /// Honest limit: server and client share this process, so `Some(geteuid())`
    /// hardcoded at the lookup site would be indistinguishable from the real
    /// lookup HERE — that one substitution is covered by
    /// `control_from_an_injected_peer_uid_is_*`, which injects a uid no account
    /// holds through the policy's lookup hook. What this pair uniquely covers is
    /// the REAL `getpeereid` path end to end, including every constant substituted
    /// INSIDE [`peer_uid_of`] itself, which the injected pair overrides and cannot
    /// see: `Some(0)` authorises this arm via the root clause and stamps
    /// `peer_uid = 0` in the acceptance arm; `None` fails both (wrong refusal
    /// message here, a refused acceptance there); any other literal fails the
    /// `contains` assertion below.
    #[tokio::test]
    async fn control_over_a_real_socket_is_refused_for_an_unlisted_peer_uid() {
        // A hard failure, deliberately not a skip: `if root { return; }` prints
        // `ok` and would silently retire the repo's only end-to-end proof of the
        // peer gate on exactly the machine (a root shell) where the daemon
        // actually runs. AGENTS.md says the suite needs no root, so `sudo cargo
        // test` is operator error, and the failure must say so.
        assert_ne!(
            own_uid(),
            ROOT_UID,
            "run the suite unprivileged: as root every uid is authorised and this test cannot discriminate \
             — the injected-peer pair (control_from_an_injected_peer_uid_is_*) covers the policy at any uid; \
             THIS pair covers the real getpeereid lookup and needs an unprivileged process"
        );
        assert_ne!(
            own_uid(),
            NOT_A_REAL_UID,
            "the daemon-uid clause must not accidentally authorise this test's peer"
        );

        let dir = temp_dir("peer-refused");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let srv = test_server(&sock_str, test_acting(), NOT_A_REAL_UID);
        let observing = Arc::clone(&srv.observing);
        let store = Arc::clone(&srv.store);
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let response = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(&sp, &Request::Control(ControlCmd::SetObserving(false)))
        })
        .await
        .unwrap()
        .unwrap();
        let r = match response {
            Response::Control(r) => r,
            other => panic!("expected a Control response, got {other:?}"),
        };

        assert!(!r.ok, "an unlisted peer uid must be refused");
        assert!(
            r.message.contains(&own_uid().to_string()),
            "the refusal must name the REAL peer uid, got: {}",
            r.message
        );
        assert!(
            observing.load(Ordering::Acquire),
            "a refused control must not touch the observing flag"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            0,
            "a refused pause must leave no boundary row behind"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Item 5, acceptance arm: the same end-to-end path, differing ONLY in
    /// `control_uids`, must authorise the real peer AND attribute the boundary row
    /// to it. See the refusal arm above for the policy setup and for the one case
    /// a single-process test cannot distinguish.
    #[tokio::test]
    async fn control_over_a_real_socket_is_accepted_for_a_listed_peer_uid() {
        // A hard failure, deliberately not a skip: `if root { return; }` prints
        // `ok` and would silently retire the repo's only end-to-end proof of the
        // peer gate on exactly the machine (a root shell) where the daemon
        // actually runs. AGENTS.md says the suite needs no root, so `sudo cargo
        // test` is operator error, and the failure must say so.
        assert_ne!(
            own_uid(),
            ROOT_UID,
            "run the suite unprivileged: as root every uid is authorised and this test cannot discriminate \
             — the injected-peer pair (control_from_an_injected_peer_uid_is_*) covers the policy at any uid; \
             THIS pair covers the real getpeereid lookup and needs an unprivileged process"
        );
        assert_ne!(
            own_uid(),
            NOT_A_REAL_UID,
            "the daemon-uid clause must not accidentally authorise this test's peer"
        );

        let dir = temp_dir("peer-accepted");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let mut srv = test_server(&sock_str, test_acting(), NOT_A_REAL_UID);
        // The ONLY difference from the refusal arm.
        srv.policy.control_uids = vec![own_uid()];
        let observing = Arc::clone(&srv.observing);
        let store = Arc::clone(&srv.store);
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let response = tokio::task::spawn_blocking(move || {
            net_observer_ipc::query(&sp, &Request::Control(ControlCmd::SetObserving(false)))
        })
        .await
        .unwrap()
        .unwrap();
        let r = match response {
            Response::Control(r) => r,
            other => panic!("expected a Control response, got {other:?}"),
        };

        assert!(r.ok, "a listed peer uid must be authorised: {}", r.message);
        assert!(
            !observing.load(Ordering::Acquire),
            "an authorised pause must flip the observing flag"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT peer_uid FROM observing_edge")
                .unwrap(),
            i64::from(own_uid()),
            "the boundary row must attribute the pause to the REAL peer uid, not a constant"
        );

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The peer gate acts on the uid the POLICY's lookup produced, not on the uid
    /// this process happens to run as.
    ///
    /// The injected uid is what makes the claim testable at all: with server and
    /// client in one process `getpeereid(2)` and `geteuid(2)` agree, so a
    /// hardcoded `Some(geteuid())` at the lookup site reads exactly like the real
    /// lookup — while in production, where `daemon_uid` IS `geteuid()`, it would
    /// authorise EVERY peer on the group-connectable (0660 root:staff by
    /// default) socket. Driven through
    /// [`handle_conn`], because that is where the lookup lives; calling
    /// [`control_request`] directly would prove nothing about it.
    ///
    /// `!r.ok` alone does NOT discriminate — under that substitution the peer
    /// becomes `own_uid()`, which is also unauthorised here. The `contains`
    /// assertion on the injected uid is what kills it. No negative substring
    /// assertion: a short `own_uid()` can be a substring of `4294967293`.
    #[tokio::test]
    async fn control_from_an_injected_peer_uid_is_refused_when_unlisted() {
        assert_ne!(
            own_uid(),
            FOREIGN_UID,
            "the injected uid must differ from this process's own, or a hardcoded geteuid() at the lookup site would be invisible here"
        );

        let (mut client, server) = UnixStream::pair().unwrap();
        // `console` is pinned to "no session", `socket_owner_uid` is None,
        // `control_uids` is empty and `daemon_uid` is a uid no account holds — so
        // a refusal can come from the peer gate and from nowhere else.
        let mut srv = test_server("/nonexistent.sock", test_acting(), NOT_A_REAL_UID);
        // The seam: a second local account, which one process cannot otherwise
        // have.
        srv.policy.peer_uid = foreign_peer;

        let frame =
            net_observer_ipc::encode_frame(&Request::Control(ControlCmd::SetObserving(false)))
                .unwrap();
        client.write_all(&frame).await.unwrap();
        client.flush().await.unwrap();

        handle_conn(server, &srv, &Arc::new(AtomicUsize::new(0)))
            .await
            .unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let r = match serde_json::from_str::<Response>(&line).unwrap() {
            Response::Control(r) => r,
            other => panic!("expected a Control response, got {other:?}"),
        };

        assert!(!r.ok, "an unlisted peer uid must be refused");
        assert!(
            r.message.contains(&FOREIGN_UID.to_string()),
            "the refusal must name the uid the policy's lookup produced, got: {}",
            r.message
        );
        assert!(
            srv.observing.load(Ordering::Acquire),
            "a refused control must not touch the observing flag"
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            0,
            "a refused pause must leave no boundary row behind"
        );
    }

    /// The decisive arm: the same path, differing ONLY in `control_uids`, must
    /// authorise the INJECTED uid and attribute the boundary row to it.
    ///
    /// Under a hardcoded `Some(geteuid())` at the lookup site the peer becomes
    /// `own_uid()`, which matches no clause of this policy — so the request is
    /// refused and `r.ok` fails. Both arms discriminate at ANY privilege level,
    /// root included, because the uid under test is [`FOREIGN_UID`] rather than
    /// the process's own; that is what lets the real-socket pair above keep its
    /// hard unprivileged precondition without losing the policy claim.
    #[tokio::test]
    async fn control_from_an_injected_peer_uid_is_accepted_when_listed() {
        assert_ne!(
            own_uid(),
            FOREIGN_UID,
            "the injected uid must differ from this process's own, or a hardcoded geteuid() at the lookup site would be invisible here"
        );

        let (mut client, server) = UnixStream::pair().unwrap();
        let mut srv = test_server("/nonexistent.sock", test_acting(), NOT_A_REAL_UID);
        srv.policy.peer_uid = foreign_peer;
        // The ONLY difference from the refusal arm.
        srv.policy.control_uids = vec![FOREIGN_UID];

        let frame =
            net_observer_ipc::encode_frame(&Request::Control(ControlCmd::SetObserving(false)))
                .unwrap();
        client.write_all(&frame).await.unwrap();
        client.flush().await.unwrap();

        handle_conn(server, &srv, &Arc::new(AtomicUsize::new(0)))
            .await
            .unwrap();

        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let r = match serde_json::from_str::<Response>(&line).unwrap() {
            Response::Control(r) => r,
            other => panic!("expected a Control response, got {other:?}"),
        };

        assert!(r.ok, "a listed peer uid must be authorised: {}", r.message);
        assert!(
            !srv.observing.load(Ordering::Acquire),
            "an authorised pause must flip the observing flag"
        );
        assert_eq!(
            srv.store
                .query_scalar_i64("SELECT peer_uid FROM observing_edge")
                .unwrap(),
            i64::from(FOREIGN_UID),
            "the boundary row must attribute the pause to the uid the lookup produced"
        );
    }

    /// The seam's anti-neutering guard: production wires BOTH lookups to the real
    /// thing.
    ///
    /// Neutering either one at its single assignment site is green across the rest
    /// of the suite, because every test policy substitutes a stub for both:
    /// `console: || None` silently disables the console-user clause — the
    /// out-of-the-box menu-bar toggle against a root daemon — and a constant
    /// `peer_uid` authorises every peer on the group-connectable socket.
    ///
    /// [`std::ptr::fn_addr_eq`], never a bare `==`: rustc's
    /// `unpredictable_function_pointer_comparisons` is warn-by-default and this
    /// workspace builds with `-D warnings`.
    #[test]
    fn from_config_wires_the_real_console_and_peer_lookups() {
        let p = ControlPolicy::from_config(Some(7), vec![9]);
        assert_eq!(p.daemon_uid, own_uid());
        assert_eq!(p.socket_owner_uid, Some(7));
        assert_eq!(p.control_uids, vec![9]);
        assert!(
            std::ptr::fn_addr_eq(p.console, console_uid as fn() -> Option<u32>),
            "production must resolve the console user with the REAL lookup"
        );
        assert!(
            std::ptr::fn_addr_eq(p.peer_uid, peer_uid_of as fn(&UnixStream) -> Option<u32>),
            "production must read peer credentials from the socket, never a constant"
        );
    }

    /// The refusal log's VOLUME, not merely its wiring: a burst of refusals inside
    /// one [`REFUSAL_LOG_INTERVAL`] emits exactly ONE line.
    ///
    /// [`a_refused_control_request_consumes_the_log_budget`] proves the limiter is
    /// CONSULTED; nothing there can tell that apart from a caller that consults it
    /// and logs anyway, because the observable a dropped `None` changes is the
    /// number of emitted events. So the assertion has to be made at a subscriber.
    /// Exactly `1` kills both directions: `{REFUSAL_BURST}` means unbounded, `0`
    /// means the line was deleted.
    #[test]
    fn a_burst_of_refused_controls_logs_exactly_one_line() {
        let log = EventLog::default();
        let srv = test_server("/nonexistent.sock", test_acting(), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        tracing::subscriber::with_default(CountingSubscriber(log.clone()), || {
            for _ in 0..REFUSAL_BURST {
                let r = control_request(ControlCmd::SetObserving(false), Some(NOT_A_REAL_UID), &cx);
                // So the loop cannot be vacuous: every iteration really refuses.
                assert!(!r.ok, "an unlisted uid must be refused");
            }
        });
        assert_eq!(
            log.count("control request refused"),
            1,
            "{REFUSAL_BURST} refusals inside one interval must emit exactly one line, captured: {:?}",
            log.messages()
        );
    }

    /// Same property on the accept-error line. Driven through
    /// [`log_accept_error`] — the ONE rate-limited line of the four that has a
    /// production seam, because a real `accept(2)` failure needs process-global fd
    /// exhaustion, which would wreck every other test in this binary. Injected
    /// [`Instant`]s, so nothing sleeps and the whole burst provably lands inside
    /// one interval.
    #[test]
    fn a_burst_of_accept_failures_logs_exactly_one_line() {
        let log = EventLog::default();
        let limiter = RateLimitedLog::new(REFUSAL_LOG_INTERVAL);
        let t0 = Instant::now();
        tracing::subscriber::with_default(CountingSubscriber(log.clone()), || {
            for i in 0..REFUSAL_BURST as u64 {
                log_accept_error(
                    &limiter,
                    &std::io::Error::from_raw_os_error(libc::EMFILE),
                    t0 + Duration::from_secs(i),
                );
            }
        });
        assert_eq!(
            log.count("status socket accept failed"),
            1,
            "{REFUSAL_BURST} accept failures inside one interval must emit exactly one line, captured: {:?}",
            log.messages()
        );
    }

    /// Same property on the subscriber-cap line, driven end to end through
    /// [`stream_events`].
    ///
    /// [`subscriber_cap_refuses_with_a_decodable_error`] cannot assert this: it
    /// passes a FRESH limiter per call, so every call is that limiter's first
    /// event. Here ONE limiter and ONE subscriber tally span the whole burst.
    #[tokio::test]
    async fn a_burst_of_refused_subscriptions_logs_exactly_one_line() {
        // MUST stay a current-thread runtime (tokio's default): the subscriber
        // guard is THREAD-LOCAL, so a `flavor = "multi_thread"` runtime could poll
        // this future on a worker thread where nothing is installed. The failure
        // mode is a red test (0 observed, 1 expected), never a false green.
        let log = EventLog::default();
        let _guard = tracing::subscriber::set_default(CountingSubscriber(log.clone()));

        let (events_tx, _rx) = broadcast::channel::<EncodedFrame>(16);
        let observing = AtomicBool::new(true);
        let probing = ProbingState::new(ProbingTier::Active);
        // Cap of 1, already taken, so every attempt below is refused.
        let subscribers = Arc::new(AtomicUsize::new(1));
        let refusals = RateLimitedLog::new(REFUSAL_LOG_INTERVAL);

        for _ in 0..REFUSAL_BURST {
            // The client half stays BOUND for the whole call: dropped, the
            // refusal frame's write fails with `BrokenPipe` and `stream_events`
            // returns `Err` before the line is ever reached.
            let (_client, mut server) = tokio::io::duplex(4096);
            let mut rd = tokio::io::empty();
            stream_events(
                &mut rd,
                &mut server,
                None,
                StreamCtx {
                    events_tx: &events_tx,
                    observing: &observing,
                    probing: &probing,
                    subscribers: &subscribers,
                    max_subscribers: 1,
                    refusals: &refusals,
                },
            )
            .await
            .expect("a refusal writes one error frame and returns Ok");
        }

        assert_eq!(
            log.count("subscriber cap reached"),
            1,
            "{REFUSAL_BURST} refused subscriptions inside one interval must emit exactly one line, captured: {:?}",
            log.messages()
        );
    }

    /// Same property on the connection-cap line — which has no coverage of ANY
    /// kind today, so this is also the first test that the line exists.
    ///
    /// Over a real `UnixListener`, because the limiter lives inside the accept
    /// loop and is reachable no other way. The single slot is taken by a real
    /// held-open subscription: the `Ready` ack `subscribe` consumes proves the
    /// connection was accepted and parked, so the burst cannot race the accept.
    #[tokio::test]
    async fn a_burst_of_connections_over_the_cap_logs_exactly_one_line() {
        // MUST stay a current-thread runtime (tokio's default): the subscriber
        // guard is THREAD-LOCAL and `serve()` is polled by this thread. On a
        // multi_thread runtime the accept loop could run on a worker where nothing
        // is installed — a red test, never a false green.
        let log = EventLog::default();
        let _guard = tracing::subscriber::set_default(CountingSubscriber(log.clone()));

        let dir = temp_dir("connlog");
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let mut srv = test_server(&sock_str, test_acting(), TEST_DAEMON_UID);
        srv.max_connections = 1;
        let handle = tokio::spawn(srv.serve());
        wait_for_socket(&sock).await;

        let sp = sock_str.clone();
        let sub = tokio::task::spawn_blocking(move || net_observer_ipc::subscribe(&sp, None))
            .await
            .unwrap()
            .unwrap();

        for i in 0..REFUSAL_BURST {
            let mut s = UnixStream::connect(&sock_str).await.unwrap();
            let mut buf = [0u8; 1];
            // The EOF proves two things at once: the server closed the connection
            // (the `record()` call precedes `drop(stream)`), and it REFUSED rather
            // than served it — a served connection would sit on the 10 s
            // initial-read budget and blow this 2 s guard, so a raised
            // `max_connections` dies here too.
            let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
            assert!(
                matches!(&read, Ok(Ok(0))),
                "connection {i} over the cap must be closed by the server, got {read:?}"
            );
        }

        assert_eq!(
            log.count("connection cap reached"),
            1,
            "{REFUSAL_BURST} refused connections inside one interval must emit exactly one line, captured: {:?}",
            log.messages()
        );

        drop(sub);
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
