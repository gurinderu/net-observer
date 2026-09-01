//! The local API server (plan Task 2 / spec "Local API").
//!
//! `net-observerd` is the sole DuckDB owner (DuckDB takes a per-process file lock, so
//! a second opener — even read-only — is blocked while the daemon runs). Every
//! other process reads live status over this Unix-domain socket instead of
//! opening the database. The server answers entirely from the in-memory
//! [`StatusSnapshot`] the pipeline keeps current — no DB read on the request
//! path, zero contention with the writer, always live.
//!
//! The wire format is `net_observer_ipc`'s: frames are encoded with
//! `net_observer_ipc::encode_frame` (the same bytes `write_frame` produces) — one
//! newline-terminated JSON [`Request`] in, one newline-terminated JSON
//! [`Response`] out, then the connection closes. The one exception is
//! [`Request::Subscribe`], which is answered by a stream of
//! [`StreamFrame`]s instead of a single [`Response`].
//!
//! Reads are open to anyone who can connect (the default `socket_mode` is
//! deliberately permissive so the unprivileged menu-bar app can poll a root
//! daemon); *control* is not. Every `Request::Control` first passes the
//! peer-credential gate in [`control_request`] — see [`ControlPolicy`].

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use net_observer_ipc::{
    ControlCmd, ControlResult, EncodedFrame, EventKind, Gap, Ready, Request, Response,
    StatusSnapshot, StreamError, StreamErrorCode, StreamFrame,
};
use store::Store;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use types::ObservingEdge;

use crate::acting;

/// The uid `root` runs as. Always authorised for control: root can already stop
/// and reconfigure the daemon, so refusing it would be theatre.
const ROOT_UID: u32 = 0;

/// Hard cap on concurrently held-open `Subscribe` streams. A generous backstop,
/// not a tuning knob: each subscriber costs a task, an fd and a broadcast
/// receiver, and the socket is world-connectable by default (`socket_mode`
/// 0o666), so an unprivileged process must not be able to exhaust the daemon by
/// opening subscriptions in a loop. Beyond it the daemon refuses with a
/// decodable `StreamFrame::Error` rather than a bare close.
pub(crate) const MAX_SUBSCRIBERS: usize = 256;

/// Largest request frame the daemon will buffer before giving up on finding a
/// newline. The socket is world-connectable by default, so no client may grow
/// server memory by never terminating its request; an over-long frame is
/// truncated, fails to parse, and is answered `Response::Error`.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// Hard cap on concurrently handled socket connections, of ANY kind, enforced at
/// accept time. [`MAX_SUBSCRIBERS`] bounds *subscriptions*; a connection that
/// never sends a request never reaches that path at all, so without this cap a
/// local process can pin unbounded tasks, fds and 8 KiB read buffers on a socket
/// that is world-connectable by default (`socket_mode` 0o666).
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
/// The socket is world-connectable by default, so an unauthorised process can loop
/// connect+`Control` and, at one `warn!` per attempt, grow a ROOT daemon's log at
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
/// `Incidents` and `Subscribe` stay open, because the permissive default
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
    /// `geteuid()` — it would authorise EVERY local peer on the mode-0666 socket.
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
/// Everything else — an unrelated local uid on the mode-0666 socket — is
/// refused. An unidentifiable peer is refused by [`authorize_control`]: an
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
            message: format!("control refused: uid {uid} is not authorised to control net-observerd"),
        }),
        None => Err(ControlResult {
            ok: false,
            message: "control refused: peer credentials unavailable".to_string(),
        }),
    }
}

/// The authority class a [`ControlCmd`] requires — the ONE place a command's
/// gating class is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlAuthority {
    /// Benign self-control: an authorised peer, and nothing else. No external
    /// effect, so `acting.enabled` does not apply.
    SelfControl,
    /// Runs an external actuator as root: an authorised peer AND
    /// `acting.enabled`.
    Acting,
}

impl ControlAuthority {
    /// The class of `cmd`.
    ///
    /// **Exhaustive on purpose.** `ControlCmd` is deliberately not
    /// `#[non_exhaustive]`, so adding a third command fails to compile here
    /// until someone decides its class — no command can inherit the weaker gate
    /// by omission. Orthogonal to peer authorisation, which every control
    /// request passes before this function is ever reached.
    pub(crate) fn of(cmd: &ControlCmd) -> Self {
        match cmd {
            ControlCmd::SetObserving(_) => Self::SelfControl,
            ControlCmd::KickstartProxy => Self::Acting,
        }
    }
}

/// The acting (write/control) configuration handed to the socket server.
///
/// Safety invariant: `enabled` is off by default; with `enabled = false` every
/// *acting-class* control request (`ControlCmd::KickstartProxy`) is refused
/// *without running anything*. Benign self-control (`ControlCmd::SetObserving`)
/// is deliberately not gated by this switch — but it, like every control
/// request, must still pass the peer-credential gate ([`ControlPolicy`]). The
/// two are orthogonal: peer credentials answer "may this uid command the daemon
/// at all", `acting.enabled` answers "may the daemon touch the outside world".
#[derive(Debug, Clone)]
pub struct ActingConfig {
    /// Master switch for the acting class of the control path
    /// (`config.acting.enabled`).
    pub enabled: bool,
    /// The `launchctl` service target for `ControlCmd::KickstartProxy`.
    pub singbox_service: String,
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
    /// `ts_us` of the most recent RESUME edge, published here and consumed by
    /// `pipeline::run` to drop its pre-pause trigger window. `0` = never
    /// resumed.
    pub resume_at_us: Arc<AtomicI64>,
    pub snapshot: Arc<Mutex<StatusSnapshot>>,
    /// Durable sink for pause/resume boundary records.
    pub store: Arc<dyn Store + Send + Sync>,
    /// The realtime bus, carrying frames already serialised once.
    pub events_tx: broadcast::Sender<EncodedFrame>,
    /// Bounded log for control refusals — attacker-triggerable on a mode-0666
    /// socket, so the line is rate-limited and aggregated, never per attempt.
    pub control_refusals: RateLimitedLog,
    /// Same treatment for subscriber-cap refusals. `MAX_CONNECTIONS` is
    /// deliberately larger than `MAX_SUBSCRIBERS`, so a peer holding the
    /// subscriber cap can still loop connect+`Subscribe` in the remaining
    /// connection slots — one refusal each, and unthrottled that is the same
    /// root-log amplification the control path already defends against.
    pub sub_refusals: RateLimitedLog,
}

impl ApiServer {
    /// Bind the Unix-domain socket at `socket_path`, `chmod` it to `socket_mode`
    /// so an unprivileged client (the bar; the daemon runs as root) can connect,
    /// optionally `chown` it to `socket_owner_uid`, and serve [`Request`]s from
    /// the shared snapshot until the task is aborted.
    ///
    /// `acting` gates the *acting class* of the control path (e.g.
    /// `KickstartProxy`); the peer-credential [`ControlPolicy`] gates the whole
    /// of it. Only this daemon runs the actuator, and only on an explicit
    /// request — never automatically.
    ///
    /// A one-shot request (`Status`, `Incidents`, `Control`) is answered with a
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
        // The root daemon must relax the mode so the logged-in user's UI can connect.
        std::fs::set_permissions(
            &self.socket_path,
            std::fs::Permissions::from_mode(self.socket_mode),
        )?;
        // Socket hardening for the control path: when an owner uid is configured,
        // chown the socket to it (operators pair this with mode 0600 when enabling
        // acting so only the owner can send privileged commands). Best-effort: a
        // chown failure is logged but never takes the daemon down. Note this is
        // belt-and-braces only — authorisation itself is the peer-credential
        // check in `control_request`, not the socket mode.
        if let Some(uid) = self.socket_owner_uid {
            match std::os::unix::fs::chown(&self.socket_path, Some(uid), None) {
                Ok(()) => tracing::info!(uid, path = %self.socket_path, "status socket chowned"),
                Err(e) => {
                    tracing::warn!(error = %e, uid, path = %self.socket_path, "failed to chown status socket")
                }
            }
        }
        tracing::info!(
            path = %self.socket_path,
            mode = format!("{:o}", self.socket_mode),
            acting = self.acting.enabled,
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
/// One-shot requests (`Status`, `Incidents`, `Control`) are answered from the
/// in-memory snapshot with a single newline-JSON [`Response`], then the connection
/// closes. A [`Request::Subscribe`] instead holds the connection open and streams
/// [`StreamFrame`]s via [`stream_events`] until the client disconnects. The
/// snapshot lock is held only long enough to clone what a response needs — never
/// across an `.await`.
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
        Ok(Request::Control(cmd)) => {
            let cx = ControlCtx {
                policy: &srv.policy,
                acting: &srv.acting,
                observing: &srv.observing,
                resume_at_us: &srv.resume_at_us,
                snapshot: &srv.snapshot,
                store: srv.store.as_ref(),
                events_tx: &srv.events_tx,
                refusals: &srv.control_refusals,
            };
            Response::Control(control_request(cmd, peer_uid, &cx))
        }
        Err(e) => Response::Error(format!("bad request: {e}")),
    };

    let buf = net_observer_ipc::encode_frame(&response)?;
    wr.write_all(&buf).await?;
    wr.flush().await
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
/// readable: the bus it reads, the pause flag it reports, and the cap plus its
/// rate-limited refusal log.
struct StreamCtx<'a> {
    events_tx: &'a broadcast::Sender<EncodedFrame>,
    observing: &'a AtomicBool,
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

    // 3. The mandatory ack, carrying the CURRENT collection state so a fresh
    //    subscriber learns it immediately instead of inferring it from silence.
    //    `observing` is read AFTER subscribing, deliberately: an edge landing in
    //    between is then delivered twice (ack + bus frame) rather than lost, and
    //    duplication is free because the frame carries an absolute state.
    write_stream_frame(
        wr,
        &StreamFrame::Ready(Ready {
            ts_us: types::now_us(),
            kinds: kinds.clone(),
            observing: observing.load(Ordering::Acquire),
        }),
    )
    .await?;

    // A fixed one-byte probe. The read half exists only to notice a subscriber
    // that went away while the stream is quiet, and its content is never
    // inspected — so nothing a client sends can grow the daemon's memory.
    // `read_line` APPENDS, so any growable buffer here (however scoped) is an
    // unbounded-memory hole on a world-connectable socket. `AsyncReadExt::read`
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
    pub resume_at_us: &'a AtomicI64,
    pub snapshot: &'a Mutex<StatusSnapshot>,
    pub store: &'a (dyn Store + Send + Sync),
    pub events_tx: &'a broadcast::Sender<EncodedFrame>,
    /// The bounded log for the refusal line, so an unauthorised local process
    /// cannot grow a root daemon's log at its own loop rate.
    pub refusals: &'a RateLimitedLog,
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
            // Rate-limited: the socket is world-connectable by default, so an
            // unauthorised local process must not be able to grow a ROOT daemon's
            // log at its own loop rate. Never silent — suppressed refusals are
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
/// Two classes of command with different gating, decided once by
/// [`ControlAuthority::of`]:
///
/// - **`SetObserving(b)` — benign self-control, NOT gated by `acting.enabled`.**
///   It flips the observer's OWN collection on/off and, on a real edge, records
///   the boundary in both sinks (durable row + realtime frame). It never touches
///   sing-box or the network, so the acting gate does not apply — a client can
///   pause/resume collection even with acting disabled.
///
/// - **Acting-class commands (e.g. `KickstartProxy`) — gated by
///   `acting.enabled`.** Safety invariant: when acting is disabled the command is
///   refused *without running anything* — no `launchctl` (or any other actuator)
///   is ever invoked.
fn control_response(
    cmd: ControlCmd,
    authorized: PeerAuthorized,
    cx: &ControlCtx<'_>,
) -> ControlResult {
    // The acting gate is derived from ONE exhaustive classification of the
    // command set, not from a per-arm decision, so a third command cannot pick a
    // weaker gate. Peer authorisation already happened in `control_request`.
    if ControlAuthority::of(&cmd) == ControlAuthority::Acting && !cx.acting.enabled {
        return ControlResult {
            ok: false,
            message: "acting disabled".into(),
        };
    }
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
                    }
                    cx.observing.store(b, Ordering::Release);
                    snap.observing = b;

                    // ONE value, TWO sinks — built once so the DB row and the wire
                    // frame cannot drift, and stamped with one `ts_us`.
                    let edge = ObservingEdge {
                        ts_us,
                        observing: b,
                        peer_uid: Some(authorized.uid()),
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
        ControlCmd::KickstartProxy => match acting::kickstart_proxy(&cx.acting.singbox_service) {
            Ok(message) => ControlResult { ok: true, message },
            Err(message) => ControlResult { ok: false, message },
        },
    }
}

/// Clone the live snapshot, recovering the lock if a previous holder panicked.
fn snapshot_clone(snapshot: &Mutex<StatusSnapshot>) -> StatusSnapshot {
    snapshot.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_observer_ipc::{Event, IncidentSummary};
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

    fn test_acting(enabled: bool) -> ActingConfig {
        ActingConfig {
            enabled,
            singbox_service: "system/sing-box".into(),
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
            socket_mode: 0o666,
            socket_owner_uid: None,
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
            resume_at_us: Arc::new(AtomicI64::new(0)),
            snapshot: Arc::new(Mutex::new(StatusSnapshot::default())),
            store: Arc::new(store::DuckdbStore::in_memory().unwrap()),
            events_tx,
            control_refusals: RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
            sub_refusals: RateLimitedLog::new(REFUSAL_LOG_INTERVAL),
        }
    }

    /// Borrow a [`ControlCtx`] out of a test server, so the control tests exercise
    /// exactly the context `handle_conn` builds.
    fn test_ctx(srv: &ApiServer) -> ControlCtx<'_> {
        ControlCtx {
            policy: &srv.policy,
            acting: &srv.acting,
            observing: &srv.observing,
            resume_at_us: &srv.resume_at_us,
            snapshot: &srv.snapshot,
            store: srv.store.as_ref(),
            events_tx: &srv.events_tx,
            refusals: &srv.control_refusals,
        }
    }

    /// A scratch directory for a socket-bound test.
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("net-observerd-{tag}-test-{}", std::process::id()));
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

        let srv = test_server(&sock_str, test_acting(false), TEST_DAEMON_UID);
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
                wifi_capture_present: false,
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
        // An unrelated local uid on the mode-0666 socket is refused.
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
        let srv = test_server("/nonexistent.sock", test_acting(true), TEST_DAEMON_UID);
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

    /// D2: EVERY control command is peer-gated, not just the acting-class one.
    /// The `match` inside the loop is exhaustive on purpose — a third `ControlCmd`
    /// variant fails to compile until it is added here and thus asserted.
    #[test]
    fn every_control_cmd_is_refused_for_an_unauthorised_peer() {
        // No real account holds it, and `test_server` pins the console clause to
        // "no session", so nothing on any host can accidentally authorise it.
        let stranger = Some(NOT_A_REAL_UID);

        for cmd in [ControlCmd::SetObserving(false), ControlCmd::KickstartProxy] {
            // Exhaustive on purpose — a new variant breaks this arm list.
            match cmd {
                ControlCmd::SetObserving(_) | ControlCmd::KickstartProxy => {}
            }
            // Acting is ENABLED, so a refusal here can only come from the peer
            // gate, never from the acting switch.
            let srv = test_server("/nonexistent.sock", test_acting(true), 1);
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
        }
    }

    /// Safety invariant: with acting disabled, an acting-class control request is
    /// refused without running anything — exercised through the real entry point
    /// with an AUTHORISED peer, so the acting dimension is tested in isolation
    /// from the peer gate. The actuator itself is intentionally never invoked.
    #[test]
    fn control_refused_when_acting_disabled() {
        let srv = test_server("/nonexistent.sock", test_acting(false), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);
        let result = control_request(ControlCmd::KickstartProxy, Some(TEST_DAEMON_UID), &cx);
        assert!(
            !result.ok,
            "control must be refused when acting is disabled"
        );
        assert_eq!(result.message, "acting disabled");
    }

    /// `SetObserving` is benign self-control: it must succeed even with acting
    /// disabled (it is NOT gated by `acting.enabled`), flip the shared flag, and
    /// mirror the new state into the live snapshot so the switch shows reality.
    #[test]
    fn set_observing_not_gated_by_acting_and_updates_snapshot() {
        let srv = test_server("/nonexistent.sock", test_acting(false), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);

        // Pause: succeeds despite acting being disabled; flag + snapshot go false.
        let off = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(off.ok, "SetObserving must not be gated by acting");
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

    /// Every [`ControlCmd`] variant must declare its gating class explicitly, so a
    /// future third variant cannot silently default to ungated: the `match` in
    /// [`ControlAuthority::of`] is exhaustive, so adding a variant fails to
    /// compile until someone decides its class.
    #[test]
    fn every_control_cmd_variant_declares_its_gating_class() {
        for cmd in [ControlCmd::SetObserving(false), ControlCmd::KickstartProxy] {
            // Exhaustive on purpose — a new variant breaks this arm list.
            let expected = match cmd {
                ControlCmd::SetObserving(_) => ControlAuthority::SelfControl,
                ControlCmd::KickstartProxy => ControlAuthority::Acting,
            };
            assert_eq!(
                ControlAuthority::of(&cmd),
                expected,
                "{cmd:?} declares the wrong authority class"
            );
        }
    }

    /// The D1↔D3 anti-drift test: one real edge produces exactly ONE durable
    /// boundary row and exactly ONE realtime frame, and the two describe the same
    /// transition (same `ts_us`, same state, same peer).
    #[test]
    fn set_observing_edge_writes_one_row_and_publishes_one_frame() {
        let srv = test_server("/nonexistent.sock", test_acting(false), TEST_DAEMON_UID);
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
        let srv = test_server("/nonexistent.sock", test_acting(false), TEST_DAEMON_UID);
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
        let srv = test_server("/nonexistent.sock", test_acting(false), TEST_DAEMON_UID);
        let cx = test_ctx(&srv);

        let off = control_request(ControlCmd::SetObserving(false), Some(TEST_DAEMON_UID), &cx);
        assert!(off.ok);
        assert_eq!(
            srv.resume_at_us.load(Ordering::Acquire),
            0,
            "a pause is not a resume and must not move the resume epoch"
        );

        let on = control_request(ControlCmd::SetObserving(true), Some(TEST_DAEMON_UID), &cx);
        assert!(on.ok);
        assert!(
            srv.resume_at_us.load(Ordering::Acquire) > 0,
            "a resume must publish its epoch for the pipeline to observe"
        );
    }

    /// D4: over the cap the daemon refuses with ONE decodable
    /// `StreamFrame::Error` rather than a bare close a client cannot distinguish
    /// from a crash — and a refused subscription consumes no slot.
    #[tokio::test]
    async fn subscriber_cap_refuses_with_a_decodable_error() {
        let (events_tx, _rx) = broadcast::channel::<EncodedFrame>(16);
        let observing = AtomicBool::new(true);
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
        let subscribers = Arc::new(AtomicUsize::new(0));

        let (client, server) = tokio::io::duplex(64 * 1024);
        let tx = events_tx.clone();
        let obs = Arc::clone(&observing);
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
        let subscribers = Arc::new(AtomicUsize::new(0));

        let (client, server) = tokio::io::duplex(4096);
        let tx = events_tx.clone();
        let obs = Arc::clone(&observing);
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

        let srv = test_server(&sock_str, test_acting(false), TEST_DAEMON_UID);
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

        let srv = test_server(&sock_str, test_acting(false), TEST_DAEMON_UID);
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
        let srv = test_server("/nonexistent.sock", test_acting(true), TEST_DAEMON_UID);
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

        let mut srv = test_server(&sock_str, test_acting(false), TEST_DAEMON_UID);
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

        let mut srv = test_server(&sock_str, test_acting(false), TEST_DAEMON_UID);
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
    /// Acting is ENABLED and `console` is pinned to "no console session", so the
    /// only clauses left are root, `daemon_uid` (deliberately set to a uid no
    /// account holds) and `control_uids` (empty) — a refusal can therefore come
    /// from the peer gate and nowhere else.
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

        let srv = test_server(&sock_str, test_acting(true), NOT_A_REAL_UID);
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

        let mut srv = test_server(&sock_str, test_acting(true), NOT_A_REAL_UID);
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
    /// authorise EVERY local peer on the mode-0666 socket. Driven through
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
        // Acting is ENABLED, `console` is pinned to "no session",
        // `socket_owner_uid` is None, `control_uids` is empty and `daemon_uid` is
        // a uid no account holds — so a refusal can come from the peer gate and
        // from nowhere else.
        let mut srv = test_server("/nonexistent.sock", test_acting(true), NOT_A_REAL_UID);
        // The seam: a second local account, which one process cannot otherwise
        // have.
        srv.policy.peer_uid = foreign_peer;

        let frame =
            net_observer_ipc::encode_frame(&Request::Control(ControlCmd::SetObserving(false))).unwrap();
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
        let mut srv = test_server("/nonexistent.sock", test_acting(true), NOT_A_REAL_UID);
        srv.policy.peer_uid = foreign_peer;
        // The ONLY difference from the refusal arm.
        srv.policy.control_uids = vec![FOREIGN_UID];

        let frame =
            net_observer_ipc::encode_frame(&Request::Control(ControlCmd::SetObserving(false))).unwrap();
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
    /// `peer_uid` authorises every local peer on the mode-0666 socket.
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
        let srv = test_server("/nonexistent.sock", test_acting(true), TEST_DAEMON_UID);
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

        let mut srv = test_server(&sock_str, test_acting(false), TEST_DAEMON_UID);
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
