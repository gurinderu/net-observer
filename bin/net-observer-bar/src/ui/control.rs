//! Socket reads and control round-trips against `net-observerd`.

use gpui::prelude::*;
use gpui::{AsyncApp, Context, Entity};

use net_observer_ipc::{
    ControlCmd, ControlResult, DiagnosticQuery, QueryOutcome, Request, Response, ScanOptions,
    StatusSnapshot, Table,
};
use types::{ConnectionsGroupBy, ProbingTier};

use super::model::Glance;

/// Why a fetch failed — the distinction the panel must not blur.
///
/// "Daemon not reachable" is an assertion about the world, so it may only be made
/// when nothing answered. A daemon that accepts the connection and replies, but
/// whose reply we cannot use (an `Error` frame, an unexpected variant, or a decode
/// failure — e.g. a new bar against an older daemon), is *up*: reporting it as
/// offline would be a false statement, and the real message would be nowhere to be
/// seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlanceError {
    /// Nothing answered: the socket is absent, the connection was refused, or the
    /// connect/round-trip timed out. The daemon is down — the panel goes offline.
    Unreachable(String),
    /// The daemon answered but the exchange failed. It is reachable, so the panel
    /// stays online and surfaces the message.
    Protocol(String),
}

impl GlanceError {
    /// The underlying message, without the reachable/unreachable framing.
    pub fn message(&self) -> &str {
        match self {
            Self::Unreachable(m) | Self::Protocol(m) => m,
        }
    }
}

impl std::fmt::Display for GlanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Classify a transport failure from [`net_observer_ipc::query`]. Only the kinds that
/// mean "nobody answered" are [`GlanceError::Unreachable`]; everything else
/// (`InvalidData` from a frame we cannot decode, a broken pipe mid-exchange, …)
/// happened *with* a daemon on the other end.
///
/// `WouldBlock` is in the first group because it is what the query's read budget
/// expiring looks like on macOS: `SO_RCVTIMEO` running out surfaces as `EAGAIN`,
/// which the standard library maps to `WouldBlock`, not `TimedOut`. A daemon
/// that accepts the connection and never answers is "no answer" — the grey dot
/// by the owner's rule — not a bad answer (realm net-observer, node #88).
fn classify_io(e: std::io::Error) -> GlanceError {
    match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::TimedOut
        | std::io::ErrorKind::WouldBlock => GlanceError::Unreachable(e.to_string()),
        _ => GlanceError::Protocol(e.to_string()),
    }
}

/// Fetch the live [`StatusSnapshot`] from `net-observerd` over the local socket.
///
/// The bar owns no DB — the daemon does — so every refresh is a blocking
/// [`net_observer_ipc::query`] round-trip. Re-querying each tick means the glance
/// recovers on its own once the daemon comes back, and fails gracefully when it
/// is not there: a missing socket, connection-refused or a timeout map to
/// [`GlanceError::Unreachable`], which the panel surfaces as "net-observer offline"
/// and the status item as a grey dot. An `Error` frame, an unexpected variant or a
/// decode failure map to [`GlanceError::Protocol`] — the daemon is up, so the
/// panel stays online and shows the message. Either way it is retried on the next
/// tick instead of crashing.
pub fn read_fresh(socket_path: &str) -> Result<StatusSnapshot, GlanceError> {
    match net_observer_ipc::query(socket_path, &Request::Status) {
        Ok(Response::Status(snap)) => Ok(snap),
        Ok(Response::Error(msg)) => Err(GlanceError::Protocol(msg)),
        Ok(_) => Err(GlanceError::Protocol(
            "unexpected response from net-observerd".to_string(),
        )),
        Err(e) => Err(classify_io(e)),
    }
}

/// Ask `net-observerd` to turn its OWN collection on (`true`) or off (`false`) over
/// the local socket (`Control(SetObserving(on))`) and return its [`ControlResult`].
///
/// Like the other requests this maps to a `Control` command on the wire, but it is
/// benign **self-control**: it pauses/resumes the observer's own collection only —
/// it does NOT touch the proxy or the network. Like every control command, the
/// only thing the daemon checks before running it is the peer uid.
/// The daemon stays alive and the socket keeps serving while paused, so the switch
/// can turn collection back on. As with every request, a missing socket /
/// connection-refused (daemon down) or a protocol error maps to `Err(String)` so
/// the panel can surface it as a transient line instead of crashing — never a
/// panic.
/// Ask `net-observerd` to switch its probing tier over the local socket
/// (`Control(SetProbing(tier))`).
///
/// `Passive` puts nothing on the wire — every link, proxy and dns probe is
/// withheld and lands as `SKIP`, the held reference streams are closed;
/// `Active` runs every probe. Benign **self-control**, and every real switch
/// is bracketed by a durable `probing_edge` row. The daemon checks only the
/// peer uid before running it. Transport failures map to `Err(String)` for
/// the panel to surface, never a panic.
pub fn send_set_probing(socket_path: &str, tier: ProbingTier) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::SetProbing(tier))
}

/// Ask `net-observerd` to copy its pcap ring out NOW
/// (`Control(FreezePcap)`) — the same passive artifact the `gw-change` trigger
/// produces, on operator demand. A daemon with no ring running answers
/// `ok: false` with a reason, which the panel shows like any other control
/// outcome; a daemon that is not there maps to `Err(String)`.
pub fn send_freeze_pcap(socket_path: &str) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::FreezePcap)
}

/// Ask `net-observerd` to go and find who is on this segment NOW
/// (`Control(ScanNeighbors)`): a sweep of the local subnet plus an mDNS browse.
///
/// The one control action in the panel that puts packets on the wire towards
/// machines that are not this one. The daemon runs it when asked — the press is
/// the sanction, no config switch gates it (realm net-observer, node #91) — and
/// answers `ok: false` with a reason when it cannot (paused, no subnet)
/// or when the peer uid is not authorised, shown like any other control outcome.
pub fn send_scan_neighbors(socket_path: &str, opts: ScanOptions) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::ScanNeighbors(opts))
}

/// The one blocking control round-trip every control action goes through, so the
/// bar has exactly one socket client (`net_observer_ipc::query`) and one mapping
/// from its answers to a `Result`.
fn control_query(socket_path: &str, cmd: ControlCmd) -> Result<ControlResult, String> {
    match net_observer_ipc::query(socket_path, &Request::Control(cmd)) {
        Ok(Response::Control(result)) => Ok(result),
        Ok(Response::Error(msg)) => Err(msg),
        Ok(_) => Err("unexpected response from net-observerd".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

pub fn send_set_observing(socket_path: &str, on: bool) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::SetObserving(on))
}

/// The blocking half of the header toggle: read the live state, flip it, read it
/// back. Returns the control outcome and the post-toggle snapshot for
/// [`Glance::apply_toggle_result`].
///
/// **Never call this on the gpui main thread** — it is three blocking socket
/// round-trips (see the click wiring in `toggle_switch`, which runs it on the
/// background executor).
///
/// The *leading* read is the point: `SetObserving(bool)` is absolute on the wire
/// and a second controller genuinely exists (`net-observer-cli observe on|off`), so a
/// cached snapshot up to one refresh tick old is not a safe premise — a state
/// change inside that window would be silently overwritten. The target is derived
/// from the freshly-read state instead. If that read fails there is no premise, so
/// no command is sent and the error is reported on both channels (as its message
/// on the control half, as the classified [`GlanceError`] on the read half). Never
/// panics — every failure is a readable `Err`.
pub fn toggle_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let before = match read_fresh(socket_path) {
        Ok(s) => s,
        Err(e) => return (Err(e.to_string()), Err(e)),
    };
    let control = send_set_observing(socket_path, !before.observing);
    // Reflect the daemon's real observing state after the toggle.
    (control, read_fresh(socket_path))
}

/// The blocking half of the probe toggle, built exactly like
/// [`toggle_round_trip`] and for the same reason: `SetProbing(tier)` is
/// absolute on the wire and a second controller exists (`net-observer-cli
/// probe`), so the target tier is derived from a freshly-read state — the
/// OTHER tier from the one the daemon holds now — rather than from a
/// snapshot up to one refresh tick old. Never call it on the gpui main thread.
pub fn probing_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let before = match read_fresh(socket_path) {
        Ok(s) => s,
        Err(e) => return (Err(e.to_string()), Err(e)),
    };
    let control = send_set_probing(socket_path, opposite_tier(before.probing));
    (control, read_fresh(socket_path))
}

/// The tier the probe row switches to from `tier`: the other one. Named so the
/// toggle's target is a testable fact rather than an inline `if`.
pub(crate) fn opposite_tier(tier: ProbingTier) -> ProbingTier {
    match tier {
        ProbingTier::Passive => ProbingTier::Active,
        ProbingTier::Active => ProbingTier::Passive,
    }
}

/// The blocking half of the "Freeze pcap now" action: send the command, then
/// re-read the snapshot so the panel's freshness/offline state stays truthful.
/// No leading read — unlike the two toggles this command carries no state to
/// derive. Never call it on the gpui main thread.
pub fn freeze_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let control = send_freeze_pcap(socket_path);
    (control, read_fresh(socket_path))
}

/// The blocking half of the "Scan" action: send the command, then re-read the
/// snapshot so the neighbour count the panel shows is the one the scan just
/// produced. Never call it on the gpui main thread — the scan takes seconds by
/// design (a settle wait plus an mDNS budget).
pub fn scan_round_trip(
    socket_path: &str,
    opts: ScanOptions,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let control = send_scan_neighbors(socket_path, opts);
    (control, read_fresh(socket_path))
}

/// The Scan button's round-trip: the base scan (sweep + mDNS), no port rung —
/// the bottom of the audit ladder, which the map window's rungs climb from
/// here (see [`scan_round_trip_cve`]). Shaped as a bare `fn(&str)` so
/// [`spawn_control_on`] takes it.
pub fn scan_round_trip_base(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    scan_round_trip(socket_path, ScanOptions::default())
}

/// The audit ladder, one `ScanOptions` per rung, each carrying every rung below
/// it: the daemon drops a `banners` request without `ports` and a `cve` request
/// without `banners` (and says so), so a rung that did not include the ones
/// beneath it would ask for what it cannot get. (realm net-observer, node #90)
// `target`/`slow`/`sweep_max` (realm net-observer, node #154) sit outside the
// audit ladder — the bar's rung buttons ask no single host and never throttle
// (that is an operator-typed CLI thing, not a click), so every rung leaves
// them at their wire defaults.
const RUNG_PORTS: ScanOptions = ScanOptions {
    ports: true,
    banners: false,
    cve: false,
    target: None,
    slow: false,
    sweep_max: None,
};
const RUNG_BANNERS: ScanOptions = ScanOptions {
    ports: true,
    banners: true,
    cve: false,
    target: None,
    slow: false,
    sweep_max: None,
};
const RUNG_CVE: ScanOptions = ScanOptions {
    ports: true,
    banners: true,
    cve: true,
    target: None,
    slow: false,
    sweep_max: None,
};
// The ladder's shape is pinned where it is declared: a rung that dropped a
// lower one would ask for what the daemon cannot give, and that is a build
// error here rather than a dropped rung at the daemon.
const _: () = assert!(RUNG_PORTS.ports && !RUNG_PORTS.banners && !RUNG_PORTS.cve);
const _: () = assert!(RUNG_BANNERS.ports && RUNG_BANNERS.banners && !RUNG_BANNERS.cve);
const _: () = assert!(RUNG_CVE.ports && RUNG_CVE.banners && RUNG_CVE.cve);

/// The Ports rung: the base scan plus a TCP port scan of the neighbours it found.
/// Same shape as [`scan_round_trip_base`], for the same reason.
pub fn scan_round_trip_ports(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    scan_round_trip(socket_path, RUNG_PORTS)
}

/// The Banners rung: ports plus a banner grab from each open port.
pub fn scan_round_trip_banners(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    scan_round_trip(socket_path, RUNG_BANNERS)
}

/// The CVE rung: the whole ladder — banners matched against the daemon's local
/// CVE snapshot. The bar only asks; whether a rung actually runs is decided by
/// the daemon against its own dependencies, and its answer is shown verbatim.
pub fn scan_round_trip_cve(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    scan_round_trip(socket_path, RUNG_CVE)
}

/// Read the findings the daemon's record holds: every CVE hypothesised for an
/// open port, on every segment (`DiagnosticQuery::Vulns { network: None }`), as
/// the table the daemon answered with.
///
/// A blocking [`net_observer_ipc::diagnose`] round-trip — **never call it on the
/// gpui main thread** (the map window runs it on the background executor, the
/// way [`spawn_control_on`] runs a control round-trip). Every outcome that is
/// not a table becomes an `Err(String)` carrying the daemon's own words, so the
/// window shows what happened instead of a blank section: a diagnosis the daemon
/// read and could not run, a daemon built before `Request::Query` existed, or
/// a transport failure.
pub fn fetch_findings(socket_path: &str) -> Result<Table, String> {
    classify_diagnosis(
        "Vulns",
        net_observer_ipc::diagnose(socket_path, DiagnosticQuery::Vulns { network: None }),
    )
}

/// Read every neighbour the daemon's record holds, on every segment
/// (`DiagnosticQuery::Neighbors { network: None }`), as the table the daemon
/// answered with. The map folds the `announce`-sourced rows of the segment it
/// is drawing out of it at paint time (see `map::announced_neighbors`); the
/// read itself is unfiltered so a fetch made before the segment changed still
/// carries the new segment's rows (realm net-observer, node #92).
///
/// The same blocking [`net_observer_ipc::diagnose`] round-trip as
/// [`fetch_findings`], with the same rule — **never on the gpui main thread**
/// (the map window runs it on the background executor) — and the same mapping
/// of every non-table outcome to the daemon's own words.
pub fn fetch_neighbors(socket_path: &str) -> Result<Table, String> {
    classify_diagnosis(
        "Neighbors",
        net_observer_ipc::diagnose(socket_path, DiagnosticQuery::Neighbors { network: None }),
    )
}

/// Read what this machine talks to right now: the newest tick of the live
/// flow table, folded by `group_by`
/// (`DiagnosticQuery::Connections { group_by }`), as the table the daemon
/// answered with (realm net-observer, node #75).
///
/// The same blocking [`net_observer_ipc::diagnose`] round-trip as
/// [`fetch_findings`], with the same rule — **never on the gpui main thread**
/// (the connections window runs it on the background executor) — and the
/// same mapping of every non-table outcome to the daemon's own words.
pub fn fetch_connections(socket_path: &str, group_by: ConnectionsGroupBy) -> Result<Table, String> {
    classify_diagnosis(
        "Connections",
        net_observer_ipc::diagnose(socket_path, DiagnosticQuery::Connections { group_by }),
    )
}

/// The pure half of [`fetch_findings`], [`fetch_neighbors`] and
/// [`fetch_connections`]: what each outcome means for a window. `query` names the diagnosis in the line an
/// older daemon earns. Separated so the mapping is testable without a socket.
fn classify_diagnosis(
    query: &str,
    outcome: std::io::Result<QueryOutcome>,
) -> Result<Table, String> {
    match outcome {
        Ok(QueryOutcome::Table(table)) => Ok(table),
        Ok(QueryOutcome::Failed(message)) => Err(message),
        Ok(QueryOutcome::Unsupported(message)) => Err(format!(
            "daemon cannot answer {query} (older daemon): {message}"
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// One blocking control round-trip: send a command, then re-read status so the
/// panel shows what the daemon actually holds rather than what the click asked
/// for. Both halves are fallible and fail differently — the command can be
/// refused (`String`) while the follow-up read can find no daemon at all
/// (`GlanceError`) — so neither collapses into the other.
pub(crate) type ControlRoundTrip = fn(
    &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
);

/// Run one blocking control round-trip on the background executor and apply its
/// outcome to the shared model on the foreground.
///
/// The single place a control action touches the socket, for any view holding
/// the shared model: the menu's entries directly, the map window's rungs through
/// [`spawn_control_then`], which is this plus a completion hook.
///
/// The wiring stays in one place on purpose: "never block the gpui main thread",
/// "a daemon that is not there is a message, not a crash", and "the daemon's
/// refusal is surfaced verbatim" are decided once for every control button in the
/// app, not re-decided per window.
pub(crate) fn spawn_control_on<V: 'static>(
    model: &Entity<Glance>,
    cx: &mut Context<V>,
    round_trip: ControlRoundTrip,
) {
    spawn_control_then(model, cx, round_trip, |_view, _cx| {});
}

/// What a view does once a control round-trip's outcome has been applied to
/// the shared model. Runs on the foreground, on the view that spawned the
/// round-trip — if it is still there; a closed window just drops it.
pub(crate) type ControlDone<V> = fn(&mut V, &mut Context<V>);

/// [`spawn_control_on`] with a completion hook: the same round-trip, the same
/// application to the shared model, and then `after` on the view — the point at
/// which a window can lower an in-flight flag or fetch what the command may
/// have produced. The hook runs after the model has been updated, so what it
/// reads there is the outcome, never the state before it.
pub(crate) fn spawn_control_then<V: 'static>(
    model: &Entity<Glance>,
    cx: &mut Context<V>,
    round_trip: ControlRoundTrip,
    after: ControlDone<V>,
) {
    let weak = model.downgrade();
    let socket = model.read(cx).socket_path.clone();
    cx.spawn(async move |view, acx: &mut AsyncApp| {
        let (control, fresh) = acx
            .background_spawn(async move { round_trip(&socket) })
            .await;
        weak.update(acx, |g, cx| {
            g.apply_toggle_result(control, fresh);
            cx.notify();
        })
        .ok();
        view.update(acx, |v, cx| {
            after(v, cx);
            cx.notify();
        })
        .ok();
    })
    .detach();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Daemon down / socket absent must map to a graceful `Err`, never a panic —
    /// this is the "net-observer offline" path the panel renders. It is specifically
    /// `Unreachable`: nothing answered, so "daemon not reachable" is true.
    #[test]
    fn read_fresh_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let err = read_fresh(missing.to_str().unwrap())
            .expect_err("absent socket must yield an offline Err");
        assert!(
            matches!(err, GlanceError::Unreachable(_)),
            "absent socket is unreachable, not a protocol failure: {err:?}"
        );
    }

    /// Only the kinds that mean "nobody answered" are unreachable — including
    /// `WouldBlock`, the shape a macOS read budget expiring takes; a decode
    /// failure (a new bar against an older daemon) happened *with* a live daemon on
    /// the other end.
    #[test]
    fn classify_io_separates_unreachable_from_protocol() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::WouldBlock,
        ] {
            assert!(
                matches!(
                    classify_io(Error::new(kind, "nope")),
                    GlanceError::Unreachable(_)
                ),
                "{kind:?} means nothing answered"
            );
        }
        assert!(
            matches!(
                classify_io(Error::new(ErrorKind::InvalidData, "bad frame")),
                GlanceError::Protocol(_)
            ),
            "an undecodable answer still came from a live daemon"
        );
    }

    /// The observing self-control path degrades gracefully too: an absent socket
    /// (daemon down) yields an `Err`, never a panic — and nothing is executed
    /// locally (the bar only sends a request; the daemon owns the state).
    #[test]
    fn send_set_observing_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        assert!(
            send_set_observing(missing.to_str().unwrap(), false).is_err(),
            "absent socket must yield a control Err (turning off)"
        );
        assert!(
            send_set_observing(missing.to_str().unwrap(), true).is_err(),
            "absent socket must yield a control Err (turning on)"
        );
    }

    /// The probe toggle degrades the same way: an absent socket is an `Err`,
    /// never a panic, and its leading read failing means no `SetProbing` is
    /// sent at all.
    #[test]
    fn probing_round_trip_is_offline_safe_and_flips_to_the_other_tier() {
        assert_eq!(opposite_tier(ProbingTier::Passive), ProbingTier::Active);
        assert_eq!(opposite_tier(ProbingTier::Active), ProbingTier::Passive);

        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        assert!(send_set_probing(missing.to_str().unwrap(), ProbingTier::Active).is_err());
        let (control, fresh) = probing_round_trip(missing.to_str().unwrap());
        let err = control.expect_err("no premise -> no command, just the error");
        let fresh = fresh.expect_err("the leading read failed");
        assert!(matches!(fresh, GlanceError::Unreachable(_)), "{fresh:?}");
        assert_eq!(err, fresh.to_string());
    }

    /// The leading read is the toggle's premise: when it fails there is nothing to
    /// flip, so no `SetObserving` is sent and both halves report the error.
    #[test]
    fn toggle_round_trip_skips_control_when_leading_read_fails() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let (control, fresh) = toggle_round_trip(missing.to_str().unwrap());
        let err = control.expect_err("no premise -> no command, just the error");
        let fresh = fresh.expect_err("the leading read failed");
        assert!(
            matches!(fresh, GlanceError::Unreachable(_)),
            "an absent socket is unreachable: {fresh:?}"
        );
        assert_eq!(
            err,
            fresh.to_string(),
            "both halves report the same offline error"
        );
    }

    /// The bottom rung is the base scan and nothing more: `ScanOptions::default()`
    /// names no rung. The shape of the three rungs above it is pinned at compile
    /// time beside their declaration.
    #[test]
    fn the_base_rung_names_no_rung() {
        let base = ScanOptions::default();
        assert!(!base.ports && !base.banners && !base.cve);
    }

    /// Every non-table outcome becomes a readable line carrying the daemon's own
    /// words, and an older daemon is named as such rather than as a failure.
    #[test]
    fn classify_findings_keeps_the_daemons_words() {
        let table = Table {
            columns: vec!["mac".to_string()],
            rows: vec![vec!["aa".to_string()]],
        };
        assert_eq!(
            classify_diagnosis("Vulns", Ok(QueryOutcome::Table(table.clone()))),
            Ok(table)
        );
        assert_eq!(
            classify_diagnosis(
                "Vulns",
                Ok(QueryOutcome::Failed("bad segment key".to_string()))
            ),
            Err("bad segment key".to_string())
        );
        let unsupported = classify_diagnosis(
            "Vulns",
            Ok(QueryOutcome::Unsupported(
                "bad request: unknown variant".to_string(),
            )),
        )
        .expect_err("an older daemon is an error line, not a table");
        assert!(
            unsupported.starts_with("daemon cannot answer Vulns (older daemon)"),
            "must name the older daemon: {unsupported}"
        );
        assert!(
            unsupported.ends_with("bad request: unknown variant"),
            "must keep the daemon's words: {unsupported}"
        );
        let io = classify_diagnosis(
            "Vulns",
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no socket",
            )),
        )
        .expect_err("a transport failure is an error line");
        assert_eq!(io, "no socket");
    }

    /// The connections read shares the mapping, and names ITS diagnosis in the
    /// older-daemon line — a window must not tell the operator the daemon
    /// cannot answer `Vulns` when it was asked about connections.
    #[test]
    fn classify_connections_names_its_own_diagnosis() {
        let table = Table {
            columns: vec!["key".to_string()],
            rows: vec![vec!["claude.ai".to_string()]],
        };
        assert_eq!(
            classify_diagnosis("Connections", Ok(QueryOutcome::Table(table.clone()))),
            Ok(table)
        );
        assert_eq!(
            classify_diagnosis(
                "Connections",
                Ok(QueryOutcome::Failed(
                    "another diagnosis is running; retry".to_string()
                ))
            ),
            Err("another diagnosis is running; retry".to_string())
        );
        let unsupported = classify_diagnosis(
            "Connections",
            Ok(QueryOutcome::Unsupported(
                "bad request: unknown variant `Connections`".to_string(),
            )),
        )
        .expect_err("an older daemon is an error line, not a table");
        assert_eq!(
            unsupported,
            "daemon cannot answer Connections (older daemon): bad request: unknown variant `Connections`"
        );
    }

    /// The connections read degrades like every other socket call: an absent
    /// socket is an `Err`, never a panic, so the window shows a line instead
    /// of dying — for every grouping, since each is its own request.
    #[test]
    fn fetch_connections_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        for group_by in [
            ConnectionsGroupBy::Host,
            ConnectionsGroupBy::Ip,
            ConnectionsGroupBy::IpPort,
            ConnectionsGroupBy::Process,
        ] {
            assert!(
                fetch_connections(missing.to_str().unwrap(), group_by).is_err(),
                "absent socket must yield a connections Err for {group_by:?}"
            );
        }
    }

    /// The findings read degrades like every other socket call: an absent socket
    /// is an `Err`, never a panic, so the section shows a line instead of the
    /// window dying.
    #[test]
    fn fetch_findings_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        assert!(
            fetch_findings(missing.to_str().unwrap()).is_err(),
            "absent socket must yield a findings Err"
        );
    }

    /// The neighbours read degrades the same way: an absent socket is an
    /// `Err`, never a panic, so the map draws its star without the announce
    /// overlay and says why, instead of the window dying.
    #[test]
    fn fetch_neighbors_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        assert!(
            fetch_neighbors(missing.to_str().unwrap()).is_err(),
            "absent socket must yield a neighbours Err"
        );
    }
}
