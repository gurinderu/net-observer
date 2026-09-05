//! Socket reads and control round-trips against `net-observerd`.

use gpui::prelude::*;
use gpui::{AsyncApp, Context, Entity};

use net_observer_ipc::{ControlCmd, ControlResult, Request, Response, ScanOptions, StatusSnapshot};

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
/// mean "nobody was there" are [`GlanceError::Unreachable`]; everything else
/// (`InvalidData` from a frame we cannot decode, a broken pipe mid-exchange, …)
/// happened *with* a daemon on the other end.
fn classify_io(e: std::io::Error) -> GlanceError {
    match e.kind() {
        std::io::ErrorKind::NotFound
        | std::io::ErrorKind::ConnectionRefused
        | std::io::ErrorKind::TimedOut => GlanceError::Unreachable(e.to_string()),
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
/// it does NOT touch the proxy or the network, and the daemon does not gate it on
/// `acting.enabled`.
/// The daemon stays alive and the socket keeps serving while paused, so the switch
/// can turn collection back on. As with every request, a missing socket /
/// connection-refused (daemon down) or a protocol error maps to `Err(String)` so
/// the panel can surface it as a transient line instead of crashing — never a
/// panic.
/// Ask `net-observerd` to enter (`true`) or leave (`false`) **quiet** mode over
/// the local socket (`Control(SetQuiet(on))`).
///
/// Quiet is not a pause: the daemon keeps collecting and keeps emitting one link
/// sample per tick — it just addresses no packet at the gateway, so the gateway
/// verdict reads `SKIP`. Benign **self-control**, not gated by `acting.enabled`.
/// Transport failures map to `Err(String)` for the panel to surface, never a panic.
pub fn send_set_quiet(socket_path: &str, on: bool) -> Result<ControlResult, String> {
    control_query(socket_path, ControlCmd::SetQuiet(on))
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
/// machines that are not this one, so it is **acting-class** — a daemon without
/// `acting.enabled` answers `ok: false` with a reason, shown like any other
/// control outcome.
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

/// The blocking half of the quiet toggle, built exactly like
/// [`toggle_round_trip`] and for the same reason: `SetQuiet(bool)` is absolute on
/// the wire, so the target is derived from a freshly-read state rather than from a
/// snapshot up to one refresh tick old. Never call it on the gpui main thread.
pub fn quiet_round_trip(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    let before = match read_fresh(socket_path) {
        Ok(s) => s,
        Err(e) => return (Err(e.to_string()), Err(e)),
    };
    let control = send_set_quiet(socket_path, !before.quiet);
    (control, read_fresh(socket_path))
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

/// The Scan button's round-trip: the base scan (sweep + mDNS), no port rung. The
/// per-rung checkboxes are a later increment; the CLI's `--ports` drives the
/// `ports` rung today. Shaped as a bare `fn(&str)` so `spawn_control` takes it.
pub fn scan_round_trip_base(
    socket_path: &str,
) -> (
    Result<ControlResult, String>,
    Result<StatusSnapshot, GlanceError>,
) {
    scan_round_trip(socket_path, ScanOptions::default())
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
/// the shared model: the menu's entries and the map window's Rescan.
///
/// The wiring stays in one place on purpose: "never block the gpui main thread",
/// "a daemon that is not there is a message, not a crash", and "the acting gate's
/// refusal is surfaced verbatim" are decided once for every control button in the
/// app, not re-decided per window.
pub(crate) fn spawn_control_on<V: 'static>(
    model: &Entity<Glance>,
    cx: &mut Context<V>,
    round_trip: ControlRoundTrip,
) {
    let weak = model.downgrade();
    let socket = model.read(cx).socket_path.clone();
    cx.spawn(async move |_view, acx: &mut AsyncApp| {
        let (control, fresh) = acx
            .background_spawn(async move { round_trip(&socket) })
            .await;
        weak.update(acx, |g, cx| {
            g.apply_toggle_result(control, fresh);
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

    /// Only the kinds that mean "nobody was there" are unreachable; a decode
    /// failure (a new bar against an older daemon) happened *with* a live daemon on
    /// the other end.
    #[test]
    fn classify_io_separates_unreachable_from_protocol() {
        use std::io::{Error, ErrorKind};
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
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
}
