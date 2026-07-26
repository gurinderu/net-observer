//! The local read-only API server (plan Task 2 / spec "Local API").
//!
//! `observerd` is the sole DuckDB owner (DuckDB takes a per-process file lock, so
//! a second opener — even read-only — is blocked while the daemon runs). Every
//! other process reads live status over this Unix-domain socket instead of
//! opening the database. The server answers entirely from the in-memory
//! [`StatusSnapshot`] the pipeline keeps current — no DB read on the request
//! path, zero contention with the writer, always live.
//!
//! The wire format matches `observer_ipc::{write_frame, read_frame}`: one
//! newline-terminated JSON [`Request`] in, one newline-terminated JSON
//! [`Response`] out, then the connection closes.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use observer_ipc::{
    ControlCmd, ControlResult, Event, EventKind, Request, Response, StatusSnapshot,
};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;

use crate::acting;

/// The acting (write/control) configuration handed to the socket server. Kept
/// small and cloneable so each connection task gets its own copy.
///
/// Safety invariant: `enabled` is off by default; with `enabled = false` every
/// control request is refused *without running anything*. Only `observerd`
/// executes actions, and never automatically — only on an explicit request that
/// passes this gate.
#[derive(Debug, Clone)]
pub struct ActingConfig {
    /// Master switch for the control path (`config.acting.enabled`).
    pub enabled: bool,
    /// The `launchctl` service target for `ControlCmd::KickstartProxy`.
    pub singbox_service: String,
}

/// Bind the Unix-domain socket at `socket_path`, `chmod` it to `socket_mode` so an
/// unprivileged client (the bar; the daemon runs as root) can connect, optionally
/// `chown` it to `socket_owner_uid`, and serve [`Request`]s from the shared
/// `snapshot` until the task is aborted.
///
/// `acting` gates the write/control path: acting-class control requests (e.g.
/// `KickstartProxy`) are refused unless `acting.enabled` is set (see
/// [`control_response`]). Only this daemon runs the actuator, and only on an
/// explicit request — never automatically. `SetObserving` is benign self-control
/// and is *not* gated by `acting`: it flips the shared `observing` flag the
/// collectors check and mirrors the new state into the live snapshot.
///
/// `events_tx` is the realtime event bus. A one-shot request (`Status`,
/// `Incidents`, `Control`) is answered with a single [`Response`] then the
/// connection closes; a [`Request::Subscribe`] instead holds the connection open
/// and streams filtered newline-JSON [`Event`] frames from a per-connection
/// broadcast receiver until the client disconnects (see [`stream_events`]).
///
/// Runs forever; the daemon spawns it and `abort()`s it on shutdown. A stale
/// socket file left by a previous run is removed before binding (otherwise
/// `bind` fails with `EADDRINUSE`).
pub async fn serve(
    socket_path: String,
    socket_mode: u32,
    socket_owner_uid: Option<u32>,
    acting: ActingConfig,
    observing: Arc<AtomicBool>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
    events_tx: broadcast::Sender<Event>,
) -> std::io::Result<()> {
    // A leftover socket file from a previous run makes bind() fail; clear it.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    // The root daemon must relax the mode so the logged-in user's UI can connect.
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(socket_mode))?;
    // Socket hardening for the control path: when an owner uid is configured,
    // chown the socket to it (operators pair this with mode 0600 when enabling
    // acting so only the owner can send privileged commands). Best-effort: a
    // chown failure is logged but never takes the daemon down.
    if let Some(uid) = socket_owner_uid {
        match std::os::unix::fs::chown(&socket_path, Some(uid), None) {
            Ok(()) => tracing::info!(uid, path = %socket_path, "status socket chowned"),
            Err(e) => {
                tracing::warn!(error = %e, uid, path = %socket_path, "failed to chown status socket")
            }
        }
    }
    tracing::info!(
        path = %socket_path,
        mode = format!("{socket_mode:o}"),
        acting = acting.enabled,
        "status socket listening"
    );

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let snapshot = Arc::clone(&snapshot);
                let observing = Arc::clone(&observing);
                let acting = acting.clone();
                let events_tx = events_tx.clone();
                // One task per connection. One-shot requests reply and close; a
                // `Subscribe` holds the connection open and streams `Event` frames.
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_conn(stream, &snapshot, &observing, &acting, &events_tx).await
                    {
                        tracing::debug!(error = %e, "status socket connection error");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "status socket accept failed"),
        }
    }
}

/// Handle one client: read a single newline-JSON [`Request`], then dispatch.
///
/// One-shot requests (`Status`, `Incidents`, `Control`) are answered from the
/// in-memory snapshot with a single newline-JSON [`Response`], then the connection
/// closes. A [`Request::Subscribe`] instead holds the connection open and streams
/// filtered [`Event`] frames via [`stream_events`] until the client disconnects.
/// The snapshot lock is held only long enough to clone what a response needs —
/// never across an `.await`.
async fn handle_conn(
    stream: UnixStream,
    snapshot: &Mutex<StatusSnapshot>,
    observing: &AtomicBool,
    acting: &ActingConfig,
    events_tx: &broadcast::Sender<Event>,
) -> std::io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(()); // client closed without sending a request
    }

    let response = match serde_json::from_str::<Request>(&line) {
        // Streaming path: hold the connection open and push filtered `Event`
        // frames from a per-connection broadcast receiver until the client goes
        // away. It never produces a single `Response`, so it returns directly.
        Ok(Request::Subscribe { kinds }) => {
            return stream_events(&mut wr, kinds, events_tx).await;
        }
        Ok(Request::Status) => Response::Status(snapshot_clone(snapshot)),
        Ok(Request::Incidents { limit }) => {
            let incidents = snapshot
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
            Response::Control(control_response(cmd, observing, snapshot, acting))
        }
        Err(e) => Response::Error(format!("bad request: {e}")),
    };

    let mut buf = serde_json::to_vec(&response)?;
    buf.push(b'\n');
    wr.write_all(&buf).await?;
    wr.flush().await
}

/// Stream live [`Event`] frames to a held-open [`Request::Subscribe`] connection.
///
/// Subscribes a fresh receiver on the realtime bus and loops, writing each event
/// as a newline-JSON frame to `wr`, filtered by `kinds` (`None` = every kind).
/// The connection stays open for the loop's whole duration — this is push, not
/// poll: the client subscribes once and the daemon pushes frames as they happen.
///
/// Termination:
/// - [`broadcast::error::RecvError::Lagged`] — the subscriber fell behind the bus;
///   log the count and continue (a live tail may drop old events).
/// - [`broadcast::error::RecvError::Closed`] — the bus is gone; stop.
/// - a write/flush error — the client disconnected; stop.
async fn stream_events<W: AsyncWrite + Unpin>(
    wr: &mut W,
    kinds: Option<Vec<EventKind>>,
    events_tx: &broadcast::Sender<Event>,
) -> std::io::Result<()> {
    let mut rx = events_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(ev) => {
                // Filter server-side: `None` passes every kind, `Some(list)` only
                // the listed kinds.
                let deliver = match &kinds {
                    Some(ks) => ks.contains(&ev.kind()),
                    None => true,
                };
                if !deliver {
                    continue;
                }
                let mut buf = serde_json::to_vec(&ev)?;
                buf.push(b'\n');
                // A write/flush error means the client is gone — stop streaming.
                if wr.write_all(&buf).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            // Slow subscriber: it missed `n` events. Acceptable for a live tail —
            // log and keep going rather than tearing the connection down.
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(skipped = n, "event subscriber lagged; dropped old events");
            }
            // The broadcast sender was dropped (daemon shutting down): end the stream.
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

/// Map a [`ControlCmd`] to its [`ControlResult`].
///
/// Two classes of command with different gating:
///
/// - **`SetObserving(b)` — benign self-control, NOT gated by `acting.enabled`.**
///   It flips the observer's OWN collection on/off: it stores `b` into the shared
///   `observing` flag the collectors check and mirrors it into the live snapshot
///   (`snapshot.observing`) so the switch shows the real state. It never touches
///   sing-box or the network, so the acting gate does not apply — a client can
///   pause/resume collection even with acting disabled. The daemon stays alive
///   and the socket keeps serving throughout, so the switch can turn it back on.
///
/// - **Acting-class commands (e.g. `KickstartProxy`) — gated by
///   `acting.enabled`.** Safety invariant: when acting is disabled the command is
///   refused *without running anything* — no `launchctl` (or any other actuator)
///   is ever invoked. Only when acting is explicitly enabled does `observerd` run
///   the actuator, and only for this explicit request (never automatically).
fn control_response(
    cmd: ControlCmd,
    observing: &AtomicBool,
    snapshot: &Mutex<StatusSnapshot>,
    acting: &ActingConfig,
) -> ControlResult {
    match cmd {
        // Self-control: not gated by acting. Set the flag + mirror into snapshot.
        ControlCmd::SetObserving(b) => {
            observing.store(b, Ordering::Release);
            snapshot.lock().unwrap_or_else(|e| e.into_inner()).observing = b;
            ControlResult {
                ok: true,
                message: format!("observing {}", if b { "on" } else { "off" }),
            }
        }
        // Acting-class: refused unless acting is explicitly enabled.
        ControlCmd::KickstartProxy => {
            if !acting.enabled {
                return ControlResult {
                    ok: false,
                    message: "acting disabled".into(),
                };
            }
            match acting::kickstart_proxy(&acting.singbox_service) {
                Ok(message) => ControlResult { ok: true, message },
                Err(message) => ControlResult { ok: false, message },
            }
        }
    }
}

/// Clone the live snapshot, recovering the lock if a previous holder panicked.
fn snapshot_clone(snapshot: &Mutex<StatusSnapshot>) -> StatusSnapshot {
    snapshot.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use observer_ipc::IncidentSummary;
    use types::{GwVerdict, HostSample, LinkSample, RouteEvent, TcpVerdict};

    /// End-to-end round-trip over a real `UnixListener` bound to a temp path,
    /// answered with the blocking `observer_ipc::query` client the bar uses.
    #[tokio::test]
    async fn serve_answers_status_and_incidents() {
        let dir = std::env::temp_dir().join(format!("observerd-api-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
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

        let acting = ActingConfig {
            enabled: false,
            singbox_service: "system/sing-box".into(),
        };
        let observing = Arc::new(AtomicBool::new(true));
        let (events_tx, _) = broadcast::channel(16);
        let handle = tokio::spawn(serve(
            sock_str.clone(),
            0o666,
            None,
            acting,
            observing,
            snapshot.clone(),
            events_tx,
        ));

        // Wait for the socket file to appear (bind + chmod complete).
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(sock.exists(), "socket was never created");

        // Status: the whole snapshot, cloned from memory.
        let sp = sock_str.clone();
        let status =
            tokio::task::spawn_blocking(move || observer_ipc::query(&sp, &Request::Status))
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
            observer_ipc::query(&sp, &Request::Incidents { limit: 1 })
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

    /// Safety invariant: with acting disabled, an acting-class control request is
    /// refused without running anything. This exercises the gate directly (no
    /// socket, no `launchctl`) so the "never act when disabled" branch is asserted
    /// in isolation. The actuator itself is intentionally never invoked here.
    #[test]
    fn control_refused_when_acting_disabled() {
        let acting = ActingConfig {
            enabled: false,
            singbox_service: "system/sing-box".into(),
        };
        let observing = AtomicBool::new(true);
        let snapshot = Mutex::new(StatusSnapshot::default());
        let result = control_response(ControlCmd::KickstartProxy, &observing, &snapshot, &acting);
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
        let acting = ActingConfig {
            enabled: false,
            singbox_service: "system/sing-box".into(),
        };
        let observing = AtomicBool::new(true);
        let snapshot = Mutex::new(StatusSnapshot::default());

        // Pause: succeeds despite acting being disabled; flag + snapshot go false.
        let off = control_response(
            ControlCmd::SetObserving(false),
            &observing,
            &snapshot,
            &acting,
        );
        assert!(off.ok, "SetObserving must not be gated by acting");
        assert_eq!(off.message, "observing off");
        assert!(!observing.load(Ordering::Acquire));
        assert!(!snapshot.lock().unwrap().observing);

        // Resume: flag + snapshot go true again.
        let on = control_response(
            ControlCmd::SetObserving(true),
            &observing,
            &snapshot,
            &acting,
        );
        assert!(on.ok);
        assert_eq!(on.message, "observing on");
        assert!(observing.load(Ordering::Acquire));
        assert!(snapshot.lock().unwrap().observing);
    }

    /// End-to-end streaming subscription over a real `UnixListener`: a `Subscribe`
    /// connection is held open and streamed filtered `Event` frames pushed on the
    /// bus (push, not poll). The client subscribes once filtered to `Route`; a
    /// `Host` event is dropped server-side by the filter while a `Route` event is
    /// delivered on the same held-open connection.
    #[tokio::test]
    async fn serve_streams_filtered_subscription_events() {
        let dir = std::env::temp_dir().join(format!("observerd-sub-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("observer.sock");
        let sock_str = sock.to_str().unwrap().to_string();

        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let acting = ActingConfig {
            enabled: false,
            singbox_service: "system/sing-box".into(),
        };
        let observing = Arc::new(AtomicBool::new(true));
        let (events_tx, _) = broadcast::channel(16);
        let handle = tokio::spawn(serve(
            sock_str.clone(),
            0o666,
            None,
            acting,
            observing,
            snapshot.clone(),
            events_tx.clone(),
        ));

        // Wait for the socket file to appear (bind + chmod complete).
        for _ in 0..200 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(sock.exists(), "socket was never created");

        // Open a live subscription filtered to Route only, on a blocking thread
        // (the client is deliberately tokio-free).
        let sp = sock_str.clone();
        let sub = tokio::task::spawn_blocking(move || {
            observer_ipc::subscribe(
                &sp,
                &Request::Subscribe {
                    kinds: Some(vec![EventKind::Route]),
                },
            )
        })
        .await
        .unwrap()
        .unwrap();

        // Wait until the server has created its broadcast receiver; a `send` before
        // that would reach no one (broadcast only delivers to receivers that exist
        // at send time).
        for _ in 0..200 {
            if events_tx.receiver_count() >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            events_tx.receiver_count() >= 1,
            "server never subscribed to the bus"
        );

        // A Host event is filtered out server-side; a Route event passes.
        events_tx
            .send(Event::Host(HostSample {
                ts_us: 1,
                load1: 0.0,
                load5: 0.0,
                load15: 0.0,
            }))
            .unwrap();
        events_tx
            .send(Event::Route(RouteEvent {
                ts_us: 7,
                kind: "iface".into(),
                iface: Some("en0".into()),
                detail: "up".into(),
            }))
            .unwrap();

        // The first frame the client receives is the Route event (Host filtered).
        let ev = tokio::task::spawn_blocking(move || {
            let mut sub = sub;
            sub.next()
        })
        .await
        .unwrap()
        .expect("subscription should yield a frame")
        .expect("frame should decode");
        match ev {
            Event::Route(r) => assert_eq!(r.ts_us, 7),
            other => panic!("expected Route event, got {other:?}"),
        }

        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
