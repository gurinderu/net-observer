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
use std::sync::{Arc, Mutex};

use observer_ipc::{ControlCmd, ControlResult, Request, Response, StatusSnapshot};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

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
/// `acting` gates the write/control path: control requests are refused unless
/// `acting.enabled` is set (see [`control_response`]). Only this daemon runs the
/// actuator, and only on an explicit request — never automatically.
///
/// Runs forever; the daemon spawns it and `abort()`s it on shutdown. A stale
/// socket file left by a previous run is removed before binding (otherwise
/// `bind` fails with `EADDRINUSE`).
pub async fn serve(
    socket_path: String,
    socket_mode: u32,
    socket_owner_uid: Option<u32>,
    acting: ActingConfig,
    snapshot: Arc<Mutex<StatusSnapshot>>,
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
                let acting = acting.clone();
                // One task per connection: read one request, reply, close.
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, &snapshot, &acting).await {
                        tracing::debug!(error = %e, "status socket connection error");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "status socket accept failed"),
        }
    }
}

/// Handle one client: read a single newline-JSON [`Request`], answer from the
/// in-memory snapshot with a newline-JSON [`Response`], then close. The snapshot
/// lock is held only long enough to clone what the response needs — never across
/// an `.await`.
async fn handle_conn(
    stream: UnixStream,
    snapshot: &Mutex<StatusSnapshot>,
    acting: &ActingConfig,
) -> std::io::Result<()> {
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(()); // client closed without sending a request
    }

    let response = match serde_json::from_str::<Request>(&line) {
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
        Ok(Request::Control(cmd)) => Response::Control(control_response(cmd, acting)),
        Err(e) => Response::Error(format!("bad request: {e}")),
    };

    let mut buf = serde_json::to_vec(&response)?;
    buf.push(b'\n');
    wr.write_all(&buf).await?;
    wr.flush().await
}

/// Map a [`ControlCmd`] to its [`ControlResult`], honoring the acting gate.
///
/// Safety invariant: when acting is disabled the command is refused *without
/// running anything* — this returns early before touching the actuator, so no
/// `launchctl` (or any other action) is ever invoked. Only when acting is
/// explicitly enabled does `observerd` run the actuator, and only for this
/// explicit request (never automatically).
fn control_response(cmd: ControlCmd, acting: &ActingConfig) -> ControlResult {
    if !acting.enabled {
        return ControlResult {
            ok: false,
            message: "acting disabled".into(),
        };
    }
    match cmd {
        ControlCmd::KickstartProxy => match acting::kickstart_proxy(&acting.singbox_service) {
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
    use observer_ipc::IncidentSummary;
    use types::{GwVerdict, LinkSample, TcpVerdict};

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
        let handle = tokio::spawn(serve(
            sock_str.clone(),
            0o666,
            None,
            acting,
            snapshot.clone(),
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

    /// Safety invariant: with acting disabled, a control request is refused
    /// without running anything. This exercises the gate directly (no socket, no
    /// `launchctl`) so the "never act when disabled" branch is asserted in
    /// isolation. The actuator itself is intentionally never invoked here.
    #[test]
    fn control_refused_when_acting_disabled() {
        let acting = ActingConfig {
            enabled: false,
            singbox_service: "system/sing-box".into(),
        };
        let result = control_response(ControlCmd::KickstartProxy, &acting);
        assert!(
            !result.ok,
            "control must be refused when acting is disabled"
        );
        assert_eq!(result.message, "acting disabled");
    }
}
