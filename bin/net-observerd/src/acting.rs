//! The actuator — the *only* place `net-observerd` executes a recovery action
//! (plan Task 2 / spec "Control path — manual acting").
//!
//! `net-observerd` runs as root, so it can restart a system LaunchDaemon; clients
//! merely *request* an action over the socket. Acting is gated OFF by default
//! (`config.acting.enabled = false`) — the gate lives in [`crate::api`]; this
//! module is reached only after the gate has passed. Nothing here ever fires
//! automatically, and every function returns a readable `Ok`/`Err` message
//! instead of panicking.

use std::process::Command;

/// Restart the sing-box LaunchDaemon via `launchctl kickstart -k <service>`
/// (`-k` kills-then-restarts), the same recovery net-observer's watchdog used —
/// but here only on an explicit, gated [`net_observer_ipc::ControlCmd::KickstartProxy`].
///
/// Returns `Ok(message)` on success or `Err(message)` on any failure (the child
/// could not be spawned, or `launchctl` exited non-zero). Never panics.
pub fn kickstart_proxy(service: &str) -> Result<String, String> {
    let output = Command::new("launchctl")
        .args(["kickstart", "-k", service])
        .output()
        .map_err(|e| format!("failed to run launchctl: {e}"))?;

    if output.status.success() {
        Ok(format!("kickstarted {service}"))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".into());
        if stderr.is_empty() {
            Err(format!(
                "launchctl kickstart {service} failed (status {code})"
            ))
        } else {
            Err(format!(
                "launchctl kickstart {service} failed (status {code}): {stderr}"
            ))
        }
    }
}
