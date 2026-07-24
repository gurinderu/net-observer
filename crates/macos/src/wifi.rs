//! Wi-Fi facts: the current SSID (`networksetup -getairportnetwork`) and
//! whether the CoreCapture Wi-Fi driver has recently dumped a diagnostic
//! bundle (a strong signal of a driver-level Wi-Fi wedge).

use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

/// Directory macOS writes Wi-Fi driver capture bundles into on a fault.
const CORECAPTURE_WIFI_DIR: &str = "/Library/Logs/CrashReporter/CoreCapture/WiFi";

/// Return the SSID currently joined on `iface`, or `None` if not associated
/// (or the query fails). Absence is a signal, so failures never panic.
#[must_use]
pub fn current_ssid(iface: &str) -> Option<String> {
    let out = Command::new("networksetup")
        .args(["-getairportnetwork", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_ssid(&text)
}

/// Extract the SSID from `networksetup -getairportnetwork` output.
fn parse_ssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("Current Wi-Fi Network: ")
            .map(|s| s.trim().to_string())
    })
}

/// `true` if a CoreCapture Wi-Fi bundle was written within `window` — i.e. the
/// Wi-Fi driver recently faulted.
#[must_use]
pub fn wifi_capture_present(window: Duration) -> bool {
    capture_present_in(Path::new(CORECAPTURE_WIFI_DIR), window, SystemTime::now())
}

/// Testable core of [`wifi_capture_present`]: scan `dir` for any entry modified
/// within `window` of `now`.
fn capture_present_in(dir: &Path, window: Duration, now: SystemTime) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if let Ok(age) = now.duration_since(modified)
            && age <= window
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_ssid() {
        let out = "Current Wi-Fi Network: cowork\n";
        assert_eq!(parse_ssid(out).as_deref(), Some("cowork"));
    }

    #[test]
    fn no_ssid_when_not_associated() {
        let out = "You are not associated with an AirPort network.\n";
        assert_eq!(parse_ssid(out), None);
    }

    #[test]
    fn capture_present_detects_recent_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("CC-2026-07-24")).unwrap();
        assert!(capture_present_in(
            dir.path(),
            Duration::from_secs(600),
            SystemTime::now()
        ));
    }

    #[test]
    fn capture_absent_for_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!capture_present_in(
            dir.path(),
            Duration::from_secs(600),
            SystemTime::now()
        ));
    }

    #[test]
    fn capture_absent_for_missing_dir() {
        assert!(!capture_present_in(
            Path::new("/nonexistent/path/xyz"),
            Duration::from_secs(600),
            SystemTime::now()
        ));
    }
}
