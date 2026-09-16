//! Wi-Fi facts: the current SSID (`networksetup -getairportnetwork`), the
//! link's identity pair — the associated AP's BSSID (`ipconfig getsummary`)
//! and the interface's own MAC (`ifconfig <iface> ether`) — and whether the
//! CoreCapture Wi-Fi driver has recently dumped a diagnostic bundle (a strong
//! signal of a driver-level Wi-Fi wedge).

use std::path::Path;
use std::time::{Duration, SystemTime};

use tokio::process::Command;

/// Directory macOS writes Wi-Fi driver capture bundles into on a fault.
const CORECAPTURE_WIFI_DIR: &str = "/Library/Logs/CrashReporter/CoreCapture/WiFi";

/// Return the SSID currently joined on `iface`, or `None` if not associated
/// (or the query fails). Absence is a signal, so failures never panic.
pub async fn current_ssid(iface: &str) -> Option<String> {
    let out = Command::new("networksetup")
        .args(["-getairportnetwork", iface])
        .output()
        .await
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

/// Return the BSSID of the access point `iface` is associated with, lowercase
/// `aa:bb:cc:dd:ee:ff`, or `None` if not associated (or the query fails).
/// Read from `ipconfig getsummary`, which is not gated behind Location
/// Services the way CoreWLAN's BSSID is (realm net-observer, node #59).
pub async fn current_bssid(iface: &str) -> Option<String> {
    let out = Command::new("ipconfig")
        .args(["getsummary", iface])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_bssid(&text)
}

/// Extract the BSSID from `ipconfig getsummary` output: the line whose trimmed
/// form is `BSSID : <mac>`. `None` when the line is absent (not associated) or
/// its value is not a MAC — never a fabricated address.
fn parse_bssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("BSSID")?
            .trim_start()
            .strip_prefix(':')?
            .trim();
        normalise_mac(value)
    })
}

/// Return `iface`'s own MAC as currently assigned (`ifconfig <iface> ether`),
/// lowercase, or `None` if it cannot be read. Private Wi-Fi Address rotates
/// this per SSID, so it is read every tick rather than once.
pub async fn interface_mac(iface: &str) -> Option<String> {
    let out = Command::new("ifconfig")
        .args([iface, "ether"])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_ether(&text)
}

/// Extract the MAC from an `ifconfig` block: the indented `ether <mac>` line.
/// `None` when the line is absent or its value is not a MAC.
fn parse_ether(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("ether ")?;
        normalise_mac(rest.split_whitespace().next()?)
    })
}

/// Normalise a colon-separated MAC to lowercase, two-digit octets
/// (`aa:bb:cc:dd:ee:ff`). Six groups of one or two hex digits are accepted —
/// macOS tools print octets both zero-padded (`ifconfig`) and stripped
/// (`arp`) — and anything else yields `None`: the caller records absence, not
/// a guess. Zero-padding is the only rewriting done, so the same address read
/// by two tools compares equal.
fn normalise_mac(token: &str) -> Option<String> {
    let octets: Vec<&str> = token.split(':').collect();
    if octets.len() != 6 {
        return None;
    }
    let mut out = String::with_capacity(17);
    for (i, octet) in octets.iter().enumerate() {
        if octet.is_empty() || octet.len() > 2 || !octet.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        if i > 0 {
            out.push(':');
        }
        if octet.len() == 1 {
            out.push('0');
        }
        out.push_str(&octet.to_ascii_lowercase());
    }
    Some(out)
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

    /// `ipconfig getsummary en0` while associated: a dict-like dump whose
    /// `BSSID` and `SSID` lines sit among address, link and security lines.
    const GETSUMMARY_OUT: &str = "<dictionary> {\n\
        \x20 BSSID : 3c:22:fb:12:34:56\n\
        \x20 IPv4 : <array> {\n\
        \x20   0 : <dictionary> {\n\
        \x20     Addresses : <array> {\n\
        \x20       0 : 192.168.1.50\n\
        \x20     }\n\
        \x20     Router : 192.168.1.1\n\
        \x20   }\n\
        \x20 }\n\
        \x20 InterfaceType : WiFi\n\
        \x20 LinkStatusActive : TRUE\n\
        \x20 NetworkID : 6F1A2B3C-4D5E-6F70-8192-A3B4C5D6E7F8\n\
        \x20 SSID : cowork\n\
        \x20 Security : WPA2_PSK\n\
        }\n";

    #[test]
    fn parses_bssid_when_associated() {
        assert_eq!(
            parse_bssid(GETSUMMARY_OUT).as_deref(),
            Some("3c:22:fb:12:34:56")
        );
    }

    /// Not associated: the summary carries no `BSSID` line at all, and the
    /// answer is absence — not an empty string, not a placeholder.
    #[test]
    fn no_bssid_when_the_line_is_absent() {
        let out = "<dictionary> {\n\
            \x20 InterfaceType : WiFi\n\
            \x20 LinkStatusActive : FALSE\n\
            }\n";
        assert_eq!(parse_bssid(out), None);
    }

    /// A `BSSID` line whose value is not a MAC is recorded as absence: a
    /// fabricated identity would later read as a roam that never happened.
    #[test]
    fn no_bssid_for_a_non_mac_value() {
        for value in [
            "none",
            "3c:22:fb:12:34",
            "3c:22:fb:12:34:56:78",
            "zz:22:fb:12:34:56",
        ] {
            let out = format!("<dictionary> {{\n  BSSID : {value}\n  SSID : cowork\n}}\n");
            assert_eq!(parse_bssid(&out), None, "value {value:?} must not parse");
        }
    }

    /// `ifconfig en0 ether`: the full interface block, of which only the
    /// indented `ether` line is the answer.
    const IFCONFIG_EN0_OUT: &str = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\
        \toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n\
        \tether f0:18:98:0a:0b:0c\n\
        \tinet6 fe80::1c2b:3d4e:5f60:7a8b%en0 prefixlen 64 secured scopeid 0xc\n\
        \tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255\n\
        \tnd6 options=201<PERFORMNUD,DAD>\n\
        \tmedia: autoselect\n\
        \tstatus: active\n";

    #[test]
    fn parses_interface_mac() {
        assert_eq!(
            parse_ether(IFCONFIG_EN0_OUT).as_deref(),
            Some("f0:18:98:0a:0b:0c")
        );
    }

    #[test]
    fn no_interface_mac_when_the_ether_line_is_absent() {
        let out = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
            \tinet 127.0.0.1 netmask 0xff000000\n";
        assert_eq!(parse_ether(out), None);
    }

    #[test]
    fn no_interface_mac_for_a_non_mac_value() {
        let out = "en0: flags=8863<UP> mtu 1500\n\tether not-a-mac\n";
        assert_eq!(parse_ether(out), None);
    }

    /// Octets are lowercased and zero-padded on the way through: macOS tools
    /// print a MAC both padded (`ifconfig`) and stripped (`arp`), and an
    /// address must compare equal to itself whichever tool read it.
    #[test]
    fn normalise_mac_lowercases_and_pads_stripped_octets() {
        assert_eq!(
            normalise_mac("3C:22:FB:1:2:3").as_deref(),
            Some("3c:22:fb:01:02:03")
        );
        assert_eq!(normalise_mac("3c:22:fb::2:3"), None);
        assert_eq!(normalise_mac("3c:22:fb:123:02:03"), None);
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
