//! Wi-Fi facts: the current SSID (`networksetup -getairportnetwork`), the
//! link's identity pair — the associated AP's BSSID (`ipconfig getsummary`)
//! and the interface's own MAC (`ifconfig <iface> ether`) — and whether the
//! CoreCapture Wi-Fi driver has recently dumped a diagnostic bundle (a strong
//! signal of a driver-level Wi-Fi wedge).

use std::path::Path;
use std::time::{Duration, SystemTime};

use tokio::process::Command;

use types::LinkMedium;

use crate::neighbors::normalize_mac;

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

/// What `networksetup` prints in place of the SSID to a reader without
/// location permission — a root LaunchDaemon among them (realm net-observer,
/// nodes #93, #108). It is the tool withholding the value, not a network
/// name, so it is recorded as absence: stored as a name it would compare
/// unequal to the real SSID and read as a network move that never happened.
const REDACTED_SSID: &str = "<redacted>";

/// Extract the SSID from `networksetup -getairportnetwork` output. `None`
/// when not associated or when the value is [`REDACTED_SSID`].
fn parse_ssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let ssid = line.trim().strip_prefix("Current Wi-Fi Network: ")?.trim();
        (ssid != REDACTED_SSID).then(|| ssid.to_string())
    })
}

/// Return the BSSID of the access point `iface` is associated with, lowercase
/// `aa:bb:cc:dd:ee:ff`, or `None` when `ipconfig getsummary` prints no `BSSID`
/// line (not associated) or the query fails. The command is an external
/// surface (realm net-observer, node #93): the owner saw the line from a user
/// session; what a root LaunchDaemon sees is unobserved, and `None` is the
/// sanctioned answer when the line is absent.
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
/// form is `BSSID : <mac>`, normalised through [`normalize_mac`] (lowercase,
/// zero-padded octets; broadcast and multicast rejected). `None` when the line
/// is absent (not associated) or its value is not a unicast MAC — never a
/// fabricated address. `gw_arp_mac` is stored raw from `arp -n` and is NOT
/// comparable to this field as stored; the AP-is-the-gateway comparison is
/// deferred to the roam step.
fn parse_bssid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("BSSID")?
            .trim_start()
            .strip_prefix(':')?
            .trim();
        normalize_mac(value)
    })
}

/// Return `iface`'s own MAC as currently assigned (`ifconfig <iface> ether`,
/// an external surface: realm net-observer, node #93), lowercase, or `None`
/// if it cannot be read. Private Wi-Fi Address rotates this per SSID, so it is
/// read every tick rather than once.
pub async fn interface_mac(iface: &str) -> Option<String> {
    let out = Command::new("ifconfig")
        .args([iface, "ether"])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_ether(&text)
}

/// Extract the MAC from an `ifconfig` block: the indented `ether <mac>` line,
/// normalised through [`normalize_mac`]. `None` when the line is absent or its
/// value is not a unicast MAC.
fn parse_ether(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("ether ")?;
        normalize_mac(rest.split_whitespace().next()?)
    })
}

/// Return the medium of `iface` from the hardware-port table
/// (`networksetup -listallhardwareports`, an external surface: realm
/// net-observer, node #93) — readable by root without Location Services,
/// which is what makes it the medium signal where the SSID and BSSID are not
/// (node #108). `None` when the table cannot be read or does not list the
/// interface. Read every tick, one command, like the identity pair: the
/// default route can move between adapters between two ticks.
pub async fn interface_medium(iface: &str) -> Option<LinkMedium> {
    let out = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_medium(&text, iface)
}

/// Classify `iface` from the hardware-port table: the port whose `Device:`
/// line names the interface is Wi-Fi when its `Hardware Port:` is `Wi-Fi` (or
/// `AirPort`, the older name) and wired otherwise; an interface no port
/// names is `None` — not determinable, never guessed.
fn parse_medium(output: &str, iface: &str) -> Option<LinkMedium> {
    let mut port: Option<&str> = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("Hardware Port:") {
            port = Some(name.trim());
        } else if let Some(device) = line.strip_prefix("Device:")
            && device.trim() == iface
        {
            return match port? {
                "Wi-Fi" | "AirPort" => Some(LinkMedium::Wifi),
                _ => Some(LinkMedium::Wired),
            };
        }
    }
    None
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

    /// A root reader without location permission gets `<redacted>` in place
    /// of the name (nodes #93, #108): the tool withholding the value is no
    /// measurement, and must never be stored as a network called
    /// `<redacted>` — a later identity comparison would read it as a move.
    #[test]
    fn redacted_ssid_is_no_measurement() {
        let out = "Current Wi-Fi Network: <redacted>\n";
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

    /// A `BSSID` line whose value is not a unicast MAC (the broadcast address
    /// included) is recorded as absence: a fabricated identity would later
    /// read as a roam that never happened.
    #[test]
    fn no_bssid_for_a_non_mac_value() {
        for value in [
            "none",
            "3c:22:fb:12:34",
            "3c:22:fb:12:34:56:78",
            "zz:22:fb:12:34:56",
            "ff:ff:ff:ff:ff:ff",
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

    /// A non-MAC or the broadcast address is absence, not an identity: an
    /// interface cannot BE `ff:ff:ff:ff:ff:ff`, and a later roam comparison
    /// must never see it as one.
    #[test]
    fn no_interface_mac_for_a_non_mac_or_broadcast_value() {
        for value in ["not-a-mac", "ff:ff:ff:ff:ff:ff"] {
            let out = format!("en0: flags=8863<UP> mtu 1500\n\tether {value}\n");
            assert_eq!(parse_ether(&out), None, "value {value:?} must not parse");
        }
    }

    /// `networksetup -listallhardwareports`: one block per port, the Wi-Fi
    /// adapter on `en0` and a Thunderbolt Ethernet adapter on `en5`, then the
    /// VLAN trailer.
    const HARDWARE_PORTS_OUT: &str = "\n\
        Hardware Port: Wi-Fi\n\
        Device: en0\n\
        Ethernet Address: f0:18:98:0a:0b:0c\n\
        \n\
        Hardware Port: Thunderbolt Ethernet\n\
        Device: en5\n\
        Ethernet Address: 00:11:22:33:44:55\n\
        \n\
        VLAN Configurations\n\
        ===================\n";

    /// The medium is the port's kind, looked up by device: Wi-Fi for the
    /// Wi-Fi port, wired for any other, and the older `AirPort` name still
    /// reads as Wi-Fi.
    #[test]
    fn medium_is_read_from_the_hardware_port_table() {
        assert_eq!(
            parse_medium(HARDWARE_PORTS_OUT, "en0"),
            Some(LinkMedium::Wifi)
        );
        assert_eq!(
            parse_medium(HARDWARE_PORTS_OUT, "en5"),
            Some(LinkMedium::Wired)
        );
        let airport = "Hardware Port: AirPort\nDevice: en1\n";
        assert_eq!(parse_medium(airport, "en1"), Some(LinkMedium::Wifi));
    }

    /// An interface no port names is not determinable — `None`, never a
    /// guess: a `utun` or a bridge the table does not list must not read as
    /// wired.
    #[test]
    fn no_medium_for_an_unlisted_interface() {
        assert_eq!(parse_medium(HARDWARE_PORTS_OUT, "utun6"), None);
        assert_eq!(parse_medium("", "en0"), None);
    }

    /// Both parsers hand their value to the shared [`normalize_mac`]: octets
    /// are lowercased and zero-padded, so the BSSID and the interface MAC are
    /// stored in one shape however the tool printed them.
    #[test]
    fn both_parsers_normalise_through_the_shared_function() {
        let summary = "<dictionary> {\n  BSSID : 3C:22:FB:1:2:3\n}\n";
        assert_eq!(parse_bssid(summary).as_deref(), Some("3c:22:fb:01:02:03"));
        let ifconfig = "en0: flags=8863<UP> mtu 1500\n\tether F0:18:98:A:B:C\n";
        assert_eq!(parse_ether(ifconfig).as_deref(), Some("f0:18:98:0a:0b:0c"));
        assert_eq!(normalize_mac("3c:22:fb::2:3"), None);
        assert_eq!(normalize_mac("3c:22:fb:123:02:03"), None);
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
