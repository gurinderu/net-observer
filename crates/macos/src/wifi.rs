//! Wi-Fi facts: the current SSID (`networksetup -getairportnetwork`), the
//! link's identity triple — the associated AP's BSSID (`ipconfig getsummary`),
//! the interface's own MAC (`ifconfig <iface> ether`) and the medium that MAC
//! belongs to (`networksetup -listallhardwareports`) — the current DHCP
//! lease's start and length (also `ipconfig getsummary`, see [`summary`]), and
//! whether the CoreCapture Wi-Fi driver has recently dumped a diagnostic
//! bundle (a strong signal of a driver-level Wi-Fi wedge).

use std::path::Path;
use std::time::{Duration, SystemTime};

use chrono::{Local, LocalResult, NaiveDateTime, TimeZone};
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

/// One parse of `ipconfig getsummary <iface>`, done once per tick and shared
/// by the facts pulled out of it: the associated AP's BSSID and the current
/// DHCP lease's start and length (realm net-observer, node #93 item 1; node
/// #109 item 1). Each field is independently `None` when its line is absent
/// or unparseable — never a fabricated value.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    pub bssid: Option<String>,
    pub lease_start_us: Option<i64>,
    pub lease_secs: Option<u32>,
}

/// Return `iface`'s [`Summary`] from `ipconfig getsummary`, or every field
/// `None` when the command itself cannot be run. The command is an external
/// surface (realm net-observer, node #93): the owner saw the BSSID line from a
/// user session; what a root LaunchDaemon sees is unobserved, and `None` is
/// the sanctioned answer when a line is absent.
pub async fn summary(iface: &str) -> Summary {
    let Ok(out) = Command::new("ipconfig")
        .args(["getsummary", iface])
        .output()
        .await
    else {
        return Summary::default();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    Summary {
        bssid: parse_bssid(&text),
        lease_start_us: parse_lease_start(&text).and_then(lease_start_to_us),
        lease_secs: parse_lease_secs(&text),
    }
}

/// Extract the BSSID from `ipconfig getsummary` output: the line whose trimmed
/// form is `BSSID : <mac>`, normalised through [`normalize_mac`] (lowercase,
/// zero-padded octets; broadcast and multicast rejected). `None` when the line
/// is absent (not associated) or its value is not a unicast MAC — never a
/// fabricated address. As of macOS 26 the value itself is `<redacted>` to a
/// reader without Location Services (a root LaunchDaemon among them), which
/// `normalize_mac` already answers `None` for, the same as any other
/// non-MAC text — no separate sentinel needed (realm net-observer, node #93
/// item 1). `gw_arp_mac` is normalised through the same fold (realm
/// net-observer, node #94), so a comparison to this field is a plain string
/// comparison for a sample written after that fix; a row written before it
/// may still carry `arp -n`'s raw, unpadded form. The AP-is-the-gateway
/// comparison itself is deferred to the roam step.
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

/// Extract the DHCP lease's start time from `ipconfig getsummary` output: the
/// line whose trimmed form is `LeaseStartTime : MM/DD/YYYY HH:MM:SS`, indented
/// inside the `DHCP : <dictionary>` block and matched by trimmed prefix like
/// [`parse_bssid`]. The text carries no time zone, so this stops at the naive
/// (zone-less) value; [`lease_start_to_us`] resolves it against the machine's
/// own local zone. `None` when the line is absent or does not parse.
fn parse_lease_start(output: &str) -> Option<NaiveDateTime> {
    output.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("LeaseStartTime")?
            .trim_start()
            .strip_prefix(':')?
            .trim();
        NaiveDateTime::parse_from_str(value, "%m/%d/%Y %H:%M:%S").ok()
    })
}

/// Resolve a naive (zone-less) lease-start timestamp against the machine's
/// LOCAL time zone into epoch microseconds. `None` when the local time is
/// ambiguous or does not exist there — a DST fold or gap — since only
/// [`LocalResult::Single`] names one unambiguous instant; guessing across a
/// fold or gap would be a fabricated value, not a measurement.
fn lease_start_to_us(naive: NaiveDateTime) -> Option<i64> {
    match Local.from_local_datetime(&naive) {
        LocalResult::Single(dt) => Some(dt.timestamp_micros()),
        _ => None,
    }
}

/// Extract the DHCP lease length, seconds, from `ipconfig getsummary` output:
/// the line whose trimmed form starts `lease_time (uint32): <value>`, inside
/// the packet dump nested under `DHCP : <dictionary>`. `<value>` is hex with a
/// `0x` prefix (as macOS prints it) or plain decimal — both are accepted.
/// `None` when the line is absent or `<value>` parses as neither.
fn parse_lease_secs(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("lease_time")?;
        let value = rest.split(':').nth(1)?.trim();
        match value.strip_prefix("0x") {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => value.parse().ok(),
        }
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
/// net-observer, node #118) — readable by root without Location Services,
/// which is what makes it the medium signal where the SSID and BSSID are not
/// (node #108). As #118 records, the output shape this parser expects
/// (`Hardware Port:` / `Device:` blocks) is from documentation and has not
/// yet been observed on the owner's Mac; the parser answers `None` on any
/// shape it does not recognise, never a guess. `None` also when the table
/// cannot be read or does not list the interface. Read every tick, one
/// command, from the interface the tick resolved.
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

    /// `ipconfig getsummary en0` as OBSERVED on the owner's Mac (macOS
    /// 26.6.2, `<redacted>` literal — realm net-observer, node #93 item 1):
    /// the DHCP lease dictionary, with its `LeaseStartTime` and the raw
    /// `lease_time` packet field the lease-length parser reads.
    const GETSUMMARY_LEASE_FIXTURE: &str = r#"<dictionary> {
  BSSID : <redacted>
  ConnectionID : 200
  IPv4 : <array> {
    0 : <dictionary> {
      Addresses : <array> {
        0 : 192.168.1.135
      }
      ChildServiceID : LINKLOCAL-en0
      ConfigMethod : DHCP
      DHCP : <dictionary> {
        LeaseExpirationTime : 09/17/2026 23:54:04
        LeaseStartTime : 09/16/2026 23:54:04
        Packet : op = BOOTREPLY
htype = 1
flags = 0x0
hlen = 6
hops = 0
xid = 0x78e7c002
secs = 1
ciaddr = 0.0.0.0
yiaddr = 192.168.1.135
siaddr = 192.168.1.1
giaddr = 0.0.0.0
chaddr = ca:8f:38:b3:12:d3
sname =
file =
options:
Options count is 10
dhcp_message_type (uint8): ACK 0x5
server_identifier (ip): 192.168.1.1
lease_time (uint32): 0x15180
renewal_t1_time_value (uint32): 0xa8c0
rebinding_t2_time_value (uint32): 0x12750
subnet_mask (ip): 255.255.255.0
domain_name (string): localdomain
domain_name_server (ip_mult): {192.168.1.1}
router (ip_mult): {192.168.1.1}
end (none):

        State : BOUND
      }
      IsPublished : TRUE
      Router : 192.168.1.1
      RouterARPVerified : TRUE
      ServiceID : 00DE6ED1-F7AC-46C8-A8DF-C3B38A93C64F
      SubnetMasks : <array> {
        0 : 255.255.255.0
      }
    }
    1 : <dictionary> {
      ConfigMethod : LinkLocal
      IsPublished : TRUE
      ParentServiceID : 00DE6ED1-F7AC-46C8-A8DF-C3B38A93C64F
      ServiceID : LINKLOCAL-en0
    }
  }
  IPv6 : <array> {
    0 : <dictionary> {
      ConfigMethod : Automatic
      DHCPv6 : <dictionary> {
        Mode : None
        State : Inactive
      }
      IsPublished : FALSE
      LastFailureStatus : network changed
      RTADV : <dictionary> {
        State : Solicit
      }
      ServiceID : 00DE6ED1-F7AC-46C8-A8DF-C3B38A93C64F
    }
  }
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  NetworkID : <redacted>
  SSID : <redacted>
  Security : WPA3_SAE
}
"#;

    /// The real macOS 26 fixture redacts the BSSID; `normalize_mac` already
    /// answers `None` for non-hex-colon text like `<redacted>`, so no
    /// separate sentinel is needed — the same absence a pre-26 non-association
    /// produces.
    #[test]
    fn bssid_is_none_on_the_macos_26_redacted_fixture() {
        assert_eq!(parse_bssid(GETSUMMARY_LEASE_FIXTURE), None);
    }

    #[test]
    fn parses_lease_start_from_the_real_fixture() {
        assert_eq!(
            parse_lease_start(GETSUMMARY_LEASE_FIXTURE),
            Some(
                NaiveDateTime::parse_from_str("09/16/2026 23:54:04", "%m/%d/%Y %H:%M:%S").unwrap()
            )
        );
    }

    /// Not the `LeaseExpirationTime` line just above it in the same block —
    /// dies under a prefix match loose enough to catch both.
    #[test]
    fn lease_start_does_not_match_the_expiration_line() {
        let out = "DHCP : <dictionary> {\n  LeaseExpirationTime : 09/17/2026 23:54:04\n}\n";
        assert_eq!(parse_lease_start(out), None);
    }

    #[test]
    fn no_lease_start_when_the_line_is_absent() {
        assert_eq!(
            parse_lease_start("DHCP : <dictionary> {\n  State : BOUND\n}\n"),
            None
        );
    }

    #[test]
    fn no_lease_start_for_an_unparseable_date() {
        let out = "LeaseStartTime : not-a-date\n";
        assert_eq!(parse_lease_start(out), None);
    }

    /// `lease_time (uint32): 0x15180` — hex with the `0x` macOS prints — is
    /// 86400 seconds, 24 hours.
    #[test]
    fn parses_lease_secs_from_the_real_fixture() {
        assert_eq!(parse_lease_secs(GETSUMMARY_LEASE_FIXTURE), Some(86400));
    }

    #[test]
    fn parses_lease_secs_accepts_plain_decimal_too() {
        let out = "lease_time (uint32): 3600\n";
        assert_eq!(parse_lease_secs(out), Some(3600));
    }

    #[test]
    fn no_lease_secs_when_the_line_is_absent() {
        assert_eq!(parse_lease_secs("State : BOUND\n"), None);
    }

    #[test]
    fn no_lease_secs_for_an_unparseable_value() {
        let out = "lease_time (uint32): not-a-number\n";
        assert_eq!(parse_lease_secs(out), None);
    }

    /// The ordinary case — an instant with a single, unambiguous local
    /// offset — resolves to a value; only a DST fold/gap must answer `None`
    /// (a claim [`lease_start_to_us`]'s own zone-dependence keeps this test
    /// from pinning to a specific epoch: node #93 item 1, node #109 item 1).
    #[test]
    fn lease_start_to_us_resolves_an_unambiguous_instant() {
        let naive = parse_lease_start(GETSUMMARY_LEASE_FIXTURE).unwrap();
        assert!(lease_start_to_us(naive).is_some());
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
