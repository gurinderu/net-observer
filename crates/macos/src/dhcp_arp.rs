//! Link-layer facts gathered from macOS command-line tools:
//! default gateway + physical interface (`route -n get default`), the DHCP
//! lease (`ipconfig getpacket`), the gateway's ARP entry (`arp -n`), the
//! joined SSID and any recent Wi-Fi driver capture.
//!
//! Every field parses defensively: a missing tool, non-zero exit, or
//! unrecognised output yields `None`, never a panic — "absence is a signal".

use std::time::Duration;

use collector_core::Readiness;
use collector_link::LinkFacts;
use tokio::process::Command;

use crate::wifi;

/// Default look-back window for a "recent" CoreCapture Wi-Fi bundle.
const DEFAULT_CAPTURE_WINDOW: Duration = Duration::from_secs(600);

/// macOS implementation of [`LinkFacts`].
///
/// Optional `gw`/`phys_iface` overrides let config pin the detection targets;
/// when `None`, both are read from the kernel route table.
#[derive(Debug, Clone)]
pub struct SystemFacts {
    gw_override: Option<String>,
    iface_override: Option<String>,
    capture_window: Duration,
}

impl Default for SystemFacts {
    fn default() -> Self {
        Self {
            gw_override: None,
            iface_override: None,
            capture_window: DEFAULT_CAPTURE_WINDOW,
        }
    }
}

impl SystemFacts {
    /// Build with optional gateway / physical-interface overrides (from config).
    #[must_use]
    pub fn new(gw_override: Option<String>, iface_override: Option<String>) -> Self {
        Self {
            gw_override,
            iface_override,
            capture_window: DEFAULT_CAPTURE_WINDOW,
        }
    }
}

impl LinkFacts for SystemFacts {
    async fn default_gw(&self) -> Option<String> {
        if let Some(gw) = &self.gw_override {
            return Some(gw.clone());
        }
        let out = run("route", &["-n", "get", "default"]).await?;
        parse_route_field(&out, "gateway")
    }

    async fn phys_iface(&self) -> Option<String> {
        if let Some(iface) = &self.iface_override {
            return Some(iface.clone());
        }
        let out = run("route", &["-n", "get", "default"]).await?;
        parse_route_field(&out, "interface")
    }

    async fn dhcp(&self) -> (Option<String>, Option<String>) {
        let Some(iface) = self.phys_iface().await else {
            return (None, None);
        };
        let Some(out) = run("ipconfig", &["getpacket", &iface]).await else {
            return (None, None);
        };
        let router = ip_for_key(&out, "router");
        let dns = ip_for_key(&out, "domain_name_server");
        (router, dns)
    }

    async fn gw_arp_mac(&self, gw: &str) -> Option<String> {
        let out = run("arp", &["-n", gw]).await?;
        parse_arp_mac(&out, gw)
    }

    async fn ssid(&self) -> Option<String> {
        let iface = self.phys_iface().await?;
        wifi::current_ssid(&iface).await
    }

    async fn wifi_capture_present(&self) -> bool {
        // A directory scan (not a subprocess): an instant filesystem read kept
        // synchronous inside the async fn.
        wifi::wifi_capture_present(self.capture_window)
    }

    async fn preflight(&self) -> Readiness {
        if self.phys_iface().await.is_some() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("no physical interface".into())
        }
    }
}

/// Run `cmd args...` and return its stdout as a `String`, or `None` if the
/// process could not be spawned or its output was not valid UTF-8.
async fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = match Command::new(cmd).args(args).output().await {
        Ok(o) => o,
        Err(e) => {
            tracing::debug!(cmd, error = %e, "command failed to spawn");
            return None;
        }
    };
    String::from_utf8(out.stdout).ok()
}

/// Extract `<field>: <value>` from `route -n get default` output (values are
/// whitespace-indented, one per line).
fn parse_route_field(text: &str, field: &str) -> Option<String> {
    let prefix = format!("{field}: ");
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .map(|v| v.trim().to_string())
    })
}

/// From `ipconfig getpacket` output, find the first line whose key matches and
/// return the first IPv4 literal on it (handles `key (ip): 1.2.3.4` and
/// `key (ip_mult): {1.2.3.4, 5.6.7.8}` shapes).
fn ip_for_key(text: &str, key: &str) -> Option<String> {
    let line = text.lines().find(|l| l.trim_start().starts_with(key))?;
    first_ipv4(line)
}

/// Return the first token in `s` that parses as an IPv4 address.
fn first_ipv4(s: &str) -> Option<String> {
    s.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find(|tok| tok.parse::<std::net::Ipv4Addr>().is_ok())
        .map(str::to_string)
}

/// Parse the MAC (or the literal `incomplete`) for `gw` from `arp -n` output.
fn parse_arp_mac(output: &str, gw: &str) -> Option<String> {
    let line = output.lines().find(|l| l.contains(gw))?;
    let after = line.split(" at ").nth(1)?;
    let token = after.split_whitespace().next()?;
    if token.starts_with("(incomplete") || token == "incomplete" {
        return Some("incomplete".to_string());
    }
    Some(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE_OUT: &str = "   route to: default\n\
        destination: default\n\
               mask: default\n\
            gateway: 10.20.0.1\n\
          interface: en0\n\
              flags: <UP,GATEWAY,DONE,STATIC>\n";

    #[test]
    fn parses_gateway_and_interface() {
        assert_eq!(
            parse_route_field(ROUTE_OUT, "gateway").as_deref(),
            Some("10.20.0.1")
        );
        assert_eq!(
            parse_route_field(ROUTE_OUT, "interface").as_deref(),
            Some("en0")
        );
    }

    #[test]
    fn missing_route_field_is_none() {
        assert_eq!(parse_route_field(ROUTE_OUT, "nexthop"), None);
    }

    #[test]
    fn extracts_dhcp_router_and_dns() {
        let out = "op = BOOTREPLY\n\
            router (ip_mult): {10.20.0.1}\n\
            domain_name_server (ip_mult): {10.20.0.1, 8.8.8.8}\n\
            lease_time (uint32): 0x15180\n";
        assert_eq!(ip_for_key(out, "router").as_deref(), Some("10.20.0.1"));
        assert_eq!(
            ip_for_key(out, "domain_name_server").as_deref(),
            Some("10.20.0.1")
        );
        assert_eq!(ip_for_key(out, "subnet_mask"), None);
    }

    #[test]
    fn parses_arp_mac() {
        let out = "? (10.20.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n";
        assert_eq!(
            parse_arp_mac(out, "10.20.0.1").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }

    #[test]
    fn parses_arp_incomplete() {
        let out = "? (10.20.0.1) at (incomplete) on en0 ifscope [ethernet]\n";
        assert_eq!(
            parse_arp_mac(out, "10.20.0.1").as_deref(),
            Some("incomplete")
        );
    }

    #[test]
    fn arp_absent_gateway_is_none() {
        let out = "? (192.168.1.1) at 11:22:33:44:55:66 on en0\n";
        assert_eq!(parse_arp_mac(out, "10.20.0.1"), None);
    }

    #[tokio::test]
    async fn overrides_short_circuit_command() {
        let facts = SystemFacts::new(Some("1.2.3.4".into()), Some("en5".into()));
        assert_eq!(facts.default_gw().await.as_deref(), Some("1.2.3.4"));
        assert_eq!(facts.phys_iface().await.as_deref(), Some("en5"));
    }
}
