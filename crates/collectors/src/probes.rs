//! Probe traits — platform I/O behind trait boundaries so all collector mapping
//! logic is unit-testable with fakes. Real macOS adapters live in the `macos` crate.

/// Outcome of a reachability probe: whether the target answered and, if so, its RTT.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingOutcome {
    pub reachable: bool,
    pub rtt_ms: Option<f64>,
}

/// ICMP echo to the default gateway.
pub trait Pinger {
    fn ping_gw(&self, gw: &str) -> PingOutcome;
}

/// TCP connect bound to a specific physical interface (`IP_BOUND_IF`).
pub trait TcpProber {
    fn connect_bound(&self, host: &str, port: u16, iface: &str) -> PingOutcome;
}

/// Static/link facts gathered from the OS (route table, DHCP lease, ARP, Wi-Fi).
pub trait LinkFacts {
    fn default_gw(&self) -> Option<String>;
    fn phys_iface(&self) -> Option<String>;
    fn dhcp(&self) -> (Option<String>, Option<String>);
    fn gw_arp_mac(&self, gw: &str) -> Option<String>;
    fn ssid(&self) -> Option<String>;
    fn wifi_capture_present(&self) -> bool;
}

/// Proxy facts: the VLESS server IPs, the TUN HTTP 204 probe, and the Clash selector.
pub trait ProxyFacts {
    fn vless_ips(&self) -> Vec<String>;
    fn tun_probe(&self, url: &str) -> Option<u16>;
    fn selector(&self) -> Option<String>;
}
