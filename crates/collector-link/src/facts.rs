//! The `link` collector's port trait: static/link facts gathered from the OS
//! (route table, DHCP lease, ARP, Wi-Fi) behind a trait boundary so the mapping
//! logic stays unit-testable with fakes. The real macOS adapter lives in the
//! `macos` crate.

use collector_core::Readiness;

/// Static/link facts gathered from the OS (route table, DHCP lease, ARP, Wi-Fi).
pub trait LinkFacts: Send + Sync {
    fn default_gw(&self) -> Option<String>;
    fn phys_iface(&self) -> Option<String>;
    fn dhcp(&self) -> (Option<String>, Option<String>);
    fn gw_arp_mac(&self, gw: &str) -> Option<String>;
    fn ssid(&self) -> Option<String>;
    fn wifi_capture_present(&self) -> bool;
    /// Runtime capability probe: Ready iff the `link` collector can work here/now
    /// (e.g. a physical interface is resolvable), else `Unavailable(reason)`.
    fn preflight(&self) -> Readiness;
}
