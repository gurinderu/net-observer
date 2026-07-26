//! The `link` collector's port trait: static/link facts gathered from the OS
//! (route table, DHCP lease, ARP, Wi-Fi) behind a trait boundary so the mapping
//! logic stays unit-testable with fakes. The real macOS adapter lives in the
//! `macos` crate.

use collector_core::Readiness;

/// Static/link facts gathered from the OS (route table, DHCP lease, ARP, Wi-Fi).
///
/// Native `async fn` in a trait (no `async-trait` macro); the daemon drives it
/// via static dispatch, so the trait is intentionally not dyn-compatible.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait LinkFacts: Send + Sync {
    async fn default_gw(&self) -> Option<String>;
    async fn phys_iface(&self) -> Option<String>;
    async fn dhcp(&self) -> (Option<String>, Option<String>);
    async fn gw_arp_mac(&self, gw: &str) -> Option<String>;
    async fn ssid(&self) -> Option<String>;
    async fn wifi_capture_present(&self) -> bool;
    /// Runtime capability probe: Ready iff the `link` collector can work here/now
    /// (e.g. a physical interface is resolvable), else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
