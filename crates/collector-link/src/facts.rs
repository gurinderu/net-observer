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
    /// IPv4 neighbor addresses from the live ARP cache on the physical
    /// interface — candidates for the probe-on-suspicion neighbor pings. The
    /// gateway is NOT filtered out here; the collector, which knows it, does.
    async fn arp_neighbor_ips(&self) -> Vec<String>;
    /// The egress interface the route table resolves for an address inside
    /// the sing-box fakeip pool — a local lookup, no packet on the wire.
    /// `None` when it cannot be determined (no config, no range, no route).
    async fn fakeip_route_iface(&self) -> Option<String>;
    /// The egress interface the route table resolves for the DEFAULT route — a
    /// local lookup, no packet on the wire. On this host sing-box's `auto_route`
    /// owns the default while the tunnel is up, so this reads a `utun*` then and
    /// the physical interface when the tunnel is down: the tunnel-liveness fact
    /// paired with `fakeip_route_iface` in one tick. `None` when there is no
    /// default route.
    async fn default_route_iface(&self) -> Option<String>;
    async fn ssid(&self) -> Option<String>;
    async fn wifi_capture_present(&self) -> bool;
    /// Runtime capability probe: Ready iff the `link` collector can work here/now
    /// (e.g. a physical interface is resolvable), else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
