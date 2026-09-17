//! The `link` collector's port trait: static/link facts gathered from the OS
//! (route table, DHCP lease, ARP, Wi-Fi) behind a trait boundary so the mapping
//! logic stays unit-testable with fakes. The real macOS adapter lives in the
//! `macos` crate.

use collector_core::Readiness;
use types::LinkMedium;

/// One parse of `ipconfig getsummary <iface>` (the macOS adapter's own name
/// for the same bundle is `macos::wifi::Summary`), carrying the three facts
/// the daemon reads out of that single call: the associated AP's BSSID and
/// the current DHCP lease's start and length. Bundled because the source
/// command is one and the same, so [`LinkFacts::summary`] replaces what used
/// to be a separate `bssid` method (realm net-observer, node #93 item 1; node
/// #109 item 1).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkSummary {
    /// BSSID of the access point `iface` is associated with, lowercase;
    /// `None` = not associated or not determinable.
    pub bssid: Option<String>,
    /// Start of the current DHCP lease, epoch microseconds. `None` = absent,
    /// unparseable, or the local time was ambiguous/nonexistent (a DST
    /// fold/gap).
    pub lease_start_us: Option<i64>,
    /// Length of the current DHCP lease, seconds. `None` = absent or
    /// unparseable.
    pub lease_secs: Option<u32>,
}

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
    /// The interface carrying sing-box's OWN TUN address (from the rendered
    /// config), or `None` when that address is on no interface — the
    /// sing-box-alive fact, since the address exists only while sing-box runs.
    /// A local read, no packet on the wire. NOT "any `utun*`": foreign VPNs
    /// (tailscale/netbird) create utuns too, so only sing-box's own address
    /// proves sing-box specifically is up. Paired with `fakeip_route_iface` in
    /// one tick.
    async fn singbox_tun_iface(&self) -> Option<String>;
    // The four per-interface reads below take the interface the COLLECTOR
    // resolved at the start of the tick rather than resolving it themselves:
    // one route lookup per tick, so a default-route move between two reads
    // (a dock or undock) can never stamp one sample with a Wi-Fi medium and
    // the wired adapter's MAC — which would read as a roam that never was.
    /// The SSID `iface` is joined to; `None` = not associated, not readable
    /// (a root reader gets `<redacted>`), or not determinable.
    async fn ssid(&self, iface: &str) -> Option<String>;
    /// [`LinkSummary`] parsed from ONE `ipconfig getsummary <iface>` call:
    /// the BSSID `iface` is associated with plus the DHCP lease's start and
    /// length. `LinkSummary::default()` (every field `None`) when nothing is
    /// determinable — never a fabricated value.
    async fn summary(&self, iface: &str) -> LinkSummary;
    /// `iface`'s own MAC as currently assigned, lowercase; `None` = not
    /// determinable. Private Wi-Fi Address rotates it per SSID.
    async fn if_mac(&self, iface: &str) -> Option<String>;
    /// The medium of `iface` — the one `if_mac` belongs to — as measured from
    /// the hardware-port table, never inferred from whether a Wi-Fi name was
    /// readable; `None` = not determinable (the table could not be read or
    /// does not list the interface).
    async fn medium(&self, iface: &str) -> Option<LinkMedium>;
    async fn wifi_capture_present(&self) -> bool;
    /// Runtime capability probe: Ready iff the `link` collector can work here/now
    /// (e.g. a physical interface is resolvable), else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
