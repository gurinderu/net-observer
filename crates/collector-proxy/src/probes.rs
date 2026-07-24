//! The proxy collector's port trait — platform I/O behind a trait boundary so the
//! mapping logic is unit-testable with fakes. The real macOS adapter lives in the
//! `macos` crate. Generic net probes (`Pinger`/`TcpProber`) live in `collector-core`.

use collector_core::Readiness;

/// Proxy facts: the VLESS server IPs, the TUN HTTP 204 probe, and the Clash selector.
pub trait ProxyFacts: Send + Sync {
    fn vless_ips(&self) -> Vec<String>;
    fn tun_probe(&self, url: &str) -> Option<u16>;
    fn selector(&self) -> Option<String>;
    /// Runtime capability probe: can the proxy collector work here/now?
    fn preflight(&self) -> Readiness;
}
