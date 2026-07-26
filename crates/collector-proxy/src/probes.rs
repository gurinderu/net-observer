//! The proxy collector's port trait — platform I/O behind a trait boundary so the
//! mapping logic is unit-testable with fakes. The real macOS adapter lives in the
//! `macos` crate. Generic net probes (`Pinger`/`TcpProber`) live in `collector-core`.

use collector_core::Readiness;

/// Proxy facts: the upstream proxy server addresses, the TUN HTTP 204 probe, and
/// the active upstream node selection.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait ProxyFacts: Send + Sync {
    /// The upstream proxy server addresses to TCP-probe.
    async fn server_endpoints(&self) -> Vec<String>;
    async fn tun_probe(&self, url: &str) -> Option<u16>;
    async fn selector(&self) -> Option<String>;
    /// Runtime capability probe: can the proxy collector work here/now?
    async fn preflight(&self) -> Readiness;
}
