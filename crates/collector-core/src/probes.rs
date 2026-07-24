//! Probe traits — platform I/O behind trait boundaries so all collector mapping
//! logic is unit-testable with fakes. Real macOS adapters live in the `macos` crate.
//!
//! These are the *generic* net probes shared by every collector. Collector-specific
//! port traits (`LinkFacts`, `ProxyFacts`) live in their own collector crates.

/// Outcome of a reachability probe: whether the target answered and, if so, its RTT.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingOutcome {
    pub reachable: bool,
    pub rtt_ms: Option<f64>,
}

/// ICMP echo to the default gateway.
pub trait Pinger: Send + Sync {
    fn ping_gw(&self, gw: &str) -> PingOutcome;
}

/// TCP connect bound to a specific physical interface (`IP_BOUND_IF`).
pub trait TcpProber: Send + Sync {
    fn connect_bound(&self, host: &str, port: u16, iface: &str) -> PingOutcome;
}
