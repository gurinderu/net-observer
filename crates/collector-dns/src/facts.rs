//! The `dns` collector's port trait: resolver probes (sing-box TUN DNS, DHCP
//! resolver, DoH, control domain) behind a trait boundary so the mapping logic
//! stays unit-testable with fakes. The real macOS adapter lives in the `macos`
//! crate.

use collector_core::Readiness;
use types::DnsVerdict;

/// Resolver facts: the set of `(name, server)` probe pairs to run and the
/// resolution of each. `FAKEIP` on a `.ru` name is decided here (in the facts)
/// and passed through verbatim by the collector.
pub trait DnsFacts: Send + Sync {
    /// Resolve `probe` via `server`, yielding its verdict, resolved IP (if any),
    /// and round-trip time in milliseconds (if measured).
    fn resolve(&self, probe: &str, server: &str) -> (DnsVerdict, Option<String>, Option<f64>);
    /// The `(name, server)` pairs to probe this tick (e.g. `("nks", "sb")`).
    fn probes(&self) -> Vec<(String, String)>;
    /// Runtime capability probe: Ready iff at least one resolver path is
    /// configured, else `Unavailable(reason)`.
    fn preflight(&self) -> Readiness;
}
