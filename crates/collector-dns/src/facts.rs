//! The `dns` collector's port trait: resolver probes (sing-box TUN DNS, DHCP
//! resolver, DoH, control domain) behind a trait boundary so the mapping logic
//! stays unit-testable with fakes. The real macOS adapter lives in the `macos`
//! crate.

use collector_core::Readiness;
use types::DnsVerdict;

/// Resolver facts: the set of `(name, server)` probe pairs to run and the
/// resolution of each. `FAKEIP` on a `.ru` name is decided here (in the facts)
/// and passed through verbatim by the collector.
///
/// The probe methods are `async` — the real adapter resolves over the network
/// (system `getaddrinfo`, DoH request) — while the pure sample assembly stays
/// synchronous: [`crate::DnsCollector::collect`] `await`s these, then hands the
/// fetched values to the sync [`crate::build_dns_samples`].
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait DnsFacts: Send + Sync {
    /// Resolve `probe` via `server`, yielding its verdict, resolved IP (if any),
    /// and round-trip time in milliseconds (if measured).
    async fn resolve(&self, probe: &str, server: &str)
    -> (DnsVerdict, Option<String>, Option<f64>);
    /// The `(name, server)` pairs to probe this tick (e.g. `("nks", "sb")`).
    async fn probes(&self) -> Vec<(String, String)>;
    /// Runtime capability probe: Ready iff at least one resolver path is
    /// configured, else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
