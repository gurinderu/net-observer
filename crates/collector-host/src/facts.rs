//! The `host` collector's port trait: host load averages read from the OS behind
//! a trait boundary so the mapping logic stays unit-testable with fakes. The real
//! macOS adapter (`libc::getloadavg`) lives in the `macos` crate.

use collector_core::Readiness;

/// Host load facts gathered from the OS (1/5/15-minute load averages).
///
/// The methods are native `async fn` (no `async-trait` macro) so real adapters
/// can use async-native I/O; the macOS `getloadavg` reader awaits an instant
/// syscall. Static dispatch (the collector is generic over `F: HostFacts`) keeps
/// this dyn-free, since native `async fn` in traits is not object-safe.
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait HostFacts: Send + Sync {
    /// The 1/5/15-minute load averages, or `None` when the OS load is unreadable.
    async fn loadavg(&self) -> Option<(f64, f64, f64)>;
    /// Runtime capability probe: Ready iff the load average is readable here/now,
    /// else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
