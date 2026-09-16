//! The `host` collector's port trait: host load averages, the record volume's
//! usage and the swap in use, read from the OS behind a trait boundary so the
//! mapping logic stays unit-testable with fakes. The real macOS adapter
//! (`libc::getloadavg`, `libc::statfs`, `sysctlbyname` on `vm.swapusage`) lives in the
//! `macos` crate.

use collector_core::Readiness;

/// Host resource facts gathered from the OS: the 1/5/15-minute load averages
/// (the sample's anchor) plus the two discriminators the retired shell oracle
/// carried and the daemon lacked — disk usage of the volume holding the
/// record and swap in use — measured as decided at (realm net-observer,
/// node #123).
///
/// The methods are native `async fn` (no `async-trait` macro) so real adapters
/// can use async-native I/O; the macOS `getloadavg` reader awaits an instant
/// syscall. Static dispatch (the collector is generic over `F: HostFacts`) keeps
/// this dyn-free, since native `async fn` in traits is not object-safe.
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait HostFacts: Send + Sync {
    /// The 1/5/15-minute load averages, or `None` when the OS load is unreadable.
    async fn loadavg(&self) -> Option<(f64, f64, f64)>;
    /// The record volume's usage as `(used fraction 0–100, free megabytes)` —
    /// the filesystem holding the DB file, which the adapter is constructed
    /// with. `None` = not measured (the volume could not be read), never a
    /// fabricated value.
    async fn disk(&self) -> Option<(f64, u64)>;
    /// Swap in use, megabytes. `None` = not measured.
    async fn swap(&self) -> Option<u64>;
    /// Runtime capability probe: Ready iff the load average is readable here/now,
    /// else `Unavailable(reason)`. Disk and swap are not gated on: each is an
    /// optional fact that lands as `None` when unreadable.
    async fn preflight(&self) -> Readiness;
}
