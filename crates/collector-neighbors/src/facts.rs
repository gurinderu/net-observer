//! The `neighbors` collector's port trait: the kernel neighbour caches behind a
//! trait boundary so the mapping stays unit-testable with fakes. The real macOS
//! adapter (`arp -an` / `ndp -an`) lives in the `macos` crate.

use collector_core::Readiness;
use types::NeighborObs;

/// One reading of the neighbour caches.
///
/// An empty `neighbors` list is a *result*, not a failure: a segment where
/// nothing else answers is exactly the fact worth recording. Failure to read at
/// all is `None` from [`NeighborFacts::read`], which becomes a SKIP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborReading {
    /// The gateway's MAC — the segment's identity across visits.
    pub network_key: Option<String>,
    /// The physical interface the neighbours were seen on.
    pub iface: Option<String>,
    pub neighbors: Vec<NeighborObs>,
}

/// Neighbour facts gathered from the OS.
///
/// Native `async fn` (no `async-trait`), static dispatch like the other ports.
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait NeighborFacts: Send + Sync {
    /// Read the neighbour caches, or `None` when they could not be read at all.
    async fn read(&self) -> Option<NeighborReading>;
    /// Runtime capability probe.
    async fn preflight(&self) -> Readiness;
}
