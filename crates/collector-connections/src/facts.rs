//! The `connections` collector's port trait: the live flows the proxy carries,
//! read from its API behind a trait boundary so the fold stays unit-testable
//! with fakes. The real adapter (`GET /connections` on sing-box's Clash API)
//! lives in the `macos` crate.

use collector_core::Readiness;
use types::LiveConnection;

/// The proxy's live flow list, as one reading.
///
/// The methods are native `async fn` (no `async-trait` macro) so the real
/// adapter can use async-native HTTP. Static dispatch (the collector is generic
/// over `F: ConnectionFacts`) keeps this dyn-free, since native `async fn` in
/// traits is not object-safe.
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait ConnectionFacts: Send + Sync {
    /// Every live flow the API lists right now — an empty list when nothing
    /// is talking. `None` when the API did not answer (unreachable, a non-2xx
    /// status, an undecodable body): the tick is then a `SKIP` sample, never
    /// silence, and never an empty list that would read as "nothing is
    /// talking".
    async fn connections(&self) -> Option<Vec<LiveConnection>>;
    /// Runtime capability probe: `Ready` iff the API is configured at all,
    /// else `Unavailable(reason)`. Whether it answers is a per-tick fact the
    /// verdict carries, not a preflight.
    async fn preflight(&self) -> Readiness;
}
