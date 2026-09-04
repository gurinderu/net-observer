//! The `air` collector's port trait: the radio environment read from the OS
//! behind a trait boundary, so the mapping logic stays unit-testable with fakes.
//! The real adapter (`system_profiler -json SPAirPortDataType`) lives in the
//! `macos` crate.

use std::future::Future;

use collector_core::Readiness;
use types::AirObservation;

/// What the OS answered for one radio-environment scan.
///
/// The two arms are the whole vocabulary the mapping needs: either the scan ran
/// and there is a list (possibly empty — "nobody else is audible" is a reading),
/// or it could not run and says why. "Could not run" is not silence: it becomes a
/// `SKIP` sample carrying the reason, every period, for as long as it lasts — and
/// crucially never an empty list, which would read as clear air.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AirRead {
    /// The scan ran; these are the foreign access points it heard.
    Scan(Vec<AirObservation>),
    /// The scan could not run (radio off, the system report failed or carried no
    /// wireless section). The string is the operator-facing reason recorded on
    /// the SKIP sample.
    Unavailable(String),
}

/// Radio-environment facts gathered from the OS.
///
/// Native `async fn` in a trait (no `async-trait` macro); the daemon drives it
/// via static dispatch, so the trait is intentionally not dyn-compatible.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait AirFacts: Send + Sync {
    /// Scan once. Never fails: an unusable radio is an [`AirRead::Unavailable`]
    /// carrying its reason, not an `Err` and never a missing period.
    ///
    /// Spelled out as `impl Future + Send` rather than `async fn` because a
    /// consumer spawns it onto the multi-threaded runtime: an operator-pressed
    /// scan runs as its own task so the control socket answers immediately
    /// instead of holding the connection for the seconds the report costs.
    /// `async fn` in a trait promises nothing about `Send`, and the bound cannot
    /// be added at the call site, so it belongs here — where the port states what
    /// its callers need. Implementors may still write a plain `async fn`.
    fn read(&self) -> impl Future<Output = AirRead> + Send;
    /// Runtime capability probe: Ready iff the report can be produced here/now,
    /// else `Unavailable(reason)`.
    async fn preflight(&self) -> Readiness;
}
