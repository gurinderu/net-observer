//! The `host` collector's port trait: host load averages read from the OS behind
//! a trait boundary so the mapping logic stays unit-testable with fakes. The real
//! macOS adapter (`libc::getloadavg`) lives in the `macos` crate.

use collector_core::Readiness;

/// Host load facts gathered from the OS (1/5/15-minute load averages).
pub trait HostFacts: Send + Sync {
    /// The 1/5/15-minute load averages, or `None` when the OS load is unreadable.
    fn loadavg(&self) -> Option<(f64, f64, f64)>;
    /// Runtime capability probe: Ready iff the load average is readable here/now,
    /// else `Unavailable(reason)`.
    fn preflight(&self) -> Readiness;
}
