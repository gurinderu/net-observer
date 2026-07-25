//! Host load facts read from the OS via `libc::getloadavg(3)`.
//!
//! `getloadavg` is the standard 1/5/15-minute load-average interface on macOS
//! (and Linux). It reads the kernel's exponentially-weighted run-queue average,
//! the starvation discriminator (`load` in the tens while `tun=000`). An
//! unobtainable load average degrades to `None`, never a panic — "absence is a
//! signal".

use collector_core::Readiness;
use collector_host::HostFacts;

/// macOS implementation of [`HostFacts`] backed by `libc::getloadavg(3)`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HostLoad;

impl HostLoad {
    /// Create a new load reader. Stateless.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl HostFacts for HostLoad {
    fn loadavg(&self) -> Option<(f64, f64, f64)> {
        let mut avg = [0f64; 3];
        // SAFETY: `getloadavg` writes up to `nelem` `c_double`s into the buffer;
        // we pass a 3-element buffer and request exactly 3, matching its
        // contract. It returns the number of samples written, or -1 on failure.
        let n = unsafe { libc::getloadavg(avg.as_mut_ptr(), 3) };
        if n == 3 {
            Some((avg[0], avg[1], avg[2]))
        } else {
            None
        }
    }

    fn preflight(&self) -> Readiness {
        if self.loadavg().is_some() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("loadavg unreadable".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loadavg_reads_three_finite_nonnegative_values() {
        // `getloadavg` is available on every macOS host the daemon runs on.
        let (l1, l5, l15) = HostLoad::new().loadavg().expect("loadavg readable");
        for v in [l1, l5, l15] {
            assert!(v.is_finite(), "load average must be finite: {v}");
            assert!(v >= 0.0, "load average must be non-negative: {v}");
        }
    }

    #[test]
    fn preflight_is_ready_when_loadavg_readable() {
        assert!(HostLoad::new().preflight().is_ready());
    }
}
