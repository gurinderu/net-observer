use types::HostSample;

use crate::facts::HostFacts;

/// Pure mapping from host load facts to a [`HostSample`]. Returns `None` when the
/// OS load average is unreadable — the collector then emits a skip (a missing
/// `host_sample` row is itself diagnostic).
pub fn build_host_sample(ts_us: i64, facts: &dyn HostFacts) -> Option<HostSample> {
    let (load1, load5, load15) = facts.loadavg()?;
    Some(HostSample {
        ts_us,
        load1,
        load5,
        load15,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_core::Readiness;

    struct FakeHost(Option<(f64, f64, f64)>);
    impl HostFacts for FakeHost {
        fn loadavg(&self) -> Option<(f64, f64, f64)> {
            self.0
        }
        fn preflight(&self) -> Readiness {
            if self.0.is_some() {
                Readiness::Ready
            } else {
                Readiness::Unavailable("loadavg unreadable".into())
            }
        }
    }

    #[test]
    fn readable_loadavg_yields_a_host_sample() {
        let s = build_host_sample(42, &FakeHost(Some((1.0, 2.0, 3.0)))).expect("sample");
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.load1, 1.0);
        assert_eq!(s.load5, 2.0);
        assert_eq!(s.load15, 3.0);
    }

    #[test]
    fn unreadable_loadavg_yields_none() {
        assert!(build_host_sample(42, &FakeHost(None)).is_none());
    }
}
