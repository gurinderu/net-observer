use types::HostSample;

/// Pure, synchronous mapping from a fetched load-average reading to a
/// [`HostSample`]. The collector `await`s the load probe, then this sync `build_*`
/// composes the sample from the fetched value — async lives only in the probe.
/// Returns `None` when the OS load average was unreadable, so the collector emits
/// a skip (a missing `host_sample` row is itself diagnostic).
pub fn build_host_sample(ts_us: i64, load: Option<(f64, f64, f64)>) -> Option<HostSample> {
    let (load1, load5, load15) = load?;
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

    #[test]
    fn readable_loadavg_yields_a_host_sample() {
        let s = build_host_sample(42, Some((1.0, 2.0, 3.0))).expect("sample");
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.load1, 1.0);
        assert_eq!(s.load5, 2.0);
        assert_eq!(s.load15, 3.0);
    }

    #[test]
    fn unreadable_loadavg_yields_none() {
        assert!(build_host_sample(42, None).is_none());
    }
}
