use types::HostSample;

/// Pure, synchronous mapping from the fetched host readings to a
/// [`HostSample`]. The collector `await`s the probes, then this sync `build_*`
/// composes the sample from the fetched values — async lives only in the
/// probes.
///
/// The load average anchors the row: returns `None` when it was unreadable, so
/// the collector emits a skip (a missing `host_sample` row is itself
/// diagnostic). Disk and swap are optional facts on top of it — an unreadable
/// one lands as `None` (not measured) inside an otherwise present sample,
/// never as a zero.
pub fn build_host_sample(
    ts_us: i64,
    load: Option<(f64, f64, f64)>,
    disk: Option<(f64, u64)>,
    swap_used_mb: Option<u64>,
) -> Option<HostSample> {
    let (load1, load5, load15) = load?;
    let (disk_used_pct, disk_free_mb) = match disk {
        Some((pct, free_mb)) => (Some(pct), Some(free_mb)),
        None => (None, None),
    };
    Some(HostSample {
        ts_us,
        load1,
        load5,
        load15,
        disk_used_pct,
        disk_free_mb,
        swap_used_mb,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readable_loadavg_yields_a_host_sample() {
        let s = build_host_sample(42, Some((1.0, 2.0, 3.0)), None, None).expect("sample");
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.load1, 1.0);
        assert_eq!(s.load5, 2.0);
        assert_eq!(s.load15, 3.0);
    }

    #[test]
    fn unreadable_loadavg_yields_none() {
        assert!(build_host_sample(42, None, Some((50.0, 1024)), Some(256)).is_none());
    }

    #[test]
    fn disk_and_swap_land_in_the_sample() {
        let s = build_host_sample(42, Some((1.0, 2.0, 3.0)), Some((87.5, 61_440)), Some(1235))
            .expect("sample");
        assert_eq!(s.disk_used_pct, Some(87.5));
        assert_eq!(s.disk_free_mb, Some(61_440));
        assert_eq!(s.swap_used_mb, Some(1235));
    }

    #[test]
    fn unmeasured_disk_and_swap_stay_none_never_zero() {
        let s = build_host_sample(42, Some((1.0, 2.0, 3.0)), None, None).expect("sample");
        assert_eq!(s.disk_used_pct, None);
        assert_eq!(s.disk_free_mb, None);
        assert_eq!(s.swap_used_mb, None);
    }

    #[test]
    fn disk_and_swap_are_independent() {
        let s = build_host_sample(42, Some((1.0, 2.0, 3.0)), None, Some(0)).expect("sample");
        assert_eq!(s.disk_used_pct, None);
        assert_eq!(s.disk_free_mb, None);
        assert_eq!(s.swap_used_mb, Some(0));
    }
}
