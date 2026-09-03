use types::{NeighborsSample, NeighborsVerdict};

use crate::facts::NeighborReading;

/// Pure, synchronous mapping from a neighbour-cache reading to a
/// [`NeighborsSample`]. `None` means the caches were unreadable and yields a SKIP
/// row rather than silence — absence of a signal is itself diagnostic.
#[must_use]
pub fn build_neighbors_sample(ts_us: i64, reading: Option<NeighborReading>) -> NeighborsSample {
    match reading {
        Some(r) => NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: r.network_key,
            iface: r.iface,
            neighbors: r.neighbors,
        },
        None => NeighborsSample {
            ts_us,
            verdict: NeighborsVerdict::Skip,
            reason: Some("neighbour caches unreadable".into()),
            network_key: None,
            iface: None,
            neighbors: Vec::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{NeighborObs, NeighborRole, NeighborSource};

    fn obs(mac: &str) -> NeighborObs {
        NeighborObs {
            mac: mac.into(),
            ip: "192.168.1.5".into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        }
    }

    #[test]
    fn a_reading_maps_to_an_ok_sample() {
        let s = build_neighbors_sample(
            42,
            Some(NeighborReading {
                network_key: Some("aa:bb:cc:dd:ee:ff".into()),
                iface: Some("en0".into()),
                neighbors: vec![obs("11:22:33:44:55:66")],
            }),
        );
        assert_eq!(s.ts_us, 42);
        assert_eq!(s.verdict, NeighborsVerdict::Ok);
        assert_eq!(s.reason, None);
        assert_eq!(s.neighbors.len(), 1);
    }

    /// An empty segment is a measurement, not a SKIP — the distinction the whole
    /// collector rests on.
    #[test]
    fn an_empty_segment_is_ok_not_skip() {
        let s = build_neighbors_sample(
            42,
            Some(NeighborReading {
                network_key: None,
                iface: Some("en0".into()),
                neighbors: Vec::new(),
            }),
        );
        assert_eq!(s.verdict, NeighborsVerdict::Ok);
        assert!(s.neighbors.is_empty());
    }

    #[test]
    fn an_unreadable_cache_is_a_skip_with_a_reason() {
        let s = build_neighbors_sample(42, None);
        assert_eq!(s.verdict, NeighborsVerdict::Skip);
        assert!(s.reason.is_some());
        assert!(s.neighbors.is_empty());
    }
}
