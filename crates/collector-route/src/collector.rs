//! Static [`META`] and the [`RouteCollector`] — the first **Event**-cadence
//! collector. It owns a persistent PF_ROUTE [`EventSource`] (opened by the `macos`
//! crate) and hands it to the daemon's blocking `next()` loop via
//! [`Collector::into_event_source`].

use std::sync::Mutex;

use collector_core::{Collector, CollectorMeta, EventSource, Os, Readiness, Source};

/// Static metadata for the `route` collector: macOS-only in v1.
pub const META: CollectorMeta = CollectorMeta {
    name: "route",
    supported_os: &[Os::MacOs],
};

/// The `route` collector: the first **Event**-cadence collector. It owns a
/// blocking PF_ROUTE [`EventSource`] (opened by the `macos` crate) and its
/// [`Readiness`] is decided at construction (the adapter tries to open the
/// socket). The daemon takes the source out with [`Collector::into_event_source`]
/// and drives its blocking `next()` loop on the blocking pool.
///
/// The source is held behind a [`Mutex`] purely to make `RouteCollector`
/// `Sync` — [`EventSource`] is only `Send`, but [`Collector`] requires
/// `Send + Sync`. It is never actually contended: the daemon takes the source out
/// by value before driving it.
pub struct RouteCollector {
    source: Mutex<Box<dyn EventSource>>,
    ready: Readiness,
}

impl RouteCollector {
    /// Construct a `route` collector from an already-opened event source and the
    /// readiness verdict from opening it (Ready iff a PF_ROUTE socket opened).
    pub fn new(source: Box<dyn EventSource>, ready: Readiness) -> Self {
        Self {
            source: Mutex::new(source),
            ready,
        }
    }
}

impl Collector for RouteCollector {
    fn meta(&self) -> &'static CollectorMeta {
        &META
    }

    fn source(&self) -> Source {
        Source::Event
    }

    fn preflight(&self) -> Readiness {
        self.ready.clone()
    }

    fn into_event_source(self: Box<Self>) -> Option<Box<dyn EventSource>> {
        self.source.into_inner().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{RouteEvent, Sample};

    /// A fake [`EventSource`] that yields a fixed list of batches, then `None`.
    struct FakeSource {
        batches: std::vec::IntoIter<Vec<Sample>>,
    }

    impl EventSource for FakeSource {
        fn next(&mut self) -> Option<Vec<Sample>> {
            self.batches.next()
        }
    }

    fn route_event(kind: &str, detail: &str) -> Sample {
        Sample::Route(RouteEvent {
            ts_us: 1,
            kind: kind.into(),
            iface: Some("en0".into()),
            detail: detail.into(),
        })
    }

    fn collector(ready: Readiness) -> RouteCollector {
        let batches = vec![
            vec![route_event("iface", "up")],
            vec![route_event("route", "default changed")],
        ];
        RouteCollector::new(
            Box::new(FakeSource {
                batches: batches.into_iter(),
            }),
            ready,
        )
    }

    #[test]
    fn source_is_event_cadence() {
        assert!(matches!(
            collector(Readiness::Ready).source(),
            Source::Event
        ));
    }

    #[test]
    fn preflight_reflects_constructed_readiness() {
        assert!(collector(Readiness::Ready).preflight().is_ready());
        let c = collector(Readiness::Unavailable("no PF_ROUTE socket".into()));
        assert!(!c.preflight().is_ready());
    }

    #[test]
    fn event_source_passes_batches_through_then_ends() {
        let c = Box::new(collector(Readiness::Ready));
        let mut src = c.into_event_source().expect("event source present");

        let first = src.next().expect("first batch");
        assert_eq!(first.len(), 1);
        assert!(matches!(first[0], Sample::Route(_)));

        let second = src.next().expect("second batch");
        assert_eq!(second.len(), 1);
        assert!(matches!(second[0], Sample::Route(_)));

        assert!(src.next().is_none());
    }
}
