//! Static [`META`] and the [`AnnounceCollector`] — an **Event**-cadence
//! collector shaped exactly like `collector-route`'s: it owns a blocking
//! [`EventSource`] (an [`crate::AnnounceSource`] over the capture child's
//! stdout, opened by the `macos` crate) and hands it to the daemon's
//! `spawn_event_collector` through [`Collector::into_event_source`]. Its
//! [`Readiness`] is decided at construction: whether the capture started.

use std::sync::Mutex;

use collector_core::{Collector, CollectorMeta, EventSource, Os, Readiness, Source};

/// Static metadata for the `announce` collector. macOS-only like the others:
/// the capture behind it is a `tcpdump` child the `macos` crate spawns.
pub const META: CollectorMeta = CollectorMeta {
    name: "announce",
    supported_os: &[Os::MacOs],
};

/// The `announce` collector: the passive listener for what the segment says
/// about itself, driven on a dedicated thread like the `route` collector.
///
/// The source is held behind a [`Mutex`] purely to make the collector `Sync`
/// — [`EventSource`] is only `Send`, but [`Collector`] requires `Send + Sync`.
/// It is never contended: the daemon takes the source out by value before
/// driving it.
pub struct AnnounceCollector {
    source: Mutex<Box<dyn EventSource>>,
    ready: Readiness,
}

impl AnnounceCollector {
    /// Construct from an already-opened source and the readiness verdict from
    /// opening it (`Ready` iff the capture child started).
    pub fn new(source: Box<dyn EventSource>, ready: Readiness) -> Self {
        Self {
            source: Mutex::new(source),
            ready,
        }
    }
}

impl Collector for AnnounceCollector {
    fn meta(&self) -> &'static CollectorMeta {
        &META
    }

    fn source(&self) -> Source {
        Source::Event
    }

    async fn preflight(&self) -> Readiness {
        self.ready.clone()
    }

    fn into_event_source(self: Box<Self>) -> Option<Box<dyn EventSource>> {
        self.source.into_inner().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Sample;

    struct Ended;
    impl EventSource for Ended {
        fn next(&mut self) -> Option<Vec<Sample>> {
            None
        }
    }

    #[test]
    fn event_cadence_with_readiness_decided_at_construction() {
        let c = AnnounceCollector::new(Box::new(Ended), Readiness::Ready);
        assert_eq!(c.meta().name, "announce");
        assert!(matches!(c.source(), Source::Event));
        assert!(
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(c.preflight())
                .is_ready()
        );
        let unavailable = AnnounceCollector::new(
            Box::new(Ended),
            Readiness::Unavailable("tcpdump: not found".into()),
        );
        assert!(
            !tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(unavailable.preflight())
                .is_ready()
        );
        let mut src = Box::new(unavailable)
            .into_event_source()
            .expect("the source is handed over");
        assert!(src.next().is_none());
    }
}
