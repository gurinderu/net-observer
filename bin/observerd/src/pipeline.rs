//! The observerd data pipeline (plan Task 13).
//!
//! Two halves of the streaming architecture from the spec:
//! - [`run`] — the consumer loop: drains the sample stream, persists each
//!   [`Sample`] into the [`Store`], keeps a small in-memory [`RecentWindow`], and
//!   evaluates the [`TriggerEngine`] on every sample. A store write error is
//!   logged (the gap is recorded) but never stops the loop.
//! - [`spawn_interval_collector`] / [`spawn_event_collector`] — supervised tasks
//!   that drive a [`Collector`] by its cadence and forward its samples onto the
//!   stream. The interval spawner runs `collect()` on the blocking pool; if a
//!   probe panics it emits a `SKIP`-bearing sample in its place and keeps ticking
//!   — one failing collector must never take down the others ("absence of a
//!   signal is itself diagnostic"). The event spawner drives a blocking
//!   [`EventSource`] on its own thread.
//!
//! It also provides [`FreezePcapHandler`], the passive handler wired onto the
//! `gw-change` trigger: on any gateway-verdict change it synchronously freezes
//! the pcap ring *before* slow forensic work and records a [`BlobRef`] per file.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use collector_core::{Collector, Source};
use observer_ipc::{IncidentSummary, StatusSnapshot};
use store::{DuckdbStore, Store};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use triggers::engine::TriggerEngine;
use triggers::handlers::Handler;
use triggers::window::RecentWindow;
use types::{BlobRef, Sample};

/// Capacity of the recent-sample window handed to the trigger engine.
const WINDOW_CAP: usize = 64;

/// Drain `rx` until the stream closes, persisting and evaluating each sample and
/// keeping the live [`StatusSnapshot`] current.
///
/// For every [`Sample`]: write it to the store, update the shared `snapshot`
/// (the latest sample for that variant, plus `generated_us`), push it into the
/// recent window, then evaluate all triggers at the sample's own timestamp. A
/// store write failure is logged and the loop continues (a DB outage must not
/// silently drop the live detection stream — the gap is recorded, per the spec);
/// the in-memory snapshot is updated regardless, so the socket API stays live
/// even through a DB hiccup.
pub async fn run(
    store: Arc<DuckdbStore>,
    mut engine: TriggerEngine,
    mut rx: mpsc::Receiver<Sample>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
) {
    let mut window = RecentWindow::new(WINDOW_CAP);
    while let Some(sample) = rx.recv().await {
        let now_us = sample.ts_us();
        if let Err(e) = store.write_sample(&sample) {
            tracing::warn!(error = %e, "store write failed; sample dropped from DB (gap logged)");
        }
        // Mirror the latest sample into the in-memory snapshot the socket serves.
        {
            let mut snap = snapshot.lock().unwrap_or_else(|e| e.into_inner());
            snap.generated_us = now_us;
            match &sample {
                Sample::Link(l) => snap.link = Some(l.clone()),
                Sample::Proxy(p) => snap.proxy = Some(p.clone()),
                Sample::Dns(d) => snap.dns = Some(d.clone()),
                Sample::Host(h) => snap.host = Some(h.clone()),
                // Route events are a stream, not a "latest sample" field of the
                // snapshot; they still bump `generated_us` above.
                Sample::Route(_) => {}
            }
        }
        window.push(sample);
        engine.on_sample(&window, now_us);
    }
    tracing::info!("sample stream closed; pipeline consumer exiting");
}

/// Interval cadence: drive a timer loop, running `collect()` on the blocking pool.
///
/// Isolation guarantees (spec: "one collector failing must never take down the
/// others; a probe that cannot run emits SKIP, never silence"):
/// - if `collect()` panics, `skip(ts_us)` is emitted in its place and the task
///   keeps ticking — it never exits on a probe error;
/// - the task exits cleanly only once the receiver is gone (channel closed).
pub fn spawn_interval_collector(c: Box<dyn Collector>, tx: mpsc::Sender<Sample>) -> JoinHandle<()> {
    let Source::Interval(interval) = c.source() else {
        unreachable!("interval spawner")
    };
    let name = c.meta().name;
    let c: Arc<dyn Collector> = Arc::from(c);
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let ts_us = types::now_us();
            let c2 = Arc::clone(&c);
            let samples = match tokio::task::spawn_blocking(move || c2.collect(ts_us)).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(collector = name, error = %e, "probe failed; SKIP");
                    c.skip(ts_us)
                }
            };
            for s in samples {
                if tx.send(s).await.is_err() {
                    tracing::info!(collector = name, "receiver dropped; collector exiting");
                    return;
                }
            }
        }
    })
}

/// Event cadence: a long-lived blocking source belongs on its own OS thread
/// (not repeated `spawn_blocking`), forwarding via the channel's `blocking_send`.
///
/// The `route` collector (persistent PF_ROUTE socket) is the live Event-cadence
/// consumer: its `next()` is a blocking `read(2)` driven here on the blocking
/// pool. Because a `spawn_blocking` closure cannot be aborted, a `next()` parked
/// on an idle socket keeps this task's stream sender alive through `abort_all`;
/// the daemon therefore bounds its shutdown drain (see `observerd::main`) rather
/// than relying on this task to release the sender.
pub fn spawn_event_collector(c: Box<dyn Collector>, tx: mpsc::Sender<Sample>) -> JoinHandle<()> {
    let name = c.meta().name;
    let Some(mut src) = c.into_event_source() else {
        tracing::error!(
            collector = name,
            "Event cadence but into_event_source() is None"
        );
        return tokio::spawn(async {});
    };
    // Bridge the blocking source into async via a dedicated thread.
    tokio::task::spawn_blocking(move || {
        while let Some(samples) = src.next() {
            for s in samples {
                if tx.blocking_send(s).is_err() {
                    return; // consumer gone
                }
            }
        }
        tracing::info!(collector = name, "event source ended");
    })
}

/// The pcap ring's freeze operation behind a trait, so [`FreezePcapHandler`] is
/// testable without a live `tcpdump` (which needs root). The production impl is
/// `macos::PcapRing`.
pub trait PcapFreezer: Send + Sync {
    /// Copy the current ring into `dest_dir`, returning the written file paths.
    fn freeze(&self, dest_dir: &Path) -> Vec<PathBuf>;
}

impl PcapFreezer for macos::PcapRing {
    fn freeze(&self, dest_dir: &Path) -> Vec<PathBuf> {
        macos::PcapRing::freeze(self, dest_dir)
    }
}

/// A passive [`Handler`] that freezes the pcap ring on fire and records a
/// [`BlobRef`] per copied file. Wired onto the `gw-change` trigger so the
/// volatile ring is preserved *before* any slow forensic work (spec regression
/// risk: "freeze BEFORE the slow arp/`log show` work ... UNCONDITIONALLY on any
/// gateway change").
pub struct FreezePcapHandler<S: Store> {
    ring: Arc<dyn PcapFreezer>,
    store: Arc<S>,
    blob_dir: PathBuf,
}

impl<S: Store> FreezePcapHandler<S> {
    /// Build a handler that freezes `ring` into a per-incident sub-directory of
    /// `blob_dir` and records the copied files through `store`.
    pub fn new(ring: Arc<dyn PcapFreezer>, store: Arc<S>, blob_dir: impl Into<PathBuf>) -> Self {
        Self {
            ring,
            store,
            blob_dir: blob_dir.into(),
        }
    }
}

impl<S: Store + Send + Sync> Handler for FreezePcapHandler<S> {
    fn on_fire(&self, incident_id: &str, ts_us: i64, _detail: &str) {
        let dest = self.blob_dir.join(format!("freeze-{incident_id}"));
        let paths = self.ring.freeze(&dest);
        for (i, path) in paths.iter().enumerate() {
            let blob = BlobRef {
                id: format!("{incident_id}-pcap-{i}"),
                incident_id: incident_id.to_string(),
                ts_us,
                kind: "pcap".into(),
                path: path.display().to_string(),
            };
            if let Err(e) = self.store.write_blob_ref(&blob) {
                tracing::warn!(incident_id, error = %e, "failed to write pcap blob_ref");
            }
        }
        tracing::info!(
            incident_id,
            frozen = paths.len(),
            "froze pcap ring on gateway change"
        );
    }
}

/// A passive [`Handler`] that mirrors each firing into the live
/// [`StatusSnapshot`]'s bounded incident ring, so the socket API can serve recent
/// incidents from memory without a DB read. Newest first; the ring is truncated
/// to `cap`. DuckDB (via [`RecordHandler`]) remains the durable record — this
/// ring is only the live view.
pub struct SnapshotHandler {
    snapshot: Arc<Mutex<StatusSnapshot>>,
    cap: usize,
}

impl SnapshotHandler {
    /// Build a handler that pushes onto `snapshot`'s incident ring, capped to `cap`.
    pub fn new(snapshot: Arc<Mutex<StatusSnapshot>>, cap: usize) -> Self {
        Self { snapshot, cap }
    }
}

impl Handler for SnapshotHandler {
    fn on_fire(&self, incident_id: &str, ts_us: i64, detail: &str) {
        // `incident_id` is `"{trigger_id}-{now_us}"`; recover the trigger id from
        // the prefix before the final `-` (matching `RecordHandler`).
        let trigger_id = incident_id
            .rsplit_once('-')
            .map(|(prefix, _)| prefix)
            .unwrap_or(incident_id)
            .to_string();
        let summary = IncidentSummary {
            id: incident_id.to_string(),
            opened_us: ts_us,
            closed_us: None,
            trigger_id,
            signature: detail.to_string(),
        };
        let mut snap = self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        snap.incidents.insert(0, summary);
        snap.incidents.truncate(self.cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_core::{CollectorMeta, Os, Readiness};
    use std::time::Duration;
    use triggers::conditions::{GwChange, GwDrop};
    use triggers::engine::Trigger;
    use triggers::handlers::RecordHandler;
    use types::{GwVerdict, LinkSample, ProxySample, TcpVerdict};

    fn link(ts_us: i64, gw: GwVerdict) -> Sample {
        Sample::Link(LinkSample {
            ts_us,
            gw,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        })
    }

    #[tokio::test]
    async fn pipeline_stores_and_fires() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwDrop), vec![rec], 0)]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(store.clone(), eng, rx, snapshot));
        tx.send(Sample::Link(LinkSample {
            ts_us: 1,
            gw: GwVerdict::Fail,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        }))
        .await
        .unwrap();
        drop(tx);
        h.await.unwrap();
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM link_sample")
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn pipeline_freezes_pcap_on_gw_change() {
        // A fake freezer stands in for `macos::PcapRing` (no tcpdump / root needed):
        // it returns a plausible ring-file path without touching the filesystem.
        struct FakeFreezer;
        impl PcapFreezer for FakeFreezer {
            fn freeze(&self, dest_dir: &Path) -> Vec<PathBuf> {
                vec![dest_dir.join("ring.pcap0")]
            }
        }

        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let freezer: Arc<dyn PcapFreezer> = Arc::new(FakeFreezer);
        let freeze: Arc<dyn Handler> = Arc::new(FreezePcapHandler::new(
            freezer,
            store.clone(),
            "/tmp/observer-blobs",
        ));
        let handlers: Vec<Arc<dyn Handler>> = vec![rec, freeze];
        let eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwChange), handlers, 0)]);

        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(store.clone(), eng, rx, snapshot));
        // Ok -> Fail is a gateway-verdict change: gw-change must fire.
        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        tx.send(link(2, GwVerdict::Fail)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        // The RecordHandler opened the incident; the FreezePcapHandler recorded a blob.
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            1
        );
    }

    /// A tiny `Source::Interval` collector whose `collect()` panics, so
    /// `spawn_interval_collector` must emit its `skip()` sample instead and keep
    /// ticking (probe-failure isolation, spec "SKIP, never silence").
    struct BoomCollector;

    static BOOM_META: CollectorMeta = CollectorMeta {
        name: "boom",
        supported_os: &[Os::MacOs],
    };

    impl Collector for BoomCollector {
        fn meta(&self) -> &'static CollectorMeta {
            &BOOM_META
        }
        fn source(&self) -> Source {
            Source::Interval(Duration::from_millis(5))
        }
        fn preflight(&self) -> Readiness {
            Readiness::Ready
        }
        fn collect(&self, _ts_us: i64) -> Vec<Sample> {
            panic!("probe blew up")
        }
        fn skip(&self, ts_us: i64) -> Vec<Sample> {
            vec![Sample::Proxy(ProxySample {
                ts_us,
                server_ip: "-".into(),
                tcp: TcpVerdict::Skip,
                rtt_ms: None,
                tun_code: None,
                selector: None,
            })]
        }
    }

    #[tokio::test]
    async fn interval_collector_emits_skip_on_panic_and_survives() {
        let (tx, mut rx) = mpsc::channel(4);
        let handle = spawn_interval_collector(Box::new(BoomCollector), tx);

        // First tick: collect() panics, so a SKIP-bearing sample is emitted instead.
        let first = rx.recv().await.unwrap();
        match first {
            Sample::Proxy(p) => assert_eq!(p.tcp, TcpVerdict::Skip),
            other => panic!("expected a proxy SKIP sample, got {other:?}"),
        }
        // Second tick: the collector is still alive (it never exits on a probe error).
        let second = rx.recv().await.unwrap();
        assert!(matches!(second, Sample::Proxy(_)));

        handle.abort();
    }

    #[tokio::test]
    async fn run_updates_snapshot_fields() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let eng = TriggerEngine::new(vec![]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(store.clone(), eng, rx, snapshot.clone()));

        // A link sample then a proxy sample: each populates its own snapshot field,
        // and `generated_us` tracks the most recent sample.
        tx.send(link(5, GwVerdict::Ok)).await.unwrap();
        tx.send(Sample::Proxy(ProxySample {
            ts_us: 9,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: Some(2.0),
            tun_code: Some(204),
            selector: None,
        }))
        .await
        .unwrap();
        drop(tx);
        h.await.unwrap();

        let snap = snapshot.lock().unwrap();
        assert_eq!(snap.link.as_ref().unwrap().ts_us, 5);
        assert_eq!(snap.link.as_ref().unwrap().gw, GwVerdict::Ok);
        assert_eq!(snap.proxy.as_ref().unwrap().ts_us, 9);
        assert_eq!(snap.proxy.as_ref().unwrap().server_ip, "1.2.3.4");
        assert!(snap.dns.is_none());
        assert!(snap.host.is_none());
        // Last sample processed was the proxy at ts=9.
        assert_eq!(snap.generated_us, 9);
    }

    #[test]
    fn snapshot_handler_caps_incident_ring() {
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let handler = SnapshotHandler::new(snapshot.clone(), 3);

        // Five firings into a cap-3 ring: only the three newest survive, newest first.
        for i in 0..5 {
            handler.on_fire(&format!("gw-drop-{i}"), i, "sig");
        }

        let snap = snapshot.lock().unwrap();
        assert_eq!(snap.incidents.len(), 3);
        assert_eq!(snap.incidents[0].id, "gw-drop-4");
        assert_eq!(snap.incidents[0].opened_us, 4);
        assert_eq!(snap.incidents[0].trigger_id, "gw-drop");
        assert_eq!(snap.incidents[0].signature, "sig");
        assert_eq!(snap.incidents[1].id, "gw-drop-3");
        assert_eq!(snap.incidents[2].id, "gw-drop-2");
    }
}
