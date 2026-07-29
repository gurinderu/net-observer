//! The observerd data pipeline (plan Task 13).
//!
//! Two halves of the streaming architecture from the spec:
//! - [`run`] — the consumer loop: drains the sample stream, persists each
//!   [`Sample`] into the [`Store`], keeps a small in-memory [`RecentWindow`], and
//!   evaluates the [`TriggerEngine`] on every sample. A store write error is
//!   logged (the gap is recorded) but never stops the loop.
//! - [`spawn_interval_collector`] / [`spawn_event_collector`] — supervised tasks
//!   that drive an [`AnyCollector`] by its cadence and forward its samples onto
//!   the stream. The interval spawner `await`s the collector's native-async
//!   `collect()` directly on the runtime (off the blocking pool); collectors return
//!   `SKIP` samples on a probe failure and keep ticking — one failing collector
//!   must never take down the others ("absence of a signal is itself
//!   diagnostic"). The event spawner drives a blocking [`EventSource`] on its own
//!   thread.
//!
//! It also provides [`FreezePcapHandler`], the passive handler wired onto the
//! `gw-change` trigger: on any gateway-verdict change it synchronously freezes
//! the pcap ring *before* slow forensic work and records a [`BlobRef`] per file.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use collector_core::Source;

use crate::AnyCollector;
use observer_ipc::{EncodedFrame, Event, IncidentSummary, StatusSnapshot, StreamFrame};
use store::{DuckdbStore, Store};
use tokio::sync::broadcast;
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
/// (the latest sample for that variant, plus `generated_us`), publish the matching
/// [`Event`] on the realtime bus, push it into the recent window, then evaluate
/// all triggers at the sample's own timestamp. A store write failure is logged and
/// the loop continues (a DB outage must not silently drop the live detection
/// stream — the gap is recorded, per the spec); the in-memory snapshot is updated
/// regardless, so the socket API stays live even through a DB hiccup.
///
/// Publishing is push, not poll: each sample becomes a [`StreamFrame::Event`] on
/// `events_tx` so held-open `Subscribe` connections receive it immediately. The
/// frame is serialised exactly ONCE here, into an [`EncodedFrame`], so N
/// subscribers cost one `serde_json` pass and an `Arc` refcount bump each. With
/// no subscribers the [`Event`] is not even built (the clone is skipped), so the
/// bus costs nothing while nobody is watching; a `send` error is likewise
/// ignored — the pipeline never back-pressures on the bus. Neither the store
/// write nor the snapshot mirror depends on the bus: both run whether or not
/// anyone subscribes. Incidents are published separately by the trigger
/// [`SnapshotHandler`] on fire.
///
/// On a RESUME edge — signalled by `resume_at_us` moving — the recent-sample
/// window is dropped before the next sample is pushed, so the count-based
/// conditions (`Wedge`, `GwChange`) can never span an observation gap: two bad
/// pre-pause ticks plus one post-resume tick must not read as "tun dead 3
/// ticks". The trigger engine's re-arm/latch state is deliberately untouched — a
/// trigger not re-firing across a pause is intended dedup, not a bug.
pub async fn run(
    store: Arc<DuckdbStore>,
    mut engine: TriggerEngine,
    mut rx: mpsc::Receiver<Sample>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
    events_tx: broadcast::Sender<EncodedFrame>,
    // `ts_us` of the most recent RESUME edge, published by the control socket.
    // `0` = the daemon has never resumed.
    resume_at_us: Arc<AtomicI64>,
) {
    let mut window = RecentWindow::new(WINDOW_CAP);
    // The resume edge this consumer has already applied.
    let mut applied_resume_us: i64 = 0;
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
        // Publish the sample as a live `Event` (push, not poll), but only build it
        // when someone is actually subscribed — the bus must add no cost while
        // nobody is watching. The check/subscribe race is benign: a receiver that
        // subscribes after the check would not have received this frame anyway
        // (broadcast delivers only frames sent after `subscribe`).
        if events_tx.receiver_count() > 0 {
            let event = match &sample {
                Sample::Link(l) => Event::Link(l.clone()),
                Sample::Proxy(p) => Event::Proxy(p.clone()),
                Sample::Dns(d) => Event::Dns(d.clone()),
                Sample::Host(h) => Event::Host(h.clone()),
                Sample::Route(r) => Event::Route(r.clone()),
            };
            // Serialise ONCE here; every subscriber then clones an Arc, not a
            // second `serde_json` pass.
            match EncodedFrame::encode(&StreamFrame::Event(event)) {
                Ok(frame) => {
                    // Ignore the send error: the last receiver may have gone.
                    let _ = events_tx.send(frame);
                }
                Err(e) => tracing::warn!(error = %e, "failed to encode event frame; not published"),
            }
        }

        let resume_us = resume_at_us.load(Ordering::Acquire);
        if resume_us != applied_resume_us {
            window.clear();
            applied_resume_us = resume_us;
            tracing::info!(
                resume_us,
                "collection resumed; recent-sample window cleared"
            );
        }
        // A sample produced before the resume is on the far side of the
        // observation gap: still persisted and still published above (it is a
        // real observation), but never seeded into the fresh window, so one
        // stale in-flight sample cannot reinstate the very continuity the clear
        // just removed.
        if now_us < applied_resume_us {
            continue;
        }
        window.push(sample);
        engine.on_sample(&window, now_us);
    }
    tracing::info!("sample stream closed; pipeline consumer exiting");
}

/// Interval cadence: drive a timer loop, `await`ing `collect()` on each tick.
///
/// The collectors are native `async fn` and do their own async I/O, so `collect()`
/// is awaited directly on the runtime — **never** on the blocking pool. That keeps
/// the interval path off the blocking pool entirely (the async-refactor invariant).
///
/// Isolation guarantees (spec: "one collector failing must never take down the
/// others; a probe that cannot run emits SKIP, never silence"):
/// - each collector handles its own probe errors internally and returns SKIP
///   samples, so a failed probe is recorded as absence rather than crashing the
///   task — the loop keeps ticking regardless;
/// - the task exits cleanly only once the receiver is gone (channel closed).
///
/// While `observing` is `false` the loop keeps ticking but **skips the probe
/// entirely** (`continue` before `collect()`), so paused collection produces no
/// new samples. The flag is checked twice per tick — once before the probe and
/// again before forwarding — because `collect()` (ICMP ping + bound TCP probe)
/// runs for seconds: a toggle-off landing mid-probe drops the in-flight result
/// instead of letting it advance `generated_us` after the control socket has
/// already acked `observing: false`. The daemon and its socket stay alive
/// throughout, so `SetObserving(true)` resumes probing on the next tick.
pub(crate) fn spawn_interval_collector(
    c: AnyCollector,
    tx: mpsc::Sender<Sample>,
    observing: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let Source::Interval(interval) = c.source() else {
        unreachable!("interval spawner")
    };
    let name = c.meta().name;
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            // Paused: skip the probe entirely for this tick (no sample produced).
            if !observing.load(Ordering::Acquire) {
                continue;
            }
            let ts_us = types::now_us();
            let samples = c.collect(ts_us).await;
            // Re-check after the probe: a pause that landed while `collect()` was
            // in flight is already acked, so this result must not be forwarded.
            if !observing.load(Ordering::Acquire) {
                continue;
            }
            for s in samples {
                if tx.send(s).await.is_err() {
                    tracing::info!(collector = name, "receiver dropped; collector exiting");
                    return;
                }
            }
        }
    })
}

/// Event cadence: a long-lived blocking source belongs on its own dedicated OS
/// thread (`std::thread`, never the interval path), forwarding via the channel's
/// `blocking_send`.
///
/// The `route` collector (persistent PF_ROUTE socket) is the live Event-cadence
/// consumer: its `next()` is a blocking `read(2)` driven here on a dedicated
/// thread. Because that `read(2)` cannot be interrupted, a `next()` parked on an
/// idle socket keeps its stream sender alive through `abort_all`; the daemon
/// therefore bounds its shutdown drain (see `observerd::main`) and the OS reaps
/// the detached thread on process exit, rather than relying on this task to
/// release the sender.
///
/// While `observing` is `false` each batch is **dropped** (`continue` before
/// forwarding): the source is still drained (`next()` keeps being called so the
/// PF_ROUTE socket does not back up), but no events reach the consumer while
/// paused. The daemon stays alive throughout; `SetObserving(true)` resumes
/// forwarding on the next batch.
///
/// Dropping is not silent, but it is rate-limited so a long pause cannot flood
/// the log: the first drop after a pause edge logs at `debug`, the rest only
/// accumulate into a counter, and the resume edge logs the total at `info`. That
/// keeps "paused" distinguishable from "the PF_ROUTE source wedged" without a
/// line per batch.
pub(crate) fn spawn_event_collector(
    c: AnyCollector,
    tx: mpsc::Sender<Sample>,
    observing: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let name = c.meta().name;
    let Some(mut src) = c.into_event_source() else {
        tracing::error!(
            collector = name,
            "Event cadence but into_event_source() is None"
        );
        return tokio::spawn(async {});
    };
    // Bridge the blocking source into async on a dedicated OS thread: PF_ROUTE's
    // `read(2)` is genuinely uninterruptible-blocking, so it lives off the async
    // runtime entirely and forwards via `blocking_send` (valid only outside a
    // runtime context). The thread is detached — it holds a stream sender until
    // `next()` ends or the consumer is gone, and the OS reaps it on process exit.
    std::thread::spawn(move || {
        // Batches dropped since the current pause began; the pause edge is derived
        // from the flag itself, so no extra shared state is needed.
        let mut dropped_while_paused: u64 = 0;
        while let Some(samples) = src.next() {
            // Paused: drop this batch (still drained from the source above).
            if !observing.load(Ordering::Acquire) {
                if dropped_while_paused == 0 {
                    tracing::debug!(
                        collector = name,
                        dropped = samples.len(),
                        "paused: dropping route batch"
                    );
                }
                dropped_while_paused += 1;
                continue;
            }
            // Resume edge: report what the pause cost, once, then re-arm.
            if dropped_while_paused > 0 {
                tracing::info!(
                    collector = name,
                    dropped = dropped_while_paused,
                    "resumed: route batches dropped while paused"
                );
                dropped_while_paused = 0;
            }
            for s in samples {
                if tx.blocking_send(s).is_err() {
                    return; // consumer gone
                }
            }
        }
        tracing::info!(collector = name, "event source ended");
    });
    // Return a completed async handle so the caller's uniform `Vec<JoinHandle>`
    // (and `abort_all`) is unaffected; the real work runs on the detached thread.
    tokio::spawn(async {})
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
/// incidents from memory without a DB read, and publishes an [`Event::Incident`]
/// on the realtime bus so held-open `Subscribe` connections see it immediately.
/// Newest first; the ring is truncated to `cap`. DuckDB (via [`RecordHandler`])
/// remains the durable record — this ring is only the live view.
pub struct SnapshotHandler {
    snapshot: Arc<Mutex<StatusSnapshot>>,
    cap: usize,
    events_tx: broadcast::Sender<EncodedFrame>,
}

impl SnapshotHandler {
    /// Build a handler that pushes onto `snapshot`'s incident ring, capped to
    /// `cap`, and publishes each firing as an [`Event::Incident`] on `events_tx`.
    pub fn new(
        snapshot: Arc<Mutex<StatusSnapshot>>,
        cap: usize,
        events_tx: broadcast::Sender<EncodedFrame>,
    ) -> Self {
        Self {
            snapshot,
            cap,
            events_tx,
        }
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
        // Publish the incident on the realtime bus (push, not poll), serialised
        // once for every subscriber. Ignore the send error: it only means no
        // client is subscribed right now.
        match EncodedFrame::encode(&StreamFrame::Event(Event::Incident(summary.clone()))) {
            Ok(frame) => {
                let _ = self.events_tx.send(frame);
            }
            Err(e) => tracing::warn!(error = %e, "failed to encode event frame; not published"),
        }
        let mut snap = self.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        snap.incidents.insert(0, summary);
        snap.incidents.truncate(self.cap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use collector_host::HostCollector;
    use macos::HostLoad;
    use std::time::Duration;
    use triggers::conditions::{GwChange, GwDrop, Wedge};
    use triggers::engine::Trigger;
    use triggers::handlers::RecordHandler;
    use types::{GwVerdict, HostSample, LinkSample, ProxySample, TcpVerdict};

    /// Decode a bus payload back into the frame it was built from. The bus
    /// carries bytes on purpose (one encode for N subscribers), so the tests
    /// decode them here rather than the wire type growing a method that exists
    /// only for tests.
    fn decode(f: &EncodedFrame) -> StreamFrame {
        serde_json::from_slice(f.bytes()).expect("bus payload must decode as a StreamFrame")
    }

    /// A never-resumed epoch: the value the daemon starts with and keeps until
    /// the first `SetObserving(true)` edge.
    fn no_resume() -> Arc<AtomicI64> {
        Arc::new(AtomicI64::new(0))
    }

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
        let (events_tx, _events_rx) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot,
            events_tx,
            no_resume(),
        ));
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
        let (events_tx, _events_rx) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot,
            events_tx,
            no_resume(),
        ));
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

    /// The interval spawner ticks its collector, `await`s `collect()` directly on
    /// the runtime (off the blocking pool), forwards every sample, and exits cleanly
    /// once the receiver is dropped. Uses a real `host` collector: `getloadavg` is
    /// an instant, privilege-free syscall available on every dev/CI host, so each
    /// tick deterministically yields a `Host` sample.
    #[tokio::test]
    async fn interval_collector_forwards_samples_and_exits_on_receiver_drop() {
        let c = AnyCollector::Host(HostCollector::new(
            Arc::new(HostLoad::new()),
            Duration::from_millis(5),
        ));
        let (tx, mut rx) = mpsc::channel(4);
        let observing = Arc::new(AtomicBool::new(true));
        let handle = spawn_interval_collector(c, tx, observing);

        // First tick forwards a Host sample (bounded so a stuck loop fails fast).
        let first = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("interval collector should forward a sample within 5s")
            .expect("channel should stay open while the collector runs");
        assert!(matches!(first, Sample::Host(_)));

        // Dropping the receiver makes the next `send` fail, so the task exits.
        drop(rx);
        time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("collector task should exit after the receiver is dropped")
            .expect("collector task should not panic");
    }

    /// While `observing` is `false` the interval collector keeps ticking but
    /// skips its probe entirely, so no samples flow. Flipping the flag back to
    /// `true` resumes probing on the next tick — the daemon (and this task) stay
    /// alive throughout, exactly the pause/resume the switch relies on.
    #[tokio::test]
    async fn interval_collector_skips_probe_while_paused() {
        let c = AnyCollector::Host(HostCollector::new(
            Arc::new(HostLoad::new()),
            Duration::from_millis(5),
        ));
        let (tx, mut rx) = mpsc::channel(4);
        let observing = Arc::new(AtomicBool::new(false));
        let handle = spawn_interval_collector(c, tx, observing.clone());

        // Paused: several tick intervals must elapse with no sample forwarded.
        let paused = time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(
            paused.is_err(),
            "paused collector must not forward any sample"
        );

        // Resume: the very next tick produces a Host sample again.
        observing.store(true, Ordering::Release);
        let resumed = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("resumed collector should forward a sample within 5s")
            .expect("channel should stay open while the collector runs");
        assert!(matches!(resumed, Sample::Host(_)));

        drop(rx);
        time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("collector task should exit after the receiver is dropped")
            .expect("collector task should not panic");
    }

    /// A pause that lands *after* a tick has begun must not produce a sample: the
    /// spawner re-checks `observing` between `collect()` and the forward, so an
    /// in-flight probe is discarded rather than advancing `generated_us` after the
    /// control socket already acked `observing: false`. The tick interval is long
    /// relative to `getloadavg` so the flag flips inside a tick, not between them.
    #[tokio::test]
    async fn interval_collector_drops_in_flight_probe_on_pause() {
        let c = AnyCollector::Host(HostCollector::new(
            Arc::new(HostLoad::new()),
            Duration::from_millis(100),
        ));
        let (tx, mut rx) = mpsc::channel(4);
        let observing = Arc::new(AtomicBool::new(true));
        let handle = spawn_interval_collector(c, tx, observing.clone());

        // Observing: the first tick forwards a sample.
        let first = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("observing collector should forward a sample within 5s")
            .expect("channel should stay open while the collector runs");
        assert!(matches!(first, Sample::Host(_)));

        // Toggle off mid-tick: nothing more may reach the consumer, across several
        // tick intervals.
        observing.store(false, Ordering::Release);
        let paused = time::timeout(Duration::from_millis(500), rx.recv()).await;
        assert!(
            paused.is_err(),
            "no sample may be forwarded once observing is false"
        );

        drop(rx);
        observing.store(true, Ordering::Release);
        time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("collector task should exit after the receiver is dropped")
            .expect("collector task should not panic");
    }

    #[tokio::test]
    async fn run_updates_snapshot_fields() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let eng = TriggerEngine::new(vec![]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, _events_rx) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot.clone(),
            events_tx,
            no_resume(),
        ));

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
        let (events_tx, _events_rx) = broadcast::channel(16);
        let handler = SnapshotHandler::new(snapshot.clone(), 3, events_tx);

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

    /// Push, not poll: the consumer publishes one `Event` per sample on the
    /// broadcast bus, in order, matching the sample variant. A receiver created
    /// before `run` starts captures every published frame.
    #[tokio::test]
    async fn run_publishes_event_per_sample() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let eng = TriggerEngine::new(vec![]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, mut events_rx) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot,
            events_tx,
            no_resume(),
        ));

        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 2,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
        }))
        .await
        .unwrap();
        drop(tx);
        h.await.unwrap();

        // Each sample was published as the matching Event, in arrival order.
        match decode(&events_rx.recv().await.unwrap()) {
            StreamFrame::Event(Event::Link(l)) => assert_eq!(l.ts_us, 1),
            other => panic!("expected a Link event frame, got {other:?}"),
        }
        match decode(&events_rx.recv().await.unwrap()) {
            StreamFrame::Event(Event::Host(hh)) => assert_eq!(hh.ts_us, 2),
            other => panic!("expected a Host event frame, got {other:?}"),
        }
    }

    /// What actually travels on the bus is an already-serialised frame, not an
    /// `Event`: the payload must decode as a `StreamFrame::Event` carrying the
    /// sample verbatim, so the daemon's one encode is byte-compatible with what
    /// a subscriber reads off the socket.
    #[tokio::test]
    async fn run_publishes_an_encoded_event_frame_per_sample() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let eng = TriggerEngine::new(vec![]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, mut events_rx) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot,
            events_tx,
            no_resume(),
        ));

        tx.send(link(11, GwVerdict::Ok)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        let frame = events_rx.recv().await.unwrap();
        // The routing metadata rides along with the bytes, so the server loop
        // never has to re-inspect the payload to filter it.
        assert_eq!(frame.kind(), Some(observer_ipc::EventKind::Link));
        match decode(&frame) {
            StreamFrame::Event(Event::Link(l)) => {
                assert_eq!(l.ts_us, 11);
                assert_eq!(l.gw, GwVerdict::Ok);
            }
            other => panic!("expected a Link event frame, got {other:?}"),
        }
    }

    /// With zero subscribers the consumer skips building the `Event` entirely, but
    /// that guard must not short-circuit anything else: the store write and the
    /// snapshot mirror still happen on every sample.
    #[tokio::test]
    async fn run_persists_and_mirrors_with_no_subscribers() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let eng = TriggerEngine::new(vec![]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, events_rx) = broadcast::channel(16);
        // Nobody is watching the bus.
        drop(events_rx);
        assert_eq!(events_tx.receiver_count(), 0);

        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot.clone(),
            events_tx,
            no_resume(),
        ));
        tx.send(link(7, GwVerdict::Ok)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 8,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
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
        let snap = snapshot.lock().unwrap();
        assert_eq!(snap.link.as_ref().unwrap().ts_us, 7);
        assert_eq!(snap.host.as_ref().unwrap().ts_us, 8);
        assert_eq!(snap.generated_us, 8);
    }

    /// On fire the `SnapshotHandler` publishes an `Event::Incident` on the bus (in
    /// addition to mirroring it into the snapshot ring), so held-open subscribers
    /// see the incident live.
    #[test]
    fn snapshot_handler_publishes_incident_event() {
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, mut events_rx) = broadcast::channel(16);
        let handler = SnapshotHandler::new(snapshot, 8, events_tx);

        handler.on_fire("gw-drop-42", 42, "sig");

        match decode(&events_rx.try_recv().unwrap()) {
            StreamFrame::Event(Event::Incident(inc)) => {
                assert_eq!(inc.id, "gw-drop-42");
                assert_eq!(inc.opened_us, 42);
                assert_eq!(inc.trigger_id, "gw-drop");
                assert_eq!(inc.signature, "sig");
            }
            other => panic!("expected an Incident event frame, got {other:?}"),
        }
    }

    /// A wedge-shaped proxy tick: the tun is dead (`tun_code == 0`) while the
    /// direct path stays healthy, which is what [`link`] already builds.
    fn dead_proxy(ts_us: i64) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(0),
            selector: None,
        })
    }

    /// Block until the consumer has mirrored a sample at or past `want_us` into
    /// the snapshot. The mirror happens before the resume check in the loop body,
    /// so observing it proves every earlier sample has already been pushed into
    /// the window — which is what lets the resume epoch be published at a
    /// deterministic point in the stream.
    async fn wait_for_generated(snapshot: &Arc<Mutex<StatusSnapshot>>, want_us: i64) {
        time::timeout(Duration::from_secs(5), async {
            loop {
                let seen = snapshot
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .generated_us;
                if seen >= want_us {
                    return;
                }
                time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("consumer should reach the expected sample within 5s");
    }

    /// D5: a resume edge drops the pre-pause samples, so the count-based `Wedge`
    /// condition cannot span the observation gap. Two wedge-shaped ticks before
    /// the pause plus one after it are three bad ticks in wall-clock terms but
    /// only one *observed* run — asserting "tun dead 3 ticks" across a gap the
    /// daemon deliberately created would be a fabricated continuity.
    #[tokio::test]
    async fn run_clears_the_window_on_a_resume_edge() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(
            Box::new(Wedge { consecutive: 3 }),
            vec![rec],
            0,
        )]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, _events_rx) = broadcast::channel(16);
        let resume_at_us = Arc::new(AtomicI64::new(0));
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot.clone(),
            events_tx,
            resume_at_us.clone(),
        ));

        // Two wedge-shaped tick pairs before the pause.
        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        tx.send(dead_proxy(2)).await.unwrap();
        tx.send(link(3, GwVerdict::Ok)).await.unwrap();
        tx.send(dead_proxy(4)).await.unwrap();
        // A sentinel past the last pair: once it is mirrored, both pairs are in
        // the window, so the resume epoch below lands on a known stream position.
        tx.send(Sample::Host(HostSample {
            ts_us: 5,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 5).await;

        // The pause/resume boundary: later than everything observed so far,
        // earlier than the post-resume pair.
        resume_at_us.store(10, Ordering::Release);

        // One wedge-shaped pair after the resume.
        tx.send(link(11, GwVerdict::Ok)).await.unwrap();
        tx.send(dead_proxy(12)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        // Every sample is still persisted — the clear forgets the *window*, not
        // the record.
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM link_sample")
                .unwrap(),
            3
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            0,
            "wedge must not fire across an observation gap"
        );
    }

    /// The other half of the D5 pair: the exact same three tick pairs with no
    /// resume edge DO fire the wedge. Without this control the test above would
    /// also pass against a window that is simply never populated.
    #[tokio::test]
    async fn run_fires_without_a_resume_edge() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(
            Box::new(Wedge { consecutive: 3 }),
            vec![rec],
            0,
        )]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, _events_rx) = broadcast::channel(16);
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot.clone(),
            events_tx,
            no_resume(),
        ));

        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        tx.send(dead_proxy(2)).await.unwrap();
        tx.send(link(3, GwVerdict::Ok)).await.unwrap();
        tx.send(dead_proxy(4)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 5,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 5).await;
        tx.send(link(11, GwVerdict::Ok)).await.unwrap();
        tx.send(dead_proxy(12)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1,
            "three uninterrupted wedge ticks must fire"
        );
    }
}
