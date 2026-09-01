//! The net-observerd data pipeline (plan Task 13).
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
use std::time::{Duration, Instant};

use collector_core::Source;

use crate::AnyCollector;
use net_observer_ipc::{EncodedFrame, Event, IncidentSummary, StatusSnapshot, StreamFrame};
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

/// How long, in MONOTONIC time, one resume edge's drain filter may stay open.
///
/// The filter exists only to keep samples that were already queued when the pause
/// began — plus the rare straggler from a probe that spanned both edges — out of
/// the freshly cleared window; that backlog drains in milliseconds. Measured with
/// [`Instant`], never the wall clock, precisely so an NTP correction or a manual
/// `date` can neither extend it nor stall it. Note [`Instant`] is suspend-excluding
/// on Apple platforms, so a sleep/wake immediately after a resume edge DOES stall
/// this deadline — which is why the clock-free
/// [`RESUME_DRAIN_MAX_SAMPLES`] cap, not this one, is what makes the gate
/// incapable of filtering for ever.
const RESUME_DRAIN: Duration = Duration::from_secs(5);

/// Hard cap on how many samples ONE resume edge may keep out of the window,
/// whatever any clock says. The sample channel cannot hold more than
/// [`crate::CHANNEL_CAP`], so twice that is a generous clock-free backstop:
/// beyond it the timestamps are lying, not the backlog deep.
const RESUME_DRAIN_MAX_SAMPLES: u32 = 2 * (crate::CHANNEL_CAP as u32);

/// Why a [`ResumeGate`] stopped filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateClose {
    /// The monotonic drain window elapsed. With drops still accumulating this IS
    /// the clock-anomaly signal: the samples' wall clock never caught up with the
    /// resume epoch, which is what a backwards step looks like from here.
    Deadline,
    /// [`RESUME_DRAIN_MAX_SAMPLES`] samples were kept out — far more than any real
    /// in-flight set, so the same anomaly by a different bound.
    Cap,
    /// A newer resume edge replaced this one before either bound was reached.
    Superseded,
}

impl GateClose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Deadline => "deadline",
            Self::Cap => "cap",
            Self::Superseded => "superseded",
        }
    }
}

/// The BOUNDED post-resume drain filter.
///
/// A resume edge clears the recent-sample window; samples still queued or in
/// flight from before the pause must not be pushed back into it, or they
/// reinstate the very continuity the clear removed. Those samples are identified
/// by WALL clock (`Sample::ts_us()` against the control path's resume `ts_us`) —
/// there is nothing else to compare, since a `Sample` carries no monotonic stamp.
///
/// A wall-clock comparison ALONE is a latent total-detection outage: one backwards
/// step larger than the collector cadence makes `ts_us < resume_us` hold for every
/// future sample, and the consumer then skips `window.push` and `engine.on_sample`
/// for ever. So the wall clock decides only WHICH sample is stale; how long the
/// filter may be applied AT ALL is bounded by a MONOTONIC [`Instant`] deadline
/// ([`RESUME_DRAIN`]) and a drop count ([`RESUME_DRAIN_MAX_SAMPLES`]). When either
/// bound is reached the gate closes for good — until the next resume edge — and
/// every sample is admitted again. The failure mode is "briefly over-accept",
/// never "silently stop detecting".
///
/// Evaluated LAZILY, at sample time only: no timer and no task. An armed gate on a
/// silent stream has by construction held nothing back.
struct ResumeGate {
    /// The resume epoch this consumer has applied (wall-clock `ts_us`;
    /// `0` = never resumed).
    applied_resume_us: i64,
    /// Monotonic deadline; `None` once the gate is closed.
    open_until: Option<Instant>,
    /// Samples this edge has kept out of the window.
    dropped: u32,
}

impl ResumeGate {
    /// A gate that has never seen a resume edge.
    fn new() -> Self {
        Self {
            applied_resume_us: 0,
            open_until: None,
            dropped: 0,
        }
    }

    /// The resume epoch this gate has applied (`0` = never resumed).
    fn applied_resume_us(&self) -> i64 {
        self.applied_resume_us
    }

    /// Samples kept out of the window since the last edge. The consumer counts
    /// its own drops (for the exit line) and the gate logs its own totals, so
    /// this reader exists for the tests that pin the cap — `#[cfg(test)]` rather
    /// than an `allow(dead_code)` that would also hide a real future orphan.
    #[cfg(test)]
    fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Observe the epoch the control path publishes. Returns `true` on a real
    /// RESUME edge — the caller must then clear its window and re-arm its triggers
    /// — and (re)opens the drain filter for [`RESUME_DRAIN`] from `now`.
    ///
    /// Compared with `!=`, not `>`: an epoch that moves BACKWARDS because the
    /// clock stepped is still a real edge and must still clear the window.
    fn observe_edge(&mut self, resume_us: i64, now: Instant) -> bool {
        if resume_us == self.applied_resume_us {
            return false;
        }
        // A previous edge's unreported drops must not vanish.
        self.close(GateClose::Superseded);
        self.applied_resume_us = resume_us;
        self.open_until = Some(now + RESUME_DRAIN);
        self.dropped = 0;
        true
    }

    /// Whether the sample stamped `ts_us` must be kept OUT of the recent-sample
    /// window. `true` only while the gate is open AND the sample predates the
    /// applied resume epoch; a closed gate admits everything.
    fn should_drop(&mut self, ts_us: i64, now: Instant) -> bool {
        let Some(deadline) = self.open_until else {
            return false;
        };
        if now >= deadline {
            self.close(GateClose::Deadline);
            return false;
        }
        if ts_us >= self.applied_resume_us {
            return false;
        }
        self.dropped += 1;
        if self.dropped == 1 {
            tracing::warn!(
                ts_us,
                resume_us = self.applied_resume_us,
                "sample predates the resume boundary; kept out of the trigger window \
                 (still persisted and published)"
            );
        }
        if self.dropped >= RESUME_DRAIN_MAX_SAMPLES {
            self.close(GateClose::Cap);
        }
        true
    }

    /// Close the gate and report what it cost, exactly once per edge.
    fn close(&mut self, reason: GateClose) {
        if self.open_until.take().is_none() {
            return;
        }
        if self.dropped > 0 {
            tracing::warn!(
                dropped = self.dropped,
                resume_us = self.applied_resume_us,
                reason = reason.as_str(),
                "post-resume drain closed; samples kept out of the trigger window"
            );
        }
    }
}

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
/// window is dropped before the next sample is pushed
/// ([`RecentWindow::clear_for_resume`]), so the count-based conditions (`Wedge`)
/// can never span an observation gap: two bad pre-pause ticks plus one
/// post-resume tick must not read as "tun dead 3 ticks".
///
/// A RESUME edge RE-OPENS detection; it does not dedup it. The recent-sample
/// window is cleared and every trigger is re-armed
/// ([`TriggerEngine::rearm_all`]), so a fault that is still present when
/// collection resumes is recorded again — as a NEW incident belonging to the new
/// observation session, not as a duplicate of the pre-pause one. What a resume
/// does NOT do is reset the firing budget: `last_fire_us` survives it, so each
/// trigger still fires at most once per `backoff_us` and a toggled switch cannot
/// storm the incident log. The `observing_edge` rows bound the gap between the
/// two records.
///
/// Exactly one thing survives [`RecentWindow::clear_for_resume`]: the newest link
/// sample, kept as the gateway-CHANGE BASIS and reachable ONLY through
/// `prev_link` / `prev_link_with_provenance` — never through `last_link`,
/// `recent_link` or any other accessor. `GwChange` can therefore still fire, and
/// [`FreezePcapHandler`] still freeze the pcap ring, for a gateway that changed
/// DURING the pause (the ring is started once in `main` and is not gated by
/// `observing`, so it keeps capturing while collection is paused — the packets
/// around that change MAY still be in it at resume, for a pause shorter than the
/// ring's retention; a long pause on a busy link freezes noise). `Wedge` still loses
/// its entire history and still cannot span the gap. A change measured against
/// the basis is reported as `LinkProvenance::AcrossGap` and the incident detail
/// ends in " (across an observation gap)", so an offline reader never mistakes it
/// for two consecutive ticks.
///
/// Which sample is stale is decided on the WALL clock — a [`Sample`] carries no
/// other time, and the resume epoch is a `types::now_us()` taken by the control
/// path. How long that comparison may be applied AT ALL is bounded by a MONOTONIC
/// [`Instant`] deadline (`RESUME_DRAIN`) and a drop cap
/// (`RESUME_DRAIN_MAX_SAMPLES`) — see `ResumeGate`. When either bound is
/// reached the gate closes until the next resume edge and every sample reaches
/// the window again, so a backwards clock step (NTP, sleep/wake, `date`) cannot
/// end detection. Samples kept out of the window are still written to DuckDB and
/// still published on the bus; the first drop of an episode and the episode total
/// are logged at `warn`, and the process total on the consumer's exit line. The
/// failure mode is "briefly over-accept", never "silently stop detecting".
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
    // The bounded post-resume drain filter, replacing the raw
    // `now_us < applied_resume_us` comparison a single backwards clock step could
    // otherwise make true for ever.
    let mut gate = ResumeGate::new();
    // Every sample this process kept out of the window, for the exit line: a
    // filtered sample must be countable, not merely logged once.
    let mut dropped_pre_resume: u64 = 0;
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

        // One MONOTONIC reading per sample, shared by the edge check and the gate,
        // so a sample is never timed against two different instants.
        let now = Instant::now();
        if gate.observe_edge(resume_at_us.load(Ordering::Acquire), now) {
            // Forget the samples, KEEP the gateway-change basis (see
            // `RecentWindow::clear_for_resume`), and re-open detection.
            window.clear_for_resume();
            engine.rearm_all();
            tracing::info!(
                resume_us = gate.applied_resume_us(),
                "collection resumed; window cleared (gateway-change basis kept), triggers re-armed"
            );
        }
        // A sample produced before the resume is on the far side of the
        // observation gap: still persisted and still published above (it is a real
        // observation), but kept out of the fresh window so one stale in-flight
        // sample cannot reinstate the continuity the clear removed. BOUNDED — see
        // `ResumeGate`: it cannot discard indefinitely, and every drop is counted
        // and logged.
        if gate.should_drop(now_us, now) {
            dropped_pre_resume = dropped_pre_resume.saturating_add(1);
            continue;
        }
        window.push(sample);
        engine.on_sample(&window, now_us);
    }
    tracing::info!(
        dropped_pre_resume,
        "sample stream closed; pipeline consumer exiting"
    );
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
/// therefore bounds its shutdown drain (see `net-observerd::main`) and the OS reaps
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
    use collector_core::Readiness;
    use collector_host::HostCollector;
    use collector_route::RouteCollector;
    use macos::HostLoad;
    use triggers::conditions::{GwChange, GwDrop, Wedge};
    use triggers::engine::Trigger;
    use triggers::handlers::RecordHandler;
    use types::{GwVerdict, HostSample, LinkSample, ProxySample, RouteEvent, TcpVerdict};

    /// A fake freezer standing in for `macos::PcapRing` (no tcpdump / root
    /// needed): it returns a plausible ring-file path without touching the
    /// filesystem. Shared by every test that asserts the ring was frozen.
    struct FakeFreezer;
    impl PcapFreezer for FakeFreezer {
        fn freeze(&self, dest_dir: &Path) -> Vec<PathBuf> {
            vec![dest_dir.join("ring.pcap0")]
        }
    }

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

    /// Once `observing` goes false NOTHING more reaches the consumer, however far
    /// into a tick the flag flips: the collector that was forwarding a moment ago
    /// goes silent and stays silent, so nothing advances `generated_us` after the
    /// control socket has already acked `observing: false`.
    ///
    /// What this does NOT cover, despite the pause landing "mid-tick" in wall-clock
    /// terms: the post-probe re-check at the top of this file (the second
    /// `observing` load, between `collect()` and the forward). `HostCollector::collect`
    /// is a single instant `getloadavg`, so the loop is parked in `ticker.tick()`
    /// when the flag flips and the pre-probe check catches it every time — deleting
    /// the re-check leaves this test green. Nothing else covers it either; making it
    /// genuinely testable needs a `#[cfg(test)]` collector whose `collect()` can be
    /// held open, which is a production change out of proportion to the line. Named
    /// here so the next auditor does not re-trip on the name (this test used to be
    /// called `interval_collector_drops_in_flight_probe_on_pause`).
    #[tokio::test]
    async fn interval_collector_forwards_nothing_after_a_pause() {
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

    /// A fake blocking [`EventSource`] standing in for the PF_ROUTE socket: its
    /// `next()` parks on a std channel the test feeds, so batches arrive exactly
    /// when the test says and the detached thread ends as soon as the test drops
    /// the sender.
    struct FakeRouteSource {
        batches: std::sync::mpsc::Receiver<Vec<Sample>>,
        /// Batches taken OUT of the source. The daemon must keep draining while
        /// paused, or the real PF_ROUTE socket backs up.
        drained: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl collector_core::EventSource for FakeRouteSource {
        fn next(&mut self) -> Option<Vec<Sample>> {
            let batch = self.batches.recv().ok()?;
            self.drained.fetch_add(1, Ordering::Release);
            Some(batch)
        }
    }

    /// A PF_ROUTE-shaped event: an interface coming up.
    fn route(ts_us: i64) -> Sample {
        Sample::Route(RouteEvent {
            ts_us,
            kind: "iface".into(),
            iface: Some("en0".into()),
            detail: "up".into(),
        })
    }

    /// The event spawner's pause path, which had no test at all: while `observing`
    /// is false every batch is DROPPED, and the source is nonetheless still
    /// DRAINED. Two halves, two mutations. Deleting the spawner's
    /// `if !observing.load(..) { .. continue; }` block lets the paused batches reach
    /// the consumer and kills the 200 ms negative bound; hoisting that same check
    /// ABOVE `src.next()` stops the source being drained (which is what backs the
    /// real PF_ROUTE socket up) and kills the `drained` wait.
    ///
    /// The `drained` half is also what makes the negative bound meaningful rather
    /// than a race with a thread that has not started yet: nothing is asserted about
    /// silence until the source is provably two batches lighter.
    #[tokio::test]
    async fn event_collector_drops_batches_while_paused_but_keeps_draining() {
        let (batch_tx, batches) = std::sync::mpsc::channel::<Vec<Sample>>();
        let drained = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = AnyCollector::Route(RouteCollector::new(
            Box::new(FakeRouteSource {
                batches,
                drained: drained.clone(),
            }),
            Readiness::Ready,
        ));
        let (tx, mut rx) = mpsc::channel(16);
        let observing = Arc::new(AtomicBool::new(false));
        let _handle = spawn_event_collector(c, tx, observing.clone());

        // Paused: both batches are taken out of the source…
        batch_tx.send(vec![route(1)]).unwrap();
        batch_tx.send(vec![route(2)]).unwrap();
        time::timeout(Duration::from_secs(5), async {
            loop {
                if drained.load(Ordering::Acquire) >= 2 {
                    return;
                }
                time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("a paused event collector must keep draining its source");
        // …and none of them reaches the consumer.
        assert!(
            time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "a paused event collector forwards nothing"
        );

        // Resume: the next batch flows again on the very next `next()`.
        observing.store(true, Ordering::Release);
        batch_tx.send(vec![route(3)]).unwrap();
        let resumed = time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a resumed event collector should forward a batch within 5s")
            .expect("channel should stay open while the collector runs");
        assert!(matches!(resumed, Sample::Route(_)));

        // Dropping the sender makes `next()` return `None`, so the detached thread
        // ends with the test rather than outliving it.
        drop(batch_tx);
        drop(rx);
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
        assert_eq!(frame.kind(), Some(net_observer_ipc::EventKind::Link));
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

    /// The resume epoch the straggler pair publishes BEFORE the consumer starts,
    /// so the very first sample carries the edge and the stream needs no sentinel.
    const STRADDLE_EPOCH_US: i64 = 1_000;

    /// The straggler arithmetic below needs at least two ticks to be one short of.
    const _: () = assert!(
        crate::WEDGE_CONSECUTIVE >= 2,
        "the pre-epoch straggler pair is built as `n` links + `n - 1` proxies"
    );

    /// Drive a wedge run that is deliberately ONE PROXY TICK short of
    /// [`crate::WEDGE_CONSECUTIVE`], preceded by a single extra proxy tick stamped
    /// `straggler_us`, across a resume edge at [`STRADDLE_EPOCH_US`]. Returns the
    /// store so each half can assert on what was — and was not — written.
    ///
    /// `Wedge` needs `n` link ticks AND `n` proxy ticks, so the straggler is the
    /// only sample that can complete the run: that is what makes the gate's
    /// ATTACHMENT to the consumer loop, and not merely its own semantics, the thing
    /// under test. Every timestamp is derived from `crate::WEDGE_CONSECUTIVE`, so
    /// retuning the production threshold cannot leave this fixture asserting a
    /// behaviour production no longer has.
    async fn wedge_one_proxy_short_across_a_resume(straggler_us: i64) -> Arc<DuckdbStore> {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let n = crate::WEDGE_CONSECUTIVE;
        let eng = TriggerEngine::new(vec![Trigger::new(
            Box::new(Wedge { consecutive: n }),
            vec![rec],
            0,
        )]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, _events_rx) = broadcast::channel(16);
        // Published BEFORE the consumer exists, so the first sample it sees
        // already carries the resume edge: no sentinel, no wait, no race.
        let resume_at_us = Arc::new(AtomicI64::new(STRADDLE_EPOCH_US));
        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot,
            events_tx,
            resume_at_us,
        ));

        // The straggler: the probe that spanned both edges.
        tx.send(dead_proxy(straggler_us)).await.unwrap();
        // `n` fresh link ticks but only `n - 1` fresh proxy ticks: one short.
        for i in 0..n as i64 {
            tx.send(link(STRADDLE_EPOCH_US + 1 + 2 * i, GwVerdict::Ok))
                .await
                .unwrap();
            if i + 1 < n as i64 {
                tx.send(dead_proxy(STRADDLE_EPOCH_US + 2 + 2 * i))
                    .await
                    .unwrap();
            }
        }
        drop(tx);
        h.await.unwrap();
        store
    }

    /// The resume gate must be ATTACHED to the consumer loop, not merely correct in
    /// isolation. A wedge run that only a pre-epoch straggler could complete stays
    /// silent: the straggler is one microsecond on the far side of the boundary, so
    /// the window holds `n - 1` proxy ticks and `Wedge` can never see its `n`th.
    ///
    /// Dies under `if gate.should_drop(now_us, now) {` -> `if false {` — the
    /// straggler then becomes the oldest of `n` proxies and the wedge fires — and
    /// under an `observe_edge` that never reports an edge, which leaves the gate
    /// closed and filters nothing. Neither mutation is visible to
    /// `run_clears_the_window_on_a_resume_edge` (one extra admitted sample still
    /// leaves every count far below `n`) or to
    /// `run_keeps_detecting_after_a_backwards_clock_step` (its `incident >= 1` is
    /// satisfied more easily by a bypassed gate, not less).
    ///
    /// The sample-count assertions are the non-vacuity half: the gate filters the
    /// WINDOW, never the record, so a fixture whose sends had silently vanished —
    /// which would read 0 incidents just as happily — fails here instead.
    #[tokio::test]
    async fn run_does_not_fire_a_wedge_completed_only_by_a_pre_epoch_straggler() {
        let store = wedge_one_proxy_short_across_a_resume(STRADDLE_EPOCH_US - 1).await;

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            0,
            "a sample from before the resume epoch must not complete a post-resume wedge run"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM proxy_sample")
                .unwrap(),
            crate::WEDGE_CONSECUTIVE as i64,
            "the gate filters the WINDOW, never the record: the straggler is still persisted"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM link_sample")
                .unwrap(),
            crate::WEDGE_CONSECUTIVE as i64,
            "every fresh link tick is persisted too"
        );
    }

    /// The matched twin, differing by exactly ONE MICROSECOND: a straggler stamped
    /// AT the resume epoch belongs to this observation session, so it is admitted
    /// and completes the run.
    ///
    /// The pair therefore measures the gate and nothing else, and it is a two-sided
    /// boundary test as well as a wiring test: `if false` and a disabled
    /// `observe_edge` die in the half above, while `if true` (nothing is ever
    /// admitted) and `ts_us >= applied_resume_us` -> `>` (the epoch sample itself is
    /// filtered) die here.
    #[tokio::test]
    async fn run_fires_a_wedge_completed_by_a_straggler_at_the_resume_epoch() {
        let store = wedge_one_proxy_short_across_a_resume(STRADDLE_EPOCH_US).await;

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1,
            "a sample stamped at the resume epoch is this session's own and completes the run"
        );
    }

    /// The drain filter's LIFETIME is monotonic even though its predicate is not:
    /// once `RESUME_DRAIN` has elapsed on the `Instant` clock the gate stops
    /// filtering, however far in the future the wall-clock resume epoch sits.
    /// Without the deadline the `ts_us < resume_us` comparison below stays true
    /// for ever and the consumer never pushes another sample.
    #[test]
    fn resume_gate_closes_on_its_monotonic_deadline() {
        let mut gate = ResumeGate::new();
        let t0 = Instant::now();
        assert!(
            gate.observe_edge(1_000_000, t0),
            "a new epoch is a resume edge"
        );
        assert!(
            gate.should_drop(1, t0),
            "a sample predating the resume epoch is kept out while the gate is open"
        );

        let past_deadline = t0 + RESUME_DRAIN + Duration::from_millis(1);
        assert!(
            !gate.should_drop(1, past_deadline),
            "the gate must not filter past its monotonic deadline"
        );
        assert!(
            !gate.should_drop(1, past_deadline + RESUME_DRAIN),
            "a closed gate stays closed"
        );
    }

    /// The second, clock-free bound: everything here happens at the SAME instant,
    /// so the deadline can never be what closes the gate — only the drop cap can.
    /// A gate with no cap would keep filtering at a frozen `Instant` for ever.
    #[test]
    fn resume_gate_closes_on_its_drop_cap() {
        let mut gate = ResumeGate::new();
        let t0 = Instant::now();
        assert!(gate.observe_edge(1_000_000, t0));

        for i in 0..RESUME_DRAIN_MAX_SAMPLES {
            assert!(
                gate.should_drop(1, t0),
                "sample {i} is still within the cap and must be kept out"
            );
        }
        assert!(
            !gate.should_drop(1, t0),
            "the cap must close the gate with no help from any clock"
        );
        assert_eq!(
            gate.dropped(),
            RESUME_DRAIN_MAX_SAMPLES,
            "the cap bounds the drops exactly, and they stay countable"
        );
    }

    /// The gate filters only what is genuinely on the far side of the boundary: a
    /// sample stamped at or after the resume epoch is this session's own
    /// observation and reaches the window immediately.
    #[test]
    fn resume_gate_admits_samples_at_or_after_the_resume_epoch() {
        let mut gate = ResumeGate::new();
        let t0 = Instant::now();
        assert!(gate.observe_edge(1_000, t0));

        assert!(gate.should_drop(999, t0), "pre-resume sample is kept out");
        assert!(
            !gate.should_drop(1_000, t0),
            "a sample stamped exactly at the resume epoch belongs to this session"
        );
        assert!(
            !gate.should_drop(1_001, t0),
            "a post-resume sample belongs to this session"
        );
    }

    /// Item 1: a backwards clock step must not end detection. The published
    /// resume epoch sits far in the future — exactly what a backwards step leaves
    /// behind — so *every* subsequent sample looks stale on the wall clock. The
    /// bounded gate closes anyway, and the daemon keeps detecting.
    ///
    /// The store assertion is the non-vacuity half: the gate filters the WINDOW,
    /// never the record, so all the fillers are still in DuckDB.
    #[tokio::test]
    async fn run_keeps_detecting_after_a_backwards_clock_step() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwDrop), vec![rec], 0)]);
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, _events_rx) = broadcast::channel(16);
        let resume_at_us = Arc::new(AtomicI64::new(0));
        // An epoch no future sample can reach: year ~128,000 in microseconds.
        resume_at_us.store(4_000_000_000_000_000, Ordering::Release);

        let (tx, rx) = mpsc::channel(16);
        let h = tokio::spawn(run(
            store.clone(),
            eng,
            rx,
            snapshot.clone(),
            events_tx,
            resume_at_us.clone(),
        ));

        // Enough stale-looking samples to exhaust the drop cap on their own.
        let fillers = i64::from(RESUME_DRAIN_MAX_SAMPLES);
        for i in 1..=fillers {
            tx.send(Sample::Host(HostSample {
                ts_us: i,
                load1: 0.0,
                load5: 0.0,
                load15: 0.0,
            }))
            .await
            .unwrap();
        }
        // The fault itself, still "stale" by the poisoned epoch.
        tx.send(link(fillers + 100, GwVerdict::Fail)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap()
                >= 1,
            "detection must resume once the bounded drain closes"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM host_sample")
                .unwrap(),
            fillers,
            "the gate filters the WINDOW, never the record"
        );
    }

    /// Item 2: a resume RE-OPENS detection. A gateway that is still dead when
    /// collection resumes is this observation session's own finding, so it is
    /// recorded again rather than staying latched behind the pre-pause firing.
    ///
    /// The post-resume sample is deliberately a LINK: `GwDrop::eval` therefore
    /// never returns `None` after the clear, so the latch cannot re-arm by
    /// accident and only `TriggerEngine::rearm_all` can produce the second
    /// incident.
    #[tokio::test]
    async fn run_refires_a_persistent_fault_after_a_resume() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwDrop), vec![rec], 0)]);
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

        // Fires once, then stays latched while the fault persists.
        tx.send(link(1, GwVerdict::Fail)).await.unwrap();
        tx.send(link(2, GwVerdict::Fail)).await.unwrap();
        // A sentinel past the last link: once mirrored, both are in the window,
        // so the resume epoch below lands on a known stream position.
        tx.send(Sample::Host(HostSample {
            ts_us: 3,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 3).await;

        resume_at_us.store(10, Ordering::Release);
        tx.send(link(11, GwVerdict::Fail)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            2,
            "a fault still present when collection resumes is this session's own finding"
        );
        assert_eq!(
            store
                .query_scalar_i64(
                    "SELECT count(*) FROM incident WHERE id IN ('gw-drop-1', 'gw-drop-11')"
                )
                .unwrap(),
            2,
            "the two incidents are the pre-pause and post-resume observations, not a rewrite"
        );
    }

    /// The matched twin of the test above: the identical stream under the daemon's
    /// PRODUCTION backoff yields exactly ONE incident. A resume re-arms the latch;
    /// it does not hand the trigger a fresh firing budget, so a spammed switch
    /// cannot storm the incident log.
    ///
    /// The operator scenario, stated plainly: toggling collection off and on again
    /// inside [`crate::BACKOFF_US`] — the real firing budget the daemon ships with,
    /// not a synthetic one — writes no second incident. Reading the production
    /// constant here is what makes this die under `BACKOFF_US = 0`, which nothing
    /// else in the suite reads.
    #[tokio::test]
    async fn run_does_not_refire_within_the_backoff_after_a_resume() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(
            Box::new(GwDrop),
            vec![rec],
            crate::BACKOFF_US,
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

        tx.send(link(1, GwVerdict::Fail)).await.unwrap();
        tx.send(link(2, GwVerdict::Fail)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 3,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 3).await;

        resume_at_us.store(10, Ordering::Release);
        tx.send(link(11, GwVerdict::Fail)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1,
            "a resume re-arms; it does not reset the firing budget"
        );
    }

    /// The other direction of that same boundary: once the production budget HAS
    /// elapsed, a fault still present at resume is recorded again. The post-resume
    /// link is stamped at exactly `1 + crate::BACKOFF_US` — the FIRST microsecond
    /// the budget is available, since the pre-pause fire was at ts 1 and the
    /// engine's guard is `>=`.
    ///
    /// Two mutations die here, one from each side: `>=` -> `>` in
    /// `TriggerEngine::on_sample` (2 -> 1) and `BACKOFF_US = i64::MAX` (2 -> 1).
    /// `saturating_add`, not `+`, precisely because of the second: a plain `+` would
    /// panic on overflow under it and mask the assertion behind an arithmetic error.
    ///
    /// The post-resume sample is deliberately a LINK, so `GwDrop::eval` never
    /// returns `None` after the clear and the latch cannot re-arm by accident — only
    /// `TriggerEngine::rearm_all` can have produced the second incident.
    #[tokio::test]
    async fn run_refires_a_persistent_fault_once_the_production_backoff_has_elapsed() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let eng = TriggerEngine::new(vec![Trigger::new(
            Box::new(GwDrop),
            vec![rec],
            crate::BACKOFF_US,
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

        // Fires once at ts 1, then stays latched while the fault persists.
        tx.send(link(1, GwVerdict::Fail)).await.unwrap();
        tx.send(link(2, GwVerdict::Fail)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 3,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 3).await;

        resume_at_us.store(10, Ordering::Release);
        // The first microsecond at which the production budget is spent.
        let refire_us = 1i64.saturating_add(crate::BACKOFF_US);
        tx.send(link(refire_us, GwVerdict::Fail)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            2,
            "a persistent fault re-fires once the production backoff has elapsed"
        );
        assert_eq!(
            store
                .query_scalar_i64(&format!(
                    "SELECT count(*) FROM incident \
                     WHERE id IN ('gw-drop-1', 'gw-drop-{refire_us}')"
                ))
                .unwrap(),
            2,
            "the two incidents are the pre-pause and post-resume observations, not a rewrite"
        );
    }

    /// Item 3, the oracle test: the pcap ring keeps capturing while collection is
    /// paused, so the packets around a gateway change that happened DURING the
    /// pause are physically still in it at resume. The change basis carried across
    /// `clear_for_resume` is what lets `gw-change` still fire on the first
    /// post-resume link sample, and the freeze then preserves real evidence.
    #[tokio::test]
    async fn run_freezes_the_pcap_ring_for_a_gateway_change_across_a_pause() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let freezer: Arc<dyn PcapFreezer> = Arc::new(FakeFreezer);
        let freeze: Arc<dyn Handler> = Arc::new(FreezePcapHandler::new(
            freezer,
            store.clone(),
            "/tmp/observer-blobs",
        ));
        let eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwChange), vec![rec, freeze], 0)]);
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

        // The last gateway state observed before the pause.
        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 2,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 2).await;

        resume_at_us.store(10, Ordering::Release);
        // The gateway changed while collection was paused.
        tx.send(link(11, GwVerdict::Fail)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1,
            "the oracle freezes the ring on ANY gateway change; a pause must not create a blind spot"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            1,
            "the oracle freezes the ring on ANY gateway change; a pause must not create a blind spot"
        );
    }

    /// The non-vacuity control for the test above: the same pause with an
    /// UNCHANGED gateway must stay silent. The carried basis is a comparison
    /// point, not a licence to fire at every resume.
    #[tokio::test]
    async fn run_does_not_freeze_when_the_gateway_is_unchanged_across_a_pause() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let freezer: Arc<dyn PcapFreezer> = Arc::new(FakeFreezer);
        let freeze: Arc<dyn Handler> = Arc::new(FreezePcapHandler::new(
            freezer,
            store.clone(),
            "/tmp/observer-blobs",
        ));
        let eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwChange), vec![rec, freeze], 0)]);
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

        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        tx.send(Sample::Host(HostSample {
            ts_us: 2,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 2).await;

        resume_at_us.store(10, Ordering::Release);
        tx.send(link(11, GwVerdict::Ok)).await.unwrap();
        drop(tx);
        h.await.unwrap();

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            0,
            "an unchanged gateway across a pause is not a change"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            0,
            "an unchanged gateway across a pause is not a change"
        );
    }

    /// The cross-gap freeze stream at a given `backoff_us`: a gateway change that
    /// FIRES before the pause, then a second change visible at resume only against
    /// the carried basis. Returns the store.
    ///
    /// The existing cross-gap tests fire for the FIRST time at the resume, so the
    /// firing budget is never in play there and the interaction between the carried
    /// basis and the backoff is never built. Here `gw-change` has already spent its
    /// budget at ts 2, so the cross-gap change at ts 11 is decided by `backoff_us`
    /// alone.
    async fn gw_change_across_a_pause_after_an_earlier_fire(backoff_us: i64) -> Arc<DuckdbStore> {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let rec: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let freezer: Arc<dyn PcapFreezer> = Arc::new(FakeFreezer);
        let freeze: Arc<dyn Handler> = Arc::new(FreezePcapHandler::new(
            freezer,
            store.clone(),
            "/tmp/observer-blobs",
        ));
        let eng = TriggerEngine::new(vec![Trigger::new(
            Box::new(GwChange),
            vec![rec, freeze],
            backoff_us,
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

        // No predecessor yet, so `GwChange::eval` returns `None` and the trigger
        // stays armed…
        tx.send(link(1, GwVerdict::Ok)).await.unwrap();
        // …then OK -> FAIL is a contiguous two-tick change: it FIRES, spending the
        // budget at ts 2 and recording the first incident + the first freeze.
        tx.send(link(2, GwVerdict::Fail)).await.unwrap();
        // A sentinel past the last link: once it is mirrored, both links are in the
        // window, so the resume epoch below lands on a known stream position.
        tx.send(Sample::Host(HostSample {
            ts_us: 3,
            load1: 0.0,
            load5: 0.0,
            load15: 0.0,
        }))
        .await
        .unwrap();
        wait_for_generated(&snapshot, 3).await;

        resume_at_us.store(10, Ordering::Release);
        // At this sample the window is cleared with the FAIL link carried as the
        // change basis and every trigger re-armed, so `prev_link_with_provenance`
        // yields (FAIL, AcrossGap) and `eval` returns `Some`. Only the backoff
        // decides whether it fires.
        tx.send(link(11, GwVerdict::Ok)).await.unwrap();
        drop(tx);
        h.await.unwrap();
        store
    }

    /// The non-vacuity twin of the test below, and an interaction nothing covered
    /// before it: the cross-gap freeze DOES happen once the budget permits, even
    /// though this is `gw-change`'s SECOND firing rather than its first. Exactly one
    /// of the two incidents carries the marker — the pre-pause firing is two
    /// consecutive ticks and its signature is unmarked — so the `LIKE` count is not
    /// something either firing alone could satisfy.
    ///
    /// Without this half, the suppression test below would pass just as well against
    /// a `GwChange` that had simply stopped firing at all.
    #[tokio::test]
    async fn run_freezes_a_cross_gap_gw_change_once_the_backoff_has_elapsed() {
        let store = gw_change_across_a_pause_after_an_earlier_fire(0).await;

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            2,
            "a cross-gap gateway change still fires when the firing budget permits"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            2,
            "the ring is frozen for the cross-gap change too"
        );
        assert_eq!(
            store
                .query_scalar_i64(
                    "SELECT count(*) FROM incident \
                     WHERE signature LIKE '%across an observation gap%'"
                )
                .unwrap(),
            1,
            "only the cross-gap firing is marked; the pre-pause one is two consecutive ticks"
        );
    }

    /// The BOUND on the cross-gap freeze guarantee the previous commits advertise: a
    /// gateway change visible only against the carried basis is still subject to the
    /// trigger's firing budget, so one that lands inside [`crate::BACKOFF_US`] of an
    /// earlier firing is suppressed. Dies under `BACKOFF_US = 0` and under an
    /// `on_sample` that ignores the backoff once a trigger has been re-armed.
    ///
    /// All three consequences are asserted as SEPARATE observables because the
    /// freeze is a handler and could be lost independently of the incident: no second
    /// incident, no cross-gap marker anywhere, and — the operator-visible cost — no
    /// second freeze, so the packets the ring kept through the pause are NOT
    /// preserved. The twin above is what keeps this from passing against a
    /// `GwChange` that had simply stopped firing.
    #[tokio::test]
    async fn run_does_not_freeze_a_cross_gap_gw_change_still_inside_the_backoff() {
        let store = gw_change_across_a_pause_after_an_earlier_fire(crate::BACKOFF_US).await;

        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM incident")
                .unwrap(),
            1,
            "the pre-pause firing spent the budget; the cross-gap change is suppressed"
        );
        assert_eq!(
            store
                .query_scalar_i64(
                    "SELECT count(*) FROM incident \
                     WHERE signature LIKE '%across an observation gap%'"
                )
                .unwrap(),
            0,
            "a suppressed cross-gap change leaves no marker"
        );
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            1,
            "no second freeze: the packets the ring kept through the pause are not preserved"
        );
    }
}
