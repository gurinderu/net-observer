//! `net-observerd` — the headless root LaunchDaemon (plan Task 13).
//!
//! Loads config, opens the DuckDB store, spawns the enabled collectors onto an
//! mpsc stream, builds the trigger engine with the starter rules + passive
//! handlers (record incidents; freeze the pcap ring on any gateway change), runs
//! the consumer loop, and shuts down cleanly on SIGTERM/SIGINT.

mod acting;
mod api;
mod pipeline;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use collector_core::{Collector, CollectorMeta, EventSource, Os, Readiness, Source};
use collector_dns::DnsCollector;
use collector_host::HostCollector;
use collector_link::{LinkCollector, LinkFacts};
use collector_proxy::ProxyCollector;
use collector_route::RouteCollector;
use config::Config;
use macos::{
    BoundTcpProber, DnsResolver, HostLoad, IcmpPinger, PcapRing, PfRouteSource, ProxySystemFacts,
    SystemFacts,
};
use net_observer_ipc::{EncodedFrame, StatusSnapshot};
use store::DuckdbStore;
use triggers::conditions::{FakeIp, GwChange, GwDrop, Starvation, Wedge};
use triggers::engine::{Trigger, TriggerEngine};
use triggers::handlers::{Handler, RecordHandler};
use types::Sample;

use pipeline::{
    FreezePcapHandler, PcapFreezer, SnapshotHandler, run, spawn_event_collector,
    spawn_interval_collector,
};

/// Minimum interval between fires for one trigger (5 minutes, in microseconds),
/// mirroring net-observer so a captive portal can't storm the incident log.
const BACKOFF_US: i64 = 300_000_000;

/// Depth of the sample stream between the collectors and the consumer.
/// `pipeline::RESUME_DRAIN_MAX_SAMPLES` is derived from this (twice it), so the
/// post-resume drain cap scales with the channel automatically and this value
/// carries no separate constraint.
const CHANNEL_CAP: usize = 256;

/// How many recent incidents the live snapshot keeps for the socket API. DuckDB
/// remains the durable record; this ring is just the in-memory live view.
const INCIDENT_RING_CAP: usize = 20;

/// Depth of the realtime event broadcast bus. The pipeline publishes one
/// already-encoded frame per sample (plus an `Event::Incident` on each trigger
/// fire, and a `StreamFrame::Observing` on each pause/resume edge) onto this bus;
/// each held-open `Subscribe` connection gets its own receiver. A subscriber that
/// falls this far behind sees a `Lagged` skip rather than back-pressuring the
/// pipeline — a live tail may drop old events, which is acceptable.
const EVENT_BUS_CAP: usize = 1024;

/// Wedge signal: tun dead while the direct path is healthy, for this many ticks.
const WEDGE_CONSECUTIVE: usize = 3;

/// Host load above which a dead tun counts as starvation (read from the `host`
/// collector's newest sample by the `Starvation` condition).
const STARVATION_LOAD: f64 = 10.0;

/// Path to the rendered sing-box config (read at runtime — server addresses are
/// never compiled in). Deployment writes it here; absent ⇒ proxy emits SKIP.
const SINGBOX_CONFIG_PATH: &str = "/etc/sing-box/config.json";

/// Clash/Mihomo proxy group whose current selection identifies the active node.
const CLASH_SELECTOR_GROUP: &str = "GLOBAL";

/// Upper bound on the post-signal drain. The `route` collector's PF_ROUTE
/// `read(2)` runs on a dedicated OS thread that cannot be interrupted, so it
/// keeps a stream sender alive and the consumer's `rx.recv()` may never observe
/// the stream close. Bounding the drain here keeps shutdown from hanging forever
/// on an idle routing socket; the detached thread is then reaped by the OS on
/// process exit.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "net-observerd",
    about = "net-observer network-forensics collector daemon"
)]
struct Cli {
    /// Path to the TOML config file (`NET_OBSERVER_*` env overrides still apply).
    #[arg(long)]
    config: Option<String>,
}

fn main() -> anyhow::Result<()> {
    // Build the runtime explicitly (instead of `#[tokio::main]`) so shutdown can
    // be *bounded*. The route collector's PF_ROUTE `read(2)` runs on a dedicated
    // OS thread that cannot be aborted; the bounded consumer drain plus process
    // exit guarantee the daemon still exits even if that read is parked on an idle
    // socket. `shutdown_timeout` bounds any remaining runtime work too.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(run_daemon());
    runtime.shutdown_timeout(SHUTDOWN_GRACE);
    result
}

/// Record that THIS process began collecting, at `ts_us`.
///
/// The observing *state* stays process-scoped and is never persisted — the
/// daemon always boots collecting. What is durable is the boundary: one
/// `observing_edge` row with `observing = true`, `peer_uid = NULL` (nobody
/// asked; the process booted) and `cause = startup`, published on the realtime
/// bus as the same `StreamFrame::Observing` an operator edge produces. One
/// value, two sinks — exactly the mechanism `api::set_observing` uses, not a
/// second one.
///
/// A store failure is logged as a gap and never fails startup: the daemon is
/// collecting either way, and refusing to boot over a missing boundary row
/// would trade a weaker record for no record at all.
fn record_startup_edge(
    store: &DuckdbStore,
    events_tx: &tokio::sync::broadcast::Sender<EncodedFrame>,
    ts_us: i64,
) -> types::ObservingEdge {
    use store::Store as _;

    let edge = types::ObservingEdge {
        ts_us,
        observing: true,
        peer_uid: None,
        cause: types::ObservingCause::Startup,
    };
    match EncodedFrame::encode(&net_observer_ipc::StreamFrame::Observing(edge)) {
        Ok(frame) => {
            let _ = events_tx.send(frame);
        }
        Err(e) => tracing::warn!(error = %e, "failed to encode startup observing frame"),
    }
    if let Err(e) = store.write_observing_edge(&edge) {
        tracing::error!(error = %e,
            "store write failed; startup observing edge not recorded (gap logged)");
    }
    edge
}

/// The async daemon body: load config, open the store, spawn the enabled
/// collectors, run the consumer loop, and shut down on SIGTERM/SIGINT. The final
/// drain is bounded (see [`SHUTDOWN_GRACE`]) so an un-abortable event source can
/// never keep the daemon from exiting.
async fn run_daemon() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref()).context("loading config")?;
    tracing::info!(db = %cfg.db_path, "starting net-observerd");

    // Ensure the store + blob directories exist before opening the database.
    if let Some(parent) = Path::new(&cfg.db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::create_dir_all(&cfg.blob_dir);

    let store = Arc::new(DuckdbStore::open(&cfg.db_path).context("opening store")?);

    // The live, in-memory snapshot the socket API serves. The pipeline consumer
    // keeps it current (latest sample per variant); the SnapshotHandler mirrors
    // fired incidents into its bounded ring. The daemon stays the sole DuckDB
    // owner — the socket answers from this snapshot, never the DB.
    let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));

    // The observer's OWN collection on/off flag (self-control). `true` (default)
    // = collecting; `false` = paused. The interval + event collectors check it
    // each cycle (skip the probe / drop the batch while paused); the
    // `SetObserving` control command flips it. Benign self-control — NOT gated by
    // `acting.enabled` and it never touches sing-box or the network. While paused
    // the daemon stays alive and the socket keeps serving, so the switch can turn
    // collection back on. `StatusSnapshot::default()` already reports
    // `observing: true`; the control handler mirrors every change into it.
    //
    // It always starts `true`, and is deliberately never loaded from disk (see
    // the startup log below for why).
    let observing = Arc::new(AtomicBool::new(true));

    // The operator's "quiet" flag: while set, the daemon addresses NO packet at
    // the gateway (the link collector's ICMP echo is not sent; its tick still
    // lands, carrying `gw = SKIP`). Shared with the link collector and the
    // control socket exactly the way `observing` is. Process-scoped and, like
    // `observing`, deliberately never persisted — a restart resumes probing.
    let quiet = Arc::new(AtomicBool::new(false));

    // The observing state is process-scoped and deliberately NEVER persisted: a
    // root forensics collector silently staying blind across a restart nobody
    // noticed is the dangerous failure mode, whereas restart-resumes fails safe.
    // Logged so the choice is explicit at every boot rather than accidental.
    tracing::info!(
        observing = true,
        "collection enabled at startup; the observing state is process-scoped and \
         deliberately never persisted — a restart always resumes collecting"
    );

    // `ts_us` of the most recent RESUME edge. The control socket publishes it on
    // every `SetObserving(true)` transition; the pipeline consumer watches it and
    // drops its recent-sample window so a count-based condition cannot span the
    // observation gap the pause opened. `0` = the daemon has never resumed.
    let resume_at_us = Arc::new(AtomicI64::new(0));

    // The realtime event bus (push, not poll): the pipeline consumer publishes a
    // `StreamFrame::Event` per sample, the trigger `SnapshotHandler` publishes an
    // `Event::Incident` on each fire, and the control path publishes a
    // `StreamFrame::Observing` on each pause/resume edge; the socket API's
    // `Subscribe` handler holds a connection open and streams filtered frames
    // from a per-connection receiver. Frames travel already serialised
    // (`EncodedFrame`), so N subscribers cost one `serde_json` pass, not N. The
    // initial receiver is dropped — the sample publisher checks
    // `receiver_count()` and skips the publish path entirely while nobody is
    // subscribed, so the bus costs nothing until someone watches. With
    // subscribers it still never back-pressures: a `send` error just means nobody
    // is listening, and is ignored.
    let (events_tx, _) = tokio::sync::broadcast::channel::<EncodedFrame>(EVENT_BUS_CAP);

    // The startup edge: the state is not persisted, but the TRANSITION is. A
    // daemon that died while paused comes back collecting and writes no resume
    // edge, so without this row the record cannot tell "still paused" from
    // "crashed while paused, then restarted", and the diagnosis queries have to
    // infer where the silence ended. Written through the same two sinks as an
    // operator edge, immediately after the bus exists and before any collector
    // can produce a sample, so it precedes the evidence it replaces.
    record_startup_edge(store.as_ref(), &events_tx, types::now_us());

    let (tx, rx) = mpsc::channel::<Sample>(CHANNEL_CAP);

    // Resolve the physical interface once, for the pcap ring. `phys_iface` is a
    // native `async fn` (it may shell out to `route -n get default`), so it is
    // awaited here rather than called synchronously.
    let phys_iface = SystemFacts::new(
        cfg.collectors.link.gw.clone(),
        cfg.collectors.link.phys_iface.clone(),
    )
    .phys_iface()
    .await;

    // Build the enabled collectors as the static-dispatch `AnyCollector` enum.
    // The `Collector` trait is native `async fn` (not `dyn`-compatible), so the
    // daemon enumerates the concrete collectors instead of boxing them, and the
    // adapters are passed by value (no `Arc` — each collector owns its ports).
    let mut collectors: Vec<AnyCollector> = Vec::new();
    if cfg.collectors.link.enabled {
        collectors.push(AnyCollector::Link(LinkCollector::new(
            IcmpPinger::new(),
            BoundTcpProber::new(),
            SystemFacts::new(
                cfg.collectors.link.gw.clone(),
                cfg.collectors.link.phys_iface.clone(),
            ),
            cfg.collectors.link.interval,
            quiet.clone(),
        )));
    }
    if cfg.collectors.proxy.enabled {
        collectors.push(AnyCollector::Proxy(ProxyCollector::new(
            BoundTcpProber::new(),
            ProxySystemFacts::new(
                SINGBOX_CONFIG_PATH,
                cfg.collectors.proxy.clash_api.clone(),
                CLASH_SELECTOR_GROUP,
            ),
            cfg.collectors.proxy.tun_probe_url.clone(),
            phys_iface.clone().unwrap_or_default(),
            cfg.collectors.proxy.interval,
        )));
    }
    if cfg.collectors.dns.enabled {
        collectors.push(AnyCollector::Dns(DnsCollector::new(
            DnsResolver::new(
                cfg.collectors.dns.monitored_domain.clone(),
                cfg.collectors.dns.ru_control_domain.clone(),
                cfg.collectors.dns.doh_url.clone(),
            ),
            cfg.collectors.dns.interval,
        )));
    }
    if cfg.collectors.host.enabled {
        collectors.push(AnyCollector::Host(HostCollector::new(
            Arc::new(HostLoad::new()),
            cfg.collectors.host.interval,
        )));
    }
    if cfg.collectors.route.enabled {
        // The route collector is Event-cadence, driven by a persistent PF_ROUTE
        // socket. Opening it here decides its readiness; if it cannot open, the
        // collector is constructed Unavailable (with a no-op source) so the
        // uniform preflight filter below drops it, mirroring every other probe.
        let (source, ready): (Box<dyn EventSource>, Readiness) = match PfRouteSource::open() {
            Ok(src) => (Box::new(src), Readiness::Ready),
            Err(e) => (
                Box::new(NullEventSource),
                Readiness::Unavailable(format!("PF_ROUTE socket: {e}")),
            ),
        };
        collectors.push(AnyCollector::Route(RouteCollector::new(source, ready)));
    }

    // Filter by OS meta + preflight, then spawn survivors with one uniform loop.
    let os = Os::current();
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    for c in collectors {
        let name = c.meta().name;
        if !c.meta().supports(os) {
            tracing::warn!(collector = name, ?os, "unsupported OS; skipping");
            continue;
        }
        // Preflight is NOT a startup gate for interval collectors. A prerequisite
        // that is missing at boot (RunAtLoad starts the daemon before any
        // interface is up) would otherwise disable the collector for the life of
        // the process, with nothing in the record saying why — bare silence, the
        // exact failure this project exists to catch. Instead the collector is
        // always spawned and re-runs preflight every tick, emitting SKIP samples
        // while unavailable and real ones as soon as it can. Startup readiness is
        // logged only as context.
        //
        // Event cadence is different and stays one-shot: the `route` collector's
        // PF_ROUTE socket is opened once, before construction, and the source is
        // moved into the collector — there is nothing left to re-probe per tick,
        // and the blocking thread has no tick to re-probe on. Retrying it means
        // reopening the socket, which is a different change (a supervisor around
        // `spawn_event_collector`) than this one.
        match (c.source(), c.preflight().await) {
            (Source::Event, Readiness::Unavailable(reason)) => {
                tracing::warn!(collector = name, %reason, "preflight failed; skipping (event cadence: not retried)");
                continue;
            }
            (Source::Interval(_), Readiness::Unavailable(reason)) => {
                tracing::warn!(
                    collector = name,
                    %reason,
                    "preflight unavailable at startup; scheduling anyway (SKIP per tick until it recovers)"
                );
            }
            _ => {}
        }
        // Dispatch on cadence — timer vs event stream. Both spawners take the
        // shared `observing` flag: the interval loop skips its probe while paused,
        // the event thread drops batches while paused.
        match c.source() {
            Source::Interval(_) => {
                handles.push(spawn_interval_collector(c, tx.clone(), observing.clone()))
            }
            Source::Event => handles.push(spawn_event_collector(c, tx.clone(), observing.clone())),
        }
    }
    // Drop our own sender so the consumer stops once every collector is gone.
    drop(tx);

    // Start the pcap ring (best-effort: needs root + tcpdump). On failure, the
    // gw-change trigger still records the incident, just without a pcap freeze.
    let freezer = maybe_start_pcap_ring(&cfg, phys_iface.as_deref());

    // Serve the read-only status socket for the unprivileged bar. Best-effort: a
    // bind failure is logged but never takes the daemon down (no API, still
    // collecting). Aborted on shutdown alongside the collectors.
    //
    // Started AFTER the pcap ring on purpose: `ControlCmd::FreezePcap` must be
    // handed the ring that is actually running, and a socket that answered a
    // freeze with "not running" while the ring was moments from starting would
    // be lying about the daemon's own state.
    let api_handle = {
        let server = build_api_server(
            &cfg,
            snapshot.clone(),
            observing.clone(),
            quiet.clone(),
            freezer.clone(),
            resume_at_us.clone(),
            store.clone(),
            events_tx.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = server.serve().await {
                tracing::error!(error = %e, "status socket server exited");
            }
        })
    };

    // Build the trigger engine with the starter rule set + passive handlers. The
    // event bus is threaded in so the `SnapshotHandler` publishes an
    // `Event::Incident` on each fire.
    let engine = build_engine(
        store.clone(),
        &cfg,
        freezer,
        snapshot.clone(),
        events_tx.clone(),
    );

    // Run the consumer loop until a shutdown signal (or the stream closing). The
    // consumer publishes a frame per sample onto the bus (push, not poll) and
    // watches `resume_at_us` so its recent-sample window never spans a pause.
    let mut consumer = tokio::spawn(run(
        store.clone(),
        engine,
        rx,
        snapshot.clone(),
        events_tx,
        resume_at_us,
    ));

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received; stopping collectors"),
        _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received; stopping collectors"),
        res = &mut consumer => {
            match res {
                Ok(()) => tracing::info!("consumer exited (stream closed)"),
                Err(e) => tracing::error!(error = %e, "consumer task failed"),
            }
            abort_all(&handles);
            api_handle.abort();
            return Ok(());
        }
    }

    // Signal path: stop the collectors, which closes the stream, then let the
    // consumer drain what remains and exit. The route collector's blocking
    // PF_ROUTE `read(2)` cannot be aborted, so its dedicated thread can keep a
    // stream sender alive and `rx.recv()` may never see the stream close; bound
    // the drain so shutdown cannot hang (the detached thread is reaped by the OS
    // on process exit).
    abort_all(&handles);
    api_handle.abort();
    match tokio::time::timeout(SHUTDOWN_GRACE, &mut consumer).await {
        Ok(Ok(())) => tracing::info!("net-observerd shut down cleanly"),
        Ok(Err(e)) => tracing::error!(error = %e, "consumer join failed during shutdown"),
        Err(_) => tracing::warn!(
            grace_s = SHUTDOWN_GRACE.as_secs(),
            "consumer did not drain within grace; forcing shutdown"
        ),
    }
    Ok(())
}

/// Static-dispatch union of every concrete collector.
///
/// The [`Collector`] trait uses native `async fn`, so it is not `dyn`-compatible
/// (no vtable, no boxing, no `async-trait` macro). The daemon therefore drives a
/// heterogeneous set of collectors through this enum: each method delegates by
/// `match` to the concrete collector, and the async ones `await` the underlying
/// future. Because every arm is a concrete type, the composed `collect` future is
/// `Send` and can be spawned onto the runtime without `Box::pin`.
pub(crate) enum AnyCollector {
    Link(LinkCollector<IcmpPinger, BoundTcpProber, SystemFacts>),
    Proxy(ProxyCollector<BoundTcpProber, ProxySystemFacts>),
    Dns(DnsCollector<DnsResolver>),
    Route(RouteCollector),
    Host(HostCollector<HostLoad>),
    /// Test-only: an interval collector with a flippable preflight (see
    /// [`FakeCollector`]).
    #[cfg(test)]
    Fake(FakeCollector),
}

impl AnyCollector {
    /// Static metadata (name + supported OSes).
    pub(crate) fn meta(&self) -> &'static CollectorMeta {
        match self {
            Self::Link(c) => c.meta(),
            Self::Proxy(c) => c.meta(),
            Self::Dns(c) => c.meta(),
            Self::Route(c) => c.meta(),
            Self::Host(c) => c.meta(),
            #[cfg(test)]
            Self::Fake(c) => c.meta(),
        }
    }

    /// The cadence the daemon should drive this collector on.
    pub(crate) fn source(&self) -> Source {
        match self {
            Self::Link(c) => c.source(),
            Self::Proxy(c) => c.source(),
            Self::Dns(c) => c.source(),
            Self::Route(c) => c.source(),
            Self::Host(c) => c.source(),
            #[cfg(test)]
            Self::Fake(c) => c.source(),
        }
    }

    /// Runtime capability probe (async: may shell out or open a socket).
    pub(crate) async fn preflight(&self) -> Readiness {
        match self {
            Self::Link(c) => c.preflight().await,
            Self::Proxy(c) => c.preflight().await,
            Self::Dns(c) => c.preflight().await,
            Self::Route(c) => c.preflight().await,
            Self::Host(c) => c.preflight().await,
            #[cfg(test)]
            Self::Fake(c) => c.preflight().await,
        }
    }

    /// One interval tick: await the probes and compose the samples. Collectors
    /// handle their own probe errors internally and return SKIP samples rather
    /// than panicking, so the interval loop never needs to catch a failure.
    pub(crate) async fn collect(&self, ts_us: i64) -> Vec<Sample> {
        match self {
            Self::Link(c) => c.collect(ts_us).await,
            Self::Proxy(c) => c.collect(ts_us).await,
            Self::Dns(c) => c.collect(ts_us).await,
            Self::Route(c) => c.collect(ts_us).await,
            Self::Host(c) => c.collect(ts_us).await,
            #[cfg(test)]
            Self::Fake(c) => c.collect(ts_us).await,
        }
    }

    /// The SKIP samples this collector emits on a tick whose preflight failed —
    /// absence of a signal recorded as a verdict rather than as silence.
    pub(crate) fn skip(&self, ts_us: i64) -> Vec<Sample> {
        match self {
            Self::Link(c) => c.skip(ts_us),
            Self::Proxy(c) => c.skip(ts_us),
            Self::Dns(c) => c.skip(ts_us),
            Self::Route(c) => c.skip(ts_us),
            Self::Host(c) => c.skip(ts_us),
            #[cfg(test)]
            Self::Fake(c) => c.skip(ts_us),
        }
    }

    /// For event collectors: take out the blocking source the daemon drives on a
    /// dedicated thread. Interval collectors return `None` (the default).
    pub(crate) fn into_event_source(self) -> Option<Box<dyn EventSource>> {
        match self {
            Self::Link(c) => Box::new(c).into_event_source(),
            Self::Proxy(c) => Box::new(c).into_event_source(),
            Self::Dns(c) => Box::new(c).into_event_source(),
            Self::Route(c) => Box::new(c).into_event_source(),
            Self::Host(c) => Box::new(c).into_event_source(),
            #[cfg(test)]
            Self::Fake(c) => Box::new(c).into_event_source(),
        }
    }
}

/// A test-only interval collector whose readiness the test flips at will, so the
/// per-tick preflight retry in `spawn_interval_collector` can be driven directly.
/// Every real collector in `AnyCollector` is a concrete type wired to real ports
/// (`IcmpPinger`, `SystemFacts`, …), so there is no other way to present the
/// spawner with a prerequisite that is missing and then appears.
#[cfg(test)]
pub(crate) struct FakeCollector {
    pub(crate) meta: &'static CollectorMeta,
    pub(crate) interval: std::time::Duration,
    /// Flipped by the test to make preflight succeed.
    pub(crate) ready: Arc<std::sync::atomic::AtomicBool>,
    /// Ticks on which `collect()` actually ran.
    pub(crate) collects: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
impl Collector for FakeCollector {
    fn meta(&self) -> &'static CollectorMeta {
        self.meta
    }
    fn source(&self) -> Source {
        Source::Interval(self.interval)
    }
    async fn preflight(&self) -> Readiness {
        if self.ready.load(std::sync::atomic::Ordering::Acquire) {
            Readiness::Ready
        } else {
            Readiness::Unavailable("no physical interface".into())
        }
    }
    async fn collect(&self, ts_us: i64) -> Vec<Sample> {
        self.collects
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        vec![Sample::Link(types::LinkSample {
            ts_us,
            gw: types::GwVerdict::Ok,
            gw_rtt_ms: Some(1.0),
            direct: types::TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        })]
    }
    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        vec![Sample::Link(types::LinkSample {
            ts_us,
            gw: types::GwVerdict::NoGw,
            gw_rtt_ms: None,
            direct: types::TcpVerdict::Skip,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        })]
    }
}

/// A no-op [`EventSource`] used only when the PF_ROUTE socket fails to open, so
/// the `route` collector can still be constructed carrying an `Unavailable`
/// readiness and be dropped by the uniform preflight filter. Its `next()` ends
/// the stream immediately (it is never actually driven — preflight filters it).
struct NullEventSource;
impl EventSource for NullEventSource {
    fn next(&mut self) -> Option<Vec<Sample>> {
        None
    }
}

/// Abort every collector task, dropping their stream senders.
fn abort_all(handles: &[JoinHandle<()>]) {
    for h in handles {
        h.abort();
    }
}

/// Start the pcap ring on the physical interface, or return `None` if disabled,
/// no interface was found, or `tcpdump` could not be spawned (logged).
fn maybe_start_pcap_ring(cfg: &Config, phys_iface: Option<&str>) -> Option<Arc<dyn PcapFreezer>> {
    if !cfg.collectors.pcap_ring.enabled {
        return None;
    }
    let Some(iface) = phys_iface else {
        // KNOWN GAP, deliberately left one-shot. Unlike an interval collector,
        // the ring is not driven by a tick: it is a `tcpdump` child started once
        // and handed to the control socket by value, so `FreezePcap` can answer
        // about the ring that is actually running. Making it retry means a
        // supervisor task owning a swappable ring slot (shared with the API
        // server) that re-resolves the interface and restarts the child when one
        // appears — a wiring change to the API surface, not a loop tweak, and out
        // of scope here. Until then a boot with no interface leaves the daemon
        // with no ring for its lifetime; the warning below is the only record.
        tracing::warn!("no physical interface resolved; pcap ring disabled (not retried)");
        return None;
    };
    let ring_dir = Path::new(&cfg.blob_dir).join("ring");
    match PcapRing::start(
        iface,
        ring_dir,
        cfg.collectors.pcap_ring.ring_mb,
        &cfg.collectors.pcap_ring.filter,
    ) {
        Ok(ring) => Some(Arc::new(ring) as Arc<dyn PcapFreezer>),
        Err(e) => {
            tracing::warn!(error = %e, "pcap ring failed to start; gw-change freeze disabled");
            None
        }
    }
}

/// Assemble the socket API server from `cfg` plus the daemon's shared state.
///
/// Split out of [`run_daemon`] so the wiring itself is addressable: this block is
/// the ONLY place the production caps, the initial-read budget, the two
/// rate-limited logs and the config-derived control policy are chosen, and every
/// `api` test overrides those fields with test-sized values — so without a seam
/// here they reach nothing but a running daemon. It is also where the shared
/// handles must stay SHARED: a fresh `Arc` for `observing` would leave the control
/// socket acking a pause no collector ever sees.
///
/// Must stay the only place an [`api::ApiServer`] is built.
// One argument over clippy's limit, deliberately. Every parameter here is one of
// the daemon's shared handles, and the arity IS the seam's content: collapsing
// them into a wrapper struct would add an indirection whose only purpose is to
// satisfy the lint, while the `Arc::ptr_eq` assertions in the wiring test — which
// is what actually keeps a handle from being silently copied — would have to
// reach through it unchanged.
#[allow(clippy::too_many_arguments)]
fn build_api_server(
    cfg: &Config,
    snapshot: Arc<Mutex<StatusSnapshot>>,
    observing: Arc<AtomicBool>,
    quiet: Arc<AtomicBool>,
    freezer: Option<Arc<dyn PcapFreezer>>,
    resume_at_us: Arc<AtomicI64>,
    store: Arc<DuckdbStore>,
    events_tx: tokio::sync::broadcast::Sender<EncodedFrame>,
) -> api::ApiServer {
    let socket_path = cfg.socket_path.clone();
    let socket_mode = cfg.socket_mode;
    let socket_owner_uid = cfg.socket_owner_uid;
    // Thread the acting config through so the control path is gated by
    // `acting.enabled` (off by default) in one place: `api::control_response`.
    // The `observing` flag is threaded separately: `SetObserving` is benign
    // self-control and must NOT be gated by that switch.
    let acting = api::ActingConfig {
        enabled: cfg.acting.enabled,
        singbox_service: cfg.acting.singbox_service.clone(),
    };
    api::ApiServer {
        socket_path,
        socket_mode,
        socket_owner_uid,
        max_subscribers: api::MAX_SUBSCRIBERS,
        // Bounds for a socket that is world-connectable by default: a local
        // process must not be able to pin unbounded tasks/fds by connecting
        // and never speaking, nor grow a root daemon's log by looping refused
        // control requests.
        max_connections: api::MAX_CONNECTIONS,
        request_timeout: api::REQUEST_READ_TIMEOUT,
        control_refusals: api::RateLimitedLog::new(api::REFUSAL_LOG_INTERVAL),
        sub_refusals: api::RateLimitedLog::new(api::REFUSAL_LOG_INTERVAL),
        acting,
        // Who may send a `Request::Control` at all — orthogonal to
        // `acting.enabled`, which only gates the acting *class* of commands.
        policy: api::ControlPolicy::from_config(cfg.socket_owner_uid, cfg.control_uids.clone()),
        observing,
        // Shared, never fresh — for `quiet` the same reason as `observing`, and
        // the ring handle so `FreezePcap` copies the ring that is actually
        // running rather than refusing next to a live capture.
        quiet,
        freezer,
        blob_dir: std::path::PathBuf::from(&cfg.blob_dir),
        resume_at_us,
        snapshot,
        // The durable sink for `observing_edge` boundary rows: the daemon
        // stays the sole DuckDB owner, so the control path writes through the
        // same handle the pipeline does.
        store: store as Arc<dyn store::Store + Send + Sync>,
        events_tx,
    }
}

/// Assemble the [`TriggerEngine`] with the starter rules (wedge, gw-drop,
/// gw-change, fakeip, starvation). Every rule records an incident (durable, in
/// DuckDB) and mirrors it into the live snapshot's ring for the socket API;
/// gw-change additionally freezes the pcap ring when one is available.
fn build_engine(
    store: Arc<DuckdbStore>,
    cfg: &Config,
    freezer: Option<Arc<dyn PcapFreezer>>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
    events_tx: tokio::sync::broadcast::Sender<EncodedFrame>,
) -> TriggerEngine {
    let record: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
    // Passive handler that pushes each firing onto the live snapshot's incident
    // ring so the socket API serves recent incidents from memory, and publishes an
    // `Event::Incident` on the realtime bus for held-open subscribers. Added to
    // every trigger alongside `record`.
    let snap: Arc<dyn Handler> =
        Arc::new(SnapshotHandler::new(snapshot, INCIDENT_RING_CAP, events_tx));

    let mut gw_change_handlers: Vec<Arc<dyn Handler>> = vec![record.clone(), snap.clone()];
    if let Some(freezer) = freezer {
        let freeze: Arc<dyn Handler> = Arc::new(FreezePcapHandler::new(
            freezer,
            store.clone(),
            cfg.blob_dir.clone(),
        ));
        gw_change_handlers.push(freeze);
    }

    let triggers = vec![
        Trigger::new(
            Box::new(Wedge {
                consecutive: WEDGE_CONSECUTIVE,
            }),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        Trigger::new(
            Box::new(GwDrop),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        Trigger::new(Box::new(GwChange), gw_change_handlers, BACKOFF_US),
        Trigger::new(
            Box::new(FakeIp),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        Trigger::new(
            Box::new(Starvation {
                load_threshold: STARVATION_LOAD,
            }),
            vec![record, snap],
            BACKOFF_US,
        ),
    ];

    TriggerEngine::new(triggers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    use net_observer_ipc::{Event, StreamFrame};
    use store::Store as _;
    use triggers::window::RecentWindow;
    use types::{GwVerdict, HostSample, LinkSample, ProxySample, TcpVerdict};

    /// A fake freezer standing in for `macos::PcapRing` (no tcpdump, no root): it
    /// returns a plausible ring-file path without touching the filesystem.
    struct FakeFreezer;
    impl PcapFreezer for FakeFreezer {
        fn freeze(&self, dest_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            vec![dest_dir.join("ring.pcap0")]
        }
    }

    /// A config whose only deviations from the shipped defaults are the ones the
    /// wiring assertions read back — so a hardcoded literal in
    /// [`build_api_server`] cannot coincide with the value under test. Nothing
    /// here is ever opened: the socket is never bound (no `serve()`), and
    /// `FakeFreezer` plus `FreezePcapHandler::on_fire` only *join* `blob_dir`.
    fn test_cfg() -> Config {
        Config {
            socket_path: "/tmp/net-observerd-wiring-test.sock".into(),
            // Deliberately NOT the shipped 0o666: a hardcoded default dies here.
            socket_mode: 0o600,
            socket_owner_uid: Some(4242),
            control_uids: vec![7, 9],
            blob_dir: "/tmp/net-observerd-wiring-test-blobs".into(),
            acting: config::ActingCfg {
                // Also NOT the shipped default (`false`), for the same reason.
                enabled: true,
                singbox_service: "system/wiring-test".into(),
            },
            ..Config::default()
        }
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

    /// A proxy tick with the tun dead (`tun_code` 0) while the TCP path is fine —
    /// the wedge/starvation shape.
    fn dead_proxy(ts_us: i64) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "1".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(0),
            selector: None,
        })
    }

    fn host(ts_us: i64, load1: f64) -> Sample {
        Sample::Host(HostSample {
            ts_us,
            load1,
            load5: load1,
            load15: load1,
        })
    }

    // ── the ApiServer wiring ────────────────────────────────────────────────

    /// Everything [`build_api_server`] is handed reaches the server it builds,
    /// and the handles it is handed stay SHARED rather than copied.
    ///
    /// Dies under any of: a hardcoded socket field (`socket_mode: 0o666`,
    /// `socket_owner_uid: None`, `enabled: false`); dropping `cfg.control_uids`
    /// from the control policy; substituting a literal for `api::MAX_SUBSCRIBERS`
    /// / `api::MAX_CONNECTIONS` / `api::REQUEST_READ_TIMEOUT`;
    /// `RateLimitedLog::new(Duration::ZERO)` on either refusal limiter; a fresh
    /// `Arc::new(AtomicBool::new(true))` / `AtomicI64::new(0)` /
    /// `Mutex::new(StatusSnapshot::default())` in place of the daemon's own
    /// handle; a fresh `broadcast::channel` for the bus; or a second
    /// `DuckdbStore` for the control path's writes.
    #[test]
    fn build_api_server_wires_the_production_bounds_and_the_daemon_handles() {
        let cfg = test_cfg();
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let observing = Arc::new(AtomicBool::new(true));
        let quiet = Arc::new(AtomicBool::new(false));
        let resume_at_us = Arc::new(AtomicI64::new(0));
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        // A broadcast channel needs no runtime, so this whole test is a plain
        // `#[test]`.
        let (events_tx, _events_rx) = tokio::sync::broadcast::channel::<EncodedFrame>(4);

        let srv = build_api_server(
            &cfg,
            snapshot.clone(),
            observing.clone(),
            quiet.clone(),
            // No pcap ring in this test: `FreezePcap` must refuse rather than
            // panic, which is the `None` arm's whole job.
            None,
            resume_at_us.clone(),
            store.clone(),
            events_tx.clone(),
        );

        // The config reaches the socket verbatim.
        assert_eq!(
            srv.socket_path, cfg.socket_path,
            "the daemon must bind the configured socket path"
        );
        assert_eq!(
            srv.socket_mode, cfg.socket_mode,
            "a hardcoded mode would ignore an operator who tightened it to 0o600"
        );
        assert_eq!(
            srv.socket_owner_uid, cfg.socket_owner_uid,
            "the socket must be chowned to the configured owner"
        );
        assert_eq!(
            srv.acting.enabled, cfg.acting.enabled,
            "the acting gate must come from config, not from a literal"
        );
        assert_eq!(
            srv.acting.singbox_service, cfg.acting.singbox_service,
            "KickstartProxy must target the configured launchctl service"
        );

        // …and the AUTHORISATION surface. `daemon_uid` is deliberately not
        // asserted here: it is `from_config`'s own behaviour, covered in `api`.
        assert_eq!(
            srv.policy.socket_owner_uid, cfg.socket_owner_uid,
            "the socket owner must be an authorised controller"
        );
        assert_eq!(
            srv.policy.control_uids, cfg.control_uids,
            "dropping control_uids locks out every headless host that set it"
        );

        // The production bounds, asserted by NAME: a deliberate retune must not
        // break this test, only a mis-wiring.
        assert_eq!(
            srv.max_subscribers,
            api::MAX_SUBSCRIBERS,
            "the daemon must run with the production subscriber cap, not a test-sized one"
        );
        assert_eq!(
            srv.max_connections,
            api::MAX_CONNECTIONS,
            "the daemon must run with the production connection cap"
        );
        assert_eq!(
            srv.request_timeout,
            api::REQUEST_READ_TIMEOUT,
            "the daemon must run with the production initial-read budget"
        );

        // Both refusal limiters carry the production interval. Asserted
        // BEHAVIOURALLY — there is no accessor, and `api.rs` is not this test's
        // to change. `record` takes `now`, so nothing sleeps. A zero interval
        // here would unbound a ROOT daemon's log while every `api` test, which
        // builds its own limiter, stayed green.
        for (name, lim) in [
            ("control_refusals", &srv.control_refusals),
            ("sub_refusals", &srv.sub_refusals),
        ] {
            let t0 = Instant::now();
            assert!(
                lim.record(t0).is_some(),
                "{name}: the first event is always reported"
            );
            assert!(
                lim.record(t0 + api::REFUSAL_LOG_INTERVAL - Duration::from_millis(1))
                    .is_none(),
                "{name}: a burst inside the production interval must not log"
            );
            assert!(
                lim.record(t0 + api::REFUSAL_LOG_INTERVAL).is_some(),
                "{name}: the next line is due exactly at the production interval"
            );
        }

        // The mutable state is SHARED with the rest of the daemon, not copied.
        assert!(
            Arc::ptr_eq(&srv.observing, &observing),
            "a fresh `observing` leaves the control socket acking a pause every \
             collector keeps ignoring"
        );
        assert!(
            Arc::ptr_eq(&srv.quiet, &quiet),
            "a fresh `quiet` leaves the control socket acking a quiet mode the \
             link collector never enters, so the gateway keeps being pinged \
             while the capture is being gathered to prove it is not us"
        );
        assert!(
            Arc::ptr_eq(&srv.resume_at_us, &resume_at_us),
            "a fresh `resume_at_us` leaves the pipeline's trigger window never \
             cleared, so a count-based condition spans the observation gap"
        );
        assert!(
            Arc::ptr_eq(&srv.snapshot, &snapshot),
            "a fresh snapshot leaves the socket serving a status the pipeline \
             never updates"
        );
        assert!(
            srv.events_tx.same_channel(&events_tx),
            "a fresh bus leaves every `Subscribe` stream silent"
        );

        // The store is the daemon's OWN handle. `Arc<dyn Store>` cannot be
        // `ptr_eq`'d against `Arc<DuckdbStore>`, so write through the server's
        // handle and read back through the daemon's — two in-memory DuckDBs are
        // two databases, so this discriminates.
        srv.store
            .write_observing_edge(&types::ObservingEdge {
                ts_us: 7,
                observing: false,
                peer_uid: Some(1),
                cause: types::ObservingCause::Control,
            })
            .unwrap();
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM observing_edge")
                .unwrap(),
            1,
            "the control path must write pause/resume edges into the daemon's own store"
        );
    }

    /// Startup writes the boundary that makes a restart a readable fact: one
    /// durable `observing_edge` row (`observing = true`, `cause = startup`, no
    /// peer) AND the same value on the realtime bus — the two sinks an operator
    /// edge uses, not a second mechanism. The state itself is still not
    /// persisted; only this transition is.
    #[test]
    fn startup_records_an_observing_edge_through_both_sinks() {
        let store = DuckdbStore::in_memory().unwrap();
        let (events_tx, mut events_rx) = tokio::sync::broadcast::channel::<EncodedFrame>(8);

        let edge = record_startup_edge(&store, &events_tx, 4_242);

        assert_eq!(edge.ts_us, 4_242);
        assert!(edge.observing, "a daemon always boots collecting");
        assert_eq!(edge.peer_uid, None, "nobody asked; the process booted");
        assert_eq!(edge.cause, types::ObservingCause::Startup);

        // Sink 1, durable.
        assert_eq!(
            store
                .query_scalar_i64(
                    "SELECT count(*) FROM observing_edge \
                     WHERE ts_us = 4242 AND observing AND peer_uid IS NULL \
                       AND cause = 'startup'"
                )
                .unwrap(),
            1,
            "the startup transition must be durable, or a restart stays an inference"
        );

        // Sink 2, realtime: the same value, decoded off the bus.
        let frame = events_rx.try_recv().expect("a frame must reach the bus");
        let decoded: net_observer_ipc::StreamFrame = serde_json::from_slice(frame.bytes())
            .expect("bus payload must decode as a StreamFrame");
        match decoded {
            net_observer_ipc::StreamFrame::Observing(back) => assert_eq!(back, edge),
            other => panic!("unexpected frame variant: {other:?}"),
        }
    }

    // ── the TriggerEngine wiring ───────────────────────────────────────────

    /// The production engine under test, plus everything needed to observe what
    /// it did: the store it records into, the live snapshot its
    /// `SnapshotHandler` mirrors into, and a held-open bus receiver.
    struct EngineFixture {
        engine: TriggerEngine,
        store: Arc<DuckdbStore>,
        snapshot: Arc<Mutex<StatusSnapshot>>,
        events_rx: tokio::sync::broadcast::Receiver<EncodedFrame>,
    }

    /// Build the real [`build_engine`] — five rules, production constants — with
    /// `freezer`.
    fn engine_under_test(freezer: Option<Arc<dyn PcapFreezer>>) -> EngineFixture {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let snapshot = Arc::new(Mutex::new(StatusSnapshot::default()));
        let (events_tx, events_rx) = tokio::sync::broadcast::channel::<EncodedFrame>(64);
        let engine = build_engine(
            store.clone(),
            &test_cfg(),
            freezer,
            snapshot.clone(),
            events_tx,
        );
        EngineFixture {
            engine,
            store,
            snapshot,
            events_rx,
        }
    }

    /// How many incidents `store` holds for `trigger_id`.
    ///
    /// ALWAYS filtered: [`build_engine`] installs five rules at once, so an
    /// unfiltered `count(*)` would let another rule's firing stand in for the one
    /// under test.
    fn incidents_for(store: &DuckdbStore, trigger_id: &str) -> i64 {
        store
            .query_scalar_i64(&format!(
                "SELECT count(*) FROM incident WHERE trigger_id='{trigger_id}'"
            ))
            .unwrap()
    }

    /// Push `s` into `w` and evaluate the engine at its timestamp, exactly as
    /// `pipeline::run` does.
    fn feed(engine: &mut TriggerEngine, w: &mut RecentWindow, s: Sample) {
        let ts_us = s.ts_us();
        w.push(s);
        engine.on_sample(w, ts_us);
    }

    /// The `wedge` rule the daemon actually runs counts to
    /// [`WEDGE_CONSECUTIVE`] — three — dead tick pairs, no fewer and no more.
    ///
    /// Dies under `WEDGE_CONSECUTIVE = 2` (the two-pair run fires, so the first
    /// assertion reds) and under `WEDGE_CONSECUTIVE = 4` (the three-pair run stays
    /// silent, so the second reds). The pair counts are LITERALS on purpose: a
    /// fixture derived from `WEDGE_CONSECUTIVE` would move with the constant and
    /// so pin nothing at all. This test IS the constant's pin — a deliberate
    /// retune must retune it here too, and it says so when it reds.
    ///
    /// Nothing else in the rule set can fire on this stream: `gw-drop` needs a
    /// FAIL, `gw-change` needs a change, `starvation` needs a host sample and
    /// `fakeip` needs DNS.
    #[test]
    fn build_engine_wires_the_production_wedge_threshold() {
        let mut fx = engine_under_test(None);
        let mut w = RecentWindow::new(8);

        // Two dead tick pairs — one short of the production threshold of three.
        for i in 0..2 {
            feed(&mut fx.engine, &mut w, link(2 * i + 1, GwVerdict::Ok));
            feed(&mut fx.engine, &mut w, dead_proxy(2 * i + 2));
        }
        assert_eq!(
            incidents_for(&fx.store, "wedge"),
            0,
            "two dead ticks are one short of WEDGE_CONSECUTIVE and must not fire"
        );

        // The third pair completes the run.
        feed(&mut fx.engine, &mut w, link(5, GwVerdict::Ok));
        feed(&mut fx.engine, &mut w, dead_proxy(6));
        assert_eq!(
            incidents_for(&fx.store, "wedge"),
            1,
            "the third consecutive dead tick must fire the wedge rule"
        );
    }

    /// The re-arm/backoff budget the daemon actually runs is
    /// [`BACKOFF_US`]: a persistent gateway fault re-fires only once the whole
    /// budget has elapsed, and it re-fires at the FIRST microsecond it is
    /// available.
    ///
    /// Dies under `BACKOFF_US = 0` (the fault at `ts = 3` re-fires, so the first
    /// assertion reds) and under `BACKOFF_US = i64::MAX` (the fault at exactly
    /// `last_fire + BACKOFF_US` stays latched, so the second reds). The last
    /// sample sits at exactly that boundary, so `>=` → `>` in the engine's
    /// predicate dies here too. `saturating_add`, not `1 + ..`: under the
    /// `i64::MAX` mutation a plain `+` would panic on overflow instead of giving
    /// a clean red. Filtered by `gw-drop` because the OK/FAIL alternation also
    /// fires `gw-change`.
    #[test]
    fn build_engine_wires_the_production_backoff() {
        let mut fx = engine_under_test(None);
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, link(1, GwVerdict::Fail)); // fires
        feed(&mut fx.engine, &mut w, link(2, GwVerdict::Ok)); // re-arms
        feed(&mut fx.engine, &mut w, link(3, GwVerdict::Fail)); // armed, but broke
        assert_eq!(
            incidents_for(&fx.store, "gw-drop"),
            1,
            "a re-armed trigger must still wait out BACKOFF_US before re-firing"
        );

        feed(&mut fx.engine, &mut w, link(4, GwVerdict::Ok)); // re-arms
        feed(
            &mut fx.engine,
            &mut w,
            link(1i64.saturating_add(BACKOFF_US), GwVerdict::Fail),
        );
        assert_eq!(
            incidents_for(&fx.store, "gw-drop"),
            2,
            "exactly BACKOFF_US after the last fire the budget is available again"
        );
    }

    /// The `starvation` rule the daemon actually runs discriminates at
    /// [`STARVATION_LOAD`].
    ///
    /// Dies under `STARVATION_LOAD = 0.0` (a load of 9.0 fires, so the first
    /// assertion reds) and under any threshold above 10.5 (the second reds).
    /// `Starvation::eval` is "newest proxy tun dead AND newest host `load1` >
    /// threshold", so the dead proxy tick alone must stay silent.
    #[test]
    fn build_engine_wires_the_production_starvation_threshold() {
        let mut fx = engine_under_test(None);
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, dead_proxy(1));
        feed(&mut fx.engine, &mut w, host(2, 9.0));
        assert_eq!(
            incidents_for(&fx.store, "starvation"),
            0,
            "a dead tun under a load below STARVATION_LOAD is a wedge, not starvation"
        );

        feed(&mut fx.engine, &mut w, host(3, 10.5));
        assert_eq!(
            incidents_for(&fx.store, "starvation"),
            1,
            "a dead tun above STARVATION_LOAD must be recorded as starvation"
        );
    }

    /// The handler fan-out: `gw-change` — and only `gw-change` — gets the pcap
    /// freeze, every rule gets the snapshot ring and the realtime bus, and a
    /// daemon with no ring still records the incident.
    ///
    /// Dies under: dropping `freeze` from `gw_change_handlers` (no `blob_ref`);
    /// adding it to another rule (two `blob_ref` rows for this stream); dropping
    /// `snap` from either the `gw-change` or the `gw-drop` handler vec (the ring
    /// and the bus lose that trigger); and dropping `record` (no incident at all,
    /// with or without a ring).
    #[test]
    fn build_engine_gives_gw_change_the_pcap_freeze_and_every_rule_the_snapshot_ring() {
        let freezer: Option<Arc<dyn PcapFreezer>> = Some(Arc::new(FakeFreezer));
        let mut fx = engine_under_test(freezer);
        let mut w = RecentWindow::new(8);

        // OK -> FAIL is both a gateway CHANGE and a gateway DROP, so one stream
        // exercises the rule that owns the freeze and one that must not.
        feed(&mut fx.engine, &mut w, link(1, GwVerdict::Ok));
        feed(&mut fx.engine, &mut w, link(2, GwVerdict::Fail));

        assert_eq!(
            incidents_for(&fx.store, "gw-change"),
            1,
            "a gateway change must be recorded durably"
        );
        assert_eq!(
            fx.store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            1,
            "gw-change must freeze the volatile ring and record the copied file"
        );

        // The live view the socket serves must carry BOTH firings.
        let ring: Vec<String> = fx
            .snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .incidents
            .iter()
            .map(|i| i.trigger_id.clone())
            .collect();
        for id in ["gw-change", "gw-drop"] {
            assert!(
                ring.iter().any(|t| t == id),
                "the snapshot ring must carry {id}; it holds {ring:?}"
            );
        }

        // …and so must the realtime bus. `SnapshotHandler` publishes
        // unconditionally, so holding a receiver is enough.
        let published = incident_trigger_ids(&mut fx.events_rx);
        for id in ["gw-change", "gw-drop"] {
            assert!(
                published.iter().any(|t| t == id),
                "the event bus must carry {id}; it carried {published:?}"
            );
        }

        // Without a ring the incident is still recorded — the freeze is the only
        // thing that goes missing.
        let mut bare = engine_under_test(None);
        let mut bare_w = RecentWindow::new(8);
        feed(&mut bare.engine, &mut bare_w, link(1, GwVerdict::Ok));
        feed(&mut bare.engine, &mut bare_w, link(2, GwVerdict::Fail));
        assert_eq!(
            incidents_for(&bare.store, "gw-change"),
            1,
            "a daemon with no pcap ring must still record the gateway change"
        );
        assert_eq!(
            bare.store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            0,
            "with no ring there is nothing to freeze, so no blob_ref"
        );
    }

    /// Every incident the bus carried, by trigger id. The bus deliberately
    /// carries bytes (one encode for N subscribers), so the frames are decoded
    /// here rather than the wire type growing a test-only accessor.
    fn incident_trigger_ids(
        rx: &mut tokio::sync::broadcast::Receiver<EncodedFrame>,
    ) -> Vec<String> {
        let mut ids = Vec::new();
        while let Ok(frame) = rx.try_recv() {
            let decoded: StreamFrame = serde_json::from_slice(frame.bytes())
                .expect("bus payload must decode as a StreamFrame");
            if let StreamFrame::Event(Event::Incident(summary)) = decoded {
                ids.push(summary.trigger_id);
            }
        }
        ids
    }
}
