//! `observerd` — the headless root LaunchDaemon (plan Task 13).
//!
//! Loads config, opens the DuckDB store, spawns the enabled collectors onto an
//! mpsc stream, builds the trigger engine with the starter rules + passive
//! handlers (record incidents; freeze the pcap ring on any gateway change), runs
//! the consumer loop, and shuts down cleanly on SIGTERM/SIGINT.

mod api;
mod pipeline;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use collector_core::{Collector, EventSource, Os, Readiness, Source};
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
use observer_ipc::StatusSnapshot;
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
const CHANNEL_CAP: usize = 256;

/// How many recent incidents the live snapshot keeps for the socket API. DuckDB
/// remains the durable record; this ring is just the in-memory live view.
const INCIDENT_RING_CAP: usize = 20;

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
/// `read(2)` runs on a blocking thread that `abort()` cannot interrupt, so it
/// keeps a stream sender alive and the consumer's `rx.recv()` may never observe
/// the stream close. Bounding the drain here (and reaping the leftover blocking
/// thread with [`tokio::runtime::Runtime::shutdown_timeout`] in [`main`]) keeps
/// shutdown from hanging forever on an idle routing socket.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(
    name = "observerd",
    about = "observer network-forensics collector daemon"
)]
struct Cli {
    /// Path to the TOML config file (`OBSERVER_*` env overrides still apply).
    #[arg(long)]
    config: Option<String>,
}

fn main() -> anyhow::Result<()> {
    // Build the runtime explicitly (instead of `#[tokio::main]`) so shutdown can
    // be *bounded*. The route collector's PF_ROUTE `read(2)` runs on a blocking
    // pool thread that cannot be aborted; `shutdown_timeout` guarantees the
    // process still exits even if that read is parked on an idle socket at exit.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = runtime.block_on(run_daemon());
    runtime.shutdown_timeout(SHUTDOWN_GRACE);
    result
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
    tracing::info!(db = %cfg.db_path, "starting observerd");

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

    // Serve the read-only status socket for the unprivileged bar. Best-effort: a
    // bind failure is logged but never takes the daemon down (no API, still
    // collecting). Aborted on shutdown alongside the collectors.
    let api_handle = {
        let snapshot = snapshot.clone();
        let socket_path = cfg.socket_path.clone();
        let socket_mode = cfg.socket_mode;
        tokio::spawn(async move {
            if let Err(e) = api::serve(socket_path, socket_mode, snapshot).await {
                tracing::error!(error = %e, "status socket server exited");
            }
        })
    };

    let (tx, rx) = mpsc::channel::<Sample>(CHANNEL_CAP);

    // Resolve the physical interface once, for the pcap ring.
    let phys_iface = SystemFacts::new(
        cfg.collectors.link.gw.clone(),
        cfg.collectors.link.phys_iface.clone(),
    )
    .phys_iface();

    // Build the enabled collectors as Box<dyn Collector>.
    let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
    if cfg.collectors.link.enabled {
        collectors.push(Box::new(LinkCollector::new(
            Arc::new(IcmpPinger::new()),
            Arc::new(BoundTcpProber::new()),
            Arc::new(SystemFacts::new(
                cfg.collectors.link.gw.clone(),
                cfg.collectors.link.phys_iface.clone(),
            )),
            cfg.collectors.link.interval,
        )));
    }
    if cfg.collectors.proxy.enabled {
        collectors.push(Box::new(ProxyCollector::new(
            Arc::new(BoundTcpProber::new()),
            Arc::new(ProxySystemFacts::new(
                SINGBOX_CONFIG_PATH,
                cfg.collectors.proxy.clash_api.clone(),
                CLASH_SELECTOR_GROUP,
            )),
            cfg.collectors.proxy.tun_probe_url.clone(),
            phys_iface.clone().unwrap_or_default(),
            cfg.collectors.proxy.interval,
        )));
    }
    if cfg.collectors.dns.enabled {
        collectors.push(Box::new(DnsCollector::new(
            Arc::new(DnsResolver::new(
                cfg.collectors.dns.monitored_domain.clone(),
                cfg.collectors.dns.ru_control_domain.clone(),
                cfg.collectors.dns.doh_url.clone(),
            )),
            cfg.collectors.dns.interval,
        )));
    }
    if cfg.collectors.host.enabled {
        collectors.push(Box::new(HostCollector::new(
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
        collectors.push(Box::new(RouteCollector::new(source, ready)));
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
        let ready = c.preflight();
        if !ready.is_ready() {
            if let Readiness::Unavailable(reason) = ready {
                tracing::warn!(collector = name, %reason, "preflight failed; skipping");
            }
            continue;
        }
        // Dispatch on cadence — timer vs event stream.
        match c.source() {
            Source::Interval(_) => handles.push(spawn_interval_collector(c, tx.clone())),
            Source::Event => handles.push(spawn_event_collector(c, tx.clone())),
        }
    }
    // Drop our own sender so the consumer stops once every collector is gone.
    drop(tx);

    // Start the pcap ring (best-effort: needs root + tcpdump). On failure, the
    // gw-change trigger still records the incident, just without a pcap freeze.
    let freezer = maybe_start_pcap_ring(&cfg, phys_iface.as_deref());

    // Build the trigger engine with the starter rule set + passive handlers.
    let engine = build_engine(store.clone(), &cfg, freezer, snapshot.clone());

    // Run the consumer loop until a shutdown signal (or the stream closing).
    let mut consumer = tokio::spawn(run(store.clone(), engine, rx, snapshot.clone()));

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
    // PF_ROUTE `read(2)` cannot be aborted, so its task can keep a stream sender
    // alive and `rx.recv()` may never see the stream close; bound the drain so
    // shutdown cannot hang (the leftover blocking thread is reaped by
    // `shutdown_timeout` in `main`).
    abort_all(&handles);
    api_handle.abort();
    match tokio::time::timeout(SHUTDOWN_GRACE, &mut consumer).await {
        Ok(Ok(())) => tracing::info!("observerd shut down cleanly"),
        Ok(Err(e)) => tracing::error!(error = %e, "consumer join failed during shutdown"),
        Err(_) => tracing::warn!(
            grace_s = SHUTDOWN_GRACE.as_secs(),
            "consumer did not drain within grace; forcing shutdown"
        ),
    }
    Ok(())
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
        tracing::warn!("no physical interface resolved; pcap ring disabled");
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

/// Assemble the [`TriggerEngine`] with the starter rules (wedge, gw-drop,
/// gw-change, fakeip, starvation). Every rule records an incident (durable, in
/// DuckDB) and mirrors it into the live snapshot's ring for the socket API;
/// gw-change additionally freezes the pcap ring when one is available.
fn build_engine(
    store: Arc<DuckdbStore>,
    cfg: &Config,
    freezer: Option<Arc<dyn PcapFreezer>>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
) -> TriggerEngine {
    let record: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
    // Passive handler that pushes each firing onto the live snapshot's incident
    // ring so the socket API serves recent incidents from memory. Added to every
    // trigger alongside `record`.
    let snap: Arc<dyn Handler> = Arc::new(SnapshotHandler::new(snapshot, INCIDENT_RING_CAP));

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
