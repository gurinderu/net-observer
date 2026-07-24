//! `observerd` — the headless root LaunchDaemon (plan Task 13).
//!
//! Loads config, opens the DuckDB store, spawns the enabled collectors onto an
//! mpsc stream, builds the trigger engine with the starter rules + passive
//! handlers (record incidents; freeze the pcap ring on any gateway change), runs
//! the consumer loop, and shuts down cleanly on SIGTERM/SIGINT.

mod pipeline;

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use collector_core::{Collector, Os, Readiness, Source};
use collector_link::{LinkCollector, LinkFacts};
use collector_proxy::ProxyCollector;
use config::Config;
use macos::{BoundTcpProber, IcmpPinger, PcapRing, ProxySystemFacts, SystemFacts};
use store::DuckdbStore;
use triggers::conditions::{FakeIp, GwChange, GwDrop, Starvation, Wedge};
use triggers::engine::{Trigger, TriggerEngine};
use triggers::handlers::{Handler, RecordHandler};
use types::Sample;

use pipeline::{
    FreezePcapHandler, PcapFreezer, run, spawn_event_collector, spawn_interval_collector,
};

/// Minimum interval between fires for one trigger (5 minutes, in microseconds),
/// mirroring net-observer so a captive portal can't storm the incident log.
const BACKOFF_US: i64 = 300_000_000;

/// Depth of the sample stream between the collectors and the consumer.
const CHANNEL_CAP: usize = 256;

/// Wedge signal: tun dead while the direct path is healthy, for this many ticks.
const WEDGE_CONSECUTIVE: usize = 3;

/// Host load above which a dead tun counts as starvation (dormant until the
/// `host-metrics` collector lands, but wired now so the rule set is complete).
const STARVATION_LOAD: f64 = 10.0;

/// Path to the rendered sing-box config (read at runtime — server addresses are
/// never compiled in). Deployment writes it here; absent ⇒ proxy emits SKIP.
const SINGBOX_CONFIG_PATH: &str = "/etc/sing-box/config.json";

/// Clash/Mihomo proxy group whose current selection identifies the active node.
const CLASH_SELECTOR_GROUP: &str = "GLOBAL";

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    // Filter by OS meta + preflight, then spawn survivors with one uniform loop.
    let os = Os::current();
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    for c in collectors {
        let name = c.meta().name;
        if !c.meta().supports(os) {
            tracing::warn!(collector = name, ?os, "unsupported OS; skipping");
            continue;
        }
        if !c.preflight().is_ready() {
            if let Readiness::Unavailable(reason) = c.preflight() {
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
    let engine = build_engine(store.clone(), &cfg, freezer);

    // Run the consumer loop until a shutdown signal (or the stream closing).
    let mut consumer = tokio::spawn(run(store.clone(), engine, rx));

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
            return Ok(());
        }
    }

    // Signal path: stop the collectors, which closes the stream, then let the
    // consumer drain what remains and exit cleanly.
    abort_all(&handles);
    if let Err(e) = consumer.await {
        tracing::error!(error = %e, "consumer join failed during shutdown");
    }
    tracing::info!("observerd shut down cleanly");
    Ok(())
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
/// gw-change, fakeip, starvation). Every rule records an incident; gw-change
/// additionally freezes the pcap ring when one is available.
fn build_engine(
    store: Arc<DuckdbStore>,
    cfg: &Config,
    freezer: Option<Arc<dyn PcapFreezer>>,
) -> TriggerEngine {
    let record: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));

    let mut gw_change_handlers: Vec<Arc<dyn Handler>> = vec![record.clone()];
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
            vec![record.clone()],
            BACKOFF_US,
        ),
        Trigger::new(Box::new(GwDrop), vec![record.clone()], BACKOFF_US),
        Trigger::new(Box::new(GwChange), gw_change_handlers, BACKOFF_US),
        Trigger::new(Box::new(FakeIp), vec![record.clone()], BACKOFF_US),
        Trigger::new(
            Box::new(Starvation {
                load_threshold: STARVATION_LOAD,
            }),
            vec![record],
            BACKOFF_US,
        ),
    ];

    TriggerEngine::new(triggers)
}
