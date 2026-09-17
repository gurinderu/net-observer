//! `net-observerd` — the headless root LaunchDaemon (plan Task 13).
//!
//! Loads config, opens the DuckDB store, spawns the enabled collectors onto an
//! mpsc stream, builds the trigger engine with the starter rules + passive
//! handlers (record incidents; freeze the pcap ring on any gateway change), runs
//! the consumer loop, and shuts down cleanly on SIGTERM/SIGINT.

mod acting;
mod api;
mod api_query;
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

use collector_air::AirCollector;
use collector_core::{Collector, CollectorMeta, EventSource, Os, ProbingState, Readiness, Source};
use collector_dns::DnsCollector;
use collector_host::HostCollector;
use collector_link::{LinkCollector, LinkFacts};
use collector_neighbors::NeighborsCollector;
use collector_proxy::ProxyCollector;
use collector_route::RouteCollector;
use collector_wifi::WifiCollector;
use config::Config;
use macos::LldpCapture;
use macos::{
    BoundTcpProber, CoreWlanFacts, DnsResolver, HeldReferenceStreams, HostLoad, IcmpPinger,
    PcapRing, PfRouteSource, ProxySystemFacts, SystemFacts, SystemNeighbors, SystemProfilerAir,
    TcpdumpLldpCapture,
};
use macos::{neighbor_scan, neighbors};
use net_observer_ipc::{Capabilities, EncodedFrame, EventKind, StatusSnapshot};
use store::DuckdbStore;
use triggers::conditions::{
    BanCycle, EndpointBlock, EstablishedStall, FakeIp, FakeIpHijack, Gated, GwChange, GwDrop,
    GwMacChange, NeighborMacCollision, PerClientBlock, Roam, Starvation, Wedge, WifiChurn,
};
use triggers::engine::{Trigger, TriggerEngine};
use triggers::handlers::{Handler, RecordHandler};
use types::{ProbingEdge, ProbingTier, Sample};

use pipeline::{
    AirScanner, FreezePcapHandler, NeighborScanner, OnDemandAirScan, PcapFreezer, PcapRingSlot,
    ScanReport, SnapshotHandler, run, spawn_event_collector, spawn_interval_collector,
};

/// How often the pcap supervisor re-checks the ring. Bounded on purpose: every
/// attempt may spawn a `tcpdump` child, so this is a slow patrol, not a tick.
const PCAP_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// How often the topology patrol opens a fresh short-lived LLDP/CDP capture.
/// Switches broadcast discovery frames roughly once every 30-60s, so a 5-minute
/// patrol reliably catches at least one advertisement per neighbour without
/// keeping a capture open continuously — a slow patrol, like the pcap one.
const TOPOLOGY_PATROL_INTERVAL: Duration = Duration::from_secs(300);

/// How long each topology capture listens before it is stopped. Long enough to
/// span a switch's advertisement interval, short enough that the throwaway
/// capture is plainly bounded.
const TOPOLOGY_CAPTURE_BUDGET: Duration = Duration::from_secs(65);

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

/// Endpoint-block signal: every upstream endpoint's underlay TCP probe dead
/// while the direct reference answers, for this many per-tick cohorts. Two
/// cohorts = 30s at the 15s proxy cadence — a single transition tick must not
/// fire the fleet-wide signature.
const ENDPOINT_BLOCK_CONSECUTIVE: usize = 2;

/// Ban-cycle signal: this many gateway bans (`Fail` runs bounded by `Ok`) in
/// the recent window read as one cycling incident with a period. Two bans are
/// two outages; the third is the pattern.
const BAN_CYCLE_MIN_BANS: usize = 3;

/// Host load above which a dead tun counts as starvation (read from the `host`
/// collector's newest sample by the `Starvation` condition), and above which
/// the `Gated` fault conditions decline to fire at all — there a probe
/// failure measures the run queue, not the network.
///
/// ONE number, owned by the store's diagnosis module: the daemon judges the
/// record by it live and the offline reader reads the record by it later, and
/// two literals could drift apart silently — the reading and the incidents it
/// was meant to explain would then disagree.
const STARVATION_LOAD: f64 = store::diagnosis::DEFAULT_STARVATION_LOAD;

/// How long after a network-identity change (`dhcp_router` moved) the `Gated`
/// fault conditions hold their fire. Right after a move every layer is
/// legitimately in flux: netreload restarts sing-box, old flows die with the
/// NAT, urltest rebuilds its history — ~2 minutes covers the whole settle
/// (measured 2026-09-16: a coworking move took ~3 min end to end, of which
/// the last minute was already healthy).
const SETTLE_US: i64 = 120_000_000;

/// Path to the rendered sing-box config (read at runtime — server addresses are
/// never compiled in). Deployment writes it here; absent ⇒ proxy emits SKIP.
const SINGBOX_CONFIG_PATH: &str = "/etc/sing-box/config.json";

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
/// Load the shared OUI registry for neighbour ROLE inference, ONCE at startup.
///
/// The configured value is a directory (like the CVE snapshot); the registry is
/// the Wireshark `manuf` file at `<dir>/manuf`. Every failure mode — no directory
/// configured, a missing/unreadable file, or an empty index — returns `None`, and
/// the inference then degrades to gateway/unknown only rather than guessing a
/// vendor. (realm net-observer, node #36)
fn load_oui_db(dir: Option<&str>) -> Option<Arc<oui_db::OuiDb>> {
    let dir = dir?;
    let path = Path::new(dir).join("manuf");
    match oui_db::OuiDb::load_from_file(&path) {
        Ok(db) if db.is_empty() => {
            tracing::warn!(
                path = %path.display(),
                "OUI snapshot loaded but empty; neighbour roles degrade to gateway/unknown"
            );
            None
        }
        Ok(db) => {
            tracing::info!(path = %path.display(), ouis = db.len(), "loaded OUI snapshot");
            Some(Arc::new(db))
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "OUI snapshot could not be read; neighbour roles degrade to gateway/unknown"
            );
            None
        }
    }
}

/// Spawn the topology patrol: on a slow interval, open a bounded LLDP/CDP
/// capture on `iface`, map every received frame to a [`types::TopologyLink`],
/// upsert each into the store, and mirror the current set onto the live
/// snapshot the socket serves.
///
/// While paused (`observing == false`) the patrol skips its capture entirely —
/// an operator pause stops collection outright rather than emitting synthetic
/// readings (AGENTS.md: the sanctioned bracketed-pause exception). A capture
/// that maps no links leaves the snapshot's last discovered set in place rather
/// than blanking it, so one quiet interval does not erase a real uplink from the
/// live view (the durable record is the store, which keeps first/last seen).
fn spawn_topology_patrol(
    store: Arc<DuckdbStore>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
    observing: Arc<AtomicBool>,
    iface: String,
) -> JoinHandle<()> {
    use std::sync::atomic::Ordering;
    use store::Store as _;

    tokio::spawn(async move {
        let capture = TcpdumpLldpCapture::new(iface.clone());
        let mut ticker = tokio::time::interval(TOPOLOGY_PATROL_INTERVAL);
        loop {
            ticker.tick().await;
            if !observing.load(Ordering::Relaxed) {
                continue;
            }
            // The capture blocks (spawns a child, waits its budget), so run it off
            // the async runtime rather than stalling the reactor.
            let cap = capture.clone();
            let frames =
                match tokio::task::spawn_blocking(move || cap.capture(TOPOLOGY_CAPTURE_BUDGET))
                    .await
                {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(error = %e, "topology capture task failed to join");
                        continue;
                    }
                };

            let now = types::now_us();
            let mut latest: Vec<types::TopologyLink> = Vec::new();
            for frame in &frames {
                let Some(link) = types::link_from_frame(frame, &iface, now) else {
                    continue;
                };
                if let Err(e) = store.write_topology_link(&link) {
                    tracing::warn!(error = %e,
                        "store write failed; topology link dropped from DB (gap logged)");
                }
                // De-duplicate by the stable key so the live set carries one node
                // per uplink even if a switch advertised several times this run.
                if !latest.iter().any(|l| {
                    l.iface == link.iface
                        && l.remote_chassis == link.remote_chassis
                        && l.remote_port == link.remote_port
                }) {
                    latest.push(link);
                }
            }

            if !latest.is_empty() {
                // The record's first/last seen for the uplinks, read before the
                // snapshot lock is taken — `TopologyLink::ts_us` is only this
                // patrol's sighting, so this read is the sole path by which
                // `first_seen_us` reaches the socket. A failed read yields no
                // bounds, which the bar renders as "unknown" rather than as a
                // freshly-discovered uplink. (realm net-observer, node #43)
                let lifetimes = match store.topology_lifetimes() {
                    Ok(l) => l
                        .into_iter()
                        .filter(|lt| latest.iter().any(|k| lt.bounds(k)))
                        .collect(),
                    Err(e) => {
                        tracing::warn!(error = %e,
                            "topology lifetime read failed; snapshot carries no first/last seen");
                        Vec::new()
                    }
                };
                let mut snap = snapshot.lock().unwrap_or_else(|e| e.into_inner());
                snap.topology = latest;
                snap.topology_lifetimes = lifetimes;
            }
        }
    })
}

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

/// Record that THIS process began in probing tier `tier` — the configured
/// default — at `ts_us`.
///
/// The tier itself is process-scoped and never persisted; what is durable is
/// the boundary: one `probing_edge` row with `peer_uid = NULL` (nobody asked;
/// the process booted with this default), published on the realtime bus as the
/// same `StreamFrame::Probing` an operator switch produces. A record that
/// starts passive therefore says so, instead of leaving a run of `SKIP`s to be
/// read as probes that could not run. Same two sinks as `api::set_probing`, not
/// a second mechanism. (realm net-observer, node #88)
///
/// A store failure is logged as a gap and never fails startup, for the same
/// reason as [`record_startup_edge`].
fn record_startup_probing_edge(
    store: &DuckdbStore,
    events_tx: &tokio::sync::broadcast::Sender<EncodedFrame>,
    ts_us: i64,
    tier: ProbingTier,
) -> ProbingEdge {
    use store::Store as _;

    let edge = ProbingEdge {
        ts_us,
        tier,
        peer_uid: None,
    };
    match EncodedFrame::encode(&net_observer_ipc::StreamFrame::Probing(edge)) {
        Ok(frame) => {
            let _ = events_tx.send(frame);
        }
        Err(e) => tracing::warn!(error = %e, "failed to encode startup probing frame"),
    }
    if let Err(e) = store.write_probing_edge(&edge) {
        tracing::error!(error = %e,
            "store write failed; startup probing edge not recorded (gap logged)");
    }
    edge
}

/// The async daemon body: load config, open the store, spawn the enabled
/// collectors, run the consumer loop, and shut down on SIGTERM/SIGINT. The final
/// drain is bounded (see [`SHUTDOWN_GRACE`]) so an un-abortable event source can
/// never keep the daemon from exiting.
async fn run_daemon() -> anyhow::Result<()> {
    // Local time with an explicit numeric offset (`+03:00`), so a reader beside
    // local wall clocks never misreads a bare-UTC line as a silence that did not
    // happen. `ChronoLocal` parses the zone itself, cached per thread; the timer
    // choice and the rejected `time`-based one: realm net-observer, node #116.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new(
            "%Y-%m-%dT%H:%M:%S%.6f%:z".into(),
        ))
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

    // Incidents left open by the previous process can never be closed by it
    // again — the closing edge lived in its memory. Stamp them closed at the
    // observation bound rather than leaving forever-open rows.
    match store.close_open_incidents(types::now_us()) {
        Ok(0) => {}
        Ok(n) => tracing::info!(n, "closed stale open incidents from a previous run"),
        Err(e) => tracing::warn!(error = %e, "failed to close stale open incidents"),
    }

    // The OUI registry for neighbour ROLE inference, loaded ONCE here and shared
    // (Arc) by the passive collector and the active scanner — loading it per tick
    // or per scan would re-read a large file for nothing. `None` when no snapshot
    // is provisioned, or it will not load: roles then degrade to gateway/unknown
    // only, never a guessed vendor. (realm net-observer, node #36)
    let oui = load_oui_db(cfg.collectors.neighbors.oui_snapshot_dir.as_deref());

    // The live, in-memory snapshot the socket API serves. The pipeline consumer
    // keeps it current (latest sample per variant); the SnapshotHandler mirrors
    // fired incidents into its bounded ring. The daemon stays the sole DuckDB
    // owner — the socket answers from this snapshot, never the DB.
    let snapshot = Arc::new(Mutex::new(StatusSnapshot {
        // Say what this daemon can collect, once, at startup: the collectors
        // this build HAS, each with whether config lets it run. A reader cannot
        // otherwise tell "this daemon has no such collector" from "it has one and
        // it is switched off", and it must not offer the operator a window onto
        // something that can never fill — nor hide the switch he is looking for.
        // Config is read once and never reloaded, so this never goes stale.
        capabilities: Some(declared_capabilities(&cfg.collectors)),
        // The tier this daemon boots into, from config — NOT the snapshot's own
        // default, which is the pre-tier daemon's `Active` and would report a
        // passive daemon as probing until the first switch.
        probing: cfg.probing.default,
        ..StatusSnapshot::default()
    }));

    // The observer's OWN collection on/off flag (self-control). `true` (default)
    // = collecting; `false` = paused. The interval + event collectors check it
    // each cycle (skip the probe / drop the batch while paused); the
    // `SetObserving` control command flips it. Benign self-control — it never
    // touches sing-box or the network. While paused the daemon stays alive and
    // the socket keeps serving, so the switch can turn collection back on.
    // `StatusSnapshot::default()` already reports
    // `observing: true`; the control handler mirrors every change into it.
    //
    // It always starts `true`, and is deliberately never loaded from disk (see
    // the startup log below for why).
    let observing = Arc::new(AtomicBool::new(true));

    // The probing tier: which emission classes the link, proxy and dns
    // collectors may put on the wire. Boots into the configured default —
    // `passive`, nothing on the wire, unless the operator's config says
    // otherwise — and is shared with those three collectors and the control
    // socket exactly the way `observing` is. Process-scoped and, like
    // `observing`, deliberately never persisted: a restart returns to the
    // configured default, and only `SetProbing` moves it while the daemon
    // runs. (realm net-observer, node #88)
    let probing = Arc::new(ProbingState::new(cfg.probing.default));

    // The observing state is process-scoped and deliberately NEVER persisted: a
    // root forensics collector silently staying blind across a restart nobody
    // noticed is the dangerous failure mode, whereas restart-resumes fails safe.
    // Logged so the choice is explicit at every boot rather than accidental.
    tracing::info!(
        observing = true,
        probing = %cfg.probing.default,
        "collection enabled at startup; the observing state is process-scoped and \
         deliberately never persisted — a restart always resumes collecting, in the \
         configured probing tier"
    );

    // `ts_us` of the most recent window-clearing edge. The control socket
    // publishes it on every `SetObserving(true)` transition and on every real
    // `SetProbing` switch (either direction); the pipeline consumer watches it
    // and drops its recent-sample window so a count-based condition cannot
    // span the observation gap a pause opened, nor the passive stretch a tier
    // switch opened or closed. `0` = no such edge yet.
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
    let booted_us = types::now_us();
    record_startup_edge(store.as_ref(), &events_tx, booted_us);
    // The same for the probing tier: the configured default is a transition
    // too, and a record that begins passive must say so before the first
    // withheld probe lands as `SKIP`. Same instant as the observing edge — one
    // boot, one `ts_us`.
    record_startup_probing_edge(store.as_ref(), &events_tx, booted_us, probing.tier());

    let (tx, rx) = mpsc::channel::<Sample>(CHANNEL_CAP);
    // A sender for the control socket's on-demand air scan, taken BEFORE the
    // collectors' own `tx` is dropped below: an operator-pressed slice must reach
    // the same consumer loop every periodic sample does.
    let api_tx = tx.clone();

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
            )
            // The fakeip-pool route resolution reads the same rendered config
            // the proxy facts adapter does; absent, the field records None.
            .with_singbox_config(SINGBOX_CONFIG_PATH),
            cfg.collectors.link.interval,
            probing.clone(),
        )));
    }
    if cfg.collectors.proxy.enabled {
        collectors.push(AnyCollector::Proxy(Box::new(ProxyCollector::new(
            BoundTcpProber::new(),
            ProxySystemFacts::new(
                SINGBOX_CONFIG_PATH,
                cfg.collectors.proxy.clash_api.clone(),
                cfg.collectors.proxy.selector_group.clone(),
            ),
            // The held reference streams: direct bound to the physical
            // interface, tunnel on the default route. The adapter owns the
            // sockets across ticks; the interval sets its staleness bound, so a
            // stream idle across an observing pause is discarded unmeasured.
            HeldReferenceStreams::new(
                phys_iface.clone().unwrap_or_default(),
                cfg.collectors.proxy.interval,
            ),
            cfg.collectors.proxy.tun_probe_url.clone(),
            phys_iface.clone().unwrap_or_default(),
            cfg.collectors.proxy.interval,
            probing.clone(),
        ))));
    }
    if cfg.collectors.dns.enabled {
        collectors.push(AnyCollector::Dns(DnsCollector::new(
            DnsResolver::new(
                cfg.collectors.dns.monitored_domain.clone(),
                cfg.collectors.dns.ru_control_domain.clone(),
                cfg.collectors.dns.doh_url.clone(),
                SINGBOX_CONFIG_PATH.to_string(),
            ),
            cfg.collectors.dns.interval,
            probing.clone(),
        )));
    }
    if cfg.collectors.host.enabled {
        // The record's volume is the filesystem holding the DB file: its
        // directory, created above before the store was opened, so it exists
        // from the first tick (realm net-observer, node #123).
        let record_volume = Path::new(&cfg.db_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        collectors.push(AnyCollector::Host(HostCollector::new(
            Arc::new(HostLoad::new(record_volume)),
            cfg.collectors.host.interval,
        )));
    }
    if cfg.collectors.wifi.enabled {
        collectors.push(AnyCollector::Wifi(WifiCollector::new(
            Arc::new(CoreWlanFacts::new()),
            cfg.collectors.wifi.interval,
        )));
    }
    if cfg.collectors.air.enabled {
        // Off unless the operator asked for it, and on its own slow period: the
        // system wireless report costs seconds per call (realm net-observer,
        // node #47). It transmits nothing — it only reads that report.
        collectors.push(AnyCollector::Air(AirCollector::new(
            Arc::new(SystemProfilerAir::new()),
            cfg.collectors.air.interval,
        )));
    }
    if cfg.collectors.neighbors.enabled {
        // Shares the link collector's `SystemFacts` so the gateway and interface
        // it keys neighbours by are the same ones the link collector probes,
        // including any config override.
        collectors.push(AnyCollector::Neighbors(NeighborsCollector::new(
            Arc::new(SystemNeighbors::new(SystemFacts::new(
                cfg.collectors.link.gw.clone(),
                cfg.collectors.link.phys_iface.clone(),
            ))),
            cfg.collectors.neighbors.interval,
            oui.clone(),
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
            Source::Interval(_) => handles.push(spawn_interval_collector(
                c,
                tx.clone(),
                observing.clone(),
                resume_at_us.clone(),
            )),
            Source::Event => handles.push(spawn_event_collector(c, tx.clone(), observing.clone())),
        }
    }
    // Drop our own sender so the consumer stops once every collector is gone.
    drop(tx);

    // Start the pcap ring (best-effort: needs root + tcpdump), and keep a
    // supervisor on it. The slot is what the socket and the gw-change handler
    // read, so a ring that starts late — or restarts after its child died — is
    // picked up by both without any re-wiring.
    let (freezer, pcap_reason) = if cfg.collectors.pcap_ring.enabled {
        maybe_start_pcap_ring(&cfg, phys_iface.as_deref())
    } else {
        (Arc::new(PcapRingSlot::empty()), None)
    };
    let pcap_handle = cfg.collectors.pcap_ring.enabled.then(|| {
        let slot = freezer.clone();
        let ring_dir = Path::new(&cfg.blob_dir).join("ring");
        let ring_mb = cfg.collectors.pcap_ring.ring_mb;
        let filter = cfg.collectors.pcap_ring.filter.clone();
        let gw = cfg.collectors.link.gw.clone();
        let configured_iface = cfg.collectors.link.phys_iface.clone();
        tokio::spawn(async move {
            supervise_pcap_ring(
                slot,
                PCAP_RETRY_INTERVAL,
                pcap_reason,
                || {
                    let facts = SystemFacts::new(gw.clone(), configured_iface.clone());
                    async move { facts.phys_iface().await }
                },
                move |iface| {
                    PcapRing::start(iface, ring_dir.clone(), ring_mb, &filter)
                        .map(|r| Arc::new(r) as Arc<dyn PcapFreezer>)
                },
            )
            .await;
        })
    });

    // Passive switch-topology discovery: a slow patrol that opens its OWN
    // short-lived LLDP/CDP capture (never the shared incident ring), maps each
    // received frame to an uplink edge, and records it. Gated on the config
    // toggle and on having resolved a physical interface to listen on. Pushed
    // onto `handles` so it is aborted with the collectors on shutdown. The LIVE
    // capture is a project Ceiling (needs root + BPF on a real network); the
    // patrol degrades honestly when it cannot open one (see `lldp_capture`).
    // Gated on the neighbours subsystem being enabled AND the topology
    // toggle: disabling neighbours turns its sub-feature off too, no surprise.
    if cfg.collectors.neighbors.enabled && cfg.collectors.neighbors.topology {
        match phys_iface.clone() {
            Some(iface) => handles.push(spawn_topology_patrol(
                store.clone(),
                snapshot.clone(),
                observing.clone(),
                iface,
            )),
            None => tracing::warn!(
                "topology discovery enabled but no physical interface resolved; not capturing LLDP/CDP"
            ),
        }
    }

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
            probing.clone(),
            freezer.clone(),
            resume_at_us.clone(),
            store.clone(),
            events_tx.clone(),
            oui.clone(),
            api_tx,
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
            abort_pcap(pcap_handle.as_ref());
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
    abort_pcap(pcap_handle.as_ref());
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
///
/// The `Proxy` collector is held behind a `Box` (a concrete pointer, not a
/// `dyn` vtable): its held reference streams carry two long-lived rustls
/// sessions inline, so an unboxed variant would size every element of the
/// `Vec<AnyCollector>` to those buffers. Boxing the one heavy variant leaves
/// the delegating `match` arms unchanged (auto-deref) and the collect future
/// still concrete and `Send`.
pub(crate) enum AnyCollector {
    Link(LinkCollector<IcmpPinger, BoundTcpProber, SystemFacts>),
    Proxy(Box<ProxyCollector<BoundTcpProber, ProxySystemFacts, HeldReferenceStreams>>),
    Dns(DnsCollector<DnsResolver>),
    Route(RouteCollector),
    Host(HostCollector<HostLoad>),
    Wifi(WifiCollector<CoreWlanFacts>),
    Neighbors(NeighborsCollector<SystemNeighbors>),
    Air(AirCollector<SystemProfilerAir>),
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
            Self::Wifi(c) => c.meta(),
            Self::Neighbors(c) => c.meta(),
            Self::Air(c) => c.meta(),
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
            Self::Wifi(c) => c.source(),
            Self::Neighbors(c) => c.source(),
            Self::Air(c) => c.source(),
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
            Self::Wifi(c) => c.preflight().await,
            Self::Neighbors(c) => c.preflight().await,
            Self::Air(c) => c.preflight().await,
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
            Self::Wifi(c) => c.collect(ts_us).await,
            Self::Neighbors(c) => c.collect(ts_us).await,
            Self::Air(c) => c.collect(ts_us).await,
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
            Self::Wifi(c) => c.skip(ts_us),
            Self::Neighbors(c) => c.skip(ts_us),
            Self::Air(c) => c.skip(ts_us),
            #[cfg(test)]
            Self::Fake(c) => c.skip(ts_us),
        }
    }

    /// For event collectors: take out the blocking source the daemon drives on a
    /// dedicated thread. Interval collectors return `None` (the default).
    pub(crate) fn into_event_source(self) -> Option<Box<dyn EventSource>> {
        match self {
            Self::Link(c) => Box::new(c).into_event_source(),
            // Already boxed in the variant (see the enum doc): it IS the
            // `Box<Self>` the trait method takes, so it is not re-boxed.
            Self::Proxy(c) => c.into_event_source(),
            Self::Dns(c) => Box::new(c).into_event_source(),
            Self::Route(c) => Box::new(c).into_event_source(),
            Self::Host(c) => Box::new(c).into_event_source(),
            Self::Wifi(c) => Box::new(c).into_event_source(),
            Self::Neighbors(c) => Box::new(c).into_event_source(),
            Self::Air(c) => Box::new(c).into_event_source(),
            #[cfg(test)]
            Self::Fake(c) => Box::new(c).into_event_source(),
        }
    }
}

/// The production [`NeighborScanner`]: sweep this machine's IPv4 subnet, browse
/// mDNS for names, and report both as one scan.
///
/// Shares the link collector's [`SystemFacts`], so the interface it sweeps and
/// the gateway it keys the results by are the same ones every other collector
/// talks about — including any config override.
pub(crate) struct SystemScanner {
    facts: SystemFacts,
    /// The CVE snapshot directory the `cve` rung matches against, when one is
    /// configured. `None`, or a directory that will not load, means the rung
    /// produces no findings — the honest refusal is decided in `api::scan_now`
    /// before the scan runs; this is the loader for a run that got that far.
    cve_snapshot_dir: Option<std::path::PathBuf>,
    /// The shared OUI registry for ROLE inference, loaded once at startup. `None`
    /// when no snapshot is provisioned: roles degrade to gateway/unknown only.
    oui: Option<Arc<oui_db::OuiDb>>,
}

impl SystemScanner {
    pub(crate) fn new(
        facts: SystemFacts,
        cve_snapshot_dir: Option<std::path::PathBuf>,
        oui: Option<Arc<oui_db::OuiDb>>,
    ) -> Self {
        Self {
            facts,
            cve_snapshot_dir,
            oui,
        }
    }
}

impl NeighborScanner for SystemScanner {
    /// Blocking work (UDP sends, a settle sleep, an mDNS budget — several
    /// seconds) inside an async request handler, so it runs under
    /// `block_in_place`: the worker thread is handed back to the runtime for the
    /// duration instead of stalling every other connection behind one scan.
    ///
    /// **Requires the multi-thread runtime** — `block_in_place` panics on a
    /// current-thread one. The daemon's `#[tokio::main]` is multi-thread, and
    /// every test drives the control path through a fake scanner instead of this
    /// type, so nothing exercises it on a single-threaded runtime today.
    fn scan(&self, opts: &net_observer_ipc::ScanOptions) -> Option<ScanReport> {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            let iface = rt.block_on(self.facts.phys_iface())?;
            let ipv4 = rt.block_on(neighbor_scan::iface_ipv4(&iface))?;
            let network_key = rt.block_on(async {
                match self.facts.default_gw().await {
                    Some(gw) => self.facts.gw_arp_mac(&gw).await,
                    None => None,
                }
            });

            let sweep = neighbor_scan::sweep_probe_blocking(&ipv4, &iface);
            // Read the cache the sweep just filled. Everything it now holds for
            // this interface counts as found: an entry the kernel resolved
            // because of our probe is indistinguishable from one that was
            // already there, and claiming otherwise would be a guess. What is
            // NOT guessed is attribution — a refused sweep leaves these entries
            // marked `arp`, which `compose_scan_report` decides.
            let arp = rt
                .block_on(neighbors::read_arp(Some(&iface)))
                .unwrap_or_default();
            let mdns = neighbor_scan::mdns_names_blocking();

            // The `ports` rung, only when this run asked for it. Targets are the
            // addresses the base scan just found, so a port scan never reaches
            // past the neighbours actually on the segment.
            let ports = if opts.ports {
                let targets: Vec<std::net::IpAddr> =
                    arp.iter().filter_map(|n| n.ip.parse().ok()).collect();
                Some(neighbor_scan::port_scan_blocking(
                    &targets,
                    neighbor_scan::COMMON_PORTS,
                    &iface,
                ))
            } else {
                None
            };

            // The `banners` rung, only when this run asked for it AND the port
            // scan actually ran (a banner grab needs an open port to read from).
            // Grab from exactly the ports the scan found open.
            let banners = match (opts.banners, ports.as_ref()) {
                (true, Some(ps)) => Some(neighbor_scan::banner_grab_blocking(&ps.open, &iface)),
                _ => None,
            };

            let ts_us = types::now_us();
            let mut report = pipeline::compose_scan_report(
                ts_us,
                network_key,
                iface,
                &sweep,
                arp,
                &mdns,
                ports.as_ref(),
                banners.as_ref(),
            );

            // The `cve` rung: match the banners the report already carries
            // against the local snapshot. `api::scan_now` only sets `opts.cve`
            // when banners are effective AND a snapshot directory exists, so a
            // load failure here is an anomaly (a directory that vanished or is
            // corrupt mid-run) — log it and record no findings rather than a
            // guess; the ports and their banners are already recorded.
            if opts.cve {
                // The snapshot is loaded HERE, at scan time, and its outcome is
                // surfaced: an existing-but-empty or wrong-layout directory, or a
                // load error, leaves `vulns` empty AND records a reason, so the
                // operator never reads "no findings" as "no vulnerabilities" when
                // the check never really ran. `api::scan_now` only sets `opts.cve`
                // once a directory is configured, so `None` here is anomalous.
                let cve_note = match &self.cve_snapshot_dir {
                    None => Some("cve rung ran without a snapshot directory".to_string()),
                    Some(dir) => match vuln_db::VulnDb::load_from_dir(dir) {
                        Err(e) => Some(format!(
                            "snapshot at {} failed to load: {e}; findings NOT checked",
                            dir.display()
                        )),
                        Ok(db) if db.is_empty() => Some(format!(
                            "snapshot at {} is empty or wrong layout; findings NOT checked \
                             (not a clean 'no vulnerabilities')",
                            dir.display()
                        )),
                        Ok(db) => {
                            report.vulns = pipeline::match_vulns(&db, &report.ports, ts_us);
                            None
                        }
                    },
                };
                if let Some(reason) = &cve_note {
                    tracing::error!(reason = %reason, "cve rung: snapshot unusable");
                }
                // A durable per-method row, like ports/banners: what the cve rung
                // did, honestly — a count, or the reason it could not check.
                report.scans.push(store::NeighborScan {
                    ts_us,
                    network_key: report.network_key.clone(),
                    iface: report.iface.clone(),
                    method: "cve".to_string(),
                    target: self
                        .cve_snapshot_dir
                        .as_ref()
                        .map(|d| d.display().to_string())
                        .unwrap_or_default(),
                    found: i32::try_from(report.vulns.len()).unwrap_or(i32::MAX),
                    duration_ms: 0,
                    detail: cve_note
                        .clone()
                        .or_else(|| Some(format!("{} findings", report.vulns.len()))),
                });
                report.cve_note = cve_note;
            }

            // ROLE hypothesis, refined with the ports this scan found open. The
            // passive collector sets a gateway/vendor-only role each tick; the
            // open ports here can raise an infra vendor's confidence or name an
            // SNMP-answering host as managed. A port row is already attributed to
            // its owner's MAC by `compose_scan_report`, so group by MAC once.
            let mut ports_by_mac: std::collections::HashMap<String, Vec<u16>> =
                std::collections::HashMap::new();
            for p in &report.ports {
                ports_by_mac.entry(p.mac.clone()).or_default().push(p.port);
            }
            let key = report.network_key.clone();
            collector_neighbors::assign_scan_roles(
                &mut report.found,
                key.as_deref(),
                self.oui.as_deref(),
                |mac| ports_by_mac.get(mac).map_or(&[][..], Vec::as_slice),
            );

            Some(report)
        })
    }
}

/// A test-only interval collector whose readiness the test flips at will, so the
/// per-tick preflight retry in `spawn_interval_collector` can be driven directly.
/// Every real collector in `AnyCollector` is a concrete type wired to real ports
/// (`IcmpPinger`, `SystemFacts`, …), so there is no other way to present the
/// spawner with a prerequisite that is missing and then appears.
/// What this build can collect, as the daemon declares it to its readers.
///
/// One entry per collector compiled into this daemon, in the
/// [`EventKind::as_str`] vocabulary, carrying whether config permits it to run.
/// Absence from this list is the daemon saying "I do not have that collector at
/// all" — which is why every collector is listed here whether or not it is
/// enabled, and why a new collector must be added here as well as to the
/// pipeline. `pcap_ring` is deliberately absent: it is not a collector and
/// produces no event kind.
fn declared_capabilities(c: &config::Collectors) -> Capabilities {
    Capabilities::from_pairs(
        EventKind::ALL
            .iter()
            .filter_map(|k| collector_switch(*k, c).map(|enabled| (k.as_str(), enabled))),
    )
}

/// Which config switch governs the collector behind one event kind, or `None`
/// for a kind no collector produces.
///
/// This match is EXHAUSTIVE over [`EventKind`] on purpose, and it is the only
/// place the answer is written. A new collector brings a new kind (its samples
/// have to reach the readers somehow), and this file then fails to compile until
/// the new kind is classified — so a collector wired into the pipeline can no
/// longer be forgotten in the declaration and announced to the bar as absent.
fn collector_switch(kind: EventKind, c: &config::Collectors) -> Option<bool> {
    Some(match kind {
        EventKind::Link => c.link.enabled,
        EventKind::Proxy => c.proxy.enabled,
        EventKind::Dns => c.dns.enabled,
        EventKind::Route => c.route.enabled,
        EventKind::Host => c.host.enabled,
        EventKind::Wifi => c.wifi.enabled,
        EventKind::Air => c.air.enabled,
        EventKind::Neighbors => c.neighbors.enabled,
        // Not a collector: incidents are what the triggers write about the
        // collectors' samples. `pcap_ring` is absent for the same reason from the
        // other side — it produces no event kind at all.
        EventKind::Incident => return None,
    })
}

#[cfg(test)]
pub(crate) struct FakeCollector {
    pub(crate) meta: &'static CollectorMeta,
    pub(crate) interval: std::time::Duration,
    /// Flipped by the test to make preflight succeed.
    pub(crate) ready: Arc<std::sync::atomic::AtomicBool>,
    /// Ticks on which `collect()` actually ran — counted on ENTRY, before the
    /// gate below, so a test can see a tick being held open.
    pub(crate) collects: Arc<std::sync::atomic::AtomicUsize>,
    /// When `Some`, `collect()` parks here until the test adds a permit: a
    /// tick held open in flight, so a pause or a probing-tier switch can land
    /// while the probe is "running" and the spawner's post-probe re-checks can
    /// be reached. `None` = collect at once.
    pub(crate) gate: Option<Arc<tokio::sync::Semaphore>>,
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
        if let Some(gate) = &self.gate {
            // One permit per released tick: the test decides when this probe
            // "returns", and the next tick parks again.
            gate.acquire()
                .await
                .expect("the test gate is never closed")
                .forget();
        }
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
            bssid: None,
            if_mac: None,
            medium: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
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
            bssid: None,
            if_mac: None,
            medium: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
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

/// Stop the pcap supervisor, if one is running. Named so the two shutdown paths
/// cannot drift apart.
fn abort_pcap(handle: Option<&JoinHandle<()>>) {
    if let Some(h) = handle {
        h.abort();
    }
}

/// Abort every collector task, dropping their stream senders.
fn abort_all(handles: &[JoinHandle<()>]) {
    for h in handles {
        h.abort();
    }
}

/// Start the pcap ring on the physical interface, returning the slot the rest of
/// the daemon reads through plus the reason it is empty, if it is.
///
/// A `None` reason means a ring is running. Any other case (disabled, no
/// interface, `tcpdump` refused to spawn) leaves the slot empty; only the
/// disabled case is terminal, and [`supervise_pcap_ring`] handles the rest.
fn maybe_start_pcap_ring(
    cfg: &Config,
    phys_iface: Option<&str>,
) -> (Arc<PcapRingSlot>, Option<String>) {
    let Some(iface) = phys_iface else {
        return (
            Arc::new(PcapRingSlot::empty()),
            Some("no physical interface resolved".to_string()),
        );
    };
    let ring_dir = Path::new(&cfg.blob_dir).join("ring");
    match PcapRing::start(
        iface,
        ring_dir,
        cfg.collectors.pcap_ring.ring_mb,
        &cfg.collectors.pcap_ring.filter,
    ) {
        Ok(ring) => (
            Arc::new(PcapRingSlot::with_ring(
                Arc::new(ring) as Arc<dyn PcapFreezer>
            )),
            None,
        ),
        Err(e) => (
            Arc::new(PcapRingSlot::empty()),
            Some(format!("tcpdump could not be spawned: {e}")),
        ),
    }
}

/// Keep `slot` holding a live pcap ring, for as long as this task runs.
///
/// The ring is the only artifact that shows packets leaving and nothing coming
/// back, and a `RunAtLoad` daemon boots exactly when there may be no interface
/// to capture on. So the ring is supervised rather than attempted once: every
/// `interval` this checks the slot and, if it is empty or its `tcpdump` child
/// has exited, re-resolves the interface and starts a new ring into the same
/// slot — which every reader (`FreezePcap`, the gw-change handler) consults at
/// use time, so recovery needs no restart and no re-wiring.
///
/// A dead ring is REPLACED, not merely reported: a handle to a corpse would let
/// `FreezePcap` answer `ok` while copying a frozen ring directory.
///
/// Logging is by *change of reason*, never per attempt: the first failure and
/// each subsequent different reason are logged, and so is every recovery. A
/// daemon that cannot capture must not drown the log it shares with the evidence.
async fn supervise_pcap_ring<R, Fut, S>(
    slot: Arc<PcapRingSlot>,
    interval: Duration,
    initial_reason: Option<String>,
    resolve_iface: R,
    start_ring: S,
) where
    R: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
    S: Fn(&str) -> std::io::Result<Arc<dyn PcapFreezer>>,
{
    if let Some(reason) = &initial_reason {
        tracing::warn!(%reason, retry_s = interval.as_secs(), "pcap ring not running; will retry");
    }
    let mut last_reason = initial_reason;
    loop {
        tokio::time::sleep(interval).await;

        if slot.is_alive() {
            continue;
        }
        // Empty, or holding a ring whose child exited. Clearing the slot first
        // drops that handle (killing and reaping the child) so the replacement
        // never races a corpse.
        if slot.set(None).is_some() {
            tracing::warn!("pcap ring child exited; restarting it");
            last_reason = None;
        }

        let reason = match resolve_iface().await {
            None => Some("no physical interface resolved".to_string()),
            Some(iface) => match start_ring(&iface) {
                Ok(ring) => {
                    slot.set(Some(ring));
                    tracing::info!(iface, "pcap ring started");
                    None
                }
                Err(e) => Some(format!("tcpdump could not be spawned: {e}")),
            },
        };
        if reason != last_reason {
            if let Some(reason) = &reason {
                tracing::warn!(%reason, "pcap ring still not running");
            }
            last_reason = reason;
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
    probing: Arc<ProbingState>,
    freezer: Arc<PcapRingSlot>,
    resume_at_us: Arc<AtomicI64>,
    store: Arc<DuckdbStore>,
    events_tx: tokio::sync::broadcast::Sender<EncodedFrame>,
    oui: Option<Arc<oui_db::OuiDb>>,
    // The SAME sample stream the collectors feed, so an operator-pressed air scan
    // is persisted, published and shown to the triggers by exactly one code path.
    samples_tx: mpsc::Sender<Sample>,
) -> api::ApiServer {
    let socket_path = cfg.socket_path.clone();
    let socket_mode = cfg.socket_mode;
    let socket_owner_uid = cfg.socket_owner_uid;
    // Parameters of the manual actions, not a gate: config never stands between
    // an authorised operator's command and its execution (realm net-observer,
    // node #91).
    let acting = api::ActingConfig {
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
        // Who may send a `Request::Control` at all — the one gate on the
        // control path.
        policy: api::ControlPolicy::from_config(cfg.socket_owner_uid, cfg.control_uids.clone()),
        observing: observing.clone(),
        // Shared, never fresh — for `probing` the same reason as `observing`,
        // and the ring handle so `FreezePcap` copies the ring that is actually
        // running rather than refusing next to a live capture.
        probing,
        freezer,
        // Built unconditionally: whether there is anything to scan is decided
        // per request (an interface with an IPv4 subnet), not once at boot.
        scanner: Some(Arc::new(SystemScanner::new(
            SystemFacts::new(
                cfg.collectors.link.gw.clone(),
                cfg.collectors.link.phys_iface.clone(),
            ),
            cfg.collectors
                .neighbors
                .cve_snapshot_dir
                .as_ref()
                .map(std::path::PathBuf::from),
            oui.clone(),
        )) as Arc<dyn NeighborScanner>),
        // Built unconditionally, exactly like the neighbour scanner: whether the
        // radio can be read is decided per request (and answered as a `Skip`
        // sample with its reason), not once at boot. It is NOT tied to
        // `collectors.air.enabled` — that switch governs the slow PERIOD, and an
        // operator asking for one slice is a different act from standing
        // collection.
        air_scanner: Some(Arc::new(OnDemandAirScan::new(
            Arc::new(SystemProfilerAir::new()),
            samples_tx,
            // The SAME flag the control socket flips and the interval collectors
            // read: a pause landing mid-scan must reach the in-flight read.
            observing.clone(),
        )) as Arc<dyn AirScanner>),
        // Where the `cve` rung loads its snapshot; the availability check in
        // `scan_now` decides whether the rung is effective this run.
        scan_cve_snapshot: cfg
            .collectors
            .neighbors
            .cve_snapshot_dir
            .as_ref()
            .map(std::path::PathBuf::from),
        blob_dir: std::path::PathBuf::from(&cfg.blob_dir),
        resume_at_us,
        snapshot,
        // The durable sink for `observing_edge` boundary rows: the daemon
        // stays the sole DuckDB owner, so the control path writes through the
        // same handle the pipeline does.
        store: store as Arc<dyn store::Store + Send + Sync>,
        // One diagnosis at a time: a `Query` holds the store mutex the pipeline
        // writes through, and the socket is world-connectable.
        query_gate: Arc::new(tokio::sync::Semaphore::new(api::MAX_QUERIES_IN_FLIGHT)),
        events_tx,
    }
}

/// Assemble the [`TriggerEngine`]'s rule set (wedge, gw-drop, gw-change,
/// roam, wifi-churn, gw-mac-change, neighbor-mac-collision, per-client-block,
/// ban-cycle, fakeip, fakeip-hijack, endpoint-block, established-stall,
/// starvation). Every rule records an incident (durable, in DuckDB) and
/// mirrors it into the live snapshot's ring for the socket API; gw-change and
/// gw-mac-change additionally freeze the pcap ring when one is available.
fn build_engine(
    store: Arc<DuckdbStore>,
    cfg: &Config,
    freezer: Arc<PcapRingSlot>,
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

    // Wired unconditionally, because the ring can start LATE: the handler holds
    // the slot, so a gw-change after a recovery freezes the ring that is running
    // then. With an empty slot it copies nothing and says so.
    let freeze: Arc<dyn Handler> = Arc::new(FreezePcapHandler::new(
        freezer as Arc<dyn PcapFreezer>,
        store.clone(),
        cfg.blob_dir.clone(),
    ));
    let gw_change_handlers: Vec<Arc<dyn Handler>> =
        vec![record.clone(), snap.clone(), freeze.clone()];

    // Fault conditions ride inside `Gated`: the first live-trial days showed
    // every one of them firing on invalid measurement context (no uplink,
    // host starvation, the settle window after a network move) — the gates
    // are the shell watchdog's field-proven guards, applied per signature
    // according to what its semantics allow. `per-client-block` measures a
    // DEAD gateway, so it cannot require a live direct path; the rest can.
    let triggers = vec![
        Trigger::new(
            Box::new(Gated {
                inner: Wedge {
                    consecutive: WEDGE_CONSECUTIVE,
                },
                // Wedge's own eval already requires the direct path.
                require_direct: false,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
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
        // A roam — a BSSID hop, or a new link address on Wi-Fi — is its own
        // incident, not the `gw-drop`/`per-client-block` it used to
        // masquerade as. Not gated: the settle window would suppress exactly
        // this event. No pcap freeze: the evidence is the two identities in
        // the record. NO backoff: the field cadence is a hop every 2.5–3 min
        // and each hop at that cadence is its own incident — under
        // `BACKOFF_US` most would be silently dropped. Hops on consecutive
        // ticks merge into one under the engine's latch; the rows still
        // record both. `wifi-churn` below carries the aggregate's rate
        // limit. (realm net-observer, node #59)
        Trigger::new(Box::new(Roam), vec![record.clone(), snap.clone()], 0),
        // Four or more identity changes in a quarter hour are one churn
        // incident, not a string of roams. A change signature, so not gated;
        // no pcap freeze, the evidence is the recorded identities; and
        // `BACKOFF_US` (5 min) is the rate limit the field asked for.
        // (realm net-observer, node #109)
        Trigger::new(
            Box::new(WifiChurn),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // The same gateway address answered by a new MAC freezes the ring like
        // any other gateway change: the frames around the swap are the evidence
        // that separates an ARP spoof from a silent move to another network.
        Trigger::new(
            Box::new(GwMacChange),
            vec![record.clone(), snap.clone(), freeze],
            BACKOFF_US,
        ),
        // An address collision is provable from the neighbors table alone, so
        // it records and snapshots but does not spend a ring freeze.
        Trigger::new(
            Box::new(NeighborMacCollision),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // No pcap freeze: the evidence is the recorded counts, and the echoes
        // the gateway never answered are packets that never arrived.
        Trigger::new(
            Box::new(Gated {
                inner: PerClientBlock,
                require_direct: false,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
            }),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // No pcap freeze: the evidence is the recorded verdict sequence
        // itself. No direct-path gate either — the pattern is measured
        // THROUGH the dead gateways, so requiring a live uplink would
        // suppress exactly what it looks for.
        Trigger::new(
            Box::new(Gated {
                inner: BanCycle {
                    min_bans: BAN_CYCLE_MIN_BANS,
                },
                require_direct: false,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
            }),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        Trigger::new(
            Box::new(FakeIp),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // No pcap freeze: the evidence is the recorded egress interface —
        // provable from the route table alone.
        Trigger::new(
            Box::new(FakeIpHijack),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // No pcap freeze: the evidence is the stored per-endpoint verdicts —
        // packets of connections that never opened add nothing.
        Trigger::new(
            Box::new(Gated {
                inner: EndpointBlock {
                    consecutive: ENDPOINT_BLOCK_CONSECUTIVE,
                },
                require_direct: true,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
            }),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // No pcap freeze: the evidence is the recorded held-stream reading —
        // the scoping verdict is already in the detail string.
        Trigger::new(
            Box::new(Gated {
                inner: EstablishedStall,
                require_direct: true,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
            }),
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

    /// The declaration covers EXACTLY the collectors this daemon can spawn.
    ///
    /// Both directions are failures the operator would act on: a collector wired
    /// into the pipeline and missing here is announced as `Absent`, and the bar
    /// hides its window for a collector that is merely switched off; a name here
    /// with no collector behind it promises a switch that turns nothing on.
    ///
    /// The set is taken from the collector crates' own `META.name` — the same
    /// constants `AnyCollector`'s arms carry — so the assertion is anchored to
    /// the wiring rather than to a second hand-written list. The compile-time
    /// half of the guard is `collector_switch`, whose match over `EventKind` is
    /// exhaustive.
    #[test]
    fn the_declaration_covers_exactly_the_collectors_the_daemon_can_spawn() {
        use net_observer_ipc::EventKind;

        // One entry per `AnyCollector` variant, by the collector's own metadata.
        let spawnable: Vec<&'static str> = vec![
            collector_link::META.name,
            collector_proxy::META.name,
            collector_dns::META.name,
            collector_route::META.name,
            collector_host::META.name,
            collector_wifi::META.name,
            collector_neighbors::META.name,
            collector_air::META.name,
        ];

        let cfg = config::Config::default();
        let declared: Vec<String> = declared_capabilities(&cfg.collectors)
            .collectors
            .iter()
            .map(|c| c.kind.clone())
            .collect();

        for name in &spawnable {
            assert!(
                declared.iter().any(|d| d == name),
                "collector `{name}` can be spawned but is not declared; readers would call it Absent. declared: {declared:?}"
            );
        }
        for d in &declared {
            assert!(
                spawnable.contains(&d.as_str()),
                "`{d}` is declared but no collector produces it; the switch would turn nothing on"
            );
        }
        assert_eq!(declared.len(), spawnable.len(), "declared: {declared:?}");

        // Every declared name is a real kind label, so the bar's per-kind lookup
        // can never miss on a typo.
        for d in &declared {
            assert!(
                EventKind::ALL.iter().any(|k| k.as_str() == d),
                "`{d}` is not an EventKind label"
            );
        }
    }

    /// The daemon must declare every collector it HAS, not only the ones running
    /// — otherwise a reader cannot tell "this build has no air collector" from
    /// "the air collector is switched off", and the operator loses the switch.
    /// `air` is off in the defaults, which makes this the live case.
    #[test]
    fn the_declaration_names_collectors_it_has_but_does_not_run() {
        use net_observer_ipc::CollectorAvailability;

        let cfg = config::Config::default();
        assert!(
            !cfg.collectors.air.enabled,
            "the fixture assumes air is off"
        );

        let snap = StatusSnapshot {
            capabilities: Some(declared_capabilities(&cfg.collectors)),
            ..StatusSnapshot::default()
        };
        // Present in the build, switched off by config.
        assert_eq!(
            snap.collector(EventKind::Air),
            CollectorAvailability::Disabled
        );
        // And a collector the defaults do run.
        assert_eq!(
            snap.collector(EventKind::Link),
            CollectorAvailability::Enabled
        );
        // Not a collector, and deliberately never declared as one.
        assert_eq!(
            snap.collector(EventKind::Incident),
            CollectorAvailability::Absent
        );
    }
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

    /// A fake ring whose liveness can be flipped, standing in for a `tcpdump`
    /// child that exits under the daemon.
    struct MortalRing(Arc<AtomicBool>);
    impl PcapFreezer for MortalRing {
        fn freeze(&self, dest_dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            vec![dest_dir.join("ring.pcap0")]
        }
        fn is_alive(&self) -> bool {
            self.0.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    /// Poll `cond` on a short cadence until it holds, or fail the test. Real
    /// (short) time rather than tokio's paused clock, because `tokio/test-util`
    /// is not a dependency of this binary and this branch is not the place to
    /// add one.
    async fn wait_until(label: &str, cond: impl Fn() -> bool) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {label}");
    }

    /// The supervisor's patrol interval under test — short enough to keep the
    /// test in milliseconds, long enough that a patrol is still a patrol.
    const TEST_PATROL: Duration = Duration::from_millis(10);

    /// The defect this branch closes: no interface at boot must not disable the
    /// ring for the life of the process. The supervisor is driven with fakes (no
    /// `tcpdump`, no root): the interface is absent for the first attempts and
    /// present afterwards, and the ring must appear in the slot on its own.
    ///
    /// Dies under: returning early instead of looping, or writing the ring
    /// anywhere but the shared slot.
    #[tokio::test]
    async fn the_ring_starts_by_itself_once_an_interface_appears() {
        let slot = Arc::new(PcapRingSlot::empty());
        let iface_up = Arc::new(AtomicBool::new(false));
        let starts = Arc::new(AtomicI64::new(0));

        let task = {
            let (slot, iface_up, starts) = (slot.clone(), iface_up.clone(), starts.clone());
            tokio::spawn(async move {
                supervise_pcap_ring(
                    slot,
                    TEST_PATROL,
                    Some("no physical interface resolved".to_string()),
                    move || {
                        let up = iface_up.load(std::sync::atomic::Ordering::Acquire);
                        async move { up.then(|| "en0".to_string()) }
                    },
                    move |_iface| {
                        starts.fetch_add(1, std::sync::atomic::Ordering::Release);
                        Ok(Arc::new(FakeFreezer) as Arc<dyn PcapFreezer>)
                    },
                )
                .await;
            })
        };

        // Several patrols with no interface: still empty, and nothing spawned.
        tokio::time::sleep(TEST_PATROL * 5).await;
        assert!(slot.get().is_none(), "no interface: the slot stays empty");
        assert_eq!(
            starts.load(std::sync::atomic::Ordering::Acquire),
            0,
            "the supervisor must not spawn a capture with no interface to bind"
        );

        iface_up.store(true, std::sync::atomic::Ordering::Release);
        wait_until("the ring to start on its own", || slot.get().is_some()).await;

        // And a healthy ring is left alone: no churn of tcpdump children.
        tokio::time::sleep(TEST_PATROL * 5).await;
        assert_eq!(
            starts.load(std::sync::atomic::Ordering::Acquire),
            1,
            "a live ring must not be restarted every patrol"
        );
        task.abort();
    }

    /// A ring whose child exited must not be left in the slot as a live-looking
    /// handle: the supervisor notices and replaces it.
    ///
    /// Dies under: checking only `slot.get().is_some()` instead of liveness.
    #[tokio::test]
    async fn a_dead_ring_is_replaced_rather_than_kept() {
        let alive = Arc::new(AtomicBool::new(true));
        let dead_ring = Arc::new(MortalRing(alive.clone())) as Arc<dyn PcapFreezer>;
        let slot = Arc::new(PcapRingSlot::with_ring(dead_ring.clone()));

        let task = {
            let slot = slot.clone();
            tokio::spawn(async move {
                supervise_pcap_ring(
                    slot,
                    TEST_PATROL,
                    None,
                    || async { Some("en0".to_string()) },
                    |_iface| Ok(Arc::new(FakeFreezer) as Arc<dyn PcapFreezer>),
                )
                .await;
            })
        };

        // While it is alive it is left alone.
        tokio::time::sleep(TEST_PATROL * 5).await;
        assert!(
            slot.get().is_some_and(|r| Arc::ptr_eq(&r, &dead_ring)),
            "a live ring must not be swapped out"
        );

        alive.store(false, std::sync::atomic::Ordering::Release);
        wait_until("the corpse to be replaced", || {
            slot.get().is_some_and(|r| !Arc::ptr_eq(&r, &dead_ring))
        })
        .await;
        assert!(
            slot.get().expect("a ring is installed").is_alive(),
            "the replacement must be a live ring"
        );
        task.abort();
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
            bssid: None,
            if_mac: None,
            medium: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    /// A gateway-FAIL link tick carrying probe-on-suspicion counts — the
    /// per-client-block shape ([`link`] pins both counts to `None`).
    fn link_gw_fail_with_lan(ts_us: i64, probed: u16, alive: u16) -> Sample {
        let Sample::Link(mut l) = link(ts_us, GwVerdict::Fail) else {
            unreachable!("link() builds a link sample")
        };
        l.lan_probed = Some(probed);
        l.lan_alive = Some(alive);
        Sample::Link(l)
    }

    /// A healthy link tick whose fakeip-pool probe resolved to `route_if` while
    /// sing-box's own TUN is up (on utun6) — the fakeip-hijack shape ([`link`]
    /// pins both interface fields to `None`).
    fn link_fakeip_via(ts_us: i64, route_if: &str) -> Sample {
        let Sample::Link(mut l) = link(ts_us, GwVerdict::Ok) else {
            unreachable!("link() builds a link sample")
        };
        l.fakeip_route_if = Some(route_if.into());
        l.singbox_tun_if = Some("utun6".into());
        Sample::Link(l)
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
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
        })
    }

    /// A per-endpoint proxy row whose underlay TCP probe FAILED while the tun
    /// is healthy — the endpoint-block shape ([`dead_proxy`] is the opposite:
    /// tcp OK, tun dead).
    fn failed_endpoint(ts_us: i64, endpoint: &str) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us,
            server_ip: endpoint.into(),
            tcp: TcpVerdict::Fail,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
        })
    }

    /// A healthy proxy tick carrying held-stream readings — the
    /// established-stall shape: fresh paths fine, the tunnel stream's fate in
    /// `tun_alive` ([`dead_proxy`]/[`failed_endpoint`] pin the est fields to
    /// `None`).
    fn proxy_with_streams(ts_us: i64, tun_alive: bool) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "1.1.1.1:443".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
            est_direct_alive: Some(true),
            est_direct_age_s: Some(120),
            est_tun_alive: Some(tun_alive),
            est_tun_age_s: Some(45),
        })
    }

    fn host(ts_us: i64, load1: f64) -> Sample {
        Sample::Host(HostSample {
            ts_us,
            load1,
            load5: load1,
            load15: load1,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
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
        let probing = Arc::new(ProbingState::new(ProbingTier::Passive));
        let resume_at_us = Arc::new(AtomicI64::new(0));
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        // A broadcast channel needs no runtime, so this whole test is a plain
        // `#[test]`.
        let (events_tx, _events_rx) = tokio::sync::broadcast::channel::<EncodedFrame>(4);
        let (samples_tx, _samples_rx) = mpsc::channel::<Sample>(4);

        let srv = build_api_server(
            &cfg,
            snapshot.clone(),
            observing.clone(),
            probing.clone(),
            // No pcap ring in this test: `FreezePcap` must refuse rather than
            // panic, which is the empty slot's whole job.
            Arc::new(PcapRingSlot::empty()),
            resume_at_us.clone(),
            store.clone(),
            events_tx.clone(),
            None,
            samples_tx.clone(),
        );

        // An operator-pressed air scan must exist and must feed the SAME sample
        // stream the collectors do: a scanner wired onto a private channel would
        // read the radio and drop the slice on the floor.
        assert!(
            srv.air_scanner.is_some(),
            "the air scan button must have something to call"
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
            Arc::ptr_eq(&srv.probing, &probing),
            "a fresh `probing` leaves the control socket acking a tier no \
             collector reads, so \"Probe network\" would light up while every \
             probe stays withheld — or the reverse"
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

    /// Startup writes the configured tier as a boundary too: one durable
    /// `probing_edge` row (`tier` as configured, no peer) AND the same value on
    /// the realtime bus — so a record that begins passive says so, before the
    /// first withheld probe lands as `SKIP`.
    #[test]
    fn startup_records_a_probing_edge_through_both_sinks() {
        let store = DuckdbStore::in_memory().unwrap();
        let (events_tx, mut events_rx) = tokio::sync::broadcast::channel::<EncodedFrame>(8);

        let edge = record_startup_probing_edge(&store, &events_tx, 4_243, ProbingTier::Passive);

        assert_eq!(edge.ts_us, 4_243);
        assert_eq!(edge.tier, ProbingTier::Passive);
        assert_eq!(edge.peer_uid, None, "nobody asked; the process booted");

        // Sink 1, durable.
        assert_eq!(
            store
                .query_scalar_i64(
                    "SELECT count(*) FROM probing_edge \
                     WHERE ts_us = 4243 AND tier = 'passive' AND peer_uid IS NULL"
                )
                .unwrap(),
            1,
            "the startup tier must be durable, or a passive start is an inference"
        );

        // Sink 2, realtime: the same value, decoded off the bus.
        let frame = events_rx.try_recv().expect("a frame must reach the bus");
        let decoded: net_observer_ipc::StreamFrame = serde_json::from_slice(frame.bytes())
            .expect("bus payload must decode as a StreamFrame");
        match decoded {
            net_observer_ipc::StreamFrame::Probing(back) => assert_eq!(back, edge),
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

    /// Build the real [`build_engine`] — the full production rule set and
    /// constants — with `freezer`.
    fn engine_under_test(freezer: Arc<PcapRingSlot>) -> EngineFixture {
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
    /// ALWAYS filtered: [`build_engine`] installs the whole rule set at once, so
    /// an unfiltered `count(*)` would let another rule's firing stand in for the
    /// one under test.
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
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
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
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
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
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
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

    /// The `endpoint-block` rule the daemon actually runs counts to
    /// [`ENDPOINT_BLOCK_CONSECUTIVE`] — two — all-fail cohorts, no fewer.
    ///
    /// The newest cohort is never judged (it ends the one before it), so the
    /// fire lands on the first row of the cohort after the run. Dies under
    /// `ENDPOINT_BLOCK_CONSECUTIVE = 1` (the single ended cohort fires, so the
    /// second assertion reds) and under `= 3` (the two-cohort run stays
    /// silent, so the third reds). The cohort counts are LITERALS on
    /// purpose — this test IS the constant's pin, exactly like the wedge pin
    /// above.
    ///
    /// Nothing else in the rule set can fire on this stream: the tun is
    /// healthy (no wedge/starvation), the gateway verdict is steadily OK with
    /// no predecessor to differ from (no gw-drop/gw-change), and there is no
    /// DNS or neighbors sample.
    #[test]
    fn build_engine_wires_the_production_endpoint_block_threshold() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, link(1, GwVerdict::Ok));
        // One all-fail cohort — one short of the production threshold of two.
        feed(&mut fx.engine, &mut w, failed_endpoint(2, "1.1.1.1:443"));
        feed(&mut fx.engine, &mut w, failed_endpoint(2, "2.2.2.2:2053"));
        assert_eq!(
            incidents_for(&fx.store, "endpoint-block"),
            0,
            "one all-fail cohort is one short of ENDPOINT_BLOCK_CONSECUTIVE and must not fire"
        );

        // The second cohort is the run — once a newer cohort has ended it.
        feed(&mut fx.engine, &mut w, failed_endpoint(3, "1.1.1.1:443"));
        feed(&mut fx.engine, &mut w, failed_endpoint(3, "2.2.2.2:2053"));
        assert_eq!(
            incidents_for(&fx.store, "endpoint-block"),
            0,
            "the newest cohort is still being written and is not judged yet"
        );
        feed(&mut fx.engine, &mut w, failed_endpoint(4, "1.1.1.1:443"));
        assert_eq!(
            incidents_for(&fx.store, "endpoint-block"),
            1,
            "the first row of a third cohort ends the second and fires the endpoint-block rule"
        );
    }

    /// The `per-client-block` rule is installed with the production handlers:
    /// a gateway-FAIL tick with live probed neighbors records the incident, and
    /// the same tick without counts (the tick did not probe) records nothing
    /// under that id. `gw-drop` fires on both streams and is filtered out by
    /// `incidents_for`, which is exactly why the filter exists.
    #[test]
    fn build_engine_registers_the_per_client_block_rule() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, link(1, GwVerdict::Fail));
        assert_eq!(
            incidents_for(&fx.store, "per-client-block"),
            0,
            "a tick that did not probe carries no measurement and must not fire"
        );

        feed(&mut fx.engine, &mut w, link_gw_fail_with_lan(2, 3, 2));
        assert_eq!(
            incidents_for(&fx.store, "per-client-block"),
            1,
            "a silent gateway with live neighbors must be recorded as per-client-block"
        );
    }

    /// The `ban-cycle` rule the daemon actually runs counts to
    /// [`BAN_CYCLE_MIN_BANS`] — three — gateway bans, no fewer. `gw-drop` and
    /// `gw-change` fire on the same stream and are filtered out by
    /// `incidents_for`. Dies under `BAN_CYCLE_MIN_BANS = 2` (the two-ban
    /// stream fires, so the first assertion reds) and under a condition that
    /// is written but never registered (the second never goes green).
    #[test]
    fn build_engine_registers_the_ban_cycle_rule() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(64);
        // One ban round at the 15 s link cadence: admitted for two ticks,
        // blocked for three, admitted for five.
        let round = [
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Fail,
            GwVerdict::Fail,
            GwVerdict::Fail,
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Ok,
        ];
        for (tick, gw) in round.iter().chain(&round).copied().enumerate() {
            feed(&mut fx.engine, &mut w, link(tick as i64 * 15_000_000, gw));
        }
        assert_eq!(
            incidents_for(&fx.store, "ban-cycle"),
            0,
            "two bans are one short of BAN_CYCLE_MIN_BANS and must not fire"
        );

        for (tick, gw) in round.iter().copied().enumerate() {
            feed(
                &mut fx.engine,
                &mut w,
                link((20 + tick as i64) * 15_000_000, gw),
            );
        }
        assert_eq!(
            incidents_for(&fx.store, "ban-cycle"),
            1,
            "the third ban must be recorded as ban-cycle, once"
        );
    }

    /// The `fakeip-hijack` rule is installed with the production handlers: a
    /// tick whose pool routes into the tunnel records nothing, one routing via
    /// a real interface records the incident. Nothing else in the rule set
    /// can fire on this stream: the gateway is steadily OK with no
    /// predecessor to differ from, and there is no proxy, DNS, host or
    /// neighbors sample.
    #[test]
    fn build_engine_registers_the_fakeip_hijack_rule() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, link_fakeip_via(1, "utun8"));
        assert_eq!(
            incidents_for(&fx.store, "fakeip-hijack"),
            0,
            "the pool routing into the tunnel is the healthy state"
        );

        feed(&mut fx.engine, &mut w, link_fakeip_via(2, "awdl0"));
        assert_eq!(
            incidents_for(&fx.store, "fakeip-hijack"),
            1,
            "the pool routing via a real interface must be recorded as fakeip-hijack"
        );
    }

    /// The `established-stall` rule is installed with the production handlers:
    /// a tick whose held tunnel stream still carries records nothing, one
    /// whose stream died (fresh probes fine) records the incident. The rule
    /// rides inside `Gated { require_direct: true, .. }`, so the stream leads
    /// with a healthy link sample — a destination-fault verdict without a
    /// measured live uplink is exactly the no-uplink false positive the gate
    /// exists to stop. Nothing else in the rule set can fire on this stream:
    /// the gateway is steadily OK with no predecessor to differ from, the tun
    /// code is healthy (no wedge/starvation), the underlay TCP is Ok (no
    /// endpoint-block), and there is no DNS or neighbors sample.
    #[test]
    fn build_engine_registers_the_established_stall_rule() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, link(0, GwVerdict::Ok));
        feed(&mut fx.engine, &mut w, proxy_with_streams(1, true));
        assert_eq!(
            incidents_for(&fx.store, "established-stall"),
            0,
            "a carrying tunnel stream is the healthy state"
        );

        feed(&mut fx.engine, &mut w, proxy_with_streams(2, false));
        assert_eq!(
            incidents_for(&fx.store, "established-stall"),
            1,
            "a stalled tunnel stream with fresh probes OK must be recorded as established-stall"
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
        let freezer = Arc::new(PcapRingSlot::with_ring(
            Arc::new(FakeFreezer) as Arc<dyn PcapFreezer>
        ));
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
        let mut bare = engine_under_test(Arc::new(PcapRingSlot::empty()));
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

    /// The OTHER consumer of the ring slot — the automatic path. The engine is
    /// built while the slot is EMPTY (a boot with no interface), so its first
    /// gateway change records the incident and freezes nothing; a ring then
    /// lands in the same slot (the supervisor's write) and the next gateway
    /// change freezes it. The two consumers must not drift: a recovered ring
    /// that only the socket can see would silently lose every automatic freeze.
    ///
    /// Dies under: giving `build_engine` a snapshot of the slot's contents
    /// instead of the slot, or reinstating the `if let Some(freezer)` that left
    /// the freeze handler unwired for the life of the process.
    #[test]
    fn a_ring_that_starts_late_is_frozen_by_the_gw_change_trigger_too() {
        let slot = Arc::new(PcapRingSlot::empty());
        let mut fx = engine_under_test(slot.clone());
        let mut w = RecentWindow::new(8);

        feed(&mut fx.engine, &mut w, link(1, GwVerdict::Ok));
        feed(&mut fx.engine, &mut w, link(2, GwVerdict::Fail));
        assert_eq!(
            incidents_for(&fx.store, "gw-change"),
            1,
            "the incident is recorded with or without a ring"
        );
        assert_eq!(
            fx.store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap(),
            0,
            "with an empty slot there is nothing to freeze"
        );

        // The supervisor's recovery, into the slot the engine already holds.
        slot.set(Some(Arc::new(FakeFreezer) as Arc<dyn PcapFreezer>));

        // A steady tick re-arms the latch (no change, so no fire), then a second
        // gateway change past the backoff fires the rule again.
        feed(&mut fx.engine, &mut w, link(3, GwVerdict::Fail));
        feed(&mut fx.engine, &mut w, link(3 + BACKOFF_US, GwVerdict::Ok));
        assert!(
            fx.store
                .query_scalar_i64("SELECT count(*) FROM blob_ref WHERE kind='pcap'")
                .unwrap()
                > 0,
            "after recovery the AUTOMATIC freeze must reach the ring that is now running"
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
