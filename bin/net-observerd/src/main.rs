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

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use collector_air::AirCollector;
use collector_announce::{AnnounceCollector, AnnounceSource};
use collector_connections::ConnectionsCollector;
use collector_core::{Collector, CollectorMeta, EventSource, Os, ProbingState, Readiness, Source};
use collector_dns::DnsCollector;
use collector_host::HostCollector;
use collector_link::{LinkCollector, LinkFacts};
use collector_neighbors::NeighborsCollector;
use collector_proxy::ProxyCollector;
use collector_route::RouteCollector;
use collector_singbox_log::SingboxLogCollector;
use collector_wifi::WifiCollector;
use config::Config;
use macos::LldpCapture;
use macos::{
    AnnounceCapture, BoundTcpProber, ConnectionSystemFacts, CoreWlanFacts, DnsResolver,
    EgressCapture, EgressCaptureOutcome, FreezeAccess, HeldReferenceStreams, HostLoad, IcmpPinger,
    PcapRing, PfRouteSource, ProxySystemFacts, SystemFacts, SystemNeighbors, SystemProfilerAir,
    SystemSegment, TcpdumpEgressCapture, TcpdumpLldpCapture,
};
use macos::{neighbor_scan, neighbors};
use net_observer_ipc::{Capabilities, EncodedFrame, EventKind, StatusSnapshot};
use store::DuckdbStore;
use triggers::conditions::{
    BanCycle, EndpointBlock, EndpointDialStall, EstablishedStall, FakeIp, FakeIpHijack, Gated,
    GwChange, GwDrop, GwMacChange, NeighborMacCollision, PerClientBlock, Roam, SingboxDialTimeout,
    SingboxNoRoute, Starvation, Wedge, WifiChurn,
};
use triggers::engine::{Trigger, TriggerEngine};
use triggers::handlers::{Handler, RecordHandler};
use types::{ProbingEdge, ProbingTier, Sample};

use pipeline::{
    AirScanner, CveLookupOutcome, EgressScanOutcome, EgressScanner, FreezePcapHandler,
    NeighborScanner, OnDemandAirScan, PcapFreezer, PcapRingSlot, ScanReport, SnapshotHandler,
    TopologyScanner, run, spawn_event_collector, spawn_interval_collector,
};

/// How often a capture supervisor re-checks its `tcpdump` child — the pcap
/// ring's, and through [`supervise_on_iface`] the announce listener's and the
/// topology patrol's, one number for all three (realm net-observer, node #134).
/// Bounded on purpose: every attempt may spawn a `tcpdump` child, so this is a
/// slow patrol, not a tick.
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

/// How long an on-demand egress capture listens before it is stopped (realm
/// net-observer, node #170). A short window: the scan is a snapshot of what is
/// leaving the uplink right now, and ~5s captures enough of an active flow to
/// name its destinations while keeping the synchronous round-trip well inside
/// the CLI's `SCAN_TIMEOUT`.
const EGRESS_CAPTURE_BUDGET: Duration = Duration::from_secs(5);

/// How many destinations one egress scan stores, heaviest by bytes. The header
/// keeps the TRUE totals across every destination; only this top slice is
/// written to `egress_dst`, so a scan of a busy uplink cannot write thousands of
/// rows while the operator only ever reads the loudest few (realm net-observer,
/// node #170).
const EGRESS_TOP_N: usize = 50;

/// How often the record's retention sweep runs after the one at startup: once
/// a day, the unit the retention window is counted in (realm net-observer,
/// node #130).
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

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
    // Before anything is created: every file this root process makes from here
    // on — the record, its WAL, a frozen ring copy, a log dump — is born
    // group-readable and world-nothing, whatever mask launchd handed us. The
    // owner's ruling is that addresses stay raw and ACCESS is what narrows
    // (realm net-observer, node #110). The previous mask `umask` returns is
    // not needed.
    // SAFETY: `umask` sets the process's file-mode creation mask and returns
    // the old one; it takes no pointers and cannot fail (POSIX: "always
    // successful").
    unsafe { libc::umask(0o027) };
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

/// Capture once, map every received frame to a [`types::TopologyLink`],
/// upsert each into the store, mirror the de-duplicated set onto the live
/// snapshot the socket serves, and return it — the one body
/// [`spawn_topology_patrol`] and an operator-forced
/// [`pipeline::TopologyScanner::scan`] both run, so there is exactly one
/// capture→store→snapshot implementation (AGENTS.md principle 4), never two
/// that could drift apart. Because the snapshot update lives here, a
/// patrol tick and a forced `scan topology` land in ALL three readers at once —
/// the DB, `net-observer-cli topology` over the socket, and the bar's live map
/// (`snapshot.topology`) — with no path that updates only some of them.
///
/// Blocking end to end: `capture.capture()` spawns a `tcpdump` child and
/// waits up to its own budget. A caller on the async runtime must therefore
/// run this off the reactor — the patrol via `spawn_blocking`, the on-demand
/// scanner via `block_in_place` (see [`SystemTopologyScanner::scan`]). The
/// snapshot lock taken at the end is a brief `std::sync::Mutex`, never held
/// across an await, so taking it inside either blocking context is sound.
fn run_topology_capture(
    capture: &dyn LldpCapture,
    store: &dyn store::Store,
    snapshot: &Mutex<StatusSnapshot>,
    iface: &str,
    now: i64,
) -> Vec<types::TopologyLink> {
    let frames = capture.capture(TOPOLOGY_CAPTURE_BUDGET);
    let mut latest: Vec<types::TopologyLink> = Vec::new();
    for frame in &frames {
        let Some(link) = types::link_from_frame(frame, iface, now) else {
            continue;
        };
        if let Err(e) = store.write_topology_link(&link) {
            tracing::warn!(error = %e,
                "store write failed; topology link dropped from DB (gap logged)");
        }
        // De-duplicate by the stable key so the returned set carries one node
        // per uplink even if a switch advertised several times this run.
        if !latest.iter().any(|l| {
            l.iface == link.iface
                && l.remote_chassis == link.remote_chassis
                && l.remote_port == link.remote_port
        }) {
            latest.push(link);
        }
    }

    // Mirror onto the live snapshot the socket serves. A capture that maps no
    // links leaves the snapshot's last discovered set in place rather than
    // blanking it, so one quiet interval (or a forced scan on a silent segment)
    // does not erase a real uplink from the live view — the durable record is
    // the store, which keeps first/last seen. (realm net-observer, node #43)
    if !latest.is_empty() {
        // The record's first/last seen for the uplinks — `TopologyLink::ts_us`
        // is only this run's sighting, so this read is the sole path by which
        // `first_seen_us` reaches the socket. A failed read yields no bounds,
        // which the bar renders as "unknown" rather than as a freshly-discovered
        // uplink.
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
        snap.topology.clone_from(&latest);
        snap.topology_lifetimes = lifetimes;
    }

    latest
}

/// Spawn the topology patrol: on a slow interval, run [`run_topology_capture`]
/// on `iface` — which captures, stores, de-duplicates, and mirrors the result
/// onto the live snapshot the socket serves, the same body a forced
/// `scan topology` runs.
///
/// While paused (`observing == false`) the patrol skips its capture entirely —
/// an operator pause stops collection outright rather than emitting synthetic
/// readings (AGENTS.md: the sanctioned bracketed-pause exception).
fn spawn_topology_patrol(
    store: Arc<DuckdbStore>,
    snapshot: Arc<Mutex<StatusSnapshot>>,
    observing: Arc<AtomicBool>,
    iface: String,
) -> JoinHandle<()> {
    use std::sync::atomic::Ordering;

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
            let store_for_capture = Arc::clone(&store);
            let snapshot_for_capture = Arc::clone(&snapshot);
            let iface_for_capture = iface.clone();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                run_topology_capture(
                    &cap,
                    store_for_capture.as_ref(),
                    &snapshot_for_capture,
                    &iface_for_capture,
                    types::now_us(),
                )
            })
            .await
            {
                tracing::warn!(error = %e, "topology capture task failed to join");
                continue;
            }
        }
    })
}

/// Capture the physical interface's outgoing IP packets once, fold them by
/// destination, write the result to the store, and return it — the body the
/// on-demand `ScanEgress` runs (realm net-observer, node #170). There is no
/// egress patrol: unlike topology, this is operator-pressed only.
///
/// A capture that could not run writes a `SKIP` header (no rows) and returns it;
/// a capture that ran writes an `OK` header carrying the TRUE totals across
/// every destination, plus the top-[`EGRESS_TOP_N`] rows by bytes. The two are
/// never conflated — SKIP is not silence, and on a tunneled uplink a false zero
/// would mislead exactly the question this scan answers.
///
/// Blocking end to end: `capture.capture()` spawns a `tcpdump` child and waits
/// up to its budget, so a caller on the async runtime must run this off the
/// reactor — the on-demand scanner via `block_in_place` (see
/// [`SystemEgressScanner::scan`]).
fn run_egress_capture(
    capture: &dyn EgressCapture,
    store: &dyn store::Store,
    iface: &str,
    now: i64,
) -> EgressScanOutcome {
    let start = std::time::Instant::now();
    let captured = capture.capture(EGRESS_CAPTURE_BUDGET);
    let duration_ms = i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX);

    let (header, rows) = match captured {
        // The capture never ran: a SKIP with its reason and no destinations,
        // never an OK zero.
        EgressCaptureOutcome::CouldNotStart(reason) => (
            store::EgressScanHeader {
                ts_us: now,
                iface: iface.to_string(),
                verdict: "SKIP".to_string(),
                reason: Some(reason),
                duration_ms,
                packet_count: 0,
                dst_count: 0,
                byte_count: 0,
            },
            Vec::new(),
        ),
        // The capture ran (possibly seeing nothing): fold the outgoing frames
        // by destination.
        EgressCaptureOutcome::Ran(frames) => {
            let mut by_dst: std::collections::HashMap<std::net::IpAddr, (i64, u64)> =
                std::collections::HashMap::new();
            let mut packet_count: i64 = 0;
            let mut byte_count: u64 = 0;
            for frame in &frames {
                let Some(pkt) = types::dst_and_len(frame) else {
                    continue;
                };
                let entry = by_dst.entry(pkt.dst_ip).or_insert((0, 0));
                entry.0 += 1;
                entry.1 = entry.1.saturating_add(u64::from(pkt.bytes));
                packet_count += 1;
                byte_count = byte_count.saturating_add(u64::from(pkt.bytes));
            }
            let dst_count = by_dst.len();

            // Heaviest by bytes first (ties broken by address for a stable
            // order); the stored rows are only the top slice, but the header's
            // counts above are the TRUE totals across every destination.
            let mut sorted: Vec<(std::net::IpAddr, (i64, u64))> = by_dst.into_iter().collect();
            sorted.sort_by(|a, b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
            let rows: Vec<store::EgressDst> = sorted
                .into_iter()
                .take(EGRESS_TOP_N)
                .map(|(ip, (packets, bytes))| store::EgressDst {
                    ts_us: now,
                    dst_ip: ip.to_string(),
                    packets: i32::try_from(packets).unwrap_or(i32::MAX),
                    bytes,
                })
                .collect();

            (
                store::EgressScanHeader {
                    ts_us: now,
                    iface: iface.to_string(),
                    verdict: "OK".to_string(),
                    reason: None,
                    duration_ms,
                    packet_count: i32::try_from(packet_count).unwrap_or(i32::MAX),
                    dst_count: i32::try_from(dst_count).unwrap_or(i32::MAX),
                    byte_count,
                },
                rows,
            )
        }
    };

    // A store write failure is logged as a gap, never swallowed — the operator
    // still gets the live answer from the returned outcome, but the record says
    // it was not persisted.
    if let Err(e) = store.write_egress_scan(&header, &rows) {
        tracing::warn!(error = %e,
            "store write failed; egress scan dropped from DB (gap logged)");
    }

    EgressScanOutcome { header, rows }
}

/// The retention plan a configuration asks for: `None` for keep-forever
/// (`retention_days == 0`) or an empty table list, otherwise the window and
/// the tables the sweep will prune — each name checked against the store's
/// own allow-list, the air slice made whole, duplicates folded (realm
/// net-observer, node #130).
///
/// A name outside `store::PRUNABLE_TABLES` is an error and the daemon refuses
/// to start: an unknown name is never a silent fall-back, as an unknown
/// probing tier is not — and the five sample tables the gap derivation reads
/// are outside that list by design, so a config asking to prune them is
/// refused here, before the store is even opened. Checked whether or not a
/// window is set. Naming either half of the air slice (`air_sample` /
/// `air_ap`) names both; the half added is logged so the operator sees the
/// list the daemon actually runs.
fn retention_plan(record: &config::RecordCfg) -> anyhow::Result<Option<config::RecordCfg>> {
    let mut tables: Vec<String> = Vec::new();
    for name in &record.retention_tables {
        if !store::PRUNABLE_TABLES.contains(&name.as_str()) {
            anyhow::bail!(
                "record retention: `{name}` is not a prunable table; \
                 [record] retention_tables may name only {:?}",
                store::PRUNABLE_TABLES
            );
        }
        if !tables.contains(name) {
            tables.push(name.clone());
        }
    }
    if record.retention_days == 0 {
        tracing::info!("record retention: keep forever");
        return Ok(None);
    }
    if tables.is_empty() {
        tracing::info!("record retention: no tables listed");
        return Ok(None);
    }
    if store::AIR_SLICE
        .iter()
        .any(|half| tables.iter().any(|t| t == half))
    {
        for half in store::AIR_SLICE {
            if !tables.iter().any(|t| t == half) {
                tracing::info!(
                    "record retention: air_sample and air_ap are one scan slice; \
                     pruning {half} with its pair"
                );
                tables.push(half.to_string());
            }
        }
    }
    Ok(Some(config::RecordCfg {
        retention_days: record.retention_days,
        retention_tables: tables,
    }))
}

/// The mode a record directory takes: its own permission bits plus setgid, so
/// a file created inside it later inherits the directory's group rather than
/// its creator's (realm net-observer, node #110). The file-type bits
/// `st_mode` carries are dropped — `chmod(2)` takes permission bits only.
fn with_setgid(st_mode: u32) -> u32 {
    (st_mode & 0o7777) | 0o2000
}

/// The write-ahead log DuckDB keeps beside the record: `<db_path>.wal`, the
/// full file name plus the suffix (not a replaced extension).
fn wal_path(db_path: &Path) -> PathBuf {
    let mut wal = db_path.as_os_str().to_owned();
    wal.push(".wal");
    PathBuf::from(wal)
}

/// Narrow who can read the record to root and one group — the console user's
/// `staff` by default — instead of hashing what is in it: the owner's ruling
/// is that addresses stay raw and ACCESS is what changes (realm net-observer,
/// node #110). Runs once, right after the store is opened, so the file exists.
///
/// Three steps, each on its own and each best-effort: the record's directory
/// takes group `gid` and the setgid bit ([`grant_dir_access`] — on macOS a
/// new file takes its directory's group regardless, the bit makes Linux do
/// the same); the record file takes group `gid` and `mode`; so does
/// `<db_path>.wal` when it exists now. `mode` reaches the files present at
/// this moment: a WAL DuckDB re-creates after a later checkpoint is born
/// under the process umask instead (`0666 & !0o027` = `0640`), so a stricter
/// `record_mode` does not follow it. `gid = None` leaves every group as it is
/// and still sets the modes. A failure is logged at warn and the next step
/// runs — a record that stays 0644 is a warning, not an outage — and the
/// closing line says whether every step landed.
fn restrict_record_access(db_path: &Path, gid: Option<u32>, mode: u32) {
    let mut ok = true;
    if let Some(dir) = db_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        ok &= grant_dir_access(dir, gid);
    }
    ok &= grant_file_access(db_path, gid, mode);
    let wal = wal_path(db_path);
    if wal.exists() {
        ok &= grant_file_access(&wal, gid, mode);
    }
    if ok {
        tracing::info!(
            path = %db_path.display(),
            ?gid,
            mode = format!("{mode:o}"),
            "record readable by root and group"
        );
    } else {
        tracing::warn!(
            path = %db_path.display(),
            ?gid,
            mode = format!("{mode:o}"),
            "record access: not every step landed (see the warnings above); \
             who can read the record is not what the config says"
        );
    }
}

/// The blob tree follows the record: `blob_dir` and, when it exists already,
/// `blob_dir/ring` take group `gid` and the setgid bit, so a freeze directory
/// and a ring file `tcpdump` creates later are born in that group (realm
/// net-observer, node #110). The ring files already there take `gid` and
/// `mode` as well: `tcpdump` reopens an existing `ring.pcap*` by truncation
/// and never re-modes it, so one an earlier build left world-readable would
/// stay so for good — and the daemon owns and restarts that `tcpdump`, so
/// the file is its to set. The freeze copies themselves — what the operator
/// opens after an incident — get the record's group and mode outright when
/// they are made (`macos::FreezeAccess`); freezes made before this build
/// keep the bits they were made with. Best-effort, like the record.
fn restrict_blob_access(blob_dir: &Path, gid: Option<u32>, mode: u32) {
    let mut ok = grant_dir_access(blob_dir, gid);
    let ring_dir = blob_dir.join("ring");
    if ring_dir.is_dir() {
        ok &= grant_dir_access(&ring_dir, gid);
        ok &= grant_ring_files_access(&ring_dir, gid, mode);
    }
    if ok {
        tracing::info!(
            path = %blob_dir.display(),
            ?gid,
            mode = format!("{mode:o}"),
            "blob directory readable by root and group"
        );
    } else {
        tracing::warn!(
            path = %blob_dir.display(),
            ?gid,
            mode = format!("{mode:o}"),
            "blob access: not every step landed (see the warnings above)"
        );
    }
}

/// Every `ring.pcap*` file in `ring_dir` (`macos::RING_BASENAME`): group
/// `gid`, then `mode`. Other files there are not the ring's and are left
/// alone. Returns whether every one landed; a directory that cannot be read
/// is one failure.
fn grant_ring_files_access(ring_dir: &Path, gid: Option<u32>, mode: u32) -> bool {
    let entries = match std::fs::read_dir(ring_dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(error = %e, path = %ring_dir.display(), "ring directory: read failed");
            return false;
        }
    };
    let mut ok = true;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_ring_file = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(macos::RING_BASENAME));
        if is_ring_file && path.is_file() {
            ok &= grant_file_access(&path, gid, mode);
        }
    }
    ok
}

/// What every freeze copy takes: the record's group and mode (realm
/// net-observer, node #110).
fn freeze_access(cfg: &Config) -> FreezeAccess {
    FreezeAccess {
        gid: cfg.record_gid,
        mode: cfg.record_mode,
    }
}

/// One directory: group `gid`, then its own bits plus setgid
/// ([`with_setgid`]). Chown first — a chown can clear mode bits, a chmod
/// never moves a group. Each failure is a warning; returns whether every
/// step landed.
fn grant_dir_access(dir: &Path, gid: Option<u32>) -> bool {
    let meta = match std::fs::metadata(dir) {
        Ok(meta) => meta,
        Err(e) => {
            tracing::warn!(error = %e, path = %dir.display(), "directory: stat failed");
            return false;
        }
    };
    let mut ok = true;
    if let Err(e) = std::os::unix::fs::chown(dir, None, gid) {
        tracing::warn!(error = %e, path = %dir.display(), ?gid, "directory: chown failed");
        ok = false;
    }
    let dir_mode = with_setgid(meta.permissions().mode());
    if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(dir_mode)) {
        tracing::warn!(
            error = %e,
            path = %dir.display(),
            mode = format!("{dir_mode:o}"),
            "directory: setgid failed"
        );
        ok = false;
    }
    ok
}

/// One file: group `gid`, then `mode`, in that order for the same reason as
/// the directory. Each failure is a warning; returns whether both landed.
fn grant_file_access(path: &Path, gid: Option<u32>, mode: u32) -> bool {
    let mut ok = true;
    if let Err(e) = std::os::unix::fs::chown(path, None, gid) {
        tracing::warn!(error = %e, path = %path.display(), ?gid, "file: chown failed");
        ok = false;
    }
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        tracing::warn!(
            error = %e,
            path = %path.display(),
            mode = format!("{mode:o}"),
            "file: chmod failed"
        );
        ok = false;
    }
    ok
}

/// One retention sweep of the record: for each table of a plan
/// [`retention_plan`] returned, delete every row older than
/// `record.retention_days` through the store's own allow-list (realm
/// net-observer, node #130). A window of `0` returns at once: that is
/// keep-forever, and a cutoff computed from it would be "everything before
/// now" — the whole record — so the guard lives here, in the function whose
/// failure mode that is, not only in its caller.
///
/// Each prune runs on the blocking pool: a `DELETE` over a table with months
/// of ticks holds the connection mutex for as long as it takes, and the
/// reactor must not wait with it. A failure — a name the store refuses, a
/// driver error — is logged and the next table is tried; it never
/// propagates: a table that could not be pruned is a fuller record, not a
/// broken one.
async fn prune_record(store: &Arc<DuckdbStore>, record: &config::RecordCfg) {
    use store::Store as _;

    let days = record.retention_days;
    if days == 0 {
        return;
    }
    // Saturating on purpose: an absurd `retention_days` must land the cutoff
    // before every row (nothing pruned), never wrap it past them all.
    let cutoff_us = types::now_us().saturating_sub(i64::from(days).saturating_mul(86_400_000_000));
    for table in &record.retention_tables {
        let store = Arc::clone(store);
        let name = table.clone();
        // The failure crosses the pool as words, as the diagnoses' do.
        let pruned = tokio::task::spawn_blocking(move || {
            store
                .prune_older_than(&name, cutoff_us)
                .map_err(|e| e.to_string())
        })
        .await;
        match pruned {
            Ok(Ok(0)) => tracing::debug!("pruned 0 rows older than {days} d from {table}"),
            Ok(Ok(n)) => tracing::info!("pruned {n} rows older than {days} d from {table}"),
            Ok(Err(e)) => tracing::warn!(
                error = %e,
                table = %table,
                "record prune failed; table left as it is (gap logged)"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                table = %table,
                "record prune task failed to join; table left as it is (gap logged)"
            ),
        }
    }
}

/// Spawn the daily retention sweep. The startup sweep has already run by the
/// time this is called, so the interval's immediate first tick is consumed
/// before the loop. The interval counts AWAKE time: tokio's timer does not
/// advance while the Mac sleeps, so a laptop awake eight hours a day sweeps
/// every three wall days or so — a later sweep, never a missed one. `Delay`
/// keeps consecutive sweeps a full interval apart even after a late tick,
/// rather than firing a burst to catch up.
fn spawn_retention_sweep(store: Arc<DuckdbStore>, record: config::RecordCfg) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            prune_record(&store, &record).await;
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
        reason: types::ProbingReason::Startup,
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

    // The record's retention plan, validated BEFORE the store is opened: a
    // config naming a table the store will not prune refuses to start here,
    // having written nothing (realm net-observer, node #130). `None` is
    // keep-forever or an empty list — no sweep at all.
    let retention = retention_plan(&cfg.record)?;

    // Ensure the store + blob directories exist before opening the database.
    if let Some(parent) = Path::new(&cfg.db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::create_dir_all(&cfg.blob_dir);

    let store = Arc::new(DuckdbStore::open(&cfg.db_path).context("opening store")?);
    // The file exists now; open it to root and one group, never to the world —
    // and the blob tree with it, so a freeze the operator opens later is too.
    restrict_record_access(Path::new(&cfg.db_path), cfg.record_gid, cfg.record_mode);
    restrict_blob_access(Path::new(&cfg.blob_dir), cfg.record_gid, cfg.record_mode);

    // The schema migrates forward only: a file a NEWER build has opened keeps
    // its wider tables under this build, and every positional write to them is
    // refused by the binder — one gap line per dropped sample, for as long as
    // this build runs. Say so ONCE here, per table, and never abort: the
    // tables this build does fit are still recorded (realm net-observer, node
    // #150).
    match store::Store::schema_drift(&*store) {
        Ok(drift) if drift.is_empty() => {
            tracing::debug!("record schema matches this build: every write binds");
        }
        Ok(drift) => {
            for d in drift {
                tracing::warn!(
                    "schema drift: {} has {} columns, this build writes {} — a newer build \
                     migrated the record; every write to this table will be dropped until \
                     the daemon is rebuilt from that or a later revision",
                    d.table,
                    d.actual,
                    d.expected
                );
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            "failed to compare the record's schema with this build"
        ),
    }

    // Incidents left open by the previous process can never be closed by it
    // again — the closing edge lived in its memory. Stamp them closed at the
    // observation bound: the record's own newest sample, not this new
    // process's start time, which is always later and would make a crashed
    // run's incidents read as though they had lasted until now. A crash WHILE
    // PAUSED closes at the last sample before the pause — earlier than the
    // pause's own `observing_edge` row — which is an accepted asymmetry: the
    // incident closes at the last thing this record actually observed, not
    // at a boundary row a paused process wrote about observing nothing
    // (realm net-observer, node #124).
    let stale_close_ts = match store.latest_sample_ts_us() {
        Ok(Some(ts)) => ts,
        Ok(None) => types::now_us(),
        Err(e) => {
            tracing::warn!(error = %e, "failed to read the record's newest sample; \
                closing stale incidents at now instead");
            types::now_us()
        }
    };
    match store.close_open_incidents(stale_close_ts) {
        Ok(0) => {}
        Ok(n) => tracing::info!(n, "closed stale open incidents from a previous run"),
        Err(e) => tracing::warn!(error = %e, "failed to close stale open incidents"),
    }

    // The record's retention sweep, for the plan validated above (the policy
    // is the owner's; this is the mechanism — realm net-observer, node #130).
    // The first sweep runs HERE, before any collector can write, and the
    // daily one is spawned; its handle joins the collectors' below so shutdown
    // aborts it with them.
    let mut retention_sweep = None;
    if let Some(record) = retention {
        tracing::info!(
            days = record.retention_days,
            tables = ?record.retention_tables,
            "record retention: pruning at startup and then every 24 h awake"
        );
        prune_record(&store, &record).await;
        retention_sweep = Some(spawn_retention_sweep(store.clone(), record));
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
    // `ts_us` of the edge that ENDED the observation session the next
    // `resume_at_us` move re-opens: `SetObserving(false)` stores the pause's
    // own `ts_us` here, `set_probing` the switch's. The pipeline consumer
    // reads it once per edge to close whatever the previous session left
    // open at the instant it actually ended, not at the edge's own (realm
    // net-observer, node #124).
    let session_end_us = Arc::new(AtomicI64::new(0));

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
    if cfg.collectors.connections.enabled {
        // Shares the proxy collector's Clash API base and rendered config:
        // the flow table comes from the same sing-box the selector is read
        // from, and each flow's scope is judged against that sing-box's own
        // listeners. Reads a loopback API and a local file and sends nothing
        // (realm net-observer, node #75).
        collectors.push(AnyCollector::Connections(ConnectionsCollector::new(
            Arc::new(ConnectionSystemFacts::new(
                SINGBOX_CONFIG_PATH,
                cfg.collectors.proxy.clash_api.clone(),
            )),
            cfg.collectors.connections.interval,
        )));
    }
    if cfg.collectors.singbox_log.enabled {
        // sing-box's own log, tailed from its current end: a world-readable
        // local file, read under both probing tiers and sending nothing. A
        // log that is not there yet is retried every tick, each such tick an
        // `unreadable` row (realm net-observer, nodes #140, #141).
        collectors.push(AnyCollector::SingboxLog(SingboxLogCollector::new(
            cfg.collectors.singbox_log.path.clone(),
            cfg.collectors.singbox_log.interval,
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
    // The announce listener is NOT built here: it is an event collector over a
    // `tcpdump` child on the physical interface, so it is constructed by its
    // supervisor below, once that capture starts (realm net-observer, node #134).

    // Filter by OS meta + preflight, then spawn survivors with one uniform loop.
    let os = Os::current();
    let mut handles: Vec<JoinHandle<()>> = Vec::new();
    handles.extend(retention_sweep);
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
        // Event cadence is different: the source is opened before construction
        // and moved into the collector, so there is nothing left to re-probe per
        // tick and the blocking thread has no tick to re-probe on. Which event
        // collectors reach this loop is therefore decided by what their source
        // needs. `route` needs no interface — its PF_ROUTE socket opens at boot
        // or never — so it is built above and stays one-shot: an Unavailable
        // `route` is logged and skipped for the life of the process. The
        // announce listener needs the physical interface, which a `RunAtLoad`
        // daemon boots without, so it never comes through here: it is started
        // by `supervise_on_iface` below, and started again when its stream
        // ends, like the pcap ring (realm net-observer, node #134).
        match (c.source(), c.preflight().await) {
            (Source::Event, Readiness::Unavailable(reason)) => {
                tracing::warn!(collector = name, %reason, "preflight failed; skipping (event cadence with no interface to wait for: not retried)");
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

    // The physical interface as it is NOW, for every supervisor that opens a
    // `tcpdump` child on it: re-resolved on each attempt, never the boot-time
    // value above, which a `RunAtLoad` daemon resolves to nothing.
    let resolve_iface = {
        let gw = cfg.collectors.link.gw.clone();
        let configured_iface = cfg.collectors.link.phys_iface.clone();
        move || {
            let facts = SystemFacts::new(gw.clone(), configured_iface.clone());
            async move { facts.phys_iface().await }
        }
    };

    // The passive announce listener (realm net-observer, node #92): Event
    // cadence like `route`, over a second `tcpdump` child's pcap stream on the
    // physical interface. Supervised, not attempted once (node #134): the
    // supervisor resolves the interface, `AnnounceCapture::start` proves the
    // child captures (it has written an Ethernet pcap header), and only then
    // is the collector constructed — always Ready — and driven like any event
    // collector; when the stream ends the source brackets it with a `SKIP` row
    // and the supervisor starts a new one. The probing tier does not gate it:
    // a tier withholds emissions and this collector has none (node #88).
    // Shares the link collector's `SystemFacts`, so the segment it keys every
    // window by is the same key the neighbour cache and the scan write under,
    // and the interface's own MAC — what it drops our own frames by — is read
    // afresh for every window through the same `SystemSegment`, since a
    // Private Wi-Fi Address rotates it per network.
    if cfg.collectors.neighbors.enabled && cfg.collectors.neighbors.announce {
        let name = collector_announce::META.name;
        if collector_announce::META.supports(os) {
            let tx = tx.clone();
            let observing = observing.clone();
            let resolve_iface = resolve_iface.clone();
            let gw = cfg.collectors.link.gw.clone();
            let configured_iface = cfg.collectors.link.phys_iface.clone();
            handles.push(tokio::spawn(async move {
                supervise_on_iface(name, PCAP_RETRY_INTERVAL, resolve_iface, move |iface| {
                    let capture = AnnounceCapture::start(iface)?;
                    let source = AnnounceSource::new(
                        capture,
                        Some(iface.to_string()),
                        SystemSegment::new(
                            SystemFacts::new(gw.clone(), configured_iface.clone()),
                            iface.to_string(),
                            tokio::runtime::Handle::current(),
                        ),
                        collector_announce::FLUSH_EVERY,
                    );
                    let collector = AnyCollector::Announce(AnnounceCollector::new(
                        Box::new(source),
                        Readiness::Ready,
                    ));
                    Ok(spawn_event_collector(
                        collector,
                        tx.clone(),
                        observing.clone(),
                    ))
                })
                .await;
            }));
        } else {
            tracing::warn!(collector = name, ?os, "unsupported OS; skipping");
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
        let freeze = freeze_access(&cfg);
        let resolve_iface = resolve_iface.clone();
        tokio::spawn(async move {
            supervise_pcap_ring(
                slot,
                PCAP_RETRY_INTERVAL,
                pcap_reason,
                resolve_iface,
                move |iface| {
                    PcapRing::start(iface, ring_dir.clone(), ring_mb, &filter, freeze)
                        .map(|r| Arc::new(r) as Arc<dyn PcapFreezer>)
                },
            )
            .await;
        })
    });

    // Passive switch-topology discovery: a slow patrol that opens its OWN
    // short-lived LLDP/CDP capture (never the shared incident ring), maps each
    // received frame to an uplink edge, and records it. Gated on the neighbours
    // subsystem being enabled AND the topology toggle: disabling neighbours
    // turns its sub-feature off too, no surprise. The patrol needs a physical
    // interface to listen on, so it too waits under `supervise_on_iface` for
    // one to appear rather than being skipped for the life of a process that
    // booted without one (realm net-observer, node #134); once started it runs
    // on that interface, its own capture bounded per run. Pushed onto `handles`
    // so it is aborted with the collectors on shutdown. The LIVE capture is a
    // project Ceiling (needs root + BPF on a real network); the patrol degrades
    // honestly when it cannot open one (see `lldp_capture`).
    if cfg.collectors.neighbors.enabled && cfg.collectors.neighbors.topology {
        let store = store.clone();
        let snapshot = snapshot.clone();
        let observing = observing.clone();
        let resolve_iface = resolve_iface.clone();
        handles.push(tokio::spawn(async move {
            supervise_on_iface(
                "topology",
                PCAP_RETRY_INTERVAL,
                resolve_iface,
                move |iface| {
                    Ok(spawn_topology_patrol(
                        store.clone(),
                        snapshot.clone(),
                        observing.clone(),
                        iface.to_string(),
                    ))
                },
            )
            .await;
        }));
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
            session_end_us.clone(),
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
        session_end_us,
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
    /// The passive announce listener: Event-cadence over a second `tcpdump`
    /// child, its samples `Sample::Neighbors` like the cache reading's.
    Announce(AnnounceCollector),
    Host(HostCollector<HostLoad>),
    Wifi(WifiCollector<CoreWlanFacts>),
    Neighbors(NeighborsCollector<SystemNeighbors>),
    Air(AirCollector<SystemProfilerAir>),
    Connections(ConnectionsCollector<ConnectionSystemFacts>),
    /// The passive reader of sing-box's own log, over the real file tail.
    SingboxLog(SingboxLogCollector),
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
            Self::Announce(c) => c.meta(),
            Self::Host(c) => c.meta(),
            Self::Wifi(c) => c.meta(),
            Self::Neighbors(c) => c.meta(),
            Self::Air(c) => c.meta(),
            Self::Connections(c) => c.meta(),
            Self::SingboxLog(c) => c.meta(),
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
            Self::Announce(c) => c.source(),
            Self::Host(c) => c.source(),
            Self::Wifi(c) => c.source(),
            Self::Neighbors(c) => c.source(),
            Self::Air(c) => c.source(),
            Self::Connections(c) => c.source(),
            Self::SingboxLog(c) => c.source(),
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
            Self::Announce(c) => c.preflight().await,
            Self::Host(c) => c.preflight().await,
            Self::Wifi(c) => c.preflight().await,
            Self::Neighbors(c) => c.preflight().await,
            Self::Air(c) => c.preflight().await,
            Self::Connections(c) => c.preflight().await,
            Self::SingboxLog(c) => c.preflight().await,
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
            Self::Announce(c) => c.collect(ts_us).await,
            Self::Host(c) => c.collect(ts_us).await,
            Self::Wifi(c) => c.collect(ts_us).await,
            Self::Neighbors(c) => c.collect(ts_us).await,
            Self::Air(c) => c.collect(ts_us).await,
            Self::Connections(c) => c.collect(ts_us).await,
            Self::SingboxLog(c) => c.collect(ts_us).await,
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
            Self::Announce(c) => c.skip(ts_us),
            Self::Host(c) => c.skip(ts_us),
            Self::Wifi(c) => c.skip(ts_us),
            Self::Neighbors(c) => c.skip(ts_us),
            Self::Air(c) => c.skip(ts_us),
            Self::Connections(c) => c.skip(ts_us),
            Self::SingboxLog(c) => c.skip(ts_us),
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
            Self::Announce(c) => Box::new(c).into_event_source(),
            Self::Host(c) => Box::new(c).into_event_source(),
            Self::Wifi(c) => Box::new(c).into_event_source(),
            Self::Neighbors(c) => Box::new(c).into_event_source(),
            Self::Air(c) => Box::new(c).into_event_source(),
            Self::Connections(c) => Box::new(c).into_event_source(),
            Self::SingboxLog(c) => Box::new(c).into_event_source(),
            #[cfg(test)]
            Self::Fake(c) => Box::new(c).into_event_source(),
        }
    }
}

/// The classified outcome of one attempt to load the CVE snapshot directory.
/// The `Unusable` reason is exactly the note `scan()` used to compute inline.
/// Only `Ready` is cached by [`SystemScanner`] (see `cve_cache`): the
/// directory's CONTENT is immutable for the daemon's life, so a successful
/// load is reused forever, but `Unusable` says nothing about whether the NEXT
/// attempt succeeds — a missing/empty directory can be provisioned later, and
/// an `Io` error (fd exhaustion, a one-off blip while walking ~395k files) can
/// be transient. Caching `Unusable` would permanently disable CVE checking
/// for the daemon's whole life on a single bad scan, with no self-heal (v1 has
/// no watchdog) — worse than the per-scan reload this replaced, which at least
/// retried. So `Unusable` is recomputed every `--cve` scan until it turns
/// `Ready`, which then latches (realm net-observer, node #158).
enum CveSnapshot {
    Ready(Arc<vuln_db::VulnDb>),
    Unusable(String),
}

/// Load and classify the CVE snapshot directory. The three honest-note cases
/// are unchanged from the inline match this replaced: no directory
/// configured, a directory that fails to load, and a directory that loads but
/// is empty or the wrong layout — all three are `Unusable` with the same
/// wording; anything else is a ready, matchable index. Called by
/// `SystemScanner::cve_rung` on every scan until it returns `Ready` (see
/// [`CveSnapshot`] for why `Unusable` is never cached).
fn load_and_classify(dir: Option<&Path>) -> CveSnapshot {
    match dir {
        None => CveSnapshot::Unusable("cve rung ran without a snapshot directory".to_string()),
        Some(dir) => match vuln_db::VulnDb::load_from_dir(dir) {
            Err(e) => CveSnapshot::Unusable(format!(
                "snapshot at {} failed to load: {e}; findings NOT checked",
                dir.display()
            )),
            Ok(db) if db.is_empty() => CveSnapshot::Unusable(format!(
                "snapshot at {} is empty or wrong layout; findings NOT checked \
                 (not a clean 'no vulnerabilities')",
                dir.display()
            )),
            Ok(db) => CveSnapshot::Ready(Arc::new(db)),
        },
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
    /// The loaded index, set by whichever `--cve` scan FIRST loads it
    /// successfully and reused by every scan after — success only, never a
    /// failure/empty/missing classification (see [`CveSnapshot`] for why: the
    /// directory's content is immutable, but an `Unusable` outcome is not, and
    /// must keep retrying). The recursive walk+parse of the provisioned "all
    /// CVEs" tree (~395k files) takes minutes — loading it on every scan hung
    /// the CLI's request budget. `scan()` takes `&self` (`NeighborScanner::
    /// scan`), so interior mutability is required; `OnceLock` is the right
    /// tool because a set index is a plain read on every later call, no lock
    /// contention on the hot path.
    cve_cache: OnceLock<Arc<vuln_db::VulnDb>>,
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
            cve_cache: OnceLock::new(),
            oui,
        }
    }

    /// The `cve` rung: match the ports' banners against the loaded snapshot.
    /// Returns the findings (empty when the snapshot is unusable) and, when
    /// unusable, the honest reason — the same two outcomes `scan()`'s inline
    /// match used to compute.
    ///
    /// A cached `Ready` index is reused without touching disk again. Anything
    /// else re-runs `load_and_classify` THIS scan and, only on success, sets
    /// the cache for every scan after — an `Unusable` outcome is returned but
    /// deliberately not cached, so the next `--cve` scan retries rather than
    /// staying permanently off on one transient I/O blip (see [`CveSnapshot`]).
    fn cve_rung(
        &self,
        ports: &[store::NeighborPort],
        ts_us: i64,
    ) -> (Vec<store::NeighborVuln>, Option<String>) {
        if let Some(db) = self.cve_cache.get() {
            return (pipeline::match_vulns(db, ports, ts_us), None);
        }
        match load_and_classify(self.cve_snapshot_dir.as_deref()) {
            CveSnapshot::Ready(db) => {
                // Another thread may have raced us and already set the cell;
                // that is fine — either `Arc` is an equally valid load of the
                // same immutable content, and only the loser's copy is
                // discarded, not re-fetched.
                let _ = self.cve_cache.set(Arc::clone(&db));
                (pipeline::match_vulns(&db, ports, ts_us), None)
            }
            CveSnapshot::Unusable(note) => (Vec::new(), Some(note)),
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
            let network_key = rt.block_on(self.facts.network_key());
            let pace = neighbor_scan::effective_pace(opts.slow);

            // Part A (realm net-observer, node #154): a named target replaces
            // the whole-segment sweep with one probe to exactly that address,
            // and skips the mDNS browse entirely — this daemon keeps no
            // persistent name cache a single host could consult "trivially",
            // and a fresh browse costs the same whole-segment seconds `target`
            // exists to avoid. The ARP cache is still re-read, but narrowed to
            // this one address: the whole cache would over-report every OTHER
            // neighbour already cached as if this run found it too.
            let (sweep, arp, mdns) = if let Some(target) = opts.target {
                let sweep = match target {
                    std::net::IpAddr::V4(v4) => {
                        neighbor_scan::single_probe_blocking(&iface, v4, pace)
                    }
                    // NDP, not ARP, resolves an IPv6 neighbour's link layer —
                    // out of scope here (the whole sweep/ARP machinery is
                    // IPv4-only). The ports/banners/cve rungs below still run
                    // against the address directly; only the ARP-forcing probe
                    // and its "found" entity are skipped, honestly refused
                    // rather than silently claiming a resolution that never
                    // happened.
                    std::net::IpAddr::V6(_) => neighbor_scan::SweepStats {
                        target: target.to_string(),
                        sent: 0,
                        total: 0,
                        duration_ms: 0,
                        refused: Some(
                            "IPv6 targets are not ARP-resolvable; ports/banners/cve still ran"
                                .to_string(),
                        ),
                    },
                };
                let target_s = target.to_string();
                let arp: Vec<types::NeighborObs> = rt
                    .block_on(neighbors::read_arp(Some(&iface)))
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|n| n.ip == target_s)
                    .collect();
                (sweep, arp, neighbor_scan::MdnsOutcome::default())
            } else {
                let sweep = match rt.block_on(neighbor_scan::iface_ipv4(&iface)) {
                    Some(ipv4) => {
                        let cap = neighbor_scan::sweep_max_cap(opts.sweep_max);
                        neighbor_scan::sweep_probe_blocking(&ipv4, &iface, cap, pace)
                    }
                    // No line in `ifconfig <iface>` parsed to a sweepable
                    // subnet — every `inet` was skipped (a /32 alias like the
                    // dns-fallback daemon's pin, TEST-NET-1, link-local, …;
                    // realm net-observer, node #159) or the interface carried
                    // no `inet` line at all. Before `parse_ifconfig_inet`
                    // learned to skip those addresses, this same interface
                    // still reached `sweep_probe_blocking` and came back
                    // refused from `host_addrs`; build the same refusal here
                    // so the attempt is still durably recorded (the ARP cache
                    // and mDNS browse below still run) instead of the whole
                    // scan silently returning nothing.
                    None => neighbor_scan::SweepStats {
                        target: iface.clone(),
                        sent: 0,
                        total: 0,
                        duration_ms: 0,
                        refused: Some(
                            "no IPv4 subnet found on this interface to sweep".to_string(),
                        ),
                    },
                };
                // Read the cache the sweep just filled. Everything it now holds
                // for this interface counts as found: an entry the kernel
                // resolved because of our probe is indistinguishable from one
                // that was already there, and claiming otherwise would be a
                // guess. What is NOT guessed is attribution — a refused sweep
                // leaves these entries marked `arp`, which `compose_scan_report`
                // decides.
                let arp = rt
                    .block_on(neighbors::read_arp(Some(&iface)))
                    .unwrap_or_default();
                let mdns = neighbor_scan::mdns_names_blocking();
                (sweep, arp, mdns)
            };

            // The `ports` rung, only when this run asked for it. A named
            // target is probed directly by its own address — ARP would hold
            // its GATEWAY's MAC for a routed, off-subnet host, never the
            // host's own, so deriving targets from `arp` would silently probe
            // nothing for exactly the boundary case Part A exists to allow
            // (realm net-observer, node #154). Without a target, targets are
            // the addresses the base sweep just found, so a port scan never
            // reaches past the neighbours actually on the segment.
            let ports = if opts.ports {
                let targets: Vec<std::net::IpAddr> = match opts.target {
                    Some(ip) => vec![ip],
                    None => arp.iter().filter_map(|n| n.ip.parse().ok()).collect(),
                };
                Some(neighbor_scan::port_scan_blocking(
                    &targets,
                    neighbor_scan::COMMON_PORTS,
                    &iface,
                    pace,
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
                opts.target,
            );

            // The `cve` rung: match the banners the report already carries
            // against the local snapshot. `api::scan_now` only sets `opts.cve`
            // when banners are effective AND a snapshot directory exists, so an
            // unusable snapshot here is an anomaly (a directory that vanished,
            // is corrupt, or is empty) — log it and record no findings rather
            // than a guess; the ports and their banners are already recorded.
            //
            // A successful load is cached and reused by every scan after — the
            // FIRST `--cve` scan that loads the snapshot populates `cve_cache`
            // (realm net-observer, node #158), so most scans never re-walk the
            // provisioned tree. An unusable outcome is NOT cached and is
            // recomputed every scan instead, so a transient failure (or a
            // directory provisioned after boot) retries rather than staying
            // permanently off. The three honest-note outcomes are unchanged:
            // an existing-but-empty or wrong-layout directory, or a load
            // error, leaves `vulns` empty AND records a reason, so the
            // operator never reads "no findings" as "no vulnerabilities" when
            // the check never really ran.
            if opts.cve {
                let (vulns, cve_note) = self.cve_rung(&report.ports, ts_us);
                report.vulns = vulns;
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

    /// `check-cve --product`'s own path into the SAME cache [`Self::cve_rung`]
    /// reads/fills — a lookup and a scan's `cve` rung share one cache, so
    /// whichever asks first loads and classifies the snapshot once, and every
    /// call after (lookup or scan) answers straight from memory. `vuln_db::
    /// VulnDb::lookup` is the thin product+version convenience over
    /// `match_product`; matching itself lives there, not here.
    fn cve_lookup(&self, product: &str, version: Option<&str>) -> CveLookupOutcome {
        if let Some(db) = self.cve_cache.get() {
            return CveLookupOutcome::Matches(db.lookup(product, version));
        }
        match load_and_classify(self.cve_snapshot_dir.as_deref()) {
            CveSnapshot::Ready(db) => {
                let matches = db.lookup(product, version);
                // Same race note as `cve_rung`: a concurrent loser's `Arc` is
                // just as valid a load of the same immutable content, so the
                // result already computed here is kept rather than redone.
                let _ = self.cve_cache.set(Arc::clone(&db));
                CveLookupOutcome::Matches(matches)
            }
            CveSnapshot::Unusable(note) => CveLookupOutcome::SnapshotUnavailable(note),
        }
    }
}

/// The production [`TopologyScanner`]: resolves the physical interface fresh
/// at scan time — never a boot-time value, which a `RunAtLoad` daemon may have
/// started without — the same "ask the OS now" precedent [`SystemScanner`]
/// already uses for `phys_iface`, not a second one. Then runs
/// [`run_topology_capture`] on it, writing through the SAME store handle AND
/// the SAME live snapshot the patrol uses — so a forced capture reaches the DB,
/// the socket, and the bar's map together, exactly as a patrol tick does.
pub(crate) struct SystemTopologyScanner {
    facts: SystemFacts,
    store: Arc<DuckdbStore>,
    /// The SAME live snapshot the patrol mirrors into, so a forced capture
    /// updates the bar's map at once rather than only on the next patrol tick.
    snapshot: Arc<Mutex<StatusSnapshot>>,
}

impl SystemTopologyScanner {
    fn new(
        facts: SystemFacts,
        store: Arc<DuckdbStore>,
        snapshot: Arc<Mutex<StatusSnapshot>>,
    ) -> Self {
        Self {
            facts,
            store,
            snapshot,
        }
    }
}

impl TopologyScanner for SystemTopologyScanner {
    /// Blocking work (an async interface lookup, then a `tcpdump` child held
    /// open for up to 65s) inside an async request handler, so it runs under
    /// `block_in_place` exactly like [`SystemScanner::scan`]: the worker
    /// thread is handed back to the runtime for the duration instead of
    /// stalling every other connection behind one capture.
    ///
    /// **Requires the multi-thread runtime** — see `SystemScanner::scan`'s
    /// doc for why that always holds here.
    fn scan(&self) -> Vec<types::TopologyLink> {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            let Some(iface) = rt.block_on(self.facts.phys_iface()) else {
                tracing::info!("topology scan: no physical interface resolved; no links this run");
                return Vec::new();
            };
            let capture = TcpdumpLldpCapture::new(iface.clone());
            run_topology_capture(
                &capture,
                self.store.as_ref(),
                &self.snapshot,
                &iface,
                types::now_us(),
            )
        })
    }
}

/// The production [`EgressScanner`]: resolves the physical interface fresh at
/// scan time — never a boot-time value, the same "ask the OS now" precedent
/// [`SystemScanner`] and [`SystemTopologyScanner`] use — then runs
/// [`run_egress_capture`] on it through the SAME store handle every other
/// durable record goes through (realm net-observer, node #170). No live
/// snapshot to mirror into: unlike topology, the egress scan is a record read
/// back on demand, not part of the bar's status view.
pub(crate) struct SystemEgressScanner {
    facts: SystemFacts,
    store: Arc<DuckdbStore>,
}

impl SystemEgressScanner {
    fn new(facts: SystemFacts, store: Arc<DuckdbStore>) -> Self {
        Self { facts, store }
    }
}

impl EgressScanner for SystemEgressScanner {
    /// Blocking work (an async interface lookup, then a `tcpdump` child held
    /// open for ~5s) inside an async request handler, so it runs under
    /// `block_in_place` exactly like [`SystemTopologyScanner::scan`]: the
    /// worker thread is handed back to the runtime for the duration instead of
    /// stalling every other connection behind one capture.
    ///
    /// **Requires the multi-thread runtime** — see `SystemScanner::scan`'s doc
    /// for why that always holds here. A physical interface that cannot be
    /// resolved is a SKIP with its reason, never a silent zero.
    fn scan(&self) -> EgressScanOutcome {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            let now = types::now_us();
            let Some(iface) = rt.block_on(self.facts.phys_iface()) else {
                tracing::info!(
                    "egress scan: no physical interface resolved; SKIP (nothing to capture)"
                );
                let header = store::EgressScanHeader {
                    ts_us: now,
                    iface: String::new(),
                    verdict: "SKIP".to_string(),
                    reason: Some("no physical interface resolved".to_string()),
                    duration_ms: 0,
                    packet_count: 0,
                    dst_count: 0,
                    byte_count: 0,
                };
                if let Err(e) = self.store.write_egress_scan(&header, &[]) {
                    tracing::warn!(error = %e,
                        "store write failed; egress SKIP dropped from DB (gap logged)");
                }
                return EgressScanOutcome {
                    header,
                    rows: Vec::new(),
                };
            };
            let capture = TcpdumpEgressCapture::new(iface.clone());
            run_egress_capture(&capture, self.store.as_ref(), &iface, now)
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
        EventKind::Connections => c.connections.enabled,
        EventKind::SingboxLog => c.singbox_log.enabled,
        // Not a collector: incidents are what the triggers write about the
        // collectors' samples, and a close is the end of one (realm
        // net-observer, node #135). `pcap_ring` is absent for the same reason
        // from the other side — it produces no event kind at all.
        EventKind::Incident | EventKind::IncidentClosed => return None,
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
            gw: types::GwVerdict::Skip,
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
        freeze_access(cfg),
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

/// Keep a capture that needs the physical interface running, for as long as
/// this task runs.
///
/// The announce listener and the topology patrol both open a `tcpdump` child on
/// the physical interface, and a `RunAtLoad` daemon boots exactly when there is
/// none to open it on — so, like the pcap ring, they are supervised rather than
/// attempted once: every `interval` this re-resolves the interface and tries to
/// start the capture, and when a running one ends it is started again after the
/// same interval. The end itself is already in the record — the announce source
/// brackets it with the `SKIP` row it emits — so the restart writes no row of
/// its own (realm net-observer, node #134).
///
/// What ends a capture is its own child dying: a running listener stays on the
/// interface it STARTED on, and a default route moving to another interface is
/// not a restart trigger yet — that needs a stop path into the child inside the
/// reader thread, a follow-up — so until the child dies, windows keyed by the
/// current gateway may carry the old interface's hearing.
///
/// `start` opens the capture on the interface and spawns what drives it,
/// returning the task that ends when the capture does (`spawn_event_collector`'s
/// handle completes when its source thread returns; the topology patrol's never
/// does, so it is started once per interface resolution). It may block —
/// `AnnounceCapture::start` waits for the child's pcap header, up to its bound
/// — so it runs on the blocking pool, never on a runtime worker. Aborting this
/// task aborts the awaited TOKIO task only: the topology patrol, or, for the
/// listener, just the oneshot bridge — its event thread, the reader thread
/// holding the `AnnounceCapture` and the `tcpdump` child run until process exit
/// (EPIPE on the next frame, launchd's process group), as `spawn_event_collector`
/// says.
///
/// Logging is by *change of reason*, never per attempt, as for the ring: the
/// first failure and each subsequent different reason are logged, and so is
/// every start and every end. The ring's supervisor is not reused here because
/// its liveness is a slot it polls, while this one awaits the end of a task;
/// the interface resolver, the interval and the log discipline are the same.
async fn supervise_on_iface<R, Fut, S>(
    name: &'static str,
    interval: Duration,
    resolve_iface: R,
    start: S,
) where
    R: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
    S: Fn(&str) -> std::io::Result<JoinHandle<()>> + Send + Sync + 'static,
{
    let start = Arc::new(start);
    let mut last_reason: Option<String> = None;
    loop {
        let reason = match resolve_iface().await {
            None => Some("no physical interface resolved".to_string()),
            Some(iface) => {
                // Off the runtime workers: the announce start waits for the
                // child's header. The blocking pool's threads carry the runtime
                // context, so `tokio::spawn` and `Handle::current()` inside
                // `start` are valid there.
                let started = {
                    let (start, iface) = (start.clone(), iface.clone());
                    tokio::task::spawn_blocking(move || start(&iface)).await
                };
                match started {
                    Ok(Ok(handle)) => {
                        tracing::info!(capture = name, iface, "capture started");
                        last_reason = None;
                        let mut running = AbortOnDrop(handle);
                        match (&mut running.0).await {
                            Ok(()) => tracing::warn!(
                                capture = name,
                                retry_s = interval.as_secs(),
                                "capture ended; will restart"
                            ),
                            Err(e) => tracing::error!(
                                capture = name,
                                error = %e,
                                retry_s = interval.as_secs(),
                                "capture task failed; will restart"
                            ),
                        }
                        None
                    }
                    Ok(Err(e)) => Some(format!("tcpdump could not be started on {iface}: {e}")),
                    Err(e) => Some(format!("capture start task failed on {iface}: {e}")),
                }
            }
        };
        if reason != last_reason {
            if let Some(reason) = &reason {
                tracing::warn!(
                    capture = name,
                    %reason,
                    retry_s = interval.as_secs(),
                    "capture not running; will retry"
                );
            }
            last_reason = reason;
        }
        tokio::time::sleep(interval).await;
    }
}

/// A spawned task that is aborted when this handle is dropped — so the tokio
/// task [`supervise_on_iface`] is awaiting is aborted with the supervisor
/// (which `abort_all` drops) instead of being detached, as dropping a bare
/// [`JoinHandle`] would. That reaches the topology patrol's task; for the
/// listener it reaches only the oneshot bridge, never the detached threads or
/// the `tcpdump` child behind it.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
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
    session_end_us: Arc<AtomicI64>,
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
    let socket_gid = cfg.socket_gid;
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
        socket_gid,
        max_subscribers: api::MAX_SUBSCRIBERS,
        // Bounds for a socket every process of the console user's group can
        // connect to by default: a local process must not be able to pin
        // unbounded tasks/fds by connecting and never speaking, nor grow a
        // root daemon's log by looping refused control requests.
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
        // Built unconditionally, exactly like `scanner`/`air_scanner`: whether
        // there is a physical interface and an answering switch/AP is decided
        // per request, not once at boot (realm net-observer, node #91). Shares
        // the SAME store handle the patrol writes through, so an operator-
        // forced capture and a patrol tick land in the same table by the same
        // path (`run_topology_capture`).
        topology_scanner: Some(Arc::new(SystemTopologyScanner::new(
            SystemFacts::new(
                cfg.collectors.link.gw.clone(),
                cfg.collectors.link.phys_iface.clone(),
            ),
            Arc::clone(&store),
            Arc::clone(&snapshot),
        )) as Arc<dyn TopologyScanner>),
        // Built unconditionally, exactly like `topology_scanner`: whether there
        // is a physical interface and anything to see leaving it is decided per
        // request, not once at boot (realm net-observer, nodes #91, #170).
        // Shares the SAME store handle the other writers use.
        egress_scanner: Some(Arc::new(SystemEgressScanner::new(
            SystemFacts::new(
                cfg.collectors.link.gw.clone(),
                cfg.collectors.link.phys_iface.clone(),
            ),
            Arc::clone(&store),
        )) as Arc<dyn EgressScanner>),
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
        session_end_us,
        snapshot,
        // The durable sink for `observing_edge` boundary rows: the daemon
        // stays the sole DuckDB owner, so the control path writes through the
        // same handle the pipeline does.
        store: store as Arc<dyn store::Store + Send + Sync>,
        // One diagnosis at a time: a `Query` holds the store mutex the pipeline
        // writes through, and the socket is group-connectable (0660 root:staff
        // by default).
        query_gate: Arc::new(tokio::sync::Semaphore::new(api::MAX_QUERIES_IN_FLIGHT)),
        events_tx,
        // Empty at boot on purpose: a window is process-scoped like the tier
        // it withholds, and a finished one is read back from the `experiment`
        // table (realm net-observer, node #61).
        experiments: Arc::new(Mutex::new(std::collections::HashMap::new())),
        // What a window's report can see of our own frames, and the tick it
        // measures a sleep and a straddling echo against.
        ring_filter: cfg.collectors.pcap_ring.filter.clone(),
        link_interval: cfg.collectors.link.interval,
    }
}

/// Assemble the [`TriggerEngine`]'s rule set (wedge, gw-drop, gw-change,
/// roam, wifi-churn, gw-mac-change, neighbor-mac-collision, per-client-block,
/// ban-cycle, fakeip, fakeip-hijack, endpoint-block, established-stall,
/// endpoint-dial-stall, singbox-no-route, singbox-dial-timeout, starvation).
/// Every rule records an incident (durable, in DuckDB) and mirrors it into the
/// live snapshot's ring for the socket API; gw-change and gw-mac-change
/// additionally freeze the pcap ring when one is available.
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
        // The two signatures read from sing-box's own log (realm net-observer,
        // node #141). No direct-path gate on either: the point of the first is
        // to name the fault under the passive tier, where the direct probe is
        // withheld, and its own context is the held router; the second reads
        // its context — the underlay reaching every endpoint — off the proxy
        // tick itself. Both hold their fire under host starvation and inside
        // the settle window after a network move, when sing-box legitimately
        // has no route for a while. No pcap freeze: the evidence is the
        // recorded log rows.
        Trigger::new(
            Box::new(Gated {
                inner: SingboxNoRoute,
                require_direct: false,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
            }),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        Trigger::new(
            Box::new(Gated {
                inner: SingboxDialTimeout,
                require_direct: false,
                load_below: Some(STARVATION_LOAD),
                settle_us: Some(SETTLE_US),
            }),
            vec![record.clone(), snap.clone()],
            BACKOFF_US,
        ),
        // Endpoint-dial-stall (realm net-observer, node #62). No pcap freeze:
        // the evidence is sing-box's own test gone absent beside the
        // endpoint's TCP verdict. The threshold is two of sing-box's URLTest
        // intervals plus slack — the interval is config, and must match
        // sing-box's. Gated like the other fault signatures — a test that
        // fails with the uplink, under starvation or in the settle window
        // after a move measures those, not sing-box.
        Trigger::new(
            Box::new(Gated {
                inner: EndpointDialStall::new(Duration::from_secs(
                    cfg.collectors.proxy.urltest_interval_secs,
                )),
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

        // One entry per `AnyCollector` variant, by the collector's own metadata —
        // all but `announce`, which produces no kind of its own: its samples are
        // `Sample::Neighbors`, declared under `neighbors`, and its supervisor
        // starts it under that same switch (`neighbors.announce`).
        let spawnable: Vec<&'static str> = vec![
            collector_link::META.name,
            collector_proxy::META.name,
            collector_dns::META.name,
            collector_route::META.name,
            collector_host::META.name,
            collector_wifi::META.name,
            collector_neighbors::META.name,
            collector_air::META.name,
            collector_connections::META.name,
            collector_singbox_log::META.name,
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
        // Not a collector, and deliberately never declared as one — nor is
        // the close of one.
        assert_eq!(
            snap.collector(EventKind::Incident),
            CollectorAvailability::Absent
        );
        assert_eq!(
            snap.collector(EventKind::IncidentClosed),
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

    /// `run_topology_capture` is the ONE body the patrol and a forced
    /// `scan topology` share: it must write the record AND mirror the live
    /// snapshot the socket serves, so a forced capture reaches the bar's map at
    /// once, not only on the next patrol tick (realm net-observer, node #43). A
    /// later capture that hears nothing must leave the last set in place, never
    /// blank it.
    #[test]
    fn run_topology_capture_writes_the_store_and_mirrors_the_snapshot() {
        /// A fake LLDP capture returning canned raw ethernet frames — no
        /// tcpdump, no root.
        struct FakeCapture(Vec<Vec<u8>>);
        impl LldpCapture for FakeCapture {
            fn capture(&self, _budget: Duration) -> Vec<Vec<u8>> {
                self.0.clone()
            }
        }

        // One synthetic LLDP frame `types::link_from_frame` maps to an edge:
        // chassis 00:11:22:33:44:55, port "Gi0/1" — the same PDU the types
        // crate's own decode tests build (eth header + LLDP EtherType + LLDPDU).
        let frame: Vec<u8> = vec![
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, // dst: LLDP multicast
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x88, 0xcc, // EtherType: LLDP
            0x02, 0x07, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // chassis id: MAC
            0x04, 0x06, 0x05, b'G', b'i', b'0', b'/', b'1', // port id: "Gi0/1"
            0x06, 0x02, 0x00, 0x78, // ttl: 120
            0x0e, 0x04, 0x00, 0x04, 0x00, 0x04, // system capabilities
            0x0a, 0x03, b's', b'w', b'1', // system name: "sw1"
            0x00, 0x00, // end
        ];

        let store = DuckdbStore::in_memory().unwrap();
        let snapshot = Mutex::new(StatusSnapshot::default());

        let found = run_topology_capture(&FakeCapture(vec![frame]), &store, &snapshot, "en0", 100);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].remote_chassis, "00:11:22:33:44:55");

        // The durable record has the row...
        assert_eq!(
            store
                .query_scalar_i64("SELECT count(*) FROM topology_link")
                .unwrap(),
            1,
            "the capture must write the uplink to the record"
        );
        // ...and the live snapshot mirrors it for the socket and the bar's map.
        {
            let snap = snapshot.lock().unwrap();
            assert_eq!(
                snap.topology.len(),
                1,
                "the snapshot must mirror the uplink"
            );
            assert_eq!(snap.topology[0].remote_chassis, "00:11:22:33:44:55");
        }

        // A capture that hears nothing must NOT blank the last discovered set.
        let none = run_topology_capture(&FakeCapture(vec![]), &store, &snapshot, "en0", 200);
        assert!(none.is_empty());
        let snap = snapshot.lock().unwrap();
        assert_eq!(
            snap.topology.len(),
            1,
            "an empty capture must leave the last set in place, not blank it"
        );
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

    /// A blocking event source that ends when the test drops its feeding end —
    /// the announce stream ending when its `tcpdump` child dies.
    struct EndsWhenDropped(std::sync::mpsc::Receiver<Vec<Sample>>);
    impl EventSource for EndsWhenDropped {
        fn next(&mut self) -> Option<Vec<Sample>> {
            self.0.recv().ok()
        }
    }

    /// The defect this branch closes (realm net-observer, node #134): no
    /// interface at boot must not leave the announce listener unstarted for the
    /// life of the process, and a listener whose stream ended must be started
    /// again. Driven with fakes (no `tcpdump`, no root) through the REAL
    /// `spawn_event_collector`, so the handle the supervisor awaits is the one
    /// production hands it: the interface is absent for the first attempts and
    /// present afterwards; the listener must start exactly once, forward what
    /// its stream yields, be left alone while the stream is open, and be
    /// started again — after the interval — once the stream ends.
    ///
    /// Dies under: returning early instead of looping, starting with no
    /// interface, restarting an open stream, an event-spawner handle that
    /// completes before the source ends, or a restart with no interval.
    #[tokio::test]
    async fn the_listener_starts_by_itself_once_an_interface_appears_and_again_when_it_ends() {
        use std::sync::atomic::Ordering::{Acquire, Release};

        let iface_up = Arc::new(AtomicBool::new(false));
        let resolves = Arc::new(AtomicI64::new(0));
        let starts = Arc::new(AtomicI64::new(0));
        // One stream per start; the test holds the feeding end of each, so it
        // decides when a stream ends.
        let feeds: Arc<Mutex<Vec<std::sync::mpsc::Sender<Vec<Sample>>>>> = Arc::default();
        let (tx, mut rx) = mpsc::channel::<Sample>(16);
        let observing = Arc::new(AtomicBool::new(true));

        let task = {
            let (iface_up, resolves, starts, feeds) = (
                iface_up.clone(),
                resolves.clone(),
                starts.clone(),
                feeds.clone(),
            );
            tokio::spawn(async move {
                supervise_on_iface(
                    "announce",
                    TEST_PATROL,
                    move || {
                        resolves.fetch_add(1, Release);
                        let up = iface_up.load(Acquire);
                        async move { up.then(|| "en0".to_string()) }
                    },
                    move |_iface| {
                        starts.fetch_add(1, Release);
                        let (feed, batches) = std::sync::mpsc::channel();
                        feeds.lock().unwrap().push(feed);
                        let c = AnyCollector::Announce(AnnounceCollector::new(
                            Box::new(EndsWhenDropped(batches)),
                            Readiness::Ready,
                        ));
                        Ok(spawn_event_collector(c, tx.clone(), observing.clone()))
                    },
                )
                .await;
            })
        };

        // Several attempts with no interface: nothing started.
        wait_until("two resolutions with no interface", || {
            resolves.load(Acquire) >= 2
        })
        .await;
        assert_eq!(
            starts.load(Acquire),
            0,
            "the supervisor must not start a listener with no interface to capture on"
        );

        iface_up.store(true, Release);
        wait_until("the listener to start on its own", || {
            starts.load(Acquire) == 1
        })
        .await;

        // Driven by the real event spawner: what its stream yields reaches the
        // consumer.
        feeds.lock().unwrap()[0]
            .send(vec![link(1, GwVerdict::Ok)])
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the started listener forwards within 5s")
            .expect("channel open");
        assert!(matches!(got, Sample::Link(_)), "{got:?}");

        // An open stream is left alone: no churn of tcpdump children.
        tokio::time::sleep(TEST_PATROL * 5).await;
        assert_eq!(
            starts.load(Acquire),
            1,
            "a running listener must not be restarted every patrol"
        );

        // The stream ends (the child died): a new listener is started, after
        // the interval rather than at once, and it forwards too.
        let ended_at = Instant::now();
        drop(feeds.lock().unwrap().remove(0));
        wait_until("the listener to be started again", || {
            starts.load(Acquire) == 2
        })
        .await;
        assert!(
            ended_at.elapsed() >= TEST_PATROL,
            "a restart waits the interval; it must not respawn tcpdump at once"
        );
        feeds.lock().unwrap()[0]
            .send(vec![link(2, GwVerdict::Ok)])
            .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the restarted listener forwards within 5s")
            .expect("channel open");
        assert!(
            matches!(got, Sample::Link(ref l) if l.ts_us == 2),
            "{got:?}"
        );
        task.abort();
    }

    /// Shutdown: `abort_all` aborts the supervisor, and the TOKIO task it was
    /// awaiting must be aborted with it — the topology patrol's case, which
    /// would otherwise keep opening captures after the daemon had stopped its
    /// collectors. This proves nothing about the listener's threads or its
    /// `tcpdump` child: those are detached and run until process exit, and the
    /// abort reaches only the oneshot bridge in front of them.
    ///
    /// Dies under: awaiting a bare `JoinHandle` (dropping one detaches the task).
    #[tokio::test]
    async fn aborting_the_supervisor_aborts_the_capture_it_awaits() {
        use std::sync::atomic::Ordering::{Acquire, Release};

        /// Set when the capture task's future is dropped — which an abort does.
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Release);
            }
        }

        let started = Arc::new(AtomicBool::new(false));
        let capture_dropped = Arc::new(AtomicBool::new(false));
        let task = {
            let (started, capture_dropped) = (started.clone(), capture_dropped.clone());
            tokio::spawn(async move {
                supervise_on_iface(
                    "topology",
                    TEST_PATROL,
                    || async { Some("en0".to_string()) },
                    move |_iface| {
                        started.store(true, Release);
                        let guard = SetOnDrop(capture_dropped.clone());
                        // A patrol: never ends on its own.
                        Ok(tokio::spawn(async move {
                            let _guard = guard;
                            std::future::pending::<()>().await;
                        }))
                    },
                )
                .await;
            })
        };

        wait_until("the capture to start", || started.load(Acquire)).await;
        tokio::time::sleep(TEST_PATROL * 5).await;
        assert!(
            !capture_dropped.load(Acquire),
            "a running capture is left alone"
        );

        task.abort();
        wait_until("the capture to be aborted with its supervisor", || {
            capture_dropped.load(Acquire)
        })
        .await;
    }

    /// A config whose only deviations from the shipped defaults are the ones the
    /// wiring assertions read back — so a hardcoded literal in
    /// [`build_api_server`] cannot coincide with the value under test. Nothing
    /// here is ever opened: the socket is never bound (no `serve()`), and
    /// `FakeFreezer` plus `FreezePcapHandler::on_fire` only *join* `blob_dir`.
    fn test_cfg() -> Config {
        Config {
            socket_path: "/tmp/net-observerd-wiring-test.sock".into(),
            // Deliberately NOT the shipped 0o660 / staff: a hardcoded default
            // dies here.
            socket_mode: 0o600,
            socket_owner_uid: Some(4242),
            socket_gid: Some(4243),
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
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
            urltest_absent_since_us: None,
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
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
            urltest_absent_since_us: None,
        })
    }

    /// A healthy proxy tick carrying sing-box's own URL-test reading of the
    /// traffic-carrying node (realm net-observer, node #62): the row of that
    /// node's endpoint, its TCP fine, the tun fine, no entry, and the
    /// absence dated as given — the endpoint-dial-stall shape (the other
    /// builders pin the urltest fields to `None`).
    fn untested_proxy(ts_us: i64, urltest_absent_since_us: i64) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us,
            server_ip: "1.1.1.1:443".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: Some("vless-out-6".into()),
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: Some("vless-out-6".into()),
            urltest_absent_since_us: Some(urltest_absent_since_us),
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
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
            urltest_absent_since_us: None,
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
    /// Dies under any of: a hardcoded socket field (`socket_mode: 0o660`,
    /// `socket_owner_uid: None`, `socket_gid: Some(20)`, `enabled: false`);
    /// dropping `cfg.control_uids`
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
        let session_end_us = Arc::new(AtomicI64::new(0));
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
            session_end_us.clone(),
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

        // The egress scanner is wired unconditionally too (realm net-observer,
        // node #170): whether there is anything to capture is decided per
        // request, not once at boot.
        assert!(
            srv.egress_scanner.is_some(),
            "the egress scan command must have something to call"
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
            srv.socket_gid, cfg.socket_gid,
            "the socket must be chowned to the configured group"
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
            Arc::ptr_eq(&srv.session_end_us, &session_end_us),
            "a fresh `session_end_us` leaves the pipeline closing a pre-pause \
             incident at the resume's ts_us instead of the pause's own"
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

    /// The `singbox-no-route` rule is installed with the production handlers,
    /// and without a direct-path gate: the passive tier's shape — the echo
    /// withheld (`Skip`), the DHCP router held — plus three `no route` lines
    /// from sing-box's log records the incident. Nothing else in the rule set
    /// fires on this stream: the gateway is `Skip` throughout (no drop, no
    /// change), and there is no proxy, DNS or neighbours sample.
    #[test]
    fn build_engine_registers_the_singbox_no_route_rule() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(8);

        let Sample::Link(mut l) = link(1, GwVerdict::Skip) else {
            unreachable!("link() builds a link sample")
        };
        l.direct = TcpVerdict::Skip;
        l.dhcp_router = Some("10.20.0.1".into());
        feed(&mut fx.engine, &mut w, Sample::Link(l));
        feed(
            &mut fx.engine,
            &mut w,
            Sample::SingboxLog(types::SingboxLogSample {
                ts_us: 2,
                class: types::SingboxLogClass::NoRoute,
                count: 3,
                node: Some("vless-out-6".into()),
                sample_message: None,
            }),
        );
        assert_eq!(
            incidents_for(&fx.store, "singbox-no-route"),
            1,
            "sing-box reporting no route while the link holds a router must be recorded as singbox-no-route"
        );
    }

    /// The `endpoint-dial-stall` rule the daemon actually runs takes its
    /// threshold from the config's `urltest_interval_secs` — the default
    /// 180 s, so 2 × 180 + 30 = 390 s of absence: an absence of 389 s stays
    /// silent, one of 390 s fires. The seconds are LITERALS on purpose —
    /// this test IS the wiring's pin, like the wedge pin above; a config
    /// default that moves must move it too, and it says so when it reds.
    ///
    /// Nothing else fires on this stream: the tun is healthy, the endpoint
    /// answers, the gateway is steadily OK, no DNS, host or neighbors sample.
    #[test]
    fn build_engine_wires_the_production_dial_stall_threshold() {
        let mut fx = engine_under_test(Arc::new(PcapRingSlot::empty()));
        let mut w = RecentWindow::new(8);
        feed(&mut fx.engine, &mut w, link(0, GwVerdict::Ok));
        feed(&mut fx.engine, &mut w, untested_proxy(389_000_000, 0));
        assert_eq!(
            incidents_for(&fx.store, "endpoint-dial-stall"),
            0,
            "389 s of absence is one short of 2 x urltest_interval_secs + 30 s"
        );
        feed(&mut fx.engine, &mut w, untested_proxy(390_000_000, 0));
        assert_eq!(
            incidents_for(&fx.store, "endpoint-dial-stall"),
            1,
            "390 s of absence over a live listener must be recorded as endpoint-dial-stall"
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

    /// A `[record]` section as `retention_plan` reads it.
    fn record(days: u32, tables: &[&str]) -> config::RecordCfg {
        config::RecordCfg {
            retention_days: days,
            retention_tables: tables.iter().map(|t| (*t).to_string()).collect(),
        }
    }

    /// A name outside `store::PRUNABLE_TABLES` — here one the gap derivation
    /// reads, and one evidence table — is an error naming the table, and it
    /// is one whether or not a window is set: an inert list is still a config
    /// error, as an unknown probing tier is (realm net-observer, node #130).
    #[test]
    fn retention_plan_refuses_a_table_outside_the_prunable_list_and_names_it() {
        let err = retention_plan(&record(7, &["link_sample"]))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("`link_sample` is not a prunable table"),
            "{err}"
        );
        let err = retention_plan(&record(0, &["incident"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("`incident`"), "{err}");
    }

    /// Keep-forever (`retention_days = 0`) and a window over no tables are
    /// both no plan at all: nothing is pruned and no sweep is spawned.
    #[test]
    fn retention_plan_is_none_for_keep_forever_and_for_an_empty_list() {
        assert!(
            retention_plan(&record(0, &["connection_sample"]))
                .unwrap()
                .is_none()
        );
        assert!(retention_plan(&record(7, &[])).unwrap().is_none());
    }

    /// A table named twice is pruned once; naming either half of the air
    /// slice names both, appended after the configured names; a list with
    /// neither half gains nothing.
    #[test]
    fn retention_plan_folds_duplicates_and_makes_the_air_slice_whole() {
        let plan = retention_plan(&record(
            7,
            &["air_ap", "connection_sample", "connection_sample"],
        ))
        .unwrap()
        .expect("a window over a list is a plan");
        assert_eq!(plan.retention_days, 7);
        assert_eq!(
            plan.retention_tables,
            ["air_ap", "connection_sample", "air_sample"]
        );
        let plan = retention_plan(&record(7, &["wifi_sample"]))
            .unwrap()
            .unwrap();
        assert_eq!(plan.retention_tables, ["wifi_sample"]);
    }

    // ── record access (realm net-observer, node #110) ───────────────────────

    /// The directory keeps its own bits and gains setgid; the file-type bits
    /// `st_mode` carries (`S_IFDIR`) are dropped, and a bit already set stays
    /// set — `chmod(2)` takes permission bits only.
    #[test]
    fn with_setgid_keeps_the_bits_and_drops_the_file_type() {
        assert_eq!(with_setgid(0o755), 0o2755);
        assert_eq!(with_setgid(0o040755), 0o2755);
        assert_eq!(with_setgid(0o042750), 0o2750);
        assert_eq!(with_setgid(0o040_000), 0o2000);
    }

    /// DuckDB's WAL is the record's full name plus `.wal`, so the record's
    /// own extension is kept, not replaced.
    #[test]
    fn wal_path_appends_to_the_full_record_name() {
        assert_eq!(
            wal_path(Path::new("/var/lib/observer/observer.duckdb")),
            PathBuf::from("/var/lib/observer/observer.duckdb.wal")
        );
        assert_eq!(
            wal_path(Path::new("observer")),
            PathBuf::from("observer.wal")
        );
    }

    /// The access pass on a real temporary record: the file and a WAL beside
    /// it take the mode, the directory takes setgid on top of its own bits, a
    /// missing WAL is skipped, and nothing is fatal. The group is left as it
    /// is (`None`): a test process is not root and owns no other group.
    #[test]
    fn restrict_record_access_sets_the_modes_and_the_setgid_dir() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("observer.duckdb");
        std::fs::write(&db, b"").unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        restrict_record_access(&db, None, 0o640);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode(&db), 0o640);
        assert_eq!(mode(dir.path()), 0o2755);

        let wal = wal_path(&db);
        std::fs::write(&wal, b"").unwrap();
        std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();
        restrict_record_access(&db, None, 0o600);
        assert_eq!(mode(&db), 0o600);
        assert_eq!(mode(&wal), 0o600);

        // A record whose directory cannot be read is a warning, not a panic.
        restrict_record_access(
            Path::new("/nonexistent/net-observerd/observer.duckdb"),
            None,
            0o640,
        );
    }

    /// The blob tree: the directory and an existing `ring/` take setgid on
    /// top of their bits, a missing `ring/` is skipped, a missing blob dir is
    /// a warning and not a panic. A ring file an earlier build left there
    /// takes the record's mode — `tcpdump` reopens it by truncation and would
    /// otherwise leave it world-readable for good — while a file that is not
    /// the ring's keeps its bits.
    #[test]
    fn restrict_blob_access_sets_setgid_on_the_tree_and_remodes_the_ring_files() {
        let blobs = tempfile::tempdir().unwrap();
        std::fs::set_permissions(blobs.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;

        restrict_blob_access(blobs.path(), None, 0o640);
        assert_eq!(mode(blobs.path()), 0o2755);

        let ring = blobs.path().join("ring");
        std::fs::create_dir(&ring).unwrap();
        std::fs::set_permissions(&ring, std::fs::Permissions::from_mode(0o750)).unwrap();
        let old = ring.join("ring.pcap0");
        std::fs::write(&old, b"").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
        let other = ring.join("notes.txt");
        std::fs::write(&other, b"").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o644)).unwrap();
        restrict_blob_access(blobs.path(), None, 0o640);
        assert_eq!(mode(&ring), 0o2750);
        assert_eq!(
            mode(&old),
            0o640,
            "a ring file from an earlier build takes the record's mode"
        );
        assert_eq!(
            mode(&other),
            0o644,
            "a file that is not the ring's is left alone"
        );

        restrict_blob_access(Path::new("/nonexistent/net-observerd/blobs"), None, 0o640);
    }

    /// Every freeze takes the record's own group and mode, read from the
    /// config — a literal here would let `record_mode` stop at the record.
    #[test]
    fn freeze_access_is_the_records() {
        let cfg = Config {
            record_gid: Some(4243),
            record_mode: 0o600,
            ..Config::default()
        };
        assert_eq!(
            freeze_access(&cfg),
            FreezeAccess {
                gid: Some(4243),
                mode: 0o600
            }
        );
    }

    /// Write a minimal CVE snapshot (one matching record, no `kev.json`) into a
    /// fresh temp directory, in exactly the layout `VulnDb::load_from_dir`
    /// expects. Mirrors `pipeline::tests::write_fixture_snapshot`; kept local
    /// rather than shared because each module's fixture only needs to be
    /// obviously right for its own asserts, not reused across crates' test
    /// boundaries.
    fn write_cve_fixture_snapshot() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let cve_dir = dir.path().join("cves/2016/6xxx");
        std::fs::create_dir_all(&cve_dir).unwrap();
        std::fs::write(
            cve_dir.join("CVE-2016-6210.json"),
            r#"{
  "cveMetadata": { "cveId": "CVE-2016-6210", "state": "PUBLISHED" },
  "containers": { "cna": {
    "title": "OpenSSH user enumeration",
    "affected": [ { "vendor": "openbsd", "product": "openssh",
      "versions": [ { "version": "7.2", "status": "affected", "lessThan": "7.4", "versionType": "custom" } ] } ]
  } }
}"#,
        )
        .unwrap();
        dir
    }

    fn cve_port_with_banner(banner: &str) -> store::NeighborPort {
        store::NeighborPort {
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            mac: "11:22:33:44:55:66".into(),
            ip: "192.168.1.5".into(),
            port: 22,
            ts_us: 42,
            banner: Some(banner.to_string()),
        }
    }

    /// `load_and_classify` with no directory configured reproduces the exact
    /// note the inline match used to produce — the seam moved, the wording did
    /// not.
    #[test]
    fn load_and_classify_notes_a_missing_directory_configuration() {
        match load_and_classify(None) {
            CveSnapshot::Unusable(note) => {
                assert_eq!(note, "cve rung ran without a snapshot directory");
            }
            CveSnapshot::Ready(_) => panic!("no directory configured must never be Ready"),
        }
    }

    /// A directory that does not exist fails `VulnDb::load_from_dir` —
    /// `load_and_classify` must classify that as `Unusable` with the
    /// "failed to load" wording, not panic or silently produce `Ready`.
    #[test]
    fn load_and_classify_notes_a_load_error() {
        let missing = tempfile::tempdir().unwrap().path().join("gone");
        match load_and_classify(Some(&missing)) {
            CveSnapshot::Unusable(note) => {
                assert!(note.contains("failed to load"), "{note:?}");
                assert!(note.contains("findings NOT checked"), "{note:?}");
            }
            CveSnapshot::Ready(_) => panic!("a missing directory must never be Ready"),
        }
    }

    /// An existing-but-empty directory loads cleanly but yields an empty
    /// index — `load_and_classify` must still call that `Unusable`, so an
    /// empty result is never mistaken for a clean "no vulnerabilities".
    #[test]
    fn load_and_classify_notes_an_empty_snapshot() {
        let empty = tempfile::tempdir().unwrap();
        match load_and_classify(Some(empty.path())) {
            CveSnapshot::Unusable(note) => {
                assert!(note.contains("empty or wrong layout"), "{note:?}");
                assert!(
                    note.contains("not a clean 'no vulnerabilities'"),
                    "{note:?}"
                );
            }
            CveSnapshot::Ready(_) => panic!("an empty snapshot must never be Ready"),
        }
    }

    /// A populated, well-formed snapshot classifies as `Ready`.
    #[test]
    fn load_and_classify_is_ready_for_a_populated_snapshot() {
        let dir = write_cve_fixture_snapshot();
        match load_and_classify(Some(dir.path())) {
            CveSnapshot::Ready(db) => assert_eq!(db.len(), 1),
            CveSnapshot::Unusable(note) => panic!("fixture snapshot must load: {note}"),
        }
    }

    /// The load-once cache (realm net-observer, node #158): two `--cve` runs
    /// through `SystemScanner::cve_rung` against a GOOD snapshot must reuse
    /// the SAME loaded index — proven here by pointer identity on the cached
    /// `Arc<VulnDb>`, which can only match if the second call read the
    /// `OnceLock` instead of calling `VulnDb::load_from_dir` again. Both calls
    /// also return identical findings, and the cache is populated after the
    /// first.
    #[test]
    fn the_cve_snapshot_loads_once_and_is_cached_across_scans() {
        let dir = write_cve_fixture_snapshot();
        let scanner =
            SystemScanner::new(SystemFacts::new(None, None), Some(dir.path().into()), None);
        let ports = vec![cve_port_with_banner("SSH-2.0-OpenSSH_7.3")];

        assert!(
            scanner.cve_cache.get().is_none(),
            "the cache must be empty before the first --cve scan"
        );

        let (first_vulns, first_note) = scanner.cve_rung(&ports, 1_000);
        assert!(first_note.is_none(), "{first_note:?}");
        assert_eq!(first_vulns.len(), 1, "the 7.3 banner falls inside <7.4");

        let first_ptr = Arc::as_ptr(
            scanner
                .cve_cache
                .get()
                .expect("a successful load must populate the cache"),
        );

        let (second_vulns, second_note) = scanner.cve_rung(&ports, 2_000);
        assert!(second_note.is_none(), "{second_note:?}");
        assert_eq!(
            second_vulns.len(),
            first_vulns.len(),
            "a second scan must see the same findings as the first"
        );

        let second_ptr = Arc::as_ptr(scanner.cve_cache.get().unwrap());
        assert_eq!(
            first_ptr, second_ptr,
            "the second scan must reuse the SAME loaded snapshot, not reload it"
        );
    }

    /// The regression this cache must NOT reintroduce: caching a transient
    /// load failure would permanently disable CVE checking for the daemon's
    /// whole life after one bad scan (v1 has no watchdog to self-heal). An
    /// `Unusable` outcome (here: no directory configured) must leave the cell
    /// empty, so the next `--cve` scan retries the load rather than reading a
    /// frozen failure.
    #[test]
    fn an_unusable_cve_outcome_is_not_cached_so_the_next_scan_retries() {
        let scanner = SystemScanner::new(SystemFacts::new(None, None), None, None);
        let ports = vec![cve_port_with_banner("SSH-2.0-OpenSSH_7.3")];

        let (first_vulns, first_note) = scanner.cve_rung(&ports, 1_000);
        assert!(first_vulns.is_empty());
        assert_eq!(
            first_note.as_deref(),
            Some("cve rung ran without a snapshot directory")
        );
        assert!(
            scanner.cve_cache.get().is_none(),
            "an unusable outcome must not latch the cache — the next scan has to retry"
        );

        // A second scan against the same unchanged (still missing) directory
        // reaches `load_and_classify` again and reports the same note —
        // proving the retry actually happens rather than the cache silently
        // absorbing it.
        let (second_vulns, second_note) = scanner.cve_rung(&ports, 2_000);
        assert!(second_vulns.is_empty());
        assert_eq!(first_note, second_note);
        assert!(scanner.cve_cache.get().is_none());
    }

    /// The other half of the same guarantee: a `Ready` outcome DOES set the
    /// cell (proven independently of the identity check above, which only
    /// exercises the already-cached path).
    #[test]
    fn a_ready_cve_outcome_sets_the_cache() {
        let dir = write_cve_fixture_snapshot();
        let scanner =
            SystemScanner::new(SystemFacts::new(None, None), Some(dir.path().into()), None);

        assert!(scanner.cve_cache.get().is_none());
        let (vulns, note) = scanner.cve_rung(&[], 1_000);
        assert!(note.is_none(), "{note:?}");
        assert!(
            vulns.is_empty(),
            "no ports means no findings, but no error either"
        );
        assert!(
            scanner.cve_cache.get().is_some(),
            "a successful load must set the cache even with nothing to match"
        );
    }

    /// The load-once cache, proven for `cve_lookup` (`check-cve --product`)
    /// instead of `cve_rung`: two lookups against a GOOD snapshot must reuse
    /// the SAME loaded index — pointer identity on the cached `Arc<VulnDb>`
    /// can only match if the second call read the `OnceLock` instead of
    /// calling `VulnDb::load_from_dir` again. This is the test the "no
    /// 395k-file reload per lookup" claim on `cve_lookup`'s doc actually
    /// rests on; without it, a future edit could reintroduce a per-lookup
    /// reload with nothing here to catch it.
    #[test]
    fn cve_lookup_loads_once_and_is_cached_across_lookups() {
        let dir = write_cve_fixture_snapshot();
        let scanner =
            SystemScanner::new(SystemFacts::new(None, None), Some(dir.path().into()), None);

        assert!(
            scanner.cve_cache.get().is_none(),
            "the cache must be empty before the first lookup"
        );

        let first_len = match scanner.cve_lookup("openssh", Some("7.3")) {
            CveLookupOutcome::Matches(m) => m.len(),
            CveLookupOutcome::SnapshotUnavailable(note) => {
                panic!("fixture snapshot must load: {note}")
            }
        };
        assert_eq!(first_len, 1, "7.3 falls inside the fixture's <7.4 range");

        let first_ptr = Arc::as_ptr(
            scanner
                .cve_cache
                .get()
                .expect("a successful load must populate the cache"),
        );

        let second_len = match scanner.cve_lookup("openssh", Some("7.3")) {
            CveLookupOutcome::Matches(m) => m.len(),
            CveLookupOutcome::SnapshotUnavailable(note) => {
                panic!("a cached lookup must not fail: {note}")
            }
        };
        assert_eq!(
            second_len, first_len,
            "a second lookup must see the same findings as the first"
        );

        let second_ptr = Arc::as_ptr(scanner.cve_cache.get().unwrap());
        assert_eq!(
            first_ptr, second_ptr,
            "the second lookup must reuse the SAME loaded snapshot, not reload it"
        );
    }

    /// Cross-method cache sharing — half of `cve_lookup`'s doc claim
    /// ("whichever asks first loads... every call after — lookup or scan —
    /// answers from memory"): `cve_rung` primes the cache first, and
    /// `cve_lookup` must then reuse the SAME `Arc` rather than reload.
    #[test]
    fn cve_rung_primes_the_cache_and_cve_lookup_reuses_it() {
        let dir = write_cve_fixture_snapshot();
        let scanner =
            SystemScanner::new(SystemFacts::new(None, None), Some(dir.path().into()), None);
        let ports = vec![cve_port_with_banner("SSH-2.0-OpenSSH_7.3")];

        let (vulns, note) = scanner.cve_rung(&ports, 1_000);
        assert!(note.is_none(), "{note:?}");
        assert_eq!(vulns.len(), 1);
        let rung_ptr = Arc::as_ptr(
            scanner
                .cve_cache
                .get()
                .expect("cve_rung's successful load must populate the cache"),
        );

        let lookup_len = match scanner.cve_lookup("openssh", Some("7.3")) {
            CveLookupOutcome::Matches(m) => m.len(),
            CveLookupOutcome::SnapshotUnavailable(n) => {
                panic!("a cached lookup must not fail: {n}")
            }
        };
        assert_eq!(lookup_len, 1);
        let lookup_ptr = Arc::as_ptr(scanner.cve_cache.get().unwrap());
        assert_eq!(
            rung_ptr, lookup_ptr,
            "cve_lookup must reuse the snapshot cve_rung already loaded, not reload it"
        );
    }

    /// The other direction of the same claim: `cve_lookup` primes the cache
    /// first, and `cve_rung` (an ordinary scan's own `cve` rung) reuses the
    /// SAME loaded snapshot rather than reload it.
    #[test]
    fn cve_lookup_primes_the_cache_and_cve_rung_reuses_it() {
        let dir = write_cve_fixture_snapshot();
        let scanner =
            SystemScanner::new(SystemFacts::new(None, None), Some(dir.path().into()), None);
        let ports = vec![cve_port_with_banner("SSH-2.0-OpenSSH_7.3")];

        let lookup_len = match scanner.cve_lookup("openssh", Some("7.3")) {
            CveLookupOutcome::Matches(m) => m.len(),
            CveLookupOutcome::SnapshotUnavailable(n) => {
                panic!("fixture snapshot must load: {n}")
            }
        };
        assert_eq!(lookup_len, 1);
        let lookup_ptr = Arc::as_ptr(
            scanner
                .cve_cache
                .get()
                .expect("cve_lookup's successful load must populate the cache"),
        );

        let (vulns, note) = scanner.cve_rung(&ports, 1_000);
        assert!(note.is_none(), "{note:?}");
        assert_eq!(vulns.len(), 1);
        let rung_ptr = Arc::as_ptr(scanner.cve_cache.get().unwrap());
        assert_eq!(
            lookup_ptr, rung_ptr,
            "cve_rung must reuse the snapshot cve_lookup already loaded, not reload it"
        );
    }

    /// The same non-latching guarantee as
    /// `an_unusable_cve_outcome_is_not_cached_so_the_next_scan_retries`, for
    /// `cve_lookup`: a lookup against a scanner with no snapshot directory
    /// configured must not cache the `Unusable` outcome, so the next lookup
    /// retries rather than reading a frozen failure forever (v1 has no
    /// watchdog to self-heal).
    #[test]
    fn an_unusable_cve_lookup_is_not_cached_so_the_next_lookup_retries() {
        let scanner = SystemScanner::new(SystemFacts::new(None, None), None, None);

        let first_note = match scanner.cve_lookup("openssh", Some("7.3")) {
            CveLookupOutcome::SnapshotUnavailable(note) => note,
            CveLookupOutcome::Matches(m) => {
                panic!("no directory configured must never match: {m:?}")
            }
        };
        assert_eq!(first_note, "cve rung ran without a snapshot directory");
        assert!(
            scanner.cve_cache.get().is_none(),
            "an unusable outcome must not latch the cache — the next lookup has to retry"
        );

        // A second lookup against the same unchanged (still missing)
        // directory reaches `load_and_classify` again and reports the same
        // note — proving the retry actually happens rather than the cache
        // silently absorbing it.
        let second_note = match scanner.cve_lookup("openssh", Some("7.3")) {
            CveLookupOutcome::SnapshotUnavailable(note) => note,
            CveLookupOutcome::Matches(m) => {
                panic!("no directory configured must never match: {m:?}")
            }
        };
        assert_eq!(first_note, second_note);
        assert!(scanner.cve_cache.get().is_none());
    }
}
