//! `net-observer-cli` — an unprivileged reader for the observer store.
//!
//! `net-observerd` is the **sole owner** of the DuckDB file: DuckDB takes a
//! per-process file lock, so a second opener (even read-only) is blocked while
//! the daemon runs. This CLI therefore splits into two access paths:
//!
//! - **LIVE** — `status` and `incidents` read the daemon's in-memory snapshot
//!   over its Unix-domain socket (`net-observer-ipc`). No DB is opened, so there is
//!   zero contention with the running daemon.
//! - **LIVE FIRST, THEN OFFLINE** — the named diagnoses (`why`,
//!   `incident-context`, `wedge-or-starvation`, `gateway-ramp`, `gaps`,
//!   `neighbors`, `vulns`, `segments`, `history`, `topology`, `connections`,
//!   `air`) run the canned
//!   `store::diagnosis` queries, so "which layer failed" is reachable without
//!   writing SQL. Each asks the running daemon first (`Request::Query`, answered
//!   from the daemon's own store while it keeps collecting) and opens the
//!   DuckDB file itself only when no daemon answers on the socket — unless the
//!   operator gave `--db`, which names the record and means the socket is not
//!   asked at all. Every diagnosis prints which record answered (`source:` on
//!   stderr). See [`route`] for the exact rule. `air` is three reads pinned to
//!   one moment: [`route_air`] decides live-or-file once, from the scan, and
//!   reuses that choice for the other two — a daemon that answers the scan
//!   and then fails or cannot decode one of them is a hard error, never a
//!   silent detour to the file, which would risk mixing a live table with a
//!   stale one. (realm net-observer, node #58)
//! - **OFFLINE** — `query <SQL>` opens the DuckDB file directly. This
//!   only works while the daemon is stopped; if `net-observerd` is running it
//!   holds the lock and the open fails with a clear message rather than a panic.

mod diagnose;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use config::Config;
use net_observer_ipc::{
    ControlCmd, ControlResult, DiagnosticQuery, EXPERIMENT_DEFAULT_MINUTES, EventKind,
    IncidentSummary, QueryOutcome, Request, Response, ScanOptions, StatusSnapshot, StreamFrame,
    Table,
};
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;
use store::{DuckdbStore, QueryTable, Store as _, diagnosis};
use types::{ConnectionScope, ConnectionsGroupBy, ProbingTier};

/// The `load1` above which a dead tun reads as host starvation rather than a
/// proxy wedge. The CLI reads the record with the same threshold the daemon
/// judges it by, rather than offering a dial that would let two readings of one
/// record disagree.
const LOAD_THRESHOLD: f64 = diagnosis::DEFAULT_STARVATION_LOAD;

#[derive(Parser)]
#[command(
    name = "net-observer-cli",
    about = "Query the net-observer store (live via socket, offline via SQL)"
)]
struct Cli {
    /// Optional path to the observer config file (TOML). Supplies the daemon
    /// socket path for every command that talks to the running daemon.
    #[arg(long)]
    config: Option<String>,
    /// Path to the observer DuckDB file [default: the `db_path` of the daemon config].
    /// Giving it means "read this file": the diagnoses then never ask the
    /// daemon's socket. Without it they ask the running daemon first and read
    /// the config's file only when nothing answers on the socket. `query <SQL>`
    /// always reads the file. Every diagnosis prints which record
    /// answered as a `source:` line on stderr.
    #[arg(long)]
    db: Option<String>,
    #[command(subcommand)]
    command: Command,
}

/// The record a command reads, and the socket to ask first when the operator
/// did not name the record — both from the same place.
///
/// `--db` names the file outright and leaves `socket` empty: nothing is asked.
/// Without it the daemon config is loaded and supplies both the socket and
/// the file (`db_path`), so the fallback is the file the daemon writes, not a
/// literal of this binary's own that could drift from it.
struct Record {
    socket: Option<String>,
    db_path: String,
}

impl Record {
    fn resolve(cli: &Cli) -> Result<Self> {
        match &cli.db {
            Some(db) => Ok(Self {
                socket: None,
                db_path: db.clone(),
            }),
            None => {
                let cfg = load_config(cli)?;
                Ok(Self {
                    socket: Some(cfg.socket_path),
                    db_path: cfg.db_path,
                })
            }
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Show the live status snapshot (latest sample per collector + incidents),
    /// read from the running daemon over its socket.
    Status,
    /// List recent incidents, newest first, read live from the daemon socket.
    Incidents {
        /// Maximum number of incidents to fetch.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Tail the daemon's live event stream, printing each frame
    /// (`HH:MM:SS  label  detail`) as it happens until interrupted (Ctrl-C).
    ///
    /// This is **pub/sub, not polling**: the CLI opens ONE `Subscribe`
    /// connection over the socket and the daemon *pushes* every frame down it
    /// (samples as they are collected, incidents as triggers fire, plus the
    /// stream-integrity frames — the opening subscription ack, gaps, and
    /// observing transitions). With `--kind` the daemon filters the *events*
    /// server-side to that single kind; without it, every kind is streamed.
    ///
    /// The tail ALWAYS prints why it ended on stderr, but only a genuine failure
    /// exits non-zero: a decode/IO error or a daemon-reported stream error. An
    /// orderly end — the daemon closing the stream on shutdown/restart, or our
    /// own output pipe going away (`| head`) — exits 0, so the command does not
    /// break under a restart-on-nonzero supervisor. Never panics.
    Events {
        /// Restrict the stream to a single event kind. Omit for all kinds.
        /// Stream-integrity frames (subscription ack, gaps, observing
        /// transitions) are delivered regardless of this filter.
        #[arg(long)]
        kind: Option<EventKindArg>,
    },
    /// Ask the running daemon to restart the sing-box proxy service
    /// (`launchctl kickstart`), sent as a `Control(KickstartProxy)` request over
    /// the socket. The daemon runs it as root for any authorised peer; nothing
    /// in its config has to be switched on. Exits non-zero if the action was
    /// refused/failed or the daemon is unreachable.
    Kickstart,
    /// Turn the observer's own collection on or off (pause/resume), sent as a
    /// `Control(SetObserving)` request over the socket. This controls the
    /// daemon's OWN observation only — it does **not** touch sing-box or the
    /// network (benign self-control).
    /// The daemon stays alive and the socket keeps serving while paused, so the
    /// switch can be turned back on. Exits non-zero if the request failed or the
    /// daemon is unreachable.
    Observe {
        /// `on` resumes collection; `off` pauses it.
        #[arg(value_enum)]
        state: ObserveState,
    },
    /// Set the daemon's probing tier, sent as a `Control(SetProbing)` request
    /// over the socket. `passive` (the daemon's default) puts nothing on the
    /// wire: every link, proxy and dns probe is withheld and lands as `SKIP`,
    /// and the held reference streams are closed. `active` runs every probe.
    /// Benign self-control like `observe`, process-scoped, and every real
    /// switch is recorded as a `probing_edge` row (see `gaps`). Exits non-zero
    /// if the request failed, the daemon refused it, or the daemon is
    /// unreachable.
    Probe {
        /// `passive` withholds every probe; `active` sends them.
        #[arg(value_enum)]
        tier: ProbeTier,
    },
    /// "Is it us or the network": ask the running daemon to run an experiment
    /// window (`Control(StartExperiment)`). For the window the daemon goes
    /// passive — nothing of its own on the wire, bracketed by a
    /// `probing_edge` with reason `experiment` — freezes the pcap ring at the
    /// start and at the end, restores the previous tier when the window
    /// elapses, and computes a report: the frames this machine itself sent
    /// inside the window (from the end freeze, by protocol; the daemon's
    /// ICMP echoes expected to be 0) next to what the record says the network
    /// did in the same minutes (route events, incidents, gateway verdicts,
    /// roams, announce flushes, flow totals, signal range) and one plain
    /// verdict line. The daemon answers at once with the window's id; this
    /// command then polls the daemon every 5 s until the report is ready and
    /// prints it, so a dropped socket does not lose the window. Benign
    /// self-control like `probe`. Exits non-zero if the daemon refused
    /// (another window running, a bad length) or is unreachable.
    Experiment {
        /// The window's length in minutes, 1 to 60.
        #[arg(long, default_value_t = EXPERIMENT_DEFAULT_MINUTES)]
        minutes: u32,
        /// Print the id and return at once instead of waiting for the report;
        /// read it later with `experiment-report <id>`.
        #[arg(long)]
        no_wait: bool,
    },
    /// The report of a past experiment window, by the id `experiment`
    /// printed. Asks the running daemon first, reads the DB file's
    /// `experiment` table only when no daemon answers. A window still
    /// running is reported as such, not waited for.
    ExperimentReport {
        /// The window's id, `experiment-<start_us>`.
        id: String,
    },
    /// Ask the running daemon to go and find out who is on this segment NOW:
    /// sweep the local IPv4 subnet and browse mDNS for names, sent as a
    /// `Control(ScanNeighbors)` request over the socket.
    ///
    /// Unlike the passive `neighbors` collector, this **speaks on the network**
    /// — it addresses every host of the subnet. Nothing in the daemon's config
    /// has to permit it: the command is the sanction, and every run leaves a
    /// `neighbor_scan` row saying what was probed. The daemon refuses it with a
    /// reason when it cannot run (paused, no IPv4 subnet, no scanner on this
    /// host) or when the peer is not authorised. Exits non-zero if the
    /// scan was refused/failed or the daemon is unreachable.
    ScanNeighbors {
        /// Also TCP-connect-scan discovered neighbours' common ports. Off unless
        /// given.
        #[arg(long)]
        ports: bool,
        /// Also grab the banner each open port volunteers. Needs `--ports` (a
        /// banner grab reads from an open port); without an effective port scan
        /// the daemon drops it and says so. Off unless given.
        #[arg(long)]
        banners: bool,
        /// Also match the grabbed banners against the daemon's local CVE
        /// snapshot. Needs `--banners` (a match parses a banner) and a
        /// provisioned `collectors.neighbors.cve_snapshot_dir` in the daemon's
        /// config; without both the daemon drops it and says so. Each stored
        /// match is a hypothesis, not a fact. Off unless given. Read the
        /// findings back with `vulns`.
        #[arg(long)]
        cve: bool,
    },
    /// The neighbours the record knows on each segment, newest sighting first:
    /// MAC, address, vendor OUI, name if one was ever learned, and how it came
    /// to be known. Asks the running daemon first, reads the DB file only when
    /// no daemon answers.
    Neighbors {
        /// Restrict to one segment, by its gateway MAC. Omit for every segment
        /// this machine has recorded.
        #[arg(long)]
        network: Option<String>,
    },
    /// The CVEs the record hypothesises for open ports, newest sighting first:
    /// MAC, address, port, CVE id, confidence, whether it is known-exploited,
    /// and CVSS. Each row is a HYPOTHESIS from matching a grabbed banner
    /// against the local snapshot, never an asserted fact — weigh it by its
    /// confidence and the KEV flag. Asks the running daemon first, reads the DB
    /// file only when no daemon answers.
    Vulns {
        /// Restrict to one segment, by its gateway MAC. Omit for every segment
        /// this machine has recorded.
        #[arg(long)]
        network: Option<String>,
    },
    /// The switch-topology uplinks learned passively from received LLDP/CDP
    /// frames, newest sighting first: local interface, remote chassis, remote
    /// port, the switch/AP's system name and capabilities, and whether LLDP or
    /// CDP carried it. Each row is a HYPOTHESIS — LLDP/CDP are unauthenticated
    /// and spoofable — never an asserted fact. Asks the running daemon first,
    /// reads the DB file only when no daemon answers.
    Topology {
        /// Restrict to one local interface (e.g. `en0`). Omit for every
        /// interface this machine has recorded an uplink on.
        #[arg(long)]
        iface: Option<String>,
    },
    /// What this machine talks to: the newest tick of the live flow table
    /// sing-box carries (its Clash API lists every flow with the name asked
    /// for, the real destination, the process and the outbound), grouped and
    /// ordered by how many flows share the key, with the names seen behind
    /// each key. `netstat` cannot answer this here — every destination it
    /// shows is a fakeip. A tick on which the API did not answer is one row
    /// saying SKIP, never an empty table. Asks the running daemon first,
    /// reads the DB file only when no daemon answers.
    ///
    /// Shows the external flows only by default — the internal ones (every
    /// app's DNS query to sing-box's own listener is a flow) and the LAN
    /// ones are counted on a last line instead of listed; `--all` lists
    /// everything with its scope, `--scope` picks one.
    Connections {
        /// Group the flows by the name asked for, the destination address,
        /// address and port, or the client process.
        #[arg(long, value_enum, default_value_t = GroupByArg::Host)]
        by: GroupByArg,
        /// List every flow whatever its scope, with a `scope` column.
        #[arg(long, conflicts_with = "scope")]
        all: bool,
        /// List the flows of one scope only (default: external).
        #[arg(long, value_enum)]
        scope: Option<ScopeArg>,
    },
    /// The latest slice of the radio environment: every foreign access point
    /// the last scan heard, with its channel, band, width, signal and noise,
    /// ordered by how likely it is to be sitting in our own band. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    ///
    /// The OVERLAP column is a HYPOTHESIS computed from channel geometry, never
    /// a measurement of interference: macOS reports no channel occupancy to any
    /// program. A scan that could not run is reported as a refusal with its
    /// reason, never as an empty list that would read as clear air.
    Air,
    /// Run an arbitrary SQL query directly against the DuckDB file (offline
    /// forensics — only works while `net-observerd` is stopped).
    Query {
        /// The SQL statement to run against the store.
        sql: String,
    },
    /// Which layer failed at a moment: the state of link, proxy server, tun and
    /// host load as the record has it, plus the layer it blames. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    ///
    /// A moment the daemon was paused for is reported as a refusal — the gap and
    /// its bounds — not as a row of blank measurements.
    Why {
        /// The moment to read, defaulting to now. Accepts `now`, raw epoch
        /// microseconds (`ts_us`), `YYYY-MM-DD[T ]HH:MM[:SS]` in local time, an
        /// ISO instant with an offset (`2026-09-01T14:05:00Z`), or `HH:MM[:SS]`
        /// for that time today.
        #[arg(long, default_value = "now")]
        at: String,
    },
    /// Every incident with the layer state just before it opened. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    ///
    /// An incident that opened inside an observation gap gets no context: the
    /// state from before the pause is not context for it, and is marked withheld.
    IncidentContext,
    /// The wedge-vs-starvation verdict over each recent `tun=000` episode — the
    /// discriminator that decides whether a restart is the cure. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    ///
    /// An episode the record cannot classify is reported `unknown`, not guessed.
    WedgeOrStarvation,
    /// The gateway RTT series before a drop, with its least-squares slope, so a
    /// coworking-gateway ramp is visible as data. Asks the running daemon
    /// first, reads the DB file only when no daemon answers.
    ///
    /// The slope is refused — "not computed" — when the window crosses an
    /// observation gap.
    GatewayRamp {
        /// The drop to look back from, in any form `why --at` accepts. Defaults
        /// to the most recent gateway drop in the record.
        #[arg(long)]
        drop: Option<String>,
        /// How far back to plot, in microseconds.
        #[arg(long, default_value_t = store::diagnosis::DEFAULT_RAMP_WINDOW_US)]
        window_us: i64,
    },
    /// The observation gaps the record contains — every interval the daemon
    /// deliberately collected nothing for, and what closed each. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    Gaps,
    /// The network segments this machine has ever recorded, newest activity
    /// first: the segment key, a best-effort SSID guess, the gateway IP when
    /// recoverable, first/last seen, and how many devices it held. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    ///
    /// `ssid_guess` is a TIME-overlap heuristic, never an asserted fact: the
    /// daemon does not join an SSID to a segment. A segment recorded under
    /// `unknown` (the gateway MAC was unreadable) is listed like any other.
    Segments,
    /// One segment's recorded state: the neighbours that were live at an
    /// instant (`--at`), or active over a window (`--since`/`--until`), each
    /// with a count of its open ports and hypothesised vulns over that slice.
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
    History {
        /// The segment to read, by its gateway MAC — or the literal `unknown`
        /// for the segment whose gateway MAC was unreadable. A non-key is an
        /// error, not an empty table.
        #[arg(long)]
        network: String,
        /// A single instant, in any form `why --at` accepts. Mutually exclusive
        /// with `--since`/`--until`; defaults to now if no window is given.
        #[arg(long, conflicts_with_all = ["since", "until"])]
        at: Option<String>,
        /// Window start (inclusive), in any form `why --at` accepts. Requires
        /// `--until`.
        #[arg(long, requires = "until")]
        since: Option<String>,
        /// Window end (inclusive), in any form `why --at` accepts. Requires
        /// `--since`.
        #[arg(long, requires = "since")]
        until: Option<String>,
    },
}

/// The desired observation state for the `observe` subcommand.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ObserveState {
    /// Resume collection (`observing = true`).
    On,
    /// Pause collection (`observing = false`).
    Off,
}

impl ObserveState {
    /// The boolean carried in `ControlCmd::SetObserving`.
    fn as_bool(self) -> bool {
        matches!(self, ObserveState::On)
    }
}

/// The grouping accepted by `connections --by`. A thin CLI mirror of
/// [`ConnectionsGroupBy`] so `clap` renders `<host|ip|ip-port|process>` in the
/// help without leaking the wire type into the argument surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum GroupByArg {
    /// By the name asked for (a bare-address flow is keyed by its address).
    Host,
    /// By the real destination address (a flow whose address the proxy never
    /// learned is keyed by its name).
    Ip,
    /// By destination address and port.
    IpPort,
    /// By the client process.
    Process,
}

impl GroupByArg {
    /// Map to the wire [`ConnectionsGroupBy`] the daemon and the SQL take.
    fn to_group_by(self) -> ConnectionsGroupBy {
        match self {
            GroupByArg::Host => ConnectionsGroupBy::Host,
            GroupByArg::Ip => ConnectionsGroupBy::Ip,
            GroupByArg::IpPort => ConnectionsGroupBy::IpPort,
            GroupByArg::Process => ConnectionsGroupBy::Process,
        }
    }
}

/// The scope accepted by `connections --scope`. A thin CLI mirror of
/// [`ConnectionScope`], like [`GroupByArg`], so `clap` renders
/// `<internal|lan|external>` in the help.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ScopeArg {
    /// Flows that never leave the machine or only reach sing-box's own
    /// listeners (the TUN address, the DNS pin, loopback, link-local).
    Internal,
    /// Flows to a private address on the segment.
    Lan,
    /// Flows to the world — the tunnel's own traffic.
    External,
}

impl ScopeArg {
    /// Map to the [`ConnectionScope`] the table's `scope` column spells.
    fn to_scope(self) -> ConnectionScope {
        match self {
            ScopeArg::Internal => ConnectionScope::Internal,
            ScopeArg::Lan => ConnectionScope::Lan,
            ScopeArg::External => ConnectionScope::External,
        }
    }
}

/// The reader's half of the connections scope (realm net-observer, node #75):
/// keep the rows of `keep` and count the rest by scope. The daemon's answer
/// carries EVERY row with its `scope` — the filtering is the reader's, so one
/// round trip serves both the table and the last line — and the CLI and the
/// bar fold the same answer.
///
/// The kept table drops the `scope` column (every row shown shares it) and
/// keeps the empty-tick marker row (`key` empty: the daemon's `SKIP` / empty
/// `OK`, which is not a flow and belongs to no scope). The hidden counts are
/// flows (`count` summed), not groups: the figure the operator asked about.
/// A table without a `scope` column — an older daemon's — has every row
/// `external`, shown, never hidden. `keep = None` keeps everything, column
/// and all.
fn fold_by_scope(table: &Table, keep: Option<ConnectionScope>) -> (Table, [u64; 3]) {
    let Some(keep) = keep else {
        return (table.clone(), [0; 3]);
    };
    let col = |name: &str| table.columns.iter().position(|c| c == name);
    let (scope_col, key_col, count_col) = (col("scope"), col("key"), col("count"));
    let cell = |row: &[String], i: Option<usize>| -> String {
        i.and_then(|i| row.get(i).cloned()).unwrap_or_default()
    };
    let mut hidden = [0u64; 3];
    let mut rows = Vec::new();
    for row in &table.rows {
        let marker = key_col.is_some() && cell(row, key_col).is_empty();
        let scope = cell(row, scope_col)
            .parse::<ConnectionScope>()
            .unwrap_or_default();
        if marker || scope == keep {
            let mut row = row.clone();
            if let Some(i) = scope_col
                && i < row.len()
            {
                row.remove(i);
            }
            rows.push(row);
        } else {
            let index = ConnectionScope::ALL
                .iter()
                .position(|s| *s == scope)
                .unwrap_or(2);
            hidden[index] =
                hidden[index].saturating_add(cell(row, count_col).parse::<u64>().unwrap_or(0));
        }
    }
    let columns = table
        .columns
        .iter()
        .filter(|c| *c != "scope")
        .cloned()
        .collect();
    (Table { columns, rows }, hidden)
}

/// The last line under a folded connections table: what was hidden, by
/// scope, in [`ConnectionScope::ALL`]'s order — `+1023 internal
/// (dns/plumbing), +4 lan hidden — --all shows them`. `None` when nothing
/// was, so the table stands alone.
fn hidden_line(hidden: [u64; 3]) -> Option<String> {
    let parts: Vec<String> = ConnectionScope::ALL
        .iter()
        .zip(hidden)
        .filter(|(_, n)| *n > 0)
        .map(|(scope, n)| match scope {
            ConnectionScope::Internal => format!("+{n} internal (dns/plumbing)"),
            other => format!("+{n} {other}"),
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(format!("{} hidden — --all shows them", parts.join(", ")))
    }
}

/// The tier accepted by the `probe` subcommand. A thin CLI mirror of
/// [`ProbingTier`] so `clap` renders `<passive|active>` in the help without
/// leaking the wire type into the argument surface.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ProbeTier {
    /// Nothing on the wire; every probe lands as `SKIP`.
    Passive,
    /// Every probe runs.
    Active,
}

impl ProbeTier {
    /// The tier carried in `ControlCmd::SetProbing`.
    fn to_tier(self) -> ProbingTier {
        match self {
            ProbeTier::Passive => ProbingTier::Passive,
            ProbeTier::Active => ProbingTier::Active,
        }
    }
}

/// The event kind accepted by `events --kind`. A thin CLI mirror of
/// [`EventKind`] so `clap` renders
/// `<link|proxy|dns|route|host|wifi|neighbors|air|connections|singbox-log|incident|incident-closed>`
/// in the help without leaking the wire type into the argument surface.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum EventKindArg {
    Link,
    Proxy,
    Dns,
    Route,
    Host,
    Wifi,
    Neighbors,
    Air,
    Connections,
    SingboxLog,
    Incident,
    /// `incident-closed` — clap's kebab-case of the variant, the same label
    /// [`EventKind::as_str`] gives it (realm net-observer, node #135).
    IncidentClosed,
}

impl EventKindArg {
    /// Map to the wire [`EventKind`] used in `Request::Subscribe { kinds }`.
    fn to_kind(self) -> EventKind {
        match self {
            EventKindArg::Link => EventKind::Link,
            EventKindArg::Proxy => EventKind::Proxy,
            EventKindArg::Dns => EventKind::Dns,
            EventKindArg::Route => EventKind::Route,
            EventKindArg::Host => EventKind::Host,
            EventKindArg::Wifi => EventKind::Wifi,
            EventKindArg::Neighbors => EventKind::Neighbors,
            EventKindArg::Air => EventKind::Air,
            EventKindArg::Connections => EventKind::Connections,
            EventKindArg::SingboxLog => EventKind::SingboxLog,
            EventKindArg::Incident => EventKind::Incident,
            EventKindArg::IncidentClosed => EventKind::IncidentClosed,
        }
    }

    /// The wire kinds `--kind` subscribes to: every kind the named one admits
    /// ([`EventKind::admits`]), so `incident` carries the closes too — a tail
    /// watching for incidents must see them end — while `incident-closed`
    /// alone stays selectable (realm net-observer, node #135).
    fn to_kinds(self) -> Vec<EventKind> {
        let named = self.to_kind();
        EventKind::ALL
            .iter()
            .copied()
            .filter(|k| named.admits(*k))
            .collect()
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode> {
    match &cli.command {
        Command::Status => {
            let cfg = load_config(cli)?;
            let snap = fetch_status(&cfg.socket_path)?;
            print!("{}", format_status(&snap));
        }
        Command::Incidents { limit } => {
            let cfg = load_config(cli)?;
            let incidents = fetch_incidents(&cfg.socket_path, *limit)?;
            print!("{}", format_incidents(&incidents));
        }
        Command::Events { kind } => {
            let cfg = load_config(cli)?;
            // `None` (no `--kind`) subscribes to every kind; `Some(k)` filters
            // server-side to the kinds that one admits (`incident` brings the
            // closes along). Either way the stream-integrity frames (ack,
            // gap, observing) are delivered.
            let kinds = kind.map(EventKindArg::to_kinds);
            // The tail owns its own exit code: an orderly end is a success even
            // though the stream stopped (see [`TailEnd`]).
            return stream_events(&cfg.socket_path, kinds);
        }
        Command::Kickstart => {
            let cfg = load_config(cli)?;
            let result = fetch_kickstart(&cfg.socket_path)?;
            print!("{}", format_control(&result));
            // A refusal (unauthorised peer) or a failed action is a non-zero
            // exit, even though the request itself round-tripped fine.
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Observe { state } => {
            let cfg = load_config(cli)?;
            let result = fetch_set_observing(&cfg.socket_path, state.as_bool())?;
            print!("{}", format_control(&result));
            // The request round-trips fine; a non-`ok` result means the daemon
            // declined or failed, which is a non-zero exit.
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Probe { tier } => {
            let cfg = load_config(cli)?;
            let result = fetch_set_probing(&cfg.socket_path, tier.to_tier())?;
            print!("{}", format_control(&result));
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Experiment { minutes, no_wait } => {
            let cfg = load_config(cli)?;
            let result = fetch_start_experiment(&cfg.socket_path, *minutes)?;
            print!("{}", format_control(&result));
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
            // The id is the daemon's, read back from its own words: a window
            // is named by the instant ITS clock opened it.
            let id = net_observer_ipc::experiment_id_in(&result.message).ok_or_else(|| {
                anyhow!(
                    "net-observerd accepted the experiment but named no id: {}",
                    result.message
                )
            })?;
            if *no_wait {
                return Ok(ExitCode::SUCCESS);
            }
            eprintln!("waiting {minutes} min for {id}; polling every {POLL_EVERY_S} s");
            let table = await_experiment(
                &cfg.socket_path,
                &id,
                experiment_polls(*minutes),
                net_observer_ipc::diagnose,
                std::thread::sleep,
            )?;
            print!("{}", format_table(&table));
        }
        Command::ExperimentReport { id } => {
            let table =
                diagnose_table(cli, DiagnosticQuery::Experiment { id: id.clone() }, |off| {
                    let record = open_store(off)?
                        .experiment(id)
                        .map_err(|e| anyhow!("query failed: {e}"))?
                        .ok_or_else(|| anyhow!("experiment {id} not found in {}", off.db_path))?;
                    let table = net_observer_ipc::experiment_table_from_json(&record.report_json)
                        .map_err(|e| anyhow!("experiment {id}: {e}"))?;
                    Ok(QueryTable {
                        columns: table.columns,
                        rows: table.rows,
                    })
                })?;
            print!("{}", format_table(&table));
        }
        Command::ScanNeighbors {
            ports,
            banners,
            cve,
        } => {
            let cfg = load_config(cli)?;
            let result = fetch_scan_neighbors(
                &cfg.socket_path,
                ScanOptions {
                    ports: *ports,
                    banners: *banners,
                    cve: *cve,
                },
            )?;
            print!("{}", format_control(&result));
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        // The named diagnoses: the filter is validated HERE, before any socket
        // or file is touched, so a bad key is the builder's own error and never
        // a round-trip — then the daemon is asked, and the file read only when
        // no daemon answers (see `diagnose_table`).
        Command::Neighbors { network } => {
            let sql = diagnosis::neighbors_sql(network.as_deref()).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::Neighbors {
                    network: network.clone(),
                },
                |off| run_query(off, &sql),
            )?;
            print!("{}", format_table(&table));
        }
        Command::Vulns { network } => {
            let sql = diagnosis::vulns_sql(network.as_deref()).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::Vulns {
                    network: network.clone(),
                },
                |off| run_query(off, &sql),
            )?;
            print!("{}", format_table(&table));
        }
        Command::Topology { iface } => {
            let sql = diagnosis::topology_sql(iface.as_deref()).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::Topology {
                    iface: iface.clone(),
                },
                |off| run_query(off, &sql),
            )?;
            print!("{}", format_table(&table));
        }
        Command::Connections { by, all, scope } => {
            let group_by = by.to_group_by();
            let sql = diagnosis::connections_sql(group_by);
            let table = diagnose_table(cli, DiagnosticQuery::Connections { group_by }, |off| {
                run_query(off, &sql)
            })?;
            // The daemon answers every scope; the fold is the reader's
            // (realm net-observer, node #75).
            let keep = (!all).then(|| scope.map_or(ConnectionScope::External, ScopeArg::to_scope));
            let (table, hidden) = fold_by_scope(&table, keep);
            print!("{}", format_table(&table));
            if let Some(line) = hidden_line(hidden) {
                println!("{line}");
            }
        }
        Command::Air => {
            // Three reads, one moment: the scan itself (so a SKIP is rendered as
            // a refusal), what it heard, and our own channel to compare against.
            // Routed once, live first, like the other diagnoses (realm
            // net-observer, node #99); the choice is reused for all three so
            // the operator sees one `source:` line, not three. The AP list is
            // pinned to the scan's own `ts_us` (`scan_ts_us`), never
            // re-derived as "the newest" — the offline file can be rewritten
            // between the two reads just as a live daemon's collector can.
            let record = Record::resolve(cli)?;
            let (scan, aps, own) =
                match route_air(record.socket.as_deref(), net_observer_ipc::diagnose)? {
                    AirRoute::Live {
                        scan,
                        aps,
                        own,
                        via,
                    } => {
                        eprintln!("source: net-observerd via {via}");
                        (scan, aps, own)
                    }
                    AirRoute::Offline { why, locked } => {
                        if let Some(why) = why {
                            eprintln!("{why}; reading the file instead");
                        }
                        eprintln!("source: file {}", record.db_path);
                        let offline = Offline {
                            db_path: record.db_path,
                            locked,
                        };
                        let scan =
                            table_from_query(run_query(&offline, diagnosis::AIR_LATEST_SCAN_SQL)?);
                        let aps = match scan_ts_us(&scan) {
                            Some(ts) => table_from_query(run_prepared(
                                &offline,
                                &diagnosis::air_aps_at_sql(ts),
                            )?),
                            None => Table::default(),
                        };
                        let own =
                            table_from_query(run_query(&offline, diagnosis::AIR_SELF_CHANNEL_SQL)?);
                        (scan, aps, own)
                    }
                };
            print!("{}", diagnose::format_air(&scan, &aps, &own)?);
        }
        Command::Query { sql } => {
            let table = table_from_query(run_query(&file_only(cli)?, sql)?);
            print!("{}", format_table(&table));
        }
        Command::Why { at } => {
            let ts_us = diagnose::parse_at(at)?;
            let table = diagnose_table(cli, DiagnosticQuery::Why { ts_us }, |off| {
                run_prepared(off, &diagnosis::verdict_at_sql(ts_us, LOAD_THRESHOLD))
            })?;
            print!("{}", diagnose::format_verdict_at(&table, ts_us)?);
        }
        Command::IncidentContext => {
            let table = diagnose_table(cli, DiagnosticQuery::IncidentContext, |off| {
                run_prepared(off, &diagnosis::incident_context_sql(LOAD_THRESHOLD))
            })?;
            print!("{}", diagnose::format_incident_context(&table)?);
        }
        Command::WedgeOrStarvation => {
            let table = diagnose_table(cli, DiagnosticQuery::WedgeVsStarvation, |off| {
                run_prepared(
                    off,
                    &diagnosis::wedge_vs_starvation_sql(
                        LOAD_THRESHOLD,
                        diagnosis::DEFAULT_EPISODE_GAP_US,
                    ),
                )
            })?;
            print!("{}", diagnose::format_wedge_vs_starvation(&table)?);
        }
        Command::GatewayRamp { drop, window_us } => {
            let drop_ts_us = match drop {
                Some(d) => diagnose::parse_at(d)?,
                None => latest_gw_drop(cli)?,
            };
            let table = diagnose_table(
                cli,
                DiagnosticQuery::GatewayRamp {
                    drop_ts_us,
                    window_us: *window_us,
                },
                |off| run_prepared(off, &diagnosis::gateway_ramp_sql(drop_ts_us, *window_us)),
            )?;
            print!(
                "{}",
                diagnose::format_gateway_ramp(&table, drop_ts_us, *window_us)?
            );
        }
        Command::Gaps => {
            // Every bracketed silence — pauses AND passive stretches — is
            // `Silences`. A daemon built before it cannot read that request;
            // it is then asked `Gaps`, the pauses-only shape it has, and the
            // reader is told what THAT answer lacks — only when it is the
            // answer: the offline record is read with the full query and
            // lists the stretches, so the file path prints its usual source
            // line alone. (realm net-observer, node #88)
            let table = diagnose_table_by(
                cli,
                |socket| {
                    let (outcome, note) = ask_silences_or_gaps(socket, net_observer_ipc::diagnose)?;
                    if let Some(note) = note {
                        eprintln!("{note}");
                    }
                    Ok(outcome)
                },
                |off| run_query(off, &diagnosis::silences_sql()),
            )?;
            print!("{}", diagnose::format_observation_gaps(&table)?);
        }
        Command::Segments => {
            let table = diagnose_table(cli, DiagnosticQuery::Segments, |off| {
                run_query(off, &diagnosis::segments_sql())
            })?;
            print!("{}", format_table(&table));
        }
        Command::History {
            network,
            at,
            since,
            until,
        } => {
            // `clap` guarantees `--since`/`--until` come as a pair and never
            // alongside `--at`; the remaining case is neither, which reads as
            // "now".
            let window = match (at, since, until) {
                (_, Some(since), Some(until)) => diagnosis::HistoryWindow::Range {
                    since: diagnose::parse_at(since)?,
                    until: diagnose::parse_at(until)?,
                },
                (Some(at), _, _) => diagnosis::HistoryWindow::At(diagnose::parse_at(at)?),
                _ => diagnosis::HistoryWindow::At(diagnose::parse_at("now")?),
            };
            let sql = diagnosis::history_sql(network, window).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::History {
                    network: network.clone(),
                    window,
                },
                |off| run_query(off, &sql),
            )?;
            print!("{}", format_table(&table));
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Load the daemon config (defaults + optional TOML file + `NET_OBSERVER_*` env),
/// mapping the large `figment::Error` into a clear `anyhow` message.
fn load_config(cli: &Cli) -> Result<Config> {
    Config::load(cli.config.as_deref()).map_err(|e| anyhow!("failed to load observer config: {e}"))
}

/// Whether a socket error means `net-observerd` is not running at all — no
/// socket file, or one nobody listens on — as opposed to a daemon that is there
/// and could not be talked to.
fn daemon_not_running(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    matches!(e.kind(), NotFound | ConnectionRefused)
}

/// Send one request to the daemon over the socket. An absent / refused socket
/// (`net-observerd` not running) becomes a clear message, never a panic.
fn daemon_query(socket_path: &str, req: &Request) -> Result<Response> {
    net_observer_ipc::query(socket_path, req).map_err(|e| {
        if daemon_not_running(&e) {
            anyhow!("net-observerd not running (socket {socket_path} unavailable)")
        } else {
            anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
        }
    })
}

/// Where a diagnosis is read from, with the words that go with it. Decided by
/// [`route`] from what the operator asked for and what the socket said — and
/// then printed, always, as one `source:` line on stderr, because a forensic
/// reader must know which record answered. (realm net-observer, node #58)
#[derive(Debug, Clone, PartialEq)]
enum Route {
    /// The daemon answered over `via`; here is its table.
    Live { table: Table, via: String },
    /// Read the file. `why` is the one line saying what sent the reader there
    /// (`None` when the operator asked for the file with `--db`); `locked` is
    /// the sentence to print if a daemon turns out to hold the file's lock —
    /// the same reason again, so the lock message never contradicts what just
    /// happened.
    Offline { why: Option<String>, locked: String },
}

/// The rule, pure: `socket` is `None` when the operator named the record with
/// `--db` (the socket is then never asked), and `ask` is the round-trip over
/// the socket it is given.
///
/// - `--db` given → the file, no socket, no question asked: an answer from a
///   running daemon over a file the operator pointed at would be an answer
///   from the wrong record, silently;
/// - the daemon answers → its table;
/// - nothing listens on the socket ([`daemon_not_running`]) → the file, saying
///   which socket was tried;
/// - the daemon is there but cannot READ the request (built before
///   `Request::Query`) → the file too, saying so — that daemon still holds the
///   lock, and the reader deserves to know why the open that follows will fail;
/// - the daemon read the request and could not run it, or the socket is there
///   and broken → an error and a non-zero exit. Never the file: it would only
///   meet the lock and report the wrong problem.
fn route(
    socket: Option<&str>,
    ask: impl FnOnce(&str) -> std::io::Result<QueryOutcome>,
) -> Result<Route> {
    let Some(socket) = socket else {
        return Ok(Route::Offline {
            why: None,
            locked: "--db was given, so the socket was not asked".to_string(),
        });
    };
    let locked = format!("the socket at {socket} did not answer or could not decode the request");
    match ask(socket) {
        Ok(QueryOutcome::Table(table)) => Ok(Route::Live {
            table,
            via: socket.to_string(),
        }),
        Ok(QueryOutcome::Failed(m)) => Err(anyhow!("net-observerd returned an error: {m}")),
        Ok(QueryOutcome::Unsupported(m)) => Ok(Route::Offline {
            why: Some(format!(
                "net-observerd at {socket} cannot decode the request ({m})"
            )),
            locked,
        }),
        Err(e) if daemon_not_running(&e) => Ok(Route::Offline {
            why: Some(format!("no daemon answered on {socket} ({e})")),
            locked,
        }),
        Err(e) => Err(anyhow!(
            "failed to query net-observerd over socket {socket}: {e}"
        )),
    }
}

/// Run one named diagnosis by the rule in [`route`], print its source, and
/// hand back the table whichever record it came from.
fn diagnose_table(
    cli: &Cli,
    q: DiagnosticQuery,
    offline: impl FnOnce(&Offline) -> Result<QueryTable>,
) -> Result<Table> {
    diagnose_table_by(cli, |s| net_observer_ipc::diagnose(s, q), offline)
}

/// Ask `Silences` and, on a daemon that cannot read it, `Gaps` instead.
///
/// The second value is the one-line note for stderr, and it is `Some` ONLY
/// when a daemon actually answered `Gaps`: that answer lists the pauses only,
/// and a reader must not take "no passive stretch listed" for "there was
/// none". A daemon too old for `Query` at all answers `Unsupported` twice;
/// [`route`] then reads the file with the full `silences_sql`, which DOES list
/// the stretches — so no note, or it would contradict the table under it.
/// `ask` is the socket round-trip, injected so the rule is testable without a
/// daemon; a daemon that reads `Silences` and fails it is NOT retried (the
/// file would only meet the lock).
fn ask_silences_or_gaps(
    socket: &str,
    ask: impl Fn(&str, DiagnosticQuery) -> std::io::Result<QueryOutcome>,
) -> std::io::Result<(QueryOutcome, Option<String>)> {
    match ask(socket, DiagnosticQuery::Silences)? {
        QueryOutcome::Unsupported(m) => {
            let fallback = ask(socket, DiagnosticQuery::Gaps)?;
            let note = matches!(fallback, QueryOutcome::Table(_)).then(|| {
                format!(
                    "net-observerd at {socket} predates the `Silences` diagnosis ({m}); \
                     it answered `Gaps` instead — pauses only, passive stretches not listed"
                )
            });
            Ok((fallback, note))
        }
        answered => Ok((answered, None)),
    }
}

/// Where the `air` group of reads came from, once decided.
///
/// `Live` carries all three tables: [`route_air`] asks `AirAps` and
/// `AirSelfChannel` over the same socket the scan answered on, so a daemon
/// that reads one reads all three — they shipped together.
#[derive(Debug, Clone, PartialEq)]
enum AirRoute {
    Live {
        scan: Table,
        aps: Table,
        own: Table,
        via: String,
    },
    Offline {
        why: Option<String>,
        locked: String,
    },
}

/// The `ts_us` of `AirScan`'s one row, read back from its own answer rather
/// than re-derived as "the newest scan": the air collector can write a new
/// scan between two round trips over a live socket, and re-deriving would pin
/// `AirAps` to a different moment than the header just read — silent wrong
/// data. `None` when the record has no scan at all, and then `AirAps` is not
/// asked at all: `format_air` renders that absence without ever touching an
/// AP list. (realm net-observer, node #99)
fn scan_ts_us(scan: &Table) -> Option<i64> {
    let i = scan.columns.iter().position(|c| c == "ts_us")?;
    scan.rows.first()?.get(i)?.parse().ok()
}

/// [`route`] the `air` group of reads from ONE question — `AirScan` — and
/// reuse that choice for `AirAps` and `AirSelfChannel`: a daemon or a file is
/// decided once, not three times, so the operator sees one `source:` line for
/// the three tables rather than three. (realm net-observer, node #99)
fn route_air(
    socket: Option<&str>,
    ask: impl Fn(&str, DiagnosticQuery) -> std::io::Result<QueryOutcome>,
) -> Result<AirRoute> {
    match route(socket, |s| ask(s, DiagnosticQuery::AirScan))? {
        Route::Live { table: scan, via } => {
            let aps = match scan_ts_us(&scan) {
                Some(scan_ts_us) => {
                    ask_air_table(&via, &ask, DiagnosticQuery::AirAps { scan_ts_us })?
                }
                None => Table::default(),
            };
            let own = ask_air_table(&via, &ask, DiagnosticQuery::AirSelfChannel)?;
            Ok(AirRoute::Live {
                scan,
                aps,
                own,
                via,
            })
        }
        Route::Offline { why, locked } => Ok(AirRoute::Offline { why, locked }),
    }
}

/// One more live read over a socket [`route_air`] already committed to,
/// mapping a daemon that stops answering mid-group to an error rather than a
/// silent fall to the file — a fall back there would mix a live scan with an
/// offline AP list from a possibly different moment.
fn ask_air_table(
    via: &str,
    ask: &impl Fn(&str, DiagnosticQuery) -> std::io::Result<QueryOutcome>,
    q: DiagnosticQuery,
) -> Result<Table> {
    match ask(via, q.clone())? {
        QueryOutcome::Table(t) => Ok(t),
        QueryOutcome::Failed(m) => Err(anyhow!("net-observerd returned an error: {m}")),
        QueryOutcome::Unsupported(m) => Err(anyhow!(
            "net-observerd at {via} answered AirScan but cannot decode {q:?} ({m})"
        )),
    }
}

/// [`diagnose_table`] with the socket round-trip itself injected, for a
/// command whose live question is not one fixed [`DiagnosticQuery`].
fn diagnose_table_by(
    cli: &Cli,
    ask: impl FnOnce(&str) -> std::io::Result<QueryOutcome>,
    offline: impl FnOnce(&Offline) -> Result<QueryTable>,
) -> Result<Table> {
    let record = Record::resolve(cli)?;
    match route(record.socket.as_deref(), ask)? {
        Route::Live { table, via } => {
            eprintln!("source: net-observerd via {via}");
            Ok(table)
        }
        Route::Offline { why, locked } => {
            if let Some(why) = why {
                eprintln!("{why}; reading the file instead");
            }
            eprintln!("source: file {}", record.db_path);
            offline(&Offline {
                db_path: record.db_path,
                locked,
            })
            .map(table_from_query)
        }
    }
}

/// The offline record and the sentence to print if a daemon holds its lock —
/// the reason the reader is at the file, so the lock message never
/// contradicts what just happened.
struct Offline {
    db_path: String,
    locked: String,
}

/// `store::QueryTable` → the wire's [`Table`]: the same two fields, moved, so
/// the offline path renders through exactly the code the live path does. The
/// daemon carries the same conversion on its side (`api_query`); neither crate
/// can own it for both, because `net-observer-ipc` must not depend on `store`.
fn table_from_query(q: QueryTable) -> Table {
    Table {
        columns: q.columns,
        rows: q.rows,
    }
}

/// Fetch the live [`StatusSnapshot`] from the daemon.
fn fetch_status(socket_path: &str) -> Result<StatusSnapshot> {
    match daemon_query(socket_path, &Request::Status)? {
        Response::Status(snap) => Ok(snap),
        Response::Error(e) => Err(anyhow!("net-observerd returned an error: {e}")),
        other => Err(anyhow!("unexpected daemon response to Status: {other:?}")),
    }
}

/// Fetch the newest `limit` incidents from the daemon.
fn fetch_incidents(socket_path: &str, limit: usize) -> Result<Vec<IncidentSummary>> {
    match daemon_query(socket_path, &Request::Incidents { limit })? {
        Response::Incidents(list) => Ok(list),
        Response::Error(e) => Err(anyhow!("net-observerd returned an error: {e}")),
        other => Err(anyhow!(
            "unexpected daemon response to Incidents: {other:?}"
        )),
    }
}

/// Why an `events` tail ended.
///
/// Always reported on stderr; only a genuine failure exits non-zero, so the
/// command stays usable under a restart-on-nonzero supervisor — an orderly
/// daemon shutdown is not a failure of the tail.
#[derive(Debug, Clone, PartialEq)]
enum TailEnd {
    /// The daemon closed the stream cleanly (shutdown / restart) — orderly.
    DaemonClosed,
    /// Our stdout went away (e.g. `| head`) — orderly.
    OutputClosed,
    /// The daemon reported a failure on the stream (`StreamFrame::Error`).
    ServerError(String),
    /// A frame failed to decode, or the socket read failed.
    Failed(String),
}

impl TailEnd {
    /// The one-line reason printed to stderr. Never empty: an unexplained exit
    /// is exactly what this type exists to prevent.
    fn message(&self) -> String {
        match self {
            TailEnd::DaemonClosed => {
                "event stream ended: net-observerd closed the connection".into()
            }
            TailEnd::OutputClosed => "event stream ended: output pipe closed".into(),
            TailEnd::ServerError(m) => format!("event stream ended: net-observerd reported {m}"),
            TailEnd::Failed(m) => format!("event stream ended: {m}"),
        }
    }

    /// `SUCCESS` for the orderly variants, `FAILURE` for the two real failures.
    fn exit_code(&self) -> ExitCode {
        match self {
            TailEnd::DaemonClosed | TailEnd::OutputClosed => ExitCode::SUCCESS,
            TailEnd::ServerError(_) | TailEnd::Failed(_) => ExitCode::FAILURE,
        }
    }
}

/// Open ONE live subscription over the socket and print each pushed frame as it
/// arrives (`HH:MM:SS  label  detail`) until interrupted (Ctrl-C) or the stream
/// ends. This is the pub/sub tail: the daemon *pushes* frames down a held-open
/// connection; the CLI never polls. `kinds` filters events server-side (`None` =
/// every kind); stream-integrity frames arrive regardless. A `# times in UTC`
/// header precedes the stream so an operator reading a tail knows the zone of the
/// printed clocks, and the daemon's `Ready` ack is printed as the first line so
/// the tail OPENS by stating the collection state instead of implying it.
///
/// Every ending is named on stderr (see [`TailEnd`]), and only a real failure —
/// a decode/IO error, or a failure the daemon reported in band — exits non-zero.
///
/// Never panics:
/// - an absent / connection-refused socket (daemon down) and a daemon-side
///   refusal (e.g. the subscriber cap) both become a clear `Err` (a non-zero
///   exit), like the one-shot commands;
/// - a mid-stream read/decode error (daemon restart/shutdown) names itself and
///   ends the tail;
/// - a broken output pipe (e.g. `| head`) also ends the tail cleanly, rather than
///   panicking the way `println!` would on a write failure.
fn stream_events(socket_path: &str, kinds: Option<Vec<EventKind>>) -> Result<ExitCode> {
    let sub = net_observer_ipc::subscribe(socket_path, kinds.as_deref()).map_err(|e| {
        if daemon_not_running(&e) {
            anyhow!("net-observerd not running (socket {socket_path} unavailable)")
        } else {
            anyhow!("failed to subscribe to net-observerd over socket {socket_path}: {e}")
        }
    })?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // The per-frame clock is UTC (this crate is deliberately timezone-free, while
    // the gpui bar renders local time); say so once so a tail is unambiguous.
    // The ack line follows it: the state at subscribe time, stated not inferred.
    let opening = format_frame_line(&StreamFrame::Ready(sub.ready().clone()));
    let end = if writeln!(out, "# times in UTC").is_err() || writeln!(out, "{opening}").is_err() {
        TailEnd::OutputClosed
    } else {
        tail_frames(sub, &mut out)
    };
    // NOT `eprintln!` — it panics if the write fails, and `net-observer-cli events
    // 2>&1 | head` makes stderr the broken pipe, so the panic would land on
    // exactly the case the doc above promises ends cleanly.
    let _ = writeln!(std::io::stderr(), "{}", end.message());
    Ok(end.exit_code())
}

/// Print frames until the stream ends, returning why it ended. Split out of
/// [`stream_events`] so every exit path funnels through one [`TailEnd`].
fn tail_frames(
    sub: impl Iterator<Item = std::io::Result<StreamFrame>>,
    out: &mut impl Write,
) -> TailEnd {
    for item in sub {
        match item {
            Ok(frame) => {
                // `writeln!` (not `println!`) so a broken pipe ends the tail
                // instead of panicking; stdout is line-buffered so each line
                // flushes on its newline, keeping the tail live.
                if writeln!(out, "{}", format_frame_line(&frame)).is_err() {
                    return TailEnd::OutputClosed;
                }
                // A daemon-side failure is a decodable frame, not a bare close:
                // print it like any other, then end the tail naming its reason.
                if let StreamFrame::Error(e) = &frame {
                    return TailEnd::ServerError(format!("{}: {}", e.code.as_str(), e.message));
                }
            }
            // A frame failed to decode, or the socket read failed. (A clean close
            // by the daemon ends the iterator instead, and lands below.)
            Err(e) => return TailEnd::Failed(e.to_string()),
        }
    }
    TailEnd::DaemonClosed
}

/// One printed line for a stream frame: `YYYY-MM-DD HH:MM:SS  label  detail`, with
/// the clock in **UTC** (see [`clock`]; the gpui bar renders the same frames in
/// local time).
/// The label and detail come from `net-observer-ipc` so the CLI tail and the bar spell
/// every frame identically. Pure over its input (the clock is derived
/// arithmetically) so it is unit-tested directly.
fn format_frame_line(f: &StreamFrame) -> String {
    format!("{}  {}  {}", clock(f.ts_us()), f.label(), f.detail())
}

/// Format an epoch-microsecond timestamp as a `YYYY-MM-DD HH:MM:SS` wall clock in
/// **UTC**.
///
/// The date is carried because a long-running tail is read the next morning, and
/// a bare time of day cannot say whether a line is yesterday's or today's.
///
/// The tail deliberately stays on pure integer math over `ts_us` — deterministic
/// and never panicking (Euclidean division handles any `i64`, including
/// negatives) — so a streaming clock cannot depend on tz-database lookups. Local
/// time is used only where a human types one, in the offline `diagnose`
/// commands (see [`diagnose`], which resolves `--at` via `jiff`).
fn clock(ts_us: i64) -> String {
    let secs = ts_us.div_euclid(1_000_000);
    let days = secs.div_euclid(86_400); // whole UTC days since the epoch
    let tod = secs.rem_euclid(86_400); // seconds within the UTC day
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

/// Days since 1970-01-01 → `(year, month, day)` in the proleptic Gregorian
/// calendar (Howard Hinnant's `civil_from_days`). Pure integer math, total over
/// `i64` in the range a `ts_us` can reach, and never panics — the same
/// properties [`clock`] relies on.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Ask the daemon to restart the sing-box proxy over the socket
/// (`Control(KickstartProxy)`) and return its [`ControlResult`]. A daemon-down /
/// absent socket becomes a clear `Err` (handled by [`daemon_query`]); the daemon
/// itself authorises the peer, runs the action and reports the outcome in the
/// result. Never panics.
fn fetch_kickstart(socket_path: &str) -> Result<ControlResult> {
    match daemon_query(socket_path, &Request::Control(ControlCmd::KickstartProxy))? {
        Response::Control(result) => Ok(result),
        Response::Error(e) => Err(anyhow!("net-observerd returned an error: {e}")),
        other => Err(anyhow!("unexpected daemon response to Control: {other:?}")),
    }
}

/// Ask the daemon to turn its own observation on/off over the socket
/// (`Control(SetObserving)`) and return its [`ControlResult`]. This is benign
/// self-control (pause/resume the daemon's OWN collection) — it does not touch
/// sing-box or the network. A daemon-down / absent socket becomes a clear `Err`
/// (handled by [`daemon_query`]). Never panics.
fn fetch_set_observing(socket_path: &str, observing: bool) -> Result<ControlResult> {
    match daemon_query(
        socket_path,
        &Request::Control(ControlCmd::SetObserving(observing)),
    )? {
        Response::Control(result) => Ok(result),
        Response::Error(e) => Err(anyhow!("net-observerd returned an error: {e}")),
        other => Err(anyhow!("unexpected daemon response to Control: {other:?}")),
    }
}

/// Ask the daemon to switch its probing tier over the socket
/// (`Control(SetProbing)`) and return its [`ControlResult`]. Benign
/// self-control, like [`fetch_set_observing`]: it changes what the daemon's
/// own collectors put on the wire and nothing else. A daemon built before the
/// tier existed cannot decode the request; that is reported as "cannot", not
/// as a refusal, through [`net_observer_ipc::control`]. Never panics.
fn fetch_set_probing(socket_path: &str, tier: ProbingTier) -> Result<ControlResult> {
    let outcome =
        net_observer_ipc::control(socket_path, ControlCmd::SetProbing(tier)).map_err(|e| {
            if daemon_not_running(&e) {
                anyhow!("net-observerd not running (socket {socket_path} unavailable)")
            } else {
                anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
            }
        })?;
    match outcome {
        net_observer_ipc::ControlOutcome::Ran(result) => Ok(result),
        net_observer_ipc::ControlOutcome::Unsupported(e) => Err(anyhow!(
            "net-observerd cannot set a probing tier (built before it existed): {e}"
        )),
    }
}

/// Ask the daemon to open an experiment window (`Control(StartExperiment)`)
/// and return its [`ControlResult`] — the id is in the message. Benign
/// self-control like [`fetch_set_probing`], and the same forward rule: a
/// daemon built before the window existed is "cannot", not a refusal.
fn fetch_start_experiment(socket_path: &str, minutes: u32) -> Result<ControlResult> {
    let outcome = net_observer_ipc::control(socket_path, ControlCmd::StartExperiment { minutes })
        .map_err(|e| {
        if daemon_not_running(&e) {
            anyhow!("net-observerd not running (socket {socket_path} unavailable)")
        } else {
            anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
        }
    })?;
    match outcome {
        net_observer_ipc::ControlOutcome::Ran(result) => Ok(result),
        net_observer_ipc::ControlOutcome::Unsupported(e) => Err(anyhow!(
            "net-observerd cannot run an experiment window (built before it existed): {e}"
        )),
    }
}

/// How often `experiment` asks the daemon whether its window has closed.
const POLL_EVERY_S: u64 = 5;

/// Polls past the window's own length that `experiment` still waits: the
/// end task freezes the ring, restores the tier and counts the record, and
/// the daemon's clock may run behind ours. Two minutes.
const POLL_GRACE: u32 = 24;

/// Consecutive socket failures `experiment` waits through before giving up
/// on the daemon — one minute. The window itself runs on in the daemon.
const MAX_POLL_FAILURES: u32 = 12;

/// How many polls a window of `minutes` gets before `experiment` stops
/// waiting: its own length at [`POLL_EVERY_S`], plus [`POLL_GRACE`].
fn experiment_polls(minutes: u32) -> u32 {
    (u64::from(minutes) * 60 / POLL_EVERY_S) as u32 + POLL_GRACE
}

/// Wait for an experiment window's report: ask `Query(Experiment { id })`
/// every [`POLL_EVERY_S`] until the daemon answers a table.
///
/// The rule, pure — `ask` is the socket round-trip and `sleep` the wait, both
/// injected so it is tested without a daemon or a clock:
/// - a table ends the wait with the report;
/// - the daemon's own "still running" ([`net_observer_ipc::is_experiment_running`])
///   is the ONE failure waited through;
/// - any other failure is the daemon's answer and ends the wait as an error
///   — a window this daemon did not run (it restarted mid-window: the tier
///   is back to its default and there is no report), or a bad id;
/// - a daemon that cannot decode the query never ran the window either, and
///   says so;
/// - a socket error is waited through up to [`MAX_POLL_FAILURES`] times in a
///   row, because the window runs in the daemon, not on this connection —
///   past that, or past `max_polls` in all, the wait ends naming
///   `experiment-report <id>` as the way to read the report later.
fn await_experiment(
    socket: &str,
    id: &str,
    max_polls: u32,
    mut ask: impl FnMut(&str, DiagnosticQuery) -> std::io::Result<QueryOutcome>,
    mut sleep: impl FnMut(Duration),
) -> Result<Table> {
    let later =
        format!("the window runs on in the daemon; read it later with `experiment-report {id}`");
    let mut failures = 0u32;
    for _ in 0..max_polls {
        match ask(socket, DiagnosticQuery::Experiment { id: id.to_string() }) {
            Ok(QueryOutcome::Table(table)) => return Ok(table),
            Ok(QueryOutcome::Failed(m)) if net_observer_ipc::is_experiment_running(&m) => {
                failures = 0;
            }
            Ok(QueryOutcome::Failed(m)) => {
                return Err(anyhow!("net-observerd returned an error: {m}"));
            }
            Ok(QueryOutcome::Unsupported(m)) => {
                return Err(anyhow!(
                    "net-observerd at {socket} cannot report experiments (built before them): {m}"
                ));
            }
            Err(e) => {
                failures += 1;
                if failures >= MAX_POLL_FAILURES {
                    return Err(anyhow!(
                        "lost net-observerd on {socket} while waiting for {id} ({e}); {later}"
                    ));
                }
            }
        }
        sleep(Duration::from_secs(POLL_EVERY_S));
    }
    Err(anyhow!(
        "{id} did not report within {max_polls} polls; {later}"
    ))
}

/// Send `Control(ScanNeighbors)` and return the daemon's verdict.
fn fetch_scan_neighbors(socket_path: &str, opts: ScanOptions) -> Result<ControlResult> {
    match daemon_query(
        socket_path,
        &Request::Control(ControlCmd::ScanNeighbors(opts)),
    )? {
        Response::Control(result) => Ok(result),
        Response::Error(e) => Err(anyhow!("net-observerd returned an error: {e}")),
        other => Err(anyhow!("unexpected daemon response to Control: {other:?}")),
    }
}

/// Render a [`ControlResult`] as a single status line: `ok: <message>` when the
/// action ran, `failed: <message>` when it was refused (unauthorised peer, a
/// state it contradicts, a missing dependency) or the action itself failed.
/// Pure over its input so it is unit-tested directly.
fn format_control(result: &ControlResult) -> String {
    let tag = if result.ok { "ok" } else { "failed" };
    format!("{tag}: {}\n", result.message)
}

/// Open the DuckDB file directly and run one query (offline forensics). If a
/// daemon holds the per-process DuckDB lock the open fails — detect that and
/// print a clear message that repeats why the file is being read at all,
/// instead of leaking the raw driver error (and never panic).
fn run_query(offline: &Offline, sql: &str) -> Result<QueryTable> {
    open_store(offline)?
        .query_table(sql)
        .map_err(|e| anyhow!("query failed: {e}"))
}

/// Like [`run_query`], but for a [`diagnosis::PreparedSql`] built by one of the
/// parameterized `diagnosis` builders (`why`, `incident-context`,
/// `wedge-or-starvation`, `gateway-ramp`): the moment/threshold values are
/// bound, not interpolated.
fn run_prepared(offline: &Offline, p: &diagnosis::PreparedSql) -> Result<QueryTable> {
    open_store(offline)?
        .query_prepared(p)
        .map_err(|e| anyhow!("query failed: {e}"))
}

fn open_store(offline: &Offline) -> Result<DuckdbStore> {
    DuckdbStore::open(&offline.db_path).map_err(|e| {
        let msg = e.to_string();
        if is_lock_error(&msg) {
            anyhow!("{}", lock_message(&offline.db_path, &offline.locked))
        } else {
            anyhow!("failed to open DuckDB at {}: {msg}", offline.db_path)
        }
    })
}

/// The message for a file a daemon holds the lock on: the record, and the
/// reason the reader came to the file — never a claim that the daemon would
/// have answered, which is exactly what did not happen.
fn lock_message(db_path: &str, locked: &str) -> String {
    format!("a daemon holds the lock on {db_path}; {locked}")
}

/// The offline context of `query <SQL>`, which reads the file by ruling and
/// never asks the socket.
fn file_only(cli: &Cli) -> Result<Offline> {
    Ok(Offline {
        db_path: Record::resolve(cli)?.db_path,
        locked: "`query` reads the file only; stop the daemon for it".to_string(),
    })
}

/// The `ts_us` of the newest gateway drop in the record, used when
/// `gateway-ramp` is invoked without `--drop`. An empty record is an error
/// naming the flag rather than a ramp plotted around an arbitrary instant.
/// Read the way every diagnosis is: the daemon first, the file when it is not
/// there.
fn latest_gw_drop(cli: &Cli) -> Result<i64> {
    let table = diagnose_table(cli, DiagnosticQuery::GwDrops, |off| {
        run_query(off, diagnosis::GW_DROPS_SQL)
    })?;
    newest_drop(&table)
}

/// The pure half of [`latest_gw_drop`]: the newest drop is the LAST row, since
/// `GW_DROPS_SQL` lists them oldest first.
fn newest_drop(table: &Table) -> Result<i64> {
    let last =
        table.rows.last().and_then(|r| r.first()).ok_or_else(|| {
            anyhow!("no gateway drop in the record; pass --drop <time> to pick one")
        })?;
    last.parse::<i64>()
        .map_err(|_| anyhow!("gateway drop has an unreadable ts_us: {last:?}"))
}

/// Heuristic over a DuckDB open error: does it indicate the file is locked by
/// another process (i.e. the daemon)? DuckDB reports this as an `IO Error`
/// mentioning a lock, e.g. `Could not set lock on file ...: Conflicting lock is
/// held`.
fn is_lock_error(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("lock")
}

/// Summarise the live [`StatusSnapshot`]: the observing state, the latest sample
/// per collector, plus an incident count. Pure over its input so it is unit-tested
/// without a socket.
fn format_status(snap: &StatusSnapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "generated_us   {}\n",
        diagnose::stamp_us(snap.generated_us)
    ));

    // While paused the daemon skips the probes entirely, so the samples below are
    // frozen at whatever they were when collection stopped — say so rather than
    // printing stale verdicts as if they were live.
    out.push_str(if snap.observing {
        "observing      on\n"
    } else {
        "observing      off (paused - samples below are stale)\n"
    });

    // The tier says what the SKIPs below mean: passive = withheld on purpose,
    // nothing on the wire; active = every probe was sent.
    out.push_str(&format!(
        "probing        {}\n",
        match snap.probing {
            ProbingTier::Passive => "passive (nothing on the wire - probe verdicts read SKIP)",
            ProbingTier::Active => "active",
        }
    ));

    match &snap.link {
        Some(l) => out.push_str(&format!(
            "link           gw={} direct={} ts_us={}\n",
            l.gw,
            l.direct,
            diagnose::stamp_us(l.ts_us)
        )),
        None => out.push_str("link           (no data)\n"),
    }

    match &snap.proxy {
        Some(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let sel = p.selector.as_deref().unwrap_or("-");
            // sing-box's own URL test (realm net-observer, node #62): the
            // newest row of a tick is the selected node's, so this is its
            // test, aged against the snapshot's own instant; `-` = no reading
            // (a pre-field daemon, no group).
            let urltest = p
                .urltest_label(snap.generated_us)
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "proxy          tun={tun} selector={sel} urltest={urltest} ts_us={}\n",
                diagnose::stamp_us(p.ts_us)
            ));
        }
        None => out.push_str("proxy          (no data)\n"),
    }

    match &snap.dns {
        Some(d) => out.push_str(&format!(
            "dns            {} {}/{} ts_us={}\n",
            d.verdict,
            d.probe,
            d.server,
            diagnose::stamp_us(d.ts_us)
        )),
        None => out.push_str("dns            (no data)\n"),
    }

    match &snap.host {
        Some(h) => {
            // Disk and swap are optional facts: `-` is "not measured", which a
            // pre-field daemon always reports, and is never a zero.
            let dash = || "-".to_string();
            let disk_pct = h
                .disk_used_pct
                .map(|p| format!("{p:.1}"))
                .unwrap_or_else(dash);
            let disk_free = h.disk_free_mb.map(|m| m.to_string()).unwrap_or_else(dash);
            let swap = h.swap_used_mb.map(|m| m.to_string()).unwrap_or_else(dash);
            out.push_str(&format!(
                "host           load1={} load5={} load15={} disk_used_pct={disk_pct} \
                 disk_free_mb={disk_free} swap_used_mb={swap} ts_us={}\n",
                h.load1,
                h.load5,
                h.load15,
                diagnose::stamp_us(h.ts_us)
            ));
        }
        None => out.push_str("host           (no data)\n"),
    }

    let open = snap
        .incidents
        .iter()
        .filter(|i| i.closed_us.is_none())
        .count();
    out.push_str(&format!(
        "incidents      {} ({open} open)\n",
        snap.incidents.len()
    ));
    out
}

/// Render [`IncidentSummary`] rows as a fixed-width table. An open incident (no
/// `closed_us`) shows `open`. Pure over its input so it is unit-tested directly.
fn format_incidents(rows: &[IncidentSummary]) -> String {
    // The instants are `<raw> (<local ISO>)`, so they no longer fit a right-aligned
    // numeric column — they are left-aligned like the identifiers beside them.
    let mut out = format!(
        "{:<20} {:<16} {:<40} {}\n",
        "ID", "TRIGGER", "OPENED", "CLOSED"
    );
    for i in rows {
        let closed = match i.closed_us {
            Some(c) => diagnose::stamp_us(c),
            None => "open".to_string(),
        };
        out.push_str(&format!(
            "{:<20} {:<16} {:<40} {closed}\n",
            i.id,
            i.trigger_id,
            diagnose::stamp_us(i.opened_us)
        ));
    }
    out
}

/// Render a generic query result as a simple space-padded table.
fn format_table(table: &Table) -> String {
    let mut widths: Vec<usize> = table.columns.iter().map(String::len).collect();
    for row in &table.rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.len());
            }
        }
    }
    let mut out = String::new();
    push_row(&mut out, &table.columns, &widths);
    for row in &table.rows {
        push_row(&mut out, row, &widths);
    }
    out
}

fn push_row(out: &mut String, cells: &[String], widths: &[usize]) {
    for (i, cell) in cells.iter().enumerate() {
        let width = widths.get(i).copied().unwrap_or(0);
        out.push_str(cell);
        for _ in cell.len()..width {
            out.push(' ');
        }
        out.push_str("  ");
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_observer_ipc::{Event, Gap, Ready, StreamError, StreamErrorCode};
    use types::{GwVerdict, LinkSample, ObservingEdge, ProxySample, TcpVerdict};

    fn incident(id: &str, trigger: &str, opened: i64, closed: Option<i64>) -> IncidentSummary {
        IncidentSummary {
            id: id.into(),
            opened_us: opened,
            closed_us: closed,
            trigger_id: trigger.into(),
            signature: "sig".into(),
        }
    }

    #[test]
    fn format_incidents_renders_rows() {
        let out = format_incidents(&[incident("i1", "gw-drop", 1000, Some(2000))]);
        assert!(out.contains("gw-drop") && out.contains("1000") && out.contains("2000"));
    }

    /// Raw microseconds alone are unreadable: both instants must also carry the
    /// local rendering `diagnose::stamp_us` produces, and the header must name
    /// the columns for what they now hold.
    #[test]
    fn format_incidents_dates_both_instants() {
        let out = format_incidents(&[incident("i1", "gw-drop", 1000, Some(2000))]);
        assert!(out.contains(&diagnose::stamp_us(1000)), "opened: {out}");
        assert!(out.contains(&diagnose::stamp_us(2000)), "closed: {out}");
        assert!(out.contains("OPENED") && out.contains("CLOSED"));
    }

    /// An open incident still has no close instant — the word stays, and the
    /// dating must not invent one.
    #[test]
    fn format_incidents_open_row_is_dated_but_not_closed() {
        let out = format_incidents(&[incident("i2", "wedge", 5000, None)]);
        assert!(out.contains(&diagnose::stamp_us(5000)), "opened: {out}");
        assert!(out.contains("open"));
    }

    #[test]
    fn format_incidents_marks_open_incidents() {
        let out = format_incidents(&[incident("i2", "wedge", 5000, None)]);
        assert!(out.contains("wedge") && out.contains("open"));
    }

    /// A populated snapshot (link + proxy, two incidents, one open) whose
    /// observing state the caller picks.
    fn snapshot(observing: bool) -> StatusSnapshot {
        StatusSnapshot {
            generated_us: 100,
            link: Some(LinkSample {
                ts_us: 42,
                gw: GwVerdict::Ok,
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
            }),
            proxy: Some(ProxySample {
                ts_us: 43,
                server_ip: "1.2.3.4".into(),
                tcp: TcpVerdict::Ok,
                rtt_ms: None,
                tun_code: Some(204),
                selector: Some("auto".into()),
                est_direct_alive: None,
                est_direct_age_s: None,
                est_tun_alive: None,
                est_tun_age_s: None,
                urltest_ms: Some(202),
                urltest_at_us: Some(-4_999_900),
                urltest_node: Some("auto".into()),
                urltest_absent_since_us: None,
            }),
            dns: None,
            host: None,
            wifi: None,
            neighbors: None,
            topology: Vec::new(),
            neighbor_lifetimes: Vec::new(),
            topology_lifetimes: Vec::new(),
            incidents: vec![
                incident("i1", "wedge", 80, None),
                incident("i2", "gw-drop", 60, Some(70)),
            ],
            observing,
            probing: ProbingTier::Active,
            capabilities: None,
        }
    }

    #[test]
    fn format_status_renders_snapshot() {
        let out = format_status(&snapshot(true));
        assert!(out.contains(&format!("generated_us   {}", diagnose::stamp_us(100))));
        assert!(out.contains("observing      on"));
        assert!(out.contains("probing        active"));
        assert!(out.contains(&format!(
            "link           gw=OK direct=OK ts_us={}",
            diagnose::stamp_us(42)
        )));
        assert!(out.contains(&format!(
            "proxy          tun=204 selector=auto urltest=auto:202ms@5s ts_us={}",
            diagnose::stamp_us(43)
        )));
        assert!(out.contains("dns            (no data)"));
        assert!(out.contains("host           (no data)"));
        // Two incidents, one still open.
        assert!(out.contains("incidents      2 (1 open)"));
    }

    /// The host line carries the record volume's usage and the swap in use
    /// next to the load triple, and prints `-` for a value the daemon did not
    /// measure (a pre-field daemon never does) rather than a zero.
    #[test]
    fn format_status_host_line_shows_disk_and_swap_or_a_dash() {
        use types::HostSample;
        let host = HostSample {
            ts_us: 44,
            load1: 1.5,
            load5: 1.0,
            load15: 0.5,
            disk_used_pct: Some(87.54),
            disk_free_mb: Some(61_440),
            swap_used_mb: Some(1235),
        };
        let measured = StatusSnapshot {
            host: Some(host.clone()),
            ..snapshot(true)
        };
        assert!(format_status(&measured).contains(&format!(
            "host           load1=1.5 load5=1 load15=0.5 disk_used_pct=87.5 \
             disk_free_mb=61440 swap_used_mb=1235 ts_us={}",
            diagnose::stamp_us(44)
        )));

        let unmeasured = StatusSnapshot {
            host: Some(HostSample {
                disk_used_pct: None,
                disk_free_mb: None,
                swap_used_mb: None,
                ..host
            }),
            ..snapshot(true)
        };
        assert!(format_status(&unmeasured).contains(
            "host           load1=1.5 load5=1 load15=0.5 disk_used_pct=- \
             disk_free_mb=- swap_used_mb=- ts_us="
        ));
    }

    #[test]
    fn format_status_marks_paused_snapshot_as_stale() {
        // Paused: the daemon skips the probes, so the samples are frozen — the
        // line must say so instead of letting them read as live.
        let out = format_status(&snapshot(false));
        assert!(out.contains("observing      off (paused - samples below are stale)"));
        assert!(!out.contains("observing      on"));
        // The rest of the snapshot still renders.
        assert!(out.contains(&format!(
            "link           gw=OK direct=OK ts_us={}",
            diagnose::stamp_us(42)
        )));
    }

    /// A passive daemon says so on its own line, and says what it means for
    /// the verdicts below — a reader must not take their SKIPs for failed
    /// probes.
    #[test]
    fn format_status_names_the_passive_tier() {
        let snap = StatusSnapshot {
            probing: ProbingTier::Passive,
            ..snapshot(true)
        };
        let out = format_status(&snap);
        assert!(
            out.contains("probing        passive (nothing on the wire - probe verdicts read SKIP)"),
            "{out}"
        );
        assert!(!out.contains("probing        active"));
    }

    #[test]
    fn format_status_shows_placeholders_when_empty() {
        let out = format_status(&StatusSnapshot::default());
        assert!(out.contains("link           (no data)"));
        assert!(out.contains("proxy          (no data)"));
        assert!(out.contains("incidents      0 (0 open)"));
    }

    #[test]
    fn format_table_renders_header_and_cells() {
        let table = Table {
            columns: vec!["ts_us".into(), "gw".into()],
            rows: vec![vec!["42".into(), "OK".into()]],
        };
        let out = format_table(&table);
        assert!(out.contains("ts_us") && out.contains("gw"));
        assert!(out.contains("42") && out.contains("OK"));
    }

    /// An explicit `--db` means the operator named the record: the socket is
    /// NOT asked — a daemon answering over a file the operator pointed at
    /// would be an answer from the wrong record, silently.
    #[test]
    fn an_explicit_db_never_asks_the_socket() {
        let asked = std::cell::Cell::new(false);
        let r = route(None, |_| {
            asked.set(true);
            Ok(QueryOutcome::Table(Table::default()))
        })
        .unwrap();
        match r {
            Route::Offline { why: None, locked } => {
                assert!(locked.contains("--db was given"), "{locked}");
            }
            other => panic!("expected Offline without a reason, got {other:?}"),
        }
        assert!(
            !asked.get(),
            "the socket must not be asked when --db is given"
        );
    }

    #[test]
    fn a_daemon_that_answers_is_the_live_source() {
        let t = Table {
            columns: vec!["a".into()],
            rows: vec![],
        };
        let r = route(Some("/run/observer.sock"), |s| {
            assert_eq!(s, "/run/observer.sock");
            Ok(QueryOutcome::Table(t.clone()))
        })
        .unwrap();
        assert_eq!(
            r,
            Route::Live {
                table: t,
                via: "/run/observer.sock".into()
            }
        );
    }

    /// Nothing listening on the socket is the ONE case that reads the file by
    /// itself — and the reason names the socket that was tried, so a reader
    /// pointed at the wrong socket sees that rather than a silent detour; the
    /// lock sentence names it again.
    #[test]
    fn no_daemon_on_the_socket_reads_the_file_and_names_the_socket() {
        let r = route(Some("/run/observer.sock"), |_| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"))
        })
        .unwrap();
        match r {
            Route::Offline {
                why: Some(why),
                locked,
            } => {
                assert!(why.contains("/run/observer.sock"), "{why}");
                assert!(locked.contains("/run/observer.sock"), "{locked}");
                assert!(locked.contains("did not answer"), "{locked}");
            }
            other => panic!("expected Offline with a reason, got {other:?}"),
        }
    }

    /// A daemon too old to read the request also sends the reader to the file,
    /// saying so and naming the socket.
    #[test]
    fn an_old_daemon_reads_the_file_and_says_why() {
        let r = route(Some("/run/observer.sock"), |_| {
            Ok(QueryOutcome::Unsupported(
                "bad request: unknown variant `Query`".into(),
            ))
        })
        .unwrap();
        match r {
            Route::Offline { why: Some(why), .. } => {
                assert!(why.contains("/run/observer.sock"), "{why}");
                assert!(why.contains("unknown variant `Query`"), "{why}");
            }
            other => panic!("expected Offline with a reason, got {other:?}"),
        }
    }

    /// `gaps` asks `Silences`; a daemon that cannot read it is asked `Gaps`
    /// instead, and only then. A daemon that answers `Silences` — with a
    /// table, or with a failure — is never asked twice.
    #[test]
    fn gaps_asks_silences_first_and_gaps_only_on_an_old_daemon() {
        use std::cell::RefCell;
        let asked: RefCell<Vec<DiagnosticQuery>> = RefCell::new(Vec::new());

        // An old daemon: `Silences` is undecodable, `Gaps` answers — and the
        // note says what that answer lacks.
        let (out, note) = ask_silences_or_gaps("/run/observer.sock", |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(match q {
                DiagnosticQuery::Silences => {
                    QueryOutcome::Unsupported("bad request: unknown variant `Silences`".into())
                }
                _ => QueryOutcome::Table(Table::default()),
            })
        })
        .unwrap();
        assert_eq!(out, QueryOutcome::Table(Table::default()));
        assert_eq!(
            *asked.borrow(),
            vec![DiagnosticQuery::Silences, DiagnosticQuery::Gaps]
        );
        let note = note.expect("a daemon that answered `Gaps` earns the note");
        assert!(note.contains("passive stretches not listed"), "{note}");

        // A daemon too old for `Query` at all: `Unsupported` twice, NO note —
        // `route` then reads the file with the full query, which does list
        // the stretches, and a note here would contradict the table under it.
        asked.borrow_mut().clear();
        let (out, note) = ask_silences_or_gaps("/run/observer.sock", |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(QueryOutcome::Unsupported(
                "bad request: unknown variant `Query`".into(),
            ))
        })
        .unwrap();
        assert!(matches!(out, QueryOutcome::Unsupported(_)));
        assert_eq!(
            *asked.borrow(),
            vec![DiagnosticQuery::Silences, DiagnosticQuery::Gaps]
        );
        assert_eq!(
            note, None,
            "no daemon answered `Gaps`, so nothing to warn about"
        );

        // A current daemon: one question, no note.
        asked.borrow_mut().clear();
        let (out, note) = ask_silences_or_gaps("/run/observer.sock", |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(QueryOutcome::Table(Table::default()))
        })
        .unwrap();
        assert_eq!(out, QueryOutcome::Table(Table::default()));
        assert_eq!(*asked.borrow(), vec![DiagnosticQuery::Silences]);
        assert_eq!(note, None);

        // A daemon that read `Silences` and failed it: reported, not retried.
        asked.borrow_mut().clear();
        let (out, note) = ask_silences_or_gaps("/run/observer.sock", |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(QueryOutcome::Failed("boom".into()))
        })
        .unwrap();
        assert_eq!(out, QueryOutcome::Failed("boom".into()));
        assert_eq!(*asked.borrow(), vec![DiagnosticQuery::Silences]);
        assert_eq!(note, None);
    }

    /// `air` routes once, from `AirScan`, and reuses that choice for `AirAps`
    /// and `AirSelfChannel`: a daemon answering all three is asked all three,
    /// `AirAps` pinned to the `ts_us` the scan itself answered with (never
    /// re-routed); an old daemon `Unsupported` on the first question sends
    /// the whole group to the file without asking the other two at all; and a
    /// scan with no row at all — an empty record — is not a moment to pin
    /// anything to, so `AirAps` is skipped rather than asked with a made-up
    /// `ts_us`.
    #[test]
    fn air_asks_all_three_on_a_live_daemon_and_none_on_an_old_one() {
        use std::cell::RefCell;
        let asked: RefCell<Vec<DiagnosticQuery>> = RefCell::new(Vec::new());

        let scan_at = |ts_us: &str| Table {
            columns: vec!["ts_us".into()],
            rows: vec![vec![ts_us.into()]],
        };
        let t = |col: &str| Table {
            columns: vec![col.into()],
            rows: vec![],
        };
        let r = route_air(Some("/run/observer.sock"), |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(QueryOutcome::Table(match q {
                DiagnosticQuery::AirScan => scan_at("1000"),
                DiagnosticQuery::AirAps { scan_ts_us } => {
                    assert_eq!(
                        scan_ts_us, 1000,
                        "AirAps must be pinned to the scan's ts_us"
                    );
                    t("channel")
                }
                DiagnosticQuery::AirSelfChannel => t("channel_band"),
                other => panic!("air must not ask {other:?}"),
            }))
        })
        .unwrap();
        assert_eq!(
            *asked.borrow(),
            vec![
                DiagnosticQuery::AirScan,
                DiagnosticQuery::AirAps { scan_ts_us: 1000 },
                DiagnosticQuery::AirSelfChannel
            ]
        );
        match r {
            AirRoute::Live {
                scan,
                aps,
                own,
                via,
            } => {
                assert_eq!(scan, scan_at("1000"));
                assert_eq!(aps, t("channel"));
                assert_eq!(own, t("channel_band"));
                assert_eq!(via, "/run/observer.sock");
            }
            other => panic!("expected Live, got {other:?}"),
        }

        // An old daemon: `Unsupported` on the first question alone sends the
        // whole group to the file — `AirAps`/`AirSelfChannel` are never asked.
        asked.borrow_mut().clear();
        let r = route_air(Some("/run/observer.sock"), |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(QueryOutcome::Unsupported(
                "bad request: unknown variant `AirScan`".into(),
            ))
        })
        .unwrap();
        assert_eq!(*asked.borrow(), vec![DiagnosticQuery::AirScan]);
        match r {
            AirRoute::Offline { why: Some(why), .. } => {
                assert!(why.contains("AirScan"), "{why}");
            }
            other => panic!("expected Offline with a reason, got {other:?}"),
        }

        // An empty record: the scan answers with no row, so there is nothing
        // to pin `AirAps` to — it is asked `AirSelfChannel` only.
        asked.borrow_mut().clear();
        let r = route_air(Some("/run/observer.sock"), |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(QueryOutcome::Table(match q {
                DiagnosticQuery::AirScan => Table {
                    columns: vec!["ts_us".into()],
                    rows: vec![],
                },
                DiagnosticQuery::AirSelfChannel => t("channel_band"),
                other => panic!("air must not ask {other:?}"),
            }))
        })
        .unwrap();
        assert_eq!(
            *asked.borrow(),
            vec![DiagnosticQuery::AirScan, DiagnosticQuery::AirSelfChannel]
        );
        match r {
            AirRoute::Live { aps, .. } => assert_eq!(aps, Table::default()),
            other => panic!("expected Live, got {other:?}"),
        }
    }

    /// A daemon that answers the scan live and then fails or cannot decode
    /// `AirAps` is a hard error, never a silent detour to the file: falling
    /// back there would risk pairing the live scan just read with a stale
    /// offline AP list from a different moment. Modelled on the
    /// `Silences`-failed case in
    /// `gaps_asks_silences_first_and_gaps_only_on_an_old_daemon`.
    #[test]
    fn air_errors_on_a_daemon_that_fails_mid_group_never_falls_to_the_file() {
        use std::cell::RefCell;
        let asked: RefCell<Vec<DiagnosticQuery>> = RefCell::new(Vec::new());
        let scan_table = Table {
            columns: vec!["ts_us".into()],
            rows: vec![vec!["1000".into()]],
        };

        let failed = route_air(Some("/run/observer.sock"), |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(match q {
                DiagnosticQuery::AirScan => QueryOutcome::Table(scan_table.clone()),
                DiagnosticQuery::AirAps { .. } => QueryOutcome::Failed("boom".into()),
                other => panic!("must not ask {other:?}"),
            })
        })
        .unwrap_err()
        .to_string();
        assert!(failed.contains("boom"), "{failed}");
        assert_eq!(
            *asked.borrow(),
            vec![
                DiagnosticQuery::AirScan,
                DiagnosticQuery::AirAps { scan_ts_us: 1000 }
            ],
            "a failure on AirAps must not be followed by AirSelfChannel either"
        );

        // `Unsupported` mid-group is the same: an error, not a fallback — the
        // daemon just answered the scan, so it is current enough that
        // "cannot decode AirAps" cannot mean "too old", and the file must not
        // silently stand in.
        asked.borrow_mut().clear();
        let unsupported = route_air(Some("/run/observer.sock"), |_, q| {
            asked.borrow_mut().push(q.clone());
            Ok(match q {
                DiagnosticQuery::AirScan => QueryOutcome::Table(scan_table.clone()),
                DiagnosticQuery::AirAps { .. } => {
                    QueryOutcome::Unsupported("bad request: unknown variant `AirAps`".into())
                }
                other => panic!("must not ask {other:?}"),
            })
        })
        .unwrap_err()
        .to_string();
        assert!(unsupported.contains("AirAps"), "{unsupported}");
        assert_eq!(
            *asked.borrow(),
            vec![
                DiagnosticQuery::AirScan,
                DiagnosticQuery::AirAps { scan_ts_us: 1000 }
            ]
        );
    }

    /// A daemon that read the request and could not run it, and a socket that
    /// is there but broken, are errors — never a detour to the file, where the
    /// lock would report the wrong problem.
    #[test]
    fn a_failed_diagnosis_and_a_broken_socket_are_errors_not_detours() {
        let failed = route(Some("/run/observer.sock"), |_| {
            Ok(QueryOutcome::Failed("not a segment key: nope".into()))
        })
        .unwrap_err()
        .to_string();
        assert!(failed.contains("not a segment key"), "{failed}");

        let broken = route(Some("/run/observer.sock"), |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no",
            ))
        })
        .unwrap_err()
        .to_string();
        assert!(broken.contains("/run/observer.sock"), "{broken}");
    }

    /// The lock message never contradicts what just happened: it names the
    /// record and repeats the reason the file was read at all.
    #[test]
    fn the_lock_message_names_the_record_and_the_reason() {
        let m = lock_message(
            "/var/lib/observer/observer.duckdb",
            "the socket at /run/observer.sock did not answer or could not decode the request",
        );
        assert!(m.contains("/var/lib/observer/observer.duckdb"), "{m}");
        assert!(m.contains("/run/observer.sock"), "{m}");
        assert!(!m.contains("read the running daemon"), "{m}");
    }

    /// The offline path renders through the wire shape: the conversion must
    /// keep every cell, the empty-string `NULL` included.
    #[test]
    fn table_from_query_keeps_every_cell() {
        let q = QueryTable {
            columns: vec!["a".into(), "b".into()],
            rows: vec![vec!["1".into(), "".into()], vec!["".into(), "x".into()]],
        };
        let t = table_from_query(q.clone());
        assert_eq!(t.columns, q.columns);
        assert_eq!(t.rows, q.rows);
    }

    /// `GW_DROPS_SQL` lists drops oldest first, so the newest is the LAST row;
    /// an empty record names the flag to pass instead of inventing a moment.
    #[test]
    fn newest_drop_is_the_last_row_and_an_empty_record_names_the_flag() {
        let table = Table {
            columns: vec!["ts_us".into(), "gw".into()],
            rows: vec![
                vec!["100".into(), "FAIL".into()],
                vec!["900".into(), "NOGW".into()],
            ],
        };
        assert_eq!(newest_drop(&table).unwrap(), 900);
        let e = newest_drop(&Table::default()).unwrap_err().to_string();
        assert!(e.contains("--drop"), "{e}");
    }

    #[test]
    fn format_control_ok_reports_success() {
        let out = format_control(&ControlResult {
            ok: true,
            message: "kickstarted system/sing-box".into(),
        });
        assert_eq!(out, "ok: kickstarted system/sing-box\n");
    }

    #[test]
    fn format_control_refused_reports_failure() {
        // The daemon refuses a peer it does not authorise.
        let out = format_control(&ControlResult {
            ok: false,
            message: "control refused: peer credentials unavailable".into(),
        });
        assert_eq!(
            out,
            "failed: control refused: peer credentials unavailable\n"
        );
    }

    #[test]
    fn observe_state_maps_to_control_bool() {
        // `on` resumes collection, `off` pauses it.
        assert!(ObserveState::On.as_bool());
        assert!(!ObserveState::Off.as_bool());
    }

    #[test]
    fn is_lock_error_detects_duckdb_lock_message() {
        // Representative DuckDB message when the daemon holds the file lock.
        let locked = "IO Error: Could not set lock on file \"/var/lib/observer/observer.duckdb\": \
             Conflicting lock is held in /usr/bin/net-observerd (PID 4242)";
        assert!(is_lock_error(locked));
    }

    #[test]
    fn is_lock_error_ignores_unrelated_errors() {
        assert!(!is_lock_error(
            "Catalog Error: Table with name link_sample does not exist!"
        ));
        assert!(!is_lock_error(
            "Parser Error: syntax error at or near \"SELCT\""
        ));
    }

    #[test]
    fn event_kind_arg_maps_to_wire_kind() {
        assert_eq!(EventKindArg::Link.to_kind(), EventKind::Link);
        assert_eq!(EventKindArg::Proxy.to_kind(), EventKind::Proxy);
        assert_eq!(EventKindArg::Dns.to_kind(), EventKind::Dns);
        assert_eq!(EventKindArg::Route.to_kind(), EventKind::Route);
        assert_eq!(EventKindArg::Host.to_kind(), EventKind::Host);
        assert_eq!(EventKindArg::Wifi.to_kind(), EventKind::Wifi);
        assert_eq!(EventKindArg::Neighbors.to_kind(), EventKind::Neighbors);
        assert_eq!(EventKindArg::Connections.to_kind(), EventKind::Connections);
        assert_eq!(EventKindArg::SingboxLog.to_kind(), EventKind::SingboxLog);
        assert_eq!(EventKindArg::Incident.to_kind(), EventKind::Incident);
        assert_eq!(
            EventKindArg::IncidentClosed.to_kind(),
            EventKind::IncidentClosed
        );
    }

    /// `events --kind` takes every kind by the label `EventKind::as_str` gives
    /// it — the two-word one included, which clap spells in kebab-case exactly
    /// as the wire label does (realm net-observer, node #135).
    #[test]
    fn events_kind_accepts_every_wire_label() {
        for kind in EventKind::ALL {
            let cli = Cli::try_parse_from(["net-observer-cli", "events", "--kind", kind.as_str()])
                .unwrap_or_else(|e| panic!("{}: {e}", kind.as_str()));
            match cli.command {
                Command::Events { kind: Some(arg) } => {
                    assert_eq!(arg.to_kind(), *kind, "{}", kind.as_str());
                }
                _ => panic!("{} did not parse as `events --kind`", kind.as_str()),
            }
        }
    }

    /// The list a `--kind` sends: `incident` subscribes to the closes as well,
    /// `incident-closed` alone stays selectable, and any other kind is just
    /// itself (realm net-observer, node #135).
    #[test]
    fn events_kind_incident_subscribes_to_closes_too() {
        assert_eq!(
            EventKindArg::Incident.to_kinds(),
            vec![EventKind::Incident, EventKind::IncidentClosed]
        );
        assert_eq!(
            EventKindArg::IncidentClosed.to_kinds(),
            vec![EventKind::IncidentClosed]
        );
        assert_eq!(EventKindArg::Link.to_kinds(), vec![EventKind::Link]);
    }

    /// `connections --by` takes the four groupings by their lowercase names,
    /// defaults to `host`, and maps onto the wire type the daemon reads.
    #[test]
    fn connections_by_parses_every_grouping_and_defaults_to_host() {
        let parse = |args: &[&str]| {
            let cli = Cli::try_parse_from(
                std::iter::once("net-observer-cli").chain(args.iter().copied()),
            )
            .unwrap_or_else(|e| panic!("{args:?}: {e}"));
            match cli.command {
                Command::Connections { by, .. } => by,
                _ => panic!("{args:?} did not parse as `connections`"),
            }
        };
        assert_eq!(parse(&["connections"]), GroupByArg::Host);
        for (token, arg, wire) in [
            ("host", GroupByArg::Host, ConnectionsGroupBy::Host),
            ("ip", GroupByArg::Ip, ConnectionsGroupBy::Ip),
            ("ip-port", GroupByArg::IpPort, ConnectionsGroupBy::IpPort),
            ("process", GroupByArg::Process, ConnectionsGroupBy::Process),
        ] {
            let by = parse(&["connections", "--by", token]);
            assert_eq!(by, arg, "{token}");
            assert_eq!(by.to_group_by(), wire, "{token}");
        }
        assert!(Cli::try_parse_from(["net-observer-cli", "connections", "--by", "port"]).is_err());
    }

    /// `connections` shows external flows by default; `--scope` picks one
    /// scope by its token, `--all` lifts the fold, and the two exclude each
    /// other.
    #[test]
    fn connections_parses_all_and_scope_and_they_exclude_each_other() {
        let parse = |args: &[&str]| {
            let cli = Cli::try_parse_from(
                std::iter::once("net-observer-cli").chain(args.iter().copied()),
            )
            .unwrap_or_else(|e| panic!("{args:?}: {e}"));
            match cli.command {
                Command::Connections { all, scope, .. } => (all, scope),
                _ => panic!("{args:?} did not parse as `connections`"),
            }
        };
        assert_eq!(parse(&["connections"]), (false, None));
        assert_eq!(parse(&["connections", "--all"]), (true, None));
        for (token, arg, scope) in [
            ("internal", ScopeArg::Internal, ConnectionScope::Internal),
            ("lan", ScopeArg::Lan, ConnectionScope::Lan),
            ("external", ScopeArg::External, ConnectionScope::External),
        ] {
            let (all, parsed) = parse(&["connections", "--scope", token]);
            assert!(!all);
            assert_eq!(parsed, Some(arg), "{token}");
            assert_eq!(arg.to_scope(), scope, "{token}");
        }
        assert!(
            Cli::try_parse_from(["net-observer-cli", "connections", "--scope", "vpn"]).is_err()
        );
        assert!(
            Cli::try_parse_from(["net-observer-cli", "connections", "--all", "--scope", "lan"])
                .is_err(),
            "--all and --scope contradict each other"
        );
    }

    /// The daemon's `Connections` table with its `scope` column: the tick
    /// measured on the owner's Mac in miniature — 1023 DNS flows to the TUN
    /// address, four LAN flows, the tunnel's own traffic — plus a `SKIP`
    /// marker row from a second table.
    fn scoped_table(rows: Vec<[&str; 8]>) -> Table {
        Table {
            columns: [
                "ts_us", "verdict", "key", "scope", "count", "upload", "download", "hosts",
            ]
            .map(String::from)
            .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    fn measured_tick() -> Table {
        scoped_table(vec![
            ["7", "OK", "172.19.0.1", "internal", "1023", "1", "1", ""],
            ["7", "OK", "printer.local", "lan", "4", "1", "1", ""],
            ["7", "OK", "claude.ai", "external", "3", "100", "5006", ""],
            ["7", "OK", "149.154.167.41", "external", "2", "30", "0", ""],
        ])
    }

    /// By default the external rows are listed without the `scope` column
    /// (every row shown shares it) and the rest are counted, as flows, on
    /// the last line in the brief's words; `--all` keeps everything; a scope
    /// with nothing hidden has no last line.
    #[test]
    fn the_fold_keeps_one_scope_and_counts_the_hidden_flows() {
        let (shown, hidden) = fold_by_scope(&measured_tick(), Some(ConnectionScope::External));
        assert_eq!(
            shown.columns,
            [
                "ts_us", "verdict", "key", "count", "upload", "download", "hosts"
            ]
        );
        let keys: Vec<&str> = shown.rows.iter().map(|r| r[2].as_str()).collect();
        assert_eq!(keys, ["claude.ai", "149.154.167.41"]);
        assert_eq!(
            shown.rows[0],
            ["7", "OK", "claude.ai", "3", "100", "5006", ""]
        );
        assert_eq!(hidden, [1023, 4, 0]);
        assert_eq!(
            hidden_line(hidden).as_deref(),
            Some("+1023 internal (dns/plumbing), +4 lan hidden — --all shows them")
        );

        let (shown, hidden) = fold_by_scope(&measured_tick(), Some(ConnectionScope::Lan));
        let keys: Vec<&str> = shown.rows.iter().map(|r| r[2].as_str()).collect();
        assert_eq!(keys, ["printer.local"]);
        assert_eq!(hidden, [1023, 0, 5]);
        assert_eq!(
            hidden_line(hidden).as_deref(),
            Some("+1023 internal (dns/plumbing), +5 external hidden — --all shows them")
        );

        let (shown, hidden) = fold_by_scope(&measured_tick(), None);
        assert_eq!(shown, measured_tick());
        assert_eq!(hidden, [0; 3]);
        assert_eq!(hidden_line(hidden), None);
    }

    /// The empty-tick marker row is not a flow and belongs to no scope: it
    /// is kept under every scope, with its `scope` cell dropped like the
    /// others, and hides nothing.
    #[test]
    fn the_fold_keeps_the_empty_tick_marker_under_every_scope() {
        let skipped = scoped_table(vec![["7", "SKIP", "", "", "", "", "", ""]]);
        for keep in ConnectionScope::ALL {
            let (shown, hidden) = fold_by_scope(&skipped, Some(keep));
            assert_eq!(
                shown.rows,
                vec![["7", "SKIP", "", "", "", "", ""]],
                "{keep}"
            );
            assert_eq!(hidden, [0; 3], "{keep}");
            assert_eq!(hidden_line(hidden), None, "{keep}");
        }
    }

    /// An older daemon's table has no `scope` column: every row is
    /// `external` — shown under the default, never hidden — and the table
    /// passes through with its columns as they were.
    #[test]
    fn a_table_without_a_scope_column_is_all_external() {
        let older = Table {
            columns: [
                "ts_us", "verdict", "key", "count", "upload", "download", "hosts",
            ]
            .map(String::from)
            .to_vec(),
            rows: vec![
                ["7", "OK", "172.19.0.1", "1023", "1", "1", ""]
                    .map(String::from)
                    .to_vec(),
            ],
        };
        let (shown, hidden) = fold_by_scope(&older, Some(ConnectionScope::External));
        assert_eq!(shown, older);
        assert_eq!(hidden, [0; 3]);
        let (shown, hidden) = fold_by_scope(&older, Some(ConnectionScope::Internal));
        assert!(shown.rows.is_empty());
        assert_eq!(hidden, [0, 0, 1023]);
    }

    /// `experiment` defaults to the shared default length and waits;
    /// `--minutes` and `--no-wait` are read; `experiment-report` takes the
    /// id as it was printed.
    #[test]
    fn experiment_parses_its_length_and_no_wait_and_the_report_its_id() {
        let parse = |args: &[&str]| {
            Cli::try_parse_from(std::iter::once("net-observer-cli").chain(args.iter().copied()))
                .unwrap_or_else(|e| panic!("{args:?}: {e}"))
                .command
        };
        match parse(&["experiment"]) {
            Command::Experiment { minutes, no_wait } => {
                assert_eq!(minutes, EXPERIMENT_DEFAULT_MINUTES);
                assert!(!no_wait);
            }
            _ => panic!("did not parse as `experiment`"),
        }
        match parse(&["experiment", "--minutes", "7", "--no-wait"]) {
            Command::Experiment { minutes, no_wait } => {
                assert_eq!(minutes, 7);
                assert!(no_wait);
            }
            _ => panic!("did not parse as `experiment`"),
        }
        match parse(&["experiment-report", "experiment-42"]) {
            Command::ExperimentReport { id } => assert_eq!(id, "experiment-42"),
            _ => panic!("did not parse as `experiment-report`"),
        }
        assert!(Cli::try_parse_from(["net-observer-cli", "experiment", "--minutes", "x"]).is_err());
        assert!(Cli::try_parse_from(["net-observer-cli", "experiment-report"]).is_err());
        // A 5-minute window gets its 60 polls and the grace on top.
        assert_eq!(experiment_polls(5), 60 + POLL_GRACE);
    }

    /// The poll waits through the daemon's own "still running" — sleeping
    /// between asks, asking for the SAME id every time — and returns the
    /// table the moment it comes.
    #[test]
    fn experiment_poll_waits_through_still_running_then_takes_the_table() {
        use std::cell::RefCell;
        let asked: RefCell<Vec<DiagnosticQuery>> = RefCell::new(Vec::new());
        let slept: RefCell<Vec<Duration>> = RefCell::new(Vec::new());
        let report = Table {
            columns: vec!["key".into(), "value".into()],
            rows: vec![vec!["id".into(), "experiment-42".into()]],
        };
        let table = await_experiment(
            "/run/observer.sock",
            "experiment-42",
            10,
            |_, q| {
                asked.borrow_mut().push(q.clone());
                Ok(if asked.borrow().len() < 3 {
                    QueryOutcome::Failed(net_observer_ipc::experiment_running_message(
                        "experiment-42",
                        99,
                    ))
                } else {
                    QueryOutcome::Table(report.clone())
                })
            },
            |d| slept.borrow_mut().push(d),
        )
        .unwrap();
        assert_eq!(table, report);
        assert_eq!(asked.borrow().len(), 3);
        assert!(asked.borrow().iter().all(|q| {
            *q == DiagnosticQuery::Experiment {
                id: "experiment-42".into(),
            }
        }));
        assert_eq!(
            *slept.borrow(),
            vec![Duration::from_secs(POLL_EVERY_S); 2],
            "one sleep per still-running answer, none after the table"
        );
    }

    /// Every other answer ends the wait: a failure in the daemon's words
    /// (a window it did not run), and a daemon that cannot decode the query
    /// — neither is waited through, and each is reported as itself.
    #[test]
    fn experiment_poll_stops_on_a_real_failure_and_on_an_old_daemon() {
        let mut polls = 0;
        let e = await_experiment(
            "/run/observer.sock",
            "experiment-42",
            10,
            |_, _| {
                polls += 1;
                Ok(QueryOutcome::Failed(
                    "experiment experiment-42 not found".into(),
                ))
            },
            |_| panic!("a real failure must not be slept through"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("not found"), "{e}");
        assert_eq!(polls, 1);

        let e = await_experiment(
            "/run/observer.sock",
            "experiment-42",
            10,
            |_, _| {
                Ok(QueryOutcome::Unsupported(
                    "bad request: unknown variant `Experiment`".into(),
                ))
            },
            |_| panic!("an old daemon must not be slept through"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("cannot report experiments"), "{e}");
    }

    /// A socket that fails is waited through — the window runs in the
    /// daemon — but not for ever: past the failure budget the wait ends
    /// naming `experiment-report`, and a recovered socket resets the count.
    #[test]
    fn experiment_poll_survives_transient_socket_errors_but_not_a_lost_daemon() {
        use std::cell::RefCell;
        let polls = RefCell::new(0u32);
        let running = || {
            QueryOutcome::Failed(net_observer_ipc::experiment_running_message(
                "experiment-42",
                99,
            ))
        };
        let refused = || std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let report = Table::default();
        // Failures short of the budget, then a still-running (resets), then
        // failures short of it again, then the table.
        let table = await_experiment(
            "/run/observer.sock",
            "experiment-42",
            100,
            |_, _| {
                *polls.borrow_mut() += 1;
                let n = *polls.borrow();
                if n < MAX_POLL_FAILURES || (n > MAX_POLL_FAILURES && n < 2 * MAX_POLL_FAILURES) {
                    Err(refused())
                } else if n == MAX_POLL_FAILURES {
                    Ok(running())
                } else {
                    Ok(QueryOutcome::Table(report.clone()))
                }
            },
            |_| {},
        )
        .unwrap();
        assert_eq!(table, report);
        assert_eq!(*polls.borrow(), 2 * MAX_POLL_FAILURES);

        let e = await_experiment(
            "/run/observer.sock",
            "experiment-42",
            100,
            |_, _| Err(refused()),
            |_| {},
        )
        .unwrap_err();
        assert!(e.to_string().contains("lost net-observerd"), "{e}");
        assert!(
            e.to_string().contains("experiment-report experiment-42"),
            "{e}"
        );

        // The overall bound: a daemon that says still-running for ever.
        let mut polls = 0;
        let e = await_experiment(
            "/run/observer.sock",
            "experiment-42",
            4,
            |_, _| {
                polls += 1;
                Ok(running())
            },
            |_| {},
        )
        .unwrap_err();
        assert_eq!(polls, 4);
        assert!(
            e.to_string().contains("did not report within 4 polls"),
            "{e}"
        );
    }

    /// The table the daemon (or the file) answers renders as the grouped
    /// columns, one line per key, with a SKIP tick's empty cells still on
    /// their own line rather than vanishing.
    #[test]
    fn connections_table_renders_the_grouped_columns() {
        let table = Table {
            columns: [
                "ts_us", "verdict", "key", "count", "upload", "download", "hosts",
            ]
            .map(String::from)
            .to_vec(),
            rows: vec![
                [
                    "1",
                    "OK",
                    "194.221.250.50",
                    "2",
                    "30",
                    "0",
                    "www.google.com",
                ]
                .map(String::from)
                .to_vec(),
                ["1", "OK", "claude.ai", "1", "100", "5006", "claude.ai"]
                    .map(String::from)
                    .to_vec(),
            ],
        };
        let out = format_table(&table);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(
            lines[0].starts_with("ts_us  verdict  key             count"),
            "{out}"
        );
        assert!(
            lines[1].contains("194.221.250.50  2      30      0         www.google.com"),
            "{out}"
        );
        assert!(
            lines[2].contains("claude.ai       1      100     5006      claude.ai"),
            "{out}"
        );

        let skipped = Table {
            columns: table.columns.clone(),
            rows: vec![["7", "SKIP", "", "", "", "", ""].map(String::from).to_vec()],
        };
        let out = format_table(&skipped);
        assert_eq!(out.lines().count(), 2, "{out}");
        assert!(
            out.lines().nth(1).unwrap().starts_with("7      SKIP"),
            "{out}"
        );
    }

    #[test]
    fn clock_formats_utc_hh_mm_ss() {
        // Epoch 0 is 1970-01-01 00:00:00 UTC; 1h1m1s later reads 01:01:01.
        assert_eq!(clock(0), "1970-01-01 00:00:00");
        assert_eq!(clock(3_661_000_000), "1970-01-01 01:01:01");
        // A negative timestamp must not panic (Euclidean wrap into the day) and
        // must roll the *date* back with the time.
        assert_eq!(clock(-1), "1969-12-31 23:59:59");
    }

    /// The morning-after question the date exists to answer: two lines a day
    /// apart at the same time of day must be distinguishable. Leap-day and
    /// century boundaries are checked too, because the calendar is hand-rolled.
    #[test]
    fn clock_carries_the_date() {
        let noon = 12 * 3_600 * 1_000_000i64;
        let day = 86_400 * 1_000_000i64;
        assert_eq!(clock(noon), "1970-01-01 12:00:00");
        assert_eq!(clock(noon + day), "1970-01-02 12:00:00");
        assert_ne!(clock(noon), clock(noon + day));
        // 2024-02-29T00:00:00Z and 2000-03-01T00:00:00Z (a leap century).
        assert_eq!(clock(1_709_164_800_000_000), "2024-02-29 00:00:00");
        assert_eq!(clock(951_868_800_000_000), "2000-03-01 00:00:00");
    }

    #[test]
    fn format_frame_line_renders_ts_kind_detail() {
        let link = StreamFrame::Event(Event::Link(LinkSample {
            ts_us: 3_661_000_000,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Fail,
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
        }));
        assert_eq!(
            format_frame_line(&link),
            "1970-01-01 01:01:01  link  gw=OK direct=FAIL"
        );
    }

    #[test]
    fn format_frame_line_renders_incident() {
        let inc = StreamFrame::Event(Event::Incident(IncidentSummary {
            id: "i1".into(),
            opened_us: 0,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        }));
        assert_eq!(
            format_frame_line(&inc),
            "1970-01-01 00:00:00  incident  wedge tun dead"
        );
    }

    /// The close is its own line, clocked at the closing instant: the id ties
    /// it to the opening line above it in the tail, the rule sits in brackets,
    /// and the duration follows when the frame carries the opening (realm
    /// net-observer, node #135).
    #[test]
    fn format_frame_line_renders_an_incident_close() {
        let closed = StreamFrame::Event(Event::IncidentClosed {
            id: "wedge-0".into(),
            trigger_id: "wedge".into(),
            opened_us: Some(0),
            closed_us: 15_000_000,
        });
        assert_eq!(
            format_frame_line(&closed),
            "1970-01-01 00:00:15  incident-closed  wedge-0 (wedge) after 15s"
        );
        let unmeasured = StreamFrame::Event(Event::IncidentClosed {
            id: "wedge-0".into(),
            trigger_id: "wedge".into(),
            opened_us: None,
            closed_us: 15_000_000,
        });
        assert_eq!(
            format_frame_line(&unmeasured),
            "1970-01-01 00:00:15  incident-closed  wedge-0 (wedge)"
        );
    }

    #[test]
    fn format_frame_line_renders_a_gap() {
        // A hole in the stream is printed like any other frame — rendering a
        // contiguous timeline across a real hole would be a lie.
        let gap = StreamFrame::Gap(Gap {
            ts_us: 0,
            skipped: 12,
        });
        assert_eq!(
            format_frame_line(&gap),
            "1970-01-01 00:00:00  gap  12 events dropped (subscriber lagged)"
        );
    }

    #[test]
    fn format_frame_line_renders_the_ready_ack() {
        // The tail's opening line: the collection state stated, not inferred
        // from silence.
        let ready = StreamFrame::Ready(Ready {
            ts_us: 0,
            kinds: None,
            observing: false,
            probing: ProbingTier::Active,
        });
        assert_eq!(
            format_frame_line(&ready),
            "1970-01-01 00:00:00  subscribed  collection off; probing active; kinds: all"
        );
    }

    #[test]
    fn format_frame_line_renders_an_observing_edge() {
        let edge = StreamFrame::Observing(ObservingEdge {
            ts_us: 0,
            observing: false,
            peer_uid: Some(501),
            cause: types::ObservingCause::Control,
        });
        assert_eq!(
            format_frame_line(&edge),
            "1970-01-01 00:00:00  observing  collection off"
        );
    }

    #[test]
    fn tail_end_messages_are_never_empty() {
        // An unexplained exit is exactly what `TailEnd` exists to prevent, so
        // every variant must have something to say.
        for end in [
            TailEnd::DaemonClosed,
            TailEnd::OutputClosed,
            TailEnd::ServerError("too-many-subscribers: limit reached".into()),
            TailEnd::Failed("bad frame".into()),
        ] {
            assert!(end.message().starts_with("event stream ended: "));
            assert!(end.message().len() > "event stream ended: ".len());
        }
    }

    #[test]
    fn tail_end_exit_codes_split_orderly_from_failure() {
        // `ExitCode` is opaque and not `PartialEq`, so compare its debug form
        // against the two known constants.
        let success = format!("{:?}", ExitCode::SUCCESS);
        let failure = format!("{:?}", ExitCode::FAILURE);
        assert_ne!(success, failure);
        // Orderly: a daemon shutdown or a closed pipe is not a tail failure.
        assert_eq!(format!("{:?}", TailEnd::DaemonClosed.exit_code()), success);
        assert_eq!(format!("{:?}", TailEnd::OutputClosed.exit_code()), success);
        // Real failures.
        assert_eq!(
            format!("{:?}", TailEnd::ServerError("x: y".into()).exit_code()),
            failure
        );
        assert_eq!(
            format!("{:?}", TailEnd::Failed("boom".into()).exit_code()),
            failure
        );
    }

    #[test]
    fn tail_frames_reports_a_clean_close_as_daemon_closed() {
        let mut out: Vec<u8> = Vec::new();
        let end = tail_frames(std::iter::empty(), &mut out);
        assert_eq!(end, TailEnd::DaemonClosed);
        assert!(out.is_empty());
    }

    #[test]
    fn tail_frames_prints_a_server_error_then_ends_with_its_reason() {
        // The daemon reports a refusal IN BAND: it is printed like any frame,
        // and then names itself as the reason the tail stopped.
        let frames = vec![Ok(StreamFrame::Error(StreamError {
            ts_us: 0,
            code: StreamErrorCode::TooManySubscribers,
            message: "subscriber limit reached (256 concurrent)".into(),
        }))];
        let mut out: Vec<u8> = Vec::new();
        let end = tail_frames(frames.into_iter(), &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "1970-01-01 00:00:00  error  too-many-subscribers: subscriber limit reached \
             (256 concurrent)\n"
        );
        assert_eq!(
            end,
            TailEnd::ServerError(
                "too-many-subscribers: subscriber limit reached (256 concurrent)".into()
            )
        );
    }

    #[test]
    fn tail_frames_reports_a_read_failure_as_failed() {
        let frames = vec![Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad frame",
        ))];
        let mut out: Vec<u8> = Vec::new();
        let end = tail_frames(frames.into_iter(), &mut out);
        assert_eq!(end, TailEnd::Failed("bad frame".into()));
    }
}
