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
use clap::{ArgGroup, CommandFactory, Parser, Subcommand, ValueEnum};
use comfy_table::{CellAlignment, ContentArrangement, presets::UTF8_FULL_CONDENSED};
use config::Config;
use net_observer_ipc::{
    ControlCmd, ControlResult, DiagnosticQuery, EXPERIMENT_DEFAULT_MINUTES, EventKind,
    IncidentSummary, QueryOutcome, Request, Response, ScanOptions, StatusSnapshot, StreamFrame,
    Table,
};
use std::io::{IsTerminal, Write};
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};
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
    /// Optional path to the observer config file (TOML).
    ///
    /// Supplies the daemon socket path for every command that talks to the
    /// running daemon.
    #[arg(long)]
    config: Option<String>,
    /// Path to the observer DuckDB file [default: the `db_path` of the daemon config].
    ///
    /// Giving it means "read this file": the diagnoses then never ask the
    /// daemon's socket. Without it they ask the running daemon first and read
    /// the config's file only when nothing answers on the socket. `query <SQL>`
    /// always reads the file. Every diagnosis prints which record answered as
    /// a `source:` line on stderr.
    #[arg(long)]
    db: Option<String>,
    /// Print every row instead of capping the console output at the first N.
    ///
    /// On an interactive terminal a long table (vulns, connections,
    /// neighbors, a diagnosis, …) shows only the first 40 rows
    /// (`DEFAULT_ROW_LIMIT`) and notes how many more exist; piping or
    /// redirecting always shows every row regardless of this flag (`vulns |
    /// less` needs no flag). Accepted after the subcommand too (`connections
    /// --full`), not only before it.
    #[arg(long, global = true)]
    full: bool,
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
    /// Live status snapshot: latest sample per collector + incidents.
    ///
    /// Read from the running daemon over its socket.
    Status,
    /// Recent incidents, newest first — read live from the daemon socket.
    ///
    /// `OPENED` is local wall-clock time as `YYYY-MM-DD HH:MM:SS` — paste it
    /// straight into `why --at`. `LASTED` is `closed - opened`, humanized;
    /// a still-open incident reads `open`.
    Incidents {
        /// Maximum number of incidents to fetch.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Also print each incident's full ID as a first column, for
        /// scripting.
        #[arg(long)]
        ids: bool,
    },
    /// Tail the daemon's live event stream until interrupted (Ctrl-C).
    ///
    /// Prints each frame as `HH:MM:SS  label  detail` as it happens.
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
    /// Restart sing-box via the daemon (`launchctl kickstart`).
    ///
    /// Sent as a `Control(KickstartProxy)` request over the socket. The
    /// daemon runs it as root for any authorised peer; nothing in its config
    /// has to be switched on. Exits non-zero if the action was refused/failed
    /// or the daemon is unreachable.
    ///
    /// Hidden alias for `daemon kickstart` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
    Kickstart,
    /// Pause or resume the daemon's own collection (benign self-control).
    ///
    /// Sent as a `Control(SetObserving)` request over the socket. This
    /// controls the daemon's OWN observation only — it does **not** touch
    /// sing-box or the network. The daemon stays alive and the socket keeps
    /// serving while paused, so the switch can be turned back on. Exits
    /// non-zero if the request failed or the daemon is unreachable.
    ///
    /// Hidden alias for `daemon observe` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
    Observe {
        /// `on` resumes collection; `off` pauses it.
        #[arg(value_enum)]
        state: ObserveState,
    },
    /// Set the daemon's probing tier: `passive` (default) or `active`.
    ///
    /// Sent as a `Control(SetProbing)` request over the socket. `passive`
    /// puts nothing on the wire: every link, proxy and dns probe is withheld
    /// and lands as `SKIP`, and the held reference streams are closed.
    /// `active` runs every probe. Benign self-control like `observe`,
    /// process-scoped, and every real switch is recorded as a `probing_edge`
    /// row (see `gaps`). Exits non-zero if the request failed, the daemon
    /// refused it, or the daemon is unreachable.
    ///
    /// Hidden alias for `daemon probe` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
    Probe {
        /// `passive` withholds every probe; `active` sends them.
        #[arg(value_enum)]
        tier: ProbeTier,
    },
    /// Run an experiment window: "is it us or the network?"
    ///
    /// Ask the running daemon to run the window (`Control(StartExperiment)`).
    /// For the window the daemon goes passive — nothing of its own on the
    /// wire, bracketed by a `probing_edge` with reason `experiment` —
    /// freezes the pcap ring at the start and at the end, restores the
    /// previous tier when the window elapses, and computes a report: the
    /// frames this machine itself sent inside the window (from the end
    /// freeze, by protocol; the daemon's ICMP echoes expected to be 0) next
    /// to what the record says the network did in the same minutes (route
    /// events, incidents, gateway verdicts, roams, announce flushes, flow
    /// totals, signal range) and one plain verdict line. The daemon answers
    /// at once with the window's id; this command then polls the daemon
    /// every 5 s until the report is ready and prints it, so a dropped
    /// socket does not lose the window. Benign self-control like `probe`.
    /// Exits non-zero if the daemon refused (another window running, a bad
    /// length) or is unreachable.
    ///
    /// Hidden alias for `daemon experiment` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
    Experiment {
        /// The window's length in minutes, 1 to 60.
        #[arg(long, default_value_t = EXPERIMENT_DEFAULT_MINUTES)]
        minutes: u32,
        /// Print the id and return at once instead of waiting for the report;
        /// read it later with `experiment-report <id>`.
        #[arg(long)]
        no_wait: bool,
    },
    /// The report of a past experiment window, by its id.
    ///
    /// The id is the one `experiment` printed. Asks the running daemon
    /// first, reads the DB file's `experiment` table only when no daemon
    /// answers. A window still running is reported as such, not waited for.
    ///
    /// Hidden alias for `daemon experiment-report` — kept flat for old
    /// scripts and muscle memory.
    #[command(hide = true)]
    ExperimentReport {
        /// The window's id, `experiment-<start_us>`.
        id: String,
    },
    /// Sweep the local IPv4 subnet and mDNS for who's on this segment now.
    ///
    /// Ask the running daemon, sent as a `Control(ScanNeighbors)` request
    /// over the socket. Unlike the passive `neighbors` collector, this
    /// **speaks on the network** — it addresses every host of the subnet, or
    /// exactly one named host with `--target`. Nothing in the daemon's
    /// config has to permit it: the command is the
    /// sanction, and every run leaves a `neighbor_scan` row saying what was
    /// probed. The daemon refuses it with a reason when it cannot run
    /// (paused, no IPv4 subnet, no scanner on this host) or when the peer is
    /// not authorised. Exits non-zero if the scan was refused/failed or the
    /// daemon is unreachable.
    ///
    /// Hidden alias for `scan neighbors` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
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
        /// Scan just this host instead of sweeping the segment.
        #[arg(long)]
        target: Option<IpAddr>,
        /// Space the probes out to be gentle on a shared segment; the scan
        /// takes longer. On a large subnet this can outlast the time this
        /// command waits for an answer — the scan still finishes on the
        /// daemon and its findings are readable afterward with `neighbors`/
        /// `vulns`, but this command itself may report a timeout.
        #[arg(long)]
        slow: bool,
        /// Override the sweep's host-count ceiling: omit for the built-in
        /// default, 0 for unlimited, or a specific ceiling. On a large
        /// subnet combine with --slow to avoid spraying the segment — and
        /// note that pairing them can outlast the time this command waits
        /// for an answer; the scan still finishes on the daemon regardless.
        #[arg(long)]
        sweep_max: Option<u32>,
    },
    /// Force one LLDP/CDP topology capture now, instead of waiting for the
    /// 5-minute patrol.
    ///
    /// Sent as a `Control(ScanTopology)` request over the socket. The daemon
    /// opens its own short-lived passive capture (~65s) and originates no
    /// frame of its own — it only listens for what switches/APs already
    /// advertise. Empty is normal on a consumer Wi-Fi network: only managed
    /// switches and enterprise APs advertise LLDP/CDP at all. Exits non-zero
    /// if the capture was refused or the daemon is unreachable.
    ///
    /// Hidden alias for `scan topology` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
    ScanTopology,
    /// The neighbours the record knows on each segment, newest tick first.
    ///
    /// MAC, address, vendor OUI, name if one was ever learned, and how it
    /// came to be known. Asks the running daemon first, reads the DB file
    /// only when no daemon answers.
    ///
    /// `neighbor` is never pruned and is upserted by passive collection every
    /// tick, so without `--all` this shows only the rows sharing the newest
    /// `last_seen_us` — the current segment's live roster — rather than every
    /// neighbour this machine has ever recorded, on every segment, including
    /// stale ones.
    Neighbors {
        /// Restrict to one segment, by its gateway MAC. Omit for every segment
        /// this machine has recorded.
        #[arg(long)]
        network: Option<String>,
        /// Show every recorded neighbour across all networks and time, not
        /// just the most recent tick.
        #[arg(long)]
        all: bool,
    },
    /// The CVEs the record hypothesises for open ports, newest first.
    ///
    /// MAC, address, port, CVE id, confidence, whether it is known-exploited,
    /// CVSS, and when this hypothesis was last (re)matched. Each row is a
    /// HYPOTHESIS from matching a grabbed banner against the local snapshot,
    /// never an asserted fact — weigh it by its confidence and the KEV flag.
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// `neighbor_vuln` is never pruned and is upserted, so without `--all`
    /// this shows only the LAST cve scan's findings (the rows sharing the
    /// newest `last_seen_us` — bumped only by an operator scan, never by
    /// passive collection) rather than every hypothesis ever recorded across
    /// every network this machine has scanned.
    Vulns {
        /// Restrict to one segment, by its gateway MAC. Omit for every segment
        /// this machine has recorded.
        #[arg(long)]
        network: Option<String>,
        /// Show every recorded hypothesis, not just the most recent scan
        /// (findings are never pruned, so this includes stale hosts/networks).
        #[arg(long)]
        all: bool,
    },
    /// Scan one host for CVEs, or look a product's CVEs up by name.
    ///
    /// Two mutually exclusive modes: exactly one of `<ip>` / `--product` is
    /// required.
    ///
    /// `<ip>` (scan mode): a convenience over the two-step `scan-neighbors
    /// --target <ip> --ports --banners --cve` then `vulns`: this runs the
    /// same targeted scan (ports + banners + cve, against `ip` only) via the
    /// daemon's `ScanNeighbors` control, then reads the record's vulns back
    /// through the same query `vulns` uses and prints just this host's rows,
    /// known-exploited (KEV) first, worst CVSS next. Nothing on the wire is
    /// new — same control command, same diagnosis.
    ///
    /// Every row is a HYPOTHESIS from matching a grabbed banner against the
    /// daemon's local CVE snapshot, never an asserted fact — see `vulns`.
    /// When the daemon has no usable CVE snapshot the cve rung cannot run at
    /// all, and that is reported as such, never as an empty "no
    /// vulnerabilities" table.
    ///
    /// By default shows only what THIS scan actually wrote (rows at or after
    /// the instant this run started, not merely the host's newest recorded
    /// row — a re-scan that finds nothing new writes no row at all, so a max
    /// could silently be a PREVIOUS scan's finding); a scan that wrote
    /// nothing fresh but finds older rows says so rather than showing them
    /// as current. `--all` shows this host's full recorded history instead,
    /// stale rows included.
    ///
    /// `--product <name> [--version <ver>]` (lookup mode): a device like an
    /// iPhone exposes no service banner and never advertises its own version
    /// on the network, so it can never reach the scan mode above — but if the
    /// operator KNOWS the product+version, this looks it up directly against
    /// the daemon's already-cached CVE snapshot (the same index the `cve`
    /// rung matches against; loaded once, never reloaded per call). No scan,
    /// no network, no MAC involved. `--version` is only valid together with
    /// `--product`; `--all` applies to scan mode only.
    ///
    /// Inherently a LIVE operation either way — the daemon holds the only
    /// scan record / cached snapshot — so a global `--db` (offline file) is
    /// refused rather than silently reading an unrelated record.
    #[command(group(
        ArgGroup::new("check_target")
            .required(true)
            .args(["ip", "product"])
    ))]
    CheckCve {
        /// Provide an IP to scan a host, or `--product` to look a product up
        /// in the snapshot — exactly one.
        ip: Option<IpAddr>,
        /// Provide `--product` to look a product up in the snapshot, or an
        /// IP to scan a host instead — exactly one.
        #[arg(long, conflicts_with = "ip")]
        product: Option<String>,
        /// Narrow the lookup to one version. Only valid with `--product`.
        #[arg(long, requires = "product")]
        version: Option<String>,
        /// Show this host's full recorded history, not just the scan just
        /// run. Scan mode only.
        #[arg(long, conflicts_with = "product")]
        all: bool,
    },
    /// Switch-topology uplinks learned passively from LLDP/CDP, newest first.
    ///
    /// Local interface, remote chassis, remote port, the switch/AP's system
    /// name and capabilities, and whether LLDP or CDP carried it. Each row
    /// is a HYPOTHESIS — LLDP/CDP are unauthenticated and spoofable — never
    /// an asserted fact. Asks the running daemon first, reads the DB file
    /// only when no daemon answers.
    ///
    /// `topology_link` is never pruned and is upserted, and the patrol only
    /// writes on a non-empty capture, so without `--all` this shows only the
    /// rows sharing the newest `last_seen_us` — the last capture that
    /// actually found a link — rather than every uplink ever recorded.
    Topology {
        /// Restrict to one local interface (e.g. `en0`). Omit for every
        /// interface this machine has recorded an uplink on.
        #[arg(long)]
        iface: Option<String>,
        /// Show every recorded uplink across all time, not just the most
        /// recent capture.
        #[arg(long)]
        all: bool,
    },
    /// What this machine talks to: the live sing-box flow table, grouped.
    ///
    /// The newest tick of the live flow table sing-box carries (its Clash
    /// API lists every flow with the name asked for, the real destination,
    /// the process and the outbound), ordered by how many flows share the
    /// key, with the names seen behind each key. `netstat` cannot answer
    /// this here — every destination it shows is a fakeip. A tick on which
    /// the API did not answer is one row saying SKIP, never an empty table.
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// Shows the external flows only by default — the internal ones (every
    /// app's DNS query to sing-box's own listener is a flow) and the LAN
    /// ones are counted on a last line instead of listed; `--all` lists
    /// everything with its scope, `--scope` picks one.
    ///
    /// `iface` names the interface a flow actually left through, derived
    /// from its outbound chain: a tunneled flow carries the TUN interface
    /// name, a direct-out flow the machine's physical interface, a blocked
    /// flow the literal `blocked`. Traffic that never enters the TUN (a
    /// route exclusion) does not appear here at all.
    Connections {
        /// Group the flows by the name asked for, the destination address,
        /// address and port, the client process, the (process, destination)
        /// pair, or the egress interface.
        #[arg(long, value_enum, default_value_t = GroupByArg::Host)]
        by: GroupByArg,
        /// List every flow whatever its scope, with a `scope` column.
        #[arg(long, conflicts_with = "scope")]
        all: bool,
        /// List the flows of one scope only (default: external).
        #[arg(long, value_enum)]
        scope: Option<ScopeArg>,
        /// Keep only flows whose egress interface is exactly this name
        /// (`blocked` matches the blocked pseudo-value too). Client-side,
        /// like `--scope`.
        #[arg(long)]
        iface: Option<String>,
    },
    /// The latest radio-environment slice: foreign APs from the last scan.
    ///
    /// Every foreign access point the last scan heard, with its channel,
    /// band, width, signal and noise, ordered by how likely it is to be
    /// sitting in our own band. Asks the running daemon first, reads the DB
    /// file only when no daemon answers.
    ///
    /// The OVERLAP column is a HYPOTHESIS computed from channel geometry, never
    /// a measurement of interference: macOS reports no channel occupancy to any
    /// program. A scan that could not run is reported as a refusal with its
    /// reason, never as an empty list that would read as clear air.
    Air,
    /// Run an arbitrary SQL query directly against the DuckDB file.
    ///
    /// Offline forensics — only works while `net-observerd` is stopped.
    Query {
        /// The SQL statement to run against the store.
        sql: String,
    },
    /// Which layer failed at a moment: link, proxy, tun, host load.
    ///
    /// The state of each as the record has it, plus the layer it blames.
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// A moment the daemon was paused for is reported as a refusal — the gap and
    /// its bounds — not as a row of blank measurements.
    ///
    /// Hidden alias for `diag why` — kept flat for old scripts and muscle
    /// memory.
    #[command(hide = true)]
    Why {
        /// The moment to read, defaulting to now. Accepts `now`, raw epoch
        /// microseconds (`ts_us`), `YYYY-MM-DD[T ]HH:MM[:SS]` in local time, an
        /// ISO instant with an offset (`2026-09-01T14:05:00Z`), or `HH:MM[:SS]`
        /// for that time today.
        #[arg(long, default_value = "now")]
        at: String,
    },
    /// Every incident with the layer state just before it opened.
    ///
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// An incident that opened inside an observation gap gets no context: the
    /// state from before the pause is not context for it, and is marked withheld.
    ///
    /// Hidden alias for `diag incident-context` — kept flat for old scripts
    /// and muscle memory.
    #[command(hide = true)]
    IncidentContext,
    /// The wedge-vs-starvation verdict over each recent `tun=000` episode.
    ///
    /// The discriminator that decides whether a restart is the cure. Asks
    /// the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// An episode the record cannot classify is reported `unknown`, not guessed.
    ///
    /// Hidden alias for `diag wedge` (renamed, shorter) — kept flat for old
    /// scripts and muscle memory.
    #[command(hide = true)]
    WedgeOrStarvation,
    /// The gateway RTT series before a drop, with its least-squares slope.
    ///
    /// So a coworking-gateway ramp is visible as data. Asks the running
    /// daemon first, reads the DB file only when no daemon answers.
    ///
    /// The slope is refused — "not computed" — when the window crosses an
    /// observation gap.
    ///
    /// Hidden alias for `diag gateway-ramp` — kept flat for old scripts and
    /// muscle memory.
    #[command(hide = true)]
    GatewayRamp {
        /// The drop to look back from, in any form `why --at` accepts. Defaults
        /// to the most recent gateway drop in the record.
        #[arg(long)]
        drop: Option<String>,
        /// How far back to plot, in microseconds.
        #[arg(long, default_value_t = store::diagnosis::DEFAULT_RAMP_WINDOW_US)]
        window_us: i64,
    },
    /// The observation gaps the record contains.
    ///
    /// Every interval the daemon deliberately collected nothing for, and
    /// what closed each. Asks the running daemon first, reads the DB file
    /// only when no daemon answers.
    ///
    /// Hidden alias for `diag gaps` — kept flat for old scripts and muscle
    /// memory.
    #[command(hide = true)]
    Gaps,
    /// The network segments this machine has ever recorded, newest first.
    ///
    /// The segment key, a best-effort SSID guess, the gateway IP when
    /// recoverable, first/last seen, and how many devices it held. Asks the
    /// running daemon first, reads the DB file only when no daemon answers.
    ///
    /// `ssid_guess` is a TIME-overlap heuristic, never an asserted fact: the
    /// daemon does not join an SSID to a segment. A segment recorded under
    /// `unknown` (the gateway MAC was unreadable) is listed like any other.
    Segments,
    /// One segment's recorded state at an instant or over a window.
    ///
    /// The neighbours that were live at an instant (`--at`), or active over
    /// a window (`--since`/`--until`), each with a count of its open ports
    /// and hypothesised vulns over that slice. Asks the running daemon
    /// first, reads the DB file only when no daemon answers.
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
    /// Generate shell completions for zsh, bash or fish.
    ///
    /// Prints the script to stdout (`net-observer-cli completions zsh`); source
    /// or install it wherever the shell looks for completions. Needs neither a
    /// running daemon nor the DuckDB file. The nix package already installs
    /// the zsh, bash and fish completions, so on the Mac nothing needs
    /// sourcing by hand.
    Completions {
        /// The shell to generate a completion script for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Operator-triggered active scans (put packets on the wire).
    #[command(subcommand)]
    Scan(ScanCmd),
    /// Post-outage forensics: why a layer failed.
    #[command(subcommand)]
    Diag(DiagCmd),
    /// Control the running daemon.
    #[command(subcommand)]
    Daemon(DaemonCmd),
}

/// Operator-triggered active scans — commands that put packets on the wire,
/// grouped under `scan` (realm net-observer, node #164).
#[derive(Subcommand)]
enum ScanCmd {
    /// Sweep the local IPv4 subnet and mDNS for who's on this segment now.
    ///
    /// Ask the running daemon, sent as a `Control(ScanNeighbors)` request
    /// over the socket. Unlike the passive `neighbors` collector, this
    /// **speaks on the network** — it addresses every host of the subnet, or
    /// exactly one named host with `--target`. Nothing in the daemon's
    /// config has to permit it: the command is the
    /// sanction, and every run leaves a `neighbor_scan` row saying what was
    /// probed. The daemon refuses it with a reason when it cannot run
    /// (paused, no IPv4 subnet, no scanner on this host) or when the peer is
    /// not authorised. Exits non-zero if the scan was refused/failed or the
    /// daemon is unreachable.
    Neighbors {
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
        /// Scan just this host instead of sweeping the segment.
        #[arg(long)]
        target: Option<IpAddr>,
        /// Space the probes out to be gentle on a shared segment; the scan
        /// takes longer. On a large subnet this can outlast the time this
        /// command waits for an answer — the scan still finishes on the
        /// daemon and its findings are readable afterward with `neighbors`/
        /// `vulns`, but this command itself may report a timeout.
        #[arg(long)]
        slow: bool,
        /// Override the sweep's host-count ceiling: omit for the built-in
        /// default, 0 for unlimited, or a specific ceiling. On a large
        /// subnet combine with --slow to avoid spraying the segment — and
        /// note that pairing them can outlast the time this command waits
        /// for an answer; the scan still finishes on the daemon regardless.
        #[arg(long)]
        sweep_max: Option<u32>,
    },
    /// Force one LLDP/CDP topology capture now, instead of waiting for the
    /// 5-minute patrol.
    ///
    /// Sent as a `Control(ScanTopology)` request over the socket. The daemon
    /// opens its own short-lived passive capture (~65s) and originates no
    /// frame of its own — it only listens for what switches/APs already
    /// advertise. Empty is normal on a consumer Wi-Fi network: only managed
    /// switches and enterprise APs advertise LLDP/CDP at all. Exits non-zero
    /// if the capture was refused or the daemon is unreachable.
    Topology,
}

/// Post-outage forensics — the named diagnoses that answer "which layer
/// failed", grouped under `diag` (realm net-observer, node #164).
#[derive(Subcommand)]
enum DiagCmd {
    /// Which layer failed at a moment: link, proxy, tun, host load.
    ///
    /// The state of each as the record has it, plus the layer it blames.
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
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
    /// Every incident with the layer state just before it opened.
    ///
    /// Asks the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// An incident that opened inside an observation gap gets no context: the
    /// state from before the pause is not context for it, and is marked withheld.
    IncidentContext,
    /// The wedge-vs-starvation verdict over each recent `tun=000` episode.
    ///
    /// The discriminator that decides whether a restart is the cure. Asks
    /// the running daemon first, reads the DB file only when no daemon
    /// answers.
    ///
    /// An episode the record cannot classify is reported `unknown`, not guessed.
    Wedge,
    /// The gateway RTT series before a drop, with its least-squares slope.
    ///
    /// So a coworking-gateway ramp is visible as data. Asks the running
    /// daemon first, reads the DB file only when no daemon answers.
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
    /// The observation gaps the record contains.
    ///
    /// Every interval the daemon deliberately collected nothing for, and
    /// what closed each. Asks the running daemon first, reads the DB file
    /// only when no daemon answers.
    Gaps,
}

/// Daemon control — benign self-control of the running daemon, grouped under
/// `daemon` (realm net-observer, node #164).
#[derive(Subcommand)]
enum DaemonCmd {
    /// Restart sing-box via the daemon (`launchctl kickstart`).
    ///
    /// Sent as a `Control(KickstartProxy)` request over the socket. The
    /// daemon runs it as root for any authorised peer; nothing in its config
    /// has to be switched on. Exits non-zero if the action was refused/failed
    /// or the daemon is unreachable.
    Kickstart,
    /// Pause or resume the daemon's own collection (benign self-control).
    ///
    /// Sent as a `Control(SetObserving)` request over the socket. This
    /// controls the daemon's OWN observation only — it does **not** touch
    /// sing-box or the network. The daemon stays alive and the socket keeps
    /// serving while paused, so the switch can be turned back on. Exits
    /// non-zero if the request failed or the daemon is unreachable.
    Observe {
        /// `on` resumes collection; `off` pauses it.
        #[arg(value_enum)]
        state: ObserveState,
    },
    /// Set the daemon's probing tier: `passive` (default) or `active`.
    ///
    /// Sent as a `Control(SetProbing)` request over the socket. `passive`
    /// puts nothing on the wire: every link, proxy and dns probe is withheld
    /// and lands as `SKIP`, and the held reference streams are closed.
    /// `active` runs every probe. Benign self-control like `observe`,
    /// process-scoped, and every real switch is recorded as a `probing_edge`
    /// row (see `gaps`). Exits non-zero if the request failed, the daemon
    /// refused it, or the daemon is unreachable.
    Probe {
        /// `passive` withholds every probe; `active` sends them.
        #[arg(value_enum)]
        tier: ProbeTier,
    },
    /// Run an experiment window: "is it us or the network?"
    ///
    /// Ask the running daemon to run the window (`Control(StartExperiment)`).
    /// For the window the daemon goes passive — nothing of its own on the
    /// wire, bracketed by a `probing_edge` with reason `experiment` —
    /// freezes the pcap ring at the start and at the end, restores the
    /// previous tier when the window elapses, and computes a report: the
    /// frames this machine itself sent inside the window (from the end
    /// freeze, by protocol; the daemon's ICMP echoes expected to be 0) next
    /// to what the record says the network did in the same minutes (route
    /// events, incidents, gateway verdicts, roams, announce flushes, flow
    /// totals, signal range) and one plain verdict line. The daemon answers
    /// at once with the window's id; this command then polls the daemon
    /// every 5 s until the report is ready and prints it, so a dropped
    /// socket does not lose the window. Benign self-control like `probe`.
    /// Exits non-zero if the daemon refused (another window running, a bad
    /// length) or is unreachable.
    Experiment {
        /// The window's length in minutes, 1 to 60.
        #[arg(long, default_value_t = EXPERIMENT_DEFAULT_MINUTES)]
        minutes: u32,
        /// Print the id and return at once instead of waiting for the report;
        /// read it later with `experiment-report <id>`.
        #[arg(long)]
        no_wait: bool,
    },
    /// The report of a past experiment window, by its id.
    ///
    /// The id is the one `experiment` printed. Asks the running daemon
    /// first, reads the DB file's `experiment` table only when no daemon
    /// answers. A window still running is reported as such, not waited for.
    ExperimentReport {
        /// The window's id, `experiment-<start_us>`.
        id: String,
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
/// [`ConnectionsGroupBy`] so `clap` renders
/// `<host|ip|ip-port|process|process-host|iface>` in the help without
/// leaking the wire type into the argument surface — except `Iface`, which
/// the wire type does not have at all (see [`GroupByArg::to_group_by`]).
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
    /// By the pair (client process, destination): one row per process/host,
    /// never folded across a process's other destinations.
    ProcessHost,
    /// By egress interface (the TUN interface name, the physical interface,
    /// or `blocked`) — answered client-side over the daemon's ordinary
    /// `host` grouping, since a new wire grouping is a hazard to an older
    /// receiver (see AGENTS.md wire invariants).
    Iface,
}

impl GroupByArg {
    /// Map to the wire [`ConnectionsGroupBy`] the daemon and the SQL take.
    /// `Iface` has no wire counterpart — it rides on `Host`, and
    /// [`fold_by_iface`] does the actual folding client-side over that
    /// answer's rows.
    fn to_group_by(self) -> ConnectionsGroupBy {
        match self {
            GroupByArg::Host | GroupByArg::Iface => ConnectionsGroupBy::Host,
            GroupByArg::Ip => ConnectionsGroupBy::Ip,
            GroupByArg::IpPort => ConnectionsGroupBy::IpPort,
            GroupByArg::Process => ConnectionsGroupBy::Process,
            GroupByArg::ProcessHost => ConnectionsGroupBy::ProcessHost,
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

/// The `connections` view's own header rename (owner ask, Part B): `ts_us`
/// converts to local time and its header becomes `ts` — this built-in view
/// only; the generic `query` path ([`format_table`]) keeps the original
/// column name, converting only the values. Converts BEFORE renaming, while
/// the column is still spelled `ts_us` (what the epoch-plausibility gate
/// keys on). A table without a `ts_us` column (an older daemon's, or
/// already-renamed) passes through unchanged.
fn rename_ts_column(table: &Table) -> Table {
    let mut table = table.clone();
    if let Some(i) = table.columns.iter().position(|c| c == "ts_us") {
        convert_epoch_us_column(&mut table.rows, i);
        table.columns[i] = "ts".to_string();
    }
    table
}

/// `connections --iface <name>`: keep only rows whose `iface` cell equals
/// `name` exactly (`blocked` matches the blocked pseudo-value too) —
/// client-side, like [`fold_by_scope`]'s filtering. `None` (no `--iface`
/// given) keeps everything. The empty-tick marker row (`key` blank) has no
/// flow to filter and is always kept: dropping it would turn "the API did
/// not answer" into an empty table indistinguishable from no answer at all.
/// A table without an `iface` column — an older daemon's — passes through
/// unfiltered rather than matching nothing.
fn filter_by_iface(table: &Table, iface: Option<&str>) -> Table {
    let Some(iface) = iface else {
        return table.clone();
    };
    let col = |name: &str| table.columns.iter().position(|c| c == name);
    let Some(iface_col) = col("iface") else {
        return table.clone();
    };
    let key_col = col("key");
    let cell = |row: &[String], i: usize| -> String { row.get(i).cloned().unwrap_or_default() };
    let rows = table
        .rows
        .iter()
        .filter(|row| {
            let marker = key_col.is_some_and(|i| cell(row, i).is_empty());
            marker || cell(row, iface_col) == iface
        })
        .cloned()
        .collect();
    Table {
        columns: table.columns.clone(),
        rows,
    }
}

/// `connections --by iface`: fold the table's rows by their `iface` cell,
/// summing `count`/`upload`/`download` into each interface — client-side,
/// like [`fold_by_scope`]; there is no server-side `iface` grouping to ask
/// for instead (see [`GroupByArg::to_group_by`]). An unknown/absent `iface`
/// folds under `-`. Rows are ordered busiest-first, like the daemon's own
/// `count DESC`.
///
/// The empty-tick marker row (`key` blank) carries no flow to fold, and the
/// table is returned unchanged when that marker is the ONLY row: folding
/// "the tick had no flow at all" into the `-` bucket would read exactly like
/// a real flow whose interface is unknown. A table missing any of the
/// columns this fold needs — an older daemon's, or already reshaped by an
/// earlier fold — also passes through unchanged.
fn fold_by_iface(table: &Table) -> Table {
    let col = |name: &str| table.columns.iter().position(|c| c == name);
    let (Some(iface_col), Some(count_col), Some(upload_col), Some(download_col), Some(key_col)) = (
        col("iface"),
        col("count"),
        col("upload"),
        col("download"),
        col("key"),
    ) else {
        return table.clone();
    };
    let cell = |row: &[String], i: usize| -> String { row.get(i).cloned().unwrap_or_default() };
    if table.rows.iter().all(|r| cell(r, key_col).is_empty()) {
        return table.clone();
    }
    let mut groups: Vec<(String, u64, u64, u64)> = Vec::new();
    for row in &table.rows {
        if cell(row, key_col).is_empty() {
            continue;
        }
        let iface = cell(row, iface_col);
        let iface = if iface.is_empty() {
            "-".to_string()
        } else {
            iface
        };
        let count: u64 = cell(row, count_col).parse().unwrap_or(0);
        let upload: u64 = cell(row, upload_col).parse().unwrap_or(0);
        let download: u64 = cell(row, download_col).parse().unwrap_or(0);
        match groups.iter_mut().find(|(i, ..)| *i == iface) {
            Some((_, c, u, d)) => {
                *c = c.saturating_add(count);
                *u = u.saturating_add(upload);
                *d = d.saturating_add(download);
            }
            None => groups.push((iface, count, upload, download)),
        }
    }
    groups.sort_by_key(|(_, count, ..)| std::cmp::Reverse(*count));
    Table {
        columns: ["iface", "count", "upload", "download"]
            .into_iter()
            .map(String::from)
            .collect(),
        rows: groups
            .into_iter()
            .map(|(iface, count, upload, download)| {
                vec![
                    iface,
                    count.to_string(),
                    upload.to_string(),
                    download.to_string(),
                ]
            })
            .collect(),
    }
}

/// `vulns`/`check-cve`'s ip scoping: keep only the rows whose `ip` column
/// equals `ip`, every original column intact (unlike [`focus_vulns_for_ip`],
/// which also projects/sorts) — so [`keep_last_run`] can still read
/// `last_seen_us` afterward. Client-side filter over the same [`vulns`][
/// diagnosis::vulns_sql] table, like [`filter_by_iface`]. A table missing
/// `ip` (an older daemon's shape) passes through unfiltered rather than
/// matching nothing.
fn filter_by_ip(table: &Table, ip: &IpAddr) -> Table {
    let Some(ip_col) = table.columns.iter().position(|c| c == "ip") else {
        return table.clone();
    };
    let ip = ip.to_string();
    let rows = table
        .rows
        .iter()
        .filter(|row| row.get(ip_col).map(String::as_str) == Some(ip.as_str()))
        .cloned()
        .collect();
    Table {
        columns: table.columns.clone(),
        rows,
    }
}

/// `vulns`'s default (no `--all`): keep only the rows of the LAST recorded
/// scan — those sharing the MAXIMUM `last_seen_us` in `table`.
/// `neighbor_vuln.last_seen_us` is bumped ONLY by an operator cve scan
/// (passive collection never touches it, see AGENTS.md's SKIP rule), so the
/// max is exactly the last scan's findings; the table itself is never pruned
/// (`schema::PRUNABLE_TABLES`'s complement) and is upserted, so without this
/// filter `vulns` accumulates every finding ever recorded, across every
/// network the operator has ever scanned — including a coworking segment's
/// stale rows. Scope `table` to one host first ([`filter_by_ip`]) to get
/// that host's own last scan rather than the whole record's.
///
/// A table missing `last_seen_us`, or carrying no parseable value at all (an
/// older daemon's shape, or an empty table), passes through unchanged rather
/// than emptying silently.
fn keep_last_run(table: &Table) -> Table {
    let Some(ts_col) = table.columns.iter().position(|c| c == "last_seen_us") else {
        return table.clone();
    };
    let ts = |row: &[String]| row.get(ts_col).and_then(|c| c.parse::<i64>().ok());
    let Some(max_ts) = table.rows.iter().filter_map(|r| ts(r)).max() else {
        return table.clone();
    };
    let rows = table
        .rows
        .iter()
        .filter(|row| ts(row) == Some(max_ts))
        .cloned()
        .collect();
    Table {
        columns: table.columns.clone(),
        rows,
    }
}

/// The columns `check-cve` renders, in order — the [`vulns`][diagnosis::vulns_sql]
/// columns minus `mac`/`ip`/`last_seen_us`, which are either constant for one
/// host (shown once in the header instead) or already spent deciding the
/// last-run scope by the time this projects the output shape.
const FOCUSED_VULN_COLUMNS: [&str; 5] = ["port", "cve_id", "cvss", "confidence", "known_exploited"];

/// `check-cve <ip>`: filter the full [`vulns`][diagnosis::vulns_sql] table to
/// `ip`'s rows and sort them KEV first, then CVSS worst-first — the reading
/// order for "what to triage now". Client-side, like [`filter_by_iface`]: the
/// query stays the one `vulns` already runs (no IP-filtered SQL variant), and
/// what the daemon calls "known exploited in the wild" outranks a raw
/// severity number the same way it does for a human triaging the list by eye.
///
/// A table missing any column this needs — an older daemon's shape — returns
/// the empty focused table rather than guessing at positions.
fn focus_vulns_for_ip(table: &Table, ip: &IpAddr) -> Table {
    let empty = Table {
        columns: FOCUSED_VULN_COLUMNS.iter().map(|s| s.to_string()).collect(),
        rows: Vec::new(),
    };
    let col = |name: &str| table.columns.iter().position(|c| c == name);
    let (
        Some(ip_col),
        Some(port_col),
        Some(cve_col),
        Some(conf_col),
        Some(kev_col),
        Some(cvss_col),
    ) = (
        col("ip"),
        col("port"),
        col("cve_id"),
        col("confidence"),
        col("known_exploited"),
        col("cvss"),
    )
    else {
        return empty;
    };
    let ip = ip.to_string();
    let cell = |row: &[String], i: usize| -> String { row.get(i).cloned().unwrap_or_default() };
    let mut rows: Vec<Vec<String>> = table
        .rows
        .iter()
        .filter(|row| cell(row, ip_col) == ip)
        .map(|row| {
            vec![
                cell(row, port_col),
                cell(row, cve_col),
                cell(row, cvss_col),
                cell(row, conf_col),
                cell(row, kev_col),
            ]
        })
        .collect();
    sort_kev_then_cvss_desc(&mut rows, 4, 2);
    Table {
        columns: FOCUSED_VULN_COLUMNS.iter().map(|s| s.to_string()).collect(),
        rows,
    }
}

/// KEV (`known_exploited = true`) first, then CVSS worst (highest) first —
/// the reading order "what to triage now", shared by [`focus_vulns_for_ip`]
/// (`check-cve <ip>`) and [`sort_cve_lookup`] (`check-cve --product`), whose
/// row shapes differ but both carry a `known_exploited`/`cvss` pair.
/// `kev_col`/`cvss_col` say which column of each row carries which. A
/// blank/unparsed cvss sorts last, never first — an unweighed hypothesis is
/// not "more severe" than one the record actually scored.
fn sort_kev_then_cvss_desc(rows: &mut [Vec<String>], kev_col: usize, cvss_col: usize) {
    rows.sort_by(|a, b| {
        let kev = |r: &[String]| r[kev_col] == "true";
        let cvss = |r: &[String]| r[cvss_col].parse::<f64>().unwrap_or(f64::NEG_INFINITY);
        kev(b).cmp(&kev(a)).then_with(|| {
            cvss(b)
                .partial_cmp(&cvss(a))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
}

/// `check-cve --product`: sort the daemon's [`DiagnosticQuery::CveLookup`]
/// table the SAME way [`focus_vulns_for_ip`] sorts the scan-mode table — KEV
/// first, then CVSS worst-first — via the shared [`sort_kev_then_cvss_desc`].
/// A table missing either column (an older daemon's shape) is returned
/// unsorted rather than guessing at positions.
fn sort_cve_lookup(table: &Table) -> Table {
    let col = |name: &str| table.columns.iter().position(|c| c == name);
    let (Some(kev_col), Some(cvss_col)) = (col("known_exploited"), col("cvss")) else {
        return table.clone();
    };
    let mut rows = table.rows.clone();
    sort_kev_then_cvss_desc(&mut rows, kev_col, cvss_col);
    Table {
        columns: table.columns.clone(),
        rows,
    }
}

/// Which of `check-cve`'s four honest outcomes to print, decided from how
/// many rows are about to be shown, whether the host has ANY recorded
/// history at all, and whether the cve rung actually ran (see
/// [`cve_rung_unavailable`]) — never from the shown row count alone: a
/// snapshot that could not run, a fresh scan that found nothing (but the
/// host has older findings), and a fresh scan that found nothing ever all
/// render as zero shown rows, and only the other two inputs tell them
/// apart. Pure over its three inputs so it is unit-tested directly.
///
/// `has_history` only ever contradicts a positive `shown_count` when the
/// caller is showing a FRESHNESS-filtered subset (`check-cve`'s default) —
/// `--all` shows the host's full history verbatim, so there `shown_count`
/// and "has history" agree by construction and
/// [`NoFreshButHasHistory`][CheckCveOutcome::NoFreshButHasHistory] cannot
/// arise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckCveOutcome {
    /// Findings to show — this scan's fresh rows (default), or the host's
    /// full history (`--all`).
    Findings,
    /// Nothing to show for THIS scan, but the host has older recorded rows
    /// — showing them here would present stale data as current (the bug
    /// this exists to prevent). `--all` shows that history instead.
    NoFreshButHasHistory,
    /// Nothing to show and no history either. FAIL-SAFE, not a confident
    /// "no vulnerabilities": `cve_ran` comes from a string match on the
    /// daemon's free-text message ([`cve_rung_unavailable`]), which can
    /// drift and miss a real drop — so this is never rendered as a clean
    /// all-clear on its own; the caller shows the daemon's own message
    /// verbatim alongside it.
    NoFindings,
    /// The cve rung could not run at all (the message positively matched a
    /// known drop/unusable wording): an empty result here is NOT "no
    /// vulnerabilities".
    SnapshotUnavailable,
}

fn check_cve_outcome(shown_count: usize, has_history: bool, cve_ran: bool) -> CheckCveOutcome {
    if !cve_ran {
        CheckCveOutcome::SnapshotUnavailable
    } else if shown_count > 0 {
        CheckCveOutcome::Findings
    } else if has_history {
        CheckCveOutcome::NoFreshButHasHistory
    } else {
        CheckCveOutcome::NoFindings
    }
}

/// Whether `scan-neighbors`'s [`ControlResult::message`] says the cve rung
/// could not run — either dropped before it ran (no snapshot directory
/// configured) or attempted and found the configured one unusable (missing,
/// unreadable, empty/wrong layout). Matches the honest-note wording
/// `net-observerd` actually emits for both cases (`bin/net-observerd/src/
/// main.rs::load_and_classify`, `bin/net-observerd/src/api.rs::scan_now`)
/// rather than a wire flag — there is none, by design (CLI-only feature, no
/// wire change).
///
/// This is a STRING MATCH on free text the daemon did not design as an API,
/// and can miss a future rewording — an accepted fragility, degraded
/// honestly: [`check_cve_outcome`]'s [`CheckCveOutcome::NoFindings`] never
/// treats a `false` from here as positive proof the rung ran cleanly; it
/// shows the daemon's raw message alongside it, rather than a confident "no
/// vulnerabilities".
fn cve_rung_unavailable(message: &str) -> bool {
    let m = message.to_lowercase();
    (m.contains("snapshot")
        && (m.contains("not") || m.contains("without") || m.contains("unusable")))
        || m.contains("dropped: cve")
}

/// `check-cve`'s freshness filter for its default view: keep only rows
/// whose `last_seen_us` is at or after `threshold_us`.
///
/// `neighbor_vuln` is upserted ONLY on a match — a clean re-scan that finds
/// nothing new for a host (patched, port closed) writes NO row at all,
/// there is no "clean" marker — so [`keep_last_run`]'s table-wide (or
/// per-ip) MAXIMUM can still be a row a PREVIOUS scan wrote, and presenting
/// it as this scan's own finding is silent wrong data: "patch SSH,
/// re-scan, still see the old CVE." Comparing against the instant THIS
/// scan started answers "did this run write it", which a max cannot once
/// nothing new was written.
///
/// ASSUMPTION, worth stating because it is load-bearing: the CLI and the
/// daemon run on the SAME machine (AGENTS.md), so `threshold_us` — taken
/// from this process's own clock just before the scan request — is
/// comparable to `last_seen_us` values that machine's daemon wrote.
///
/// A table missing `last_seen_us` (an older daemon's shape) passes through
/// unchanged, like [`keep_last_run`].
fn keep_since(table: &Table, threshold_us: i64) -> Table {
    let Some(ts_col) = table.columns.iter().position(|c| c == "last_seen_us") else {
        return table.clone();
    };
    let rows = table
        .rows
        .iter()
        .filter(|row| {
            row.get(ts_col)
                .and_then(|c| c.parse::<i64>().ok())
                .is_some_and(|ts| ts >= threshold_us)
        })
        .cloned()
        .collect();
    Table {
        columns: table.columns.clone(),
        rows,
    }
}

/// The local time of `table`'s newest `last_seen_us` — for
/// [`CheckCveOutcome::NoFreshButHasHistory`]'s message, naming when the
/// stale finding it is refusing to show was actually last matched. `None`
/// for an empty table or one missing the column.
fn newest_last_seen_local(table: &Table) -> Option<String> {
    let newest = keep_last_run(table);
    let ts_col = newest.columns.iter().position(|c| c == "last_seen_us")?;
    let us: i64 = newest.rows.first()?.get(ts_col)?.parse().ok()?;
    Some(opened_local(us))
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
        Command::Incidents { limit, ids } => {
            let cfg = load_config(cli)?;
            let mut incidents = fetch_incidents(&cfg.socket_path, *limit)?;
            // `--limit` bounds the query (default 50, over `DEFAULT_ROW_LIMIT`);
            // the cap bounds the interactive display — the same two-axis split
            // `check-cve --all` has against the row cap.
            let note = cap_rows(&mut incidents, std::io::stdout().is_terminal(), cli.full);
            print!("{}", format_incidents(&incidents, *ids));
            if let Some(note) = note {
                print!("{note}");
            }
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
        Command::Daemon(DaemonCmd::Kickstart) | Command::Kickstart => {
            let cfg = load_config(cli)?;
            let result = fetch_kickstart(&cfg.socket_path)?;
            print!("{}", format_control(&result));
            // A refusal (unauthorised peer) or a failed action is a non-zero
            // exit, even though the request itself round-tripped fine.
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Daemon(DaemonCmd::Observe { state }) | Command::Observe { state } => {
            let cfg = load_config(cli)?;
            let result = fetch_set_observing(&cfg.socket_path, state.as_bool())?;
            print!("{}", format_control(&result));
            // The request round-trips fine; a non-`ok` result means the daemon
            // declined or failed, which is a non-zero exit.
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Daemon(DaemonCmd::Probe { tier }) | Command::Probe { tier } => {
            let cfg = load_config(cli)?;
            let result = fetch_set_probing(&cfg.socket_path, tier.to_tier())?;
            print!("{}", format_control(&result));
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Daemon(DaemonCmd::Experiment { minutes, no_wait })
        | Command::Experiment { minutes, no_wait } => {
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
            print_table(&table, true, cli.full);
        }
        Command::Daemon(DaemonCmd::ExperimentReport { id }) | Command::ExperimentReport { id } => {
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
            print_table(&table, true, cli.full);
        }
        Command::Scan(ScanCmd::Neighbors {
            ports,
            banners,
            cve,
            target,
            slow,
            sweep_max,
        })
        | Command::ScanNeighbors {
            ports,
            banners,
            cve,
            target,
            slow,
            sweep_max,
        } => {
            let cfg = load_config(cli)?;
            let result = fetch_scan_neighbors(
                &cfg.socket_path,
                ScanOptions {
                    ports: *ports,
                    banners: *banners,
                    cve: *cve,
                    target: *target,
                    slow: *slow,
                    sweep_max: *sweep_max,
                },
            )?;
            print!("{}", format_control(&result));
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
        }
        Command::Scan(ScanCmd::Topology) | Command::ScanTopology => {
            let cfg = load_config(cli)?;
            let result = fetch_scan_topology(&cfg.socket_path)?;
            print!("{}", format_control(&result));
            if !result.ok {
                return Ok(ExitCode::FAILURE);
            }
            eprintln!("read the uplinks with `net-observer-cli topology`");
        }
        // The named diagnoses: the filter is validated HERE, before any socket
        // or file is touched, so a bad key is the builder's own error and never
        // a round-trip — then the daemon is asked, and the file read only when
        // no daemon answers (see `diagnose_table`).
        Command::Neighbors { network, all } => {
            let sql = diagnosis::neighbors_sql(network.as_deref()).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::Neighbors {
                    network: network.clone(),
                },
                |off| run_query(off, &sql),
            )?;
            let table = if *all { table } else { keep_last_run(&table) };
            print_table(&table, true, cli.full);
        }
        Command::Vulns { network, all } => {
            let sql = diagnosis::vulns_sql(network.as_deref()).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::Vulns {
                    network: network.clone(),
                },
                |off| run_query(off, &sql),
            )?;
            // Filter BEFORE rendering: `format_table`'s readable-time funnel
            // converts `last_seen_us` in place, and `keep_last_run` needs the
            // raw epoch value to find the maximum.
            let table = if *all { table } else { keep_last_run(&table) };
            print_table(&table, true, cli.full);
        }
        Command::CheckCve {
            product, version, ..
        } if product.is_some() => {
            // Lookup mode is inherently LIVE too: the daemon holds the only
            // cached CVE index, so `--db` (an unrelated offline file, and one
            // this variant never reads from anyway) is refused the same way
            // scan mode refuses it.
            if cli.db.is_some() {
                return Err(anyhow!(
                    "check-cve --product needs the running daemon; --db (offline file) is not \
                     compatible"
                ));
            }
            let product = product.as_deref().expect("guarded by the match arm");
            let label = match version {
                Some(v) => format!("{product} {v}"),
                None => product.to_string(),
            };
            let cfg = load_config(cli)?;
            let outcome = net_observer_ipc::diagnose(
                &cfg.socket_path,
                DiagnosticQuery::CveLookup {
                    product: product.to_string(),
                    version: version.clone(),
                },
            )
            .map_err(|e| socket_error(&cfg.socket_path, e))?;
            eprintln!("CVE for {label}");
            match outcome {
                QueryOutcome::Unsupported(m) => {
                    return Err(anyhow!("this daemon is too old for product lookup ({m})"));
                }
                QueryOutcome::Failed(m) => {
                    return Err(anyhow!("net-observerd returned an error: {m}"));
                }
                QueryOutcome::Table(table) => {
                    let sorted = sort_cve_lookup(&table);
                    if sorted.rows.is_empty() {
                        eprintln!(
                            "no CVEs found for {label} (try another spelling — e.g. iphone_os \
                             for iOS)"
                        );
                    } else {
                        print_table(&sorted, true, cli.full);
                    }
                    eprintln!(
                        "Names in the CVE data are messy — a product like iOS may be recorded \
                         as \"iphone_os\"/\"apple\"; try a couple of spellings. Without \
                         --version, every CVE ever filed for the product is listed. These are \
                         catalogue entries, not a claim your device is unpatched."
                    );
                }
            }
        }
        Command::CheckCve { ip, all, .. } => {
            // check-cve is inherently a LIVE operation: it just told the
            // running daemon to scan `ip`, so the readback must come from
            // that SAME daemon's record. `--db` names an unrelated offline
            // file — honoring it here would silently report a different
            // record's (possibly stale, possibly unrelated) history as if
            // it were this scan's own findings.
            if cli.db.is_some() {
                return Err(anyhow!(
                    "check-cve scans the running daemon and reads back from it; \
                     --db (offline file) is not compatible"
                ));
            }
            // clap's `required_unless_present`/`conflicts_with` on `ip` and
            // `product` guarantee exactly one is present, and this arm is
            // only reached when `product` was `None`.
            let ip = ip.expect("clap guarantees <ip> is present when --product is absent");
            let cfg = load_config(cli)?;
            // Captured BEFORE the scan request: see `keep_since`'s doc for
            // why a timestamp, not a max, is what makes the default view
            // honest.
            let scan_start_us = types::now_us();
            let scan = fetch_scan_neighbors(
                &cfg.socket_path,
                ScanOptions {
                    ports: true,
                    banners: true,
                    cve: true,
                    target: Some(ip),
                    slow: false,
                    sweep_max: None,
                },
            )?;
            if !scan.ok {
                eprintln!("scan of {ip} failed: {}", scan.message);
                return Ok(ExitCode::FAILURE);
            }
            let sql = diagnosis::vulns_sql(None).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(cli, DiagnosticQuery::Vulns { network: None }, |off| {
                run_query(off, &sql)
            })?;
            // This host's rows across ALL of its recorded scans, every
            // column intact — the base both the shown table and
            // `has_history` are read from below.
            let ip_rows = filter_by_ip(&table, &ip);
            let has_history = !ip_rows.rows.is_empty();
            // `--all`: the full history. Default: only what THIS scan
            // actually wrote — `>= scan_start_us`, never `keep_last_run`'s
            // table-wide max, which a clean re-scan (nothing new to write)
            // would silently satisfy with a PREVIOUS scan's row.
            let shown = if *all {
                ip_rows.clone()
            } else {
                keep_since(&ip_rows, scan_start_us)
            };
            let focused = focus_vulns_for_ip(&shown, &ip);
            let cve_ran = !cve_rung_unavailable(&scan.message);
            eprintln!("CVE hypotheses for {ip}");
            eprintln!("scanned: {}", scan.message);
            match check_cve_outcome(focused.rows.len(), has_history, cve_ran) {
                CheckCveOutcome::SnapshotUnavailable => eprintln!(
                    "CVE snapshot not available on the daemon — matches were NOT checked \
                     (not a clean \"no vulnerabilities\")"
                ),
                CheckCveOutcome::NoFreshButHasHistory => {
                    let newest = newest_last_seen_local(&ip_rows)
                        .unwrap_or_else(|| "an unknown time".to_string());
                    eprintln!(
                        "no CVE hypotheses from this scan of {ip} — the record has older \
                         findings (most recent {newest}); see --all"
                    );
                }
                CheckCveOutcome::NoFindings => eprintln!(
                    "no CVE hypotheses matched for {ip}. daemon: \"{}\"",
                    scan.message
                ),
                CheckCveOutcome::Findings => {
                    print_table(&focused, true, cli.full);
                    eprintln!(
                        "These are hypotheses matched from the service banner. A backported \
                         patch can leave a version that looks in-range not actually \
                         vulnerable; known_exploited=true (KEV) is the CISA \"exploited in \
                         the wild\" flag — triage those first."
                    );
                }
            }
        }
        Command::Topology { iface, all } => {
            let sql = diagnosis::topology_sql(iface.as_deref()).map_err(|e| anyhow!("{e}"))?;
            let table = diagnose_table(
                cli,
                DiagnosticQuery::Topology {
                    iface: iface.clone(),
                },
                |off| run_query(off, &sql),
            )?;
            let table = if *all { table } else { keep_last_run(&table) };
            print_table(&table, true, cli.full);
        }
        Command::Connections {
            by,
            all,
            scope,
            iface,
        } => {
            let group_by = by.to_group_by();
            let sql = diagnosis::connections_sql(group_by);
            let table = diagnose_table(cli, DiagnosticQuery::Connections { group_by }, |off| {
                run_query(off, &sql)
            })?;
            let table = rename_ts_column(&table);
            let table = filter_by_iface(&table, iface.as_deref());
            // The daemon answers every scope; the fold is the reader's
            // (realm net-observer, node #75).
            let keep = (!all).then(|| scope.map_or(ConnectionScope::External, ScopeArg::to_scope));
            let (table, hidden) = fold_by_scope(&table, keep);
            let table = if *by == GroupByArg::Iface {
                fold_by_iface(&table)
            } else {
                table
            };
            print_table(&table, true, cli.full);
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
            print!(
                "{}",
                diagnose::format_air(&scan, &aps, &own, std::io::stdout().is_terminal(), cli.full)?
            );
        }
        Command::Query { sql } => {
            let table = table_from_query(run_query(&file_only(cli)?, sql)?);
            // The record's raw/machine-readable carrier (realm net-observer,
            // node #75): `ts_us` stays microseconds here, never converted to
            // local time — there is no `--json`/`--raw` flag to route
            // around the conversion instead, so a script or agent reading
            // this output must see the integer it asked for.
            print_table(&table, false, cli.full);
        }
        Command::Diag(DiagCmd::Why { at }) | Command::Why { at } => {
            let ts_us = diagnose::parse_at(at)?;
            let table = diagnose_table(cli, DiagnosticQuery::Why { ts_us }, |off| {
                run_prepared(off, &diagnosis::verdict_at_sql(ts_us, LOAD_THRESHOLD))
            })?;
            print!("{}", diagnose::format_verdict_at(&table, ts_us)?);
        }
        Command::Diag(DiagCmd::IncidentContext) | Command::IncidentContext => {
            let table = diagnose_table(cli, DiagnosticQuery::IncidentContext, |off| {
                run_prepared(off, &diagnosis::incident_context_sql(LOAD_THRESHOLD))
            })?;
            print!(
                "{}",
                diagnose::format_incident_context(
                    &table,
                    std::io::stdout().is_terminal(),
                    cli.full
                )?
            );
        }
        Command::Diag(DiagCmd::Wedge) | Command::WedgeOrStarvation => {
            let table = diagnose_table(cli, DiagnosticQuery::WedgeVsStarvation, |off| {
                run_prepared(
                    off,
                    &diagnosis::wedge_vs_starvation_sql(
                        LOAD_THRESHOLD,
                        diagnosis::DEFAULT_EPISODE_GAP_US,
                    ),
                )
            })?;
            print!(
                "{}",
                diagnose::format_wedge_vs_starvation(
                    &table,
                    std::io::stdout().is_terminal(),
                    cli.full
                )?
            );
        }
        Command::Diag(DiagCmd::GatewayRamp { drop, window_us })
        | Command::GatewayRamp { drop, window_us } => {
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
                diagnose::format_gateway_ramp(
                    &table,
                    drop_ts_us,
                    *window_us,
                    std::io::stdout().is_terminal(),
                    cli.full
                )?
            );
        }
        Command::Diag(DiagCmd::Gaps) | Command::Gaps => {
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
            print!(
                "{}",
                diagnose::format_observation_gaps(
                    &table,
                    std::io::stdout().is_terminal(),
                    cli.full
                )?
            );
        }
        Command::Segments => {
            let table = diagnose_table(cli, DiagnosticQuery::Segments, |off| {
                run_query(off, &diagnosis::segments_sql())
            })?;
            print_table(&table, true, cli.full);
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
            print_table(&table, true, cli.full);
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                *shell,
                &mut Cli::command(),
                "net-observer-cli",
                &mut std::io::stdout(),
            );
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

/// Turn a transport failure from `net_observer_ipc` into the message every
/// socket round-trip in this file reports it with: "not running" when nothing
/// is there to answer, else the raw error alongside the socket path. Shared by
/// every fetcher below so the wording — and the [`daemon_not_running`] split —
/// stays in one place instead of being retyped per command.
fn socket_error(socket_path: &str, e: std::io::Error) -> anyhow::Error {
    if daemon_not_running(&e) {
        anyhow!("net-observerd not running (socket {socket_path} unavailable)")
    } else {
        anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
    }
}

/// Send one request to the daemon over the socket. An absent / refused socket
/// (`net-observerd` not running) becomes a clear message, never a panic.
fn daemon_query(socket_path: &str, req: &Request) -> Result<Response> {
    net_observer_ipc::query(socket_path, req).map_err(|e| socket_error(socket_path, e))
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
    let outcome = net_observer_ipc::control(socket_path, ControlCmd::SetProbing(tier))
        .map_err(|e| socket_error(socket_path, e))?;
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
        .map_err(|e| socket_error(socket_path, e))?;
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

/// The one line printed to stderr before the blocking wait in
/// [`fetch_scan_neighbors`] — an operator watching a `--cve`/`--slow` scan
/// that goes quiet for minutes needs to know it is working, not stuck, and
/// that Ctrl-C does not stop it on the daemon. Named after the rungs actually
/// present in `opts`, so a plain scan carries no CVE/slow caveat it does not
/// run.
fn scan_starting_line(opts: &ScanOptions) -> String {
    let mut rungs = Vec::new();
    if opts.ports {
        rungs.push("ports");
    }
    if opts.banners {
        rungs.push("banners");
    }
    if opts.cve {
        rungs.push("cve");
    }
    if opts.slow {
        rungs.push("slow");
    }
    let rungs = if rungs.is_empty() {
        String::new()
    } else {
        format!(" ({})", rungs.join(", "))
    };

    let mut caveats = Vec::new();
    if opts.cve {
        caveats
            .push("a --cve scan loads a large CVE snapshot the first time after a daemon restart");
    }
    if opts.slow {
        caveats.push("a --slow sweep paces the whole segment");
    }
    let caveats = if caveats.is_empty() {
        String::new()
    } else {
        format!(" — {}", caveats.join(", "))
    };

    format!(
        "scanning neighbours{rungs}… this can take a while{caveats}. Ctrl-C leaves the scan \
         running on net-observerd; read results later with `net-observer-cli vulns` / \
         `neighbors`."
    )
}

/// Classify a transport failure from a scan's [`net_observer_ipc::control_within`]
/// call — distinct from [`socket_error`] because a scan's own read timeout
/// ([`net_observer_ipc::SCAN_TIMEOUT`] elapsed, surfaced as
/// `WouldBlock`/`TimedOut`) is not a failure: the scan keeps running on the
/// daemon and its rows still land in the record, so it earns its own message
/// instead of the raw, cryptic errno line (`Resource temporarily unavailable
/// (os error 35)`) that `socket_error` would otherwise produce.
fn scan_socket_error(socket_path: &str, e: &std::io::Error) -> anyhow::Error {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    if matches!(e.kind(), WouldBlock | TimedOut) {
        anyhow!(
            "the scan is still running on net-observerd and will finish there — its rows land \
             in the record. Read them with `net-observer-cli vulns` and `net-observer-cli \
             neighbors`. (The first --cve scan after a restart loads a large snapshot; a \
             --slow sweep of a big segment takes minutes.)"
        )
    } else if daemon_not_running(e) {
        anyhow!("net-observerd not running (socket {socket_path} unavailable)")
    } else {
        anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
    }
}

/// How often the main thread wakes to redraw [`fetch_scan_neighbors`]'s
/// spinner while waiting on the background socket call.
const SPINNER_TICK: Duration = Duration::from_millis(120);

/// The spinner glyph for tick `n` — cycles through a small braille frame set.
/// Pure over its input so it is unit-tested directly; the render loop only
/// calls it in sequence and is not itself tested (see `fetch_scan_neighbors`).
fn spinner_frame(tick: u64) -> char {
    const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    FRAMES[(tick as usize) % FRAMES.len()]
}

/// Format an elapsed duration as `M:SS` for the scan spinner line (e.g. 65s
/// -> `1:05`). Pure over its input so it is unit-tested directly; sub-second
/// precision is dropped — the spinner glyph itself already shows motion
/// between whole seconds.
fn format_elapsed(d: Duration) -> String {
    let secs = d.as_secs();
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// Redraw the live `⠋ scanning… M:SS` line in place: `\r` returns to column 0
/// so the write overwrites the previous frame instead of scrolling a new
/// line. Write errors (e.g. a broken stderr pipe) are ignored, never
/// `eprintln!`'d — same reasoning as [`stream_events`]'s comment: a panic
/// here would turn a merely closed stderr into a crash.
fn render_scan_spinner(tick: u64, elapsed: Duration) {
    let _ = write!(
        std::io::stderr(),
        "\r{} scanning… {}",
        spinner_frame(tick),
        format_elapsed(elapsed)
    );
    let _ = std::io::stderr().flush();
}

/// Erase the live spinner line — `\r` + clear-to-end-of-line — before the
/// final result or error prints, so it is never tangled with a half-drawn
/// spinner frame.
fn clear_scan_spinner() {
    let _ = write!(std::io::stderr(), "\r\x1b[K");
    let _ = std::io::stderr().flush();
}

/// Send one long-running control command and show a spinner on a TTY until the
/// daemon answers, reading with [`net_observer_ipc::SCAN_TIMEOUT`] rather than
/// the default 2s budget: the daemon replies only after the whole capture/scan
/// finishes, and a client that gives up first would read its own timeout
/// instead of the daemon's real result. The channel/spinner loop is identical
/// for every such command — [`fetch_scan_neighbors`] and [`fetch_scan_topology`]
/// call this one body (AGENTS.md principle 4); only the starting line, the
/// command, and the two failure messages differ, so those are parameters.
///
/// The blocking socket call runs on a background thread while the main thread
/// ticks a live spinner + elapsed-time indicator on stderr — client-side
/// liveness only, not real per-stage progress, and only when stderr is a TTY: a
/// pipe/redirect/script gets no spinner writes and the exact output a plain call
/// would produce. The worker thread always ends when the socket call returns
/// (success, error, or the client's own [`net_observer_ipc::SCAN_TIMEOUT`]), so
/// nothing is leaked even though Ctrl-C here does not stop the work on the daemon
/// (see [`scan_starting_line`]).
fn run_scan_with_spinner(
    socket_path: &str,
    cmd: ControlCmd,
    starting_line: &str,
    map_socket_error: impl FnOnce(&str, &std::io::Error) -> anyhow::Error,
    unsupported: impl FnOnce(String) -> anyhow::Error,
) -> Result<ControlResult> {
    let _ = writeln!(std::io::stderr(), "{starting_line}");

    let (tx, rx) = std::sync::mpsc::channel();
    let socket_path_for_thread = socket_path.to_string();
    std::thread::spawn(move || {
        let outcome = net_observer_ipc::control_within(
            &socket_path_for_thread,
            cmd,
            net_observer_ipc::SCAN_TIMEOUT,
        );
        // The receiver only ever drops after taking the result below, so a
        // failed send here would mean it dropped first — nothing left to
        // tell.
        let _ = tx.send(outcome);
    });

    let live = std::io::stderr().is_terminal();
    let start = Instant::now();
    let mut tick: u64 = 0;
    let outcome = loop {
        match rx.recv_timeout(SPINNER_TICK) {
            Ok(outcome) => {
                if live {
                    clear_scan_spinner();
                }
                break outcome;
            }
            Err(RecvTimeoutError::Timeout) => {
                if live {
                    render_scan_spinner(tick, start.elapsed());
                    tick += 1;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                if live {
                    clear_scan_spinner();
                }
                return Err(anyhow!(
                    "internal error: the scan's background thread ended without a result"
                ));
            }
        }
    };

    let outcome = outcome.map_err(|e| map_socket_error(socket_path, &e))?;
    match outcome {
        net_observer_ipc::ControlOutcome::Ran(result) => Ok(result),
        net_observer_ipc::ControlOutcome::Unsupported(e) => Err(unsupported(e)),
    }
}

/// Send `Control(ScanNeighbors)` and return the daemon's verdict, over the
/// shared [`run_scan_with_spinner`] machinery.
///
/// The daemon answers only after the whole sweep (ARP + mDNS, then the
/// ports/banners rungs) — tens of seconds on a real segment — so a client that
/// gives up first reads its own timeout instead of the daemon's
/// effective/dropped-rungs message; [`scan_socket_error`] turns that timeout
/// into a message saying so, rather than [`socket_error`]'s generic transport
/// wording. A daemon built before `ScanNeighbors` existed cannot decode the
/// request; that is reported as "cannot", not as a refusal.
fn fetch_scan_neighbors(socket_path: &str, opts: ScanOptions) -> Result<ControlResult> {
    let starting_line = scan_starting_line(&opts);
    run_scan_with_spinner(
        socket_path,
        ControlCmd::ScanNeighbors(opts),
        &starting_line,
        scan_socket_error,
        |e| anyhow!("net-observerd cannot scan for neighbours (built before it existed): {e}"),
    )
}

/// Send `Control(ScanTopology)` and return the daemon's verdict.
///
/// Shares the spinner/timeout machinery of [`run_scan_with_spinner`] with
/// [`fetch_scan_neighbors`] — the daemon answers only after the whole capture
/// (~65s, `TOPOLOGY_CAPTURE_BUDGET` on the daemon) finishes, so this reads with
/// [`net_observer_ipc::SCAN_TIMEOUT`], not the default 2s budget. Only the
/// starting line and the two topology-specific failure messages differ from the
/// neighbour scan.
fn fetch_scan_topology(socket_path: &str) -> Result<ControlResult> {
    run_scan_with_spinner(
        socket_path,
        ControlCmd::ScanTopology,
        "capturing LLDP/CDP for up to ~65s… this is normal, not stuck. Ctrl-C leaves the \
         capture running on net-observerd; read results later with `net-observer-cli topology`.",
        |socket_path, e| {
            use std::io::ErrorKind::{TimedOut, WouldBlock};
            if matches!(e.kind(), WouldBlock | TimedOut) {
                anyhow!(
                    "the capture is still running on net-observerd and will finish there — its \
                     uplinks land in the record. Read them with `net-observer-cli topology`."
                )
            } else if daemon_not_running(e) {
                anyhow!("net-observerd not running (socket {socket_path} unavailable)")
            } else {
                anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
            }
        },
        |e| anyhow!("net-observerd cannot force a topology capture (built before it existed): {e}"),
    )
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

/// A screenful: how many rows of a table this CLI shows on an interactive
/// terminal before it cuts off and notes the rest ([`row_cap`]) — an
/// interactive-readability cap, not a claim about how much data exists.
/// Piping, redirecting, or `--full` always shows every row.
const DEFAULT_ROW_LIMIT: usize = 40;

/// How many of `total_rows` to render, or `None` for "render them all, no
/// note": piping/redirecting (`!is_tty`) and `--full` both mean "show
/// everything" (so `vulns | less` and a script see the full data), and an
/// interactive terminal needs no cap either when the table already fits
/// under [`DEFAULT_ROW_LIMIT`]. Otherwise the first `DEFAULT_ROW_LIMIT` rows
/// are shown and the caller notes how many were left out
/// ([`more_rows_note`]). Pure over its inputs so the cap decision is
/// unit-tested directly; the TTY check itself cannot run in a test.
fn row_cap(is_tty: bool, full: bool, total_rows: usize) -> Option<usize> {
    if is_tty && !full && total_rows > DEFAULT_ROW_LIMIT {
        Some(DEFAULT_ROW_LIMIT)
    } else {
        None
    }
}

/// The note printed under a capped table, naming how many rows were left out
/// and the two ways to see them. Shared so every capped command reads the
/// same line.
fn more_rows_note(total_rows: usize, shown: usize) -> String {
    format!(
        "… and {} more rows — pass --full to show all, or pipe to less\n",
        total_rows - shown
    )
}

/// The ONE place `total_rows → row_cap → truncate → note` happens: truncates
/// `rows` in place to [`DEFAULT_ROW_LIMIT`] when [`row_cap`] says to, and
/// returns the trailing note to append when it did (`None` otherwise).
/// Generic over the row type so every renderer shares this exact sequence —
/// [`render_table_capped`]'s `Table.rows`, `diagnose`'s hand-rolled
/// `Vec<Vec<String>>`/ranked-AP rows, and `Command::Incidents`'s
/// `Vec<IncidentSummary>` alike — rather than each hand-rolling its own
/// `if let Some(shown) = row_cap(...) { rows.truncate(shown); }` copy. Pure
/// over `is_tty`/`full` (a real terminal check happens only at the call
/// site), so a renderer's cap wiring is unit-tested without one.
fn cap_rows<T>(rows: &mut Vec<T>, is_tty: bool, full: bool) -> Option<String> {
    let total = rows.len();
    row_cap(is_tty, full, total).map(|shown| {
        rows.truncate(shown);
        more_rows_note(total, shown)
    })
}

/// Render `table` the way [`format_table`] does, capped to
/// [`DEFAULT_ROW_LIMIT`] rows with a trailing note when `is_tty && !full` and
/// the table does not fit ([`row_cap`], via [`cap_rows`]); every row
/// otherwise. Pure over its inputs — including a simulated `is_tty` — so the
/// capped rendering is unit-tested without a real terminal; [`print_table`]
/// is the thin real-stdout wrapper around it.
fn render_table_capped(table: &Table, readable_time: bool, is_tty: bool, full: bool) -> String {
    let mut capped = table.clone();
    let note = cap_rows(&mut capped.rows, is_tty, full);
    let mut out = format_table(&capped, readable_time);
    if let Some(note) = note {
        out.push_str(&note);
    }
    out
}

/// Print a [`Table`] through [`render_table_capped`] against the real
/// terminal state. This is the funnel every table-printing subcommand's
/// final output goes through now that the pager is gone — pagination is
/// replaced by a row cap, but the readable-time conversion ([`format_table`])
/// still rides along.
fn print_table(table: &Table, readable_time: bool, full: bool) {
    print!(
        "{}",
        render_table_capped(table, readable_time, std::io::stdout().is_terminal(), full)
    );
}

/// One table style for every rendered table in this CLI ([`format_incidents`]
/// and [`format_table`]), so `incidents`, `query` and the diagnoses all look
/// the same: `UTF8_FULL_CONDENSED` preset, header cells plain (no bold).
/// `ContentArrangement::Dynamic` wraps a long cell (a signature, a host name)
/// inside the terminal width instead of letting it overflow — comfy-table
/// reads the real width itself when stdout is a tty; piped output (no tty)
/// falls back to comfy-table's own default of 80 columns, too narrow for a
/// signature, so it is widened to 120 only in that case — an interactive
/// terminal's own width is never overridden.
fn new_table() -> comfy_table::Table {
    let mut t = comfy_table::Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_content_arrangement(ContentArrangement::Dynamic);
    if !std::io::stdout().is_terminal() {
        t.set_width(120);
    }
    t
}

/// Render [`IncidentSummary`] rows newest first, as the daemon returns them:
/// `OPENED` (local wall clock, pasteable into `why --at`), `LASTED`
/// (humanized `closed - opened`, `open` while still open), `TRIGGER`, and
/// `SIGNATURE` last — the one column left to wrap. `with_ids` prepends the
/// full `ID` for scripting; there is no other shape. No rows prints
/// `no incidents` rather than an empty table. Pure over its input so it is
/// unit-tested directly.
fn format_incidents(rows: &[IncidentSummary], with_ids: bool) -> String {
    if rows.is_empty() {
        return "no incidents\n".to_string();
    }
    let mut t = new_table();
    let mut header: Vec<String> = Vec::new();
    if with_ids {
        header.push("ID".to_string());
    }
    header.extend(["OPENED", "LASTED", "TRIGGER", "SIGNATURE"].map(String::from));
    t.set_header(header);
    for i in rows {
        let mut cells: Vec<String> = Vec::new();
        if with_ids {
            cells.push(i.id.clone());
        }
        cells.push(opened_local(i.opened_us));
        cells.push(humanize_lasted(i.opened_us, i.closed_us));
        cells.push(i.trigger_id.clone());
        cells.push(i.signature.clone());
        t.add_row(cells);
    }
    format!("{t}\n")
}

/// The `OPENED` cell: the local wall-clock instant as `YYYY-MM-DD HH:MM:SS`,
/// so it pastes straight into `why --at`. Built by cutting the offset off
/// [`types::local_instant`]'s ISO rendering rather than reformatting the
/// timestamp a second way, so the two clocks can never disagree. An
/// out-of-range instant (no `T` to cut at) passes through
/// `local_instant`'s own words unchanged.
fn opened_local(ts_us: i64) -> String {
    let iso = types::local_instant(ts_us);
    match iso.split_once('T') {
        Some((date, rest)) if rest.len() >= 8 => format!("{date} {}", &rest[..8]),
        _ => iso,
    }
}

/// The `LASTED` cell: `closed_us - opened_us`, humanized — `< 60 s` as
/// `NN s`, `< 1 h` as `Mm SSs` (`2m 05s`), else `Hh MMm`. An open incident
/// (`closed_us` is `None`) reads `open`. A zero or negative duration reads
/// `0 s` rather than a negative number — the triggers engine now clamps a
/// close to never precede its open, but an operator-supplied or stale record
/// could still carry one, and this must not render as backwards time.
fn humanize_lasted(opened_us: i64, closed_us: Option<i64>) -> String {
    let Some(closed_us) = closed_us else {
        return "open".to_string();
    };
    let secs = (closed_us - opened_us).div_euclid(1_000_000);
    if secs <= 0 {
        "0 s".to_string()
    } else if secs < 60 {
        format!("{secs} s")
    } else if secs < 3_600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3_600, (secs % 3_600) / 60)
    }
}

/// Whether a cell counts as "no measurement" for [`column_is_numeric`],
/// rather than as a number: empty (a `SKIP` tick's withheld field — see
/// "SKIP, never silence" in AGENTS.md) or `-` (the placeholder
/// `format_status` prints for a value never measured at all). Neither should
/// flip a column of real numbers to left-alignment, since the diagnosis
/// tables routinely mix numeric rows with SKIP/gap rows.
fn is_blank_cell(c: &str) -> bool {
    let c = c.trim();
    c.is_empty() || c == "-"
}

/// Whether column `i` of `table` should right-align in [`format_table`]:
/// every NON-blank cell ([`is_blank_cell`]) parses as a number AND at least
/// one cell actually has a value. A column blank throughout (nothing to
/// align by) or genuinely non-numeric stays left-aligned. Pure over the
/// table so the rule is unit-tested directly, without parsing alignment back
/// out of comfy-table's rendered box.
fn column_is_numeric(table: &Table, i: usize) -> bool {
    let mut any_value = false;
    table.rows.iter().all(|r| match r.get(i) {
        None => true,
        Some(c) if is_blank_cell(c) => true,
        Some(c) => {
            any_value = true;
            c.trim().parse::<f64>().is_ok()
        }
    }) && any_value
}

/// The epoch-microseconds plausibility gate (owner ask): `s` parses as an
/// `i64` inside `2001-09-09`..`2096-10-27` in epoch microseconds. A duration
/// carried in the same `*_us` unit — `rtt_us`, `lasted_us`, a gap length —
/// never reaches eight-figure-plus microseconds even over a long window, so
/// checking the VALUE, not just a column's `_us`-suffixed name, keeps a
/// duration column from being misread as a clock reading.
fn plausible_epoch_us(s: &str) -> bool {
    const LOW: i64 = 1_000_000_000_000_000;
    const HIGH: i64 = 4_000_000_000_000_000;
    s.trim()
        .parse::<i64>()
        .is_ok_and(|v| (LOW..HIGH).contains(&v))
}

/// Whether column `i` of `rows` should convert to local time: every
/// non-blank cell ([`is_blank_cell`]) passes [`plausible_epoch_us`], and at
/// least one cell has a value (a column blank throughout has nothing to
/// judge). Blank/`-` cells are tolerated throughout, matching
/// [`column_is_numeric`]'s treatment of a SKIP tick's withheld field.
fn column_is_epoch_us(rows: &[Vec<String>], i: usize) -> bool {
    let mut any_value = false;
    rows.iter().all(|r| match r.get(i) {
        None => true,
        Some(c) if is_blank_cell(c) => true,
        Some(c) => {
            any_value = true;
            plausible_epoch_us(c)
        }
    }) && any_value
}

/// Convert column `i` of `rows` to local `YYYY-MM-DD HH:MM:SS`
/// ([`opened_local`] — the same format `incidents`' OPENED uses, pasteable
/// into `why --at`) in place, when [`column_is_epoch_us`] passes over it; a
/// no-op otherwise. Blank cells pass through unchanged either way. The one
/// site the readable-timestamps rule funnels through: every caller — the
/// generic [`format_table`], the `connections` view, and each of
/// `diagnose`'s own hand-rolled tables — converts by calling this on the
/// specific column index it knows is a `ts_us`/`*_us` epoch, never by
/// re-deriving the gate.
fn convert_epoch_us_column(rows: &mut [Vec<String>], i: usize) {
    if !column_is_epoch_us(rows, i) {
        return;
    }
    for row in rows.iter_mut() {
        let Some(cell) = row.get_mut(i) else { continue };
        if is_blank_cell(cell) {
            continue;
        }
        if let Ok(us) = cell.trim().parse::<i64>() {
            *cell = opened_local(us);
        }
    }
}

/// Render a generic query result as a [`new_table`]. See [`column_is_numeric`]
/// for which columns right-align.
///
/// `readable_time` gates the epoch-microseconds conversion: when `true`,
/// every column named `ts_us` or ending `_us` converts to local time first
/// ([`convert_epoch_us_column`]) if [`column_is_epoch_us`] clears it — the
/// header keeps its original name here (the `connections` view renames
/// `ts_us` to `ts` itself, before calling this). `query <SQL>` passes
/// `false`: it IS the record's raw/machine-readable carrier (realm
/// net-observer, node #75 — "raw queries stay in microseconds"; AGENTS.md's
/// Reality table names it the way to read the record's own contents), there
/// is no `--json`/`--raw` flag to route around it instead, and a converted
/// cell there would silently hand a script or agent a date string where an
/// integer was asked for. Every other named diagnosis is a human-facing
/// table and passes `true`.
fn format_table(table: &Table, readable_time: bool) -> String {
    let mut table = table.clone();
    if readable_time {
        for i in 0..table.columns.len() {
            if table.columns[i].ends_with("_us") {
                convert_epoch_us_column(&mut table.rows, i);
            }
        }
    }
    let mut t = new_table();
    t.set_header(table.columns.clone());
    for row in &table.rows {
        t.add_row(row.clone());
    }
    for i in 0..table.columns.len() {
        if !column_is_numeric(&table, i) {
            continue;
        }
        if let Some(col) = t.column_mut(i) {
            col.set_cell_alignment(CellAlignment::Right);
        }
    }
    format!("{t}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
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

    /// A closed row carries the new headers, the local `OPENED` rendering
    /// (never the raw microseconds alone), the humanized `LASTED`, and the
    /// trigger/signature — with no `ID` column when `--ids` was not asked
    /// for.
    #[test]
    fn format_incidents_renders_a_closed_row() {
        let out = format_incidents(
            &[incident("i1", "gw-drop", 1_000_000, Some(46_000_000))],
            false,
        );
        assert!(
            out.contains("OPENED")
                && out.contains("LASTED")
                && out.contains("TRIGGER")
                && out.contains("SIGNATURE"),
            "{out}"
        );
        // Column order: OPENED, LASTED, TRIGGER, SIGNATURE.
        assert!(
            out.find("OPENED") < out.find("LASTED")
                && out.find("LASTED") < out.find("TRIGGER")
                && out.find("TRIGGER") < out.find("SIGNATURE"),
            "{out}"
        );
        assert!(!out.contains("ID"), "no --ids: {out}");
        assert!(out.contains(&opened_local(1_000_000)), "opened: {out}");
        assert!(out.contains("45 s"), "lasted: {out}");
        assert!(out.contains("gw-drop") && out.contains("sig"), "{out}");
    }

    /// An open incident (no `closed_us`) reads `open` in `LASTED`, and the
    /// dating must not invent a close.
    #[test]
    fn format_incidents_marks_open_incidents_as_open() {
        let out = format_incidents(&[incident("i2", "wedge", 5_000_000, None)], false);
        assert!(out.contains(&opened_local(5_000_000)), "opened: {out}");
        assert!(out.contains("wedge") && out.contains("open"), "{out}");
    }

    /// `--ids` prepends the full incident id as its own column.
    #[test]
    fn format_incidents_with_ids_prepends_the_full_id() {
        let out = format_incidents(
            &[incident("i1", "gw-drop", 1_000_000, Some(2_000_000))],
            true,
        );
        assert!(out.contains("ID"), "{out}");
        assert!(out.contains("i1"), "{out}");
    }

    /// No rows prints `no incidents` rather than an empty (or header-only)
    /// table.
    #[test]
    fn format_incidents_of_no_rows_says_so() {
        assert_eq!(format_incidents(&[], false), "no incidents\n");
    }

    /// `LASTED`: `< 60 s` as `NN s`, `< 1 h` as `Mm SSs`, else `Hh MMm`; a
    /// zero/negative duration (a close stamped at or before its open) reads
    /// `0 s`, never a negative number.
    #[test]
    fn humanize_lasted_formats_by_magnitude() {
        assert_eq!(humanize_lasted(0, Some(5_000_000)), "5 s");
        assert_eq!(humanize_lasted(0, Some(125_000_000)), "2m 05s");
        assert_eq!(humanize_lasted(0, Some(3_725_000_000)), "1h 02m");
        assert_eq!(humanize_lasted(1_000, Some(991)), "0 s");
        assert_eq!(humanize_lasted(0, None), "open");
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
        let out = format_table(&table, true);
        assert!(out.contains("ts_us") && out.contains("gw"));
        assert!(out.contains("42") && out.contains("OK"));
    }

    /// A column mixing real numbers with a SKIP tick's withheld cell (`""`)
    /// and the "never measured" placeholder (`-`) still right-aligns: the
    /// diagnosis tables routinely mix numeric rows with SKIP/gap rows, and
    /// neither blank shape should flip the whole column to left-alignment.
    /// A column that is blank throughout has nothing to align by, so it
    /// stays left-aligned; a column with a genuinely non-numeric value
    /// anywhere is not numeric either.
    #[test]
    fn column_is_numeric_ignores_blanks_but_needs_at_least_one_value() {
        let mixed = Table {
            columns: vec!["n".into()],
            rows: vec![
                vec!["1".into()],
                vec!["".into()],
                vec!["-".into()],
                vec!["2.5".into()],
            ],
        };
        assert!(
            column_is_numeric(&mixed, 0),
            "numbers plus blanks: {mixed:?}"
        );

        let all_blank = Table {
            columns: vec!["n".into()],
            rows: vec![vec!["".into()], vec!["-".into()]],
        };
        assert!(
            !column_is_numeric(&all_blank, 0),
            "nothing to align by: {all_blank:?}"
        );

        let mixed_text = Table {
            columns: vec!["n".into()],
            rows: vec![vec!["1".into()], vec!["www.google.com".into()]],
        };
        assert!(
            !column_is_numeric(&mixed_text, 0),
            "one non-numeric cell rules out the column: {mixed_text:?}"
        );
    }

    /// The epoch-us plausibility gate (owner ask, Part B): a value inside
    /// the range reads as plausible; a duration-shaped `rtt_us`/`lasted_us`
    /// value — small, even a several-hour one in microseconds — never does,
    /// so the VALUE decides, not just a `*_us`-suffixed column name.
    #[test]
    fn plausible_epoch_us_gates_on_the_value() {
        assert!(plausible_epoch_us("1700000000000000"));
        assert!(plausible_epoch_us(" 1700000000000000 "));
        assert!(!plausible_epoch_us("42"));
        assert!(!plausible_epoch_us("999999999999")); // a `rtt_us`-shaped value
        assert!(!plausible_epoch_us("not a number"));
        assert!(!plausible_epoch_us(""));
        assert!(!plausible_epoch_us("4000000000000000")); // the gate's own high end, exclusive
        assert!(plausible_epoch_us("3999999999999999"));
    }

    /// [`column_is_epoch_us`] tolerates blanks like [`column_is_numeric`]
    /// does, and needs at least one value to judge; a column mixing a
    /// plausible epoch with a duration-shaped value is not uniformly epoch,
    /// so the whole column is left alone.
    #[test]
    fn column_is_epoch_us_tolerates_blanks_but_needs_a_value() {
        let rows = vec![
            vec!["1700000000000000".to_string()],
            vec![String::new()],
            vec!["-".to_string()],
            vec!["1700000060000000".to_string()],
        ];
        assert!(column_is_epoch_us(&rows, 0));

        let all_blank = vec![vec![String::new()], vec!["-".to_string()]];
        assert!(!column_is_epoch_us(&all_blank, 0));

        let mixed_with_a_duration = vec![
            vec!["1700000000000000".to_string()],
            vec!["120".to_string()],
        ];
        assert!(!column_is_epoch_us(&mixed_with_a_duration, 0));
    }

    /// [`convert_epoch_us_column`] rewrites a qualifying column's non-blank
    /// cells to local time in place, leaves blanks untouched, and is a no-op
    /// on a column that does not clear [`column_is_epoch_us`].
    #[test]
    fn convert_epoch_us_column_converts_in_place_and_skips_non_epoch_columns() {
        let epoch = 1_700_000_000_000_000i64;
        let mut rows = vec![
            vec![epoch.to_string(), "42".to_string()],
            vec![String::new(), "43".to_string()],
        ];
        convert_epoch_us_column(&mut rows, 0);
        assert_eq!(rows[0][0], opened_local(epoch));
        assert_eq!(rows[1][0], "", "a blank cell passes through unchanged");

        let mut untouched = vec![vec!["42".to_string()]];
        convert_epoch_us_column(&mut untouched, 0);
        assert_eq!(untouched[0][0], "42", "not plausibly epoch: left alone");
    }

    /// [`format_table`] converts every `_us`-suffixed column that clears the
    /// plausibility gate, keeps the header name as-is (the `connections`
    /// view renames it itself — see [`rename_ts_column`]), and leaves a
    /// duration-shaped `_us` column raw.
    #[test]
    fn format_table_converts_epoch_us_columns_but_not_duration_shaped_ones() {
        let epoch = 1_700_000_000_000_000i64;
        let table = Table {
            columns: vec!["ts_us".into(), "rtt_us".into()],
            rows: vec![vec![epoch.to_string(), "45000".into()]],
        };
        let out = format_table(&table, true);
        assert!(out.contains("ts_us"), "header name is kept: {out}");
        assert!(!out.contains(&epoch.to_string()), "raw epoch leaked: {out}");
        assert!(out.contains(&opened_local(epoch)), "{out}");
        assert!(out.contains("45000"), "a duration column stays raw: {out}");
    }

    /// `query <SQL>` is the record's raw/machine-readable carrier (realm
    /// net-observer, node #75 — "raw queries stay in microseconds"): it
    /// calls `format_table` with `readable_time = false`, so `ts_us` prints
    /// as the plain digits a script or agent can parse as an integer, never
    /// a date string — the exact same table read as `readable_time = true`
    /// (what `connections` and every other named diagnosis pass) converts.
    #[test]
    fn format_table_readable_time_false_keeps_query_output_raw() {
        let epoch = 1_700_000_000_000_000i64;
        let table = Table {
            columns: vec!["ts_us".into(), "gw".into()],
            rows: vec![vec![epoch.to_string(), "OK".into()]],
        };

        let raw = format_table(&table, false);
        assert!(
            raw.contains(&epoch.to_string()),
            "query's raw path must print the digits: {raw}"
        );
        assert!(
            !raw.contains(&opened_local(epoch)),
            "query's raw path must not render a date: {raw}"
        );

        let readable = format_table(&table, true);
        assert!(
            !readable.contains(&epoch.to_string()),
            "the readable path must not leak the raw epoch: {readable}"
        );
        assert!(
            readable.contains(&opened_local(epoch)),
            "the readable path converts: {readable}"
        );
    }

    /// The `connections` view's own rename: `ts_us` converts to local time
    /// AND its header becomes `ts`; a table without `ts_us` (an older
    /// daemon's, or already renamed) passes through unchanged.
    #[test]
    fn rename_ts_column_converts_and_renames_ts_us_only() {
        let epoch = 1_700_000_000_000_000i64;
        let table = Table {
            columns: vec!["ts_us".into(), "key".into()],
            rows: vec![vec![epoch.to_string(), "claude.ai".into()]],
        };
        let renamed = rename_ts_column(&table);
        assert_eq!(renamed.columns, vec!["ts", "key"]);
        assert_eq!(renamed.rows[0][0], opened_local(epoch));
        assert_eq!(renamed.rows[0][1], "claude.ai");

        let no_ts = Table {
            columns: vec!["key".into()],
            rows: vec![vec!["claude.ai".into()]],
        };
        assert_eq!(rename_ts_column(&no_ts), no_ts);
    }

    /// [`row_cap`]'s full truth table: capped only when stdout is a terminal
    /// AND `--full` was not given AND the table does not already fit under
    /// [`DEFAULT_ROW_LIMIT`] — every other combination shows everything. The
    /// "N more" count is `total - shown`.
    #[test]
    fn row_cap_truth_table() {
        assert_eq!(row_cap(false, false, DEFAULT_ROW_LIMIT + 1), None);
        assert_eq!(row_cap(false, true, DEFAULT_ROW_LIMIT + 1), None);
        assert_eq!(row_cap(true, true, DEFAULT_ROW_LIMIT + 1), None);
        assert_eq!(row_cap(true, false, DEFAULT_ROW_LIMIT), None);
        assert_eq!(
            row_cap(true, false, DEFAULT_ROW_LIMIT + 1),
            Some(DEFAULT_ROW_LIMIT)
        );
        let total = DEFAULT_ROW_LIMIT + 7;
        let shown = row_cap(true, false, total).unwrap();
        assert_eq!(total - shown, 7);
    }

    /// [`cap_rows`] is the ONE place `total_rows → row_cap → truncate → note`
    /// happens, shared by every renderer (the comfy_table path here and
    /// diagnose.rs's five hand-rolled tables alike) — pinned generically over
    /// a plain `Vec<usize>` rather than through any one renderer's shape.
    #[test]
    fn cap_rows_truncates_and_notes_when_capped() {
        let mut rows: Vec<usize> = (0..DEFAULT_ROW_LIMIT + 3).collect();
        let note = cap_rows(&mut rows, true, false);
        assert_eq!(rows, (0..DEFAULT_ROW_LIMIT).collect::<Vec<_>>());
        assert!(note.unwrap().contains("3 more rows"));
    }

    /// Off a terminal (or with `--full`), `cap_rows` leaves `rows` untouched
    /// and returns no note — the complement of the case above.
    #[test]
    fn cap_rows_leaves_everything_when_not_capped() {
        let mut rows: Vec<usize> = (0..DEFAULT_ROW_LIMIT + 3).collect();
        let original = rows.clone();
        assert!(cap_rows(&mut rows, false, false).is_none());
        assert_eq!(rows, original);
        assert!(cap_rows(&mut rows, true, true).is_none());
        assert_eq!(rows, original);
    }

    /// A table of `n` rows, each cell a fixed-width `row-NN` label so no
    /// value is ever a substring of another (unlike bare `0`..`9` inside
    /// `10`..`44`), which lets a test count exactly how many data rows a
    /// render actually carries.
    fn table_of(n: usize) -> Table {
        Table {
            columns: vec!["n".to_string()],
            rows: (0..n).map(|i| vec![format!("row-{i:02}")]).collect(),
        }
    }

    /// A table over [`DEFAULT_ROW_LIMIT`] rows, rendered on a simulated
    /// interactive terminal: capped to `DEFAULT_ROW_LIMIT` data rows plus the
    /// "more rows" note.
    #[test]
    fn render_table_capped_caps_on_a_tty() {
        let table = table_of(DEFAULT_ROW_LIMIT + 5);
        let out = render_table_capped(&table, false, true, false);
        assert_eq!(out.matches("row-").count(), DEFAULT_ROW_LIMIT);
        for i in 0..DEFAULT_ROW_LIMIT {
            assert!(
                out.contains(&format!("row-{i:02}")),
                "row {i} missing from capped output"
            );
        }
        for i in DEFAULT_ROW_LIMIT..table.rows.len() {
            assert!(
                !out.contains(&format!("row-{i:02}")),
                "row {i} should have been capped out"
            );
        }
        assert!(out.contains("more rows"));
        assert!(out.contains("5 more rows"));
    }

    /// The same table, not on a terminal (a pipe/redirect/script): every row
    /// renders, no "more rows" note — piping shows everything.
    #[test]
    fn render_table_capped_shows_everything_off_a_tty() {
        let table = table_of(DEFAULT_ROW_LIMIT + 5);
        let out = render_table_capped(&table, false, false, false);
        assert_eq!(out.matches("row-").count(), table.rows.len());
        assert!(!out.contains("more rows"));
    }

    /// `--full` is `global = true`: accepted before the subcommand and after
    /// it alike, and absent by default.
    #[test]
    fn full_flag_parses_before_and_after_the_subcommand() {
        let cli = Cli::try_parse_from(["net-observer-cli", "status"]).unwrap();
        assert!(!cli.full);
        let cli = Cli::try_parse_from(["net-observer-cli", "--full", "status"]).unwrap();
        assert!(cli.full);
        let cli = Cli::try_parse_from(["net-observer-cli", "status", "--full"]).unwrap();
        assert!(cli.full);
    }

    /// `--target`, `--slow` and `--sweep-max` (realm net-observer, node #154)
    /// parse into the right `ScanNeighbors` fields alongside the existing
    /// rung flags.
    #[test]
    fn scan_neighbors_parses_target_and_slow_and_sweep_max() {
        let cli = Cli::try_parse_from([
            "net-observer-cli",
            "scan-neighbors",
            "--target",
            "10.0.0.5",
            "--ports",
            "--slow",
        ])
        .unwrap();
        match cli.command {
            Command::ScanNeighbors {
                ports,
                banners,
                cve,
                target,
                slow,
                sweep_max,
            } => {
                assert!(ports);
                assert!(!banners);
                assert!(!cve);
                assert_eq!(target, Some("10.0.0.5".parse().unwrap()));
                assert!(slow);
                assert_eq!(sweep_max, None);
            }
            _ => panic!("did not parse as `scan-neighbors`"),
        }
    }

    /// `--sweep-max` parses as an `Option<u32>`, distinct from `--slow` and
    /// `--target`; the two flags are independent.
    #[test]
    fn scan_neighbors_parses_sweep_max() {
        let cli = Cli::try_parse_from(["net-observer-cli", "scan-neighbors", "--sweep-max", "500"])
            .unwrap();
        match cli.command {
            Command::ScanNeighbors {
                target, sweep_max, ..
            } => {
                assert_eq!(target, None);
                assert_eq!(sweep_max, Some(500));
            }
            _ => panic!("did not parse as `scan-neighbors`"),
        }
    }

    /// The nested `scan neighbors --ports` form parses exactly like the old
    /// flat `scan-neighbors --ports` did (realm net-observer, node #164).
    #[test]
    fn scan_neighbors_nested_form_parses() {
        let cli =
            Cli::try_parse_from(["net-observer-cli", "scan", "neighbors", "--ports"]).unwrap();
        match cli.command {
            Command::Scan(ScanCmd::Neighbors {
                ports,
                banners,
                cve,
                target,
                slow,
                sweep_max,
            }) => {
                assert!(ports);
                assert!(!banners);
                assert!(!cve);
                assert_eq!(target, None);
                assert!(!slow);
                assert_eq!(sweep_max, None);
            }
            _ => panic!("did not parse as `scan neighbors`"),
        }
    }

    /// The nested `scan topology` form parses as `ScanCmd::Topology`.
    #[test]
    fn scan_topology_nested_form_parses() {
        let cli = Cli::try_parse_from(["net-observer-cli", "scan", "topology"]).unwrap();
        assert!(matches!(cli.command, Command::Scan(ScanCmd::Topology)));
    }

    /// The flat `scan-topology` legacy alias still parses, hidden but not
    /// removed — kept flat for old scripts and muscle memory (realm
    /// net-observer, node #164).
    #[test]
    fn scan_topology_flat_alias_parses() {
        let cli = Cli::try_parse_from(["net-observer-cli", "scan-topology"]).unwrap();
        assert!(matches!(cli.command, Command::ScanTopology));
    }

    /// `diag why --at …` parses into the nested form, same as the old flat
    /// `why --at …` (realm net-observer, node #164).
    #[test]
    fn diag_why_nested_form_parses() {
        let cli = Cli::try_parse_from(["net-observer-cli", "diag", "why", "--at", "now"]).unwrap();
        match cli.command {
            Command::Diag(DiagCmd::Why { at }) => assert_eq!(at, "now"),
            _ => panic!("did not parse as `diag why`"),
        }
        // The old flat `why` invocation still works too.
        let cli = Cli::try_parse_from(["net-observer-cli", "why", "--at", "now"]).unwrap();
        match cli.command {
            Command::Why { at } => assert_eq!(at, "now"),
            _ => panic!("did not parse as `why` (legacy alias)"),
        }
    }

    /// `diag wedge` is the renamed, shorter nested form of the old
    /// `wedge-or-starvation`, which still parses as a hidden alias (realm
    /// net-observer, node #164).
    #[test]
    fn diag_wedge_nested_form_parses_and_old_alias_still_works() {
        let cli = Cli::try_parse_from(["net-observer-cli", "diag", "wedge"]).unwrap();
        assert!(matches!(cli.command, Command::Diag(DiagCmd::Wedge)));
        let cli = Cli::try_parse_from(["net-observer-cli", "wedge-or-starvation"]).unwrap();
        assert!(matches!(cli.command, Command::WedgeOrStarvation));
    }

    /// `daemon observe on`/`daemon probe active` parse into the nested form;
    /// the old flat `observe`/`probe` invocations still work as hidden
    /// aliases (realm net-observer, node #164).
    #[test]
    fn daemon_observe_and_probe_nested_form_parses() {
        let cli = Cli::try_parse_from(["net-observer-cli", "daemon", "observe", "on"]).unwrap();
        match cli.command {
            Command::Daemon(DaemonCmd::Observe { state }) => assert!(state.as_bool()),
            _ => panic!("did not parse as `daemon observe`"),
        }
        let cli = Cli::try_parse_from(["net-observer-cli", "observe", "off"]).unwrap();
        match cli.command {
            Command::Observe { state } => assert!(!state.as_bool()),
            _ => panic!("did not parse as `observe` (legacy alias)"),
        }
        let cli = Cli::try_parse_from(["net-observer-cli", "daemon", "probe", "active"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Daemon(DaemonCmd::Probe {
                tier: ProbeTier::Active
            })
        ));
    }

    /// `daemon kickstart`/`daemon experiment-report <id>` parse into the
    /// nested form (realm net-observer, node #164).
    #[test]
    fn daemon_kickstart_and_experiment_report_nested_form_parses() {
        let cli = Cli::try_parse_from(["net-observer-cli", "daemon", "kickstart"]).unwrap();
        assert!(matches!(cli.command, Command::Daemon(DaemonCmd::Kickstart)));
        let cli = Cli::try_parse_from([
            "net-observer-cli",
            "daemon",
            "experiment-report",
            "experiment-42",
        ])
        .unwrap();
        match cli.command {
            Command::Daemon(DaemonCmd::ExperimentReport { id }) => {
                assert_eq!(id, "experiment-42");
            }
            _ => panic!("did not parse as `daemon experiment-report`"),
        }
    }

    /// The shallow, frequently-used commands still parse directly at the top
    /// level, unaffected by the scan/diag/daemon grouping (realm
    /// net-observer, node #164).
    #[test]
    fn shallow_commands_still_parse_at_top_level() {
        assert!(matches!(
            Cli::try_parse_from(["net-observer-cli", "status"])
                .unwrap()
                .command,
            Command::Status
        ));
        assert!(matches!(
            Cli::try_parse_from(["net-observer-cli", "query", "select 1"])
                .unwrap()
                .command,
            Command::Query { .. }
        ));
        assert!(matches!(
            Cli::try_parse_from(["net-observer-cli", "segments"])
                .unwrap()
                .command,
            Command::Segments
        ));
        assert!(matches!(
            Cli::try_parse_from(["net-observer-cli", "air"])
                .unwrap()
                .command,
            Command::Air
        ));
    }

    #[test]
    fn check_cve_parses_the_target_ip() {
        let cli = Cli::try_parse_from(["net-observer-cli", "check-cve", "10.0.0.5"]).unwrap();
        match cli.command {
            Command::CheckCve {
                ip,
                product,
                version,
                all,
            } => {
                assert_eq!(ip, Some("10.0.0.5".parse::<IpAddr>().unwrap()));
                assert_eq!(product, None);
                assert_eq!(version, None);
                assert!(!all);
            }
            _ => panic!("did not parse as `check-cve`"),
        }
    }

    #[test]
    fn check_cve_parses_all() {
        let cli =
            Cli::try_parse_from(["net-observer-cli", "check-cve", "10.0.0.5", "--all"]).unwrap();
        match cli.command {
            Command::CheckCve { all, .. } => assert!(all),
            _ => panic!("did not parse as `check-cve`"),
        }
    }

    /// `--product` and `--version` parse into lookup mode, with the positional
    /// `<ip>` left `None`.
    #[test]
    fn check_cve_parses_product_and_version() {
        let cli = Cli::try_parse_from([
            "net-observer-cli",
            "check-cve",
            "--product",
            "ios",
            "--version",
            "17.2",
        ])
        .unwrap();
        match cli.command {
            Command::CheckCve {
                ip,
                product,
                version,
                all,
            } => {
                assert_eq!(ip, None);
                assert_eq!(product.as_deref(), Some("ios"));
                assert_eq!(version.as_deref(), Some("17.2"));
                assert!(!all);
            }
            _ => panic!("did not parse as `check-cve`"),
        }
    }

    /// `<ip>` and `--product` are mutually exclusive — giving both is a clap
    /// error, not a silent pick of one. `Cli` carries no `Debug` impl, so
    /// `.err()` (not `.unwrap_err()`, which would need one to format the `Ok`
    /// side on a mismatch) is how every other clap-rejection test here gets
    /// at the error.
    #[test]
    fn check_cve_rejects_ip_and_product_together() {
        let err = Cli::try_parse_from([
            "net-observer-cli",
            "check-cve",
            "10.0.0.5",
            "--product",
            "openssh",
        ])
        .err()
        .expect("ip and --product together must be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// `--version` without `--product` is a clap error: a bare version narrows
    /// nothing without a product to look up.
    #[test]
    fn check_cve_rejects_version_without_product() {
        let err = Cli::try_parse_from(["net-observer-cli", "check-cve", "--version", "17.2"])
            .err()
            .expect("--version without --product must be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// Neither `<ip>` nor `--product` given: clap refuses rather than silently
    /// running neither mode.
    #[test]
    fn check_cve_rejects_neither_ip_nor_product() {
        let err = Cli::try_parse_from(["net-observer-cli", "check-cve"])
            .err()
            .expect("neither <ip> nor --product must be rejected");
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// The `check_target` `ArgGroup` (`ip`/`--product`) renders the bare
    /// invocation as ONE required choice, not two arguments that each read
    /// as independently required — the confusing shape this replaced (owner
    /// ask). Captured from an actual `try_parse_from` error, not guessed.
    #[test]
    fn check_cve_bare_invocation_names_one_required_choice() {
        let err = Cli::try_parse_from(["net-observer-cli", "check-cve"])
            .err()
            .expect("neither <ip> nor --product must be rejected");
        let rendered = err.to_string();
        // Old shape (pre-ArgGroup): `--product <PRODUCT>` and `<IP>` were
        // listed as two separate required arguments, each on its own line —
        // reading as "both are required". The group instead names the pair
        // as a single alternative, `<IP|--product <PRODUCT>>`, once.
        assert_eq!(
            rendered.matches("<IP|--product <PRODUCT>>").count(),
            2, // once in "required arguments", once in the Usage: line
            "expected the group to render as one <IP|--product <PRODUCT>> choice, got:\n{rendered}"
        );
    }

    #[test]
    fn vulns_parses_all() {
        let cli = Cli::try_parse_from(["net-observer-cli", "vulns"]).unwrap();
        match cli.command {
            Command::Vulns { all, .. } => assert!(!all),
            _ => panic!("did not parse as `vulns`"),
        }
        let cli = Cli::try_parse_from(["net-observer-cli", "vulns", "--all"]).unwrap();
        match cli.command {
            Command::Vulns { all, .. } => assert!(all),
            _ => panic!("did not parse as `vulns`"),
        }
    }

    /// `neighbors --all` parses, mirroring `vulns --all` — the client-side
    /// `keep_last_run` filter (already unit-tested on its own) applies by
    /// default and is skipped with `--all`.
    #[test]
    fn neighbors_parses_all() {
        let cli = Cli::try_parse_from(["net-observer-cli", "neighbors"]).unwrap();
        match cli.command {
            Command::Neighbors { all, .. } => assert!(!all),
            _ => panic!("did not parse as `neighbors`"),
        }
        let cli = Cli::try_parse_from(["net-observer-cli", "neighbors", "--all"]).unwrap();
        match cli.command {
            Command::Neighbors { all, .. } => assert!(all),
            _ => panic!("did not parse as `neighbors`"),
        }
    }

    /// `topology --all` parses, the same mechanism as `neighbors --all`.
    #[test]
    fn topology_parses_all() {
        let cli = Cli::try_parse_from(["net-observer-cli", "topology"]).unwrap();
        match cli.command {
            Command::Topology { all, .. } => assert!(!all),
            _ => panic!("did not parse as `topology`"),
        }
        let cli = Cli::try_parse_from(["net-observer-cli", "topology", "--all"]).unwrap();
        match cli.command {
            Command::Topology { all, .. } => assert!(all),
            _ => panic!("did not parse as `topology`"),
        }
    }

    #[test]
    fn check_cve_rejects_a_bad_ip() {
        assert!(Cli::try_parse_from(["net-observer-cli", "check-cve", "not-an-ip"]).is_err());
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

    /// The [`focus_vulns_for_ip`] fixture: `mac, ip, port, cve_id, confidence,
    /// known_exploited, cvss` — exactly [`diagnosis::vulns_sql`]'s column
    /// order, so a positional slip in the helper would be caught here too.
    fn vulns_table(rows: Vec<[&str; 7]>) -> Table {
        Table {
            columns: [
                "mac",
                "ip",
                "port",
                "cve_id",
                "confidence",
                "known_exploited",
                "cvss",
            ]
            .map(String::from)
            .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    /// Like [`vulns_table`], plus `last_seen_us` — every column
    /// [`focus_vulns_for_ip`] AND the freshness/last-run filters need, for a
    /// test that runs a row through both.
    fn vulns_table_full(rows: Vec<[&str; 8]>) -> Table {
        Table {
            columns: [
                "mac",
                "ip",
                "port",
                "cve_id",
                "confidence",
                "known_exploited",
                "cvss",
                "last_seen_us",
            ]
            .map(String::from)
            .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    /// Two hosts' worth of rows, mixed KEV/non-KEV and CVSS, to prove
    /// [`focus_vulns_for_ip`] both filters to the one address and sorts KEV
    /// first, worst CVSS next within each KEV group — and drops `mac`/`ip`.
    #[test]
    fn focus_vulns_for_ip_filters_and_sorts_kev_then_cvss() {
        let t = vulns_table(vec![
            ["aa:1", "10.0.0.5", "22", "CVE-A", "high", "false", "5.5"],
            ["aa:1", "10.0.0.5", "443", "CVE-B", "high", "true", "7.5"],
            ["aa:1", "10.0.0.5", "80", "CVE-C", "medium", "false", "9.1"],
            ["aa:1", "10.0.0.5", "8080", "CVE-D", "low", "true", "9.8"],
            // A different host — must not appear in the focused table.
            ["bb:2", "10.0.0.9", "22", "CVE-E", "high", "true", "9.9"],
        ]);
        let ip = "10.0.0.5".parse().unwrap();
        let focused = focus_vulns_for_ip(&t, &ip);

        assert_eq!(
            focused.columns,
            ["port", "cve_id", "cvss", "confidence", "known_exploited"]
        );
        let ids: Vec<&str> = focused.rows.iter().map(|r| r[1].as_str()).collect();
        // KEV (D, B) before non-KEV (C, A); worst CVSS first within each group.
        assert_eq!(ids, ["CVE-D", "CVE-B", "CVE-C", "CVE-A"]);
        assert!(focused.rows.iter().all(|r| r.len() == 5));
    }

    /// A blank `cvss` cell (no CVSS in the record) sorts LAST, not first — an
    /// unscored hypothesis must never outrank a scored one.
    #[test]
    fn focus_vulns_for_ip_sorts_blank_cvss_last() {
        let t = vulns_table(vec![
            ["aa:1", "10.0.0.5", "22", "CVE-A", "low", "false", ""],
            ["aa:1", "10.0.0.5", "23", "CVE-B", "low", "false", "3.1"],
        ]);
        let ip = "10.0.0.5".parse().unwrap();
        let focused = focus_vulns_for_ip(&t, &ip);
        let ids: Vec<&str> = focused.rows.iter().map(|r| r[1].as_str()).collect();
        assert_eq!(ids, ["CVE-B", "CVE-A"]);
    }

    /// A table missing a column `check-cve` needs (an older daemon's shape)
    /// returns the empty focused table rather than panicking on an index.
    #[test]
    fn focus_vulns_for_ip_on_a_table_missing_columns_is_empty_not_a_panic() {
        let t = Table {
            columns: vec!["mac".into(), "ip".into()],
            rows: vec![vec!["aa:1".into(), "10.0.0.5".into()]],
        };
        let ip = "10.0.0.5".parse().unwrap();
        let focused = focus_vulns_for_ip(&t, &ip);
        assert!(focused.rows.is_empty());
        assert_eq!(
            focused.columns,
            ["port", "cve_id", "cvss", "confidence", "known_exploited"]
        );
    }

    /// A fixture with a `last_seen_us` column, for [`keep_last_run`] and
    /// [`filter_by_ip`].
    fn vulns_table_with_last_seen(rows: Vec<[&str; 4]>) -> Table {
        Table {
            columns: ["ip", "cve_id", "cvss", "last_seen_us"]
                .map(String::from)
                .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    /// `vulns`' default: rows at two different `last_seen_us` values keep
    /// only the newest scan's rows; `--all` is simply skipping this filter,
    /// so the untouched table already proves the other half.
    #[test]
    fn keep_last_run_keeps_only_the_max_timestamp_rows() {
        let t = vulns_table_with_last_seen(vec![
            ["10.0.0.5", "CVE-OLD", "5.0", "1000"],
            ["10.0.0.5", "CVE-NEW-1", "6.0", "2000"],
            ["10.0.0.9", "CVE-NEW-2", "7.0", "2000"],
        ]);
        let last_run = keep_last_run(&t);
        let ids: Vec<&str> = last_run.rows.iter().map(|r| r[1].as_str()).collect();
        assert_eq!(ids, ["CVE-NEW-1", "CVE-NEW-2"]);
        // `--all` keeps everything — proven by simply not calling the filter.
        assert_eq!(t.rows.len(), 3);
    }

    /// A table missing `last_seen_us` (an older daemon's shape) passes
    /// through unchanged rather than emptying every `vulns` row.
    #[test]
    fn keep_last_run_passes_through_a_table_missing_the_column() {
        let t = Table {
            columns: vec!["cve_id".into()],
            rows: vec![vec!["CVE-A".into()]],
        };
        assert_eq!(keep_last_run(&t), t);
    }

    /// The order `check-cve`'s default actually uses: scope to the host
    /// FIRST, then to the max `last_seen_us` AMONG that host's own rows — a
    /// different host scanned more recently (`10.0.0.9` at `3000`) must
    /// neither leak into the result nor suppress `10.0.0.5`'s own latest
    /// scan (`2000`), which the table's GLOBAL maximum would get wrong.
    #[test]
    fn filter_by_ip_then_keep_last_run_gives_this_scan_only() {
        let t = vulns_table_with_last_seen(vec![
            ["10.0.0.5", "CVE-OLD-SCAN", "5.0", "1000"],
            ["10.0.0.5", "CVE-NEW-SCAN", "6.0", "2000"],
            ["10.0.0.9", "CVE-OTHER-HOST", "9.0", "3000"],
        ]);
        let ip = "10.0.0.5".parse().unwrap();
        let scoped = keep_last_run(&filter_by_ip(&t, &ip));
        let ids: Vec<&str> = scoped.rows.iter().map(|r| r[1].as_str()).collect();
        assert_eq!(ids, ["CVE-NEW-SCAN"]);
    }

    /// `filter_by_ip` alone: a table missing `ip` passes through unfiltered,
    /// like [`filter_by_iface`]'s equivalent case.
    #[test]
    fn filter_by_ip_passes_through_a_table_missing_the_column() {
        let t = Table {
            columns: vec!["cve_id".into()],
            rows: vec![vec!["CVE-A".into()]],
        };
        let ip = "10.0.0.5".parse().unwrap();
        assert_eq!(filter_by_ip(&t, &ip), t);
    }

    /// `keep_since` keeps a row exactly AT the threshold (this scan's own
    /// write can land at the same microsecond the clock was read at, given
    /// how fast the comparison is taken) and drops everything strictly
    /// before it.
    #[test]
    fn keep_since_keeps_rows_at_or_after_the_threshold() {
        let t = vulns_table_with_last_seen(vec![
            ["10.0.0.5", "CVE-OLD", "5.0", "1000"],
            ["10.0.0.5", "CVE-AT-THRESHOLD", "6.0", "5000"],
            ["10.0.0.5", "CVE-AFTER", "7.0", "6000"],
        ]);
        let fresh = keep_since(&t, 5000);
        let ids: Vec<&str> = fresh.rows.iter().map(|r| r[1].as_str()).collect();
        assert_eq!(ids, ["CVE-AT-THRESHOLD", "CVE-AFTER"]);
        assert!(keep_since(&t, 6001).rows.is_empty());
    }

    /// A table missing `last_seen_us` (an older daemon's shape) passes
    /// through unchanged rather than emptying every row.
    #[test]
    fn keep_since_passes_through_a_table_missing_the_column() {
        let t = Table {
            columns: vec!["cve_id".into()],
            rows: vec![vec!["CVE-A".into()]],
        };
        assert_eq!(keep_since(&t, 1000), t);
    }

    #[test]
    fn newest_last_seen_local_reads_the_tables_max_timestamp() {
        let t = vulns_table_with_last_seen(vec![
            ["10.0.0.5", "CVE-OLD", "5.0", "1000"],
            ["10.0.0.5", "CVE-NEW", "6.0", "5000"],
        ]);
        assert_eq!(newest_last_seen_local(&t), Some(opened_local(5000)));
        assert_eq!(newest_last_seen_local(&Table::default()), None);
    }

    /// The regression case fix #1 exists for: a re-scan that finds nothing
    /// NEW for the host (patched, port closed — `neighbor_vuln` is upserted
    /// only on a match, so a clean re-scan writes no row at all) must not
    /// fall back to a PREVIOUS scan's row and present it as this scan's own
    /// finding. `check-cve`'s default composes `filter_by_ip` then
    /// `keep_since(scan_start_us)`, exactly as the `CheckCve` arm does —
    /// proving the shown table is empty (never the stale row) and that
    /// `check_cve_outcome` reports the honest `NoFreshButHasHistory`, not a
    /// silent "no vulnerabilities".
    #[test]
    fn check_cve_default_reports_stale_history_instead_of_showing_it() {
        let t = vulns_table_full(vec![[
            "aa:bb:cc:dd:ee:01",
            "10.0.0.5",
            "22",
            "CVE-OLD",
            "high",
            "false",
            "5.0",
            "1000",
        ]]);
        let ip = "10.0.0.5".parse().unwrap();
        // The scan started strictly after the only recorded row was written
        // — exactly what "found nothing new" looks like from the CLI side.
        let scan_start_us = 5000;

        let ip_rows = filter_by_ip(&t, &ip);
        let has_history = !ip_rows.rows.is_empty();
        let fresh = keep_since(&ip_rows, scan_start_us);
        let focused = focus_vulns_for_ip(&fresh, &ip);

        assert!(
            focused.rows.is_empty(),
            "the stale row must never be shown as this scan's finding: {focused:?}"
        );
        assert!(has_history, "the host does have an older recorded row");
        assert_eq!(
            check_cve_outcome(focused.rows.len(), has_history, true),
            CheckCveOutcome::NoFreshButHasHistory
        );
    }

    /// `check-cve` is a live operation — it just scanned the running daemon
    /// — so a global `--db` naming an unrelated offline file is refused
    /// before any socket or file is touched, rather than silently reading
    /// that file's history back as if it were this scan's.
    #[test]
    fn check_cve_refuses_an_explicit_db() {
        let cli = Cli::try_parse_from([
            "net-observer-cli",
            "--db",
            "/tmp/some-other-record.duckdb",
            "check-cve",
            "10.0.0.5",
        ])
        .unwrap();
        let err = run(&cli).unwrap_err().to_string();
        assert!(err.contains("--db"), "{err}");
        assert!(err.contains("not compatible"), "{err}");
    }

    #[test]
    fn check_cve_outcome_picks_the_right_branch() {
        // The cve rung not running outranks everything else, whatever the
        // shown count or history say.
        assert_eq!(
            check_cve_outcome(0, false, false),
            CheckCveOutcome::SnapshotUnavailable
        );
        assert_eq!(
            check_cve_outcome(3, true, false),
            CheckCveOutcome::SnapshotUnavailable
        );
        // Nothing shown, but the host has older rows: the honest "stale, not
        // current" message — never the rows themselves.
        assert_eq!(
            check_cve_outcome(0, true, true),
            CheckCveOutcome::NoFreshButHasHistory
        );
        // Nothing shown and no history at all: the fail-safe fallback, never
        // a confident "no vulnerabilities" on its own.
        assert_eq!(
            check_cve_outcome(0, false, true),
            CheckCveOutcome::NoFindings
        );
        assert_eq!(check_cve_outcome(1, true, true), CheckCveOutcome::Findings);
        assert_eq!(check_cve_outcome(5, false, true), CheckCveOutcome::Findings);
    }

    /// The three honest-note wordings `net-observerd` actually emits for "the
    /// cve rung could not run" (`load_and_classify`'s three `Unusable`
    /// reasons, and `scan_now`'s pre-run drop) all read as unavailable; an
    /// ordinary scan summary with no mention of a snapshot problem does not.
    #[test]
    fn cve_rung_unavailable_matches_the_daemons_own_wordings() {
        for msg in [
            "swept 192.168.1.0/24 (12/12 probed): 3 neighbours, 1 named; 3 open ports, \
             2 banners [cve: cve rung ran without a snapshot directory]",
            "swept 192.168.1.0/24 (12/12 probed): 3 neighbours, 1 named; 3 open ports, \
             2 banners [cve: snapshot at /var/lib/observer/cve failed to load: I/O error; \
             findings NOT checked]",
            "swept 192.168.1.0/24 (12/12 probed): 3 neighbours, 1 named; 3 open ports, \
             2 banners [cve: snapshot at /var/lib/observer/cve is empty or wrong layout; \
             findings NOT checked (not a clean 'no vulnerabilities')]",
            "swept 192.168.1.0/24 (12/12 probed): 3 neighbours, 1 named; 3 open ports, \
             2 banners [dropped: cve (no CVE snapshot; set \
             collectors.neighbors.cve_snapshot_dir to a provisioned directory)]",
        ] {
            assert!(cve_rung_unavailable(msg), "{msg}");
        }
        let clean = "swept 192.168.1.0/24 (12/12 probed): 3 neighbours, 1 named; 3 open \
                      ports, 2 banners";
        assert!(!cve_rung_unavailable(clean), "{clean}");
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

    /// `connections --by` takes the six groupings by their lowercase names,
    /// defaults to `host`, and maps onto the wire type the daemon reads —
    /// `iface` has none of its own and rides on `host` (see
    /// [`GroupByArg::to_group_by`]).
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
            (
                "process-host",
                GroupByArg::ProcessHost,
                ConnectionsGroupBy::ProcessHost,
            ),
            ("iface", GroupByArg::Iface, ConnectionsGroupBy::Host),
        ] {
            let by = parse(&["connections", "--by", token]);
            assert_eq!(by, arg, "{token}");
            assert_eq!(by.to_group_by(), wire, "{token}");
        }
        assert!(Cli::try_parse_from(["net-observer-cli", "connections", "--by", "port"]).is_err());
    }

    /// `connections --iface <name>` is a plain string filter, independent of
    /// `--by`/`--scope`/`--all`; absent by default.
    #[test]
    fn connections_iface_flag_parses() {
        let parse = |args: &[&str]| {
            let cli = Cli::try_parse_from(
                std::iter::once("net-observer-cli").chain(args.iter().copied()),
            )
            .unwrap_or_else(|e| panic!("{args:?}: {e}"));
            match cli.command {
                Command::Connections { iface, .. } => iface,
                _ => panic!("{args:?} did not parse as `connections`"),
            }
        };
        assert_eq!(parse(&["connections"]), None);
        assert_eq!(
            parse(&["connections", "--iface", "utun10"]),
            Some("utun10".to_string())
        );
        assert_eq!(
            parse(&["connections", "--iface", "blocked", "--by", "iface"]),
            Some("blocked".to_string())
        );
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

    /// A `connections` table shaped like the current `connections_sql`
    /// answer, `iface` included — after `key`, before `scope` (realm
    /// net-observer, node #75).
    fn iface_table(rows: Vec<[&str; 9]>) -> Table {
        Table {
            columns: [
                "ts_us", "verdict", "key", "iface", "scope", "count", "upload", "download", "hosts",
            ]
            .map(String::from)
            .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    /// `--iface <name>` keeps exact matches (`blocked` included), keeps the
    /// empty-tick marker under every filter, and `None` (no `--iface`)
    /// passes the table through unfiltered.
    #[test]
    fn filter_by_iface_keeps_matching_rows_and_the_marker() {
        let t = iface_table(vec![
            [
                "7",
                "OK",
                "claude.ai",
                "utun10",
                "external",
                "3",
                "100",
                "5006",
                "",
            ],
            ["7", "OK", "printer.local", "en0", "lan", "1", "1", "1", ""],
            [
                "7",
                "OK",
                "ads.example",
                "blocked",
                "external",
                "1",
                "1",
                "0",
                "",
            ],
        ]);
        let kept = filter_by_iface(&t, Some("utun10"));
        assert_eq!(kept.rows.len(), 1);
        assert_eq!(kept.rows[0][2], "claude.ai");

        let blocked = filter_by_iface(&t, Some("blocked"));
        assert_eq!(blocked.rows.len(), 1);
        assert_eq!(blocked.rows[0][2], "ads.example");

        assert_eq!(filter_by_iface(&t, None), t);

        let skipped = iface_table(vec![["7", "SKIP", "", "", "", "", "", "", ""]]);
        assert_eq!(filter_by_iface(&skipped, Some("utun10")), skipped);
    }

    /// A minimal shape [`fold_by_iface`] needs: `key`, `iface`,
    /// `count`/`upload`/`download` — what the table looks like after
    /// [`fold_by_scope`] has already dropped `scope`.
    fn iface_fold_input(rows: Vec<[&str; 5]>) -> Table {
        Table {
            columns: ["key", "iface", "count", "upload", "download"]
                .map(String::from)
                .to_vec(),
            rows: rows
                .into_iter()
                .map(|r| r.map(String::from).to_vec())
                .collect(),
        }
    }

    /// `--by iface` sums `count`/`upload`/`download` per interface, an
    /// absent `iface` folds under `-`, and the busiest interface comes
    /// first — the daemon's own `count DESC` order, kept by the client fold.
    #[test]
    fn fold_by_iface_sums_by_interface_and_defaults_unknown_to_dash() {
        let t = iface_fold_input(vec![
            ["claude.ai", "utun10", "3", "100", "5006"],
            ["o540343.ingest.sentry.io", "utun10", "1", "4", "0"],
            ["printer.local", "en0", "1", "1", "1"],
            ["ads.example", "blocked", "1", "1", "0"],
            ["mystery.example", "", "1", "2", "0"],
        ]);
        let folded = fold_by_iface(&t);
        assert_eq!(
            folded.columns,
            ["iface", "count", "upload", "download"],
            "{folded:?}"
        );
        let row = |iface: &str| {
            folded
                .rows
                .iter()
                .find(|r| r[0] == iface)
                .unwrap_or_else(|| panic!("no {iface} row in {folded:?}"))
                .clone()
        };
        assert_eq!(row("utun10"), vec!["utun10", "4", "104", "5006"]);
        assert_eq!(row("en0"), vec!["en0", "1", "1", "1"]);
        assert_eq!(row("blocked"), vec!["blocked", "1", "1", "0"]);
        assert_eq!(row("-"), vec!["-", "1", "2", "0"]);
        assert_eq!(folded.rows[0][0], "utun10", "busiest interface first");
    }

    /// The empty-tick marker row (`key` blank) carries no flow to fold: the
    /// table passes through unchanged rather than folding "no flow at all"
    /// into the `-` bucket alongside a real unknown-interface flow.
    #[test]
    fn fold_by_iface_passes_through_an_empty_tick_unchanged() {
        let skipped = iface_fold_input(vec![["", "", "", "", ""]]);
        assert_eq!(fold_by_iface(&skipped), skipped);
    }

    /// A table missing a column this fold needs — an older daemon's, or one
    /// already reshaped by a different fold — passes through unchanged
    /// rather than panicking or matching nothing.
    #[test]
    fn fold_by_iface_passes_through_a_table_missing_its_columns() {
        let t = Table {
            columns: vec!["key".into()],
            rows: vec![vec!["x".into()]],
        };
        assert_eq!(fold_by_iface(&t), t);
    }

    /// The default `connections` view end to end: `ts_us` becomes `ts` and
    /// reads local time, `iface` sits between `key` and (the now-dropped)
    /// `scope`, and the internal/lan rows are counted rather than listed —
    /// the render an operator actually sees.
    #[test]
    fn connections_default_view_renders_the_iface_column() {
        let epoch_us = 1_700_000_000_000_000i64;
        let ts = epoch_us.to_string();
        let t = iface_table(vec![
            [
                ts.as_str(),
                "OK",
                "172.19.0.1",
                "",
                "internal",
                "1023",
                "1",
                "1",
                "",
            ],
            [
                ts.as_str(),
                "OK",
                "printer.local",
                "en0",
                "lan",
                "4",
                "1",
                "1",
                "",
            ],
            [
                ts.as_str(),
                "OK",
                "claude.ai",
                "utun10",
                "external",
                "3",
                "100",
                "5006",
                "",
            ],
            [
                ts.as_str(),
                "OK",
                "ads.example",
                "blocked",
                "external",
                "1",
                "1",
                "0",
                "",
            ],
        ]);
        let renamed = rename_ts_column(&t);
        let filtered = filter_by_iface(&renamed, None);
        let (shown, hidden) = fold_by_scope(&filtered, Some(ConnectionScope::External));
        assert_eq!(
            shown.columns,
            [
                "ts", "verdict", "key", "iface", "count", "upload", "download", "hosts"
            ]
        );
        let local = opened_local(epoch_us);
        assert_eq!(
            shown.rows[0],
            vec![
                local.clone(),
                "OK".to_string(),
                "claude.ai".to_string(),
                "utun10".to_string(),
                "3".to_string(),
                "100".to_string(),
                "5006".to_string(),
                String::new(),
            ]
        );
        assert_eq!(
            shown.rows[1],
            vec![
                local,
                "OK".to_string(),
                "ads.example".to_string(),
                "blocked".to_string(),
                "1".to_string(),
                "1".to_string(),
                "0".to_string(),
                String::new(),
            ]
        );
        assert_eq!(hidden, [1023, 4, 0]);
        // Captured for the STATUS report: the rendered header + these rows.
        println!("{}", format_table(&shown, true));
    }

    /// `connections --by iface` end to end, chained exactly as `run()`
    /// chains it: rename the ts column, filter by `--iface` (none given
    /// here), fold by scope (external only, the default), then fold by
    /// interface. The internal/lan rows never reach the interface fold —
    /// they are gone at the scope step — and the three external rows (two
    /// sharing `utun10`) merge into two interface totals.
    #[test]
    fn connections_by_iface_pipeline_chains_filter_scope_and_iface_fold() {
        let t = iface_table(vec![
            [
                "7",
                "OK",
                "172.19.0.1",
                "",
                "internal",
                "1023",
                "1",
                "1",
                "",
            ],
            ["7", "OK", "printer.local", "en0", "lan", "4", "1", "1", ""],
            [
                "7",
                "OK",
                "claude.ai",
                "utun10",
                "external",
                "3",
                "100",
                "5006",
                "",
            ],
            [
                "7",
                "OK",
                "o540343.ingest.sentry.io",
                "utun10",
                "external",
                "1",
                "4",
                "0",
                "",
            ],
            [
                "7",
                "OK",
                "ads.example",
                "blocked",
                "external",
                "1",
                "1",
                "0",
                "",
            ],
        ]);
        let renamed = rename_ts_column(&t);
        let filtered = filter_by_iface(&renamed, None);
        let (scoped, hidden) = fold_by_scope(&filtered, Some(ConnectionScope::External));
        let folded = fold_by_iface(&scoped);

        assert_eq!(hidden, [1023, 4, 0], "internal/lan never reach the fold");
        assert_eq!(folded.columns, ["iface", "count", "upload", "download"]);
        let row = |iface: &str| {
            folded
                .rows
                .iter()
                .find(|r| r[0] == iface)
                .unwrap_or_else(|| panic!("no {iface} row in {folded:?}"))
                .clone()
        };
        assert_eq!(row("utun10"), vec!["utun10", "4", "104", "5006"]);
        assert_eq!(row("blocked"), vec!["blocked", "1", "1", "0"]);
        assert_eq!(folded.rows.len(), 2, "only the two external interfaces");
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
        let out = format_table(&table, true);
        for col in &table.columns {
            assert!(out.contains(col.as_str()), "header {col}: {out}");
        }
        assert!(
            out.contains("194.221.250.50") && out.contains("www.google.com"),
            "{out}"
        );
        assert!(out.contains("claude.ai"), "{out}");
        // Row order preserved: the first row's key precedes the second's.
        let first = out.find("194.221.250.50").expect("first row present");
        let second = out.find("claude.ai").expect("second row present");
        assert!(first < second, "{out}");

        let skipped = Table {
            columns: table.columns.clone(),
            rows: vec![["7", "SKIP", "", "", "", "", ""].map(String::from).to_vec()],
        };
        let out = format_table(&skipped, true);
        assert!(
            out.contains('7') && out.contains("SKIP"),
            "a SKIP tick's row must still print: {out}"
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

    /// The top-level `--help` command list carries one short line per
    /// subcommand — the long prose from each `///` doc must stay confined to
    /// that subcommand's own `--help`, never leak into the list a first-time
    /// reader scans.
    #[test]
    fn top_level_help_lists_one_short_line_per_subcommand() {
        let mut cmd = Cli::command();
        let help = cmd.render_help().to_string();
        // Every line clap lists under `Commands:`, not just `status`: a
        // re-joined doc comment (the blank `///` dropped) on ANY variant
        // would leak its long prose back into the list, so every line is
        // checked, not a hand-picked one.
        let commands_section: Vec<&str> = help
            .lines()
            .skip_while(|l| *l != "Commands:")
            .skip(1)
            .take_while(|l| !l.trim().is_empty())
            .collect();
        assert!(
            !commands_section.is_empty(),
            "no `Commands:` section found in the top-level help:\n{help}"
        );
        for line in &commands_section {
            assert!(
                line.len() < 100,
                "command-list line is {} chars, expected < 100 — a doc comment's \
                 blank separator was likely dropped, re-joining its prose into \
                 the summary: {line:?}",
                line.len()
            );
        }
        // Belt: two long-prose markers that must never survive into the
        // summary list even if some future variant's line sneaks under the
        // char cap. `HYPOTHESIS` (the caps row-marker in the long prose of
        // `vulns`/`topology`/`air`) is distinct from `vulns`' own short
        // line, which legitimately says "hypothesises" (lowercase verb) —
        // checking the caps form avoids a false positive there.
        assert!(
            !help.contains("HYPOTHESIS") && !help.contains("Asks the running daemon"),
            "long prose leaked into the top-level help:\n{help}"
        );
    }

    /// The scan/diag/daemon grouping (realm net-observer, node #164): the
    /// top-level help lists the three groups as single entries and no longer
    /// lists the renamed/moved commands flat — they still parse (hidden
    /// aliases), but do not clutter the list a first-time reader scans.
    #[test]
    fn top_level_help_shows_groups_not_legacy_flat_names() {
        let mut cmd = Cli::command();
        let help = cmd.render_help().to_string();
        let commands_section: Vec<&str> = help
            .lines()
            .skip_while(|l| *l != "Commands:")
            .skip(1)
            .take_while(|l| !l.trim().is_empty())
            .collect();
        let names: Vec<&str> = commands_section
            .iter()
            .map(|l| l.split_whitespace().next().unwrap_or(""))
            .collect();
        for group in ["scan", "diag", "daemon"] {
            assert!(
                names.contains(&group),
                "expected `{group}` listed as a top-level group, got: {names:?}"
            );
        }
        for legacy in [
            "scan-neighbors",
            "scan-topology",
            "why",
            "incident-context",
            "wedge-or-starvation",
            "gateway-ramp",
            "gaps",
            "kickstart",
            "observe",
            "probe",
            "experiment",
            "experiment-report",
        ] {
            assert!(
                !names.contains(&legacy),
                "`{legacy}` is a hidden alias and must not appear in the top-level list: {names:?}"
            );
        }
        // The frequently-used commands stay shallow, listed by name.
        for shallow in [
            "status",
            "events",
            "connections",
            "neighbors",
            "vulns",
            "check-cve",
            "topology",
            "air",
            "segments",
            "history",
            "query",
            "completions",
        ] {
            assert!(
                names.contains(&shallow),
                "expected shallow command `{shallow}` listed at top level, got: {names:?}"
            );
        }
    }

    /// The prose carved out of a subcommand's short line survives, unabridged,
    /// in that subcommand's own `--help` — carving the summary must not lose
    /// a fact, only relocate it.
    #[test]
    fn connections_long_help_keeps_the_fakeip_note() {
        let mut cmd = Cli::command();
        let sub = cmd
            .find_subcommand_mut("connections")
            .expect("`connections` is a subcommand");
        let long = sub.render_long_help().to_string();
        assert!(long.contains("fakeip"), "{long}");
    }

    /// `scan --help`/`diag --help`/`daemon --help` each list their own
    /// nested subcommands (realm net-observer, node #164).
    #[test]
    fn group_help_lists_its_nested_subcommands() {
        let mut cmd = Cli::command();
        let scan = cmd
            .find_subcommand_mut("scan")
            .expect("`scan` is a subcommand")
            .render_help()
            .to_string();
        assert!(scan.contains("neighbors"), "{scan}");
        assert!(scan.contains("topology"), "{scan}");

        let mut cmd = Cli::command();
        let diag = cmd
            .find_subcommand_mut("diag")
            .expect("`diag` is a subcommand")
            .render_help()
            .to_string();
        for name in ["why", "incident-context", "wedge", "gateway-ramp", "gaps"] {
            assert!(diag.contains(name), "missing `{name}` in:\n{diag}");
        }
        // The renamed `wedge` shows; the old `wedge-or-starvation` name does
        // not appear as a nested entry under `diag` (it lives only as a
        // hidden top-level alias).
        assert!(!diag.contains("wedge-or-starvation"), "{diag}");

        let mut cmd = Cli::command();
        let daemon = cmd
            .find_subcommand_mut("daemon")
            .expect("`daemon` is a subcommand")
            .render_help()
            .to_string();
        for name in [
            "kickstart",
            "observe",
            "probe",
            "experiment",
            "experiment-report",
        ] {
            assert!(daemon.contains(name), "missing `{name}` in:\n{daemon}");
        }
    }

    /// `completions zsh` prints a non-empty zsh completion script naming this
    /// binary — the file the nix package installs to
    /// `share/zsh/site-functions/_net-observer-cli`.
    #[test]
    fn completions_zsh_generates_a_named_script() {
        let mut out: Vec<u8> = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Zsh,
            &mut Cli::command(),
            "net-observer-cli",
            &mut out,
        );
        assert!(!out.is_empty());
        let script = String::from_utf8(out).expect("zsh completion script is UTF-8");
        assert!(script.contains("_net-observer-cli"), "{script}");
    }

    /// Same shape for bash, the second file the nix package installs.
    #[test]
    fn completions_bash_generates_a_named_script() {
        let mut out: Vec<u8> = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut Cli::command(),
            "net-observer-cli",
            &mut out,
        );
        assert!(!out.is_empty());
        let script = String::from_utf8(out).expect("bash completion script is UTF-8");
        assert!(script.contains("net-observer-cli"), "{script}");
    }

    /// Same shape for fish, the third file the nix package installs — a
    /// `postInstall` `>` redirect doesn't fail on empty output, so this is
    /// the guard against a clap_complete regression silently shipping a
    /// truncated fish script.
    #[test]
    fn completions_fish_generates_a_named_script() {
        let mut out: Vec<u8> = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Fish,
            &mut Cli::command(),
            "net-observer-cli",
            &mut out,
        );
        assert!(!out.is_empty());
        let script = String::from_utf8(out).expect("fish completion script is UTF-8");
        assert!(script.contains("complete -c net-observer-cli"), "{script}");
    }

    /// `clap_complete` does NOT honor `#[command(hide = true)]`: unlike
    /// `--help`'s `Commands:` list, the generated completion script still
    /// offers every hidden legacy alias alongside the new scan/diag/daemon
    /// groups — checked by exact token match on the root command's `opts=`
    /// line, not substring `contains`, since several of these names (`why`,
    /// `gaps`, `probe`) are short enough to false-positive inside another
    /// word. Pinned here so a future clap_complete upgrade that starts
    /// respecting `hide` is noticed rather than silently changing the
    /// discoverable completion surface (realm net-observer, node #164).
    #[test]
    fn completions_include_hidden_aliases_alongside_new_groups() {
        let mut out: Vec<u8> = Vec::new();
        clap_complete::generate(
            clap_complete::Shell::Bash,
            &mut Cli::command(),
            "net-observer-cli",
            &mut out,
        );
        let script = String::from_utf8(out).expect("bash completion script is UTF-8");
        let opts_line = script
            .lines()
            .find(|l| l.trim_start().starts_with("opts=") && l.contains("kickstart"))
            .unwrap_or_else(|| panic!("no root `opts=` line found in:\n{script}"));
        let tokens: std::collections::HashSet<&str> = opts_line
            .trim()
            .trim_start_matches("opts=\"")
            .trim_end_matches('"')
            .split_whitespace()
            .collect();
        // The new groups are offered.
        for group in ["scan", "diag", "daemon"] {
            assert!(tokens.contains(group), "missing `{group}` in: {opts_line}");
        }
        // Every hidden legacy alias still completes — clap_complete has no
        // notion of `hide` at all, so this is current reality, not a choice
        // this crate makes.
        for legacy in [
            "scan-neighbors",
            "scan-topology",
            "why",
            "incident-context",
            "wedge-or-starvation",
            "gateway-ramp",
            "gaps",
            "kickstart",
            "observe",
            "probe",
            "experiment",
            "experiment-report",
        ] {
            assert!(
                tokens.contains(legacy),
                "expected hidden alias `{legacy}` to still complete: {opts_line}"
            );
        }
    }

    /// `spinner_frame` cycles through the whole ten-glyph braille set and
    /// wraps back to the first frame rather than panicking or stalling on one
    /// glyph past the end of the array.
    #[test]
    fn spinner_frame_cycles_and_wraps() {
        let first_cycle: Vec<char> = (0..10u64).map(spinner_frame).collect();
        let second_cycle: Vec<char> = (10..20u64).map(spinner_frame).collect();
        assert_eq!(first_cycle, second_cycle, "tick 10..20 should repeat 0..10");
        assert_eq!(
            first_cycle.len(),
            first_cycle
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            "all ten frames should be distinct: {first_cycle:?}"
        );
        assert_eq!(spinner_frame(0), spinner_frame(10));
    }

    /// `format_elapsed` renders `M:SS`, zero-padding seconds under ten and
    /// rolling minutes over without a limit.
    #[test]
    fn format_elapsed_renders_minutes_and_seconds() {
        assert_eq!(format_elapsed(Duration::from_secs(0)), "0:00");
        assert_eq!(format_elapsed(Duration::from_secs(5)), "0:05");
        assert_eq!(format_elapsed(Duration::from_secs(65)), "1:05");
        assert_eq!(format_elapsed(Duration::from_secs(600)), "10:00");
        assert_eq!(format_elapsed(Duration::from_secs(3661)), "61:01");
    }

    /// A scan's read timeout (the client gave up after `SCAN_TIMEOUT`, not the
    /// daemon reporting a failure) gets the "still running, read it later"
    /// message — never the raw errno line `socket_error` would produce for the
    /// exact same `WouldBlock`/`TimedOut` kind.
    #[test]
    fn scan_socket_error_reports_a_timeout_as_still_running() {
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            let e = std::io::Error::new(kind, "timed out");
            let msg = scan_socket_error("/tmp/observer.sock", &e).to_string();
            assert!(msg.contains("vulns"), "{kind:?}: {msg}");
            assert!(
                !msg.contains("Resource temporarily unavailable"),
                "{kind:?}: {msg}"
            );
        }
    }

    /// An absent/refused socket still reads as "not running", the same as
    /// every other fetcher.
    #[test]
    fn scan_socket_error_reports_an_absent_daemon_as_not_running() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            let e = std::io::Error::new(kind, "gone");
            let msg = scan_socket_error("/tmp/observer.sock", &e).to_string();
            assert!(msg.contains("not running"), "{kind:?}: {msg}");
        }
    }

    /// Any other transport error keeps the generic `socket_error` wording.
    #[test]
    fn scan_socket_error_reports_other_errors_generically() {
        let e = std::io::Error::other("boom");
        let msg = scan_socket_error("/tmp/observer.sock", &e).to_string();
        assert!(
            msg.contains("failed to query net-observerd over socket"),
            "{msg}"
        );
        assert!(msg.contains("boom"), "{msg}");
    }

    /// Every rung actually in `opts` is named, plus the caveat each of
    /// `--cve`/`--slow` earns, plus the Ctrl-C/read-later tail every scan
    /// gets. Substrings, not the exact line — so a wording tweak doesn't
    /// over-couple this test to `scan_starting_line`'s phrasing.
    #[test]
    fn scan_starting_line_names_every_rung_and_caveat() {
        let opts = ScanOptions {
            ports: true,
            banners: true,
            cve: true,
            target: None,
            slow: true,
            sweep_max: None,
        };
        let line = scan_starting_line(&opts);
        assert!(line.contains("ports"), "{line}");
        assert!(line.contains("banners"), "{line}");
        assert!(line.contains("cve"), "{line}");
        assert!(line.contains("slow"), "{line}");
        assert!(
            line.contains("--cve") && line.contains("first time"),
            "{line}"
        );
        assert!(line.contains("--slow") && line.contains("paces"), "{line}");
        assert!(
            line.contains("Ctrl-C") && line.contains("vulns") && line.contains("neighbors"),
            "{line}"
        );
    }

    /// A plain scan (no rungs) degrades to the short form: no rung list, no
    /// `--cve`/`--slow` caveats, but still the same Ctrl-C/read-later tail.
    #[test]
    fn scan_starting_line_plain_scan_has_no_rungs_or_caveats() {
        let line = scan_starting_line(&ScanOptions::default());
        assert!(!line.contains('('), "{line}");
        assert!(!line.contains("--cve"), "{line}");
        assert!(!line.contains("--slow"), "{line}");
        assert!(
            line.contains("Ctrl-C") && line.contains("vulns") && line.contains("neighbors"),
            "{line}"
        );
    }
}
