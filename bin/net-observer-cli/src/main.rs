//! `net-observer-cli` — an unprivileged reader for the observer store.
//!
//! `net-observerd` is the **sole owner** of the DuckDB file: DuckDB takes a
//! per-process file lock, so a second opener (even read-only) is blocked while
//! the daemon runs. This CLI therefore splits into two access paths:
//!
//! - **LIVE** — `status` and `incidents` read the daemon's in-memory snapshot
//!   over its Unix-domain socket (`net-observer-ipc`). No DB is opened, so there is
//!   zero contention with the running daemon.
//! - **OFFLINE** — `query <SQL>` opens the DuckDB file directly for ad-hoc
//!   forensics, and the `diagnose` commands (`why`, `incident-context`,
//!   `wedge-or-starvation`, `gateway-ramp`, `gaps`) run the canned
//!   `store::diagnosis` queries over the same path, so "which layer failed" is
//!   reachable without writing SQL. This only works while the daemon is stopped;
//!   if `net-observerd` is running it holds the lock and the open fails with a
//!   clear message rather than a panic.

mod diagnose;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use config::Config;
use net_observer_ipc::{
    ControlCmd, ControlResult, EventKind, IncidentSummary, Request, Response, StatusSnapshot,
    StreamFrame,
};
use std::io::Write;
use std::process::ExitCode;
use store::{DuckdbStore, QueryTable, diagnosis};

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
    /// socket path for the live `status`/`incidents` commands.
    #[arg(long)]
    config: Option<String>,
    /// Path to the observer DuckDB file, used only by the offline `query`
    /// command (requires the daemon to be stopped — it holds the DB lock).
    #[arg(long, default_value = "/var/lib/observer/observer.duckdb")]
    db: String,
    #[command(subcommand)]
    command: Command,
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
    /// the socket. The daemon runs it as root **only** when `acting.enabled` is
    /// set in its config; otherwise it refuses the request without acting. Exits
    /// non-zero if the action was refused/failed or the daemon is unreachable.
    Kickstart,
    /// Turn the observer's own collection on or off (pause/resume), sent as a
    /// `Control(SetObserving)` request over the socket. This controls the
    /// daemon's OWN observation only — it does **not** touch sing-box or the
    /// network, and is **not** gated by `acting.enabled` (benign self-control).
    /// The daemon stays alive and the socket keeps serving while paused, so the
    /// switch can be turned back on. Exits non-zero if the request failed or the
    /// daemon is unreachable.
    Observe {
        /// `on` resumes collection; `off` pauses it.
        #[arg(value_enum)]
        state: ObserveState,
    },
    /// Run an arbitrary SQL query directly against the DuckDB file (offline
    /// forensics — only works while `net-observerd` is stopped).
    Query {
        /// The SQL statement to run against the store.
        sql: String,
    },
    /// Which layer failed at a moment: the state of link, proxy server, tun and
    /// host load as the record has it, plus the layer it blames (offline).
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
    /// Every incident with the layer state just before it opened (offline).
    ///
    /// An incident that opened inside an observation gap gets no context: the
    /// state from before the pause is not context for it, and is marked withheld.
    IncidentContext,
    /// The wedge-vs-starvation verdict over each recent `tun=000` episode
    /// (offline) — the discriminator that decides whether a restart is the cure.
    ///
    /// An episode the record cannot classify is reported `unknown`, not guessed.
    WedgeOrStarvation,
    /// The gateway RTT series before a drop, with its least-squares slope, so a
    /// coworking-gateway ramp is visible as data (offline).
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
    /// deliberately collected nothing for, and what closed each (offline).
    Gaps,
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

/// The event kind accepted by `events --kind`. A thin CLI mirror of
/// [`EventKind`] so `clap` renders `<link|proxy|dns|route|host|wifi|neighbors|incident>` in the
/// help without leaking the wire type into the argument surface.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum EventKindArg {
    Link,
    Proxy,
    Dns,
    Route,
    Host,
    Wifi,
    Neighbors,
    Incident,
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
            EventKindArg::Incident => EventKind::Incident,
        }
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
            // server-side to that single kind. Either way the stream-integrity
            // frames (ack, gap, observing) are delivered.
            let kinds = kind.map(|k| vec![k.to_kind()]);
            // The tail owns its own exit code: an orderly end is a success even
            // though the stream stopped (see [`TailEnd`]).
            return stream_events(&cfg.socket_path, kinds);
        }
        Command::Kickstart => {
            let cfg = load_config(cli)?;
            let result = fetch_kickstart(&cfg.socket_path)?;
            print!("{}", format_control(&result));
            // A refusal (acting disabled) or a failed action is a non-zero exit,
            // even though the request itself round-tripped fine.
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
        Command::Query { sql } => {
            let table = run_query(&cli.db, sql)?;
            print!("{}", format_table(&table));
        }
        Command::Why { at } => {
            let ts_us = diagnose::parse_at(at)?;
            let table = run_query(&cli.db, &diagnosis::verdict_at_sql(ts_us, LOAD_THRESHOLD))?;
            print!("{}", diagnose::format_verdict_at(&table, ts_us)?);
        }
        Command::IncidentContext => {
            let table = run_query(&cli.db, &diagnosis::incident_context_sql(LOAD_THRESHOLD))?;
            print!("{}", diagnose::format_incident_context(&table)?);
        }
        Command::WedgeOrStarvation => {
            let sql = diagnosis::wedge_vs_starvation_sql(
                LOAD_THRESHOLD,
                diagnosis::DEFAULT_EPISODE_GAP_US,
            );
            let table = run_query(&cli.db, &sql)?;
            print!("{}", diagnose::format_wedge_vs_starvation(&table)?);
        }
        Command::GatewayRamp { drop, window_us } => {
            let drop_ts_us = match drop {
                Some(d) => diagnose::parse_at(d)?,
                None => latest_gw_drop(&cli.db)?,
            };
            let table = run_query(
                &cli.db,
                &diagnosis::gateway_ramp_sql(drop_ts_us, *window_us),
            )?;
            print!(
                "{}",
                diagnose::format_gateway_ramp(&table, drop_ts_us, *window_us)?
            );
        }
        Command::Gaps => {
            let table = run_query(&cli.db, &diagnosis::observation_gaps_sql())?;
            print!("{}", diagnose::format_observation_gaps(&table)?);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Load the daemon config (defaults + optional TOML file + `NET_OBSERVER_*` env),
/// mapping the large `figment::Error` into a clear `anyhow` message.
fn load_config(cli: &Cli) -> Result<Config> {
    Config::load(cli.config.as_deref()).map_err(|e| anyhow!("failed to load observer config: {e}"))
}

/// Send one request to the daemon over the socket. An absent / refused socket
/// (`net-observerd` not running) becomes a clear message, never a panic.
fn daemon_query(socket_path: &str, req: &Request) -> Result<Response> {
    net_observer_ipc::query(socket_path, req).map_err(|e| {
        use std::io::ErrorKind::{ConnectionRefused, NotFound};
        if matches!(e.kind(), NotFound | ConnectionRefused) {
            anyhow!("net-observerd not running (socket {socket_path} unavailable)")
        } else {
            anyhow!("failed to query net-observerd over socket {socket_path}: {e}")
        }
    })
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
        use std::io::ErrorKind::{ConnectionRefused, NotFound};
        if matches!(e.kind(), NotFound | ConnectionRefused) {
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

/// One printed line for a stream frame: `HH:MM:SS  label  detail`, with the clock
/// in **UTC** (see [`clock`]; the gpui bar renders the same frames in local time).
/// The label and detail come from `net-observer-ipc` so the CLI tail and the bar spell
/// every frame identically. Pure over its input (the clock is derived
/// arithmetically) so it is unit-tested directly.
fn format_frame_line(f: &StreamFrame) -> String {
    format!("{}  {}  {}", clock(f.ts_us()), f.label(), f.detail())
}

/// Format an epoch-microsecond timestamp as a `HH:MM:SS` wall clock in **UTC**.
///
/// The tail deliberately stays on pure integer math over `ts_us` — deterministic
/// and never panicking (Euclidean division handles any `i64`, including
/// negatives) — so a streaming clock cannot depend on tz-database lookups. Local
/// time is used only where a human types one, in the offline `diagnose`
/// commands (see [`diagnose`], which resolves `--at` via `jiff`).
fn clock(ts_us: i64) -> String {
    let secs = ts_us.div_euclid(1_000_000);
    let tod = secs.rem_euclid(86_400); // seconds within the UTC day
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{h:02}:{m:02}:{s:02}")
}

/// Ask the daemon to restart the sing-box proxy over the socket
/// (`Control(KickstartProxy)`) and return its [`ControlResult`]. A daemon-down /
/// absent socket becomes a clear `Err` (handled by [`daemon_query`]); the daemon
/// itself decides whether to act (gated by `acting.enabled`) and reports the
/// outcome in the result. Never panics.
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
/// sing-box or the network and is not gated by `acting.enabled`. A daemon-down /
/// absent socket becomes a clear `Err` (handled by [`daemon_query`]). Never
/// panics.
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

/// Render a [`ControlResult`] as a single status line: `ok: <message>` when the
/// action ran, `failed: <message>` when it was refused (acting disabled) or the
/// action itself failed. Pure over its input so it is unit-tested directly.
fn format_control(result: &ControlResult) -> String {
    let tag = if result.ok { "ok" } else { "failed" };
    format!("{tag}: {}\n", result.message)
}

/// Open the DuckDB file directly and run one query (offline forensics). If
/// `net-observerd` is running it holds the per-process DuckDB lock, so the open
/// fails — detect that and print a clear, actionable message instead of leaking
/// the raw driver error (and never panic).
fn run_query(db_path: &str, sql: &str) -> Result<QueryTable> {
    let store = DuckdbStore::open(db_path).map_err(|e| {
        let msg = e.to_string();
        if is_lock_error(&msg) {
            anyhow!(
                "net-observerd is running and holds the DuckDB lock; stop it for \
                 offline SQL, or use `status`/`incidents` (live via socket)"
            )
        } else {
            anyhow!("failed to open DuckDB at {db_path}: {msg}")
        }
    })?;
    store
        .query_table(sql)
        .map_err(|e| anyhow!("query failed: {e}"))
}

/// The `ts_us` of the newest gateway drop in the record, used when
/// `gateway-ramp` is invoked without `--drop`. An empty record is an error
/// naming the flag rather than a ramp plotted around an arbitrary instant.
fn latest_gw_drop(db_path: &str) -> Result<i64> {
    let table = run_query(db_path, diagnosis::GW_DROPS_SQL)?;
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
    out.push_str(&format!("generated_us   {}\n", snap.generated_us));

    // While paused the daemon skips the probes entirely, so the samples below are
    // frozen at whatever they were when collection stopped — say so rather than
    // printing stale verdicts as if they were live.
    out.push_str(if snap.observing {
        "observing      on\n"
    } else {
        "observing      off (paused - samples below are stale)\n"
    });

    match &snap.link {
        Some(l) => out.push_str(&format!(
            "link           gw={} direct={} ts_us={}\n",
            l.gw, l.direct, l.ts_us
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
            out.push_str(&format!(
                "proxy          tun={tun} selector={sel} ts_us={}\n",
                p.ts_us
            ));
        }
        None => out.push_str("proxy          (no data)\n"),
    }

    match &snap.dns {
        Some(d) => out.push_str(&format!(
            "dns            {} {}/{} ts_us={}\n",
            d.verdict, d.probe, d.server, d.ts_us
        )),
        None => out.push_str("dns            (no data)\n"),
    }

    match &snap.host {
        Some(h) => out.push_str(&format!(
            "host           load1={} load5={} load15={} ts_us={}\n",
            h.load1, h.load5, h.load15, h.ts_us
        )),
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
    let mut out = format!(
        "{:<20} {:<16} {:>18} {:>18}\n",
        "ID", "TRIGGER", "OPENED_US", "CLOSED_US"
    );
    for i in rows {
        let closed = match i.closed_us {
            Some(c) => c.to_string(),
            None => "open".to_string(),
        };
        out.push_str(&format!(
            "{:<20} {:<16} {:>18} {closed:>18}\n",
            i.id, i.trigger_id, i.opened_us
        ));
    }
    out
}

/// Render a generic query result as a simple space-padded table.
fn format_table(table: &QueryTable) -> String {
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
                wifi_capture_present: false,
            }),
            proxy: Some(ProxySample {
                ts_us: 43,
                server_ip: "1.2.3.4".into(),
                tcp: TcpVerdict::Ok,
                rtt_ms: None,
                tun_code: Some(204),
                selector: Some("auto".into()),
            }),
            dns: None,
            host: None,
            wifi: None,
            neighbors: None,
            incidents: vec![
                incident("i1", "wedge", 80, None),
                incident("i2", "gw-drop", 60, Some(70)),
            ],
            observing,
            quiet: false,
        }
    }

    #[test]
    fn format_status_renders_snapshot() {
        let out = format_status(&snapshot(true));
        assert!(out.contains("generated_us   100"));
        assert!(out.contains("observing      on"));
        assert!(out.contains("link           gw=OK direct=OK ts_us=42"));
        assert!(out.contains("proxy          tun=204 selector=auto ts_us=43"));
        assert!(out.contains("dns            (no data)"));
        assert!(out.contains("host           (no data)"));
        // Two incidents, one still open.
        assert!(out.contains("incidents      2 (1 open)"));
    }

    #[test]
    fn format_status_marks_paused_snapshot_as_stale() {
        // Paused: the daemon skips the probes, so the samples are frozen — the
        // line must say so instead of letting them read as live.
        let out = format_status(&snapshot(false));
        assert!(out.contains("observing      off (paused - samples below are stale)"));
        assert!(!out.contains("observing      on"));
        // The rest of the snapshot still renders.
        assert!(out.contains("link           gw=OK direct=OK ts_us=42"));
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
        let table = QueryTable {
            columns: vec!["ts_us".into(), "gw".into()],
            rows: vec![vec!["42".into(), "OK".into()]],
        };
        let out = format_table(&table);
        assert!(out.contains("ts_us") && out.contains("gw"));
        assert!(out.contains("42") && out.contains("OK"));
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
        // The daemon refuses when acting is disabled (the safe default).
        let out = format_control(&ControlResult {
            ok: false,
            message: "acting disabled".into(),
        });
        assert_eq!(out, "failed: acting disabled\n");
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
        assert_eq!(EventKindArg::Incident.to_kind(), EventKind::Incident);
    }

    #[test]
    fn clock_formats_utc_hh_mm_ss() {
        // Epoch 0 is 00:00:00 UTC; 1h1m1s later reads 01:01:01.
        assert_eq!(clock(0), "00:00:00");
        assert_eq!(clock(3_661_000_000), "01:01:01");
        // A negative timestamp must not panic (Euclidean wrap into the day).
        assert_eq!(clock(-1), "23:59:59");
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
            wifi_capture_present: false,
        }));
        assert_eq!(
            format_frame_line(&link),
            "01:01:01  link  gw=OK direct=FAIL"
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
            "00:00:00  incident  wedge tun dead"
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
            "00:00:00  gap  12 events dropped (subscriber lagged)"
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
        });
        assert_eq!(
            format_frame_line(&ready),
            "00:00:00  subscribed  collection off; kinds: all"
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
            "00:00:00  observing  collection off"
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
            "00:00:00  error  too-many-subscribers: subscriber limit reached \
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
