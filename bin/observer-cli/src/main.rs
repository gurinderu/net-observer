//! `observer-cli` — an unprivileged reader for the observer store.
//!
//! `observerd` is the **sole owner** of the DuckDB file: DuckDB takes a
//! per-process file lock, so a second opener (even read-only) is blocked while
//! the daemon runs. This CLI therefore splits into two access paths:
//!
//! - **LIVE** — `status` and `incidents` read the daemon's in-memory snapshot
//!   over its Unix-domain socket (`observer-ipc`). No DB is opened, so there is
//!   zero contention with the running daemon.
//! - **OFFLINE** — `query <SQL>` opens the DuckDB file directly for ad-hoc
//!   forensics. This only works while the daemon is stopped; if `observerd` is
//!   running it holds the lock and the open fails with a clear message rather
//!   than a panic.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use config::Config;
use observer_ipc::{
    ControlCmd, ControlResult, Event, EventKind, IncidentSummary, Request, Response, StatusSnapshot,
};
use std::io::Write;
use std::process::ExitCode;
use store::{DuckdbStore, QueryTable};

#[derive(Parser)]
#[command(
    name = "observer-cli",
    about = "Query the observer store (live via socket, offline via SQL)"
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
    /// Tail the daemon's live event stream, printing each event
    /// (`HH:MM:SS  kind  detail`) as it happens until interrupted (Ctrl-C).
    ///
    /// This is **pub/sub, not polling**: the CLI opens ONE `Subscribe`
    /// connection over the socket and the daemon *pushes* every event down it
    /// (samples as they are collected, incidents as triggers fire). With
    /// `--kind` the daemon filters the stream server-side to that single kind;
    /// without it, every kind is streamed. Graceful if the daemon is down or the
    /// stream drops mid-tail; never panics.
    Events {
        /// Restrict the stream to a single event kind. Omit for all kinds.
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
    /// forensics — only works while `observerd` is stopped).
    Query {
        /// The SQL statement to run against the store.
        sql: String,
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

/// The event kind accepted by `events --kind`. A thin CLI mirror of
/// [`EventKind`] so `clap` renders `<link|proxy|dns|route|host|incident>` in the
/// help without leaking the wire type into the argument surface.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum EventKindArg {
    Link,
    Proxy,
    Dns,
    Route,
    Host,
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
            // server-side to that single kind.
            let kinds = kind.map(|k| vec![k.to_kind()]);
            stream_events(&cfg.socket_path, kinds)?;
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
    }
    Ok(ExitCode::SUCCESS)
}

/// Load the daemon config (defaults + optional TOML file + `OBSERVER_*` env),
/// mapping the large `figment::Error` into a clear `anyhow` message.
fn load_config(cli: &Cli) -> Result<Config> {
    Config::load(cli.config.as_deref()).map_err(|e| anyhow!("failed to load observer config: {e}"))
}

/// Send one request to the daemon over the socket. An absent / refused socket
/// (`observerd` not running) becomes a clear message, never a panic.
fn daemon_query(socket_path: &str, req: &Request) -> Result<Response> {
    observer_ipc::query(socket_path, req).map_err(|e| {
        use std::io::ErrorKind::{ConnectionRefused, NotFound};
        if matches!(e.kind(), NotFound | ConnectionRefused) {
            anyhow!("observerd not running (socket {socket_path} unavailable)")
        } else {
            anyhow!("failed to query observerd over socket {socket_path}: {e}")
        }
    })
}

/// Fetch the live [`StatusSnapshot`] from the daemon.
fn fetch_status(socket_path: &str) -> Result<StatusSnapshot> {
    match daemon_query(socket_path, &Request::Status)? {
        Response::Status(snap) => Ok(snap),
        Response::Error(e) => Err(anyhow!("observerd returned an error: {e}")),
        other => Err(anyhow!("unexpected daemon response to Status: {other:?}")),
    }
}

/// Fetch the newest `limit` incidents from the daemon.
fn fetch_incidents(socket_path: &str, limit: usize) -> Result<Vec<IncidentSummary>> {
    match daemon_query(socket_path, &Request::Incidents { limit })? {
        Response::Incidents(list) => Ok(list),
        Response::Error(e) => Err(anyhow!("observerd returned an error: {e}")),
        other => Err(anyhow!(
            "unexpected daemon response to Incidents: {other:?}"
        )),
    }
}

/// Open ONE live event subscription over the socket and print each pushed event
/// as it arrives (`HH:MM:SS  kind  detail`) until interrupted (Ctrl-C) or the
/// daemon closes the stream. This is the pub/sub tail: the daemon *pushes* frames
/// down a held-open connection; the CLI never polls. `kinds` filters server-side
/// (`None` = every kind).
///
/// Never panics:
/// - an absent / connection-refused socket (daemon down) becomes a clear `Err`
///   (a non-zero exit), like the one-shot commands;
/// - a mid-stream read/decode error (daemon restart/shutdown) prints a note and
///   ends the tail cleanly;
/// - a broken output pipe (e.g. `| head`) also ends the tail cleanly, rather than
///   panicking the way `println!` would on a write failure.
fn stream_events(socket_path: &str, kinds: Option<Vec<EventKind>>) -> Result<()> {
    let sub = observer_ipc::subscribe(socket_path, &Request::Subscribe { kinds }).map_err(|e| {
        use std::io::ErrorKind::{ConnectionRefused, NotFound};
        if matches!(e.kind(), NotFound | ConnectionRefused) {
            anyhow!("observerd not running (socket {socket_path} unavailable)")
        } else {
            anyhow!("failed to subscribe to observerd over socket {socket_path}: {e}")
        }
    })?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for item in sub {
        match item {
            Ok(ev) => {
                // `writeln!` (not `println!`) so a broken pipe ends the tail
                // instead of panicking; stdout is line-buffered so each line
                // flushes on its newline, keeping the tail live.
                if writeln!(out, "{}", format_event_line(&ev)).is_err() {
                    break;
                }
            }
            // The daemon went away mid-stream (restart / shutdown) or a frame
            // failed to decode. Note it and stop — the tail is over.
            Err(e) => {
                eprintln!("event stream ended: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// One printed line for a live event: `HH:MM:SS  kind  detail`. Pure over its
/// input (the clock is derived arithmetically) so it is unit-tested directly.
fn format_event_line(ev: &Event) -> String {
    format!(
        "{}  {}  {}",
        clock(ev.ts_us()),
        kind_label(ev.kind()),
        event_detail(ev)
    )
}

/// The short lowercase label for an [`EventKind`] (matches the `--kind` values).
fn kind_label(kind: EventKind) -> &'static str {
    match kind {
        EventKind::Link => "link",
        EventKind::Proxy => "proxy",
        EventKind::Dns => "dns",
        EventKind::Route => "route",
        EventKind::Host => "host",
        EventKind::Incident => "incident",
    }
}

/// The per-variant one-line detail for an event.
fn event_detail(ev: &Event) -> String {
    match ev {
        Event::Link(l) => format!("gw={} direct={}", l.gw, l.direct),
        Event::Proxy(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
            format!("tun={tun} sel={sel}")
        }
        Event::Dns(d) => {
            let ip = d.ip.clone().unwrap_or_else(|| "-".to_string());
            format!("{}/{} {} {}", d.probe, d.server, d.verdict, ip)
        }
        Event::Route(r) => {
            let iface = r.iface.clone().unwrap_or_else(|| "-".to_string());
            format!("{} {} {}", r.kind, iface, r.detail)
        }
        Event::Host(h) => format!("load {:.2}/{:.2}/{:.2}", h.load1, h.load5, h.load15),
        Event::Incident(i) => format!("{} {}", i.trigger_id, i.signature),
    }
}

/// Format an epoch-microsecond timestamp as a `HH:MM:SS` wall clock in **UTC**.
///
/// `observer-cli` does not depend on a timezone crate (only the gpui bar does, via
/// `jiff`), so this uses pure integer math over `ts_us` — deterministic, never
/// panics (Euclidean division handles any `i64`, including negatives).
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
        Response::Error(e) => Err(anyhow!("observerd returned an error: {e}")),
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
        Response::Error(e) => Err(anyhow!("observerd returned an error: {e}")),
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
/// `observerd` is running it holds the per-process DuckDB lock, so the open
/// fails — detect that and print a clear, actionable message instead of leaking
/// the raw driver error (and never panic).
fn run_query(db_path: &str, sql: &str) -> Result<QueryTable> {
    let store = DuckdbStore::open(db_path).map_err(|e| {
        let msg = e.to_string();
        if is_lock_error(&msg) {
            anyhow!(
                "observerd is running and holds the DuckDB lock; stop it for \
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

/// Heuristic over a DuckDB open error: does it indicate the file is locked by
/// another process (i.e. the daemon)? DuckDB reports this as an `IO Error`
/// mentioning a lock, e.g. `Could not set lock on file ...: Conflicting lock is
/// held`.
fn is_lock_error(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("lock")
}

/// Summarise the live [`StatusSnapshot`]: the latest sample per collector plus an
/// incident count. Pure over its input so it is unit-tested without a socket.
fn format_status(snap: &StatusSnapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!("generated_us   {}\n", snap.generated_us));

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
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
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
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, LinkSample, ProxySample, RouteEvent,
        TcpVerdict,
    };

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

    #[test]
    fn format_status_renders_snapshot() {
        let snap = StatusSnapshot {
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
            incidents: vec![
                incident("i1", "wedge", 80, None),
                incident("i2", "gw-drop", 60, Some(70)),
            ],
            observing: true,
        };
        let out = format_status(&snap);
        assert!(out.contains("generated_us   100"));
        assert!(out.contains("link           gw=OK direct=OK ts_us=42"));
        assert!(out.contains("proxy          tun=204 selector=auto ts_us=43"));
        assert!(out.contains("dns            (no data)"));
        assert!(out.contains("host           (no data)"));
        // Two incidents, one still open.
        assert!(out.contains("incidents      2 (1 open)"));
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
             Conflicting lock is held in /usr/bin/observerd (PID 4242)";
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
    fn format_event_line_renders_ts_kind_detail() {
        let link = Event::Link(LinkSample {
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
        });
        assert_eq!(
            format_event_line(&link),
            "01:01:01  link  gw=OK direct=FAIL"
        );
    }

    #[test]
    fn format_event_line_renders_incident() {
        let inc = Event::Incident(IncidentSummary {
            id: "i1".into(),
            opened_us: 0,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        });
        assert_eq!(
            format_event_line(&inc),
            "00:00:00  incident  wedge tun dead"
        );
    }

    #[test]
    fn event_detail_covers_each_variant() {
        let proxy = Event::Proxy(ProxySample {
            ts_us: 0,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: Some("auto".into()),
        });
        assert_eq!(event_detail(&proxy), "tun=204 sel=auto");

        // Missing tun_code / selector fall back to a placeholder dash.
        let proxy_bare = Event::Proxy(ProxySample {
            ts_us: 0,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code: None,
            selector: None,
        });
        assert_eq!(event_detail(&proxy_bare), "tun=- sel=-");

        let dns = Event::Dns(DnsSample {
            ts_us: 0,
            probe: "nks".into(),
            server: "sb".into(),
            verdict: DnsVerdict::FakeIp,
            ip: Some("198.18.0.1".into()),
            rtt_ms: None,
        });
        assert_eq!(event_detail(&dns), "nks/sb FAKEIP 198.18.0.1");

        let route = Event::Route(RouteEvent {
            ts_us: 0,
            kind: "iface".into(),
            iface: Some("en0".into()),
            detail: "up".into(),
        });
        assert_eq!(event_detail(&route), "iface en0 up");

        let host = Event::Host(HostSample {
            ts_us: 0,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
        });
        assert_eq!(event_detail(&host), "load 1.00/2.00/3.00");
    }
}
