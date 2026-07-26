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
use clap::{Parser, Subcommand};
use config::Config;
use observer_ipc::{ControlCmd, ControlResult, IncidentSummary, Request, Response, StatusSnapshot};
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
    /// Ask the running daemon to restart the sing-box proxy service
    /// (`launchctl kickstart`), sent as a `Control(KickstartProxy)` request over
    /// the socket. The daemon runs it as root **only** when `acting.enabled` is
    /// set in its config; otherwise it refuses the request without acting. Exits
    /// non-zero if the action was refused/failed or the daemon is unreachable.
    Kickstart,
    /// Run an arbitrary SQL query directly against the DuckDB file (offline
    /// forensics — only works while `observerd` is stopped).
    Query {
        /// The SQL statement to run against the store.
        sql: String,
    },
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
    use types::{GwVerdict, LinkSample, ProxySample, TcpVerdict};

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
}
