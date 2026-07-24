//! `observer-cli` — an unprivileged reader for the observer DuckDB store.
//!
//! The root daemon (`observerd`) writes samples, incidents and trigger rows;
//! this CLI only reads them. Three subcommands cover day-to-day forensics:
//! `status` (row counts + last tick), `incidents` (open/closed list) and
//! `query` (arbitrary read-only SQL rendered as a table).

use anyhow::Result;
use clap::{Parser, Subcommand};
use store::{DuckdbStore, QueryTable, Store};

#[derive(Parser)]
#[command(name = "observer-cli", about = "Query the observer DuckDB store")]
struct Cli {
    /// Path to the observer DuckDB database file.
    #[arg(long, default_value = "/var/lib/observer/observer.duckdb")]
    db: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show row counts per table and the last sample timestamp.
    Status,
    /// List incidents (open and closed), newest first.
    Incidents,
    /// Run an arbitrary SQL query and print the resulting rows.
    Query {
        /// The SQL statement to run against the store.
        sql: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let store = DuckdbStore::open(&cli.db)?;
    match cli.command {
        Command::Status => print!("{}", format_status(&store)?),
        Command::Incidents => print!("{}", format_incidents(&store.list_incidents()?)),
        Command::Query { sql } => print!("{}", format_table(&store.query_table(&sql)?)),
    }
    Ok(())
}

/// Render `(trigger_id, opened_us, closed_us)` incident rows as a fixed-width
/// table. An open incident (no `closed_us`) shows `open`.
fn format_incidents(rows: &[(String, i64, Option<i64>)]) -> String {
    let mut out = format!(
        "{:<24} {:>18} {:>18}\n",
        "TRIGGER", "OPENED_US", "CLOSED_US"
    );
    for (trigger_id, opened_us, closed_us) in rows {
        let closed = match closed_us {
            Some(c) => c.to_string(),
            None => "open".to_string(),
        };
        out.push_str(&format!("{trigger_id:<24} {opened_us:>18} {closed:>18}\n"));
    }
    out
}

/// Summarise store contents: per-table row counts and the newest sample tick.
fn format_status(store: &DuckdbStore) -> Result<String> {
    let link = store.query_scalar_i64("SELECT count(*) FROM link_sample")?;
    let proxy = store.query_scalar_i64("SELECT count(*) FROM proxy_sample")?;
    let incidents = store.query_scalar_i64("SELECT count(*) FROM incident")?;
    let open = store.query_scalar_i64("SELECT count(*) FROM incident WHERE closed_us IS NULL")?;
    let triggers = store.query_scalar_i64("SELECT count(*) FROM trigger_fired")?;
    let blobs = store.query_scalar_i64("SELECT count(*) FROM blob_ref")?;
    let last_tick = store.query_scalar_i64(
        "SELECT COALESCE(max(ts_us), 0) FROM \
         (SELECT ts_us FROM link_sample UNION ALL SELECT ts_us FROM proxy_sample)",
    )?;
    let mut out = String::new();
    out.push_str(&format!("link_sample    {link}\n"));
    out.push_str(&format!("proxy_sample   {proxy}\n"));
    out.push_str(&format!("incident       {incidents} ({open} open)\n"));
    out.push_str(&format!("trigger_fired  {triggers}\n"));
    out.push_str(&format!("blob_ref       {blobs}\n"));
    out.push_str(&format!("last_tick_us   {last_tick}\n"));
    Ok(out)
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
    #[test]
    fn format_incidents_renders_rows() {
        let out = format_incidents(&[("gw-drop".into(), 1000i64, Some(2000i64))]);
        assert!(out.contains("gw-drop") && out.contains("1000"));
    }

    #[test]
    fn format_incidents_marks_open_incidents() {
        let out = format_incidents(&[("wedge".into(), 5000i64, None)]);
        assert!(out.contains("wedge") && out.contains("open"));
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
}
