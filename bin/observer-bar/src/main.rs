//! `observer-bar` — a read-only glance at the observer DuckDB store: the latest
//! link tick (gw/direct), the latest proxy tick (tun_code/selector), and the
//! most recent incidents.
//!
//! The load-bearing, unit-tested part is the [`status`] data layer
//! ([`Status`](crate::status::Status) + `read_status` + `render_status`), which
//! reads through the [`QuerySource`](crate::status::QuerySource) trait. In
//! production that trait is backed by [`db::ReadOnlyDb`], a DuckDB connection
//! opened with `access_mode=read_only`: it runs no DDL and does not take
//! DuckDB's single read-write slot, so the glance is safe to run while
//! `observerd` holds the store open for writing.
//!
//! Today this is a headless glance that prints the `Status`.
//!
//! TODO(menu-bar): the intended UI is a macOS **menu-bar** app (LSUIElement, no
//! dock icon): an `NSStatusItem` (via `objc2`) whose click opens a gpui panel
//! showing that `Status`. gpui's build script needs the macOS Metal Toolchain
//! (absent on this build host / CI), and `NSStatusItem` + gpui-panel integration
//! is non-standard and cannot be verified in a headless pass, so the GUI is left
//! for a follow-up on a machine with the Metal Toolchain installed
//! (`xcodebuild -downloadComponent MetalToolchain`). The gpui/objc2 workspace
//! deps are already declared for that work; re-add them to this crate then.

mod db;
mod status;

use anyhow::Result;
use config::Config;
use db::ReadOnlyDb;
use status::read_status;

/// How many recent incidents the glance shows.
const INCIDENT_LIMIT: usize = 10;

fn main() -> Result<()> {
    let cfg = Config::load(None)?;
    // Read-only: open the DuckDB file at the configured `db_path` with
    // `access_mode=read_only` (no DDL, no read-write lock) and snapshot the
    // latest link/proxy tick plus the most recent incidents.
    let store = ReadOnlyDb::open(&cfg.db_path)?;
    let snapshot = read_status(&store, INCIDENT_LIMIT)?;

    // Headless glance: print the `Status`. The gpui menu-bar UI is deferred
    // (see the module-level TODO(menu-bar)).
    print!("{}", status::render_status(&snapshot));

    Ok(())
}
