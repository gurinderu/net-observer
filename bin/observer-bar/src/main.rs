//! `observer-bar` — a macOS **menu-bar** glance at the observer DuckDB store.
//!
//! An `NSStatusItem` in the system menu bar shows a compact health glyph derived
//! from the latest link/proxy tick (a colored dot + `gw:OK tun:204`, red when
//! gw/tun are bad). Clicking it opens a **gpui** panel rendering the full
//! [`Status`](crate::status::Status): the latest link tick (gw/direct), the
//! latest proxy tick (tun/selector), and the most recent incidents, plus a Quit
//! control. The glance re-reads the store on a ~3s timer, updating both the
//! status-item glyph and any open panel.
//!
//! ## Layers
//!
//! - [`status`] — the load-bearing, unit-tested data layer:
//!   [`Status`](crate::status::Status) + `read_status` + `render_status` +
//!   `status_glyph`, all reading through the
//!   [`QuerySource`](crate::status::QuerySource) trait so the snapshot logic is
//!   testable against an in-memory store yet runs against a read-only connection
//!   in production.
//! - [`db`] — [`ReadOnlyDb`](crate::db::ReadOnlyDb): a DuckDB connection opened
//!   with `access_mode=read_only` (no DDL, never contends for the write slot).
//!   DuckDB's per-process file lock means this opens only when no `observerd` is
//!   holding the store read-write (offline forensics); while the daemon runs the
//!   open fails and the panel shows "store unavailable". Concurrent live access
//!   is a post-v1 socket/snapshot concern — see the [`db`] module docs.
//! - [`ui`] — the gpui panel view + shared model.
//! - [`menubar`] — the dockless (`.accessory`) `NSStatusItem` shell (AppKit
//!   interop via `objc2`) that hosts the gpui panel and drives the refresh timer.
//!
//! The GUI cannot run headlessly, so it is verified by compiling + clippy; the
//! tested surface stays the data layer.

mod db;
mod menubar;
mod status;
mod ui;

fn main() {
    menubar::run();
}
