//! `observer-bar` — a macOS **menu-bar** glance at the live observer status.
//!
//! An `NSStatusItem` in the system menu bar shows a compact health glyph derived
//! from the latest link/proxy tick (a colored dot + `gw:OK tun:204`, red when
//! gw/tun are bad). Clicking it opens a **gpui** panel rendering the full
//! [`StatusSnapshot`](observer_ipc::StatusSnapshot): the latest link tick
//! (gw/direct), the latest proxy tick (tun/selector), and the most recent
//! incidents, plus a Quit control. The glance re-queries the daemon on a ~3s
//! timer, updating both the status-item glyph and any open panel.
//!
//! ## Data source: the daemon's local socket (no DB)
//!
//! The bar is a **pure socket client**. `observerd` is the sole owner of the
//! DuckDB store (DuckDB takes a per-process file lock, so a second opener — even
//! read-only — is blocked while the daemon runs). Instead of opening the DB, the
//! bar fetches a live in-memory [`StatusSnapshot`](observer_ipc::StatusSnapshot)
//! via [`observer_ipc::query`] over the Unix-domain socket at `cfg.socket_path`.
//! When the daemon is down / the socket is absent the query fails and the bar
//! renders a graceful **"observer offline"** state (grey glyph, message in the
//! panel) — it never panics.
//!
//! ## Layers
//!
//! - [`status`] — the load-bearing, unit-tested pure render layer:
//!   `render_status` + `status_glyph` + `health`, all over an
//!   [`observer_ipc::StatusSnapshot`], tested against synthetic snapshots.
//! - [`ui`] — the gpui panel view + shared model, and [`ui::read_fresh`], the
//!   blocking socket fetch that maps daemon-down to an "offline" `Err`.
//! - [`menubar`] — the dockless (`.accessory`) `NSStatusItem` shell (AppKit
//!   interop via `objc2`) that hosts the gpui panel and drives the refresh timer.
//!
//! The GUI cannot run headlessly, so it is verified by compiling + clippy; the
//! tested surface stays the data/render layer.

mod menubar;
mod status;
mod ui;

fn main() {
    menubar::run();
}
