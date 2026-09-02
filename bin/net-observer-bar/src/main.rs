//! `net-observer-bar` — a macOS **menu-bar** glance at the live observer status.
//!
//! An `NSStatusItem` in the system menu bar shows an icon-only health dot derived
//! from the latest link/proxy tick (green when healthy, red when gw/tun are bad,
//! white before any data). Clicking it toggles an anchored **gpui** popup (a
//! Tailscale-style dropdown, dismissed on click-away) rendering the full
//! [`StatusSnapshot`](net_observer_ipc::StatusSnapshot): the latest link tick
//! (gw/direct), the latest proxy tick (tun/selector), and the most recent
//! incidents, plus a Quit control. The glance re-queries the daemon on a ~3s
//! timer, updating both the status-item dot and any open panel.
//!
//! ## Data source: the daemon's local socket (no DB)
//!
//! The bar is a **pure socket client**. `net-observerd` is the sole owner of the
//! DuckDB store (DuckDB takes a per-process file lock, so a second opener — even
//! read-only — is blocked while the daemon runs). Instead of opening the DB, the
//! bar fetches a live in-memory [`StatusSnapshot`](net_observer_ipc::StatusSnapshot)
//! via [`net_observer_ipc::query`] over the Unix-domain socket at `cfg.socket_path`.
//! When the daemon is down / the socket is absent the query fails and the bar
//! renders a graceful **"net-observer offline"** state (grey dot, message in the
//! panel) — it never panics.
//!
//! ## Layers
//!
//! - [`status`] — the load-bearing, unit-tested pure render layer:
//!   `render_status` + `status_dot`/`status_glyph` + `health`, all over an
//!   [`net_observer_ipc::StatusSnapshot`], tested against synthetic snapshots.
//! - [`ui`] — the gpui panel view + shared model, and [`ui::read_fresh`], the
//!   blocking socket fetch that maps daemon-down to an "offline" `Err`.
//! - [`menubar`] — the dockless (`.accessory`) `NSStatusItem` shell (AppKit
//!   interop via `objc2`) that hosts the gpui panel and drives the refresh timer.
//! - [`events`] — the realtime **event-log window** (a resizable, closable
//!   `WindowKind::Normal`): opened from the panel footer, fed by one held-open
//!   `Subscribe` stream over the socket (pub/sub, push not poll), with a type
//!   selector over a live autoscrolling list.
//!
//! The GUI cannot run headlessly, so it is verified by compiling + clippy; the
//! tested surface stays the data/render layer.

mod events;
mod map;
mod menubar;
mod status;
mod ui;

use clap::Parser;

// The same `clap` surface as the sibling binaries (`net-observerd`, `net-observer-cli`):
// `--config=<path>` works, a `--config` without a value is a hard error rather
// than a silently ignored flag, and an unknown argument exits non-zero instead of
// being swallowed. A dropped `--config` would fall back to the default socket and
// render as "offline" with nothing said about why.
#[derive(Parser)]
#[command(
    name = "net-observer-bar",
    about = "macOS menu-bar glance at the live observer status"
)]
struct Cli {
    /// Optional path to the observer config file (TOML). Supplies the daemon
    /// socket path the bar reads its snapshots from.
    #[arg(long)]
    config: Option<String>,
    /// Open the panel immediately on launch instead of waiting for a
    /// status-item click.
    #[arg(long)]
    open: bool,
}

fn main() {
    let cli = Cli::parse();
    menubar::run(cli.config, cli.open);
}
