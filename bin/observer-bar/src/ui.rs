//! The gpui panel view for the menu-bar app.
//!
//! [`Glance`] is a shared entity holding the most recent
//! [`StatusSnapshot`](observer_ipc::StatusSnapshot) fetched from `observerd` over
//! the local socket (plus the last fetch error and the socket path used to
//! refresh). The menu-bar refresh timer writes into it (see [`crate::menubar`]);
//! [`PanelView`] observes it and re-renders whenever it changes, so an open panel
//! updates live on the same ~3s cadence as the status-item glyph.
//!
//! The bar is a pure socket client — it never opens the DuckDB store (the daemon
//! is the sole DB owner). When the daemon is down / the socket is absent,
//! [`read_fresh`] returns `Err` and the panel renders a graceful "observer
//! offline" state instead of crashing.

use std::time::{SystemTime, UNIX_EPOCH};

use gpui::prelude::*;
use gpui::{App, Context, Entity, Rgba, SharedString, Subscription, Window, div, px, rgb};

use observer_ipc::{IncidentSummary, Request, Response, StatusSnapshot};

use crate::status::{Health, health};

// Dark palette for the panel.
const BG: u32 = 0x1e1e2e;
const CARD: u32 = 0x2a2a3c;
const FG: u32 = 0xe6e6f0;
const MUTED: u32 = 0x9a9ab0;
const OK: u32 = 0x66d17d;
const BAD: u32 = 0xf05a5a;
const WARN: u32 = 0xe6b450;
const ACCENT: u32 = 0x7aa2f7;

/// Fetch the live [`StatusSnapshot`] from `observerd` over the local socket.
///
/// The bar owns no DB — the daemon does — so every refresh is a blocking
/// [`observer_ipc::query`] round-trip. Re-querying each tick means the glance
/// recovers on its own once the daemon comes back, and fails gracefully when it
/// is not there: a missing socket, connection-refused (daemon down), or a
/// protocol error all map to `Err(String)`, which the panel surfaces as
/// "observer offline" and the status item as a grey glyph — retried on the next
/// tick instead of crashing.
pub fn read_fresh(socket_path: &str) -> Result<StatusSnapshot, String> {
    match observer_ipc::query(socket_path, &Request::Status) {
        Ok(Response::Status(snap)) => Ok(snap),
        Ok(Response::Error(msg)) => Err(msg),
        Ok(_) => Err("unexpected response from observerd".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// Shared, app-scoped model: the latest snapshot the UI renders.
pub struct Glance {
    pub snapshot: StatusSnapshot,
    /// The most recent fetch error, if the last refresh failed (daemon offline).
    pub error: Option<String>,
    /// Config socket path, so the panel's manual "Refresh" can re-query.
    pub socket_path: String,
}

impl Glance {
    pub fn new(snapshot: StatusSnapshot, error: Option<String>, socket_path: String) -> Self {
        Self {
            snapshot,
            error,
            socket_path,
        }
    }

    /// Re-query the daemon into this model. Used by the manual refresh button; the
    /// timer path in [`crate::menubar`] mutates the same fields directly.
    pub fn refresh(&mut self) {
        match read_fresh(&self.socket_path) {
            Ok(s) => {
                self.snapshot = s;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }
}

/// The root view of the panel window. Holds a handle to the shared [`Glance`]
/// and re-renders whenever it changes.
pub struct PanelView {
    model: Entity<Glance>,
    _observe: Subscription,
}

impl PanelView {
    pub fn new(model: Entity<Glance>, cx: &mut Context<Self>) -> Self {
        // Re-render this view whenever the shared model is notified (timer tick
        // or manual refresh).
        let observe = cx.observe(&model, |_, _, cx| cx.notify());
        Self {
            model,
            _observe: observe,
        }
    }
}

impl Render for PanelView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let glance = self.model.read(cx);
        let snapshot = glance.snapshot.clone();
        let error = glance.error.clone();
        let now_us = now_us();

        let (dot, dot_color) = health_dot(&snapshot);

        div()
            .flex()
            .flex_col()
            .size_full()
            .gap_3()
            .p_4()
            .bg(rgb(BG))
            .text_color(rgb(FG))
            .text_sm()
            // Header: health dot + title + last-updated age.
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().text_color(dot_color).text_xl().child(dot))
                    .child(
                        div()
                            .text_xl()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child("observer"),
                    )
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_color(rgb(MUTED))
                            .text_xs()
                            .child(freshness_line(&snapshot, now_us)),
                    ),
            )
            .children(error.map(error_banner))
            .child(link_card(&snapshot, now_us))
            .child(proxy_card(&snapshot, now_us))
            .child(incidents_card(&snapshot.incidents, now_us))
            .child(footer(cx))
    }
}

/// The colored health dot + its color for the panel header. The color follows
/// the shared [`health`] classifier, so the panel dot and the menu-bar
/// [`status_glyph`](crate::status::status_glyph) can never disagree.
fn health_dot(snapshot: &StatusSnapshot) -> (&'static str, Rgba) {
    let color = match health(snapshot) {
        Health::NoData => rgb(MUTED),
        Health::Ok => rgb(OK),
        Health::Bad => rgb(BAD),
    };
    ("\u{25CF}", color)
}

fn error_banner(msg: String) -> impl IntoElement {
    card(WARN).child(
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(section_title("observer offline"))
            .child(div().text_color(rgb(WARN)).child(SharedString::from(msg))),
    )
}

fn link_card(snapshot: &StatusSnapshot, now_us: i64) -> impl IntoElement {
    let body = match &snapshot.link {
        Some(l) => {
            let gw = l.gw.to_string();
            let direct = l.direct.to_string();
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(kv("gw", &gw, verdict_color(&gw)))
                .child(kv("direct", &direct, verdict_color(&direct)))
                .child(kv("age", &age_str(l.ts_us, now_us), rgb(MUTED)))
        }
        None => div().child(no_data()),
    };
    card(CARD).child(
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title("link (latest tick)"))
            .child(body),
    )
}

fn proxy_card(snapshot: &StatusSnapshot, now_us: i64) -> impl IntoElement {
    let body = match &snapshot.proxy {
        Some(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let tun_color = match p.tun_code {
                Some(204) => rgb(OK),
                Some(_) => rgb(BAD),
                None => rgb(MUTED),
            };
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(kv("tun", &tun, tun_color))
                .child(kv("selector", &sel, rgb(FG)))
                .child(kv("age", &age_str(p.ts_us, now_us), rgb(MUTED)))
        }
        None => div().child(no_data()),
    };
    card(CARD).child(
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title("proxy (latest tick)"))
            .child(body),
    )
}

fn incidents_card(incidents: &[IncidentSummary], now_us: i64) -> impl IntoElement {
    let body = if incidents.is_empty() {
        div().child(div().text_color(rgb(MUTED)).child("no recent incidents"))
    } else {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .children(incidents.iter().map(|i| incident_row(i, now_us)))
    };
    card(CARD).child(
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_title("recent incidents"))
            .child(body),
    )
}

fn incident_row(i: &IncidentSummary, now_us: i64) -> impl IntoElement {
    let (state, state_color) = match i.closed_us {
        Some(_) => ("closed", rgb(MUTED)),
        None => ("open", rgb(BAD)),
    };
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(div().text_color(state_color).w(px(48.0)).child(state))
        .child(
            div()
                .flex_1()
                .text_color(rgb(FG))
                .child(SharedString::from(i.trigger_id.clone())),
        )
        .child(
            div()
                .text_color(rgb(MUTED))
                .text_xs()
                .child(age_str(i.opened_us, now_us)),
        )
}

fn footer(cx: &mut Context<PanelView>) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(div().flex_1())
        .child(
            div()
                .id("refresh")
                .px_3()
                .py_1()
                .rounded_md()
                .bg(rgb(CARD))
                .text_color(rgb(ACCENT))
                .cursor_pointer()
                .hover(|s| s.bg(rgb(0x33334a)))
                .child("Refresh")
                .on_click(cx.listener(|this, _, _window, cx| {
                    this.model.update(cx, |g, cx| {
                        g.refresh();
                        cx.notify();
                    });
                })),
        )
        .child(
            div()
                .id("quit")
                .px_3()
                .py_1()
                .rounded_md()
                .bg(rgb(CARD))
                .text_color(rgb(BAD))
                .cursor_pointer()
                .hover(|s| s.bg(rgb(0x3a2a2a)))
                .child("Quit")
                .on_click(|_, _window, cx: &mut App| cx.quit()),
        )
}

// ---- small element helpers -------------------------------------------------

fn card(border: u32) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .p_3()
        .rounded_md()
        .bg(rgb(CARD))
        .border_l_2()
        .border_color(rgb(border))
}

fn section_title(text: &'static str) -> impl IntoElement {
    div()
        .text_xs()
        .text_color(rgb(MUTED))
        .font_weight(gpui::FontWeight::SEMIBOLD)
        .child(text)
}

fn kv(key: &'static str, value: &str, value_color: Rgba) -> impl IntoElement {
    div()
        .flex()
        .items_center()
        .gap_2()
        .child(div().w(px(72.0)).text_color(rgb(MUTED)).child(key))
        .child(
            div()
                .text_color(value_color)
                .child(SharedString::from(value.to_string())),
        )
}

fn no_data() -> impl IntoElement {
    div().text_color(rgb(MUTED)).child("(no data)")
}

fn verdict_color(verdict: &str) -> Rgba {
    match verdict {
        "OK" => rgb(OK),
        "" => rgb(MUTED),
        _ => rgb(BAD),
    }
}

/// Current wall-clock time in microseconds since the Unix epoch.
pub fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// A short "12s ago" / "3m ago" string from a microsecond timestamp.
fn age_str(ts_us: i64, now_us: i64) -> String {
    if ts_us <= 0 {
        return "-".to_string();
    }
    let secs = (now_us - ts_us) / 1_000_000;
    if secs < 0 {
        return "just now".to_string();
    }
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

fn freshness_line(snapshot: &StatusSnapshot, now_us: i64) -> String {
    let newest = [
        snapshot.link.as_ref().map(|l| l.ts_us),
        snapshot.proxy.as_ref().map(|p| p.ts_us),
    ]
    .into_iter()
    .flatten()
    .max();
    match newest {
        Some(ts) => format!("updated {}", age_str(ts, now_us)),
        None => "no data".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_str_buckets() {
        let now = 1_000_000_000i64;
        assert_eq!(age_str(0, now), "-");
        assert_eq!(age_str(now, now), "0s ago");
        assert_eq!(age_str(now - 5_000_000, now), "5s ago");
        assert_eq!(age_str(now - 120_000_000, now), "2m ago");
        assert_eq!(age_str(now + 5_000_000, now), "just now");
    }

    #[test]
    fn freshness_prefers_newest_tick() {
        let mut s = StatusSnapshot::default();
        assert_eq!(freshness_line(&s, 10_000_000), "no data");
        s.link = Some(types::LinkSample {
            ts_us: 1_000_000,
            gw: types::GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: types::TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        });
        s.proxy = Some(types::ProxySample {
            ts_us: 4_000_000,
            server_ip: "1.2.3.4".into(),
            tcp: types::TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
        });
        // newest is the proxy tick at 4s -> 6s ago at now=10s.
        assert_eq!(freshness_line(&s, 10_000_000), "updated 6s ago");
    }

    /// Daemon down / socket absent must map to a graceful `Err`, never a panic —
    /// this is the "observer offline" path the panel renders.
    #[test]
    fn read_fresh_offline_when_socket_absent() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let res = read_fresh(missing.to_str().unwrap());
        assert!(res.is_err(), "absent socket must yield an offline Err");
    }
}
