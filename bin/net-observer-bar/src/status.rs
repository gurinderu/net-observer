//! Pure render layer for `net-observer-bar`: turn an [`net_observer_ipc::StatusSnapshot`]
//! (fetched live from `net-observerd` over the local socket) into the menu-bar health
//! dot (and the retained compact glyph), the health classification, the
//! multi-line tooltip/panel text, and — over the fetch outcome as well — the
//! whole status-item [`Presentation`].
//!
//! This is the load-bearing, unit-tested part of the menu-bar app. It is pure
//! over its input — no DB, no socket, no GUI — so every renderer is tested here
//! against synthetic [`StatusSnapshot`]s. The bar no longer touches DuckDB at
//! all: the daemon is the sole DB owner and serves the snapshot from memory (see
//! [`crate::ui::read_fresh`], which calls [`net_observer_ipc::query`]).

use std::time::Duration;

use net_observer_ipc::StatusSnapshot;
use types::{GwVerdict, ProbingTier};

use crate::ui::GlanceError;

/// How old a snapshot's last tick may be before the bar stops presenting it as
/// live: past this, the daemon answered the socket but nothing has advanced its
/// `generated_us`, so the dot goes grey exactly as for a daemon that does not
/// answer at all (realm net-observer, node #88).
///
/// Two default collector intervals (15 s each, see the `config` crate): one
/// missed tick is a probe that ran long, two is a pipeline that stopped. The
/// bar re-reads every 3 s (`menubar::REFRESH`), so the grey lands within one
/// refresh of the bound. Measured against the bar's own wall clock — the same
/// clock the daemon stamps its samples with, since both run on this Mac.
pub const STALE_AFTER: Duration = Duration::from_secs(30);

/// Render a [`StatusSnapshot`] as a compact, human-readable multi-line glance:
/// the [`headline`] (the app name, or the "no verdict" sentence that explains a
/// hollow dot), then the link, proxy and incident lines ([`render_body`]).
/// Pure over its input so it can be unit-tested without a socket or a GUI.
pub fn render_status(snap: &StatusSnapshot) -> String {
    format!("{}\n{}", headline(snap), render_body(snap))
}

/// The first line of [`render_status`]. `net-observer` while there is a verdict
/// to show; when there is none ([`Health::NoData`]) it says so and why, so the
/// hollow dot ([`status_dot`]) is explained by the very tooltip it hangs under:
///
/// - `no verdict — probing passive (gw SKIP, tun not probed)` — the passive
///   tier withheld the gateway echo (and the tun probe with it); a measured
///   tun reads `tun 204` instead,
/// - `no verdict — gateway probe did not run (gw SKIP, …)` — a `SKIP` under
///   the active tier: the link tick's preflight found nothing to probe, which
///   is a different fact from a tier that never asks,
/// - `no verdict — no link or proxy tick yet` — nothing has arrived at all.
fn headline(snap: &StatusSnapshot) -> String {
    if health(snap) != Health::NoData {
        return "net-observer".to_string();
    }
    // `NoData` has exactly two sources (see `health`): no link *and* no proxy
    // tick, or a `SKIP` gateway with an unmeasured or healthy tun.
    match &snap.link {
        None => "no verdict — no link or proxy tick yet".to_string(),
        Some(_) => {
            let why = match snap.probing {
                ProbingTier::Passive => "probing passive",
                ProbingTier::Active => "gateway probe did not run",
            };
            let tun = match snap.proxy.as_ref().and_then(|p| p.tun_code) {
                None => "tun not probed".to_string(),
                Some(code) => format!("tun {code}"),
            };
            format!("no verdict — {why} (gw SKIP, {tun})")
        }
    }
}

/// The lines under the [`headline`]: the latest link and proxy ticks and the
/// recent incidents, one per line, with placeholders for what is missing.
fn render_body(snap: &StatusSnapshot) -> String {
    let mut out = String::new();

    match &snap.link {
        Some(l) => out.push_str(&format!(
            "link   gw={} direct={} ts_us={}\n",
            l.gw, l.direct, l.ts_us
        )),
        None => out.push_str("link   (no data)\n"),
    }

    match &snap.proxy {
        Some(p) => {
            let tun = p
                .tun_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".to_string());
            let sel = p.selector.clone().unwrap_or_else(|| "-".to_string());
            // sing-box's own URL test of the selected node (realm
            // net-observer, node #62), the same rendering the CLI's `status`
            // uses, aged against the snapshot's instant; `-` = no reading.
            let urltest = p
                .urltest_label(snap.generated_us)
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "proxy  tun={tun} selector={sel} urltest={urltest} ts_us={}\n",
                p.ts_us
            ));
        }
        None => out.push_str("proxy  (no data)\n"),
    }

    if snap.incidents.is_empty() {
        out.push_str("incidents (none)\n");
    } else {
        out.push_str("incidents\n");
        for i in &snap.incidents {
            let closed = i
                .closed_us
                .map(|c| c.to_string())
                .unwrap_or_else(|| "open".to_string());
            out.push_str(&format!(
                "  {} opened={} closed={}\n",
                i.trigger_id, i.opened_us, closed
            ));
        }
    }

    out
}

/// Move incident `id` to closed at `closed_us` in a snapshot's incident list —
/// the bar's own mirror of the stamp the daemon's ring gets on `on_clear`,
/// applied when an `Event::IncidentClosed` frame arrives so the panel does not
/// wait for its next poll (realm net-observer, node #135). `false` when the
/// list does not hold `id` (opened after the last poll, or already past the
/// ring's cap): nothing is added, and the next poll settles it.
pub fn close_incident(
    incidents: &mut [net_observer_ipc::IncidentSummary],
    id: &str,
    closed_us: i64,
) -> bool {
    match incidents.iter_mut().find(|i| i.id == id) {
        Some(inc) => {
            inc.closed_us = Some(closed_us);
            true
        }
        None => false,
    }
}

/// The three-state health of a [`StatusSnapshot`], derived from the gateway
/// verdict and the tun probe code. The single source of truth for both the
/// menu-bar dot ([`status_dot`]) and the panel's header dot
/// (`ui::health_dot`), so the two can never drift apart.
///
/// Reachability is not a health: whether the daemon answered at all lives in
/// [`GlanceError`], and [`presentation`] is where the two meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// No verdict: no link and no proxy tick yet, or the gateway probe was
    /// withheld (`SKIP`) with nothing else at fault — nothing to judge.
    NoData,
    /// Gateway `OK` and the tun probe returned HTTP 204.
    Ok,
    /// Gateway or tun is bad / degraded.
    Bad,
}

/// Classify a [`StatusSnapshot`] into a [`Health`]: [`Health::NoData`] when there
/// is no link *and* no proxy tick (and when the gateway verdict is `SKIP` — the
/// passive tier — while the tun is unmeasured (`None`) or healthy (`204`):
/// nothing was measured at the gateway, so there is no verdict to give),
/// [`Health::Ok`] when the gateway verdict is `OK` *and* the tun probe returned
/// HTTP 204 (the healthy reachability code), and [`Health::Bad`] otherwise (gw
/// or tun bad / degraded — e.g. tun `0` = wedge). Pure over its input, so it is
/// unit-tested without a socket or a GUI.
pub fn health(snap: &StatusSnapshot) -> Health {
    if snap.link.is_none() && snap.proxy.is_none() {
        return Health::NoData;
    }
    // A `SKIP` gateway is the passive tier: the echo was deliberately not sent, so
    // there is no gateway verdict to judge. Under this tier the tun 204 probe is
    // withheld too, so `tun_code` is usually `None` ("not probed"), not `204`
    // ("probed and healthy") — both mean the same thing here: nothing was
    // measured, so there is no verdict to give. Only a *measured* non-204 tun
    // (a wedge, or another code) is an independent fault the gateway withholding
    // does not excuse. The first passive daemon left `None` unhandled here and
    // lit the dot red on a healthy network for exactly this reason
    // (realm net-observer, node #88).
    if snap.link.as_ref().is_some_and(|l| l.gw == GwVerdict::Skip) {
        let tun_code = snap.proxy.as_ref().and_then(|p| p.tun_code);
        return match tun_code {
            None | Some(204) => Health::NoData,
            Some(_) => Health::Bad,
        };
    }
    let gw_ok = snap.link.as_ref().is_some_and(|l| l.gw == GwVerdict::Ok);
    // The tun HTTP 204 probe: 204 means the tunnel path is reachable; anything
    // else (0 = wedge, other codes, or missing) is not healthy.
    let tun_ok = snap.proxy.as_ref().and_then(|p| p.tun_code) == Some(204);
    if gw_ok && tun_ok {
        Health::Ok
    } else {
        Health::Bad
    }
}

/// The bare health *dot* for the menu-bar status item — no text — derived from a
/// [`StatusSnapshot`] via the shared [`health`] classifier:
///
/// - green (`🟢`) when the gateway verdict is `OK` and the tun probe returned
///   HTTP 204 (the healthy reachability code, [`Health::Ok`]),
/// - red (`🔴`) when gw or tun is bad / degraded ([`Health::Bad`]),
/// - hollow (`◌`, U+25CC, a dotted circle) when there is no verdict
///   ([`Health::NoData`]) — never a filled grey dot, because grey is what the
///   bar shows for a daemon that is unreachable or stale, and a reachable
///   daemon with nothing to say must not look like one that is not there
///   (realm net-observer, node #88).
///
/// This is what the menu-bar title shows (icon-only, Tailscale-style). Pure over
/// its input, so it is unit-tested without a socket or a GUI. The daemon-down
/// "offline" state is rendered separately (see [`presentation`]); this dot
/// describes a live snapshot only.
pub fn status_dot(snap: &StatusSnapshot) -> &'static str {
    match health(snap) {
        Health::NoData => "◌",
        Health::Ok => "🟢",
        Health::Bad => "🔴",
    }
}

/// A compact, single-line health glyph derived from a [`StatusSnapshot`]: the
/// [`status_dot`] plus `gw:<verdict> tun:<code>`. Pure over its input so it can
/// be unit-tested without a socket or a GUI.
///
/// The dot follows [`health`], the shared classifier the panel header dot uses.
/// The daemon-down "offline" state is rendered separately (see
/// [`presentation`]); this glyph describes a live snapshot only.
///
/// Retained as a tested pure renderer of the verbose form; the menu-bar title now
/// shows the icon-only [`status_dot`], so nothing outside the tests calls this in
/// a release build (hence the conditional `allow(dead_code)`).
#[cfg_attr(not(test), allow(dead_code))]
pub fn status_glyph(snap: &StatusSnapshot) -> String {
    let dot = status_dot(snap);

    let gw = snap
        .link
        .as_ref()
        .map(|l| l.gw.to_string())
        .unwrap_or_else(|| "?".to_string());
    let tun = snap
        .proxy
        .as_ref()
        .and_then(|p| p.tun_code)
        .map(|c| c.to_string())
        .unwrap_or_else(|| "-".to_string());

    format!("{dot} gw:{gw} tun:{tun}")
}

/// What the status item shows: the title glyph and the hover tooltip, decided
/// by [`presentation`]. The shell in `menubar` only copies both onto the
/// `NSStatusBarButton`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    /// The icon-only title: `⚫` offline, `⚠` bad answer, `⏸` paused, or the
    /// live [`status_dot`].
    pub glyph: &'static str,
    /// The tooltip's opening line(s): the state and its reason.
    pub tooltip_head: String,
    /// The rest of the tooltip — the snapshot rendered by [`render_body`] —
    /// present only when the snapshot is current enough to show. An
    /// unreachable, badly-answering or stale daemon gets the head alone: stale
    /// health under an "offline" line would still read as live.
    pub tooltip_body: Option<String>,
}

impl Presentation {
    /// The full tooltip text: the head, then the body when there is one.
    pub fn tooltip(&self) -> String {
        match &self.tooltip_body {
            Some(body) => format!("{}\n{body}", self.tooltip_head),
            None => self.tooltip_head.clone(),
        }
    }
}

/// The grey dot: the daemon is not there, or has stopped ticking.
const OFFLINE_GLYPH: &str = "\u{26AB}"; // ⚫

/// Decide the status item's glyph and tooltip from the last fetch outcome, the
/// snapshot it left behind, and the bar's clock (`now_us`, epoch microseconds).
/// Pure over its inputs, so the whole state table is testable without a GUI
/// (realm net-observer, node #88):
///
/// - **offline** ([`GlanceError::Unreachable`] — daemon down / socket absent):
///   `⚫` and `net-observer offline` plus the transport error, rather than stale
///   health shown as live.
/// - **bad answer** ([`GlanceError::Protocol`]): the daemon *is* reachable — it
///   answered, we just could not use the answer (an error frame, or a decode
///   failure against an older daemon). `⚠` and a tooltip that says so, never
///   "offline", which would be a false claim about the world.
/// - **paused** (collection turned off via the panel switch): `⏸` and a
///   "paused" head over the snapshot — the daemon is alive but not collecting,
///   so the live health dot would be misleading. Outranks staleness: a paused
///   daemon stops ticking by design, and the pause is bracketed in the record.
/// - **stale** (the daemon answered, but its `generated_us` is more than
///   [`STALE_AFTER`] behind `now_us`): `⚫` and `net-observer offline` /
///   `last tick <n> s ago` — the socket is up, the pipeline behind it is not,
///   and a green dot from a dead pipeline is the silent wrong data the bar
///   exists to prevent. A daemon that has not ticked at all yet
///   (`generated_us == 0`) is not stale — there is no tick to date — and falls
///   through to the hollow "no verdict" dot.
/// - **live**: the [`status_dot`] under the snapshot's own [`headline`], so a
///   hollow dot is explained by the first line of its tooltip.
pub fn presentation(
    error: Option<&GlanceError>,
    snap: &StatusSnapshot,
    now_us: i64,
) -> Presentation {
    match error {
        Some(GlanceError::Unreachable(e)) => {
            return Presentation {
                glyph: OFFLINE_GLYPH,
                tooltip_head: format!("net-observer offline\n{e}"),
                tooltip_body: None,
            };
        }
        Some(GlanceError::Protocol(e)) => {
            return Presentation {
                glyph: "\u{26A0}", // ⚠ up, but the answer is unusable
                tooltip_head: format!("net-observer: daemon reachable, but its answer failed\n{e}"),
                tooltip_body: None,
            };
        }
        None => {}
    }
    if !snap.observing {
        return Presentation {
            glyph: "\u{23F8}", // ⏸ paused (collection off)
            tooltip_head: "paused".to_string(),
            tooltip_body: Some(render_status(snap)),
        };
    }
    if let Some(age_s) = stale_age_s(snap, now_us) {
        return Presentation {
            glyph: OFFLINE_GLYPH,
            tooltip_head: format!("net-observer offline\nlast tick {age_s} s ago"),
            tooltip_body: None,
        };
    }
    Presentation {
        glyph: status_dot(snap),
        tooltip_head: headline(snap),
        tooltip_body: Some(render_body(snap)),
    }
}

/// The age of the snapshot's last tick in whole seconds, when it is past
/// [`STALE_AFTER`]; `None` while it is fresh, and `None` for a snapshot that
/// has never ticked (`generated_us == 0`, the daemon's own starting value).
fn stale_age_s(snap: &StatusSnapshot, now_us: i64) -> Option<i64> {
    if snap.generated_us <= 0 {
        return None;
    }
    let age_us = now_us.saturating_sub(snap.generated_us);
    (age_us > STALE_AFTER.as_micros() as i64).then_some(age_us / 1_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use net_observer_ipc::IncidentSummary;
    use types::{LinkSample, ProxySample, TcpVerdict};

    /// A synthetic link sample with the given gateway verdict; other fields are
    /// filled with harmless defaults so the tests read as one-liners.
    fn link(gw: GwVerdict) -> LinkSample {
        LinkSample {
            ts_us: 1,
            gw,
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
        }
    }

    /// A synthetic proxy sample with the given tun code and selector.
    fn proxy(tun_code: Option<u16>, selector: Option<&str>) -> ProxySample {
        ProxySample {
            ts_us: 1,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code,
            selector: selector.map(str::to_string),
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
            urltest_ms: None,
            urltest_at_us: None,
            urltest_node: None,
            urltest_absent_since_us: None,
        }
    }

    #[test]
    fn glyph_green_when_gw_ok_and_tun_204() {
        let snap = StatusSnapshot {
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(204), Some("auto"))),
            ..Default::default()
        };
        assert_eq!(status_glyph(&snap), "🟢 gw:OK tun:204");
    }

    /// The passive tier (`gw = SKIP`) is not a fault: with the tun healthy —
    /// measured 204, or unmeasured (`None`, the tier's default since the tun
    /// probe is withheld too) — the dot is the "no verdict" one, not red, and
    /// not green either, since nothing at the gateway was measured. A
    /// *measured* non-204 tun is still an independent fault.
    #[test]
    fn skip_gateway_is_no_verdict_not_a_fault() {
        let passive = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(Some(204), Some("auto"))),
            ..Default::default()
        };
        assert_eq!(health(&passive), Health::NoData);

        // The passive tier's actual default: tun not probed at all.
        let passive_unmeasured = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(None, Some("auto"))),
            ..Default::default()
        };
        assert_eq!(health(&passive_unmeasured), Health::NoData);

        // A wedged tun is still a fault while the gateway is withheld.
        let wedged = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(Some(0), None)),
            ..Default::default()
        };
        assert_eq!(health(&wedged), Health::Bad);

        // A measured, non-204, non-wedge code is also a fault.
        let bad_code = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(Some(200), None)),
            ..Default::default()
        };
        assert_eq!(health(&bad_code), Health::Bad);
    }

    #[test]
    fn glyph_red_when_gw_fail_or_tun_wedged() {
        let wedged = StatusSnapshot {
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(0), None)),
            ..Default::default()
        };
        // tun=0 is the wedge signature -> red, and the raw code must render.
        assert_eq!(status_glyph(&wedged), "🔴 gw:OK tun:0");

        let gw_down = StatusSnapshot {
            link: Some(link(GwVerdict::Fail)),
            proxy: Some(proxy(Some(204), None)),
            ..Default::default()
        };
        assert_eq!(status_glyph(&gw_down), "🔴 gw:FAIL tun:204");
    }

    #[test]
    fn glyph_hollow_and_placeholders_when_no_data() {
        assert_eq!(status_glyph(&StatusSnapshot::default()), "◌ gw:? tun:-");
    }

    #[test]
    fn health_classifier_matches_glyph_states() {
        // No data at all -> NoData.
        assert_eq!(health(&StatusSnapshot::default()), Health::NoData);

        // gw OK + tun 204 -> Ok.
        let ok = StatusSnapshot {
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(204), None)),
            ..Default::default()
        };
        assert_eq!(health(&ok), Health::Ok);

        // tun wedged (0) -> Bad, even with gw OK.
        let wedged = StatusSnapshot {
            proxy: Some(proxy(Some(0), None)),
            ..ok.clone()
        };
        assert_eq!(health(&wedged), Health::Bad);

        // gw FAIL -> Bad, even with tun 204.
        let gw_down = StatusSnapshot {
            link: Some(link(GwVerdict::Fail)),
            ..ok
        };
        assert_eq!(health(&gw_down), Health::Bad);
    }

    /// The three dots, one per health — and the no-verdict one is hollow, a
    /// dotted circle no filled grey dot can be mistaken for (realm
    /// net-observer, node #88).
    #[test]
    fn status_dot_maps_each_health_to_its_dot() {
        // NoData -> hollow (U+25CC), never a filled grey.
        assert_eq!(status_dot(&StatusSnapshot::default()), "\u{25CC}");
        assert_ne!(status_dot(&StatusSnapshot::default()), OFFLINE_GLYPH);

        // gw OK + tun 204 -> green (Health::Ok).
        let ok = StatusSnapshot {
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(204), None)),
            ..Default::default()
        };
        assert_eq!(status_dot(&ok), "🟢");

        // gw FAIL (or tun wedged) -> red (Health::Bad).
        let bad = StatusSnapshot {
            link: Some(link(GwVerdict::Fail)),
            proxy: Some(proxy(Some(204), None)),
            ..Default::default()
        };
        assert_eq!(status_dot(&bad), "🔴");
    }

    #[test]
    fn render_full_status_lists_link_proxy_and_incidents() {
        let snap = StatusSnapshot {
            generated_us: 100,
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(204), Some("auto"))),
            incidents: vec![IncidentSummary {
                id: "i1".into(),
                opened_us: 80,
                closed_us: None,
                trigger_id: "wedge".into(),
                signature: "tun dead".into(),
            }],
            ..Default::default()
        };
        let out = render_status(&snap);
        assert!(out.starts_with("net-observer\n"), "{out}");
        assert!(out.contains("gw=OK direct=OK"));
        assert!(out.contains("tun=204 selector=auto urltest=-"));
        assert!(out.contains("wedge opened=80 closed=open"));
    }

    /// The first line explains a hollow dot: the passive tier names itself and
    /// what it withheld; a `SKIP` under the active tier is a different fact
    /// and says so; nothing at all says nothing at all. With a verdict the
    /// line is the app name, as before.
    #[test]
    fn render_headline_explains_the_missing_verdict() {
        let passive = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(None, Some("auto"))),
            probing: ProbingTier::Passive,
            ..Default::default()
        };
        assert!(
            render_status(&passive)
                .starts_with("no verdict — probing passive (gw SKIP, tun not probed)\n"),
            "{}",
            render_status(&passive)
        );

        let passive_tun_measured = StatusSnapshot {
            proxy: Some(proxy(Some(204), Some("auto"))),
            ..passive.clone()
        };
        assert!(
            render_status(&passive_tun_measured)
                .starts_with("no verdict — probing passive (gw SKIP, tun 204)\n")
        );

        let active_skip = StatusSnapshot {
            probing: ProbingTier::Active,
            ..passive
        };
        assert!(
            render_status(&active_skip)
                .starts_with("no verdict — gateway probe did not run (gw SKIP, tun not probed)\n")
        );

        assert!(
            render_status(&StatusSnapshot::default())
                .starts_with("no verdict — no link or proxy tick yet\n")
        );

        let ok = StatusSnapshot {
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(204), None)),
            ..Default::default()
        };
        assert!(render_status(&ok).starts_with("net-observer\n"));
    }

    /// An incident-closed frame moves exactly the entry it names to closed,
    /// leaves the others alone, and adds nothing for an id the list does not
    /// hold (realm net-observer, node #135).
    #[test]
    fn close_incident_stamps_the_named_entry_only() {
        let incident = |id: &str, opened_us: i64| IncidentSummary {
            id: id.into(),
            opened_us,
            closed_us: None,
            trigger_id: "wedge".into(),
            signature: "tun dead".into(),
        };
        let mut incidents = vec![incident("wedge-105", 105), incident("wedge-80", 80)];

        assert!(close_incident(&mut incidents, "wedge-80", 95));
        assert_eq!(incidents[1].closed_us, Some(95));
        assert_eq!(incidents[0].closed_us, None, "the other entry is untouched");

        assert!(
            !close_incident(&mut incidents, "wedge-1", 96),
            "an id the list does not hold is reported, not invented"
        );
        assert_eq!(incidents.len(), 2);
    }

    /// sing-box's own test of the selected node renders as the CLI renders
    /// it (realm net-observer, node #62): `<node>:<ms>ms@<age>s`, the age
    /// against the snapshot's own instant.
    #[test]
    fn render_shows_the_urltest() {
        let snap = StatusSnapshot {
            generated_us: 30_000_000,
            proxy: Some(ProxySample {
                urltest_ms: Some(202),
                urltest_at_us: Some(25_000_000),
                urltest_node: Some("auto".into()),
                ..proxy(Some(204), Some("auto"))
            }),
            ..Default::default()
        };
        assert!(render_status(&snap).contains("urltest=auto:202ms@5s"));

        // A node whose entry sing-box deleted shows the age of the absence.
        let snap = StatusSnapshot {
            generated_us: 30_000_000,
            proxy: Some(ProxySample {
                urltest_node: Some("auto".into()),
                urltest_absent_since_us: Some(20_000_000),
                ..proxy(Some(204), Some("auto"))
            }),
            ..Default::default()
        };
        assert!(render_status(&snap).contains("urltest=auto:absent@10s"));
    }

    #[test]
    fn render_empty_status_shows_placeholders() {
        let out = render_status(&StatusSnapshot::default());
        assert!(out.contains("link   (no data)"));
        assert!(out.contains("proxy  (no data)"));
        assert!(out.contains("incidents (none)"));
    }

    #[test]
    fn render_shows_dead_tun_code_zero() {
        let snap = StatusSnapshot {
            proxy: Some(proxy(Some(0), None)),
            ..Default::default()
        };
        // tun=000 is the wedge signature; a zero code must render, not vanish.
        assert!(render_status(&snap).contains("tun=0 selector=-"));
    }

    /// The bar's clock in the presentation tests: 100 s after the epoch.
    const NOW_US: i64 = 100_000_000;

    /// A snapshot that ticked 5 s before [`NOW_US`] — well inside
    /// [`STALE_AFTER`].
    fn fresh(link: Option<LinkSample>, proxy: Option<ProxySample>) -> StatusSnapshot {
        StatusSnapshot {
            generated_us: NOW_US - 5_000_000,
            link,
            proxy,
            ..Default::default()
        }
    }

    /// The whole state table of the status item, one row per state
    /// (realm net-observer, node #88).
    #[test]
    fn presentation_maps_each_state_to_its_glyph_and_tooltip() {
        // Unreachable -> the grey dot, "offline" and the transport error.
        let unreachable = GlanceError::Unreachable("No such file or directory".into());
        let p = presentation(Some(&unreachable), &StatusSnapshot::default(), NOW_US);
        assert_eq!(p.glyph, "\u{26AB}");
        assert_eq!(
            p.tooltip_head,
            "net-observer offline\nNo such file or directory"
        );
        assert_eq!(p.tooltip_body, None);

        // Protocol -> the warning sign: reachable, never "offline".
        let protocol = GlanceError::Protocol("unexpected response".into());
        let p = presentation(Some(&protocol), &StatusSnapshot::default(), NOW_US);
        assert_eq!(p.glyph, "\u{26A0}");
        assert_eq!(
            p.tooltip_head,
            "net-observer: daemon reachable, but its answer failed\nunexpected response"
        );
        assert!(!p.tooltip().contains("offline"));

        // Paused -> the pause sign over the snapshot.
        let paused = StatusSnapshot {
            observing: false,
            ..fresh(Some(link(GwVerdict::Ok)), Some(proxy(Some(204), None)))
        };
        let p = presentation(None, &paused, NOW_US);
        assert_eq!(p.glyph, "\u{23F8}");
        assert_eq!(p.tooltip_head, "paused");
        assert_eq!(
            p.tooltip_body.as_deref(),
            Some(render_status(&paused).as_str())
        );

        // Fresh Ok -> green, under the app name and the snapshot.
        let ok = fresh(Some(link(GwVerdict::Ok)), Some(proxy(Some(204), None)));
        let p = presentation(None, &ok, NOW_US);
        assert_eq!(p.glyph, "🟢");
        assert_eq!(p.tooltip(), render_status(&ok));

        // Fresh Bad -> red.
        let bad = fresh(Some(link(GwVerdict::Fail)), Some(proxy(Some(204), None)));
        let p = presentation(None, &bad, NOW_US);
        assert_eq!(p.glyph, "🔴");
        assert_eq!(p.tooltip_head, "net-observer");

        // Fresh SKIP-only -> hollow, and the head says why.
        let skip_only = StatusSnapshot {
            probing: ProbingTier::Passive,
            ..fresh(Some(link(GwVerdict::Skip)), Some(proxy(None, Some("auto"))))
        };
        let p = presentation(None, &skip_only, NOW_US);
        assert_eq!(p.glyph, "\u{25CC}");
        assert_eq!(
            p.tooltip_head,
            "no verdict — probing passive (gw SKIP, tun not probed)"
        );
        assert!(p.tooltip_body.is_some());
    }

    /// A daemon that answers but whose last tick is 40 s old is presented as
    /// offline — the grey dot and a "last tick" line, the stale health kept out
    /// of the tooltip — whatever that stale health was
    /// (realm net-observer, node #88).
    #[test]
    fn presentation_treats_a_stale_snapshot_as_offline() {
        let stale_ok = StatusSnapshot {
            generated_us: NOW_US - 40_000_000,
            link: Some(link(GwVerdict::Ok)),
            proxy: Some(proxy(Some(204), None)),
            ..Default::default()
        };
        let p = presentation(None, &stale_ok, NOW_US);
        assert_eq!(p.glyph, "\u{26AB}");
        assert_eq!(p.tooltip_head, "net-observer offline\nlast tick 40 s ago");
        assert_eq!(p.tooltip_body, None);
        assert_eq!(p.tooltip(), "net-observer offline\nlast tick 40 s ago");

        // Exactly at the bound is still fresh; one microsecond past it is not.
        let at_bound = StatusSnapshot {
            generated_us: NOW_US - STALE_AFTER.as_micros() as i64,
            ..stale_ok.clone()
        };
        assert_eq!(presentation(None, &at_bound, NOW_US).glyph, "🟢");
        let past_bound = StatusSnapshot {
            generated_us: at_bound.generated_us - 1,
            ..stale_ok.clone()
        };
        assert_eq!(presentation(None, &past_bound, NOW_US).glyph, "\u{26AB}");

        // A pause outranks staleness: a paused daemon stops ticking by design.
        let stale_paused = StatusSnapshot {
            observing: false,
            ..stale_ok
        };
        assert_eq!(presentation(None, &stale_paused, NOW_US).glyph, "\u{23F8}");
    }

    /// A daemon that has never ticked (`generated_us` still 0, its starting
    /// value) has no tick to date: it is a hollow "no verdict", not a grey
    /// "offline" dated to the epoch.
    #[test]
    fn presentation_does_not_date_a_daemon_that_never_ticked() {
        let p = presentation(None, &StatusSnapshot::default(), NOW_US);
        assert_eq!(p.glyph, "\u{25CC}");
        assert_eq!(p.tooltip_head, "no verdict — no link or proxy tick yet");
    }
}
