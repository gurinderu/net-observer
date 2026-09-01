//! Pure render layer for `net-observer-bar`: turn an [`net_observer_ipc::StatusSnapshot`]
//! (fetched live from `net-observerd` over the local socket) into the menu-bar health
//! dot (and the retained compact glyph), the health classification, and the
//! multi-line tooltip/panel text.
//!
//! This is the load-bearing, unit-tested part of the menu-bar app. It is pure
//! over its input — no DB, no socket, no GUI — so every renderer is tested here
//! against synthetic [`StatusSnapshot`]s. The bar no longer touches DuckDB at
//! all: the daemon is the sole DB owner and serves the snapshot from memory (see
//! [`crate::ui::read_fresh`], which calls [`net_observer_ipc::query`]).

use net_observer_ipc::StatusSnapshot;
use types::GwVerdict;

/// Render a [`StatusSnapshot`] as a compact, human-readable multi-line glance.
/// Pure over its input so it can be unit-tested without a socket or a GUI.
pub fn render_status(snap: &StatusSnapshot) -> String {
    let mut out = String::from("net-observer\n");

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
            out.push_str(&format!(
                "proxy  tun={tun} selector={sel} ts_us={}\n",
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

/// The three-state health of a [`StatusSnapshot`], derived from the gateway
/// verdict and the tun probe code. The single source of truth for both the
/// menu-bar dot ([`status_dot`]) and the panel's header dot
/// (`ui::health_dot`), so the two can never drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// No link and no proxy tick yet — nothing to judge.
    NoData,
    /// Gateway `OK` and the tun probe returned HTTP 204.
    Ok,
    /// Gateway or tun is bad / degraded.
    Bad,
}

/// Classify a [`StatusSnapshot`] into a [`Health`]: [`Health::NoData`] when there
/// is no link *and* no proxy tick (and when the gateway verdict is `SKIP` — quiet
/// mode — while the tun is healthy: nothing was measured at the gateway, so there
/// is no verdict to give), [`Health::Ok`] when the gateway verdict is
/// `OK` *and* the tun probe returned HTTP 204 (the healthy reachability code),
/// and [`Health::Bad`] otherwise (gw or tun bad / degraded — e.g. tun `0` =
/// wedge). Pure over its input, so it is unit-tested without a socket or a GUI.
pub fn health(snap: &StatusSnapshot) -> Health {
    if snap.link.is_none() && snap.proxy.is_none() {
        return Health::NoData;
    }
    // A `SKIP` gateway is quiet mode: the echo was deliberately not sent, so
    // there is no gateway verdict to judge. Calling that red would be a false
    // alarm about the network and calling it green would be a claim we did not
    // measure — so unless the tun is independently bad, the dot goes to
    // `NoData`, the "no verdict" state.
    if snap.link.as_ref().is_some_and(|l| l.gw == GwVerdict::Skip) {
        let tun_ok = snap.proxy.as_ref().and_then(|p| p.tun_code) == Some(204);
        return if tun_ok { Health::NoData } else { Health::Bad };
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
/// - white (`⚪`) when there is no data at all yet ([`Health::NoData`]).
///
/// This is what the menu-bar title shows (icon-only, Tailscale-style). Pure over
/// its input, so it is unit-tested without a socket or a GUI. The daemon-down
/// "offline" state is rendered separately by the shell (see [`crate::menubar`]);
/// this dot describes a live snapshot only.
pub fn status_dot(snap: &StatusSnapshot) -> &'static str {
    match health(snap) {
        Health::NoData => "⚪",
        Health::Ok => "🟢",
        Health::Bad => "🔴",
    }
}

/// A compact, single-line health glyph derived from a [`StatusSnapshot`]: the
/// [`status_dot`] plus `gw:<verdict> tun:<code>`. Pure over its input so it can
/// be unit-tested without a socket or a GUI.
///
/// The dot follows [`health`], the shared classifier the panel header dot uses.
/// The daemon-down "offline" state is rendered separately by the shell (see
/// [`crate::menubar`]); this glyph describes a live snapshot only.
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
            wifi_capture_present: false,
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

    /// Quiet mode (`gw = SKIP`) is not a fault: with the tun healthy the dot is
    /// the "no verdict" one, not red — and not green either, since nothing at the
    /// gateway was measured.
    #[test]
    fn skip_gateway_is_no_verdict_not_a_fault() {
        let quiet = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(Some(204), Some("auto"))),
            quiet: true,
            ..Default::default()
        };
        assert_eq!(health(&quiet), Health::NoData);
        // A wedged tun is still a fault while quiet.
        let wedged = StatusSnapshot {
            link: Some(link(GwVerdict::Skip)),
            proxy: Some(proxy(Some(0), None)),
            quiet: true,
            ..Default::default()
        };
        assert_eq!(health(&wedged), Health::Bad);
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
    fn glyph_white_and_placeholders_when_no_data() {
        assert_eq!(status_glyph(&StatusSnapshot::default()), "⚪ gw:? tun:-");
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

    #[test]
    fn status_dot_maps_each_health_to_its_dot() {
        // NoData -> white.
        assert_eq!(status_dot(&StatusSnapshot::default()), "⚪");

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
        assert!(out.contains("gw=OK direct=OK"));
        assert!(out.contains("tun=204 selector=auto"));
        assert!(out.contains("wedge opened=80 closed=open"));
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
}
