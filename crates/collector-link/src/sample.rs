use collector_core::PingOutcome;
use types::{GwVerdict, LinkMedium, LinkSample, TcpVerdict};

/// Pure, SYNC mapping from fetched probe outcomes + link facts to a [`LinkSample`].
///
/// `collect()` `await`s the probes/facts, then hands the fetched values here so
/// the assembly stays trivially testable while async lives only in the ports.
/// `ping` is the gateway echo outcome (ignored when `gw_addr` is `None` — that is
/// the `NoGw` case); `direct` is the iface-bound TCP outcome; `dhcp` is the
/// `(router, dns)` lease pair; `arp` is the gateway's ARP MAC.
///
/// A probe arrives as `None` when it was deliberately NOT sent — the gateway
/// echo under quiet or in the passive tier, the direct probe in the passive tier
/// (realm net-observer, node #88) — and its verdict is then `SKIP` with no RTT.
/// The decision to withhold is the collector's; this mapping only reports it.
/// The sample is still produced — SKIP, never silence — and every passive fact
/// (DHCP lease, ARP, SSID) still flows through, because reading them puts
/// nothing on the wire.
///
/// `lan` is the probe-on-suspicion `(probed, alive)` neighbor-ping count pair,
/// already gathered by `collect()` on a gateway-FAIL tick and `(None, None)`
/// otherwise; it flows through untouched like the other fetched facts.
/// `fakeip_route_if` is the egress interface the route table resolves for a
/// fakeip-pool address and `singbox_tun_if` the interface carrying sing-box's
/// own TUN address (`None` = could not be determined / sing-box not up),
/// equally untouched. `bssid` and `if_mac` are the link's identity pair — the
/// AP associated with and the interface's own (rotating) MAC — passed through
/// as read, `None` meaning not determinable, never a fabricated value.
#[allow(clippy::too_many_arguments)]
pub fn build_link_sample(
    ts_us: i64,
    ping: Option<PingOutcome>,
    direct: Option<PingOutcome>,
    gw_addr: Option<String>,
    dhcp: (Option<String>, Option<String>),
    arp: Option<String>,
    lan: (Option<u16>, Option<u16>),
    fakeip_route_if: Option<String>,
    singbox_tun_if: Option<String>,
    ssid: Option<String>,
    bssid: Option<String>,
    if_mac: Option<String>,
    medium: Option<LinkMedium>,
    wifi_present: bool,
) -> LinkSample {
    let (gw, gw_rtt_ms) = match (&gw_addr, ping) {
        (None, _) => (GwVerdict::NoGw, None),
        // Withheld outranks any outcome: no packet was sent, so there is no
        // measurement to report either way.
        (Some(_), None) => (GwVerdict::Skip, None),
        (Some(_), Some(ping)) => (
            if ping.reachable {
                GwVerdict::Ok
            } else {
                GwVerdict::Fail
            },
            ping.rtt_ms,
        ),
    };
    let (direct_verdict, direct_rtt_ms) = match direct {
        None => (TcpVerdict::Skip, None),
        Some(direct) => (
            if direct.reachable {
                TcpVerdict::Ok
            } else {
                TcpVerdict::Fail
            },
            direct.rtt_ms,
        ),
    };
    let (dhcp_router, dhcp_dns) = dhcp;
    let (lan_probed, lan_alive) = lan;
    LinkSample {
        ts_us,
        gw,
        gw_rtt_ms,
        direct: direct_verdict,
        direct_rtt_ms,
        dhcp_router,
        dhcp_dns,
        gw_arp_mac: arp,
        ssid,
        bssid,
        if_mac,
        medium,
        wifi_capture_present: wifi_present,
        lan_probed,
        lan_alive,
        fakeip_route_if,
        singbox_tun_if,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{GwVerdict, TcpVerdict};

    fn outcome(reachable: bool) -> Option<PingOutcome> {
        Some(PingOutcome {
            reachable,
            rtt_ms: reachable.then_some(2.0),
        })
    }

    #[test]
    fn no_gw_when_addr_is_none() {
        let s = build_link_sample(
            1,
            outcome(false),
            outcome(true),
            None,
            (Some("10.20.0.1".into()), None),
            None,
            (None, None),
            None,
            None,
            Some("cowork".into()),
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::NoGw);
        assert_eq!(s.gw_rtt_ms, None);
        assert_eq!(s.direct, TcpVerdict::Ok);
    }

    #[test]
    fn gw_fail_when_ping_fails() {
        let s = build_link_sample(
            1,
            outcome(false),
            outcome(true),
            Some("10.20.0.1".into()),
            (None, None),
            Some("aa:bb".into()),
            (Some(3), Some(2)),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::Fail);
        assert_eq!(s.lan_probed, Some(3));
        assert_eq!(s.lan_alive, Some(2));
    }

    #[test]
    fn gw_ok_when_ping_succeeds() {
        let s = build_link_sample(
            1,
            outcome(true),
            outcome(false),
            Some("10.20.0.1".into()),
            (None, None),
            Some("aa:bb".into()),
            (None, None),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::Ok);
        assert_eq!(s.direct, TcpVerdict::Fail);
    }

    /// A withheld echo (quiet, or the passive tier) suppresses the gateway
    /// verdict, not the sample: the gateway reads `SKIP` with no RTT while
    /// every passive fact still flows through.
    #[test]
    fn a_withheld_echo_skips_the_gateway_verdict_but_still_emits_a_sample() {
        let s = build_link_sample(
            3,
            None,
            outcome(true),
            Some("10.20.0.1".into()),
            (Some("10.20.0.1".into()), None),
            Some("aa:bb:cc".into()),
            (None, None),
            None,
            None,
            Some("cowork".into()),
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::Skip);
        assert_eq!(s.gw_rtt_ms, None);
        // The passive half of the tick is untouched.
        assert_eq!(s.direct, TcpVerdict::Ok);
        assert_eq!(s.gw_arp_mac.as_deref(), Some("aa:bb:cc"));
        assert_eq!(s.dhcp_router.as_deref(), Some("10.20.0.1"));
    }

    /// The passive tier withholds the direct probe too: it reads `SKIP` with
    /// no RTT, and the passive facts still land.
    #[test]
    fn a_withheld_direct_probe_reads_skip_with_no_rtt() {
        let s = build_link_sample(
            5,
            None,
            None,
            Some("10.20.0.1".into()),
            (Some("10.20.0.1".into()), None),
            Some("aa:bb:cc".into()),
            (None, None),
            Some("utun8".into()),
            Some("utun8".into()),
            Some("cowork".into()),
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::Skip);
        assert_eq!(s.direct, TcpVerdict::Skip);
        assert_eq!(s.direct_rtt_ms, None);
        assert_eq!(s.gw_arp_mac.as_deref(), Some("aa:bb:cc"));
        assert_eq!(s.fakeip_route_if.as_deref(), Some("utun8"));
    }

    /// A withheld echo does not invent a gateway: with no default route the
    /// verdict stays `NOGW`, the fact that there is nothing to probe.
    #[test]
    fn a_withheld_echo_with_no_gateway_is_still_nogw() {
        let s = build_link_sample(
            4,
            None,
            outcome(true),
            None,
            (None, None),
            None,
            (None, None),
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::NoGw);
    }

    #[test]
    fn facts_flow_through_untouched() {
        let s = build_link_sample(
            7,
            outcome(true),
            outcome(true),
            Some("10.20.0.1".into()),
            (Some("10.20.0.1".into()), Some("1.1.1.1".into())),
            Some("aa:bb:cc".into()),
            (None, None),
            Some("awdl0".into()),
            Some("utun6".into()),
            Some("cowork".into()),
            Some("3c:22:fb:12:34:56".into()),
            Some("f0:18:98:0a:0b:0c".into()),
            Some(LinkMedium::Wifi),
            true,
        );
        assert_eq!(s.ts_us, 7);
        assert_eq!(s.dhcp_router.as_deref(), Some("10.20.0.1"));
        assert_eq!(s.dhcp_dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(s.gw_arp_mac.as_deref(), Some("aa:bb:cc"));
        assert_eq!(s.fakeip_route_if.as_deref(), Some("awdl0"));
        assert_eq!(s.singbox_tun_if.as_deref(), Some("utun6"));
        assert_eq!(s.ssid.as_deref(), Some("cowork"));
        assert_eq!(s.bssid.as_deref(), Some("3c:22:fb:12:34:56"));
        assert_eq!(s.if_mac.as_deref(), Some("f0:18:98:0a:0b:0c"));
        assert_eq!(s.medium, Some(LinkMedium::Wifi));
        assert!(s.wifi_capture_present);
    }

    /// The identity pair is passed through as read: an undeterminable BSSID or
    /// interface MAC stays `None` — never a placeholder that a later roam
    /// comparison could mistake for a real address.
    #[test]
    fn an_undeterminable_identity_stays_none() {
        let s = build_link_sample(
            8,
            outcome(true),
            outcome(true),
            Some("10.20.0.1".into()),
            (None, None),
            None,
            (None, None),
            None,
            None,
            Some("cowork".into()),
            None,
            None,
            None,
            false,
        );
        assert_eq!(s.ssid.as_deref(), Some("cowork"));
        assert_eq!(s.bssid, None);
        assert_eq!(s.if_mac, None);
        assert_eq!(s.medium, None);
    }
}
