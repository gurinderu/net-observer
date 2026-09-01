use collector_core::PingOutcome;
use types::{GwVerdict, LinkSample, TcpVerdict};

/// Pure, SYNC mapping from fetched probe outcomes + link facts to a [`LinkSample`].
///
/// `collect()` `await`s the probes/facts, then hands the fetched values here so
/// the assembly stays trivially testable while async lives only in the ports.
/// `ping` is the gateway echo outcome (ignored when `gw_addr` is `None` — that is
/// the `NoGw` case); `direct` is the iface-bound TCP outcome; `dhcp` is the
/// `(router, dns)` lease pair; `arp` is the gateway's ARP MAC.
///
/// `quiet` is the operator's "address no packet AT the gateway" switch: the echo
/// was deliberately not sent, so the verdict is [`GwVerdict::Skip`] with no RTT.
/// The sample is still produced — SKIP, never silence — and every passive fact
/// (DHCP lease, ARP, SSID) still flows through, because reading them addresses
/// the gateway with nothing.
#[allow(clippy::too_many_arguments)]
pub fn build_link_sample(
    ts_us: i64,
    ping: PingOutcome,
    direct: PingOutcome,
    quiet: bool,
    gw_addr: Option<String>,
    dhcp: (Option<String>, Option<String>),
    arp: Option<String>,
    ssid: Option<String>,
    wifi_present: bool,
) -> LinkSample {
    let (gw, gw_rtt_ms) = match &gw_addr {
        None => (GwVerdict::NoGw, None),
        // Quiet outranks the echo outcome: no packet was sent, so there is no
        // measurement to report either way.
        Some(_) if quiet => (GwVerdict::Skip, None),
        Some(_) => (
            if ping.reachable {
                GwVerdict::Ok
            } else {
                GwVerdict::Fail
            },
            ping.rtt_ms,
        ),
    };
    let (direct_verdict, direct_rtt_ms) = (
        if direct.reachable {
            TcpVerdict::Ok
        } else {
            TcpVerdict::Fail
        },
        direct.rtt_ms,
    );
    let (dhcp_router, dhcp_dns) = dhcp;
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
        wifi_capture_present: wifi_present,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{GwVerdict, TcpVerdict};

    fn outcome(reachable: bool) -> PingOutcome {
        PingOutcome {
            reachable,
            rtt_ms: reachable.then_some(2.0),
        }
    }

    #[test]
    fn no_gw_when_addr_is_none() {
        let s = build_link_sample(
            1,
            outcome(false),
            outcome(true),
            false,
            None,
            (Some("10.20.0.1".into()), None),
            None,
            Some("cowork".into()),
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
            false,
            Some("10.20.0.1".into()),
            (None, None),
            Some("aa:bb".into()),
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::Fail);
    }

    #[test]
    fn gw_ok_when_ping_succeeds() {
        let s = build_link_sample(
            1,
            outcome(true),
            outcome(false),
            false,
            Some("10.20.0.1".into()),
            (None, None),
            Some("aa:bb".into()),
            None,
            false,
        );
        assert_eq!(s.gw, GwVerdict::Ok);
        assert_eq!(s.direct, TcpVerdict::Fail);
    }

    /// Quiet suppresses the echo verdict, not the sample: the gateway reads
    /// `SKIP` with no RTT while every passive fact still flows through.
    #[test]
    fn quiet_skips_the_gateway_verdict_but_still_emits_a_sample() {
        let s = build_link_sample(
            3,
            outcome(true),
            outcome(true),
            true,
            Some("10.20.0.1".into()),
            (Some("10.20.0.1".into()), None),
            Some("aa:bb:cc".into()),
            Some("cowork".into()),
            false,
        );
        assert_eq!(s.gw, GwVerdict::Skip);
        assert_eq!(s.gw_rtt_ms, None);
        // The passive half of the tick is untouched.
        assert_eq!(s.direct, TcpVerdict::Ok);
        assert_eq!(s.gw_arp_mac.as_deref(), Some("aa:bb:cc"));
        assert_eq!(s.dhcp_router.as_deref(), Some("10.20.0.1"));
    }

    /// Quiet does not invent a gateway: with no default route the verdict stays
    /// `NOGW`, the fact that there is nothing to probe.
    #[test]
    fn quiet_with_no_gateway_is_still_nogw() {
        let s = build_link_sample(
            4,
            outcome(false),
            outcome(true),
            true,
            None,
            (None, None),
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
            false,
            Some("10.20.0.1".into()),
            (Some("10.20.0.1".into()), Some("1.1.1.1".into())),
            Some("aa:bb:cc".into()),
            Some("cowork".into()),
            true,
        );
        assert_eq!(s.ts_us, 7);
        assert_eq!(s.dhcp_router.as_deref(), Some("10.20.0.1"));
        assert_eq!(s.dhcp_dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(s.gw_arp_mac.as_deref(), Some("aa:bb:cc"));
        assert_eq!(s.ssid.as_deref(), Some("cowork"));
        assert!(s.wifi_capture_present);
    }
}
