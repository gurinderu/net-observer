use crate::probes::{LinkFacts, Pinger, TcpProber};
use types::{GwVerdict, LinkSample, TcpVerdict};

/// Pure mapping from probe outcomes + link facts to a [`LinkSample`].
pub fn build_link_sample(
    ts_us: i64,
    ping: &dyn Pinger,
    tcp: &dyn TcpProber,
    facts: &dyn LinkFacts,
) -> LinkSample {
    let gw_addr = facts.default_gw();
    let iface = facts.phys_iface().unwrap_or_default();
    let (gw, gw_rtt_ms) = match &gw_addr {
        None => (GwVerdict::NoGw, None),
        Some(a) => {
            let o = ping.ping_gw(a);
            (
                if o.reachable {
                    GwVerdict::Ok
                } else {
                    GwVerdict::Fail
                },
                o.rtt_ms,
            )
        }
    };
    let d = tcp.connect_bound("1.1.1.1", 443, &iface);
    let (direct, direct_rtt_ms) = (
        if d.reachable {
            TcpVerdict::Ok
        } else {
            TcpVerdict::Fail
        },
        d.rtt_ms,
    );
    let (dhcp_router, dhcp_dns) = facts.dhcp();
    LinkSample {
        ts_us,
        gw,
        gw_rtt_ms,
        direct,
        direct_rtt_ms,
        dhcp_router,
        dhcp_dns,
        gw_arp_mac: gw_addr.as_deref().and_then(|a| facts.gw_arp_mac(a)),
        ssid: facts.ssid(),
        wifi_capture_present: facts.wifi_capture_present(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::*;
    use types::{GwVerdict, TcpVerdict};

    struct FakePing(bool);
    impl Pinger for FakePing {
        fn ping_gw(&self, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: self.0,
                rtt_ms: self.0.then_some(2.0),
            }
        }
    }
    struct FakeTcp(bool);
    impl TcpProber for FakeTcp {
        fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: self.0,
                rtt_ms: None,
            }
        }
    }
    struct FakeFacts {
        gw: Option<String>,
    }
    impl LinkFacts for FakeFacts {
        fn default_gw(&self) -> Option<String> {
            self.gw.clone()
        }
        fn phys_iface(&self) -> Option<String> {
            Some("en0".into())
        }
        fn dhcp(&self) -> (Option<String>, Option<String>) {
            (Some("10.20.0.1".into()), None)
        }
        fn gw_arp_mac(&self, _: &str) -> Option<String> {
            Some("aa:bb".into())
        }
        fn ssid(&self) -> Option<String> {
            Some("cowork".into())
        }
        fn wifi_capture_present(&self) -> bool {
            false
        }
    }

    #[test]
    fn no_gw_when_facts_have_none() {
        let s = build_link_sample(1, &FakePing(false), &FakeTcp(true), &FakeFacts { gw: None });
        assert_eq!(s.gw, GwVerdict::NoGw);
        assert_eq!(s.direct, TcpVerdict::Ok);
    }
    #[test]
    fn gw_fail_when_ping_fails() {
        let s = build_link_sample(
            1,
            &FakePing(false),
            &FakeTcp(true),
            &FakeFacts {
                gw: Some("10.20.0.1".into()),
            },
        );
        assert_eq!(s.gw, GwVerdict::Fail);
    }
    #[test]
    fn gw_ok_when_ping_succeeds() {
        let s = build_link_sample(
            1,
            &FakePing(true),
            &FakeTcp(false),
            &FakeFacts {
                gw: Some("10.20.0.1".into()),
            },
        );
        assert_eq!(s.gw, GwVerdict::Ok);
        assert_eq!(s.direct, TcpVerdict::Fail);
    }
}
