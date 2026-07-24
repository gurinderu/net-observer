use crate::probes::{ProxyFacts, TcpProber};
use types::{ProxySample, TcpVerdict};

/// Pure mapping: one [`ProxySample`] per VLESS server, with the shared
/// `tun_code`/`selector` attached to every row. Emits a single `SKIP` row when
/// no servers are configured (absence of a signal is itself diagnostic).
pub fn build_proxy_samples(
    ts_us: i64,
    tcp: &dyn TcpProber,
    facts: &dyn ProxyFacts,
    tun_url: &str,
    iface: &str,
) -> Vec<ProxySample> {
    let tun_code = facts.tun_probe(tun_url);
    let selector = facts.selector();
    let ips = facts.vless_ips();
    if ips.is_empty() {
        return vec![ProxySample {
            ts_us,
            server_ip: "-".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code,
            selector,
        }];
    }
    ips.into_iter()
        .map(|ip| {
            let o = tcp.connect_bound(&ip, 443, iface);
            ProxySample {
                ts_us,
                server_ip: ip,
                tcp: if o.reachable {
                    TcpVerdict::Ok
                } else {
                    TcpVerdict::Fail
                },
                rtt_ms: o.rtt_ms,
                tun_code,
                selector: selector.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::*;
    use types::TcpVerdict;
    struct T(bool);
    impl TcpProber for T {
        fn connect_bound(&self, _: &str, _: u16, _: &str) -> PingOutcome {
            PingOutcome {
                reachable: self.0,
                rtt_ms: Some(9.0),
            }
        }
    }
    struct F;
    impl ProxyFacts for F {
        fn vless_ips(&self) -> Vec<String> {
            vec!["1.1.1.1".into(), "2.2.2.2".into()]
        }
        fn tun_probe(&self, _: &str) -> Option<u16> {
            Some(204)
        }
        fn selector(&self) -> Option<String> {
            Some("node-a".into())
        }
    }
    #[test]
    fn one_row_per_server_with_tun_and_selector() {
        let rows = build_proxy_samples(7, &T(true), &F, "http://x/204", "en0");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.tcp == TcpVerdict::Ok
            && r.tun_code == Some(204)
            && r.selector.as_deref() == Some("node-a")));
    }
    #[test]
    fn skip_verdict_when_no_servers() {
        struct Empty;
        impl ProxyFacts for Empty {
            fn vless_ips(&self) -> Vec<String> {
                vec![]
            }
            fn tun_probe(&self, _: &str) -> Option<u16> {
                None
            }
            fn selector(&self) -> Option<String> {
                None
            }
        }
        let rows = build_proxy_samples(7, &T(false), &Empty, "http://x/204", "en0");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tcp, TcpVerdict::Skip);
    }
}
