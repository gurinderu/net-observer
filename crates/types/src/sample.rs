use serde::{Deserialize, Serialize};

use crate::verdict::{GwVerdict, TcpVerdict};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkSample {
    pub ts_us: i64,
    pub gw: GwVerdict,
    pub gw_rtt_ms: Option<f64>,
    pub direct: TcpVerdict,
    pub direct_rtt_ms: Option<f64>,
    pub dhcp_router: Option<String>,
    pub dhcp_dns: Option<String>,
    pub gw_arp_mac: Option<String>,
    pub ssid: Option<String>,
    pub wifi_capture_present: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxySample {
    pub ts_us: i64,
    pub server_ip: String,
    pub tcp: TcpVerdict,
    pub rtt_ms: Option<f64>,
    pub tun_code: Option<u16>,
    pub selector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Sample {
    Link(LinkSample),
    Proxy(ProxySample),
}

impl Sample {
    pub fn ts_us(&self) -> i64 {
        match self {
            Sample::Link(l) => l.ts_us,
            Sample::Proxy(p) => p.ts_us,
        }
    }
}

/// Current wall-clock time as epoch microseconds.
pub fn now_us() -> i64 {
    jiff::Timestamp::now().as_microsecond()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GwVerdict, TcpVerdict};

    #[test]
    fn sample_ts_dispatch() {
        let l = Sample::Link(LinkSample {
            ts_us: 42,
            gw: GwVerdict::Ok,
            gw_rtt_ms: Some(1.0),
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        });
        assert_eq!(l.ts_us(), 42);

        let p = Sample::Proxy(ProxySample {
            ts_us: 99,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
        });
        assert_eq!(p.ts_us(), 99);
    }

    #[test]
    fn now_us_is_positive() {
        assert!(now_us() > 0);
    }
}
