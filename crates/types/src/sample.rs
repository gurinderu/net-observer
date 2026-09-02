use serde::{Deserialize, Serialize};

use crate::neighbor::NeighborsSample;
use crate::verdict::{DnsVerdict, GwVerdict, TcpVerdict, WifiVerdict};

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

/// One resolver probe. `probe` is the queried name label (e.g. "nks"), `server`
/// the resolver path label ("sb" | "rtr" | "doh" | "ru"), per the oracle's DNS columns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsSample {
    pub ts_us: i64,
    pub probe: String,
    pub server: String,
    pub verdict: DnsVerdict,
    pub ip: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// A kernel routing-socket event (PF_ROUTE): iface up/down, addr add/loss, default-route change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteEvent {
    pub ts_us: i64,
    pub kind: String, // "iface" | "addr" | "route"
    pub iface: Option<String>,
    pub detail: String,
}

/// Host load sample (1/5/15-min averages) — the starvation discriminator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostSample {
    pub ts_us: i64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}

/// Wi-Fi air quality for one tick, read from CoreWLAN.
///
/// The gateway going quiet and the *air* going quiet are different failures: in a
/// saturated coworking channel the link stays associated and the signal looks
/// fine while the transmit window never arrives. Nothing else the daemon collects
/// sees that.
///
/// `rssi_dbm` and `noise_dbm` are kept as the **raw pair** and `snr_db` is derived
/// from them (`rssi - noise`), never the other way round: RSSI alone barely moves
/// until the link is already gone, while the margin over the noise floor degrades
/// earlier — and keeping both means the derivation can be revisited without
/// losing the measurement.
///
/// Every field is independently optional: an API that declines one value yields
/// `None` for it inside an otherwise `OK` sample. When the probe could not run at
/// all, `wifi` is [`WifiVerdict::Skip`] and `reason` says why — a SKIP row every
/// tick, never an absent one.
///
/// SSID/BSSID are deliberately absent. macOS gates them behind Location Services,
/// which a LaunchDaemon cannot obtain; the SSID is collected by the `link`
/// collector instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiSample {
    pub ts_us: i64,
    pub wifi: WifiVerdict,
    /// Why the probe could not run. `Some` iff `wifi == Skip`.
    pub reason: Option<String>,
    /// Received signal strength, dBm (negative).
    pub rssi_dbm: Option<i32>,
    /// Noise floor, dBm (negative).
    pub noise_dbm: Option<i32>,
    /// Derived: `rssi_dbm - noise_dbm`, `Some` only when both raw values are.
    pub snr_db: Option<i32>,
    /// Negotiated transmit rate, Mbps.
    pub tx_rate_mbps: Option<f64>,
    /// Active PHY mode label ("11a"/"11b"/"11g"/"11n"/"11ac"/"11ax").
    pub phy_mode: Option<String>,
    /// Channel number (e.g. 48).
    pub channel: Option<i32>,
    /// Channel width in MHz (20/40/80/160).
    pub channel_width_mhz: Option<i32>,
    /// Band label ("2ghz"/"5ghz"/"6ghz").
    pub channel_band: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Sample {
    Link(LinkSample),
    Proxy(ProxySample),
    Dns(DnsSample),
    Route(RouteEvent),
    Host(HostSample),
    Wifi(WifiSample),
    Neighbors(NeighborsSample),
}

impl Sample {
    pub fn ts_us(&self) -> i64 {
        match self {
            Sample::Link(l) => l.ts_us,
            Sample::Proxy(p) => p.ts_us,
            Sample::Dns(d) => d.ts_us,
            Sample::Route(r) => r.ts_us,
            Sample::Host(h) => h.ts_us,
            Sample::Wifi(w) => w.ts_us,
            Sample::Neighbors(n) => n.ts_us,
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
    use crate::{DnsVerdict, GwVerdict, TcpVerdict};

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

        let d = Sample::Dns(DnsSample {
            ts_us: 7,
            probe: "nks".into(),
            server: "sb".into(),
            verdict: DnsVerdict::FakeIp,
            ip: Some("198.18.0.1".into()),
            rtt_ms: Some(3.0),
        });
        assert_eq!(d.ts_us(), 7);

        let r = Sample::Route(RouteEvent {
            ts_us: 11,
            kind: "iface".into(),
            iface: Some("en0".into()),
            detail: "up".into(),
        });
        assert_eq!(r.ts_us(), 11);

        let h = Sample::Host(HostSample {
            ts_us: 23,
            load1: 1.0,
            load5: 2.0,
            load15: 3.0,
        });
        assert_eq!(h.ts_us(), 23);

        let w = Sample::Wifi(WifiSample {
            ts_us: 31,
            wifi: crate::WifiVerdict::Ok,
            reason: None,
            rssi_dbm: Some(-53),
            noise_dbm: Some(-96),
            snr_db: Some(43),
            tx_rate_mbps: Some(270.0),
            phy_mode: Some("11ax".into()),
            channel: Some(48),
            channel_width_mhz: Some(20),
            channel_band: Some("5ghz".into()),
        });
        assert_eq!(w.ts_us(), 31);
    }

    #[test]
    fn now_us_is_positive() {
        assert!(now_us() > 0);
    }
}
