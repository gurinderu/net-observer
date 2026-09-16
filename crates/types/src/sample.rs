use serde::{Deserialize, Serialize};

use crate::air::AirSample;
use crate::connection::ConnectionsSample;
use crate::neighbor::NeighborsSample;
use crate::verdict::{DnsVerdict, GwVerdict, LinkMedium, TcpVerdict, WifiVerdict};

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
    /// BSSID of the access point currently associated on the link interface
    /// (`ipconfig getsummary <iface>`), lowercase `aa:bb:cc:dd:ee:ff`. `None` =
    /// not associated or not determinable — never a fabricated value. A change
    /// of BSSID at the same SSID is a roam (band steering / twin SSIDs), which
    /// the SSID alone cannot show (realm net-observer, node #59).
    /// `serde(default)` so a pre-field daemon's samples still decode.
    #[serde(default)]
    pub bssid: Option<String>,
    /// The link interface's OWN MAC as currently assigned (`ifconfig <iface>`
    /// `ether` line), lowercase. Private Wi-Fi Address rotates it per SSID, so
    /// a change here is a new DHCP identity toward the network (realm
    /// net-observer, node #59). `serde(default)` as above.
    #[serde(default)]
    pub if_mac: Option<String>,
    /// The medium of the default-route interface this sample describes —
    /// the interface `if_mac` belongs to — measured from the hardware-port
    /// table each tick ([`LinkMedium`]). `None` = not determinable (the port
    /// table could not be read, or does not list the interface); the sample
    /// still lacks the interface name itself. The identity rules judge the
    /// `if_mac` comparison by this, never by whether an SSID or BSSID was
    /// readable: under root neither is (realm net-observer, nodes #93,
    /// #108). `serde(default)` so a pre-field daemon's samples still decode.
    #[serde(default)]
    pub medium: Option<LinkMedium>,
    pub wifi_capture_present: bool,
    /// Probe-on-suspicion: how many LAN neighbors were pinged on this tick.
    /// Measured only when the gateway verdict is `Fail`; `None` = not probed
    /// (healthy gateway, quiet mode, or no gateway) — never a zero.
    /// `serde(default)` so a pre-field daemon's samples still decode.
    #[serde(default)]
    pub lan_probed: Option<u16>,
    /// Probe-on-suspicion: how many of the pinged neighbors answered. `None`
    /// exactly when `lan_probed` is.
    #[serde(default)]
    pub lan_alive: Option<u16>,
    /// The egress interface the route table resolves for an address inside the
    /// sing-box fakeip pool (a local lookup, no packet sent). A fakeip answer
    /// is only meaningful inside the tunnel, so anything but a `utun*` here is
    /// the hijack signature. `None` = could not be determined (no config, no
    /// range, no route). `serde(default)` so a pre-field daemon's samples
    /// still decode.
    #[serde(default)]
    pub fakeip_route_if: Option<String>,
    /// The interface carrying sing-box's OWN TUN address (from the rendered
    /// config; a local read, no packet sent). That address is assigned only
    /// while sing-box runs, so `Some(_)` is the sing-box-alive fact the
    /// `fakeip-hijack` signature compares its pool egress against — same tick,
    /// no cross-sample skew. NOT "any `utun*`": a foreign VPN's utun would not
    /// carry this address. `None` = sing-box's TUN is not up. `serde(default)`
    /// so a pre-field daemon's samples still decode.
    #[serde(default)]
    pub singbox_tun_if: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProxySample {
    pub ts_us: i64,
    pub server_ip: String,
    pub tcp: TcpVerdict,
    pub rtt_ms: Option<f64>,
    pub tun_code: Option<u16>,
    pub selector: Option<String>,
    /// Established-flow discriminator, a per-tick fact replicated across the
    /// tick's rows like `tun_code`: whether the held reference stream bound to
    /// the physical interface (the direct underlay path) still round-tripped
    /// data this tick. `None` = no measurement (the stream was only just
    /// opened, or could not be opened). `serde(default)` so a pre-field
    /// daemon's samples still decode.
    #[serde(default)]
    pub est_direct_alive: Option<bool>,
    /// Age of the direct held stream at the check, seconds. `Some` exactly
    /// when `est_direct_alive` is — on a dead check it is the age at death.
    #[serde(default)]
    pub est_direct_age_s: Option<u32>,
    /// Same discriminator for the held stream on the default route (through
    /// the TUN while sing-box is up): the established proxied flow.
    #[serde(default)]
    pub est_tun_alive: Option<bool>,
    /// Age of the tunnel held stream at the check, seconds.
    #[serde(default)]
    pub est_tun_age_s: Option<u32>,
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

/// Host resource sample: load averages (1/5/15-min) — the starvation
/// discriminator — plus the usage of the volume holding the record and the
/// swap in use, the ENOSPC and memory-pressure discriminators the retired
/// shell oracle carried (the oracle backlog: realm net-observer, node #114),
/// measured as decided at node #123. A store write that fails for want of
/// space is logged as a gap; this is the row that lets the record name the
/// cause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostSample {
    pub ts_us: i64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    /// Used fraction of the filesystem holding the record (the DB file's
    /// volume), 0–100, as `df` computes capacity. `None` = not measured —
    /// never a fabricated value (realm net-observer, node #123).
    /// `serde(default)` so a pre-field daemon's samples still decode.
    #[serde(default)]
    pub disk_used_pct: Option<f64>,
    /// Free MiB on that same filesystem, available to a writer. `None`
    /// = not measured; `Some` exactly when `disk_used_pct` is.
    #[serde(default)]
    pub disk_free_mb: Option<u64>,
    /// Swap in use, MiB. `None` = not measured (realm net-observer,
    /// node #123). `serde(default)` as above.
    #[serde(default)]
    pub swap_used_mb: Option<u64>,
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
/// which a LaunchDaemon cannot obtain; the `link` collector reads both from the
/// command-line tools instead ([`LinkSample::ssid`], [`LinkSample::bssid`]).
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
    /// One scan of the radio environment — the foreign access points audible
    /// here. Its own slow period, not the tick: the scan costs seconds
    /// (realm net-observer, node #47).
    Air(AirSample),
    /// One tick of the live flow table — what this machine talks to, as the
    /// proxy's API lists it, aggregated per destination (realm net-observer,
    /// node #75).
    Connections(ConnectionsSample),
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
            Sample::Air(a) => a.ts_us,
            Sample::Connections(c) => c.ts_us,
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
            bssid: None,
            if_mac: None,
            medium: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        });
        assert_eq!(l.ts_us(), 42);

        let p = Sample::Proxy(ProxySample {
            ts_us: 99,
            server_ip: "1.2.3.4".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
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
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
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

        let a = Sample::Air(crate::AirSample {
            ts_us: 37,
            air: crate::AirVerdict::Ok,
            reason: None,
            aps: vec![crate::AirObservation {
                channel: Some(44),
                channel_band: Some("5ghz".into()),
                channel_width_mhz: Some(80),
                phy_mode: Some("802.11a/n/ac/ax".into()),
                security: Some("wpa2_personal".into()),
                rssi_dbm: Some(-72),
                noise_dbm: Some(-95),
            }],
        });
        assert_eq!(a.ts_us(), 37);

        let c = Sample::Connections(crate::ConnectionsSample {
            ts_us: 41,
            verdict: crate::ConnectionsVerdict::Skip,
            rows: Vec::new(),
        });
        assert_eq!(c.ts_us(), 41);
    }

    /// A host sample written by a daemon that shipped before the disk and swap
    /// columns existed carries only the load triple; it must still decode,
    /// with the new fields reading as "not measured" rather than failing.
    #[test]
    fn pre_disk_host_sample_decodes_with_unmeasured_disk_and_swap() {
        let older = r#"{"ts_us":23,"load1":1.0,"load5":2.0,"load15":3.0}"#;
        let h: HostSample = serde_json::from_str(older).expect("older host sample must decode");
        assert_eq!(
            h,
            HostSample {
                ts_us: 23,
                load1: 1.0,
                load5: 2.0,
                load15: 3.0,
                disk_used_pct: None,
                disk_free_mb: None,
                swap_used_mb: None,
            }
        );
    }

    #[test]
    fn now_us_is_positive() {
        assert!(now_us() > 0);
    }
}
