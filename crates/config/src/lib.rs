use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub db_path: String,
    pub blob_dir: String,
    /// Unix-domain socket the daemon binds and the bar connects to for live status.
    pub socket_path: String,
    /// Permission bits applied to the socket file (octal), so the unprivileged bar
    /// can connect while the daemon runs as root.
    pub socket_mode: u32,
    /// When `Some(uid)`, the daemon `chown`s the socket to this uid (control-path
    /// hardening: pair with a restrictive `socket_mode` such as `0o600` when
    /// enabling acting so only the owner can send privileged commands). Default
    /// `None` — the socket keeps the daemon's ownership.
    pub socket_owner_uid: Option<u32>,
    pub collectors: Collectors,
    /// The write/control ("acting") path. Disabled by default.
    pub acting: ActingCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collectors {
    pub link: LinkCfg,
    pub proxy: ProxyCfg,
    pub dns: DnsCfg,
    pub route: RouteCfg,
    pub host: HostCfg,
    pub pcap_ring: PcapCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub gw: Option<String>,
    pub phys_iface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub tun_probe_url: String,
    pub clash_api: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// The monitored service domain (the `nks[*]` probes resolve this).
    pub monitored_domain: String,
    /// A `.ru` control domain (the `ru[*]` probes resolve this); a fakeip answer
    /// on it is always a bug.
    pub ru_control_domain: String,
    /// DNS-over-HTTPS endpoint used by the `doh` resolver path.
    pub doh_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCfg {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapCfg {
    pub enabled: bool,
    pub ring_mb: u32,
    pub filter: String,
}

/// The write/control ("acting") path — manual recovery actions the daemon runs
/// as root. Disabled by default: with `enabled = false`, every control request
/// is refused without running anything. Acting NEVER happens automatically — only
/// on an explicit `Request::Control`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActingCfg {
    /// Master switch for the control path. `false` (default) ⇒ refuse every
    /// control request without executing anything.
    pub enabled: bool,
    /// The `launchctl` service target restarted by `ControlCmd::KickstartProxy`
    /// (`launchctl kickstart -k <service>`).
    pub singbox_service: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            db_path: "/var/lib/observer/observer.duckdb".into(),
            blob_dir: "/var/lib/observer/blobs".into(),
            socket_path: "/var/lib/observer/observer.sock".into(),
            socket_mode: 0o666,
            socket_owner_uid: None,
            collectors: Collectors {
                link: LinkCfg {
                    enabled: true,
                    interval: Duration::from_secs(15),
                    gw: None,
                    phys_iface: None,
                },
                proxy: ProxyCfg {
                    enabled: true,
                    interval: Duration::from_secs(15),
                    tun_probe_url: "http://connectivitycheck.gstatic.com/generate_204".into(),
                    clash_api: "http://127.0.0.1:9090".into(),
                },
                dns: DnsCfg {
                    enabled: true,
                    interval: Duration::from_secs(15),
                    monitored_domain: "nks.lab.mirari.ru".into(),
                    ru_control_domain: "ya.ru".into(),
                    doh_url: "https://1.1.1.1/dns-query".into(),
                },
                route: RouteCfg { enabled: true },
                host: HostCfg {
                    enabled: true,
                    interval: Duration::from_secs(15),
                },
                pcap_ring: PcapCfg {
                    enabled: true,
                    ring_mb: 8,
                    filter: "arp or icmp or udp port 67 or udp port 68 or ether broadcast".into(),
                },
            },
            acting: ActingCfg {
                enabled: false,
                singbox_service: "system/sing-box".into(),
            },
        }
    }
}

impl Config {
    // Signature is a fixed cross-crate interface (see plan Task 3), so the
    // large `figment::Error` cannot be boxed away here.
    #[allow(clippy::result_large_err)]
    pub fn load(path: Option<&str>) -> Result<Config, figment::Error> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = path {
            fig = fig.merge(Toml::file(p));
        }
        fig.merge(Env::prefixed("OBSERVER_").split("__")).extract()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_apply_when_file_absent() {
        let c = Config::load(None).unwrap();
        assert!(c.collectors.link.enabled);
        assert_eq!(c.collectors.link.interval.as_secs(), 15);
    }
    #[test]
    fn socket_defaults_apply() {
        let c = Config::load(None).unwrap();
        assert_eq!(c.socket_path, "/var/lib/observer/observer.sock");
        assert_eq!(c.socket_mode, 0o666);
    }
    #[test]
    fn dns_route_host_defaults_apply() {
        let c = Config::load(None).unwrap();
        assert!(c.collectors.dns.enabled);
        assert_eq!(c.collectors.dns.interval.as_secs(), 15);
        assert_eq!(c.collectors.dns.monitored_domain, "nks.lab.mirari.ru");
        assert_eq!(c.collectors.dns.ru_control_domain, "ya.ru");
        assert_eq!(c.collectors.dns.doh_url, "https://1.1.1.1/dns-query");
        assert!(c.collectors.route.enabled);
        assert!(c.collectors.host.enabled);
        assert_eq!(c.collectors.host.interval.as_secs(), 15);
    }
    #[test]
    fn toml_overrides_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(&p, "[collectors.link]\ninterval = \"5s\"\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.collectors.link.interval.as_secs(), 5);
    }
    #[test]
    fn acting_disabled_by_default() {
        // Safety invariant: acting is OFF unless explicitly enabled.
        let c = Config::load(None).unwrap();
        assert!(!c.acting.enabled);
        assert_eq!(c.acting.singbox_service, "system/sing-box");
        assert!(c.socket_owner_uid.is_none());
    }
    #[test]
    fn acting_can_be_enabled_via_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "socket_owner_uid = 501\n\
             [acting]\n\
             enabled = true\n\
             singbox_service = \"system/mihomo\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(c.acting.enabled);
        assert_eq!(c.acting.singbox_service, "system/mihomo");
        assert_eq!(c.socket_owner_uid, Some(501));
    }
}
