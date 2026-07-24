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
    pub collectors: Collectors,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collectors {
    pub link: LinkCfg,
    pub proxy: ProxyCfg,
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
pub struct PcapCfg {
    pub enabled: bool,
    pub ring_mb: u32,
    pub filter: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            db_path: "/var/lib/observer/observer.duckdb".into(),
            blob_dir: "/var/lib/observer/blobs".into(),
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
                pcap_ring: PcapCfg {
                    enabled: true,
                    ring_mb: 8,
                    filter: "arp or icmp or udp port 67 or udp port 68 or ether broadcast".into(),
                },
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
    fn toml_overrides_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(&p, "[collectors.link]\ninterval = \"5s\"\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.collectors.link.interval.as_secs(), 5);
    }
}
