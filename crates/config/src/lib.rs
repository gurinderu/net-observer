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
    /// Extra uids allowed to send a `Request::Control`, on top of root, the
    /// daemon's own uid, `socket_owner_uid`, and the logged-in console user.
    /// Empty by default. The escape hatch for a host with no graphical console
    /// session (SSH-only / headless), where the console-user rule authorises
    /// nobody. See `net-observerd::api::ControlPolicy`.
    pub control_uids: Vec<u32>,
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
    pub wifi: WifiCfg,
    pub neighbors: NeighborsCfg,
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

/// The `wifi` collector: passive CoreWLAN air-quality readings (RSSI, noise,
/// transmit rate, PHY, channel). Reading the radio's own statistics sends
/// nothing and never scans, so it is on by default like the other passive
/// collectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

/// The `neighbors` collector: who else is on the local segment, read from the
/// kernel's ARP and NDP caches. Reading a cache the OS already filled sends
/// nothing, so it is on by default like the other passive collectors — and the
/// interval is minutes, not seconds, because a neighbour table changes on the
/// timescale of devices joining a network, not of packets.
///
/// The *active* discovery (subnet sweep, mDNS) is deliberately NOT configurable
/// here: it never runs on a timer, only on an explicit `ControlCmd::ScanNeighbors`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborsCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// What an operator-pressed scan is PERMITTED to do. The ceiling, not the
    /// switch: every capability is off by default, and the bar's checkboxes pick
    /// which permitted capabilities a given manual run includes. A run never
    /// exceeds this — a requested-but-unpermitted capability is dropped and the
    /// scan says so. The passive collector above needs none of this; it only
    /// ever reads caches the OS filled.
    #[serde(default)]
    pub scan: ScanCfg,
    /// Directory holding the local CVE snapshot the `cve` rung matches banners
    /// against (a cvelistV5 tree under `cves/` plus an optional `kev.json`).
    /// `None` by default, and the operator provisions the data out-of-band. The
    /// `cve` rung is UNAVAILABLE - and honestly reported as dropped - whenever
    /// this is `None` or the directory is absent: no snapshot, no matching, and
    /// never a pretence of one.
    #[serde(default)]
    pub cve_snapshot_dir: Option<String>,
    /// Directory holding the local OUI snapshot (a Wireshark `manuf` file at
    /// `<dir>/manuf`) that the ROLE inference resolves a neighbour's MAC vendor
    /// against. `None` by default, provisioned out-of-band like the CVE snapshot.
    /// When `None`, absent, or unreadable, roles degrade to gateway/unknown only
    /// — honestly, never a guessed vendor. (realm net-observer, node #36)
    #[serde(default)]
    pub oui_snapshot_dir: Option<String>,
}

/// Per-capability permission for the active neighbour scan, each off by default.
/// The rungs escalate in how loud they are on the wire; a host turns on exactly
/// what it is willing to emit into the networks it visits. Reading order matches
/// the ladder: sweep/mDNS are the base (always run when scanning); the rungs
/// below are the additions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanCfg {
    /// TCP-connect probes to discovered neighbours' ports — the daemon opening
    /// connections to other machines, so off by default and gated by acting.
    #[serde(default)]
    pub ports: bool,
    /// Banner grabs on the open ports the port scan found — reading what each
    /// service volunteers about itself. Louder than a bare connect (it exchanges
    /// bytes) and needs `ports` to have anything to grab from, so off by default.
    #[serde(default)]
    pub banners: bool,
    /// Match grabbed banners against the local CVE snapshot, the loudest rung in
    /// diagnostic terms though it emits nothing new on the wire: it needs the
    /// `banners` rung to have parsed a service and a provisioned snapshot to
    /// match against. Off by default; every match it stores is a hypothesis,
    /// never an asserted fact.
    #[serde(default)]
    pub cve: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapCfg {
    pub enabled: bool,
    pub ring_mb: u32,
    pub filter: String,
}

/// The write/control ("acting") path — manual recovery actions the daemon runs
/// as root. Disabled by default: with `enabled = false`, every *acting-class*
/// control request (`ControlCmd::KickstartProxy`) is refused without running
/// anything. Benign self-control (`ControlCmd::SetObserving`, which only
/// pauses/resumes this daemon's own collection) is not gated by *this* switch.
///
/// This switch is NOT the whole story for the control path, and never was for
/// authorisation: **every** `Request::Control`, of either class, must first pass
/// the daemon's peer-credential check (`net-observerd::api::ControlPolicy`) — root,
/// the daemon's own uid, `socket_owner_uid`, the logged-in console user, or a
/// uid listed in `control_uids`. `SetObserving` is exempt from the *acting*
/// gate, not from authorisation. Both gates are applied in exactly one place,
/// `net-observerd::api::control_request`. Acting NEVER happens automatically — only
/// on an explicit `Request::Control`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActingCfg {
    /// Master switch for the ACTING CLASS of the control path only. `false`
    /// (default) ⇒ refuse every acting-class control request
    /// (`ControlCmd::KickstartProxy`) without executing anything. Benign
    /// self-control (`ControlCmd::SetObserving`) is not gated by this switch —
    /// but, like every control request, it still requires an authorised peer.
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
            control_uids: Vec::new(),
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
                wifi: WifiCfg {
                    enabled: true,
                    interval: Duration::from_secs(15),
                },
                neighbors: NeighborsCfg {
                    enabled: true,
                    interval: Duration::from_secs(120),
                    scan: ScanCfg::default(),
                    cve_snapshot_dir: None,
                    oui_snapshot_dir: None,
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
    /// Load defaults, then an optional TOML file, then `NET_OBSERVER_*` env vars.
    ///
    /// When `path` is `Some`, the file **must exist and be a readable regular
    /// file**: figment treats a missing file as an empty provider, so a typo'd
    /// `--config` would otherwise silently yield defaults for every setting —
    /// which for `net-observerd` means binding a socket and opening a database
    /// nobody asked for. The merge also uses `Toml::file_exact`, not
    /// `Toml::file`, which walks up parent directories looking for the name: a
    /// relative `--config` must resolve where the operator pointed, never at an
    /// ancestor's file they never named.
    ///
    /// `net-observer-bar` deliberately treats this error as non-fatal — a GUI that
    /// refuses to start leaves the user with nothing — and surfaces the reason
    /// in its panel and on stderr instead.
    // Signature is a fixed cross-crate interface (see plan Task 3), so the
    // large `figment::Error` cannot be boxed away here.
    #[allow(clippy::result_large_err)]
    pub fn load(path: Option<&str>) -> Result<Config, figment::Error> {
        let mut fig = Figment::from(Serialized::defaults(Config::default()));
        if let Some(p) = path {
            let meta = std::fs::metadata(p)
                .map_err(|e| figment::Error::from(format!("config file `{p}`: {e}")))?;
            if !meta.is_file() {
                return Err(figment::Error::from(format!(
                    "config path `{p}` is not a regular file"
                )));
            }
            // Read it ONCE, here, and hand figment the bytes. Probing the path and
            // then letting figment re-open it leaves a window in which the file can
            // be unlinked (routine for unlink-then-write config management): the
            // re-open finds nothing, a file provider yields an empty map rather than
            // an error, and `load` returns pure defaults — silently binding the
            // default socket and opening the default DB, which is the exact outcome
            // requiring the path to exist is meant to prevent.
            // `is_file` above is what keeps this from blocking forever on a FIFO.
            let body = std::fs::read_to_string(p).map_err(|e| {
                figment::Error::from(format!("config file `{p}` is not readable: {e}"))
            })?;
            // `Toml::string`, not `Toml::file*`: no path means no ancestor-directory
            // search, so a named path can never resolve to a file nobody named.
            fig = fig.merge(Toml::string(&body));
        }
        fig.merge(Env::prefixed("NET_OBSERVER_").split("__"))
            .extract()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_apply_when_no_config_path() {
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
    fn wifi_defaults_apply_and_can_be_disabled() {
        let c = Config::load(None).unwrap();
        assert!(c.collectors.wifi.enabled);
        assert_eq!(c.collectors.wifi.interval.as_secs(), 15);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "[collectors.wifi]\nenabled = false\ninterval = \"30s\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(!c.collectors.wifi.enabled);
        assert_eq!(c.collectors.wifi.interval.as_secs(), 30);
    }
    #[test]
    fn scan_capabilities_are_all_off_by_default_and_toggle_from_toml() {
        let c = Config::load(None).unwrap();
        assert!(
            !c.collectors.neighbors.scan.ports,
            "an active scan capability must be off until explicitly permitted"
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(&p, "[collectors.neighbors.scan]\nports = true\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(c.collectors.neighbors.scan.ports);
        // A rung not named in the toml stays off.
        assert!(!c.collectors.neighbors.scan.banners);
        // The rest of the neighbors config keeps its defaults.
        assert!(c.collectors.neighbors.enabled);

        let p = dir.path().join("b.toml");
        std::fs::write(&p, "[collectors.neighbors.scan]\nbanners = true\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(c.collectors.neighbors.scan.banners);
    }

    #[test]
    fn cve_rung_is_off_and_snapshot_dir_absent_by_default() {
        let c = Config::load(None).unwrap();
        assert!(
            !c.collectors.neighbors.scan.cve,
            "the cve rung must be off until explicitly permitted"
        );
        assert!(
            c.collectors.neighbors.cve_snapshot_dir.is_none(),
            "no snapshot directory until the operator provisions one"
        );
    }

    #[test]
    fn oui_snapshot_dir_absent_by_default_and_read_from_toml() {
        let c = Config::load(None).unwrap();
        assert!(
            c.collectors.neighbors.oui_snapshot_dir.is_none(),
            "no OUI snapshot until the operator provisions one — roles then \
             degrade to gateway/unknown, never a guessed vendor"
        );

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("oui.toml");
        std::fs::write(
            &p,
            "[collectors.neighbors]\noui_snapshot_dir = \"/var/lib/observer/oui\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(
            c.collectors.neighbors.oui_snapshot_dir.as_deref(),
            Some("/var/lib/observer/oui")
        );
    }

    #[test]
    fn cve_rung_and_snapshot_dir_come_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "[collectors.neighbors]\ncve_snapshot_dir = \"/var/lib/observer/cve\"\n\
             [collectors.neighbors.scan]\ncve = true\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(c.collectors.neighbors.scan.cve);
        assert_eq!(
            c.collectors.neighbors.cve_snapshot_dir.as_deref(),
            Some("/var/lib/observer/cve")
        );
    }

    #[test]
    fn neighbors_defaults_apply_and_can_be_disabled() {
        let c = Config::load(None).unwrap();
        assert!(c.collectors.neighbors.enabled);
        assert_eq!(c.collectors.neighbors.interval.as_secs(), 120);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "[collectors.neighbors]\nenabled = false\ninterval = \"5m\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(!c.collectors.neighbors.enabled);
        assert_eq!(c.collectors.neighbors.interval.as_secs(), 300);
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
        // Asserts the default value only: `acting.enabled` ships off. What that
        // switch gates lives in `net-observerd::api::control_response`.
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
    #[test]
    fn missing_named_config_is_rejected() {
        // An explicitly named file that does not exist is an error, not a
        // silent fall-back to defaults: figment treats a missing file as an
        // empty provider, which would hide a typo'd `--config` completely.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.toml");
        let path = p.to_str().unwrap();
        let err = Config::load(Some(path)).unwrap_err();
        assert!(
            err.to_string().contains(path),
            "error should name the path: {err}"
        );
    }
    #[test]
    fn directory_as_config_is_rejected() {
        // `File::open` on a directory succeeds on macOS, so the `is_file` check
        // is what catches this.
        let dir = tempfile::tempdir().unwrap();
        let err = Config::load(Some(dir.path().to_str().unwrap())).unwrap_err();
        assert!(
            err.to_string().contains("not a regular file"),
            "unexpected error: {err}"
        );
    }
    #[test]
    fn named_config_is_not_searched_up_the_tree() {
        // `Toml::file` walks up parent directories looking for the file name; the
        // bytes we read ourselves cannot. A named path must resolve where the
        // operator pointed, never at an ancestor's file they never named.
        //
        // The ancestor file carries a DIFFERENT value from the named one, so a
        // resurrected search is visible in the result. An earlier version of this
        // test pointed at a path that did not exist, so `load` bailed on the
        // existence check before provider construction was ever reached — it
        // passed whether or not the search was disabled, and guarded nothing.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("o.toml"),
            "[collectors.link]\ninterval = \"5s\"\n",
        )
        .unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let named = sub.join("o.toml");
        std::fs::write(&named, "[collectors.link]\ninterval = \"9s\"\n").unwrap();

        let c = Config::load(Some(named.to_str().unwrap())).unwrap();
        assert_eq!(
            c.collectors.link.interval.as_secs(),
            9,
            "loaded the ancestor's config instead of the named one"
        );
    }

    #[test]
    fn named_config_that_does_not_exist_is_an_error() {
        // The existence pre-check, stated separately from the search behaviour
        // above so neither test can silently start covering for the other.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("o.toml"),
            "[collectors.link]\ninterval = \"5s\"\n",
        )
        .unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let missing = sub.join("o.toml");
        let err = Config::load(Some(missing.to_str().unwrap())).unwrap_err();
        assert!(
            err.to_string().contains("o.toml"),
            "error should name the config path: {err}"
        );
    }
    #[test]
    fn control_uids_default_empty() {
        assert!(Config::load(None).unwrap().control_uids.is_empty());
    }
    #[test]
    fn control_uids_can_be_set_via_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(&p, "control_uids = [501, 502]\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.control_uids, vec![501, 502]);
    }
}
