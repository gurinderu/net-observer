use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use types::ProbingTier;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub db_path: String,
    /// How long the record at `db_path` keeps its sample rows. Absent: keep
    /// forever (realm net-observer, node #130).
    #[serde(default)]
    pub record: RecordCfg,
    pub blob_dir: String,
    /// Unix-domain socket the daemon binds and the bar connects to for live status.
    pub socket_path: String,
    /// Permission bits applied to the socket file (octal), so the unprivileged bar
    /// can connect while the daemon runs as root.
    pub socket_mode: u32,
    /// When `Some(uid)`, the daemon `chown`s the socket to this uid (control-path
    /// hardening: pair with a restrictive `socket_mode` such as `0o600` so only
    /// the owner can even connect to the control endpoint). Default `None` — the
    /// socket keeps the daemon's ownership.
    pub socket_owner_uid: Option<u32>,
    /// Extra uids allowed to send a `Request::Control`, on top of root, the
    /// daemon's own uid, `socket_owner_uid`, and the logged-in console user.
    /// Empty by default. The escape hatch for a host with no graphical console
    /// session (SSH-only / headless), where the console-user rule authorises
    /// nobody. See `net-observerd::api::ControlPolicy`.
    pub control_uids: Vec<u32>,
    pub collectors: Collectors,
    /// The probing tier the daemon boots into. Absent, `passive`: nothing on
    /// the wire until the operator presses (realm net-observer, node #88).
    #[serde(default)]
    pub probing: ProbingCfg,
    /// Parameters of the manual actions the control path can run. Gates nothing.
    pub acting: ActingCfg,
}

/// Retention of the record's sample tables: the mechanism only — the POLICY
/// (how long to keep) is the owner's, and the default changes nothing (realm
/// net-observer, node #130).
///
/// The daemon prunes at startup and then once a day: every row of each named
/// table whose `ts_us` is older than `retention_days` is deleted. The names
/// are checked against the store's own list of sample tables, never
/// interpolated as given, so config can name nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordCfg {
    /// Days of samples to keep; `0` (the default) keeps forever and runs no
    /// prune at all.
    #[serde(default)]
    pub retention_days: u32,
    /// The tables the prune touches. Default: `connection_sample` alone — one
    /// row per flow key per tick, an order of magnitude more than any other
    /// table; the owner widens the list by config.
    #[serde(default = "default_retention_tables")]
    pub retention_tables: Vec<String>,
}

impl Default for RecordCfg {
    fn default() -> Self {
        RecordCfg {
            retention_days: 0,
            retention_tables: default_retention_tables(),
        }
    }
}

fn default_retention_tables() -> Vec<String> {
    vec!["connection_sample".to_string()]
}

/// The probing tier at startup. Applied once, when the daemon boots, and
/// written as the first `probing_edge` row; the tier is then process-scoped
/// like `observing` — never persisted, moved only by `ControlCmd::SetProbing`,
/// and back to this value on the next start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbingCfg {
    /// `"passive"` (the default when the key is absent — the owner's decision:
    /// a daemon nobody has pressed puts nothing on the wire) or `"active"`.
    #[serde(default = "default_probing_tier")]
    pub default: ProbingTier,
}

impl Default for ProbingCfg {
    fn default() -> Self {
        ProbingCfg {
            default: default_probing_tier(),
        }
    }
}

fn default_probing_tier() -> ProbingTier {
    // One spelling of the default: `types::ProbingTier::default` IS passive,
    // so a tier nobody recorded and a tier nobody configured agree.
    ProbingTier::default()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collectors {
    pub link: LinkCfg,
    pub proxy: ProxyCfg,
    pub dns: DnsCfg,
    pub route: RouteCfg,
    pub host: HostCfg,
    pub wifi: WifiCfg,
    #[serde(default)]
    pub air: AirCfg,
    pub neighbors: NeighborsCfg,
    /// Tolerated absent: a config written before the collector existed keeps
    /// loading, with the collector on.
    #[serde(default)]
    pub connections: ConnectionsCfg,
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
    /// The proxy group whose `now` field names the active node. "GLOBAL" is
    /// the clash-core convention, but sing-box's Clash API exposes ONLY the
    /// groups the config actually declares — against such a config the
    /// default 404s and the selector column reads "-" forever (observed
    /// live: /proxies/GLOBAL -> 404 while /proxies/vless-auto answered).
    /// Point it at the deployment's selector/urltest group.
    #[serde(default = "default_selector_group")]
    pub selector_group: String,
    /// How often sing-box's URLTest group re-tests its members, seconds —
    /// MUST match the group's `interval` in sing-box's config (its default
    /// is 3 min). sing-box deletes a node's history entry on a failed test,
    /// so the `endpoint-dial-stall` rule waits `2 × interval + 30 s` of
    /// absence before calling the traffic-carrying node's test dead: two
    /// missed rounds, not one slow one (realm net-observer, node #62).
    #[serde(default = "default_urltest_interval_secs")]
    pub urltest_interval_secs: u64,
}

fn default_selector_group() -> String {
    "GLOBAL".into()
}

fn default_urltest_interval_secs() -> u64 {
    180
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

/// The `air` collector: the radio environment — which foreign access points are
/// audible, on which channels and how loudly (realm net-observer, node #48).
///
/// **Off by default**, unlike the other passive collectors, and on its **own
/// slow interval** rather than the tick. Not because it emits anything — it does
/// not; it reads the system's own wireless report — but because producing that
/// report costs seconds of wall time per call (realm net-observer, node #47). A
/// subsystem whose every sample occupies a collector for that long is one the
/// operator opts into, and its period is minutes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

impl Default for AirCfg {
    fn default() -> Self {
        AirCfg {
            enabled: false,
            interval: Duration::from_secs(300),
        }
    }
}

/// The `connections` collector: what this machine talks to — the live flows
/// sing-box carries, read from its Clash API (`GET /connections`, the same API
/// and base URL `[collectors.proxy].clash_api` names) and folded per
/// destination each tick (realm net-observer, node #75). Reading a local API
/// on the loopback sends nothing on the wire, so it is on by default like the
/// other passive collectors, at the proxy collector's cadence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionsCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
}

impl Default for ConnectionsCfg {
    fn default() -> Self {
        ConnectionsCfg {
            enabled: true,
            interval: Duration::from_secs(15),
        }
    }
}

/// The serde default for a `bool` field that should default to `true` when the
/// key is absent (deriving `Default` would give `false`).
fn default_true() -> bool {
    true
}

/// The `neighbors` collector: who else is on the local segment, read from the
/// kernel's ARP and NDP caches. Reading a cache the OS already filled sends
/// nothing, so it is on by default like the other passive collectors — and the
/// interval is minutes, not seconds, because a neighbour table changes on the
/// timescale of devices joining a network, not of packets.
///
/// The *active* discovery (subnet sweep, mDNS, and the ports/banners/cve rungs)
/// is deliberately NOT configurable here: it never runs on a timer, only on an
/// explicit `ControlCmd::ScanNeighbors`, and config gates only what the daemon
/// does by itself — an operator's command is its own sanction (realm
/// net-observer, node #91). What a rung needs to work with (a snapshot, an
/// effective earlier rung) is a dependency the daemon reports, not a permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborsCfg {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Switch-topology discovery: passively CAPTURE received LLDP/CDP frames and
    /// record which switch/AP each interface uplinks to (realm net-observer, node
    /// #42). On by default like the other passive collectors — it emits NOTHING
    /// on the wire, only listens for the multicast discovery frames a switch
    /// already broadcasts. It does, however, need root and a BPF/pcap read to
    /// hear them, so it degrades HONESTLY: when the capture cannot open it logs
    /// that and records no links, never a pretence of a clean topology.
    #[serde(default = "default_true")]
    pub topology: bool,
    /// Passive announcement listening: a second `tcpdump` child hears what
    /// the segment says about itself (ARP, mDNS, SSDP, DHCP) and keeps the
    /// neighbour map alive with no packet of ours (realm net-observer, node
    /// #92). On by default like the other passive collectors — it emits
    /// NOTHING on the wire, and the probing tier does not gate it, since a
    /// tier withholds emissions and this has none. Like the topology capture
    /// it needs root and a BPF read, and it degrades HONESTLY: when the child
    /// cannot start the daemon logs why and runs without the listener, and
    /// the neighbour-cache ticks keep saying who is on the segment.
    #[serde(default = "default_true")]
    pub announce: bool,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcapCfg {
    pub enabled: bool,
    pub ring_mb: u32,
    pub filter: String,
}

/// Parameters of the manual actions the daemon runs as root on an explicit
/// `Request::Control` (today: `ControlCmd::KickstartProxy`). This section holds
/// parameters only and gates nothing: config may switch off what the daemon
/// does by itself, never a command the operator sends by hand — the invocation
/// is the sanction (realm net-observer, node #91).
///
/// What does gate the control path is authorisation: **every** `Request::Control`
/// must first pass the daemon's peer-credential check
/// (`net-observerd::api::ControlPolicy`) — root, the daemon's own uid,
/// `socket_owner_uid`, the logged-in console user, or a uid listed in
/// `control_uids`. Acting NEVER happens automatically — only on an explicit
/// `Request::Control`.
///
/// A legacy `enabled` key under `[acting]` is ignored on load, so a deployed
/// config that still carries it keeps parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActingCfg {
    /// The `launchctl` service target restarted by `ControlCmd::KickstartProxy`
    /// (`launchctl kickstart -k <service>`).
    pub singbox_service: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            db_path: "/var/lib/observer/observer.duckdb".into(),
            record: RecordCfg::default(),
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
                    selector_group: default_selector_group(),
                    urltest_interval_secs: default_urltest_interval_secs(),
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
                air: AirCfg::default(),
                neighbors: NeighborsCfg {
                    enabled: true,
                    interval: Duration::from_secs(120),
                    topology: true,
                    announce: true,
                    cve_snapshot_dir: None,
                    oui_snapshot_dir: None,
                },
                connections: ConnectionsCfg::default(),
                pcap_ring: PcapCfg {
                    enabled: true,
                    ring_mb: 8,
                    filter: "arp or icmp or udp port 67 or udp port 68 or ether broadcast".into(),
                },
            },
            probing: ProbingCfg::default(),
            acting: ActingCfg {
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
    /// sing-box's URLTest default is 3 min; a proxy section written before
    /// the field existed loads with it, and a section naming it overrides.
    #[test]
    fn urltest_interval_defaults_to_singbox_three_minutes() {
        let c = Config::load(None).unwrap();
        assert_eq!(c.collectors.proxy.urltest_interval_secs, 180);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "[collectors.proxy]\nenabled = true\ninterval = \"15s\"\n\
             tun_probe_url = \"http://x/204\"\nclash_api = \"http://127.0.0.1:9090\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.collectors.proxy.urltest_interval_secs, 180);

        std::fs::write(
            &p,
            "[collectors.proxy]\nenabled = true\ninterval = \"15s\"\n\
             tun_probe_url = \"http://x/204\"\nclash_api = \"http://127.0.0.1:9090\"\n\
             urltest_interval_secs = 60\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.collectors.proxy.urltest_interval_secs, 60);
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
    /// On by default at the proxy cadence; a file that never names the section
    /// loads with the collector on, and one that names it can switch it off.
    #[test]
    fn connections_default_on_and_the_section_is_optional() {
        let c = Config::load(None).unwrap();
        assert!(c.collectors.connections.enabled);
        assert_eq!(
            c.collectors.connections.interval,
            c.collectors.proxy.interval
        );

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(&p, "[collectors.host]\nenabled = false\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(c.collectors.connections.enabled);

        std::fs::write(
            &p,
            "[collectors.connections]\nenabled = false\ninterval = \"1m\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(!c.collectors.connections.enabled);
        assert_eq!(c.collectors.connections.interval.as_secs(), 60);
    }
    /// The gates this section used to carry (`acting.enabled`, the
    /// `collectors.neighbors.scan.*` rung permissions) are gone, but the owner's
    /// deployed config still names them. Figment ignores keys no field claims,
    /// so such a file must keep loading — and the keys around the legacy ones
    /// must still land (realm net-observer, node #91).
    #[test]
    fn legacy_gate_keys_are_ignored_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("legacy.toml");
        std::fs::write(
            &p,
            "[acting]\n\
             enabled = true\n\
             singbox_service = \"system/mihomo\"\n\
             [collectors.neighbors]\n\
             cve_snapshot_dir = \"/var/lib/observer/cve\"\n\
             [collectors.neighbors.scan]\n\
             ports = true\n\
             banners = true\n\
             cve = true\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap()))
            .expect("a config carrying the retired gate keys must still load");
        assert_eq!(c.acting.singbox_service, "system/mihomo");
        assert_eq!(
            c.collectors.neighbors.cve_snapshot_dir.as_deref(),
            Some("/var/lib/observer/cve")
        );
        // The rest of the neighbors config keeps its defaults.
        assert!(c.collectors.neighbors.enabled);
    }

    #[test]
    fn cve_snapshot_dir_absent_by_default() {
        let c = Config::load(None).unwrap();
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
    fn cve_snapshot_dir_comes_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "[collectors.neighbors]\ncve_snapshot_dir = \"/var/lib/observer/cve\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
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
        // The listener is on by default, tolerated absent, and its own switch.
        assert!(c.collectors.neighbors.announce);
        std::fs::write(&p, "[collectors.neighbors]\nannounce = false\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert!(c.collectors.neighbors.enabled);
        assert!(!c.collectors.neighbors.announce);
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
    fn acting_parameters_default() {
        // `[acting]` holds parameters of manual actions, not a switch: the only
        // default to assert is the service `KickstartProxy` targets.
        let c = Config::load(None).unwrap();
        assert_eq!(c.acting.singbox_service, "system/sing-box");
        assert!(c.socket_owner_uid.is_none());
    }
    #[test]
    fn acting_parameters_come_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(
            &p,
            "socket_owner_uid = 501\n\
             [acting]\n\
             singbox_service = \"system/mihomo\"\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
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
    /// Passive when the key is absent — the owner's decision — and the tier
    /// reads from `[probing] default` in the same lowercase vocabulary the
    /// socket and the DB column use. A config from before the section keeps
    /// loading and lands on passive.
    #[test]
    fn probing_defaults_to_passive_and_reads_from_toml() {
        assert_eq!(
            Config::load(None).unwrap().probing.default,
            ProbingTier::Passive
        );

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        std::fs::write(&p, "[probing]\ndefault = \"active\"\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.probing.default, ProbingTier::Active);

        let p = dir.path().join("legacy.toml");
        std::fs::write(&p, "[collectors.link]\ninterval = \"5s\"\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.probing.default, ProbingTier::Passive);

        let p = dir.path().join("bad.toml");
        std::fs::write(&p, "[probing]\ndefault = \"loud\"\n").unwrap();
        assert!(
            Config::load(Some(p.to_str().unwrap())).is_err(),
            "an unknown tier is an error, never a silent fall-back"
        );
    }
    /// Keep forever when nothing is configured — the default changes nothing
    /// — with `connection_sample` the one table a widening starts from; a
    /// `[record]` section sets the days and may widen or replace the list
    /// (realm net-observer, node #130).
    #[test]
    fn record_retention_defaults_to_keep_forever_and_reads_from_toml() {
        let c = Config::load(None).unwrap();
        assert_eq!(c.record.retention_days, 0);
        assert_eq!(c.record.retention_tables, ["connection_sample"]);

        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.toml");
        // The section without the list: the days land, the list keeps its
        // default.
        std::fs::write(&p, "[record]\nretention_days = 30\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.record.retention_days, 30);
        assert_eq!(c.record.retention_tables, ["connection_sample"]);

        std::fs::write(
            &p,
            "[record]\nretention_days = 90\n\
             retention_tables = [\"connection_sample\", \"proxy_sample\"]\n",
        )
        .unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.record.retention_days, 90);
        assert_eq!(
            c.record.retention_tables,
            ["connection_sample", "proxy_sample"]
        );

        // A config from before the section keeps loading, on keep-forever.
        std::fs::write(&p, "[collectors.link]\ninterval = \"5s\"\n").unwrap();
        let c = Config::load(Some(p.to_str().unwrap())).unwrap();
        assert_eq!(c.record.retention_days, 0);
    }
    /// The shipped example loads and mirrors the defaults, with every root
    /// key still at the root: a `[section]` header placed above one would
    /// silently claim it.
    #[test]
    fn the_example_config_loads_and_mirrors_the_defaults() {
        let p = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../net-observer.example.toml"
        );
        let c = Config::load(Some(p)).unwrap();
        assert_eq!(c.db_path, "/var/lib/observer/observer.duckdb");
        assert_eq!(c.blob_dir, "/var/lib/observer/blobs");
        assert_eq!(c.socket_path, "/var/lib/observer/observer.sock");
        assert_eq!(c.record.retention_days, 0);
        assert_eq!(c.record.retention_tables, ["connection_sample"]);
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
