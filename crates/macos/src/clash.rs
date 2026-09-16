//! Clash/Mihomo RESTful API client and the proxy-side facts adapters.
//!
//! [`ClashClient`] reads the currently selected node from a proxy *group* via
//! `GET /proxies/<group>` and the live flow list via `GET /connections` (the
//! surface as observed on sing-box: realm net-observer, node #127).
//! [`ProxySystemFacts`] implements [`collector_proxy::ProxyFacts`]: it reads the
//! VLESS server endpoints from the rendered sing-box config at runtime (never
//! baked into the binary — secret hygiene), probes the TUN with an HTTP request,
//! and reports the selected node. [`ConnectionSystemFacts`] implements
//! [`collector_connections::ConnectionFacts`] over the same client.

use std::path::PathBuf;
use std::time::Duration;

use collector_connections::ConnectionFacts;
use collector_core::Readiness;
use collector_proxy::{ProxyFacts, TunProbe};
use serde::Deserialize;
use types::LiveConnection;

/// HTTP timeout for every Clash/TUN request. A stalled proxy control plane is
/// itself a signal, so we fail fast.
const HTTP_TIMEOUT: Duration = Duration::from_secs(1);

/// Minimal client for the Clash/Mihomo RESTful API.
#[derive(Debug, Clone)]
pub struct ClashClient {
    /// API base URL, e.g. `http://127.0.0.1:9090`.
    pub base: String,
    /// Shared async HTTP client with a per-request [`HTTP_TIMEOUT`].
    http: reqwest::Client,
}

impl ClashClient {
    /// Build a client pointing at `base` (e.g. `http://127.0.0.1:9090`).
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into(),
            http: build_http_client(),
        }
    }

    /// The node currently selected in the top-level `GLOBAL` group, if the API
    /// is reachable.
    pub async fn now(&self) -> Option<String> {
        self.selected("GLOBAL").await
    }

    /// The node currently selected in proxy `group`, via `GET /proxies/<group>`.
    pub async fn selected(&self, group: &str) -> Option<String> {
        let url = format!("{}/proxies/{}", self.base.trim_end_matches('/'), group);
        let resp = match self.http.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(url, error = %e, "clash proxies query failed");
                return None;
            }
        };
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(url, error = %e, "clash proxies query failed");
                return None;
            }
        };
        parse_clash_now(&body)
    }

    /// Every live flow the proxy carries right now, via `GET /connections`.
    ///
    /// `None` when the API did not answer: a transport failure or timeout, a
    /// non-2xx status, or a body that does not decode — each logged at debug
    /// and each the same fact to the caller, "could not look". Never an empty
    /// list for any of them.
    pub async fn connections(&self) -> Option<Vec<LiveConnection>> {
        let url = format!("{}/connections", self.base.trim_end_matches('/'));
        let resp = match self.http.get(&url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(url, error = %e, "clash connections query failed");
                return None;
            }
        };
        let status = resp.status();
        if !status.is_success() {
            tracing::debug!(url, %status, "clash connections query refused");
            return None;
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(url, error = %e, "clash connections query failed");
                return None;
            }
        };
        let parsed = parse_connections(&body);
        if parsed.is_none() {
            tracing::debug!(url, "clash connections body did not decode");
        }
        parsed
    }
}

/// The `GET /connections` body, as far as the daemon reads it. Every field
/// the API also carries (`downloadTotal`, `uploadTotal`, `memory`, per-flow
/// `id`/`rule`/`start`, the metadata's `sourceIP`/`type`/`dnsMode`, …) is
/// ignored by serde's default, deliberately: the surface is sing-box's to
/// grow, and a new field must not blank the flow table.
#[derive(Deserialize)]
struct ConnectionsBody {
    /// Absent or `null` (a Go nil slice) when nothing is talking: both read
    /// as an answered, empty list.
    #[serde(default)]
    connections: Option<Vec<WireConnection>>,
}

#[derive(Deserialize)]
struct WireConnection {
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
    #[serde(default)]
    metadata: WireMetadata,
}

/// The per-flow metadata. The API spells these camelCase with an upper-case
/// `IP`, which `rename_all` cannot produce, so the renames are explicit.
#[derive(Default, Deserialize)]
struct WireMetadata {
    #[serde(default, rename = "destinationIP")]
    destination_ip: String,
    /// A string on the wire (`"443"`), not a number.
    #[serde(default, rename = "destinationPort")]
    destination_port: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    network: String,
    #[serde(default, rename = "processPath")]
    process_path: String,
}

/// Parse a `GET /connections` body into the daemon's flow list. `None` when
/// the body is not that shape at all; an answered, empty list is `Some(vec![])`.
///
/// Per flow: empty strings become `None` (an absent fact is not an empty
/// name), `chain` is the LAST element of `chains` (the node the flow actually
/// left through; the earlier elements are the selector and the group), and
/// `process` is the last path component of `processPath` with its ` (user)`
/// suffix stripped — `/Applications/Warp.app/Contents/MacOS/stable (gurinderu)`
/// is `stable`.
fn parse_connections(body: &str) -> Option<Vec<LiveConnection>> {
    let body: ConnectionsBody = serde_json::from_str(body).ok()?;
    Some(
        body.connections
            .unwrap_or_default()
            .into_iter()
            .map(|mut c| LiveConnection {
                host: non_empty(c.metadata.host),
                dst_ip: non_empty(c.metadata.destination_ip),
                dst_port: c.metadata.destination_port.trim().parse().ok(),
                process: process_name(&c.metadata.process_path),
                network: c.metadata.network,
                chain: c.chains.pop(),
                upload: c.upload,
                download: c.download,
            })
            .collect(),
    )
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// The process name from the API's `processPath`: the ` (<user>)` suffix
/// sing-box appends is dropped, then only the last path component is kept.
/// Empty in → `None`.
fn process_name(process_path: &str) -> Option<String> {
    let path = process_path.trim();
    let path = match path.rsplit_once(" (") {
        Some((before, rest)) if rest.ends_with(')') => before,
        _ => path,
    };
    let name = path.rsplit('/').next().unwrap_or(path).trim();
    non_empty(name.to_string())
}

/// Build the async HTTP client used for Clash/TUN requests, applying
/// [`HTTP_TIMEOUT`] as the per-request deadline. Falls back to the default
/// client if the builder fails (which it does not with the workspace features).
fn build_http_client() -> reqwest::Client {
    crate::tls::install_default_provider();
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .unwrap_or_default()
}

/// Extract the `now` (selected node) field from a Clash `/proxies/<group>`
/// JSON body.
fn parse_clash_now(body: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    value
        .get("now")
        .and_then(|n| n.as_str())
        .map(str::to_string)
}

/// macOS implementation of [`ProxyFacts`].
#[derive(Debug, Clone)]
pub struct ProxySystemFacts {
    /// Path to the rendered sing-box config JSON.
    singbox_config: PathBuf,
    /// Clash API client used to read the selected node.
    clash: ClashClient,
    /// Proxy group whose selection identifies the active node.
    selector_group: String,
    /// Async HTTP client for the TUN 204 probe.
    http: reqwest::Client,
}

impl ProxySystemFacts {
    /// Build the proxy facts adapter.
    ///
    /// - `singbox_config`: path to the rendered sing-box config JSON (read at
    ///   runtime so server addresses are never compiled in).
    /// - `clash_base`: Clash/Mihomo API base URL.
    /// - `selector_group`: proxy group whose current selection is the node.
    #[must_use]
    pub fn new(
        singbox_config: impl Into<PathBuf>,
        clash_base: impl Into<String>,
        selector_group: impl Into<String>,
    ) -> Self {
        Self {
            singbox_config: singbox_config.into(),
            clash: ClashClient::new(clash_base),
            selector_group: selector_group.into(),
            http: build_http_client(),
        }
    }
}

impl ProxyFacts for ProxySystemFacts {
    /// The upstream endpoints: `"server:server_port"` for every `vless`
    /// outbound in the rendered sing-box config, deduplicated.
    async fn server_endpoints(&self) -> Vec<String> {
        // A small local config file: an instant read, kept synchronous inside
        // the async fn (no blocking of consequence, mirroring `getloadavg`).
        let Ok(text) = std::fs::read_to_string(&self.singbox_config) else {
            tracing::debug!(path = ?self.singbox_config, "sing-box config unreadable");
            return Vec::new();
        };
        parse_vless_endpoints(&text)
    }

    async fn tun_probe(&self, url: &str) -> TunProbe {
        // `reqwest` does not turn 4xx/5xx into `Err` (only `error_for_status`
        // would), so this reports the status code of *any* HTTP response (the 204
        // probe target); a transport/timeout/TLS failure — the request was
        // attempted and no status came back — is `NoStatus`, which the record
        // stores as `tun_code = 0`, the shell oracle's curl `000`.
        match self.http.get(url).send().await {
            Ok(resp) => TunProbe::Status(resp.status().as_u16()),
            Err(e) => {
                tracing::debug!(url, error = %e, "tun probe failed");
                TunProbe::NoStatus
            }
        }
    }

    async fn selector(&self) -> Option<String> {
        self.clash.selected(&self.selector_group).await
    }

    async fn preflight(&self) -> Readiness {
        if self.singbox_config.exists() || !self.clash.base.is_empty() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("no sing-box config / clash api".into())
        }
    }
}

/// macOS implementation of [`ConnectionFacts`]: the live flow list, read from
/// the same Clash API the proxy facts use (the same [`ClashClient`] type, the
/// same HTTP client construction and timeout — not a second HTTP stack).
#[derive(Debug, Clone)]
pub struct ConnectionSystemFacts {
    clash: ClashClient,
}

impl ConnectionSystemFacts {
    /// Build the adapter over the Clash/Mihomo API at `clash_base`.
    #[must_use]
    pub fn new(clash_base: impl Into<String>) -> Self {
        Self {
            clash: ClashClient::new(clash_base),
        }
    }
}

impl ConnectionFacts for ConnectionSystemFacts {
    async fn connections(&self) -> Option<Vec<LiveConnection>> {
        self.clash.connections().await
    }

    async fn preflight(&self) -> Readiness {
        if self.clash.base.is_empty() {
            Readiness::Unavailable("no clash api".into())
        } else {
            Readiness::Ready
        }
    }
}

/// Collect the `"server:server_port"` endpoint of every `vless` outbound in a
/// sing-box config. Outbounds missing either field are skipped; duplicates are
/// dropped keeping first-occurrence order (nodes share endpoints across
/// outbounds, and one endpoint must be probed once).
fn parse_vless_endpoints(config_json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return Vec::new();
    };
    let Some(outbounds) = value.get("outbounds").and_then(|o| o.as_array()) else {
        return Vec::new();
    };
    let mut endpoints: Vec<String> = Vec::new();
    for endpoint in outbounds
        .iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("vless"))
        .filter_map(|o| {
            let server = o.get("server").and_then(|s| s.as_str())?;
            let port = o.get("server_port").and_then(serde_json::Value::as_u64)?;
            Some(format!("{server}:{port}"))
        })
    {
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
    endpoints
}

/// The fakeip pool a sing-box config declares (the first `dns.servers[]`
/// entry carrying `inet4_range`), as a `(network, mask)` pair ready for a
/// bitwise membership test. `None` — no config, no range, no parse — means
/// the caller CANNOT JUDGE pool membership; it must never be read as "not a
/// fakeip". Config-driven on purpose: the pool moved four times in one
/// month, and anything hardcoding it gets left behind (the dns collector's
/// 198.18.0.0/15 literal silently judged a pool sing-box no longer served).
pub(crate) fn fakeip_range(config_json: &str) -> Option<(u32, u32)> {
    let value: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let servers = value.get("dns")?.get("servers")?.as_array()?;
    let range = servers
        .iter()
        .find_map(|s| s.get("inet4_range").and_then(|r| r.as_str()))?;
    let (net, prefix) = range.split_once('/')?;
    let net: std::net::Ipv4Addr = net.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Some((u32::from(net) & mask, mask))
}

/// One probe address from inside the fakeip pool a sing-box config declares:
/// the range's network address + 8 — inside any real pool, and never a
/// network or broadcast address of one.
pub(crate) fn fakeip_probe_addr(config_json: &str) -> Option<std::net::Ipv4Addr> {
    let (net, _mask) = fakeip_range(config_json)?;
    Some(std::net::Ipv4Addr::from(net + 8))
}

/// The sing-box TUN inbound's own IPv4 address (the first `inbounds[]` of
/// `type == "tun"`, its first `address` entry, stripped of any `/prefix`):
/// `172.19.0.1` from `172.19.0.1/30`. This address is assigned to an
/// interface only while sing-box is running, so its presence is the
/// sing-box-alive signal the whole stack keys on (dns-fallback.nix). Read from
/// the rendered config so it stays config-driven, never hardcoded.
pub(crate) fn singbox_tun_addr(config_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let inbounds = value.get("inbounds")?.as_array()?;
    inbounds
        .iter()
        .filter(|i| i.get("type").and_then(|t| t.as_str()) == Some("tun"))
        .find_map(|i| {
            let addr = i
                .get("address")?
                .as_array()?
                .iter()
                .find_map(serde_json::Value::as_str)?;
            Some(addr.split('/').next().unwrap_or(addr).to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_selected_node() {
        let body =
            r#"{"name":"GLOBAL","type":"Selector","now":"node-a","all":["node-a","node-b"]}"#;
        assert_eq!(parse_clash_now(body).as_deref(), Some("node-a"));
    }

    #[test]
    fn no_now_field_is_none() {
        let body = r#"{"name":"GLOBAL","type":"Selector"}"#;
        assert_eq!(parse_clash_now(body), None);
    }

    #[test]
    fn malformed_json_is_none() {
        assert_eq!(parse_clash_now("not json"), None);
    }

    #[test]
    fn extracts_vless_endpoints() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "a", "server": "1.1.1.1", "server_port": 443},
                {"type": "direct", "tag": "direct"},
                {"type": "vless", "tag": "b", "server": "2.2.2.2", "server_port": 2053}
            ]
        }"#;
        assert_eq!(
            parse_vless_endpoints(cfg),
            vec!["1.1.1.1:443", "2.2.2.2:2053"]
        );
    }

    /// Nodes share a server IP across outbounds — on different ports they are
    /// different listeners and both are probed, while a repeated (server, port)
    /// pair is one endpoint and probed once, in first-occurrence order.
    #[test]
    fn duplicate_endpoints_are_probed_once() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "a", "server": "1.1.1.1", "server_port": 443},
                {"type": "vless", "tag": "b", "server": "1.1.1.1", "server_port": 2053},
                {"type": "vless", "tag": "c", "server": "1.1.1.1", "server_port": 443}
            ]
        }"#;
        assert_eq!(
            parse_vless_endpoints(cfg),
            vec!["1.1.1.1:443", "1.1.1.1:2053"]
        );
    }

    /// An outbound missing `server_port` yields no probable endpoint: skipping
    /// it beats inventing a port for it.
    #[test]
    fn missing_server_port_is_skipped() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "a", "server": "1.1.1.1"},
                {"type": "vless", "tag": "b", "server": "2.2.2.2", "server_port": 443}
            ]
        }"#;
        assert_eq!(parse_vless_endpoints(cfg), vec!["2.2.2.2:443"]);
    }

    #[test]
    fn no_outbounds_is_empty() {
        assert!(parse_vless_endpoints("{}").is_empty());
        assert!(parse_vless_endpoints("garbage").is_empty());
    }

    #[test]
    fn fakeip_probe_addr_is_network_plus_eight() {
        let cfg = r#"{
            "dns": {
                "servers": [
                    {"type": "udp", "server": "1.1.1.1"},
                    {"type": "fakeip", "inet4_range": "198.18.0.0/15"}
                ]
            }
        }"#;
        assert_eq!(
            fakeip_probe_addr(cfg),
            Some(std::net::Ipv4Addr::new(198, 18, 0, 8))
        );
    }

    #[test]
    fn no_fakeip_range_is_none() {
        assert_eq!(fakeip_probe_addr("{}"), None);
        assert_eq!(fakeip_probe_addr(r#"{"dns":{"servers":[]}}"#), None);
        assert_eq!(
            fakeip_probe_addr(r#"{"dns":{"servers":[{"inet4_range":"not-a-cidr"}]}}"#),
            None
        );
        assert_eq!(fakeip_probe_addr("garbage"), None);
    }

    #[test]
    fn extracts_singbox_tun_addr_stripping_the_prefix() {
        let cfg = r#"{
            "inbounds": [
                {"type": "mixed", "listen": "127.0.0.1"},
                {"type": "tun", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]}
            ]
        }"#;
        assert_eq!(singbox_tun_addr(cfg).as_deref(), Some("172.19.0.1"));
    }

    #[test]
    fn no_tun_inbound_is_none() {
        assert_eq!(singbox_tun_addr("{}"), None);
        assert_eq!(singbox_tun_addr(r#"{"inbounds":[{"type":"mixed"}]}"#), None);
        assert_eq!(singbox_tun_addr(r#"{"inbounds":[{"type":"tun"}]}"#), None);
        assert_eq!(singbox_tun_addr("garbage"), None);
    }

    /// `GET /connections` as observed on the owner's Mac, verbatim (realm
    /// net-observer, node #127).
    const CONNECTIONS_FIXTURE: &str = r#"{"connections":[{"chains":["vless-out-6","vless-auto","vless-main"],"download":0,"id":"549ec5ea-1d3d-4a87-94cf-7791e4088bab","metadata":{"destinationIP":"149.154.167.41","destinationPort":"80","dnsMode":"normal","host":"","network":"tcp","processPath":"","sourceIP":"172.19.0.1","sourcePort":"57420","type":"tun/0"},"rule":"final","rulePayload":"","start":"2026-09-16T19:57:06.925224+03:00","upload":0},{"chains":["vless-out-6","vless-auto","vless-main"],"download":0,"id":"d72b62b1-c27b-4114-85b2-92d15b625c7b","metadata":{"destinationIP":"194.221.250.50","destinationPort":"5222","dnsMode":"normal","host":"www.google.com","network":"tcp","processPath":"","sourceIP":"172.19.0.1","sourcePort":"53598","type":"tun/0"},"rule":"final","rulePayload":"","start":"2026-09-16T19:42:24.816839+03:00","upload":0},{"chains":["vless-out-6","vless-auto","vless-main"],"download":0,"id":"b3f1e891-eb73-4736-9669-16930fe93eac","metadata":{"destinationIP":"","destinationPort":"443","dnsMode":"normal","host":"claude.ai","network":"tcp","processPath":"","sourceIP":"172.19.0.1","sourcePort":"58299","type":"tun/0"},"rule":"final","rulePayload":"","start":"2026-09-16T19:57:15.494335+03:00","upload":0},{"chains":["vless-out-6","vless-auto","vless-main"],"download":5006,"id":"a92b3f11-b58c-45fb-b005-7374211c1572","metadata":{"destinationIP":"","destinationPort":"443","dnsMode":"normal","host":"o540343.ingest.sentry.io","network":"tcp","processPath":"/Applications/Warp.app/Contents/MacOS/stable (gurinderu)","sourceIP":"172.19.0.1","sourcePort":"63428","type":"tun/0"},"rule":"final","rulePayload":"","start":"2026-09-17T00:01:47.501601+03:00","upload":4}]}"#;

    /// The fixture's four flows, each field read the way the daemon keeps it:
    /// empty strings as `None`, the port parsed, the chain's LAST element, the
    /// process name without its path and user.
    #[test]
    fn parses_the_observed_connections_body() {
        let flows = parse_connections(CONNECTIONS_FIXTURE).expect("the fixture decodes");
        assert_eq!(flows.len(), 4);

        let direct = &flows[0];
        assert_eq!(direct.host, None);
        assert_eq!(direct.dst_ip.as_deref(), Some("149.154.167.41"));
        assert_eq!(direct.dst_port, Some(80));
        assert_eq!(direct.process, None);
        assert_eq!(direct.network, "tcp");
        assert_eq!(direct.chain.as_deref(), Some("vless-main"));

        let spoofed = &flows[1];
        assert_eq!(spoofed.host.as_deref(), Some("www.google.com"));
        assert_eq!(spoofed.dst_ip.as_deref(), Some("194.221.250.50"));
        assert_eq!(spoofed.dst_port, Some(5222));

        let resolved_remotely = &flows[2];
        assert_eq!(resolved_remotely.host.as_deref(), Some("claude.ai"));
        assert_eq!(resolved_remotely.dst_ip, None);
        assert_eq!(resolved_remotely.dst_port, Some(443));

        let attributed = &flows[3];
        assert_eq!(attributed.host.as_deref(), Some("o540343.ingest.sentry.io"));
        assert_eq!(attributed.process.as_deref(), Some("stable"));
        assert_eq!(attributed.upload, 4);
        assert_eq!(attributed.download, 5006);
    }

    /// The top-level totals and any field this build does not read must not
    /// fail the decode: the surface is sing-box's to grow.
    #[test]
    fn unknown_fields_and_a_null_list_are_tolerated() {
        let flows = parse_connections(
            r#"{"downloadTotal":1,"uploadTotal":2,"memory":3,"connections":[
                {"chains":[],"download":0,"upload":0,"metadata":{"network":"udp","future":true}}
            ]}"#,
        )
        .expect("unknown fields decode");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].chain, None);
        assert_eq!(flows[0].network, "udp");
        assert_eq!(flows[0].dst_port, None);

        assert_eq!(
            parse_connections(r#"{"connections":null,"downloadTotal":0}"#),
            Some(Vec::new())
        );
        assert_eq!(parse_connections("{}"), Some(Vec::new()));
    }

    /// Not the shape at all is `None` — the caller's "could not look", never
    /// an empty list.
    #[test]
    fn an_undecodable_connections_body_is_none() {
        assert_eq!(parse_connections("not json"), None);
        assert_eq!(parse_connections(r#"{"connections":"nope"}"#), None);
    }

    #[test]
    fn process_name_keeps_the_last_component_and_drops_the_user() {
        assert_eq!(
            process_name("/Applications/Warp.app/Contents/MacOS/stable (gurinderu)").as_deref(),
            Some("stable")
        );
        assert_eq!(
            process_name("/Applications/Telegram.app/Contents/MacOS/Telegram (gurinderu)")
                .as_deref(),
            Some("Telegram")
        );
        assert_eq!(process_name("/usr/bin/curl").as_deref(), Some("curl"));
        assert_eq!(process_name("curl").as_deref(), Some("curl"));
        assert_eq!(process_name(""), None);
    }
}
