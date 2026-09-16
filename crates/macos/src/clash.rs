//! Clash/Mihomo RESTful API client and the proxy-side facts adapter.
//!
//! [`ClashClient`] reads the currently selected node from a proxy *group* via
//! `GET /proxies/<group>`. [`ProxySystemFacts`] implements
//! [`collector_proxy::ProxyFacts`]: it reads the VLESS server endpoints from the
//! rendered sing-box config at runtime (never baked into the binary — secret
//! hygiene), probes the TUN with an HTTP request, and reports the selected node.

use std::path::PathBuf;
use std::time::Duration;

use collector_core::Readiness;
use collector_proxy::ProxyFacts;

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

    async fn tun_probe(&self, url: &str) -> Option<u16> {
        // `reqwest` does not turn 4xx/5xx into `Err` (only `error_for_status`
        // would), so this reports the status code of *any* HTTP response (the 204
        // probe target) and returns `None` only on a transport/timeout failure.
        match self.http.get(url).send().await {
            Ok(resp) => Some(resp.status().as_u16()),
            Err(e) => {
                tracing::debug!(url, error = %e, "tun probe failed");
                None
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
}
