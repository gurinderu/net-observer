//! Clash/Mihomo RESTful API client and the proxy-side facts adapter.
//!
//! [`ClashClient`] reads the currently selected node from a proxy *group* via
//! `GET /proxies/<group>`. [`ProxySystemFacts`] implements
//! [`collector_proxy::ProxyFacts`]: it reads the VLESS server IPs from the
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
}

impl ClashClient {
    /// Build a client pointing at `base` (e.g. `http://127.0.0.1:9090`).
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into() }
    }

    /// The node currently selected in the top-level `GLOBAL` group, if the API
    /// is reachable.
    #[must_use]
    pub fn now(&self) -> Option<String> {
        self.selected("GLOBAL")
    }

    /// The node currently selected in proxy `group`, via `GET /proxies/<group>`.
    #[must_use]
    pub fn selected(&self, group: &str) -> Option<String> {
        let url = format!("{}/proxies/{}", self.base.trim_end_matches('/'), group);
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .ok()?;
        let body = match client.get(&url).send().and_then(|r| r.text()) {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(url, error = %e, "clash proxies query failed");
                return None;
            }
        };
        parse_clash_now(&body)
    }
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
        }
    }
}

impl ProxyFacts for ProxySystemFacts {
    /// The upstream server addresses: the `server` field of every `vless`
    /// outbound in the rendered sing-box config.
    fn server_endpoints(&self) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(&self.singbox_config) else {
            tracing::debug!(path = ?self.singbox_config, "sing-box config unreadable");
            return Vec::new();
        };
        parse_vless_ips(&text)
    }

    fn tun_probe(&self, url: &str) -> Option<u16> {
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .ok()?;
        match client.get(url).send() {
            Ok(resp) => Some(resp.status().as_u16()),
            Err(e) => {
                tracing::debug!(url, error = %e, "tun probe failed");
                None
            }
        }
    }

    fn selector(&self) -> Option<String> {
        self.clash.selected(&self.selector_group)
    }

    fn preflight(&self) -> Readiness {
        if self.singbox_config.exists() || !self.clash.base.is_empty() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("no sing-box config / clash api".into())
        }
    }
}

/// Collect the `server` address of every `vless` outbound in a sing-box config.
fn parse_vless_ips(config_json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return Vec::new();
    };
    let Some(outbounds) = value.get("outbounds").and_then(|o| o.as_array()) else {
        return Vec::new();
    };
    outbounds
        .iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("vless"))
        .filter_map(|o| o.get("server").and_then(|s| s.as_str()))
        .map(str::to_string)
        .collect()
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
    fn extracts_vless_server_ips() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "a", "server": "1.1.1.1", "server_port": 443},
                {"type": "direct", "tag": "direct"},
                {"type": "vless", "tag": "b", "server": "2.2.2.2", "server_port": 443}
            ]
        }"#;
        assert_eq!(parse_vless_ips(cfg), vec!["1.1.1.1", "2.2.2.2"]);
    }

    #[test]
    fn no_outbounds_is_empty() {
        assert!(parse_vless_ips("{}").is_empty());
        assert!(parse_vless_ips("garbage").is_empty());
    }
}
