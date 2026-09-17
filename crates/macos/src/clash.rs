//! Clash/Mihomo RESTful API client and the proxy-side facts adapters.
//!
//! [`ClashClient`] reads a proxy *group* — its selected node and its members
//! — via `GET /proxies/<group>`, the live flow list via `GET /connections`
//! (the surface as observed on sing-box: realm net-observer, node #127), and
//! asks sing-box to dial through one node via `GET /proxies/<node>/delay`
//! (observed 2026-09-17: realm net-observer, node #62).
//! [`ProxySystemFacts`] implements [`collector_proxy::ProxyFacts`]: it reads the
//! VLESS server endpoints from the rendered sing-box config at runtime (never
//! baked into the binary — secret hygiene), probes the TUN with an HTTP request,
//! reports the selected node and the group's members, and dials.
//! [`ConnectionSystemFacts`] implements
//! [`collector_connections::ConnectionFacts`] over the same client.

use std::path::PathBuf;
use std::time::Duration;

use collector_connections::ConnectionFacts;
use collector_core::Readiness;
use collector_proxy::{DialOutcome, ProxyFacts, TunProbe};
use serde::Deserialize;
use types::LiveConnection;

/// HTTP timeout for every Clash/TUN request. A stalled proxy control plane is
/// itself a signal, so we fail fast.
const HTTP_TIMEOUT: Duration = Duration::from_secs(1);

/// How long sing-box's delay test may wait for its answer through a node
/// (the `timeout` query parameter, milliseconds): a healthy dial answers in
/// a few hundred, a dead path runs to this and reports `Timeout`
/// (realm net-observer, node #62).
const DIAL_TIMEOUT_MS: u32 = 5_000;

/// How much longer than the delay test itself the HTTP request for it waits,
/// so a test that runs to its timeout still delivers its `Timeout` body
/// instead of being cut off by the client and read as "the API did not
/// answer" — a different fact.
const DIAL_GRACE: Duration = Duration::from_secs(2);

/// A proxy group as `GET /proxies/<group>` describes it: the node it selects
/// right now and every member it can select.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    /// The selected node (`now`); absent on a body that is not a group's.
    pub now: Option<String>,
    /// The members (`all`), in the order the group lists them.
    pub all: Vec<String>,
}

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
        self.group(group).await?.now
    }

    /// Proxy `group` as the API describes it, via `GET /proxies/<group>`:
    /// `None` when the API did not answer or the body does not decode.
    pub async fn group(&self, group: &str) -> Option<GroupInfo> {
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
        parse_clash_group(&body)
    }

    /// sing-box's own dial through `node`: `GET
    /// /proxies/<node>/delay?timeout=<ms>&url=<url>`, sing-box fetching `url`
    /// through that one outbound and reporting how long it took (realm
    /// net-observer, node #62). The HTTP request waits [`DIAL_GRACE`] longer
    /// than the test's own `timeout_ms`, so a test that runs to its timeout
    /// still delivers its `Timeout` body — [`DialOutcome::NoAnswer`] — and
    /// only a request the API never answered reads as
    /// [`DialOutcome::Unknown`].
    pub async fn delay(&self, node: &str, url: &str, timeout_ms: u32) -> DialOutcome {
        let api = format!("{}/proxies/{}/delay", self.base.trim_end_matches('/'), node);
        let resp = match self
            .http
            .get(&api)
            .query(&[
                ("timeout", timeout_ms.to_string()),
                ("url", url.to_string()),
            ])
            .timeout(Duration::from_millis(u64::from(timeout_ms)) + DIAL_GRACE)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(api, node, url, error = %e, "clash delay query failed");
                return DialOutcome::Unknown;
            }
        };
        let status = resp.status();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(api, node, url, error = %e, "clash delay query failed");
                return DialOutcome::Unknown;
            }
        };
        let outcome = parse_delay(&body);
        if outcome == DialOutcome::Unknown {
            tracing::debug!(api, node, url, %status, body, "clash delay body not understood");
        }
        outcome
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
/// name), `chain` is the FIRST element of `chains` — the outbound that actually
/// carried the flow: sing-box lists them node-first (`vless-out-6`, then the
/// group, then the top-level selector; `common.Reverse(chain)` in its tracker),
/// so the last element is a constant selector name — and
/// `process` is the last path component of `processPath` with its ` (user)`
/// suffix stripped — `/Applications/Warp.app/Contents/MacOS/stable (gurinderu)`
/// is `stable`.
fn parse_connections(body: &str) -> Option<Vec<LiveConnection>> {
    let body: ConnectionsBody = serde_json::from_str(body).ok()?;
    Some(
        body.connections
            .unwrap_or_default()
            .into_iter()
            .map(|c| LiveConnection {
                host: non_empty(c.metadata.host),
                dst_ip: non_empty(c.metadata.destination_ip),
                dst_port: c.metadata.destination_port.trim().parse().ok(),
                process: process_name(&c.metadata.process_path),
                network: c.metadata.network,
                chain: c.chains.into_iter().next(),
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
/// Empty in → `None`, and so is a bare integer: when sing-box could resolve
/// only the uid of the flow's owner it writes that uid as the path (`"501"`),
/// and a uid is not a process name.
fn process_name(process_path: &str) -> Option<String> {
    let path = process_path.trim();
    let path = match path.rsplit_once(" (") {
        Some((before, rest)) if rest.ends_with(')') => before,
        _ => path,
    };
    let name = path.rsplit('/').next().unwrap_or(path).trim();
    if name.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(name.to_string())
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

/// The `GET /proxies/<group>` body, as far as the daemon reads it: the
/// selected node and the members. `type`, `history`, `udp` and whatever else
/// sing-box adds are ignored by serde's default.
#[derive(Deserialize)]
struct GroupBody {
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    all: Vec<String>,
}

/// Parse a Clash `/proxies/<group>` body into its selection and members.
/// `None` when the body is not JSON at all; a body without `now` (a plain
/// proxy, not a group) is `Some` with `now: None`.
fn parse_clash_group(body: &str) -> Option<GroupInfo> {
    let body: GroupBody = serde_json::from_str(body).ok()?;
    Some(GroupInfo {
        now: body.now,
        all: body.all,
    })
}

/// Parse a `/proxies/<node>/delay` body, the four shapes observed on
/// 2026-09-17 (realm net-observer, node #62): `{"delay": <ms>}` is an
/// answer; `{"message":"Timeout"}` and `{"message":"An error occurred in the
/// delay test"}` are a dial that got nothing back; `{"message":"Resource
/// not found"}` (a node the API does not know) and any other shape are no
/// measurement. An answer of `0` ms is reported as `1`, because the record
/// spells "no answer" as `0` and an answer is never that.
fn parse_delay(body: &str) -> DialOutcome {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body) else {
        return DialOutcome::Unknown;
    };
    if let Some(ms) = value.get("delay").and_then(serde_json::Value::as_u64) {
        return DialOutcome::Ok(u32::try_from(ms).unwrap_or(u32::MAX).max(1));
    }
    match value.get("message").and_then(serde_json::Value::as_str) {
        Some("Timeout" | "An error occurred in the delay test") => DialOutcome::NoAnswer,
        _ => DialOutcome::Unknown,
    }
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

    /// Every `vless` outbound as `(tag, "server:server_port")`, from the same
    /// rendered config — the map from a group member to the endpoint row its
    /// dial rides.
    async fn node_endpoints(&self) -> Vec<(String, String)> {
        let Ok(text) = std::fs::read_to_string(&self.singbox_config) else {
            tracing::debug!(path = ?self.singbox_config, "sing-box config unreadable");
            return Vec::new();
        };
        parse_vless_nodes(&text)
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

    async fn group_members(&self) -> Vec<String> {
        self.clash
            .group(&self.selector_group)
            .await
            .map(|g| g.all)
            .unwrap_or_default()
    }

    async fn dial(&self, node: &str, url: &str) -> DialOutcome {
        self.clash.delay(node, url, DIAL_TIMEOUT_MS).await
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

/// Every `vless` outbound in a sing-box config as `(tag, "server:server_port")`,
/// in config order. Outbounds missing either address field are skipped; a
/// missing `tag` reads as an empty name (sing-box requires tags, so this
/// only keeps the endpoint list complete — no group ever names `""`).
fn parse_vless_nodes(config_json: &str) -> Vec<(String, String)> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return Vec::new();
    };
    let Some(outbounds) = value.get("outbounds").and_then(|o| o.as_array()) else {
        return Vec::new();
    };
    outbounds
        .iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("vless"))
        .filter_map(|o| {
            let server = o.get("server").and_then(|s| s.as_str())?;
            let port = o.get("server_port").and_then(serde_json::Value::as_u64)?;
            let tag = o.get("tag").and_then(|t| t.as_str()).unwrap_or_default();
            Some((tag.to_string(), format!("{server}:{port}")))
        })
        .collect()
}

/// Collect the `"server:server_port"` endpoint of every `vless` outbound in a
/// sing-box config. Outbounds missing either field are skipped; duplicates are
/// dropped keeping first-occurrence order (nodes share endpoints across
/// outbounds, and one endpoint must be probed once).
fn parse_vless_endpoints(config_json: &str) -> Vec<String> {
    let mut endpoints: Vec<String> = Vec::new();
    for (_, endpoint) in parse_vless_nodes(config_json) {
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

    /// `GET /proxies/<group>` as observed on the owner's Mac on 2026-09-17
    /// (realm net-observer, node #62): the selection and the members, in
    /// the group's order, with the fields this build does not read ignored.
    #[test]
    fn parses_the_groups_selection_and_members() {
        let body = r#"{"type":"URLTest","now":"vless-out-6","all":["vless-out-6","vless-out-5","vless-out-2","vless-out-3"],"history":[]}"#;
        let g = parse_clash_group(body).expect("the observed body decodes");
        assert_eq!(g.now.as_deref(), Some("vless-out-6"));
        assert_eq!(
            g.all,
            vec!["vless-out-6", "vless-out-5", "vless-out-2", "vless-out-3"]
        );
        let body =
            r#"{"name":"GLOBAL","type":"Selector","now":"node-a","all":["node-a","node-b"]}"#;
        assert_eq!(
            parse_clash_group(body).and_then(|g| g.now).as_deref(),
            Some("node-a")
        );
    }

    /// A body without `now` (a plain proxy, not a group) has no selection and
    /// no members — never an invented one.
    #[test]
    fn no_now_field_is_no_selection() {
        let body = r#"{"name":"GLOBAL","type":"Selector"}"#;
        let g = parse_clash_group(body).unwrap();
        assert_eq!(g.now, None);
        assert!(g.all.is_empty());
    }

    #[test]
    fn malformed_json_is_none() {
        assert_eq!(parse_clash_group("not json"), None);
    }

    /// The four delay-test bodies observed on 2026-09-17 (realm net-observer,
    /// node #62), each read as the record keeps it: an answer as its
    /// latency, a timeout or a test error as "no answer", an unknown node as
    /// no measurement — and anything not of that shape the same way.
    #[test]
    fn parses_the_four_observed_delay_bodies() {
        assert_eq!(parse_delay(r#"{"delay":202}"#), DialOutcome::Ok(202));
        assert_eq!(parse_delay(r#"{"delay":352}"#), DialOutcome::Ok(352));
        assert_eq!(
            parse_delay(r#"{"message":"Timeout"}"#),
            DialOutcome::NoAnswer
        );
        assert_eq!(
            parse_delay(r#"{"message":"An error occurred in the delay test"}"#),
            DialOutcome::NoAnswer
        );
        assert_eq!(
            parse_delay(r#"{"message":"Resource not found"}"#),
            DialOutcome::Unknown
        );
        assert_eq!(parse_delay("not json"), DialOutcome::Unknown);
        assert_eq!(
            parse_delay(r#"{"message":"something new"}"#),
            DialOutcome::Unknown
        );
        assert_eq!(parse_delay("{}"), DialOutcome::Unknown);
    }

    /// An answer is never the record's `0`: a sub-millisecond delay reads as
    /// 1 ms, and a delay past `u32` saturates rather than wraps.
    #[test]
    fn an_answered_delay_is_never_zero() {
        assert_eq!(parse_delay(r#"{"delay":0}"#), DialOutcome::Ok(1));
        assert_eq!(
            parse_delay(r#"{"delay":4294967296}"#),
            DialOutcome::Ok(u32::MAX)
        );
    }

    /// The dial's home row: every vless outbound's tag paired with its
    /// endpoint, in config order, shared endpoints kept per node.
    #[test]
    fn extracts_vless_nodes_with_their_endpoints() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "a", "server": "1.1.1.1", "server_port": 443},
                {"type": "direct", "tag": "direct"},
                {"type": "vless", "tag": "b", "server": "1.1.1.1", "server_port": 443},
                {"type": "vless", "tag": "c", "server": "2.2.2.2", "server_port": 2053},
                {"type": "vless", "tag": "d", "server": "3.3.3.3"}
            ]
        }"#;
        assert_eq!(
            parse_vless_nodes(cfg),
            vec![
                ("a".to_string(), "1.1.1.1:443".to_string()),
                ("b".to_string(), "1.1.1.1:443".to_string()),
                ("c".to_string(), "2.2.2.2:2053".to_string()),
            ]
        );
        assert!(parse_vless_nodes("{}").is_empty());
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
    /// empty strings as `None`, the port parsed, the chain's FIRST element, the
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
        assert_eq!(direct.chain.as_deref(), Some("vless-out-6"));

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

    /// When sing-box knows only the uid of the flow's owner it writes that
    /// uid as the path; a bare integer is not a process name, so the fact is
    /// absent rather than a process called `501`.
    #[test]
    fn a_bare_uid_is_not_a_process() {
        assert_eq!(process_name("501"), None);
        assert_eq!(process_name("0"), None);
        assert_eq!(process_name(" 501 "), None);
        // A name that merely ends in digits is still a name.
        assert_eq!(process_name("/usr/bin/python3").as_deref(), Some("python3"));
    }
}
