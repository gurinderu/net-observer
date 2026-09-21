//! Clash/Mihomo RESTful API client and the proxy-side facts adapters.
//!
//! [`ClashClient`] reads one proxy — a group (`type` `Selector` / `URLTest`
//! / `Fallback`: its selected member `now` and its members `all`) or a
//! single node (`type` `VLESS`, `Direct`, …), the same `GET /proxies/<name>`
//! endpoint either way — together with its own URL-test history
//! (`history: [{time, delay}]`, Clash-compatible in shape), and the live
//! flow list via `GET /connections` (the surface as observed on sing-box:
//! realm net-observer, nodes #127, #62 and #139).
//!
//! The history's semantics are sing-box's, not Clash's
//! (`protocol/group/urltest.go` v1.12, `outbound/urltest.go` v1.8): the
//! URLTest group tests every member on its `interval`; a SUCCESSFUL test
//! stores one entry `{time, delay}` — `delay` in milliseconds, and `0` a
//! real sub-millisecond answer — while a FAILED test DELETES the node's
//! entry, so `/proxies/<node>` then renders `"history": []`. `delay: 0` as
//! a failure marker is Clash/mihomo's convention and never appears here.
//! An empty list therefore means "not tested yet" (observed on every node at
//! 18:23 on 2026-09-17, before the group's first round) OR "the last test
//! failed" — told apart only by whether an entry was seen before, which is
//! the collector's memory, not this surface (realm net-observer, node #62).
//!
//! It deliberately does NOT call `GET /proxies/<node>/delay`, for two facts
//! observed on the owner's Mac (realm net-observer, node #62): sing-box's
//! handler ignores an `http://` URL and substitutes
//! `https://www.gstatic.com/generate_204` (`url=http://192.0.2.1/` answered
//! `{"delay":517}` while `https://192.0.2.1/` timed out), so a by-IP /
//! by-name split through it never happens; and it writes its result into
//! the urltest group's history (`urlTestHistory` in
//! `experimental/clashapi/proxies.go`, v1.5–v1.12) — a failed dial deletes
//! the node's entry and the group deselects it, a success overwrites the
//! group's own measurement — so the caller steers sing-box's selection,
//! which "observe, never act" forbids. The daemon reads what sing-box
//! measured on its own interval instead.
//!
//! [`ProxySystemFacts`] implements [`collector_proxy::ProxyFacts`]: it reads the
//! VLESS nodes and their server endpoints from the rendered sing-box config at
//! runtime (never baked into the binary — secret hygiene), probes the TUN with
//! an HTTP request, and reads the group and each node's history.
//! [`ConnectionSystemFacts`] implements
//! [`collector_connections::ConnectionFacts`] over the same client.

use std::path::PathBuf;
use std::time::Duration;

use collector_connections::{ConnectionFacts, OwnListeners};
use collector_core::Readiness;
use collector_proxy::{ProxyFacts, ProxyInfo, TunProbe, UrlTestEntry};
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

    /// One proxy as the API describes it, via `GET /proxies/<name>` — a
    /// group or a single node, the same endpoint: its type, its selection
    /// and members (a group's), and the newest entry of its own URL-test
    /// history (realm net-observer, nodes #62, #139). `None` when the API
    /// did not answer or the body does not decode.
    pub async fn proxy(&self, name: &str) -> Option<ProxyInfo> {
        // The name is an outbound tag from sing-box's config — a path
        // segment, so it is percent-encoded as one rather than pasted in.
        let url = self.endpoint(&["proxies", name])?;
        let resp = match self.http.get(url.clone()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(%url, error = %e, "clash proxies query failed");
                return None;
            }
        };
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(%url, error = %e, "clash proxies query failed");
                return None;
            }
        };
        let parsed = parse_proxy(&body, name);
        if parsed.is_none() {
            tracing::debug!(%url, "clash proxies body did not decode");
        }
        parsed
    }

    /// `base` with `segments` appended to its path, each percent-encoded as
    /// one segment; `None` (logged) when `base` is not a URL at all — a
    /// misconfiguration, reported once per read rather than as a
    /// transport failure with a nonsense address.
    fn endpoint(&self, segments: &[&str]) -> Option<reqwest::Url> {
        let mut url = match reqwest::Url::parse(&self.base) {
            Ok(url) => url,
            Err(e) => {
                tracing::debug!(base = %self.base, error = %e, "clash api base is not a url");
                return None;
            }
        };
        match url.path_segments_mut() {
            Ok(mut path) => {
                path.pop_if_empty().extend(segments);
            }
            Err(()) => {
                tracing::debug!(base = %self.base, "clash api base cannot carry a path");
                return None;
            }
        }
        Some(url)
    }

    /// Every live flow the proxy carries right now, via `GET /connections`.
    ///
    /// `None` when the API did not answer: a transport failure or timeout, a
    /// non-2xx status, or a body that does not decode — each logged at debug
    /// and each the same fact to the caller, "could not look". Never an empty
    /// list for any of them.
    pub async fn connections(&self) -> Option<Vec<LiveConnection>> {
        let url = self.endpoint(&["connections"])?;
        let resp = match self.http.get(url.clone()).send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(%url, error = %e, "clash connections query failed");
                return None;
            }
        };
        let status = resp.status();
        if !status.is_success() {
            tracing::debug!(%url, %status, "clash connections query refused");
            return None;
        }
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => {
                tracing::debug!(%url, error = %e, "clash connections query failed");
                return None;
            }
        };
        let parsed = parse_connections(&body);
        if parsed.is_none() {
            tracing::debug!(%url, "clash connections body did not decode");
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

/// The `GET /proxies/<name>` body, as far as the daemon reads it — a
/// group's and a single node's alike: the type, the name, a group's
/// selection and members, and the URL-test history. `udp` and whatever else
/// sing-box adds are ignored by serde's default.
#[derive(Deserialize)]
struct ProxyBody {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    all: Vec<String>,
    #[serde(default)]
    history: Vec<HistoryEntry>,
}

/// One URL-test entry as sing-box renders it: `time` RFC 3339, `delay` in
/// milliseconds — a real measurement, since sing-box stores an entry only
/// for a successful test (see the module doc).
#[derive(Deserialize)]
struct HistoryEntry {
    #[serde(default)]
    time: String,
    #[serde(default)]
    delay: u64,
}

/// Parse a `/proxies/<name>` body (realm net-observer, nodes #62, #139).
/// `None` when the body is not JSON of that shape at all. The name is the
/// body's own, falling back to `requested`; the URL-test entry is the
/// NEWEST by the entries' own times, not by position, so a reordered list
/// still reads right, and `None` when the history is empty or no entry
/// carries a parseable time. A delay past `u32` saturates rather than wraps.
fn parse_proxy(body: &str, requested: &str) -> Option<ProxyInfo> {
    let body: ProxyBody = serde_json::from_str(body).ok()?;
    let urltest = body
        .history
        .iter()
        .filter_map(|e| {
            let at_us = chrono::DateTime::parse_from_rfc3339(&e.time)
                .ok()?
                .timestamp_micros();
            Some(UrlTestEntry {
                at_us,
                ms: u32::try_from(e.delay).unwrap_or(u32::MAX),
            })
        })
        .max_by_key(|e| e.at_us);
    Some(ProxyInfo {
        name: body
            .name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| requested.to_string()),
        kind: body.kind,
        now: body.now,
        all: body.all,
        urltest,
    })
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
    /// Every `vless` outbound as `(tag, "server:server_port")` from the
    /// rendered sing-box config: the endpoints to probe and the row each
    /// node's reading rides, from one read.
    async fn node_endpoints(&self) -> Vec<(String, String)> {
        // A small local config file: an instant read, kept synchronous inside
        // the async fn (no blocking of consequence, mirroring `getloadavg`).
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

    async fn group(&self) -> Option<ProxyInfo> {
        self.clash.proxy(&self.selector_group).await
    }

    /// Every name read at once, one task each on the daemon's runtime, so a
    /// stalled API costs the one [`HTTP_TIMEOUT`], not one per name. The
    /// client is cloned into each task (its connection pool is shared
    /// behind an `Arc`); a task that panicked answers `None` like a read
    /// that failed.
    async fn proxies(&self, names: &[String]) -> Vec<Option<ProxyInfo>> {
        let mut tasks = tokio::task::JoinSet::new();
        for (i, name) in names.iter().enumerate() {
            let clash = self.clash.clone();
            let name = name.clone();
            tasks.spawn(async move { (i, clash.proxy(&name).await) });
        }
        let mut out = vec![None; names.len()];
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((i, info)) => out[i] = info,
                Err(e) => tracing::debug!(error = %e, "clash proxies read task failed"),
            }
        }
        out
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
/// same HTTP client construction and timeout — not a second HTTP stack), and
/// sing-box's own listeners from the same rendered config the proxy facts
/// read their node list from.
#[derive(Debug, Clone)]
pub struct ConnectionSystemFacts {
    /// Path to the rendered sing-box config JSON.
    singbox_config: PathBuf,
    clash: ClashClient,
}

impl ConnectionSystemFacts {
    /// Build the adapter over the rendered sing-box config at
    /// `singbox_config` and the Clash/Mihomo API at `clash_base`.
    #[must_use]
    pub fn new(singbox_config: impl Into<PathBuf>, clash_base: impl Into<String>) -> Self {
        Self {
            singbox_config: singbox_config.into(),
            clash: ClashClient::new(clash_base),
        }
    }
}

impl ConnectionFacts for ConnectionSystemFacts {
    async fn connections(&self) -> Option<Vec<LiveConnection>> {
        self.clash.connections().await
    }

    /// The TUN inbound's address and the `dns-in` listener from the rendered
    /// config, read per tick like [`ProxySystemFacts::node_endpoints`] (a
    /// small local file, an instant synchronous read). A config that cannot
    /// be read names neither: the fold then judges without them, and says
    /// `lan` / `external` for those addresses rather than hiding them.
    ///
    /// Also the iface-derivation facts (realm net-observer, node #75, third
    /// paragraph): `tun_if` resolved the same way
    /// `dhcp_arp::SystemFacts::singbox_tun_iface` does — the address from
    /// THIS read of the config, then one `ifconfig`, through the shared
    /// [`crate::dhcp_arp::iface_with_inet`] parser — `direct_if` via the
    /// same route-table resolution the link facts' `phys_iface` falls back
    /// to ([`crate::dhcp_arp::default_route_iface`]), and the direct/block
    /// outbound tags from this same config text. All local reads (config
    /// file, `ifconfig`, `route -n get`) — passive-tier safe, same as the
    /// rest of this method: no packet on the wire.
    async fn own_listeners(&self) -> OwnListeners {
        let Ok(text) = std::fs::read_to_string(&self.singbox_config) else {
            tracing::debug!(path = ?self.singbox_config, "sing-box config unreadable");
            return OwnListeners::default();
        };
        let tun_addr = singbox_tun_addr(&text);
        let tun_if = match &tun_addr {
            Some(addr) => crate::dhcp_arp::run("ifconfig", &[])
                .await
                .and_then(|out| crate::dhcp_arp::iface_with_inet(&out, addr)),
            None => None,
        };
        let (direct_tags, block_tags) = singbox_outbound_tags(&text);
        OwnListeners {
            tun_addr,
            dns_pin: singbox_dns_pin(&text),
            tun_if,
            direct_if: crate::dhcp_arp::default_route_iface().await,
            direct_tags,
            block_tags,
        }
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

/// The address sing-box's own DNS listener sits on: the `listen` of the
/// first `inbounds[]` entry tagged `dns-in` (the `direct` inbound that
/// forwards to sing-box's resolver — `192.0.2.53` in the owner's config),
/// read from the rendered config like the TUN address above, never
/// hardcoded. Matched by tag, not by type: the tag is the name the config
/// gives the listener, the type is how it happens to be implemented. `None`
/// when the config names no such inbound or it carries no `listen`, which
/// the fold treats as "cannot judge" (realm net-observer, node #75).
pub(crate) fn singbox_dns_pin(config_json: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(config_json).ok()?;
    let inbounds = value.get("inbounds")?.as_array()?;
    inbounds
        .iter()
        .filter(|i| i.get("tag").and_then(|t| t.as_str()) == Some("dns-in"))
        .find_map(|i| i.get("listen")?.as_str())
        .filter(|listen| !listen.is_empty())
        .map(str::to_string)
}

/// The tags of every `type = "direct"` and every `type = "block"` outbound
/// in a sing-box config, as `(direct_tags, block_tags)` — what
/// [`collector_connections::OwnListeners::iface_for_chain`] matches a flow's
/// `chain` against to tell a direct-out flow and a blocked one apart from a
/// tunneled one. Read by type, never by tag (`direct-out`/`block-out` are
/// this owner's names, not sing-box's convention — the config renames them
/// at will), like [`singbox_tun_addr`] reads by the inbound's own type/tag
/// rather than a hardcoded name. Absent `outbounds`, or a tag-less entry, is
/// simply not collected — the empty list, not an error. Both lists are in
/// config order and may contain duplicates if the config does (never
/// deduplicated: a membership test is unaffected either way).
pub(crate) fn singbox_outbound_tags(config_json: &str) -> (Vec<String>, Vec<String>) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config_json) else {
        return (Vec::new(), Vec::new());
    };
    let Some(outbounds) = value.get("outbounds").and_then(|o| o.as_array()) else {
        return (Vec::new(), Vec::new());
    };
    let tags_of = |kind: &str| -> Vec<String> {
        outbounds
            .iter()
            .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some(kind))
            .filter_map(|o| o.get("tag").and_then(|t| t.as_str()))
            .map(str::to_string)
            .collect()
    };
    (tags_of("direct"), tags_of("block"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The API path is built from `base` by segments, so an outbound tag
    /// with a space or a slash is one percent-encoded segment rather than a
    /// second path; a trailing slash on `base` does not double up; and a
    /// base that is not a URL at all yields no endpoint.
    #[test]
    fn endpoints_encode_each_segment_and_tolerate_a_trailing_slash() {
        let c = ClashClient::new("http://127.0.0.1:9090");
        assert_eq!(
            c.endpoint(&["proxies", "vless-out-8"]).unwrap().as_str(),
            "http://127.0.0.1:9090/proxies/vless-out-8"
        );
        assert_eq!(
            c.endpoint(&["proxies", "a b/c"]).unwrap().as_str(),
            "http://127.0.0.1:9090/proxies/a%20b%2Fc"
        );
        let c = ClashClient::new("http://127.0.0.1:9090/");
        assert_eq!(
            c.endpoint(&["connections"]).unwrap().as_str(),
            "http://127.0.0.1:9090/connections"
        );
        assert_eq!(ClashClient::new("not a url").endpoint(&["proxies"]), None);
        assert_eq!(ClashClient::new("").endpoint(&["proxies"]), None);
    }

    /// The three `GET /proxies/<name>` bodies observed on the owner's Mac on
    /// 2026-09-17 (realm net-observer, nodes #62, #139), each read as the
    /// collector needs it: the top Selector with its selection and members
    /// (a group, so it carries no test of its own that matters), the nested
    /// URLTest group the same way, and a node with its newest history entry
    /// — its time as epoch microseconds, its delay as measured — with the
    /// fields this build does not read (`udp`) ignored.
    #[test]
    fn parses_the_observed_selector_urltest_and_node_bodies() {
        let main = parse_proxy(
            r#"{"type":"Selector","name":"vless-main","udp":true,"history":[],"now":"vless-out-8","all":["vless-auto","vless-out-8","vless-out-4","vless-out-1","block-out"]}"#,
            "vless-main",
        )
        .expect("the observed Selector body decodes");
        assert_eq!(main.name, "vless-main");
        assert_eq!(main.kind, "Selector");
        assert!(main.is_group());
        assert!(!main.is_untestable());
        assert_eq!(main.now.as_deref(), Some("vless-out-8"));
        assert_eq!(
            main.all,
            vec![
                "vless-auto",
                "vless-out-8",
                "vless-out-4",
                "vless-out-1",
                "block-out"
            ]
        );
        assert_eq!(main.urltest, None);

        let auto = parse_proxy(
            r#"{"type":"URLTest","name":"vless-auto","udp":true,"history":[],"now":"vless-out-6","all":["vless-out-6","vless-out-5","vless-out-2","vless-out-3"]}"#,
            "vless-auto",
        )
        .expect("the observed URLTest body decodes");
        assert!(auto.is_group());
        assert_eq!(auto.now.as_deref(), Some("vless-out-6"));
        assert_eq!(auto.all.len(), 4);

        let node = parse_proxy(
            r#"{"type":"VLESS","name":"vless-out-8","udp":true,"history":[{"time":"2026-09-17T20:55:29.874142+03:00","delay":186}]}"#,
            "vless-out-8",
        )
        .expect("the observed node body decodes");
        assert_eq!(node.name, "vless-out-8");
        assert_eq!(node.kind, "VLESS");
        assert!(!node.is_group());
        assert!(!node.is_untestable());
        assert_eq!(node.now, None);
        assert!(node.all.is_empty());
        assert_eq!(
            node.urltest,
            Some(UrlTestEntry {
                at_us: 1_789_667_729_874_142,
                ms: 186,
            })
        );
    }

    /// The outbounds sing-box never tests are told by their type, whatever
    /// its case; a body without a name takes the name asked for.
    #[test]
    fn direct_block_and_dns_are_untestable_and_the_name_falls_back() {
        for kind in ["Direct", "Block", "DNS", "direct"] {
            let info = parse_proxy(&format!(r#"{{"type":"{kind}","history":[]}}"#), "x").unwrap();
            assert!(info.is_untestable(), "{kind}");
            assert!(!info.is_group(), "{kind}");
            assert_eq!(info.name, "x");
        }
        assert!(
            parse_proxy(r#"{"type":"Fallback","now":"a","all":["a"]}"#, "f")
                .unwrap()
                .is_group()
        );
    }

    /// The newest entry is the newest by its own time, not by position, so
    /// a reordered list still reads right; `delay` 0 is a real answer.
    #[test]
    fn the_newest_history_entry_is_by_time() {
        let body = r#"{"type":"VLESS","name":"vless-out-6","history":[
            {"time":"2026-09-17T18:40:00+03:00","delay":0},
            {"time":"2026-09-17T18:30:00+03:00","delay":352},
            {"time":"2026-09-17T18:35:00+03:00","delay":202}
        ]}"#;
        assert_eq!(
            parse_proxy(body, "vless-out-6").unwrap().urltest,
            Some(UrlTestEntry {
                at_us: 1_789_659_600_000_000,
                ms: 0,
            }),
            "a sub-millisecond answer is the answer it is"
        );
    }

    /// The empty history observed on every node at 18:23 on 2026-09-17 is
    /// no entry — untested yet, or the last test failed; this surface cannot
    /// tell — and so is a body without a history or an entry whose time
    /// does not parse. No body of that shape at all is `None`; a delay past
    /// `u32` saturates rather than wraps.
    #[test]
    fn an_empty_or_unreadable_history_is_no_entry() {
        let empty = parse_proxy(
            r#"{"type":"VLESS","name":"vless-out-6","history":[]}"#,
            "vless-out-6",
        )
        .unwrap();
        assert_eq!(empty.urltest, None);
        assert_eq!(
            parse_proxy(r#"{"type":"VLESS"}"#, "n").unwrap().urltest,
            None
        );
        assert_eq!(
            parse_proxy(r#"{"history":[{"time":"yesterday","delay":5}]}"#, "n")
                .unwrap()
                .urltest,
            None
        );
        assert_eq!(parse_proxy("not json", "n"), None);
        assert_eq!(
            parse_proxy(
                r#"{"history":[{"time":"2026-09-17T15:30:00Z","delay":4294967296}]}"#,
                "n"
            )
            .unwrap()
            .urltest
            .map(|e| e.ms),
            Some(u32::MAX)
        );
    }

    /// The reading's home row: every vless outbound's tag paired with its
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

    /// Nodes share a server IP across outbounds — on different ports they
    /// are different listeners, while a repeated (server, port) pair is one
    /// listener under two names: the list keeps every node, and the
    /// collector probes each distinct endpoint once.
    #[test]
    fn shared_endpoints_are_kept_per_node() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "a", "server": "1.1.1.1", "server_port": 443},
                {"type": "vless", "tag": "b", "server": "1.1.1.1", "server_port": 2053},
                {"type": "vless", "tag": "c", "server": "1.1.1.1", "server_port": 443}
            ]
        }"#;
        assert_eq!(
            parse_vless_nodes(cfg),
            vec![
                ("a".to_string(), "1.1.1.1:443".to_string()),
                ("b".to_string(), "1.1.1.1:2053".to_string()),
                ("c".to_string(), "1.1.1.1:443".to_string()),
            ]
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
        assert_eq!(
            parse_vless_nodes(cfg),
            vec![("b".to_string(), "2.2.2.2:443".to_string())]
        );
    }

    #[test]
    fn no_outbounds_is_empty() {
        assert!(parse_vless_nodes("{}").is_empty());
        assert!(parse_vless_nodes("garbage").is_empty());
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

    /// The DNS pin is the `listen` of the inbound tagged `dns-in`, found by
    /// its tag among the other inbounds; a config without one, or whose
    /// `dns-in` names no listener, pins nothing.
    #[test]
    fn extracts_the_dns_pin_from_the_dns_in_inbound() {
        let cfg = r#"{
            "inbounds": [
                {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1"},
                {"type": "direct", "tag": "dns-in", "listen": "192.0.2.53", "listen_port": 53,
                 "override_address": "1.1.1.1", "override_port": 53},
                {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"]}
            ]
        }"#;
        assert_eq!(singbox_dns_pin(cfg).as_deref(), Some("192.0.2.53"));
        assert_eq!(singbox_dns_pin("{}"), None);
        assert_eq!(
            singbox_dns_pin(r#"{"inbounds":[{"type":"direct","tag":"other","listen":"1.2.3.4"}]}"#),
            None
        );
        assert_eq!(
            singbox_dns_pin(r#"{"inbounds":[{"type":"direct","tag":"dns-in"}]}"#),
            None
        );
        assert_eq!(
            singbox_dns_pin(r#"{"inbounds":[{"type":"direct","tag":"dns-in","listen":""}]}"#),
            None
        );
        assert_eq!(singbox_dns_pin("garbage"), None);
    }

    /// Direct and block outbound tags are read by `type`, never by a
    /// hardcoded tag name (`direct-out`/`block-out` are this owner's own
    /// names, not sing-box's convention): a renamed or duplicated tag is
    /// still found, and a `vless`/other outbound contributes to neither list.
    #[test]
    fn extracts_direct_and_block_outbound_tags_by_type() {
        let cfg = r#"{
            "outbounds": [
                {"type": "vless", "tag": "vless-out-6", "server": "1.1.1.1", "server_port": 443},
                {"type": "direct", "tag": "direct-egress"},
                {"type": "block", "tag": "reject-ads"},
                {"type": "direct", "tag": "another-direct"}
            ]
        }"#;
        assert_eq!(
            singbox_outbound_tags(cfg),
            (
                vec!["direct-egress".to_string(), "another-direct".to_string()],
                vec!["reject-ads".to_string()]
            )
        );
    }

    /// A config with no `direct`/`block` outbound at all — or no config —
    /// yields two empty lists, never an invented tag.
    #[test]
    fn no_direct_or_block_outbound_is_two_empty_lists() {
        assert_eq!(singbox_outbound_tags("{}"), (Vec::new(), Vec::new()));
        assert_eq!(
            singbox_outbound_tags(r#"{"outbounds":[{"type":"vless","tag":"a"}]}"#),
            (Vec::new(), Vec::new())
        );
        assert_eq!(singbox_outbound_tags("garbage"), (Vec::new(), Vec::new()));
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
