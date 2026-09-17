//! The proxy collector's port trait — platform I/O behind a trait boundary so the
//! mapping logic is unit-testable with fakes. The real macOS adapter lives in the
//! `macos` crate. Generic net probes (`Pinger`/`TcpProber`) live in `collector-core`.

use collector_core::Readiness;

/// One held reference stream's per-tick check: whether the established stream
/// still round-tripped data, and how old it was at the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCheck {
    pub alive: bool,
    pub age_s: u32,
}

/// The established-flow discriminator's per-tick reading. `None` on a side
/// means no measurement this tick (the stream was only just opened, or could
/// not be opened at all) — never a verdict.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StallReading {
    /// The stream bound to the physical interface (the direct underlay path).
    pub direct: Option<StreamCheck>,
    /// The stream on the default route (through the TUN while sing-box is up).
    pub tun: Option<StreamCheck>,
}

/// Established-stream prober: holds one long-lived reference stream per path
/// across ticks (the adapter owns the sockets as state between calls) and
/// reports, each tick, whether each still carries data.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait StallProbe: Send + Sync {
    async fn check(&self) -> StallReading;
    /// Drop every held stream, so nothing is kept open — let alone exercised —
    /// while the probing tier is passive (realm net-observer, node #88). The
    /// next `check` re-establishes them, reporting no measurement on that
    /// tick as it does after any teardown. Idempotent: closing nothing is a
    /// no-op.
    async fn close(&self);
}

/// The outcome of one ATTEMPTED TUN probe: the request went out (or tried
/// to), and either an HTTP status came back or nothing did.
///
/// The port distinguishes the two explicitly so the record can: a status is
/// stored as itself, [`TunProbe::NoStatus`] as `tun_code = 0` — the shell
/// oracle's curl `000` — and "not probed at all" (the passive tier, a
/// preflight skip) is the collector's `None`, stored as `NULL`. The offline
/// readings (`why`, `wedge-or-starvation`) and the live `starvation` rule
/// both read that `0` as the dead tun; `NULL` is neither health nor fault.
/// (realm net-observer, node #88)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunProbe {
    /// An HTTP response came back with this status (204 is the healthy one).
    Status(u16),
    /// The request was attempted and no HTTP status came back: connect
    /// refused, timeout, TLS or another transport failure.
    NoStatus,
}

impl TunProbe {
    /// The value that lands in `ProxySample::tun_code` for an attempted probe:
    /// the status, or `0` for no status.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Status(code) => code,
            Self::NoStatus => 0,
        }
    }
}

/// The newest entry of one node's URL-test history as sing-box keeps it
/// (`GET /proxies/<node>` → `history[]`): when sing-box ran the test and
/// what it measured. A history is written only by a SUCCESSFUL test —
/// sing-box's URLTest group deletes the node's entry on a failed one — so
/// `0` ms here is a real sub-millisecond answer, never a failure (realm
/// net-observer, node #62).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlTestEntry {
    /// The entry's `time`, epoch microseconds.
    pub at_us: i64,
    /// The entry's `delay`, milliseconds.
    pub ms: u32,
}

/// One proxy as sing-box's Clash API describes it (`GET /proxies/<name>` —
/// a group and a single node answer on the same endpoint, told apart by
/// `type`): what it is, what it selects, what it contains, and its own
/// URL-test history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyInfo {
    /// The name the API reports (`name`), falling back to the name asked for.
    pub name: String,
    /// The `type` as the API spells it: `Selector` / `URLTest` / `Fallback`
    /// for a group, `VLESS`, `Direct`, `Block`, `DNS`, … for a node.
    pub kind: String,
    /// The selected member (`now`); absent on a node.
    pub now: Option<String>,
    /// The members (`all`), in the order the group lists them; empty on a
    /// node.
    pub all: Vec<String>,
    /// The newest history entry; `None` = the history is empty.
    pub urltest: Option<UrlTestEntry>,
}

impl ProxyInfo {
    /// Whether this is a group — one that selects among members — rather
    /// than a node that carries traffic itself.
    #[must_use]
    pub fn is_group(&self) -> bool {
        ["selector", "urltest", "fallback"]
            .iter()
            .any(|k| self.kind.eq_ignore_ascii_case(k))
    }

    /// Whether this is a `URLTest` group — the one kind that re-tests its
    /// members on an interval, so only their history going empty is
    /// evidence of a failed test (realm net-observer, node #62).
    #[must_use]
    pub fn is_urltest(&self) -> bool {
        self.kind.eq_ignore_ascii_case("urltest")
    }

    /// Whether this is a node sing-box never URL-tests: the direct, block
    /// and DNS outbounds have no upstream to test through.
    #[must_use]
    pub fn is_untestable(&self) -> bool {
        ["direct", "block", "dns"]
            .iter()
            .any(|k| self.kind.eq_ignore_ascii_case(k))
    }
}

/// One node's URL-test reading on one tick, ready for the mapping: the
/// node, the endpoint it tests through (so the reading can ride that
/// endpoint's row; `None` when the config names none for it), the newest
/// history entry the API showed this tick (`None` = no entry now), and —
/// from the collector's memory — since when that history has been empty
/// after having carried an entry (`None` = it has an entry, or never had
/// one) (realm net-observer, node #62).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlTest {
    pub node: String,
    pub endpoint: Option<String>,
    pub entry: Option<UrlTestEntry>,
    pub absent_since_us: Option<i64>,
}

/// Proxy facts: the upstream nodes and their endpoints, the TUN HTTP 204
/// probe, and sing-box's Clash API view of the selector group, its members
/// and each node's own URL-test history.
///
/// Reads of the Clash API and of the rendered config are LOCAL and emit
/// nothing on the wire, so they belong to no emission class and run under
/// every probing tier. The daemon never asks sing-box to test — its delay
/// endpoint writes into the group's history and steers the selection
/// (realm net-observer, node #62).
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait ProxyFacts: Send + Sync {
    /// Every upstream node the config declares, as `(node, "host:port")`
    /// pairs, in config order — one read per tick: the collector derives
    /// the endpoints to TCP-probe (deduplicated: nodes may share one) and
    /// the row a node's reading rides from the same list.
    async fn node_endpoints(&self) -> Vec<(String, String)>;
    /// Attempt the HTTP 204 probe through the TUN at `url`. Always an
    /// attempt: whether to send it at all is the collector's decision (the
    /// probing tier), taken before this is called.
    async fn tun_probe(&self, url: &str) -> TunProbe;
    /// The configured selector group, from one API read: the root the
    /// collector descends from. `None` when the API did not answer.
    async fn group(&self) -> Option<ProxyInfo>;
    /// Every named proxy from one API read each, issued together so a
    /// stalled API costs one timeout, not one per name; `None` in a slot =
    /// that read did not answer or did not decode. Same order as `names`.
    async fn proxies(&self, names: &[String]) -> Vec<Option<ProxyInfo>>;
    /// Runtime capability probe: can the proxy collector work here/now?
    async fn preflight(&self) -> Readiness;
}
