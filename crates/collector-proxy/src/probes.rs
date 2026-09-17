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

/// The selector group as sing-box's Clash API describes it
/// (`GET /proxies/<group>`): the node it selects right now and every member
/// it can select. One read per tick serves both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyGroup {
    /// The selected node (`now`); absent on a body that is not a group's.
    pub now: Option<String>,
    /// The members (`all`), in the order the group lists them.
    pub all: Vec<String>,
}

/// The newest entry of one node's URL-test history as sing-box keeps it
/// (`GET /proxies/<node>` → `history[]`): when sing-box ran the test and
/// what it measured — `0` ms is sing-box's spelling of a failed test, kept
/// as the record's `0` (realm net-observer, node #62).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlTestEntry {
    /// The entry's `time`, epoch microseconds.
    pub at_us: i64,
    /// The entry's `delay`, milliseconds; `0` = the test failed.
    pub ms: u32,
}

/// One node's URL-test reading on one tick, ready for the mapping: the
/// node, the endpoint it tests through (so the reading can ride that
/// endpoint's row; `None` when the config names none for it) and the newest
/// history entry (`None` = sing-box has not tested the node, or the API did
/// not answer — not measured).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlTest {
    pub node: String,
    pub endpoint: Option<String>,
    pub entry: Option<UrlTestEntry>,
}

/// Proxy facts: the upstream nodes and their endpoints, the TUN HTTP 204
/// probe, the selector group, and sing-box's own URL-test history per node.
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
    /// The selector group — its selection and its members — from one API
    /// read. `None` when the API did not answer.
    async fn group(&self) -> Option<ProxyGroup>;
    /// The newest entry of `node`'s URL-test history. `None` = no entry
    /// (an empty history: sing-box has not tested it yet; or the API did not
    /// answer) — never a failure.
    async fn urltest(&self, node: &str) -> Option<UrlTestEntry>;
    /// Runtime capability probe: can the proxy collector work here/now?
    async fn preflight(&self) -> Readiness;
}
