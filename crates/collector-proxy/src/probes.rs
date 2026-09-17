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

/// The outcome of one ATTEMPTED dial: sing-box was asked, through its Clash
/// API, to fetch a URL through one node (realm net-observer, node #62).
///
/// Three outcomes, because the record keeps three facts apart: an answer is
/// stored as its latency, [`DialOutcome::NoAnswer`] as `0` — the same `0`
/// `tun_code` uses for "attempted, nothing came back" — and
/// [`DialOutcome::Unknown`] as `NULL` under a named `dial_target`: the API
/// could not run the test at all (it does not know the node, or it did not
/// answer), which is no measurement, never a dead dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialOutcome {
    /// sing-box fetched the URL through the node in this many milliseconds.
    Ok(u32),
    /// sing-box tried and nothing came back within its timeout, or the delay
    /// test reported an error: the record's `0`.
    NoAnswer,
    /// The API does not know the node, or did not answer the request: no
    /// measurement.
    Unknown,
}

impl DialOutcome {
    /// The value that lands in the sample's `dial_*_ms` column: the latency,
    /// `0` for no answer, `None` for no measurement.
    #[must_use]
    pub fn ms(self) -> Option<u32> {
        match self {
            Self::Ok(ms) => Some(ms),
            Self::NoAnswer => Some(0),
            Self::Unknown => None,
        }
    }
}

/// One node's dial on one tick, ready for the mapping: the node, the
/// endpoint its dial went through (so the reading can ride that endpoint's
/// row; `None` when the config names none for it) and the two outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dial {
    pub node: String,
    pub endpoint: Option<String>,
    pub ip: DialOutcome,
    pub name: DialOutcome,
}

/// Proxy facts: the upstream proxy endpoints, the TUN HTTP 204 probe, the
/// active upstream node selection, and the dial probe through the selector
/// group's nodes.
#[allow(async_fn_in_trait)] // internal workspace port, not a published API
pub trait ProxyFacts: Send + Sync {
    /// The upstream proxy endpoints to TCP-probe, as `"host:port"` strings.
    async fn server_endpoints(&self) -> Vec<String>;
    /// Every upstream node the config declares, as `(node, "host:port")`
    /// pairs — the map from a dialled node to the endpoint row its reading
    /// rides. Nodes may share an endpoint.
    async fn node_endpoints(&self) -> Vec<(String, String)>;
    /// Attempt the HTTP 204 probe through the TUN at `url`. Always an
    /// attempt: whether to send it at all is the collector's decision (the
    /// probing tier), taken before this is called.
    async fn tun_probe(&self, url: &str) -> TunProbe;
    async fn selector(&self) -> Option<String>;
    /// The members of the selector group (`all` of `GET /proxies/<group>`):
    /// the nodes the dial probe walks. Empty when the API did not answer.
    async fn group_members(&self) -> Vec<String>;
    /// Ask sing-box to fetch `url` through `node` and report how long it
    /// took (`GET /proxies/<node>/delay`). Always an attempt, like
    /// [`ProxyFacts::tun_probe`]: the probing tier is decided before this is
    /// called (realm net-observer, node #62).
    async fn dial(&self, node: &str, url: &str) -> DialOutcome;
    /// Runtime capability probe: can the proxy collector work here/now?
    async fn preflight(&self) -> Readiness;
}
