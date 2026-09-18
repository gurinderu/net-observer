//! The `connections` collector's port trait: the live flows the proxy carries,
//! read from its API behind a trait boundary so the fold stays unit-testable
//! with fakes. The real adapter (`GET /connections` on sing-box's Clash API)
//! lives in the `macos` crate.

use collector_core::Readiness;
use types::{ConnectionScope, LiveConnection, classify_scope};

/// sing-box's own two listeners, as its rendered config names them — what
/// marks a flow as never leaving the machine (realm net-observer, node #75).
///
/// `tun_addr` is the TUN inbound's address (`172.19.0.1`: every app's DNS
/// query to sing-box's `dns-in` listener is a flow keyed by it), `dns_pin`
/// the `dns-in` inbound's `listen` (`192.0.2.53`). Each is `None` when the
/// config does not name it or could not be read; the fold then judges
/// without it, and a flow to that listener reads as `lan` (the TUN address
/// is RFC 1918) or `external` (the pin is TEST-NET) — the honest default,
/// never hidden.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnListeners {
    pub tun_addr: Option<String>,
    pub dns_pin: Option<String>,
}

impl OwnListeners {
    /// The scope of a flow to `dst_ip`, judged against these listeners
    /// ([`classify_scope`]).
    #[must_use]
    pub fn classify(&self, dst_ip: Option<&str>) -> ConnectionScope {
        classify_scope(dst_ip, self.tun_addr.as_deref(), self.dns_pin.as_deref())
    }
}

/// The proxy's live flow list, as one reading.
///
/// The methods are native `async fn` (no `async-trait` macro) so the real
/// adapter can use async-native HTTP. Static dispatch (the collector is generic
/// over `F: ConnectionFacts`) keeps this dyn-free, since native `async fn` in
/// traits is not object-safe.
#[allow(async_fn_in_trait)] // internal workspace trait, not a published API
pub trait ConnectionFacts: Send + Sync {
    /// Every live flow the API lists right now — an empty list when nothing
    /// is talking. `None` when the API did not answer (unreachable, a non-2xx
    /// status, an undecodable body): the tick is then a `SKIP` sample, never
    /// silence, and never an empty list that would read as "nothing is
    /// talking".
    async fn connections(&self) -> Option<Vec<LiveConnection>>;
    /// sing-box's own listeners as its rendered config names them right now
    /// — read per tick, like the proxy adapter reads its node list, so a
    /// re-rendered config is picked up without a restart.
    async fn own_listeners(&self) -> OwnListeners;
    /// Runtime capability probe: `Ready` iff the API is configured at all,
    /// else `Unavailable(reason)`. Whether it answers is a per-tick fact the
    /// verdict carries, not a preflight.
    async fn preflight(&self) -> Readiness;
}
