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
///
/// `tun_if`/`direct_if`/`direct_tags`/`block_tags` are what
/// [`OwnListeners::iface_for_chain`] derives a flow's egress interface from
/// (realm net-observer, node #75, third paragraph): the interface carrying
/// sing-box's TUN address, the machine's physical egress, and the tags of
/// every `type = "direct"` / `type = "block"` outbound in the rendered
/// config. None of the four is hardcoded — a config that renames or drops an
/// outbound changes what these carry, never what the fold assumes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnListeners {
    pub tun_addr: Option<String>,
    pub dns_pin: Option<String>,
    /// The interface carrying sing-box's own TUN address right now. `None`
    /// when the config names no TUN address, or no interface currently
    /// carries it (sing-box not running).
    pub tun_if: Option<String>,
    /// The machine's physical egress interface (the default route's).
    /// `None` when it could not be read.
    pub direct_if: Option<String>,
    /// Tags of every `type = "direct"` outbound in the rendered config, in
    /// no particular order.
    pub direct_tags: Vec<String>,
    /// Tags of every `type = "block"` outbound in the rendered config, in no
    /// particular order.
    pub block_tags: Vec<String>,
}

impl OwnListeners {
    /// The scope of a flow to `dst_ip`, judged against these listeners
    /// ([`classify_scope`]).
    #[must_use]
    pub fn classify(&self, dst_ip: Option<&str>) -> ConnectionScope {
        classify_scope(dst_ip, self.tun_addr.as_deref(), self.dns_pin.as_deref())
    }

    /// The egress interface a flow carried by `chain` actually left through
    /// (realm net-observer, node #75, third paragraph): flows are presented
    /// by interface name, not by outbound-chain tag, because Clash's API has
    /// no interface field of its own.
    ///
    /// `chain` is the outbound that actually carried the flow (the FIRST
    /// element of the Clash API's `chains`, already the final node — see
    /// [`types::LiveConnection::chain`]), so this matches tags directly, no
    /// selector descent needed:
    /// - `chain` names a `block_tags` member → `Some("blocked")`, the
    ///   pseudo-value for a blocked flow.
    /// - `chain` names a `direct_tags` member → `direct_if` (`None` when the
    ///   physical egress could not be read — never invented).
    /// - any other non-empty `chain` → `tun_if` (`None` when it could not be
    ///   read).
    /// - `chain` is `None` or empty → `None`: nothing carried the flow, so
    ///   there is nothing to derive from.
    ///
    /// Pure. An unrecognised chain name is `tun_if`, not `None`: the
    /// config's `direct`/`block` outbounds are enumerated exhaustively above,
    /// so anything else is presumed to have gone through the tunnel like the
    /// vast majority of outbounds do.
    #[must_use]
    pub fn iface_for_chain(&self, chain: Option<&str>) -> Option<String> {
        let chain = chain?;
        if chain.is_empty() {
            return None;
        }
        if self.block_tags.iter().any(|t| t == chain) {
            return Some("blocked".to_string());
        }
        if self.direct_tags.iter().any(|t| t == chain) {
            return self.direct_if.clone();
        }
        self.tun_if.clone()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The listeners the owner's config names, with a direct and a block
    /// outbound each under their own tag (never the hardcoded `direct-out`).
    fn listeners() -> OwnListeners {
        OwnListeners {
            tun_addr: Some("172.19.0.1".into()),
            dns_pin: Some("192.0.2.53".into()),
            tun_if: Some("utun10".into()),
            direct_if: Some("en0".into()),
            direct_tags: vec!["direct-egress".into()],
            block_tags: vec!["reject-ads".into()],
        }
    }

    #[test]
    fn a_tunneled_chain_maps_to_the_tun_interface() {
        assert_eq!(
            listeners().iface_for_chain(Some("vless-out-6")),
            Some("utun10".to_string())
        );
    }

    #[test]
    fn a_direct_tagged_chain_maps_to_the_physical_interface() {
        assert_eq!(
            listeners().iface_for_chain(Some("direct-egress")),
            Some("en0".to_string())
        );
    }

    #[test]
    fn a_block_tagged_chain_maps_to_the_blocked_pseudo_value() {
        assert_eq!(
            listeners().iface_for_chain(Some("reject-ads")),
            Some("blocked".to_string())
        );
    }

    /// A chain naming neither a direct nor a block outbound reads as
    /// tunneled, like the vast majority of outbounds do.
    #[test]
    fn an_unrecognised_chain_name_maps_to_the_tun_interface() {
        assert_eq!(
            listeners().iface_for_chain(Some("some-other-node")),
            Some("utun10".to_string())
        );
    }

    #[test]
    fn no_chain_maps_to_no_interface() {
        assert_eq!(listeners().iface_for_chain(None), None);
        assert_eq!(listeners().iface_for_chain(Some("")), None);
    }

    /// The underlying facts being unknown must never be papered over with an
    /// invented value: a direct-tagged chain with no readable physical
    /// egress, or a tunneled one with no readable TUN interface, is `None`.
    #[test]
    fn an_unknown_underlying_interface_is_none_not_invented() {
        let mut l = listeners();
        l.direct_if = None;
        assert_eq!(l.iface_for_chain(Some("direct-egress")), None);
        let mut l = listeners();
        l.tun_if = None;
        assert_eq!(l.iface_for_chain(Some("vless-out-6")), None);
    }
}
