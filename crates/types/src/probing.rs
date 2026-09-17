use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::verdict::ParseVerdictError;

/// One thing this daemon can put on the wire of its own accord — a packet it
/// originates, as opposed to a cache, a config file or a system report it only
/// reads. Every collector emission is one of these; everything else the daemon
/// collects is passive by construction and is not a class.
/// (realm net-observer, node #88)
///
/// The list is the daemon's whole active surface, so a new probe that sends
/// anything must add a variant here before it can be gated — and so the same
/// vocabulary can later name which classes a phase experiment withholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmissionClass {
    /// `link`: the ICMP echo to the default gateway.
    GatewayEcho,
    /// `link`: the TCP connect to the reference host, bound to the physical
    /// interface.
    DirectProbe,
    /// `link`: the ICMP echoes to LAN neighbours on a gateway-`FAIL` tick
    /// (probe-on-suspicion).
    LanProbe,
    /// `proxy`: the HTTP 204 request through the TUN.
    TunProbe,
    /// `proxy`: the TCP connect to each upstream endpoint.
    EndpointProbe,
    /// `proxy`: the two held HTTPS reference streams and the request each
    /// carries every tick.
    HeldStream,
    /// `dns`: the resolver queries.
    DnsQuery,
}

/// How much of its active surface the daemon is allowed to use right now.
///
/// A tier is a named set of [`EmissionClass`]es the daemon may emit, decided
/// by [`ProbingTier::emits`]. `Passive` emits nothing — the daemon is a
/// recorder of what the OS already knows; `Active` emits everything. A third
/// tier (a lighter one, say) is one more arm of `emits`, not a new mechanism.
///
/// Passive means **no emission the daemon makes on its own** — nothing on a
/// timer. An operator's scan (`ScanNeighbors`) is not the daemon's emission:
/// the command is the sanction (realm net-observer, node #91), and the scan
/// writes its own `neighbor_scan` row, so passive does NOT refuse it.
///
/// Process-scoped like the observing switch: never persisted, and a restart
/// returns to the configured default. Every switch is bracketed by a durable
/// [`ProbingEdge`]. (realm net-observer, node #88)
///
/// Serialised lowercase (`"passive"` / `"active"`): the same token travels the
/// socket, sits in the config file and lands in the `probing_edge.tier` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbingTier {
    /// Nothing on the wire. Every probe is withheld and its verdict lands as
    /// `SKIP`; the passive collectors keep reading.
    Passive,
    /// Every emission class runs.
    Active,
}

impl ProbingTier {
    /// Whether this tier lets `class` on the wire.
    ///
    /// Matched on the pair so a tier that emits SOME classes is one arm per
    /// class it admits, with the rest falling through to `false`.
    #[must_use]
    pub fn emits(self, class: EmissionClass) -> bool {
        match (self, class) {
            (Self::Passive, _) => false,
            (Self::Active, _) => true,
        }
    }

    /// The lowercase token: the wire spelling, the config value and the
    /// `probing_edge.tier` column.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passive => "passive",
            Self::Active => "active",
        }
    }
}

impl fmt::Display for ProbingTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProbingTier {
    type Err = ParseVerdictError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "passive" => Ok(Self::Passive),
            "active" => Ok(Self::Active),
            _ => Err(ParseVerdictError(s.to_string())),
        }
    }
}

/// One switch of the probing tier.
///
/// The single value behind BOTH sinks of a transition, exactly like
/// [`ObservingEdge`](crate::ObservingEdge): the durable `probing_edge` row
/// (`store::Store::write_probing_edge`) and the realtime
/// `net_observer_ipc::StreamFrame::Probing` frame. One struct, two sinks.
///
/// Written once per real EDGE, never per tick. A passive daemon is not silent
/// — every withheld probe still lands as a `SKIP` row — but the record must
/// say WHY a stretch of ticks carries no measurement, and which peer asked for
/// it; this row is that statement. The startup default is written as an edge
/// too, so a record that begins passive says so rather than leaving the
/// reader to infer it from a run of `SKIP`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbingEdge {
    /// When the transition took effect (epoch microseconds).
    pub ts_us: i64,
    /// The tier the daemon moved *into*.
    pub tier: ProbingTier,
    /// The uid of the control-socket peer that asked for it, or `None` for a
    /// transition no peer asked for — the startup edge, which applies the
    /// configured default. Stores as SQL `NULL`.
    pub peer_uid: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_CLASS: [EmissionClass; 7] = [
        EmissionClass::GatewayEcho,
        EmissionClass::DirectProbe,
        EmissionClass::LanProbe,
        EmissionClass::TunProbe,
        EmissionClass::EndpointProbe,
        EmissionClass::HeldStream,
        EmissionClass::DnsQuery,
    ];

    /// Passive is "nothing on the wire" for EVERY class — a single class that
    /// slipped through would make the default tier a lie the operator cannot
    /// see.
    #[test]
    fn passive_emits_no_class_at_all() {
        for class in EVERY_CLASS {
            assert!(
                !ProbingTier::Passive.emits(class),
                "{class:?} must be withheld in the passive tier"
            );
        }
    }

    #[test]
    fn active_emits_every_class() {
        for class in EVERY_CLASS {
            assert!(
                ProbingTier::Active.emits(class),
                "{class:?} must run in the active tier"
            );
        }
    }

    /// The token is the wire spelling, the config value and the DB column:
    /// one vocabulary, round-tripped.
    #[test]
    fn tier_token_round_trips() {
        for (tier, token) in [
            (ProbingTier::Passive, "passive"),
            (ProbingTier::Active, "active"),
        ] {
            assert_eq!(tier.as_str(), token);
            assert_eq!(tier.to_string(), token);
            assert_eq!(ProbingTier::from_str(token).unwrap(), tier);
            assert_eq!(
                serde_json::to_string(&tier).unwrap(),
                format!("\"{token}\"")
            );
            assert_eq!(
                serde_json::from_str::<ProbingTier>(&format!("\"{token}\"")).unwrap(),
                tier
            );
        }
        assert!(ProbingTier::from_str("Passive").is_err());
        assert!(ProbingTier::from_str("").is_err());
    }

    #[test]
    fn probing_edge_round_trips_with_a_null_peer() {
        let edge = ProbingEdge {
            ts_us: 42,
            tier: ProbingTier::Passive,
            peer_uid: None,
        };
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"tier\":\"passive\""), "{json}");
        assert_eq!(serde_json::from_str::<ProbingEdge>(&json).unwrap(), edge);
    }
}
