use serde::{Deserialize, Serialize};

/// One pause/resume boundary of the daemon's own collection.
///
/// The single value behind BOTH sinks of a transition: the durable
/// `observing_edge` row (`store::Store::write_observing_edge`) and the realtime
/// `net_observer_ipc::StreamFrame::Observing` frame. One struct, two sinks — the DB
/// row and the wire frame cannot describe the same transition differently.
///
/// Written once per real EDGE, never per tick: a paused daemon deliberately
/// produces no samples (the one sanctioned exception to "SKIP, never silence"),
/// and this row is what bounds that silence and makes it attributable offline.
/// A `SetObserving` that does not change the state is not an edge and produces
/// neither a row nor a frame — a no-op click must not manufacture a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservingEdge {
    /// When the transition took effect (epoch microseconds).
    pub ts_us: i64,
    /// The state collection moved *into*: `false` opens a gap, `true` closes one.
    pub observing: bool,
    /// The uid of the control-socket peer that asked for it. Always `Some` for
    /// every edge v1 produces — the record is only written after the daemon's
    /// peer-credential gate passed, so the gap is attributable to a *who*, not
    /// just a *when*. `None` is reserved for a future daemon-initiated
    /// transition and stores as SQL `NULL`.
    pub peer_uid: Option<u32>,
}
