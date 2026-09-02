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
    /// just a *when*. `None` marks a transition no peer asked for — today that
    /// is exactly the startup edge ([`ObservingCause::Startup`]) — and stores
    /// as SQL `NULL`.
    pub peer_uid: Option<u32>,
    /// What produced the transition. Defaults to [`ObservingCause::Control`],
    /// so a record written before this field existed — a row with a `NULL`
    /// `cause`, or a frame from an older daemon — still decodes, and reads as
    /// what it in fact was: an operator's control-socket toggle.
    #[serde(default)]
    pub cause: ObservingCause,
}

/// What produced an [`ObservingEdge`].
///
/// The observing state itself is process-scoped and deliberately never
/// persisted — a restart always resumes collecting — so a daemon that dies
/// while paused writes no resume edge at all. Without this distinction the
/// `observing_edge` table cannot tell "still paused" from "crashed while
/// paused, then restarted", and a reader has to *infer* where the silence
/// ended. `Startup` is that missing fact written down: this process began
/// collecting at this instant. It records the transition, never the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservingCause {
    /// An operator's `ControlCmd::SetObserving` over the control socket.
    #[default]
    Control,
    /// The daemon started up and began collecting. Always `observing: true`
    /// and `peer_uid: None`: nobody asked for it, the process simply booted.
    Startup,
}

impl ObservingCause {
    /// The token stored in the `observing_edge.cause` column and read back by
    /// the gap derivation in `store::diagnosis`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Startup => "startup",
        }
    }
}
