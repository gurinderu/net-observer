//! The shared probing-tier switch the emitting collectors read every tick.

use std::sync::atomic::{AtomicU8, Ordering};

use types::ProbingTier;

/// The daemon's current [`ProbingTier`], shared between the control socket
/// (its only writer) and the link, proxy and dns collectors, which read it once
/// per tick before emitting — exactly the way the link collector's `quiet`
/// `AtomicBool` is shared. Process-scoped and never persisted: the daemon
/// constructs it from the configured default at startup. (realm net-observer,
/// node #88)
///
/// A single atomic rather than a lock: the readers take one load per tick and
/// must never wait on the control path.
#[derive(Debug)]
pub struct ProbingState(AtomicU8);

const PASSIVE: u8 = 0;
const ACTIVE: u8 = 1;

fn encode(tier: ProbingTier) -> u8 {
    match tier {
        ProbingTier::Passive => PASSIVE,
        ProbingTier::Active => ACTIVE,
    }
}

fn decode(v: u8) -> ProbingTier {
    match v {
        PASSIVE => ProbingTier::Passive,
        ACTIVE => ProbingTier::Active,
        // `set` is the only writer and it only ever stores an encoded tier.
        other => unreachable!("ProbingState holds an encoded tier, found {other}"),
    }
}

impl ProbingState {
    /// A switch initially set to `tier`.
    #[must_use]
    pub fn new(tier: ProbingTier) -> Self {
        Self(AtomicU8::new(encode(tier)))
    }

    /// The tier in force now. Read ONCE per tick by a collector, so the probes
    /// it withholds and the verdicts that report them cannot disagree.
    #[must_use]
    pub fn tier(&self) -> ProbingTier {
        decode(self.0.load(Ordering::Acquire))
    }

    /// Switch to `tier`, returning the tier that was in force before — so the
    /// caller can tell a real edge from a no-op.
    pub fn set(&self, tier: ProbingTier) -> ProbingTier {
        decode(self.0.swap(encode(tier), Ordering::AcqRel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_switches_the_tier() {
        let s = ProbingState::new(ProbingTier::Passive);
        assert_eq!(s.tier(), ProbingTier::Passive);
        assert_eq!(s.set(ProbingTier::Active), ProbingTier::Passive);
        assert_eq!(s.tier(), ProbingTier::Active);
        // A no-op switch reports the same tier back, which is how the control
        // path knows not to write an edge.
        assert_eq!(s.set(ProbingTier::Active), ProbingTier::Active);
    }
}
