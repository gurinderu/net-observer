//! When to probe: the growing series after a trigger, the steady watch while
//! a portal stands, silence otherwise. Pure state — the daemon owns the
//! clock and the sockets (realm net-observer, node #178).

use std::time::Duration;

use types::PortalVerdict;

/// Pauses before each attempt of a fresh series, from the trigger onward:
/// the first probe runs almost at once, the later ones outlive sing-box's
/// rebind to the new interface — the ~13 s in which the OS's own one-shot
/// probe died on the observed morning (realm net-observer, node #173).
pub const SERIES_DELAYS: [Duration; 4] = [
    Duration::from_secs(3),
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
];

/// While a portal stands, re-probe at this pace until the answer is clean —
/// the close side of the incident.
pub const WATCH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
enum Phase {
    #[default]
    Idle,
    /// The post-trigger series: `attempt` indexes [`SERIES_DELAYS`].
    Series { iface: String, attempt: usize },
    /// A portal was seen and its incident may stand: keep probing until the
    /// answer is clean.
    Watch { iface: String },
}

/// The probe scheduler: feed it triggers and finished attempts, it answers
/// with the pause before the next probe (`None` = nothing scheduled).
#[derive(Debug, Default)]
pub struct Scheduler {
    phase: Phase,
}

impl Scheduler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A relevant route event landed on `iface`. Starts a series when idle,
    /// retargets when the network moved to another interface, and changes
    /// nothing while this interface is already being probed or watched — the
    /// running series absorbs the churn of a network still settling.
    pub fn on_trigger(&mut self, iface: &str) -> Option<Duration> {
        match &self.phase {
            Phase::Series { iface: cur, .. } | Phase::Watch { iface: cur } if cur == iface => None,
            _ => {
                self.phase = Phase::Series {
                    iface: iface.to_string(),
                    attempt: 0,
                };
                Some(SERIES_DELAYS[0])
            }
        }
    }

    /// The interface the next probe is for, while one is scheduled.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        match &self.phase {
            Phase::Idle => None,
            Phase::Series { iface, .. } | Phase::Watch { iface } => Some(iface),
        }
    }

    /// One attempt finished with `verdict`; the pause before the next probe,
    /// or `None` — the series is over and the scheduler is idle again.
    pub fn on_attempt_done(&mut self, verdict: PortalVerdict) -> Option<Duration> {
        match (std::mem::take(&mut self.phase), verdict) {
            // A clean answer ends everything: no portal, or the portal fell.
            (Phase::Series { .. } | Phase::Watch { .. } | Phase::Idle, PortalVerdict::Ok) => None,
            // A portal holds the watch, from either phase.
            (Phase::Series { iface, .. } | Phase::Watch { iface }, PortalVerdict::Portal) => {
                self.phase = Phase::Watch { iface };
                Some(WATCH_INTERVAL)
            }
            // No measurement: the series walks on; the watch keeps trying —
            // an open portal incident must not be orphaned by one dead probe.
            (Phase::Series { iface, attempt }, PortalVerdict::Skip) => {
                let next = attempt + 1;
                let delay = SERIES_DELAYS.get(next).copied()?;
                self.phase = Phase::Series {
                    iface,
                    attempt: next,
                };
                Some(delay)
            }
            (Phase::Watch { iface }, PortalVerdict::Skip) => {
                self.phase = Phase::Watch { iface };
                Some(WATCH_INTERVAL)
            }
            (Phase::Idle, _) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trigger_starts_the_series_and_churn_is_absorbed() {
        let mut s = Scheduler::new();
        assert_eq!(s.on_trigger("en0"), Some(SERIES_DELAYS[0]));
        assert_eq!(s.target(), Some("en0"));
        // The same interface settling (more RTM_NEWADDR) changes nothing.
        assert_eq!(s.on_trigger("en0"), None);
        // Another interface is another network: restart at attempt 0.
        assert_eq!(s.on_trigger("en13"), Some(SERIES_DELAYS[0]));
        assert_eq!(s.target(), Some("en13"));
    }

    #[test]
    fn skips_walk_the_series_then_give_up() {
        let mut s = Scheduler::new();
        s.on_trigger("en0");
        assert_eq!(
            s.on_attempt_done(PortalVerdict::Skip),
            Some(SERIES_DELAYS[1])
        );
        assert_eq!(
            s.on_attempt_done(PortalVerdict::Skip),
            Some(SERIES_DELAYS[2])
        );
        assert_eq!(
            s.on_attempt_done(PortalVerdict::Skip),
            Some(SERIES_DELAYS[3])
        );
        // The series is spent; back to idle until the next trigger.
        assert_eq!(s.on_attempt_done(PortalVerdict::Skip), None);
        assert_eq!(s.target(), None);
    }

    #[test]
    fn a_portal_holds_the_watch_until_the_answer_is_clean() {
        let mut s = Scheduler::new();
        s.on_trigger("en0");
        assert_eq!(
            s.on_attempt_done(PortalVerdict::Portal),
            Some(WATCH_INTERVAL)
        );
        assert_eq!(s.target(), Some("en0"));
        // A dead probe does not orphan the open incident.
        assert_eq!(s.on_attempt_done(PortalVerdict::Skip), Some(WATCH_INTERVAL));
        // Still watching; a trigger on the same interface changes nothing.
        assert_eq!(s.on_trigger("en0"), None);
        // Login happened: the clean answer ends the watch.
        assert_eq!(s.on_attempt_done(PortalVerdict::Ok), None);
        assert_eq!(s.target(), None);
    }

    #[test]
    fn a_clean_first_answer_ends_the_series_at_once() {
        let mut s = Scheduler::new();
        s.on_trigger("en0");
        assert_eq!(s.on_attempt_done(PortalVerdict::Ok), None);
        assert_eq!(s.target(), None);
    }
}
