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

/// How many consecutive dead attempts end a watch: ten minutes of probes
/// that could not run mean the interface is gone, not that the portal
/// stands — the prober goes idle instead of running a SKIP-row generator
/// for the life of the daemon. A live network re-arms by its next address;
/// the standing incident ends by its own window.
pub const WATCH_SKIP_LIMIT: u32 = 10;

#[derive(Debug, Default)]
enum Phase {
    #[default]
    Idle,
    /// The post-trigger series: `attempt` indexes [`SERIES_DELAYS`].
    Series { iface: String, attempt: usize },
    /// A portal was seen and its incident may stand: keep probing until the
    /// answer is clean, `skips` dead attempts in a row so far.
    Watch { iface: String, skips: u32 },
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

    /// A relevant route event landed on `iface`: restart the series there.
    /// Always a restart, the same interface included — the ordinary portal
    /// is the SAME `en0` joining another network, and only a fresh series
    /// beats the rebind race there; a watch on a fresh address would probe
    /// the new network at the old 60 s pace and keep the old login page. A
    /// settling network's burst of `RTM_NEWADDR` coalesces into one series
    /// counted from the last event.
    pub fn on_trigger(&mut self, iface: &str) -> Duration {
        self.phase = Phase::Series {
            iface: iface.to_string(),
            attempt: 0,
        };
        SERIES_DELAYS[0]
    }

    /// The interface the next probe is for, while one is scheduled.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        match &self.phase {
            Phase::Idle => None,
            Phase::Series { iface, .. } | Phase::Watch { iface, .. } => Some(iface),
        }
    }

    /// One attempt finished with `verdict`; the pause before the next probe,
    /// or `None` — the series is over and the scheduler is idle again.
    pub fn on_attempt_done(&mut self, verdict: PortalVerdict) -> Option<Duration> {
        match (std::mem::take(&mut self.phase), verdict) {
            // A clean answer ends everything: no portal, or the portal fell.
            (Phase::Series { .. } | Phase::Watch { .. } | Phase::Idle, PortalVerdict::Ok) => None,
            // A portal holds the watch, from either phase; a fresh reading
            // resets the dead-attempt count.
            (Phase::Series { iface, .. } | Phase::Watch { iface, .. }, PortalVerdict::Portal) => {
                self.phase = Phase::Watch { iface, skips: 0 };
                Some(WATCH_INTERVAL)
            }
            // No measurement: the series walks on; the watch keeps trying —
            // an open portal incident must not be orphaned by one dead probe
            // — up to [`WATCH_SKIP_LIMIT`] dead attempts in a row.
            (Phase::Series { iface, attempt }, PortalVerdict::Skip) => {
                let next = attempt + 1;
                let delay = SERIES_DELAYS.get(next).copied()?;
                self.phase = Phase::Series {
                    iface,
                    attempt: next,
                };
                Some(delay)
            }
            (Phase::Watch { iface, skips }, PortalVerdict::Skip) => {
                let skips = skips + 1;
                if skips >= WATCH_SKIP_LIMIT {
                    return None;
                }
                self.phase = Phase::Watch { iface, skips };
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
    fn every_trigger_restarts_the_series_same_interface_included() {
        let mut s = Scheduler::new();
        assert_eq!(s.on_trigger("en0"), SERIES_DELAYS[0]);
        assert_eq!(s.target(), Some("en0"));
        // The ordinary portal: the SAME en0 joins another network mid-series
        // or mid-watch — the series restarts at attempt 0 both times.
        s.on_attempt_done(PortalVerdict::Skip);
        assert_eq!(s.on_trigger("en0"), SERIES_DELAYS[0]);
        s.on_attempt_done(PortalVerdict::Portal);
        assert_eq!(s.on_trigger("en0"), SERIES_DELAYS[0]);
        // Another interface is another network too.
        assert_eq!(s.on_trigger("en13"), SERIES_DELAYS[0]);
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
        // Login happened: the clean answer ends the watch.
        assert_eq!(s.on_attempt_done(PortalVerdict::Ok), None);
        assert_eq!(s.target(), None);
    }

    /// An interface that went away for good must not leave a permanent
    /// once-a-minute SKIP generator: the watch gives up after
    /// [`WATCH_SKIP_LIMIT`] dead attempts in a row, and a fresh reading
    /// resets the count.
    #[test]
    fn the_watch_gives_up_after_a_run_of_dead_attempts() {
        let mut s = Scheduler::new();
        s.on_trigger("en0");
        s.on_attempt_done(PortalVerdict::Portal);
        // A fresh PORTAL reading mid-run resets the count.
        for _ in 0..WATCH_SKIP_LIMIT - 1 {
            assert_eq!(s.on_attempt_done(PortalVerdict::Skip), Some(WATCH_INTERVAL));
        }
        assert_eq!(
            s.on_attempt_done(PortalVerdict::Portal),
            Some(WATCH_INTERVAL)
        );
        for _ in 0..WATCH_SKIP_LIMIT - 1 {
            assert_eq!(s.on_attempt_done(PortalVerdict::Skip), Some(WATCH_INTERVAL));
        }
        // The limit-th dead attempt ends the watch.
        assert_eq!(s.on_attempt_done(PortalVerdict::Skip), None);
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
