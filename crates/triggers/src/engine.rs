//! The [`TriggerEngine`]: evaluates each [`Trigger`]'s condition against the recent
//! window on every sample, firing passive handlers with per-trigger re-arm + backoff.

use std::sync::Arc;

use crate::conditions::Condition;
use crate::handlers::Handler;
use crate::window::RecentWindow;

/// One rule: a [`Condition`] plus the [`Handler`]s to run when it fires, guarded by a
/// re-arm latch and a backoff so a persistent fault fires at most once per `backoff_us`.
pub struct Trigger {
    condition: Box<dyn Condition>,
    handlers: Vec<Arc<dyn Handler>>,
    backoff_us: i64,
    armed: bool,
    last_fire_us: i64,
    /// The incident the last firing opened, held until the condition's
    /// Some→None edge closes it. Lives here because this is the only place
    /// that edge is observable. A firing suppressed by the backoff does NOT
    /// replace it: a continuing assertion belongs to the same episode.
    open_incident: Option<String>,
}

impl Trigger {
    /// Create an armed trigger with the given firing `backoff_us`.
    pub fn new(
        condition: Box<dyn Condition>,
        handlers: Vec<Arc<dyn Handler>>,
        backoff_us: i64,
    ) -> Self {
        Self {
            condition,
            handlers,
            backoff_us,
            armed: true,
            last_fire_us: i64::MIN,
            open_incident: None,
        }
    }
}

/// Owns the set of [`Trigger`]s and evaluates them on each incoming sample.
pub struct TriggerEngine {
    triggers: Vec<Trigger>,
}

impl TriggerEngine {
    /// Create an engine over `triggers`.
    pub fn new(triggers: Vec<Trigger>) -> Self {
        Self { triggers }
    }

    /// Evaluate every trigger against the current window at `now_us`.
    ///
    /// A trigger fires only when it is `armed` and at least `backoff_us` have elapsed
    /// since its last firing; firing disarms it. It re-arms as soon as its condition
    /// stops matching (returns `None`).
    ///
    /// A RESUME edge RE-OPENS detection; it does not dedup it. The recent-sample
    /// window is cleared and every trigger is re-armed
    /// ([`TriggerEngine::rearm_all`]), so a fault that is still present when
    /// collection resumes is recorded again — as a NEW incident belonging to the
    /// new observation session, not as a duplicate of the pre-pause one. What a
    /// resume does NOT do is reset the firing budget: `last_fire_us` survives it,
    /// so each trigger still fires at most once per `backoff_us` and a toggled
    /// switch cannot storm the incident log. The `observing_edge` rows bound the
    /// gap between the two records.
    pub fn on_sample(&mut self, w: &RecentWindow, now_us: i64) {
        for trig in &mut self.triggers {
            match trig.condition.eval(w) {
                Some(fire) => {
                    if trig.armed && now_us.saturating_sub(trig.last_fire_us) >= trig.backoff_us {
                        let incident_id = format!("{}-{}", trig.condition.id(), now_us);
                        for h in &trig.handlers {
                            h.on_fire(&incident_id, now_us, &fire.detail);
                        }
                        trig.open_incident = Some(incident_id);
                        trig.armed = false;
                        trig.last_fire_us = now_us;
                    }
                }
                None => {
                    // The condition stopped asserting: close what it opened.
                    // `None` covers both "measured healthy" and "cannot tell"
                    // (an emptied window after a resume) — either way the
                    // assertion ends HERE, and this edge is the only closing
                    // signal that will ever exist. Leaving the row open
                    // instead is strictly worse: the first trial week
                    // accumulated 60+ forever-open incidents.
                    if let Some(id) = trig.open_incident.take() {
                        for h in &trig.handlers {
                            h.on_clear(&id, now_us);
                        }
                    }
                    trig.armed = true;
                }
            }
        }
    }

    /// Re-arm every trigger, WITHOUT touching its backoff.
    ///
    /// Called by `pipeline::run` on a collection RESUME edge, together with
    /// `RecentWindow::clear_for_resume`. A resume RE-OPENS detection; it does not
    /// dedup it: a fault that is still present when collection resumes is
    /// recorded again, as a NEW incident belonging to the new observation
    /// session, rather than staying latched behind a firing that belongs to the
    /// previous one.
    ///
    /// Explicit because the alternative is accidental. An emptied window already
    /// re-arms a trigger *if* the next sample is one its condition reads nothing
    /// from (a `host` tick re-arms `gw-drop`; a `link` tick leaves it latched),
    /// which made "does a persistent fault re-fire across a pause?" depend on
    /// collector arrival order. This makes it a decision.
    ///
    /// `last_fire_us` and `backoff_us` are deliberately NOT reset: a pause
    /// neither shortens nor extends a trigger's firing budget, so a toggled
    /// switch cannot storm the incident log.
    pub fn rearm_all(&mut self) {
        for trig in &mut self.triggers {
            trig.armed = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditions::GwDrop;
    use crate::window::RecentWindow;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use types::{GwVerdict, LinkSample, Sample, TcpVerdict};

    struct CountHandler(AtomicUsize);
    impl crate::handlers::Handler for CountHandler {
        fn on_fire(&self, _: &str, _: i64, _: &str) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Records every open and close it sees, so a test can assert the pairing.
    struct EdgeHandler {
        opened: std::sync::Mutex<Vec<String>>,
        cleared: std::sync::Mutex<Vec<(String, i64)>>,
    }
    impl EdgeHandler {
        fn new() -> Self {
            Self {
                opened: std::sync::Mutex::new(Vec::new()),
                cleared: std::sync::Mutex::new(Vec::new()),
            }
        }
    }
    impl crate::handlers::Handler for EdgeHandler {
        fn on_fire(&self, id: &str, _: i64, _: &str) {
            self.opened.lock().unwrap().push(id.to_string());
        }
        fn on_clear(&self, id: &str, ts_us: i64) {
            self.cleared.lock().unwrap().push((id.to_string(), ts_us));
        }
    }
    fn link(ts: i64, gw: GwVerdict) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    #[test]
    fn the_clear_edge_closes_exactly_the_incident_the_firing_opened() {
        let h = Arc::new(EdgeHandler::new());
        let handlers: Vec<Arc<dyn crate::handlers::Handler>> = vec![h.clone()];
        let trig = Trigger::new(Box::new(GwDrop), handlers, 1_000);
        let mut eng = TriggerEngine::new(vec![trig]);
        let mut w = RecentWindow::new(8);
        w.push(link(0, GwVerdict::Fail));
        eng.on_sample(&w, 0);
        // Still asserting: no close yet, and the backoff-suppressed re-fire
        // must not open (or later close) a second incident.
        w.push(link(1, GwVerdict::Fail));
        eng.on_sample(&w, 1);
        assert!(h.cleared.lock().unwrap().is_empty());
        // Recovery closes the one incident the firing opened, at recovery time.
        w.push(link(2, GwVerdict::Ok));
        eng.on_sample(&w, 2);
        let opened = h.opened.lock().unwrap().clone();
        let cleared = h.cleared.lock().unwrap().clone();
        assert_eq!(opened.len(), 1);
        assert_eq!(cleared, vec![(opened[0].clone(), 2)]);
        // A later healthy tick has nothing left to close.
        w.push(link(3, GwVerdict::Ok));
        eng.on_sample(&w, 3);
        assert_eq!(h.cleared.lock().unwrap().len(), 1);
    }

    #[test]
    fn fires_once_then_rearms_after_ok() {
        let h = Arc::new(CountHandler(AtomicUsize::new(0)));
        let handlers: Vec<Arc<dyn crate::handlers::Handler>> = vec![h.clone()];
        let trig = Trigger::new(Box::new(GwDrop), handlers, 300_000_000); // 5 min backoff (us)
        let mut eng = TriggerEngine::new(vec![trig]);
        let mut w = RecentWindow::new(8);
        // FAIL at t=0 fires once; staying FAIL does NOT re-fire (disarmed)
        w.push(link(0, GwVerdict::Fail));
        eng.on_sample(&w, 0);
        w.push(link(1, GwVerdict::Fail));
        eng.on_sample(&w, 1);
        assert_eq!(h.0.load(Ordering::SeqCst), 1);
        // return to OK re-arms; next FAIL (past backoff) fires again
        w.push(link(2, GwVerdict::Ok));
        eng.on_sample(&w, 2);
        w.push(link(3, GwVerdict::Fail));
        eng.on_sample(&w, 300_000_001);
        assert_eq!(h.0.load(Ordering::SeqCst), 2);
    }

    /// A resume starts a new observation session: the latch re-arms, the backoff
    /// does not. Both halves are load-bearing — dropping `rearm_all` loses the
    /// fresh record, resetting `last_fire_us` inside it lets a toggled switch
    /// write an incident per click.
    #[test]
    fn rearm_all_rearms_without_resetting_the_backoff() {
        let h = Arc::new(CountHandler(AtomicUsize::new(0)));
        let handlers: Vec<Arc<dyn crate::handlers::Handler>> = vec![h.clone()];
        let trig = Trigger::new(Box::new(GwDrop), handlers, 1_000);
        let mut eng = TriggerEngine::new(vec![trig]);
        let mut w = RecentWindow::new(8);
        w.push(link(0, GwVerdict::Fail));
        eng.on_sample(&w, 0);
        assert_eq!(h.0.load(Ordering::SeqCst), 1);
        // The resume edge exactly as `pipeline::run` performs it.
        w.clear_for_resume();
        eng.rearm_all();
        // The post-resume sample is a LINK, so `GwDrop::eval` keeps returning
        // `Some` and only `rearm_all` can have re-armed the latch — but the
        // backoff has not elapsed, so nothing is written yet.
        w.push(link(1, GwVerdict::Fail));
        eng.on_sample(&w, 1);
        assert_eq!(
            h.0.load(Ordering::SeqCst),
            1,
            "re-arming must not bypass the firing backoff"
        );
        eng.on_sample(&w, 1_001);
        assert_eq!(
            h.0.load(Ordering::SeqCst),
            2,
            "a fault still present in a new observation session is recorded again"
        );
    }
}
