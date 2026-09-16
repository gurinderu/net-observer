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
    /// new observation session, not as a duplicate of the pre-pause one. The
    /// incident the PREVIOUS session had open closes at the edge that ends it
    /// ([`TriggerEngine::close_all`]), called before the re-arm, so no row is
    /// left open across the bracket — and closing it releases that trigger's
    /// firing budget too: `last_fire_us` resets, so a fault still present opens
    /// its new-session incident AT ONCE rather than waiting out whatever backoff
    /// the closed incident had spent. A trigger with NOTHING open at the edge
    /// keeps its budget untouched, so a toggle storm on a healthy network still
    /// cannot fire (realm net-observer, node #124). The `observing_edge` rows
    /// bound the gap between the two records.
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

    /// Close every currently open incident at `ts_us` — the edge that ENDED
    /// their observation session (a pause's own `ts_us`, or a tier switch's),
    /// never the timestamp of whatever sample happens to land after it.
    ///
    /// Called by `pipeline::run` immediately BEFORE `RecentWindow::clear_for_resume`
    /// and `rearm_all`. Without this, a trigger still latched at the edge (its
    /// condition never returned `None` before the session ended) keeps its
    /// `open_incident` across the clear; the first post-edge sample that still
    /// asserts the fault then fires a NEW incident on top of it, and the old one
    /// is silently overwritten — its `incident` row never gets `closed_us`. A
    /// resume RE-OPENS detection as a NEW incident (see [`Self::on_sample`]); this
    /// is what makes the OLD one closed rather than merely abandoned (realm
    /// net-observer, node #124).
    ///
    /// For every trigger with an open incident: every handler's `on_clear` runs
    /// at `ts_us`, the id is taken (so a later `close_all` or the next `None`
    /// edge finds nothing to close twice), and the trigger is armed — the same
    /// effect the `None` arm has.
    ///
    /// `last_fire_us` is reset to [`i64::MIN`] — the same sentinel
    /// [`Trigger::new`] starts a never-fired trigger at — but ONLY for a
    /// trigger whose incident this call actually closed. Closing an incident at
    /// the edge releases that trigger's firing budget: the engine's documented
    /// contract is that a fault still present when collection resumes is
    /// recorded again "as a NEW incident", and a new incident that then sits
    /// silently unrecorded until the OLD session's backoff happens to expire is
    /// a missed incident, which this project ranks above a noisy log. A trigger
    /// with NOTHING open here is untouched: its budget survives exactly as
    /// before, so a toggle storm on a healthy network still cannot fire (realm
    /// net-observer, node #124).
    pub fn close_all(&mut self, ts_us: i64) {
        for trig in &mut self.triggers {
            if let Some(id) = trig.open_incident.take() {
                for h in &trig.handlers {
                    h.on_clear(&id, ts_us);
                }
                trig.armed = true;
                trig.last_fire_us = i64::MIN;
            }
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
            medium: None,
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

    /// (a) `close_all` clears exactly the incident a firing left open, stamped
    /// with the EDGE's `ts_us` — never the firing's own — and re-arms the
    /// trigger. A second `close_all` right after finds nothing left open
    /// (`open_incident` was actually taken to `None`, not merely re-armed with
    /// the id still latched) — the same proof [`Trigger`]'s own invariant relies
    /// on (realm net-observer, node #124).
    #[test]
    fn close_all_closes_the_open_incident_at_the_edge_ts() {
        let h = Arc::new(EdgeHandler::new());
        let handlers: Vec<Arc<dyn crate::handlers::Handler>> = vec![h.clone()];
        let trig = Trigger::new(Box::new(GwDrop), handlers, 1_000);
        let mut eng = TriggerEngine::new(vec![trig]);
        let mut w = RecentWindow::new(8);
        w.push(link(0, GwVerdict::Fail));
        eng.on_sample(&w, 0);
        let opened = h.opened.lock().unwrap().clone();
        assert_eq!(opened.len(), 1, "the fire must open exactly one incident");

        eng.close_all(50);
        assert_eq!(
            h.cleared.lock().unwrap().clone(),
            vec![(opened[0].clone(), 50)],
            "close_all must clear the open incident at the edge ts, not the firing ts"
        );

        // Nothing left open: a second close_all right after records nothing.
        eng.close_all(51);
        assert_eq!(
            h.cleared.lock().unwrap().len(),
            1,
            "close_all must take the id, leaving nothing for a later close_all to re-clear"
        );

        // Armed: the very next sample, past the untouched backoff, fires again.
        w.push(link(1_001, GwVerdict::Fail));
        eng.on_sample(&w, 1_001);
        assert_eq!(
            h.opened.lock().unwrap().len(),
            2,
            "close_all must re-arm the trigger"
        );
    }

    /// (b) The pin for the hole itself, stated positively: fire (A) -> `close_all`
    /// at the edge -> `rearm_all` (the exact pair `pipeline::run` calls at a
    /// resume/tier-switch edge) -> a sample STILL WELL INSIDE A's old backoff,
    /// still asserting -> a NEW incident (B) fires anyway, and EXACTLY ONE clear
    /// exists — A, at the edge. The backoff is 1_000 and the post-edge sample
    /// lands at `ts 15` — only 15us after A's own firing — so this dies unless
    /// `close_all` actually releases the budget, not merely if a mutation
    /// happened to leave enough real elapsed time for the old backoff to expire
    /// on its own. Without `close_all` this sequence would produce ONE fire and
    /// ZERO clears: A silently latched forever, its `incident` row never closed
    /// (realm net-observer, node #124).
    #[test]
    fn close_all_then_rearm_all_lets_a_persistent_fault_open_a_new_incident_with_one_clear() {
        let h = Arc::new(EdgeHandler::new());
        let handlers: Vec<Arc<dyn crate::handlers::Handler>> = vec![h.clone()];
        let trig = Trigger::new(Box::new(GwDrop), handlers, 1_000);
        let mut eng = TriggerEngine::new(vec![trig]);
        let mut w = RecentWindow::new(8);
        w.push(link(0, GwVerdict::Fail));
        eng.on_sample(&w, 0);

        // The edge: exactly the pair `pipeline::run` calls, in that order.
        eng.close_all(10);
        w.clear_for_resume();
        eng.rearm_all();

        // Still asserting, well INSIDE the old backoff (0 -> 1_000): only the
        // budget release lets this fire.
        w.push(link(15, GwVerdict::Fail));
        eng.on_sample(&w, 15);

        let opened = h.opened.lock().unwrap().clone();
        assert_eq!(
            opened.len(),
            2,
            "closing at the edge must release the budget so the persistent \
             fault opens a second incident immediately, not once the old \
             backoff happens to expire"
        );
        assert_ne!(
            opened[0], opened[1],
            "the post-edge firing must be a NEW incident id, not a reuse of A's"
        );
        assert_eq!(
            h.cleared.lock().unwrap().clone(),
            vec![(opened[0].clone(), 10)],
            "exactly one clear: A, closed at the edge — never zero, never B"
        );
    }

    /// (c) `close_all` on an engine with nothing open is a no-op: no handler is
    /// called and nothing changes.
    #[test]
    fn close_all_with_nothing_open_is_a_no_op() {
        let h = Arc::new(EdgeHandler::new());
        let handlers: Vec<Arc<dyn crate::handlers::Handler>> = vec![h.clone()];
        let trig = Trigger::new(Box::new(GwDrop), handlers, 1_000);
        let mut eng = TriggerEngine::new(vec![trig]);

        eng.close_all(99);

        assert!(h.opened.lock().unwrap().is_empty());
        assert!(h.cleared.lock().unwrap().is_empty());
    }
}
