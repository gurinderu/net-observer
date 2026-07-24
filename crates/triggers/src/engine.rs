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
    pub fn on_sample(&mut self, w: &RecentWindow, now_us: i64) {
        for trig in &mut self.triggers {
            match trig.condition.eval(w) {
                Some(fire) => {
                    if trig.armed && now_us.saturating_sub(trig.last_fire_us) >= trig.backoff_us {
                        let incident_id = format!("{}-{}", trig.condition.id(), now_us);
                        for h in &trig.handlers {
                            h.on_fire(&incident_id, now_us, &fire.detail);
                        }
                        trig.armed = false;
                        trig.last_fire_us = now_us;
                    }
                }
                None => {
                    trig.armed = true;
                }
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
            wifi_capture_present: false,
        })
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
}
