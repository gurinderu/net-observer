//! The captive-portal prober's driving loop (realm net-observer, node #178):
//! route events in, portal samples out. The schedule and the reading of an
//! answer are `collector-portal`'s pure logic; the sockets are the `macos`
//! adapter's; this loop owns the clock. Supervised like every collector — a
//! dead probe lands as a SKIP sample and the loop keeps listening.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use collector_core::ProbingState;
use collector_portal::schedule::Scheduler;
use collector_portal::{PortalProbe, attempt_fields, build_sample, series_trigger};
use tokio::sync::mpsc;
use types::{EmissionClass, PortalVerdict, RouteEvent, Sample, now_us};

/// How soon a deferred attempt is retried while an operator pause stands, or
/// after an edge landed mid-probe: a cheap atomic read a few times a minute,
/// so the series is still armed when collection resumes.
const PAUSE_RETRY: std::time::Duration = std::time::Duration::from_secs(15);

/// Drive the prober until the pipeline goes away: arm a series on a relevant
/// route event, run each due attempt, and hand every reading to the same
/// consumer loop every collector feeds.
///
/// The probing tier is read per attempt: a passive daemon writes the SKIP
/// instead of a packet (realm net-observer, nodes #88, #137). An operator
/// pause drops the attempt whole — no sample; the pause bracket in the
/// record is what explains the silence — while the series still advances, so
/// a daemon resumed hours later is not probing a network long settled.
pub(crate) async fn run_portal_prober<P: PortalProbe>(
    probe: P,
    mut route_rx: mpsc::UnboundedReceiver<RouteEvent>,
    samples_tx: mpsc::Sender<Sample>,
    probing: Arc<ProbingState>,
    observing: Arc<AtomicBool>,
) {
    let mut sched = Scheduler::new();
    // The pending attempt's deadline; `None` = nothing scheduled, wait for a
    // route event.
    let mut deadline: Option<tokio::time::Instant> = None;
    loop {
        // `Instant` is `Copy`, so the sleeper owns its own copy and the arms
        // below stay free to move the deadline.
        let fire = async move {
            match deadline {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            ev = route_rx.recv() => {
                // The tap's sender lives in the pipeline: its end is shutdown.
                let Some(ev) = ev else { break };
                if let Some(iface) = series_trigger(&ev) {
                    let delay = sched.on_trigger(iface);
                    tracing::debug!(iface, "route event armed a captive-portal probe series");
                    deadline = Some(tokio::time::Instant::now() + delay);
                }
            }
            () = fire, if deadline.is_some() => {
                let Some(iface) = sched.target().map(str::to_string) else {
                    deadline = None;
                    continue;
                };
                // An operator pause DEFERS the attempt rather than spending
                // it: a resume always resumes collecting, and the series must
                // still be there to run — a network seconds old at resume is
                // exactly what it exists for.
                if !observing.load(Ordering::Relaxed) {
                    deadline = Some(tokio::time::Instant::now() + PAUSE_RETRY);
                    continue;
                }
                // The stamp is taken BEFORE the fetch, like every interval
                // collector's: a reading always dates from before any edge
                // that lands mid-probe, so the consumer's post-resume drain
                // can drop it too.
                let ts_us = now_us();
                let tier = probing.tier();
                let (verdict, login_url, reason) =
                    if tier.emits(EmissionClass::CaptiveProbe) {
                        attempt_fields(probe.fetch(&iface).await)
                    } else {
                        (
                            PortalVerdict::Skip,
                            None,
                            Some("withheld: passive probing tier".to_string()),
                        )
                    };
                // A probe in flight across a pause or a tier switch is
                // dropped whole at the source, like every straddling tick
                // (realm net-observer, nodes #25, #88): its sample would
                // otherwise stand as a measurement inside a bracketed
                // stretch. The attempt is deferred, not spent.
                if !observing.load(Ordering::Relaxed) || probing.tier() != tier {
                    tracing::info!(
                        iface,
                        "portal probe straddled a pause or tier switch; dropped whole"
                    );
                    deadline = Some(tokio::time::Instant::now() + PAUSE_RETRY);
                    continue;
                }
                let sample = build_sample(ts_us, &iface, verdict, login_url, reason);
                if samples_tx.send(Sample::Portal(sample)).await.is_err() {
                    break;
                }
                deadline = sched
                    .on_attempt_done(verdict)
                    .map(|d| tokio::time::Instant::now() + d);
            }
        }
    }
    tracing::info!("portal prober stopped (pipeline closed)");
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::PortalSample;

    /// A probe that answers from a script, recording the interfaces asked.
    struct FakeProbe {
        answers: std::sync::Mutex<std::vec::IntoIter<Result<Vec<u8>, String>>>,
    }

    impl PortalProbe for FakeProbe {
        async fn fetch(&self, _iface: &str) -> Result<Vec<u8>, String> {
            self.answers
                .lock()
                .unwrap()
                .next()
                .unwrap_or_else(|| Err("script exhausted".into()))
        }
    }

    fn newaddr(iface: &str) -> RouteEvent {
        RouteEvent {
            ts_us: 1,
            kind: "addr".into(),
            iface: Some(iface.into()),
            detail: "RTM_NEWADDR".into(),
        }
    }

    /// The whole reactive arc under a paused clock: a fresh address arms the
    /// series, the first attempt reads the portal (sample carries the login
    /// page), the watch re-probes, and the clean answer after login ends it.
    #[tokio::test(start_paused = true)]
    async fn a_route_event_probes_and_the_watch_ends_on_a_clean_answer() {
        let redirect: Vec<u8> =
            b"HTTP/1.0 302 Found\r\nLocation: http://login.example/\r\n\r\n".to_vec();
        let success: Vec<u8> = b"HTTP/1.0 200 OK\r\n\r\nSuccess".to_vec();
        let probe = FakeProbe {
            answers: std::sync::Mutex::new(vec![Ok(redirect), Ok(success)].into_iter()),
        };
        let (tap_tx, tap_rx) = mpsc::unbounded_channel();
        let (samples_tx, mut samples_rx) = mpsc::channel(16);
        let probing = Arc::new(ProbingState::new(types::ProbingTier::Active));
        let observing = Arc::new(AtomicBool::new(true));
        let prober = tokio::spawn(run_portal_prober(
            probe, tap_rx, samples_tx, probing, observing,
        ));

        tap_tx.send(newaddr("en0")).unwrap();
        let first = samples_rx.recv().await.expect("the armed series probes");
        let Sample::Portal(PortalSample {
            verdict, login_url, ..
        }) = first
        else {
            panic!("a portal sample");
        };
        assert_eq!(verdict, PortalVerdict::Portal);
        assert_eq!(login_url.as_deref(), Some("http://login.example/"));

        // The watch re-probes and the clean answer ends the loop: no third
        // sample without a new trigger.
        let second = samples_rx.recv().await.expect("the watch re-probes");
        let Sample::Portal(p) = second else {
            panic!("a portal sample");
        };
        assert_eq!(p.verdict, PortalVerdict::Ok);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(600), samples_rx.recv())
                .await
                .is_err(),
            "an idle prober probes nothing"
        );

        drop(tap_tx);
        prober.await.unwrap();
    }

    /// The passive tier withholds the probe: the attempt lands as a SKIP row
    /// naming the withholding, and the wire stays quiet (the fake would
    /// panic the script if fetched).
    #[tokio::test(start_paused = true)]
    async fn the_passive_tier_writes_skip_rows_instead_of_packets() {
        let probe = FakeProbe {
            answers: std::sync::Mutex::new(Vec::new().into_iter()),
        };
        let (tap_tx, tap_rx) = mpsc::unbounded_channel();
        let (samples_tx, mut samples_rx) = mpsc::channel(16);
        let probing = Arc::new(ProbingState::new(types::ProbingTier::Passive));
        let observing = Arc::new(AtomicBool::new(true));
        let prober = tokio::spawn(run_portal_prober(
            probe, tap_rx, samples_tx, probing, observing,
        ));

        tap_tx.send(newaddr("en0")).unwrap();
        // The whole series lands as SKIPs, then the prober goes idle.
        for _ in 0..collector_portal::schedule::SERIES_DELAYS.len() {
            let Sample::Portal(p) = samples_rx.recv().await.expect("a SKIP row per attempt") else {
                panic!("a portal sample");
            };
            assert_eq!(p.verdict, PortalVerdict::Skip);
            assert_eq!(p.reason.as_deref(), Some("withheld: passive probing tier"));
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(600), samples_rx.recv())
                .await
                .is_err(),
            "a spent series probes nothing"
        );

        drop(tap_tx);
        prober.await.unwrap();
    }
}
