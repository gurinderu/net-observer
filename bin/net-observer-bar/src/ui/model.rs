//! The shared application model: the latest snapshot, the bar's own history ring.

use std::collections::VecDeque;

use net_observer_ipc::{ControlResult, StatusSnapshot};

use super::control::{GlanceError, read_fresh};

/// How many refresh ticks the panel's own sparkline history keeps.
///
/// 120 points at the menu-bar's `REFRESH` cadence of 3s (see [`crate::menubar`])
/// is a 6-minute window. That length is chosen against the failure this panel
/// exists to catch: the coworking gateway does not drop, it *ramps* — the reply
/// time climbs for roughly 40 seconds before the gateway stops answering at all.
/// Six minutes shows that ramp with several minutes of quiet baseline in front of
/// it, so the slope is legible as a departure rather than filling the whole chart;
/// it is also short enough that 120 one-pixel columns fit the 320pt panel width
/// without downsampling, so every point drawn is a point measured.
///
/// **This history is the bar's own, and it is not a record.** It starts empty when
/// the bar launches and dies with the process — the daemon's DuckDB store is the
/// record, and the bar never opens it (the daemon is the sole DB owner). A short
/// line after a restart means "the bar just started", never "the network was
/// fine".
pub const HISTORY_LEN: usize = 120;

/// One refresh tick's worth of plottable values.
///
/// Both fields are `Option` on purpose. A tick where the measurement did not
/// happen — no sample yet, a paused daemon, quiet mode (`gw = SKIP`), a gateway
/// that failed or is absent, or an unreachable daemon — is a **gap**, and a gap is
/// not a zero. Plotting a missing measurement as a value on the floor is the same
/// lie the `SKIP` verdict exists to prevent (see `AGENTS.md`, "SKIP, never
/// silence"): it would draw a flat healthy-looking 0ms line for a gateway that was
/// never asked.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct HistoryPoint {
    /// Gateway round-trip time, `None` when nothing was measured this tick.
    pub gw_rtt_ms: Option<f64>,
    /// Host 1-minute load average, `None` when there is no host sample.
    pub load1: Option<f64>,
}

/// Reduce a snapshot to the one plottable point for this tick.
///
/// Pure over its inputs, so the gap rules above are directly testable. `online` is
/// [`Glance::online`]: an unreachable daemon measured nothing, whatever the stale
/// snapshot still says.
pub fn history_point(snapshot: &StatusSnapshot, online: bool) -> HistoryPoint {
    if !online || !snapshot.observing {
        // Offline or paused: collection is not running. Nothing was measured.
        return HistoryPoint::default();
    }
    let gw_rtt_ms = snapshot.link.as_ref().and_then(|l| match l.gw {
        // Only an answered echo carries a time. FAIL/NOGW have no RTT to plot and
        // SKIP means quiet mode — the echo was deliberately not sent.
        types::GwVerdict::Ok => l.gw_rtt_ms,
        types::GwVerdict::Fail | types::GwVerdict::NoGw | types::GwVerdict::Skip => None,
    });
    HistoryPoint {
        gw_rtt_ms,
        load1: snapshot.host.as_ref().map(|h| h.load1),
    }
}

/// Shared, app-scoped model: the latest snapshot the UI renders.
pub struct Glance {
    pub snapshot: StatusSnapshot,
    /// The most recent fetch error, if the last refresh failed — classified into
    /// "nothing answered" vs "the daemon answered badly" (see [`GlanceError`]).
    pub error: Option<GlanceError>,
    /// Config socket path, so the panel's manual "Refresh" can re-query and the
    /// event-log window can open its subscription.
    pub socket_path: String,
    /// The most recent control-action outcome (e.g. the observing toggle outcome
    /// or `"acting disabled"`), surfaced as a transient line in the panel. `None`
    /// until the operator triggers a control action.
    pub control_msg: Option<String>,
    /// The live event-log window, if one is open. Stashed here (persists across
    /// panel re-opens) so a second "Events" click focuses the existing window
    /// instead of opening a duplicate subscription; a stale handle re-opens.
    pub events_window: Option<gpui::AnyWindowHandle>,
    /// The live network-map window, if one is open. Stashed here (persists across
    /// panel re-opens) so a second "Map" click focuses the existing window instead
    /// of opening a duplicate; a stale handle re-opens (see [`crate::map`]).
    pub map_window: Option<gpui::AnyWindowHandle>,
    /// The live air-map window, if one is open. Stashed like `map_window` so a
    /// second "Air" click focuses the existing window instead of opening a
    /// second subscription (see [`crate::air`]).
    pub air_window: Option<gpui::AnyWindowHandle>,
    /// The open actions menu, if any. It is its own window — a menu that flies
    /// out past the panel's edge cannot be an element inside it, because gpui
    /// draws nothing outside a window.
    pub menu_window: Option<gpui::AnyWindowHandle>,
    /// Set while the actions menu holds focus. The panel closes when it resigns
    /// key, and opening the menu is exactly that — without this latch the panel
    /// would vanish the moment its own menu appeared.
    pub menu_focus_guard: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The panel window itself, so the menu can close its parent when the click
    /// that dismisses the menu lands outside both. This is the *only* record of
    /// the live panel: the status-item click reads it too, so a window closed
    /// from anywhere is closed everywhere.
    pub panel_window: Option<gpui::AnyWindowHandle>,
    /// When the panel was last dismissed, so the status-item click that caused
    /// the dismissal is not read as a request to reopen. Shared rather than owned
    /// by the click task, because the menu closes the panel too and a dismissal
    /// it did not stamp reopens under the next click
    /// (see [`crate::menubar::close_panel`]).
    pub panel_dismissed_at: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// The panel's own bounded history of the last [`HISTORY_LEN`] refresh ticks,
    /// oldest first — the series behind the sparklines. Appended by
    /// [`Glance::record_tick`] from the refresh timer *only*, so one column is one
    /// `REFRESH` interval and the window length is a real duration.
    pub history: VecDeque<HistoryPoint>,
}

impl Glance {
    pub fn new(snapshot: StatusSnapshot, error: Option<GlanceError>, socket_path: String) -> Self {
        Self {
            snapshot,
            error,
            socket_path,
            control_msg: None,
            events_window: None,
            map_window: None,
            air_window: None,
            menu_window: None,
            menu_focus_guard: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            panel_window: None,
            panel_dismissed_at: std::sync::Arc::new(std::sync::Mutex::new(None)),
            history: VecDeque::with_capacity(HISTORY_LEN),
        }
    }

    /// Append the current state as one sparkline point, evicting the oldest once
    /// [`HISTORY_LEN`] is reached — the ring never grows past that bound.
    ///
    /// Called from the refresh timer after it has applied the tick's read, and
    /// from nowhere else: the manual "Refresh" button and the observing toggle
    /// also re-read the daemon, but appending there would compress the time axis
    /// (two columns a second apart drawn as one interval), so they update the
    /// snapshot without adding a column.
    pub fn record_tick(&mut self) {
        if self.history.len() == HISTORY_LEN {
            self.history.pop_front();
        }
        self.history
            .push_back(history_point(&self.snapshot, self.online()));
    }

    /// Re-query the daemon into this model. Used by the manual refresh button; the
    /// timer path in [`crate::menubar`] mutates the same fields directly.
    pub fn refresh(&mut self) {
        match read_fresh(&self.socket_path) {
            Ok(s) => {
                self.snapshot = s;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }

    /// Whether the daemon is reachable. Only [`GlanceError::Unreachable`] means
    /// "not there": a protocol failure came *from* a live daemon, so the panel
    /// stays online (the toggle keeps working, the message is shown instead).
    pub fn online(&self) -> bool {
        !matches!(self.error, Some(GlanceError::Unreachable(_)))
    }

    /// Apply the outcome of a toggle round-trip (see [`toggle_round_trip`]) to this
    /// model. Pure state application — it performs no I/O, so it is safe to run on
    /// the gpui main thread and is directly testable.
    ///
    /// `control` becomes the transient `control_msg` line; `fresh` is applied
    /// exactly the way [`Glance::refresh`] applies its own read, so the switch
    /// reflects the daemon's real state (or goes offline) rather than a
    /// silently-flipped local bool.
    pub fn apply_toggle_result(
        &mut self,
        control: Result<ControlResult, String>,
        fresh: Result<StatusSnapshot, GlanceError>,
    ) {
        self.control_msg = Some(match control {
            Ok(result) => {
                let tag = if result.ok { "ok" } else { "failed" };
                format!("{tag}: {}", result.message)
            }
            Err(e) => format!("failed: {e}"),
        });
        match fresh {
            Ok(s) => {
                self.snapshot = s;
                self.error = None;
            }
            Err(e) => self.error = Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::control::send_set_observing;
    use super::*;

    fn link(gw: types::GwVerdict, rtt: Option<f64>) -> types::LinkSample {
        types::LinkSample {
            ts_us: 1_000_000,
            gw,
            gw_rtt_ms: rtt,
            direct: types::TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            wifi_capture_present: false,
        }
    }

    fn glance() -> Glance {
        Glance::new(StatusSnapshot::default(), None, "/nonexistent.sock".into())
    }

    /// The ring is bounded: it never exceeds `HISTORY_LEN`, and it evicts the
    /// oldest column rather than the newest — the sparkline must keep showing the
    /// present, not freeze on the first six minutes after launch.
    #[test]
    fn history_ring_stays_bounded_and_drops_the_oldest() {
        let mut g = glance();
        for i in 0..(HISTORY_LEN * 2) {
            g.snapshot.host = Some(types::HostSample {
                ts_us: i as i64,
                load1: i as f64,
                load5: 0.0,
                load15: 0.0,
            });
            g.record_tick();
            assert!(
                g.history.len() <= HISTORY_LEN,
                "ring grew past its bound at tick {i}"
            );
        }
        assert_eq!(g.history.len(), HISTORY_LEN);
        // The window holds the LAST HISTORY_LEN ticks, oldest first.
        assert_eq!(
            g.history.front().unwrap().load1,
            Some(HISTORY_LEN as f64),
            "oldest retained column must be the (2N - N)th tick"
        );
        assert_eq!(
            g.history.back().unwrap().load1,
            Some((HISTORY_LEN * 2 - 1) as f64),
            "newest column must be the most recent tick"
        );
    }

    /// A gap is not a zero. Every way a measurement can fail to happen must land
    /// as `None`, never as a value on the floor.
    #[test]
    fn unmeasured_ticks_stay_gaps() {
        // No sample at all.
        let empty = StatusSnapshot::default();
        assert_eq!(history_point(&empty, true), HistoryPoint::default());

        // Gateway verdicts that carry no measured reply time. SKIP is quiet mode:
        // the echo was deliberately never sent.
        for gw in [
            types::GwVerdict::Fail,
            types::GwVerdict::NoGw,
            types::GwVerdict::Skip,
        ] {
            // Even with an RTT field set, a non-OK verdict is not a measurement.
            let s = StatusSnapshot {
                link: Some(link(gw, Some(42.0))),
                ..Default::default()
            };
            assert_eq!(
                history_point(&s, true).gw_rtt_ms,
                None,
                "{gw} must be a gap, not a plotted value"
            );
        }

        // An OK verdict with no time is still a gap.
        let s = StatusSnapshot {
            link: Some(link(types::GwVerdict::Ok, None)),
            ..Default::default()
        };
        assert_eq!(history_point(&s, true).gw_rtt_ms, None);

        // A paused daemon collects nothing, however healthy the retained snapshot
        // looks; and an unreachable daemon measured nothing at all.
        let live = StatusSnapshot {
            link: Some(link(types::GwVerdict::Ok, Some(12.0))),
            host: Some(types::HostSample {
                ts_us: 1,
                load1: 3.0,
                load5: 0.0,
                load15: 0.0,
            }),
            ..Default::default()
        };
        assert_eq!(
            history_point(&live, true),
            HistoryPoint {
                gw_rtt_ms: Some(12.0),
                load1: Some(3.0)
            },
            "a live, observing daemon plots both series"
        );
        let mut paused = live.clone();
        paused.observing = false;
        assert_eq!(history_point(&paused, true), HistoryPoint::default());
        assert_eq!(history_point(&live, false), HistoryPoint::default());
    }

    /// The bar's own reachability, not the stale snapshot, decides: a `Glance`
    /// holding an `Unreachable` error records a gap.
    #[test]
    fn offline_glance_records_a_gap() {
        let mut g = glance();
        g.snapshot.link = Some(link(types::GwVerdict::Ok, Some(99.0)));
        g.error = Some(GlanceError::Unreachable("no socket".into()));
        g.record_tick();
        assert_eq!(g.history.back().copied(), Some(HistoryPoint::default()));
    }

    /// A protocol failure must NOT read as offline: the daemon answered, so the
    /// panel stays online (toggle live) and the message goes to the footer.
    #[test]
    fn protocol_error_keeps_the_panel_online() {
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            None,
            "/nonexistent.sock".to_string(),
        );
        assert!(glance.online(), "no error is online");

        glance.error = Some(GlanceError::Protocol("missing field `observing`".into()));
        assert!(
            glance.online(),
            "a daemon that answered badly is still reachable"
        );
        assert_eq!(
            glance.error.as_ref().map(GlanceError::message),
            Some("missing field `observing`"),
            "the real message must survive for the footer line"
        );

        glance.error = Some(GlanceError::Unreachable("No such file".into()));
        assert!(!glance.online(), "nothing answered -> offline");
    }

    /// Applying a toggle outcome from a down daemon records a readable failure line
    /// instead of panicking, and the failed read surfaces the offline state (the
    /// switch reflects the daemon's real, unreachable state — never a
    /// silently-flipped local bool).
    #[test]
    fn glance_toggle_observing_records_failure_when_daemon_down() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        let socket = missing.to_str().unwrap();
        let mut glance = Glance::new(StatusSnapshot::default(), None, socket.to_string());
        // A fresh snapshot reads as observing; the daemon is down.
        assert!(glance.snapshot.observing);
        // The real errors the background round-trip would hand back.
        glance.apply_toggle_result(send_set_observing(socket, false), read_fresh(socket));
        let msg = glance
            .control_msg
            .clone()
            .expect("toggle must record a message");
        assert!(
            msg.starts_with("failed:"),
            "daemon-down must be a failure: {msg}"
        );
        // The read failed against the absent socket -> offline (unreachable, since
        // nothing answered), and the (unreached) snapshot state is left as-is
        // rather than flipped.
        assert!(
            matches!(glance.error, Some(GlanceError::Unreachable(_))),
            "refresh must surface offline: {:?}",
            glance.error
        );
        assert!(!glance.online(), "the panel reads as offline");
        assert!(glance.snapshot.observing, "state not flipped locally");
    }

    /// A successful toggle applies the daemon's post-toggle snapshot and clears a
    /// previous offline error — the switch follows the daemon, not a local guess.
    #[test]
    fn apply_toggle_result_adopts_fresh_snapshot_and_clears_error() {
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            Some(GlanceError::Unreachable("was offline".to_string())),
            "/nonexistent.sock".to_string(),
        );
        let paused = StatusSnapshot {
            observing: false,
            ..StatusSnapshot::default()
        };
        glance.apply_toggle_result(
            Ok(ControlResult {
                ok: true,
                message: "observing off".to_string(),
            }),
            Ok(paused),
        );
        assert_eq!(glance.control_msg.as_deref(), Some("ok: observing off"));
        assert!(!glance.snapshot.observing, "switch follows the daemon");
        assert!(glance.error.is_none(), "a good read clears offline");
    }

    /// A refusal (`ok: false`) reads as a failure line even though the round-trip
    /// itself succeeded.
    #[test]
    fn apply_toggle_result_marks_refusal_as_failed() {
        let mut glance = Glance::new(
            StatusSnapshot::default(),
            None,
            "/nonexistent.sock".to_string(),
        );
        glance.apply_toggle_result(
            Ok(ControlResult {
                ok: false,
                message: "refused".to_string(),
            }),
            Err(GlanceError::Unreachable("offline".to_string())),
        );
        assert_eq!(glance.control_msg.as_deref(), Some("failed: refused"));
        assert_eq!(
            glance.error,
            Some(GlanceError::Unreachable("offline".to_string()))
        );
    }
}
