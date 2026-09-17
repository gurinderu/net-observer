//! Passive incident handlers invoked when a [`crate::engine::Trigger`] fires.

use std::sync::Arc;

use store::Store;
use types::{Incident, TriggerFired};

/// Reacts to a fired trigger. Handlers are passive in v1 (record only, no acting).
///
/// `Send + Sync` so an [`Arc<dyn Handler>`] can be shared across tokio tasks in the
/// daemon without any change to this crate.
pub trait Handler: Send + Sync {
    /// Called once per firing with the generated `incident_id`, firing timestamp
    /// (epoch microseconds) and a human-readable `detail`.
    fn on_fire(&self, incident_id: &str, ts_us: i64, detail: &str);

    /// Called once when the condition that opened `incident_id` stops
    /// asserting — the engine's Some→None edge (and at a session-ending edge,
    /// through `TriggerEngine::close_all`). Default: nothing, so a handler
    /// whose side effect has no closing half (a pcap freeze) keeps its
    /// one-shot semantics untouched. A handler that shows an incident as open
    /// MUST implement it, or its view never closes: the daemon's live
    /// snapshot ring did not, and the socket showed a `gw-drop` open for an
    /// hour after the record had closed it (realm net-observer, node #124).
    fn on_clear(&self, _incident_id: &str, _ts_us: i64) {}
}

/// A [`Handler`] that persists a firing: opens an [`Incident`] and records a
/// [`TriggerFired`] row through the [`Store`]. Holds an [`Arc<S>`] so it is
/// cheaply shareable across tasks.
pub struct RecordHandler<S: Store> {
    store: Arc<S>,
}

impl<S: Store> RecordHandler<S> {
    /// Create a handler that writes through `store`.
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: Store + Send + Sync> Handler for RecordHandler<S> {
    fn on_fire(&self, incident_id: &str, ts_us: i64, detail: &str) {
        // `incident_id` is `"{trigger_id}-{now_us}"`; recover the trigger id from the
        // prefix before the final `-`.
        let trigger_id = incident_id
            .rsplit_once('-')
            .map(|(prefix, _)| prefix)
            .unwrap_or(incident_id)
            .to_string();
        let incident = Incident {
            id: incident_id.to_string(),
            opened_us: ts_us,
            closed_us: None,
            trigger_id: trigger_id.clone(),
            signature: detail.to_string(),
        };
        if let Err(e) = self.store.open_incident(&incident) {
            tracing::warn!(incident_id, error = %e, "failed to open incident");
        }
        let fired = TriggerFired {
            ts_us,
            trigger_id,
            incident_id: incident_id.to_string(),
            detail: detail.to_string(),
        };
        if let Err(e) = self.store.write_trigger_fired(&fired) {
            tracing::warn!(incident_id, error = %e, "failed to record trigger_fired");
        }
    }

    fn on_clear(&self, incident_id: &str, ts_us: i64) {
        if let Err(e) = self.store.close_incident(incident_id, ts_us) {
            tracing::warn!(incident_id, error = %e, "failed to close incident");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conditions::GwDrop;
    use crate::engine::{Trigger, TriggerEngine};
    use crate::window::RecentWindow;
    use store::DuckdbStore;
    use types::{GwVerdict, LinkSample, Sample, TcpVerdict};

    fn link(ts: i64, gw: GwVerdict) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw,
            gw_rtt_ms: None,
            direct: TcpVerdict::Skip,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            lease_start_us: None,
            lease_secs: None,
            if_mac_private: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    /// The sequence observed live on the Mac, replayed against the real
    /// record: a `NOGW` link tick opens `gw-drop`, the next tick reads `SKIP`
    /// (the passive tier withheld the echo) and the durable row gets its
    /// `closed_us` — the engine's `None` arm reaches `RecordHandler::on_clear`
    /// and `Store::close_incident` updates the row it opened. The live view
    /// that stayed open for an hour was the socket's in-memory ring, not this
    /// row (realm net-observer, node #124).
    #[test]
    fn a_skip_tick_after_a_nogw_firing_closes_the_recorded_incident() {
        let store = Arc::new(DuckdbStore::in_memory().unwrap());
        let record: Arc<dyn Handler> = Arc::new(RecordHandler::new(store.clone()));
        let mut eng = TriggerEngine::new(vec![Trigger::new(Box::new(GwDrop), vec![record], 1_000)]);
        let mut w = RecentWindow::new(8);

        w.push(link(100, GwVerdict::NoGw));
        eng.on_sample(&w, 100);
        assert_eq!(
            store.list_incidents().unwrap(),
            vec![("gw-drop".to_string(), 100, None)],
            "the NOGW tick opens gw-drop"
        );

        w.push(link(115, GwVerdict::Skip));
        eng.on_sample(&w, 115);
        assert_eq!(
            store.list_incidents().unwrap(),
            vec![("gw-drop".to_string(), 100, Some(115))],
            "the SKIP tick closes it at its own ts"
        );
        assert_eq!(
            store
                .query_scalar_i64(
                    "SELECT count(*) FROM trigger_fired WHERE incident_id='gw-drop-100'"
                )
                .unwrap(),
            1
        );
    }
}
