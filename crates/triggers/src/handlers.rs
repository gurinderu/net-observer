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
}
