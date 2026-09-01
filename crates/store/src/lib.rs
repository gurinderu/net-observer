pub mod diagnosis;
mod duckdb_store;
mod schema;

pub use duckdb_store::{DuckdbStore, QueryTable, StoreError};
use types::{BlobRef, Incident, ObservingEdge, Sample, TriggerFired};

pub trait Store {
    fn write_sample(&self, s: &Sample) -> Result<(), StoreError>;
    fn open_incident(&self, i: &Incident) -> Result<(), StoreError>;
    fn close_incident(&self, id: &str, closed_us: i64) -> Result<(), StoreError>;
    fn write_blob_ref(&self, b: &BlobRef) -> Result<(), StoreError>;
    fn write_trigger_fired(&self, t: &TriggerFired) -> Result<(), StoreError>;
    /// Record one pause/resume boundary (see [`ObservingEdge`]).
    ///
    /// The only durable trace of an operator pause — a paused daemon writes no
    /// samples at all, so `SELECT ts_us, observing FROM observing_edge ORDER BY
    /// ts_us` reads as the list of intervals in which the daemon deliberately
    /// collected nothing. That is what makes an operator pause distinguishable,
    /// offline and after the fact, from a wedged collector.
    fn write_observing_edge(&self, e: &ObservingEdge) -> Result<(), StoreError>;
    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError>;
}
