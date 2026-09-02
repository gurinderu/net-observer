pub mod diagnosis;
mod duckdb_store;
mod schema;

pub use duckdb_store::{DuckdbStore, NeighborPort, NeighborScan, QueryTable, StoreError};
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
    /// Record one operator-pressed neighbour scan (see the `neighbor_scan`
    /// table).
    ///
    /// On the `Store` trait rather than on `DuckdbStore` alone because the
    /// control socket writes it: a scan is the daemon speaking on the segment,
    /// and the row saying it did so must be written through the same interface
    /// every other durable record goes through.
    fn write_neighbor_scan(&self, s: &NeighborScan) -> Result<(), StoreError>;
    /// Record one open port found on a neighbour (see the `neighbor_port`
    /// table). Upserts on `(network_key, mac, port)`, preserving `first_seen_us`.
    fn write_neighbor_port(&self, p: &NeighborPort) -> Result<(), StoreError>;
    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError>;
}
