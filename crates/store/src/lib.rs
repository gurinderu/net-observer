mod duckdb_store;
mod schema;

pub use duckdb_store::{DuckdbStore, QueryTable, StoreError};
use types::{BlobRef, Incident, Sample, TriggerFired};

pub trait Store {
    fn write_sample(&self, s: &Sample) -> Result<(), StoreError>;
    fn open_incident(&self, i: &Incident) -> Result<(), StoreError>;
    fn close_incident(&self, id: &str, closed_us: i64) -> Result<(), StoreError>;
    fn write_blob_ref(&self, b: &BlobRef) -> Result<(), StoreError>;
    fn write_trigger_fired(&self, t: &TriggerFired) -> Result<(), StoreError>;
    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError>;
}
