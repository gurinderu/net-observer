pub mod diagnosis;
mod duckdb_store;
mod schema;

pub use duckdb_store::{
    DuckdbStore, NeighborPort, NeighborScan, NeighborVuln, QueryTable, StoreError,
};
use types::{
    BlobRef, Incident, NeighborLifetime, ObservingEdge, ProbingEdge, Sample, TopologyLifetime,
    TopologyLink, TriggerFired,
};

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
    /// Record one switch of the probing tier (see [`ProbingEdge`]).
    ///
    /// The durable bracket around a passive stretch: the collectors keep
    /// writing `SKIP` rows while the tier is passive, and `SELECT ts_us, tier
    /// FROM probing_edge ORDER BY ts_us` is what says those rows are withheld
    /// probes rather than probes that could not run — and who withheld them.
    /// (realm net-observer, node #88)
    fn write_probing_edge(&self, e: &ProbingEdge) -> Result<(), StoreError>;
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
    /// Record one CVE hypothesised for an open port (see the `neighbor_vuln`
    /// table). Upserts on `(network_key, mac, port, cve_id)`, preserving
    /// `first_seen_us`. Every row is a hypothesis, never an asserted fact.
    fn write_neighbor_vuln(&self, v: &NeighborVuln) -> Result<(), StoreError>;
    /// Record one switch-topology link learned from a received LLDP/CDP frame
    /// (see the `topology_link` table). Upserts on
    /// `(iface, remote_chassis, remote_port)`, preserving `first_seen_us`. Every
    /// row is a hypothesis — LLDP/CDP are unauthenticated — never an asserted fact.
    fn write_topology_link(&self, l: &TopologyLink) -> Result<(), StoreError>;
    /// The lifetime bounds the record keeps for every neighbour on one segment
    /// (`network_key`; `None` folds to the same "unidentified network" key the
    /// writer uses).
    ///
    /// The read half of what [`Store::write_sample`] upserts into `neighbor`.
    /// It exists so the daemon can put since-when onto the status snapshot: the
    /// bar is a pure socket client and never opens the database, so without this
    /// the fact is recorded but unreachable to the only reader that wants it.
    /// (realm net-observer, node #43)
    fn neighbor_lifetimes(
        &self,
        network_key: Option<&str>,
    ) -> Result<Vec<NeighborLifetime>, StoreError>;
    /// The lifetime bounds the record keeps for every discovered uplink — the
    /// read half of [`Store::write_topology_link`], and the only path by which
    /// `topology_link.first_seen_us` reaches the socket.
    fn topology_lifetimes(&self) -> Result<Vec<TopologyLifetime>, StoreError>;
    fn query_scalar_i64(&self, sql: &str) -> Result<i64, StoreError>;
    /// Run one read-only query and return its column names plus stringified
    /// rows — the primitive every named diagnosis in [`diagnosis`] is built on.
    ///
    /// On the trait, not only on [`DuckdbStore`], because the daemon's socket
    /// server holds its store as `dyn Store` and answers the named diagnoses
    /// through it while the daemon runs — the only reader that can, since the
    /// daemon's per-process lock keeps every other opener out. (realm
    /// net-observer, node #58)
    fn query_table(&self, sql: &str) -> Result<QueryTable, StoreError>;
    /// Like [`Store::query_table`], for a [`diagnosis::PreparedSql`] whose
    /// moment/threshold values are bound, never interpolated.
    fn query_prepared(&self, p: &diagnosis::PreparedSql) -> Result<QueryTable, StoreError>;
    /// [`Store::query_prepared`] with a deadline: the statement is interrupted
    /// at `budget` and the call returns [`StoreError::Interrupted`], with the
    /// connection usable again at once. For a reader that shares the connection
    /// with the writer — the daemon serving a diagnosis over its socket — an
    /// unbounded read is a stall of every write behind it, so the daemon never
    /// runs a diagnosis without one. The offline reader owns its process and
    /// keeps the unbounded [`Store::query_prepared`].
    fn query_prepared_within(
        &self,
        p: &diagnosis::PreparedSql,
        budget: std::time::Duration,
    ) -> Result<QueryTable, StoreError>;
}
