use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub opened_us: i64,
    pub closed_us: Option<i64>,
    pub trigger_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlobRef {
    pub id: String,
    pub incident_id: String,
    pub ts_us: i64,
    pub kind: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerFired {
    pub ts_us: i64,
    pub trigger_id: String,
    pub incident_id: String,
    pub detail: String,
}
