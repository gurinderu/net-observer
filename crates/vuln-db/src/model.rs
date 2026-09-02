//! The result types a query returns.

/// How strongly a match is believed. A match is a **hypothesis**, never an
/// asserted fact: the daemon may be on a dead network with a stale snapshot,
/// and a wrong "you are vulnerable" is worse than an honest "maybe". The
/// confidence records how the match was reached so a consumer can weigh it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Product matched, but the query carried no version: any version of the
    /// product could be affected, or none.
    Low,
    /// The query carried a version and the affected entry matched the product,
    /// but it named no usable version constraint — the whole product is flagged
    /// affected, so the version could not narrow it.
    Medium,
    /// The query version fell inside an explicit affected version range (or hit
    /// an exact affected version).
    High,
}

/// A single CVE hypothesised to affect the queried product.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnMatch {
    /// The CVE identifier, e.g. `CVE-2016-6210`.
    pub cve_id: String,
    /// A short human summary (the record title, else its first English
    /// description), possibly empty when the record carried neither.
    pub summary: String,
    /// How the match was reached.
    pub confidence: Confidence,
    /// Whether this CVE is in the CISA KEV catalog (known exploited in the
    /// wild) — a strong prioritisation signal independent of confidence.
    pub known_exploited: bool,
    /// The record's CVSS base score, if it carried one.
    pub cvss: Option<f32>,
}
