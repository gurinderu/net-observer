//! `vuln-db` — a local, **offline** CVE-matching library.
//!
//! At runtime the daemon may sit on a dead network, so this crate never touches
//! the network. It ingests a **local snapshot** already present on disk and
//! answers matching queries from an in-memory index.
//!
//! # Snapshot layout
//! [`VulnDb::load_from_dir`] expects a directory shaped like:
//!
//! ```text
//! <snapshot>/
//!   cves/                     # a cvelistV5 JSON tree (CVEProject/cvelistV5)
//!     2016/6xxx/CVE-2016-6210.json
//!     2024/1xxx/CVE-2024-0001.json
//!     ...                     # scanned recursively for *.json files
//!   kev.json                  # the CISA KEV catalog (optional)
//! ```
//!
//! The `cves/` subtree is walked recursively; every `*.json` file is treated as
//! one CVE record. `kev.json`, if present, flags known-exploited CVEs. The real
//! datasets are large and provisioned out-of-band by the operator; they are
//! never vendored into this repository.
//!
//! # A match is a hypothesis
//! [`VulnDb::match_product`] returns [`VulnMatch`] values, each carrying an
//! explicit [`Confidence`]. A match is never asserted as fact: a stale snapshot
//! or a spoofed banner can mislead, and a wrong "you are vulnerable" is worse
//! than an honest "maybe". Version comparison is conservative — an input that
//! cannot be parsed is never claimed to be inside a range.

mod banner;
mod cpe;
mod error;
mod ingest;
mod model;
mod version;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

pub use banner::parse_banner;
pub use cpe::Cpe;
pub use error::VulnDbError;
pub use model::{Confidence, VulnMatch};
pub use version::{Version, VersionRange};

use ingest::CveEntry;

/// An in-memory, queryable vulnerability index built from a local snapshot.
#[derive(Debug, Clone, Default)]
pub struct VulnDb {
    entries: Vec<CveEntry>,
    /// Lowercased product name -> indices into `entries`.
    by_product: HashMap<String, Vec<usize>>,
    /// CVE ids present in the CISA KEV catalog.
    kev: HashSet<String>,
}

impl VulnDb {
    /// Ingest a snapshot directory into an index.
    ///
    /// Malformed or partial individual records are skipped, never fatal — only
    /// a missing snapshot directory or an I/O failure while walking it is an
    /// error. A missing `kev.json` simply leaves every match `known_exploited:
    /// false`.
    pub fn load_from_dir(path: impl AsRef<Path>) -> Result<VulnDb, VulnDbError> {
        let root = path.as_ref();
        if !root.is_dir() {
            return Err(VulnDbError::SnapshotNotFound(root.to_path_buf()));
        }

        let mut entries = Vec::new();
        let cves_dir = root.join("cves");
        // Tolerate a snapshot whose records sit at the root rather than under
        // `cves/` — walk whichever exists.
        let scan_root = if cves_dir.is_dir() {
            cves_dir
        } else {
            root.to_path_buf()
        };
        collect_records(&scan_root, &mut entries)?;

        let kev_path = root.join("kev.json");
        let kev = match fs::read_to_string(&kev_path) {
            Ok(text) => ingest::parse_kev(&text),
            Err(_) => HashSet::new(),
        };

        let by_product = ingest::build_product_index(&entries);
        Ok(VulnDb {
            entries,
            by_product,
            kev,
        })
    }

    /// Number of indexed CVE records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the CVEs hypothesised to affect the given product, applying
    /// version-range containment when a version is supplied.
    ///
    /// At most one [`VulnMatch`] is returned per CVE (the highest confidence it
    /// reaches). Results are ordered most-serious first: known-exploited before
    /// not, then higher confidence, then higher CVSS.
    pub fn match_product(&self, cpe: &Cpe) -> Vec<VulnMatch> {
        let product_key = cpe.product.trim().to_ascii_lowercase();
        let query_vendor = cpe.vendor.as_ref().map(|v| v.trim().to_ascii_lowercase());

        let Some(indices) = self.by_product.get(&product_key) else {
            return Vec::new();
        };

        let mut out: Vec<VulnMatch> = Vec::new();
        for &i in indices {
            let entry = &self.entries[i];
            let mut best: Option<Confidence> = None;

            for aff in &entry.affected {
                if aff.product != product_key {
                    continue;
                }
                // Vendor narrows only when both the query and the record name
                // one; a record without a vendor does not veto the match.
                if let (Some(q), Some(a)) = (&query_vendor, &aff.vendor)
                    && q != a
                {
                    continue;
                }

                if let Some(conf) = confidence_for(aff, cpe.version.as_deref()) {
                    best = Some(best.map_or(conf, |b| b.max(conf)));
                }
            }

            if let Some(confidence) = best {
                out.push(VulnMatch {
                    cve_id: entry.cve_id.clone(),
                    summary: entry.summary.clone(),
                    confidence,
                    known_exploited: self.kev.contains(&entry.cve_id),
                    cvss: entry.cvss,
                });
            }
        }

        out.sort_by(|a, b| {
            b.known_exploited
                .cmp(&a.known_exploited)
                .then(b.confidence.cmp(&a.confidence))
                .then(
                    b.cvss
                        .unwrap_or(0.0)
                        .partial_cmp(&a.cvss.unwrap_or(0.0))
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
                .then(a.cve_id.cmp(&b.cve_id))
        });
        out
    }
}

/// Decide the confidence with which an affected-product entry matches the
/// (optional) queried version. Returns `None` when it does not match at all.
fn confidence_for(aff: &ingest::AffectedProduct, version: Option<&str>) -> Option<Confidence> {
    let Some(v) = version else {
        // Product-only query: any hit is a Low-confidence lead.
        return Some(Confidence::Low);
    };

    // No usable constraints => the whole product is flagged affected. The
    // version could not narrow it: Medium.
    let all_unbounded = aff.ranges.is_empty() || aff.ranges.iter().all(VersionRange::is_unbounded);
    if all_unbounded {
        return Some(Confidence::Medium);
    }

    // A concrete range that contains the version is the strongest signal.
    for range in &aff.ranges {
        if range.is_unbounded() {
            continue;
        }
        if range.contains(v) == Some(true) {
            return Some(Confidence::High);
        }
    }

    // Bounded ranges existed but none contained the version (or the version was
    // unparseable): no confident match. A residual unbounded range still flags
    // the product at Medium.
    if aff.ranges.iter().any(VersionRange::is_unbounded) {
        return Some(Confidence::Medium);
    }
    None
}

/// Recursively collect and parse every `*.json` file under `dir` into `out`.
/// A file that fails to read or parse is skipped.
fn collect_records(dir: &Path, out: &mut Vec<CveEntry>) -> Result<(), VulnDbError> {
    let read = fs::read_dir(dir).map_err(|source| VulnDbError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in read {
        let entry = entry.map_err(|source| VulnDbError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| VulnDbError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_dir() {
            collect_records(&path, out)?;
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        {
            // A KEV file living inside the scanned tree is not a CVE record; it
            // parses to nothing and is harmlessly skipped.
            if let Ok(text) = fs::read_to_string(&path)
                && let Some(record) = ingest::parse_cve_record(&text)
            {
                out.push(record);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
