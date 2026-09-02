//! Parsing of the on-disk snapshot into the in-memory index shapes.
//!
//! Two source formats are understood:
//! - **cvelistV5** CVE records (JSON Schema 5.0), one per file;
//! - the **CISA KEV** catalog (a single JSON file).
//!
//! Both are parsed leniently: a record that fails to deserialize, or lacks the
//! fields a match needs, is skipped rather than aborting the ingest. Partial
//! data still yields a usable index.

use std::collections::{HashMap, HashSet};

use serde::Deserialize;

use crate::version::VersionRange;

/// One affected product entry drawn from a CVE record.
#[derive(Debug, Clone)]
pub struct AffectedProduct {
    /// Lowercased vendor, if the record named a usable one.
    pub vendor: Option<String>,
    /// Lowercased product name.
    pub product: String,
    /// Version constraints. An empty vector means the whole product is
    /// affected (no version narrowing possible).
    pub ranges: Vec<VersionRange>,
}

/// A single indexed CVE.
#[derive(Debug, Clone)]
pub struct CveEntry {
    pub cve_id: String,
    pub summary: String,
    pub cvss: Option<f32>,
    pub affected: Vec<AffectedProduct>,
}

// ---- Raw serde shapes (all fields optional so partial records still load) ----

#[derive(Debug, Deserialize)]
struct RawRecord {
    #[serde(rename = "cveMetadata")]
    cve_metadata: Option<RawMetadata>,
    containers: Option<RawContainers>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    #[serde(rename = "cveId")]
    cve_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawContainers {
    cna: Option<RawCna>,
}

#[derive(Debug, Deserialize)]
struct RawCna {
    title: Option<String>,
    #[serde(default)]
    descriptions: Vec<RawDescription>,
    #[serde(default)]
    affected: Vec<RawAffected>,
    #[serde(default)]
    metrics: Vec<RawMetric>,
}

#[derive(Debug, Deserialize)]
struct RawDescription {
    lang: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAffected {
    vendor: Option<String>,
    product: Option<String>,
    #[serde(rename = "defaultStatus")]
    default_status: Option<String>,
    #[serde(default)]
    versions: Vec<RawVersion>,
}

#[derive(Debug, Deserialize)]
struct RawVersion {
    version: Option<String>,
    status: Option<String>,
    #[serde(rename = "lessThan")]
    less_than: Option<String>,
    #[serde(rename = "lessThanOrEqual")]
    less_than_or_equal: Option<String>,
    #[serde(rename = "versionStartIncluding")]
    version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    version_end_excluding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMetric {
    #[serde(rename = "cvssV3_1")]
    cvss_v3_1: Option<RawCvss>,
    #[serde(rename = "cvssV3_0")]
    cvss_v3_0: Option<RawCvss>,
    #[serde(rename = "cvssV2_0")]
    cvss_v2_0: Option<RawCvss>,
}

#[derive(Debug, Deserialize)]
struct RawCvss {
    #[serde(rename = "baseScore")]
    base_score: Option<f32>,
}

/// Parse one cvelistV5 record from its JSON text. Returns `None` when the text
/// is not valid JSON, or the record lacks a CVE id or any affected product
/// worth indexing.
pub fn parse_cve_record(text: &str) -> Option<CveEntry> {
    let record: RawRecord = serde_json::from_str(text).ok()?;
    let cve_id = record.cve_metadata?.cve_id?;
    if cve_id.is_empty() {
        return None;
    }
    let cna = record.containers?.cna?;

    let summary = cna
        .title
        .filter(|t| !t.is_empty())
        .or_else(|| first_english_description(&cna.descriptions))
        .unwrap_or_default();

    let cvss = cna.metrics.iter().find_map(metric_base_score);

    let affected: Vec<AffectedProduct> = cna
        .affected
        .into_iter()
        .filter_map(convert_affected)
        .collect();

    if affected.is_empty() {
        return None;
    }

    Some(CveEntry {
        cve_id,
        summary,
        cvss,
        affected,
    })
}

fn first_english_description(descs: &[RawDescription]) -> Option<String> {
    descs
        .iter()
        .find(|d| d.lang.as_deref().is_some_and(|l| l.starts_with("en")))
        .or_else(|| descs.first())
        .and_then(|d| d.value.clone())
        .filter(|v| !v.is_empty())
}

fn metric_base_score(m: &RawMetric) -> Option<f32> {
    [&m.cvss_v3_1, &m.cvss_v3_0, &m.cvss_v2_0]
        .into_iter()
        .flatten()
        .find_map(|c| c.base_score)
}

fn convert_affected(raw: RawAffected) -> Option<AffectedProduct> {
    let product = raw.product?.trim().to_ascii_lowercase();
    if product.is_empty() || product == "n/a" || product == "*" {
        return None;
    }
    let vendor = raw
        .vendor
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty() && v != "n/a" && v != "*");

    let default_affected = raw
        .default_status
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("affected"))
        .unwrap_or(false);

    let ranges: Vec<VersionRange> = raw
        .versions
        .into_iter()
        .filter_map(|v| convert_version(v, default_affected))
        .collect();

    Some(AffectedProduct {
        vendor,
        product,
        ranges,
    })
}

/// A start bound value of `0` or `*` means "from the beginning" — not a real
/// lower bound.
fn meaningful_start(v: &str) -> bool {
    let v = v.trim();
    !v.is_empty() && v != "0" && v != "*"
}

fn convert_version(raw: RawVersion, default_affected: bool) -> Option<VersionRange> {
    // Honour explicit status; fall back to the affected-list default status.
    let affected = match raw.status.as_deref() {
        Some(s) => s.eq_ignore_ascii_case("affected"),
        None => default_affected,
    };
    if !affected {
        return None;
    }

    let mut range = VersionRange::default();
    let mut has_upper = false;

    if let Some(lt) = raw.less_than.filter(|s| !s.trim().is_empty()) {
        range.end_excluding = Some(lt);
        has_upper = true;
    }
    if let Some(lte) = raw.less_than_or_equal.filter(|s| !s.trim().is_empty()) {
        range.end_including = Some(lte);
        has_upper = true;
    }
    if let Some(s) = raw.version_start_including.filter(|s| meaningful_start(s)) {
        range.start_including = Some(s);
    }
    if let Some(s) = raw.version_start_excluding.filter(|s| meaningful_start(s)) {
        range.start_excluding = Some(s);
    }
    if let Some(e) = raw.version_end_including.filter(|s| !s.trim().is_empty()) {
        range.end_including = Some(e);
        has_upper = true;
    }
    if let Some(e) = raw.version_end_excluding.filter(|s| !s.trim().is_empty()) {
        range.end_excluding = Some(e);
        has_upper = true;
    }

    if let Some(v) = raw.version.filter(|s| !s.trim().is_empty()) {
        if has_upper || range.start_including.is_some() || range.start_excluding.is_some() {
            // `version` acts as the (inclusive) lower bound of a range.
            if meaningful_start(&v)
                && range.start_including.is_none()
                && range.start_excluding.is_none()
            {
                range.start_including = Some(v);
            }
        } else if meaningful_start(&v) {
            // A lone concrete `version` is an exact affected version.
            range.exact = Some(v);
        }
        // A lone `version` of `0`/`*` with no bounds => whole product affected.
    }

    Some(range)
}

// ---- KEV catalog ----

#[derive(Debug, Deserialize)]
struct RawKev {
    #[serde(default)]
    vulnerabilities: Vec<RawKevEntry>,
}

#[derive(Debug, Deserialize)]
struct RawKevEntry {
    #[serde(rename = "cveID")]
    cve_id: Option<String>,
}

/// Parse the CISA KEV catalog into the set of known-exploited CVE ids. A
/// malformed catalog yields an empty set (the flag simply stays `false`),
/// never an error.
pub fn parse_kev(text: &str) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(kev) = serde_json::from_str::<RawKev>(text) {
        for entry in kev.vulnerabilities {
            if let Some(id) = entry.cve_id.filter(|s| !s.is_empty()) {
                set.insert(id);
            }
        }
    }
    set
}

/// Build a product-name -> entry-indices lookup over the given entries.
pub fn build_product_index(entries: &[CveEntry]) -> HashMap<String, Vec<usize>> {
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, entry) in entries.iter().enumerate() {
        let mut seen = HashSet::new();
        for aff in &entry.affected {
            if seen.insert(aff.product.clone()) {
                index.entry(aff.product.clone()).or_default().push(i);
            }
        }
    }
    index
}
