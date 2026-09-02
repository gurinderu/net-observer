//! Integration tests: load a small hand-written snapshot from disk and exercise
//! matching end to end. The fixtures under `tests/fixtures/snapshot/` stand in
//! for the real cvelistV5 + KEV data, which is provisioned out-of-band and
//! never vendored.

use std::path::PathBuf;

use vuln_db::{Confidence, Cpe, VulnDb};

fn load() -> VulnDb {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/snapshot");
    VulnDb::load_from_dir(dir).expect("snapshot loads")
}

#[test]
fn snapshot_skips_malformed_and_indexes_the_rest() {
    let db = load();
    // Three valid records; the malformed CVE-2024-BAD.json is skipped.
    assert_eq!(db.len(), 3);
}

#[test]
fn exact_version_in_range_is_high_confidence() {
    let db = load();
    let hits = db.match_product(
        &Cpe::product("openssh")
            .with_vendor("openbsd")
            .with_version("7.3"),
    );
    assert_eq!(hits.len(), 1);
    let hit = &hits[0];
    assert_eq!(hit.cve_id, "CVE-2016-6210");
    assert_eq!(hit.confidence, Confidence::High);
    assert!(hit.known_exploited, "CVE-2016-6210 is in the KEV fixture");
    assert_eq!(hit.cvss, Some(5.9));
}

#[test]
fn version_outside_range_does_not_match() {
    let db = load();
    // 7.4 is the exclusive upper bound: not affected.
    let hits = db.match_product(&Cpe::product("openssh").with_version("7.4"));
    assert!(hits.is_empty());
}

#[test]
fn product_only_query_is_low_confidence() {
    let db = load();
    let hits = db.match_product(&Cpe::product("nginx"));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].confidence, Confidence::Low);
    assert!(!hits[0].known_exploited);
}

#[test]
fn whole_product_with_version_is_medium_confidence() {
    let db = load();
    let hits = db.match_product(&Cpe::product("nginx").with_version("1.18.0"));
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].confidence, Confidence::Medium);
}

#[test]
fn exact_affected_version_matches_only_itself() {
    let db = load();
    let hit = db.match_product(&Cpe::product("openssl").with_version("3.0.0"));
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].confidence, Confidence::High);

    let miss = db.match_product(&Cpe::product("openssl").with_version("3.0.1"));
    assert!(miss.is_empty());
}

#[test]
fn unknown_product_yields_nothing() {
    let db = load();
    assert!(db.match_product(&Cpe::product("nonesuch")).is_empty());
}

#[test]
fn wrong_vendor_filters_out_the_match() {
    let db = load();
    let hits = db.match_product(
        &Cpe::product("openssh")
            .with_vendor("acme")
            .with_version("7.3"),
    );
    assert!(hits.is_empty());
}
