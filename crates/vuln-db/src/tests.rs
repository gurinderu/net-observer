//! In-crate unit tests for the pure logic: version comparison, banner parsing,
//! and record parsing. Integration against an on-disk snapshot lives in
//! `tests/`.

use super::*;

// ---- version comparator ----

fn v(s: &str) -> Version {
    Version::parse(s).expect("parseable")
}

#[test]
fn version_orders_dotted_numeric() {
    assert!(v("7.2") < v("7.4"));
    assert!(v("8.2.0") > v("8.1.9"));
    assert!(v("1.10") > v("1.9"));
    assert_eq!(v("1.2.3"), v("1.2.3"));
}

#[test]
fn version_orders_patch_suffix() {
    // A patch suffix makes a release strictly newer than the bare release.
    assert!(v("7.2p2") > v("7.2"));
    assert!(v("1.2.3p1") > v("1.2.3"));
    assert!(v("1.2.3p1") < v("1.2.4"));
}

#[test]
fn version_unparseable_yields_none() {
    assert!(Version::parse("").is_none());
    assert!(Version::parse("unknown").is_none());
    assert!(Version::parse("*").is_none());
    assert!(Version::parse("n/a").is_none());
}

#[test]
fn range_contains_respects_bounds() {
    let r = VersionRange {
        start_including: Some("7.2".into()),
        end_excluding: Some("7.4".into()),
        ..Default::default()
    };
    assert_eq!(r.contains("7.2"), Some(true));
    assert_eq!(r.contains("7.3"), Some(true));
    assert_eq!(r.contains("7.4"), Some(false)); // exclusive upper
    assert_eq!(r.contains("7.1"), Some(false));
}

#[test]
fn range_exact_matches_only_itself() {
    let r = VersionRange {
        exact: Some("3.0.0".into()),
        ..Default::default()
    };
    assert_eq!(r.contains("3.0.0"), Some(true));
    assert_eq!(r.contains("3.0.1"), Some(false));
}

#[test]
fn range_unparseable_query_is_conservative() {
    let r = VersionRange {
        start_including: Some("1.0".into()),
        end_excluding: Some("2.0".into()),
        ..Default::default()
    };
    // An unparseable version is never claimed to be in range.
    assert_eq!(r.contains("garbage"), None);
}

// ---- banner parsing ----

#[test]
fn banner_parses_openssh() {
    let cpe = parse_banner("SSH-2.0-OpenSSH_7.4").expect("parses");
    assert_eq!(cpe.product, "openssh");
    assert_eq!(cpe.version.as_deref(), Some("7.4"));
}

#[test]
fn banner_parses_openssh_with_os_comment() {
    let cpe = parse_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5").expect("parses");
    assert_eq!(cpe.product, "openssh");
    assert_eq!(cpe.version.as_deref(), Some("8.2p1"));
}

#[test]
fn banner_parses_http_server_header() {
    let cpe = parse_banner("Server: nginx/1.18.0").expect("parses");
    assert_eq!(cpe.product, "nginx");
    assert_eq!(cpe.version.as_deref(), Some("1.18.0"));

    let cpe = parse_banner("Apache/2.4.41 (Ubuntu)").expect("parses");
    assert_eq!(cpe.product, "apache");
    assert_eq!(cpe.version.as_deref(), Some("2.4.41"));
}

#[test]
fn banner_gives_up_honestly() {
    assert!(parse_banner("").is_none());
    assert!(parse_banner("this is not a banner").is_none());
    assert!(parse_banner("SSH-2.0-Dropbear").is_none()); // no _version
}
