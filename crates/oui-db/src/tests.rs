//! In-crate unit tests for the pure logic: OUI extraction, line parsing, and the
//! randomized-bit short-circuit. Integration against an on-disk `manuf` snapshot
//! lives in `tests/`.

use super::*;

// ---- OUI extraction ----

#[test]
fn extract_oui_normalizes_case_and_separators() {
    assert_eq!(
        extract_oui("00:1A:2B:CC:DD:EE"),
        Some((0x00, "00:1a:2b".to_string()))
    );
    // Hyphen separators are accepted too.
    assert_eq!(
        extract_oui("00-1a-2b-cc-dd-ee"),
        Some((0x00, "00:1a:2b".to_string()))
    );
    // A bare OUI is enough.
    assert_eq!(
        extract_oui("aa:bb:cc"),
        Some((0xaa, "aa:bb:cc".to_string()))
    );
}

#[test]
fn extract_oui_rejects_garbage() {
    assert!(extract_oui("").is_none());
    assert!(extract_oui("00:11").is_none()); // too few octets
    assert!(extract_oui("zz:11:22").is_none()); // non-hex
}

// ---- line parsing ----

#[test]
fn parse_line_reads_a_ma_l_entry_with_long_name() {
    let (oui, entry) = parse_line("00:1A:2B\tAcme\tAcme Corporation").expect("parses");
    assert_eq!(oui, "00:1a:2b");
    assert_eq!(entry.name, "Acme Corporation");
    assert_eq!(entry.short.as_deref(), Some("Acme"));
}

#[test]
fn parse_line_reads_short_only_entry() {
    let (oui, entry) = parse_line("00:AA:BB\tShortOnly").expect("parses");
    assert_eq!(oui, "00:aa:bb");
    assert_eq!(entry.name, "ShortOnly");
    assert_eq!(entry.short, None);
}

#[test]
fn parse_line_skips_comments_and_blanks() {
    assert!(parse_line("# a comment").is_none());
    assert!(parse_line("   ").is_none());
    assert!(parse_line("").is_none());
}

#[test]
fn parse_line_skips_longer_prefix() {
    // A MA-M/MA-S sub-block must not be indexed as the 24-bit OUI.
    assert!(parse_line("3C:5A:B4:D0:00:00/28\tGoogleSub\tGoogle Sub").is_none());
}

#[test]
fn parse_line_skips_malformed_octets() {
    assert!(parse_line("ZZ:ZZ:ZZ\tGarbage").is_none());
}

// ---- randomized short-circuit ----

#[test]
fn lookup_reports_randomized_for_locally_administered() {
    let db = OuiDb::default();
    // 0x06 has the locally-administered bit (0x02) set.
    assert_eq!(db.lookup("06:11:22:33:44:55"), VendorLookup::Randomized);
    // 0x02 itself is the boundary case.
    assert_eq!(db.lookup("02:00:00:00:00:01"), VendorLookup::Randomized);
}

#[test]
fn lookup_unknown_for_universally_administered_miss() {
    let db = OuiDb::default();
    // 0x00 is universally administered; empty db has no entry.
    assert_eq!(db.lookup("00:11:22:33:44:55"), VendorLookup::Unknown);
}

#[test]
fn lookup_unknown_for_unparseable_input() {
    let db = OuiDb::default();
    assert_eq!(db.lookup("not-a-mac"), VendorLookup::Unknown);
}
