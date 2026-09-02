//! Integration tests: load a small hand-written `manuf` snapshot from disk and
//! exercise lookups end to end. The fixture under `tests/fixtures/manuf` stands
//! in for the real Wireshark registry, which is provisioned out-of-band and
//! never vendored.

use std::path::PathBuf;

use oui_db::{OuiDb, VendorLookup};

fn load() -> OuiDb {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manuf");
    OuiDb::load_from_file(path).expect("snapshot loads")
}

#[test]
fn indexes_only_the_two_valid_ma_l_entries() {
    let db = load();
    // 00:1A:2B, 00:AA:BB and the explicitly /24-stamped AA:BB:CC are valid; the
    // comment, the /28 sub-block and the malformed line are all skipped.
    assert_eq!(db.len(), 3);
}

#[test]
fn resolves_a_registered_oui_with_long_and_short_names() {
    let db = load();
    assert_eq!(
        db.lookup("00:1A:2B:99:88:77"),
        VendorLookup::Vendor {
            name: "Acme Corporation".to_string(),
            short: Some("Acme".to_string()),
        }
    );
}

#[test]
fn lookup_is_case_insensitive() {
    let db = load();
    let lower = db.lookup("00:1a:2b:00:00:01");
    let upper = db.lookup("00:1A:2B:00:00:01");
    assert_eq!(lower, upper);
    assert!(matches!(lower, VendorLookup::Vendor { .. }));
}

#[test]
fn short_only_entry_has_no_short_field() {
    let db = load();
    assert_eq!(
        db.lookup("00:AA:BB:00:00:01"),
        VendorLookup::Vendor {
            name: "ShortOnly".to_string(),
            short: None,
        }
    );
}

#[test]
fn longer_prefix_is_not_indexed_as_24_bit_oui() {
    let db = load();
    // The /28 sub-block line must not have created an entry for 3c:5a:b4.
    // 0x3C is universally administered, so this is a clean Unknown.
    assert_eq!(db.lookup("3C:5A:B4:00:00:01"), VendorLookup::Unknown);
}

#[test]
fn randomized_mac_reads_as_randomized_not_unknown() {
    let db = load();
    // A privacy/randomized address (locally-administered bit set) must never be
    // guessed as a vendor and must be distinct from Unknown.
    assert_eq!(db.lookup("DA:A1:19:12:34:56"), VendorLookup::Randomized);
}

#[test]
fn universally_administered_miss_is_unknown() {
    let db = load();
    assert_eq!(db.lookup("00:CC:DD:11:22:33"), VendorLookup::Unknown);
}

#[test]
fn missing_file_is_an_error() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/does-not-exist");
    assert!(OuiDb::load_from_file(path).is_err());
}

#[test]
fn an_explicitly_slash24_masked_ma_l_entry_is_indexed() {
    // Some manuf snapshots stamp MA-L with an explicit /24; it must resolve, not
    // silently drop to Unknown (which would empty a differently-formatted DB).
    let db = load();
    match db.lookup("A8:BB:CC:11:22:33") {
        VendorLookup::Vendor { name, .. } => assert_eq!(name, "Masked Company Inc"),
        other => panic!("expected a vendor for a /24-stamped MA-L, got {other:?}"),
    }
}
