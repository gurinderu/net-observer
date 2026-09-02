//! `oui-db` — a local, **offline** hardware-vendor resolver for MAC addresses.
//!
//! The IEEE registry maps the first 24 bits of a MAC (the OUI / MA-L block) to
//! the organization that registered it. At runtime the daemon may sit on a dead
//! network, so this crate never touches the network: it ingests a **local
//! snapshot** already present on disk and answers lookups from an in-memory map.
//!
//! # Snapshot format
//! [`OuiDb::load_from_file`] expects a file in the Wireshark `manuf` format:
//! one entry per line, fields separated by a TAB, `#` starting a comment.
//!
//! ```text
//! # comment lines start with '#'
//! 00:1A:2B<TAB>Acme<TAB>Acme Corporation
//! 00:AA:BB<TAB>ShortOnly
//! 3C:5A:B4:D0:00:00/28<TAB>Google<TAB>Google, Inc.   # longer prefix: skipped
//! ```
//!
//! Only plain 24-bit MA-L entries (exactly three hex octets, no `/mask`) are
//! indexed. Longer-prefix MA-M/MA-S lines (`AA:BB:CC:D0:00:00/28`) are skipped
//! rather than mis-parsed as a 24-bit block — degrading gracefully instead of
//! attributing a whole OUI to a sub-block owner. The real registry is large and
//! provisioned out-of-band by the operator; it is never vendored into this repo.
//!
//! # A lookup has three distinct outcomes
//! [`OuiDb::lookup`] returns a [`VendorLookup`] that keeps the three cases apart:
//! a registry [`VendorLookup::Vendor`] hit, a [`VendorLookup::Randomized`]
//! locally-administered address (a privacy/randomized MAC with no registered
//! owner — never guess a vendor for it), and a [`VendorLookup::Unknown`]
//! universally-administered MAC absent from the snapshot.

mod error;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub use error::OuiDbError;

/// The outcome of resolving a MAC address against the registry.
///
/// The three cases are deliberately distinct: a randomized phone MAC must read
/// as [`Randomized`](VendorLookup::Randomized), not as an
/// [`Unknown`](VendorLookup::Unknown) vendor, and never as a made-up owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VendorLookup {
    /// The OUI is present in the registry snapshot.
    Vendor {
        /// The organization name (the long name when the snapshot carries one,
        /// otherwise the short name).
        name: String,
        /// The short name, when the snapshot distinguishes it from `name`.
        short: Option<String>,
    },
    /// The MAC is locally administered (the second-least-significant bit of the
    /// first octet is set, `first_octet & 0x02 != 0`): a privacy/randomized
    /// address with no registered owner. No vendor is ever guessed for it.
    Randomized,
    /// A well-formed, universally-administered MAC with no registry entry — or
    /// an input from which no OUI could be extracted.
    Unknown,
}

/// One registry entry: the names registered for an OUI.
#[derive(Debug, Clone)]
struct VendorEntry {
    name: String,
    short: Option<String>,
}

/// An in-memory, queryable OUI→vendor index built from a local snapshot.
#[derive(Debug, Clone, Default)]
pub struct OuiDb {
    /// Lowercase `aa:bb:cc` OUI -> registered names.
    by_oui: HashMap<String, VendorEntry>,
}

impl OuiDb {
    /// Ingest a `manuf`-format snapshot file into an index.
    ///
    /// A malformed or non-24-bit line is skipped, never fatal — only a missing
    /// file or an I/O failure while reading it is an error.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<OuiDb, OuiDbError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| OuiDbError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        let mut by_oui = HashMap::new();
        for line in text.lines() {
            if let Some((oui, entry)) = parse_line(line) {
                by_oui.insert(oui, entry);
            }
        }
        Ok(OuiDb { by_oui })
    }

    /// Number of indexed OUIs.
    pub fn len(&self) -> usize {
        self.by_oui.len()
    }

    /// Whether the index holds no entries.
    pub fn is_empty(&self) -> bool {
        self.by_oui.is_empty()
    }

    /// Resolve a MAC (or bare OUI) against the registry.
    ///
    /// A locally-administered address short-circuits to
    /// [`VendorLookup::Randomized`] before any registry lookup — the randomized
    /// bit is authoritative, so a privacy MAC is never reported as a vendor even
    /// if its (meaningless) OUI happened to collide with a real block.
    pub fn lookup(&self, mac: &str) -> VendorLookup {
        let Some((first_octet, oui)) = extract_oui(mac) else {
            return VendorLookup::Unknown;
        };

        // The locally-administered bit is decisive: no real owner exists.
        if first_octet & 0x02 != 0 {
            return VendorLookup::Randomized;
        }

        match self.by_oui.get(&oui) {
            Some(entry) => VendorLookup::Vendor {
                name: entry.name.clone(),
                short: entry.short.clone(),
            },
            None => VendorLookup::Unknown,
        }
    }
}

/// Parse one `manuf`-format line into `(oui, entry)`, or `None` to skip it.
///
/// Skips blank lines, `#` comments, and any first field that is not exactly a
/// 24-bit OUI (three hex octets, no `/mask`).
fn parse_line(line: &str) -> Option<(String, VendorEntry)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut fields = line.split('\t').map(str::trim);
    let prefix = fields.next()?;

    // A longer-prefix line (MA-M/MA-S, e.g. `AA:BB:CC:D0:00:00/28`) or anything
    // that is not a clean 24-bit OUI is skipped rather than mis-parsed.
    let (_first_octet, oui) = parse_plain_oui(prefix)?;

    let short = fields.next().filter(|s| !s.is_empty());
    let long = fields.next().filter(|s| !s.is_empty());

    // Prefer the long descriptive name; fall back to the short name.
    let entry = match (short, long) {
        (Some(s), Some(l)) => VendorEntry {
            name: l.to_string(),
            short: Some(s.to_string()),
        },
        (Some(s), None) => VendorEntry {
            name: s.to_string(),
            short: None,
        },
        // A bare OUI with no name carries no information: skip it.
        (None, _) => return None,
    };
    Some((oui, entry))
}

/// Parse a token that must be exactly a 24-bit OUI (three hex octets separated
/// by `:` or `-`, with no CIDR-style `/mask`). Returns `(first_octet,
/// "aa:bb:cc")`, or `None` if it is anything else.
fn parse_plain_oui(token: &str) -> Option<(u8, String)> {
    // Reject sub-block prefixes outright.
    if token.contains('/') {
        return None;
    }
    let parts: Vec<&str> = token.split([':', '-']).collect();
    if parts.len() != 3 {
        return None;
    }
    let mut octets = [0u8; 3];
    for (slot, p) in octets.iter_mut().zip(parts) {
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    let oui = format!("{:02x}:{:02x}:{:02x}", octets[0], octets[1], octets[2]);
    Some((octets[0], oui))
}

/// Extract the first octet and the lowercase `aa:bb:cc` OUI from a full MAC or a
/// bare OUI. Accepts `:`- or `-`-separated hex; needs at least three octets.
fn extract_oui(mac: &str) -> Option<(u8, String)> {
    let mac = mac.trim();
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() < 3 {
        return None;
    }
    let mut octets = [0u8; 3];
    for (slot, p) in octets.iter_mut().zip(&parts[..3]) {
        *slot = u8::from_str_radix(p, 16).ok()?;
    }
    let oui = format!("{:02x}:{:02x}:{:02x}", octets[0], octets[1], octets[2]);
    Some((octets[0], oui))
}

#[cfg(test)]
mod tests;
