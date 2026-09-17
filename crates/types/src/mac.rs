//! Classifying an already-read MAC address, kept beside the sample types that
//! carry one rather than beside the OS-facing MAC parser: the parser
//! (`normalize_mac`) lives in the `macos` crate, which depends on
//! `collector-link` to implement its `LinkFacts` port — so `collector-link`'s
//! pure `build_link_sample` (which needs this fold) cannot depend back on
//! `macos` without a cycle. `types` sits under both, so the fold lives here
//! instead of "beside `normalize_mac`" as first proposed (realm net-observer,
//! node #93 item 1; node #109 item 1).

/// Classify `mac`'s Universal/Local bit — bit 1 of the first octet — as
/// administratively assigned (`true`: a randomized/Private Wi-Fi Address) or
/// the hardware-burned address (`false`). `None` when `mac` does not parse as
/// a colon-separated MAC (mirrors the leniency of `macos::neighbors::normalize_mac`,
/// which this reads the same shape as, whether or not the value has already
/// passed through it).
#[must_use]
pub fn mac_is_private(mac: &str) -> Option<bool> {
    let first_octet = mac.split(':').next()?;
    let octet = u8::from_str_radix(first_octet, 16).ok()?;
    Some(octet & 0b0000_0010 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ca:8f:38:b3:12:d3` — the fixture DHCP client MAC (node #93 item 1) —
    /// has the U/L bit set: a Private Wi-Fi Address, administratively local.
    #[test]
    fn ca_prefix_is_private() {
        assert_eq!(mac_is_private("ca:8f:38:b3:12:d3"), Some(true));
    }

    /// `3c:...` is a real OUI-assigned prefix: the U/L bit is clear, the
    /// hardware-burned address.
    #[test]
    fn three_c_prefix_is_not_private() {
        assert_eq!(mac_is_private("3c:22:fb:12:34:56"), Some(false));
    }

    #[test]
    fn unparseable_mac_is_none() {
        assert_eq!(mac_is_private(""), None);
        assert_eq!(mac_is_private("not-a-mac"), None);
        assert_eq!(mac_is_private("zz:22:fb:12:34:56"), None);
    }

    /// Case-insensitive, like the OS tools' own output before normalization.
    #[test]
    fn uppercase_hex_still_parses() {
        assert_eq!(mac_is_private("CA:8F:38:B3:12:D3"), Some(true));
    }
}
