//! MAC-address folds shared by every producer that parses one from a macOS
//! command's raw text output (`arp`, `ndp`, `ifconfig`, `ipconfig getsummary`)
//! and by the readers that compare or classify one — `triggers`, the link
//! sample's pure `build_link_sample` — without depending on the Apple-only
//! `macos` crate. `types` sits under every one of them, so the folds live here
//! rather than beside the OS-facing parsers: `macos` depends on
//! `collector-link` to implement its ports, and `collector-link` cannot depend
//! back on it without a cycle (realm net-observer, nodes #94 and #93).

/// Normalise a BSD-printed MAC to lowercase `aa:bb:cc:dd:ee:ff`, or `None` when
/// it is not a usable device address.
///
/// BSD prints octets without leading zeros (`0:1c:42:…`), so the padding
/// matters: unpadded, the same device would key two different rows depending
/// on which tool saw it. Rejected outright: an unparseable token — including a
/// literal `(incomplete)` ARP entry — the broadcast address, and any
/// multicast MAC (least-significant bit of the first octet set) — those are
/// not devices on the segment.
#[must_use]
pub fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut octets = Vec::with_capacity(6);
    for p in parts {
        octets.push(u8::from_str_radix(p, 16).ok()?);
    }
    if octets.iter().all(|&o| o == 0xff) || octets[0] & 1 == 1 {
        return None;
    }
    Some(
        octets
            .iter()
            .map(|o| format!("{o:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Classify `mac`'s Universal/Local bit — bit 1 of the first octet — as
/// administratively assigned (`true`: a randomized / Private Wi-Fi Address) or
/// the hardware-burned address (`false`). `None` exactly when
/// [`normalize_mac`] would reject the value, so the class is never claimed for
/// something that is not a device address (realm net-observer, node #93 item
/// 1; node #109 item 1).
#[must_use]
pub fn mac_is_private(mac: &str) -> Option<bool> {
    let normalised = normalize_mac(mac)?;
    let first_octet = normalised.split(':').next()?;
    let octet = u8::from_str_radix(first_octet, 16).ok()?;
    Some(octet & 0b0000_0010 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_and_multicast_are_not_devices() {
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(normalize_mac("01:00:5e:00:00:fb"), None);
        assert_eq!(normalize_mac("(incomplete)"), None);
        assert_eq!(
            normalize_mac("a4:83:E7:1b:2c:3d").as_deref(),
            Some("a4:83:e7:1b:2c:3d")
        );
    }

    /// Unpadded octets must key the same row as padded ones.
    #[test]
    fn pads_bsd_short_octets() {
        assert_eq!(
            normalize_mac("0:1c:42:8:9:a").as_deref(),
            Some("00:1c:42:08:09:0a")
        );
    }

    #[test]
    fn malformed_octets_are_none() {
        assert_eq!(normalize_mac("3c:22:fb::2:3"), None);
        assert_eq!(normalize_mac("3c:22:fb:123:02:03"), None);
    }

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

    /// The class is only ever claimed for a value `normalize_mac` accepts: a
    /// bare first octet, a short token or a multicast address is `None`.
    #[test]
    fn unparseable_or_non_device_mac_is_none() {
        assert_eq!(mac_is_private(""), None);
        assert_eq!(mac_is_private("not-a-mac"), None);
        assert_eq!(mac_is_private("zz:22:fb:12:34:56"), None);
        assert_eq!(mac_is_private("ca"), None);
        assert_eq!(mac_is_private("ca:garbage"), None);
        assert_eq!(mac_is_private("01:00:5e:00:00:fb"), None);
    }

    /// Case-insensitive and padding-insensitive, like the OS tools' own output
    /// before normalization.
    #[test]
    fn uppercase_and_unpadded_hex_still_classify() {
        assert_eq!(mac_is_private("CA:8F:38:B3:12:D3"), Some(true));
        assert_eq!(mac_is_private("2:1c:42:8:9:a"), Some(true));
    }
}
