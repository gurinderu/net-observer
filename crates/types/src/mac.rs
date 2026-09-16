//! MAC-address normalisation, shared by every producer that parses one from a
//! macOS command's raw text output (`arp`, `ndp`, `ifconfig`,
//! `ipconfig getsummary`) and by `triggers`, which compares two such values
//! without depending on the Apple-only `macos` crate. Lives here rather than
//! in `macos` so that fold is available on both sides of the boundary
//! (realm net-observer, node #94).

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
}
