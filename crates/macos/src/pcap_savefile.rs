//! The classic (non-`pcapng`) libpcap savefile parser, shared by every
//! short-lived `tcpdump -w <file>` capture in this crate.
//!
//! Two on-demand captures write a throwaway savefile and read its frames back:
//! the LLDP/CDP topology capture ([`crate::lldp_capture`]) and the `en0` egress
//! capture ([`crate::egress_capture`], realm net-observer, node #170). Both
//! need exactly the same thing — turn a classic-pcap file `tcpdump` left behind
//! into the per-record captured frames — so the parser lives here once rather
//! than being copied into each capture (AGENTS.md principle 4).
//!
//! Every path a missing, short, truncated or non-classic file can take yields
//! an empty vec or the records decoded so far, never a panic: a child killed
//! mid-write must cost at most its last partial record, and a `pcapng` magic
//! (a future `tcpdump` default) must decode to nothing rather than be misread.

use std::path::Path;

/// The classic-pcap savefile global header size. `tcpdump` writes it on
/// opening the capture device, before any packet — so a savefile shorter than
/// this never held a real capture, which lets a caller tell "ran, saw nothing"
/// from "never ran" (realm net-observer, node #170).
pub(crate) const PCAP_GLOBAL_HEADER: usize = 24;

/// Whether `path` holds at least a full pcap global header — i.e. `tcpdump`
/// actually opened the device and began a capture. `false` for a missing or
/// header-short file: the capture never started, which the egress scan must
/// not mistake for an honest empty capture (realm net-observer, node #170).
pub(crate) fn has_pcap_header(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.len() >= PCAP_GLOBAL_HEADER as u64)
}

/// Read a classic-`pcap` savefile and return each record's captured frame
/// bytes. A missing/short/garbage file yields an empty vec, never a panic.
pub(crate) fn read_pcap_frames(path: &Path) -> Vec<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => parse_pcap_records(&bytes),
        Err(_) => Vec::new(),
    }
}

/// Parse the classic (non-`pcapng`) libpcap savefile format into its per-record
/// captured frames.
///
/// Layout: a 24-byte global header whose 4-byte magic selects endianness
/// (`0xa1b2c3d4` native, `0xd4c3b2a1` byte-swapped), then records of a 16-byte
/// header (`ts_sec`, `ts_usec`, `incl_len`, `orig_len`) followed by `incl_len`
/// captured bytes. Any length that would run past the buffer stops the parse
/// with what was decoded so far — a truncated tail (a child killed mid-write) is
/// not a panic and not a lost prefix.
pub(crate) fn parse_pcap_records(bytes: &[u8]) -> Vec<Vec<u8>> {
    const RECORD_HEADER: usize = 16;
    if bytes.len() < PCAP_GLOBAL_HEADER {
        return Vec::new();
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let swapped = match magic {
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        // Not a classic pcap savefile (e.g. pcapng's 0x0a0d0d0a): decode nothing
        // rather than misread it.
        _ => return Vec::new(),
    };
    let u32_at = |b: &[u8]| -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if swapped {
            u32::from_le_bytes(arr)
        } else {
            u32::from_be_bytes(arr)
        }
    };

    let mut frames = Vec::new();
    let mut off = PCAP_GLOBAL_HEADER;
    while off + RECORD_HEADER <= bytes.len() {
        let incl_len = u32_at(&bytes[off + 8..off + 12]) as usize;
        let start = off + RECORD_HEADER;
        let end = match start.checked_add(incl_len) {
            Some(e) => e,
            None => break,
        };
        if end > bytes.len() {
            break;
        }
        frames.push(bytes[start..end].to_vec());
        off = end;
    }
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal classic-pcap savefile carrying `records`, in the given
    /// endianness, so the parser can be exercised without a live capture.
    fn pcap_file(records: &[&[u8]], swapped: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let magic: [u8; 4] = if swapped {
            [0xd4, 0xc3, 0xb2, 0xa1]
        } else {
            [0xa1, 0xb2, 0xc3, 0xd4]
        };
        out.extend_from_slice(&magic);
        // Remaining 20 bytes of the global header are unread by the parser.
        out.extend_from_slice(&[0u8; 20]);
        let put_u32 = |out: &mut Vec<u8>, v: u32| {
            if swapped {
                out.extend_from_slice(&v.to_le_bytes());
            } else {
                out.extend_from_slice(&v.to_be_bytes());
            }
        };
        for rec in records {
            put_u32(&mut out, 1); // ts_sec
            put_u32(&mut out, 2); // ts_usec
            put_u32(&mut out, rec.len() as u32); // incl_len
            put_u32(&mut out, rec.len() as u32); // orig_len
            out.extend_from_slice(rec);
        }
        out
    }

    /// The egress scan leans on this to tell "tcpdump ran and saw nothing"
    /// (header present, no records) from "tcpdump was killed before it opened
    /// the device" (no header) — the false-zero the egress capture must never
    /// produce (realm net-observer, node #170).
    #[test]
    fn has_pcap_header_tells_a_started_capture_from_a_killed_before_header_one() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file: the child never wrote anything.
        assert!(!has_pcap_header(&dir.path().join("missing.pcap")));
        // Shorter than the global header: killed before it opened the device.
        let short = dir.path().join("short.pcap");
        std::fs::write(&short, [0u8; PCAP_GLOBAL_HEADER - 1]).unwrap();
        assert!(!has_pcap_header(&short));
        // A header-only file is a real capture that genuinely saw nothing.
        let empty = dir.path().join("empty.pcap");
        std::fs::write(&empty, pcap_file(&[], false)).unwrap();
        assert!(has_pcap_header(&empty));
    }

    #[test]
    fn parses_records_in_both_endiannesses() {
        for swapped in [false, true] {
            let a: &[u8] = &[0xaa, 0xbb, 0xcc];
            let b: &[u8] = &[0x11, 0x22, 0x33, 0x44];
            let file = pcap_file(&[a, b], swapped);
            let frames = parse_pcap_records(&file);
            assert_eq!(frames, vec![a.to_vec(), b.to_vec()], "swapped={swapped}");
        }
    }

    #[test]
    fn a_non_pcap_or_short_buffer_yields_nothing() {
        assert!(parse_pcap_records(&[]).is_empty());
        assert!(parse_pcap_records(&[0u8; 10]).is_empty());
        // pcapng magic, not classic pcap.
        let mut ng = vec![0x0a, 0x0d, 0x0d, 0x0a];
        ng.extend_from_slice(&[0u8; 40]);
        assert!(parse_pcap_records(&ng).is_empty());
    }

    #[test]
    fn a_truncated_tail_keeps_the_whole_records_before_it() {
        let good: &[u8] = &[0x01, 0x02, 0x03];
        let mut file = pcap_file(&[good], false);
        // Append a record header claiming more bytes than remain.
        file.extend_from_slice(&99u32.to_be_bytes()); // ts_sec
        file.extend_from_slice(&0u32.to_be_bytes()); // ts_usec
        file.extend_from_slice(&100u32.to_be_bytes()); // incl_len (past EOF)
        file.extend_from_slice(&100u32.to_be_bytes()); // orig_len
        file.extend_from_slice(&[0xde, 0xad]); // only 2 bytes, not 100
        let frames = parse_pcap_records(&file);
        assert_eq!(frames, vec![good.to_vec()]);
    }
}
