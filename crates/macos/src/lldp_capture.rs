//! A bounded, self-contained capture of LLDP/CDP discovery frames.
//!
//! # Why a dedicated capture, not the shared ring
//! The daemon already runs a `tcpdump` pcap *ring* (see [`crate::pcap`]), but
//! that ring is shared with the shell-oracle daemon and is deliberately delicate
//! (AGENTS.md gotcha): tapping it, or widening its BPF filter to also keep LLDP,
//! risks the one capture the incident freeze depends on. So topology discovery
//! opens its **own** short-lived `tcpdump`, filtered to just the two discovery
//! protocols, writing a tiny throwaway savefile that is parsed and discarded.
//! Nothing here touches the incident ring.
//!
//! # This is the privileged, un-verifiable edge
//! Reading raw Ethernet needs root and a BPF device, so — like the ICMP and
//! `tcpdump`-ring paths — the LIVE behaviour of this adapter cannot be observed
//! in the test environment; it is a project "Ceiling" claim (AGENTS.md, Reality).
//! It is therefore kept THIN and put behind the [`LldpCapture`] trait: the daemon
//! depends on the trait, the pure frame→edge mapping lives in
//! `types::topology` and is fully tested, and the only untested surface is the
//! spawn-and-read glue below. The classic-`pcap` savefile parser IS tested, so a
//! captured file is decoded into frames deterministically.
//!
//! # Honest degradation
//! No root, no `tcpdump`, or no BPF device → the capture yields an empty batch
//! and the caller logs it. Zero frames in a good capture is itself a signal
//! (nothing on this segment speaks LLDP/CDP), not an error — the SKIP-never-
//! silence discipline: absence is recorded, never dressed up as a healthy answer.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Captures raw Ethernet frames carrying LLDP/CDP, so a caller can map them to
/// topology links without knowing how the bytes were obtained.
///
/// Each returned `Vec<u8>` is one raw Ethernet frame starting at the destination
/// MAC — exactly what [`types::link_from_frame`] expects.
pub trait LldpCapture: Send + Sync {
    /// Capture for up to `budget`, returning the raw Ethernet frames seen. An
    /// empty vec means either nothing was heard or the capture could not run;
    /// the implementation logs which. Never panics, never blocks past `budget`.
    fn capture(&self, budget: Duration) -> Vec<Vec<u8>>;
}

/// The BPF filter: LLDP by its EtherType, CDP by its well-known multicast
/// destination (CDP is 802.3-framed and carries no EtherType to match on).
const LLDP_CDP_FILTER: &str = "ether proto 0x88cc or ether host 01:00:0c:cc:cc:cc";

/// Snap length: an LLDPDU/CDP payload of interest fits comfortably in 512 bytes;
/// a small snaplen keeps the throwaway savefile tiny.
const SNAPLEN: &str = "512";

/// Upper bound on frames captured per run, so a chatty segment cannot grow the
/// savefile without bound. `tcpdump -c` also lets a busy segment finish early.
const MAX_FRAMES: &str = "64";

/// A [`LldpCapture`] backed by a short-lived `tcpdump` child on one interface.
#[derive(Debug, Clone)]
pub struct TcpdumpLldpCapture {
    iface: String,
}

impl TcpdumpLldpCapture {
    /// Capture on `iface` (the physical uplink the daemon already resolved).
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
    }
}

impl LldpCapture for TcpdumpLldpCapture {
    fn capture(&self, budget: Duration) -> Vec<Vec<u8>> {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "topology capture: could not create temp dir; no links this run");
                return Vec::new();
            }
        };
        let out = dir.path().join("lldp.pcap");

        let mut cmd = Command::new("tcpdump");
        cmd.arg("-i")
            .arg(&self.iface)
            .arg("-s")
            .arg(SNAPLEN)
            .arg("-c")
            .arg(MAX_FRAMES)
            .arg("-w")
            .arg(&out)
            .arg("-U") // packet-buffered: flush each frame so a killed child still leaves a file
            .arg(LLDP_CDP_FILTER)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                // tcpdump missing, or no privilege to open BPF: degrade honestly.
                tracing::warn!(iface = %self.iface, error = %e,
                    "topology capture: could not start tcpdump (needs root + BPF); no links this run");
                return Vec::new();
            }
        };

        // Wait until the child exits on its own (hit -c), or the budget elapses.
        let deadline = Instant::now() + budget;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
            }
        }

        let frames = read_pcap_frames(&out);
        if frames.is_empty() {
            // Absence is a signal, not an error: say so plainly.
            tracing::info!(iface = %self.iface,
                "topology capture: no LLDP/CDP frames seen this run");
        } else {
            tracing::info!(iface = %self.iface, frames = frames.len(),
                "topology capture: received LLDP/CDP frames");
        }
        frames
    }
}

/// Read a classic-`pcap` savefile and return each record's captured frame bytes.
/// A missing/short/garbage file yields an empty vec, never a panic.
fn read_pcap_frames(path: &Path) -> Vec<Vec<u8>> {
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
fn parse_pcap_records(bytes: &[u8]) -> Vec<Vec<u8>> {
    const GLOBAL_HEADER: usize = 24;
    const RECORD_HEADER: usize = 16;
    if bytes.len() < GLOBAL_HEADER {
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
    let mut off = GLOBAL_HEADER;
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
