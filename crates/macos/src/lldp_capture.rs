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

        let frames = crate::pcap_savefile::read_pcap_frames(&out);
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
