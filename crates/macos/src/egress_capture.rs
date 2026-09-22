//! A bounded, self-contained capture of the physical interface's **outgoing**
//! IP packets, for the on-demand `en0` egress scan (realm net-observer, node
//! #170).
//!
//! # Why a dedicated capture, not the shared ring or `connections`
//! The `connections` collector reads sing-box's Clash API — the tunneled view.
//! It cannot see what physically leaves `en0`: the encrypted uplink carries the
//! proxy endpoint's address, and route-excluded traffic never reaches the Clash
//! API at all. The daemon's incident pcap *ring* ([`crate::pcap`]) is shared
//! with the shell-oracle daemon and deliberately delicate, so — exactly like the
//! LLDP capture ([`crate::lldp_capture`]) — this opens its **own** short-lived
//! `tcpdump`, filtered to outgoing IP only, writing a throwaway savefile that is
//! parsed by [`crate::pcap_savefile`] and discarded. Nothing here touches the
//! incident ring.
//!
//! # SKIP is not silence — and here it matters more than anywhere
//! This is the privileged, un-verifiable edge (root + BPF), a project "Ceiling"
//! claim, so it is kept THIN behind [`EgressCapture`]; the pure frame→(dst,len)
//! mapping lives in `types::egress` and is fully tested. The one distinction
//! this glue MUST get right is **could-not-capture vs a real zero**: under an
//! active tunnel, zero outgoing packets on `en0` almost always means the capture
//! failed, not that nothing left the machine — and a false "nothing observed"
//! would mislead exactly the question this scan answers. So the outcome is a
//! two-state [`EgressCaptureOutcome`]: [`CouldNotStart`] when `tcpdump` could not
//! be spawned or exited with an error before its budget, [`Ran`] (possibly with
//! an empty frame list) only when a capture genuinely ran. The two are never
//! conflated.
//!
//! [`CouldNotStart`]: EgressCaptureOutcome::CouldNotStart
//! [`Ran`]: EgressCaptureOutcome::Ran

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What one capture attempt did: either it could not run at all, or it ran and
/// left these frames.
///
/// The distinction is the whole point (see the module doc): an empty
/// [`EgressCaptureOutcome::Ran`] is a genuine zero the caller records as
/// `verdict = OK, dst_count = 0`; [`EgressCaptureOutcome::CouldNotStart`] is the
/// `SKIP` the caller records with its reason. Never collapse them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressCaptureOutcome {
    /// The capture could not run: `tcpdump` is missing, the daemon lacks
    /// root/BPF, the interface is gone, or the child exited with an error
    /// before its budget. Carries a human reason for the `SKIP` row.
    CouldNotStart(String),
    /// A capture ran to its budget (or hit its packet cap) and left these raw
    /// Ethernet frames, each starting at the destination MAC — exactly what
    /// [`types::dst_and_len`] expects. An empty vec is an honest zero, never a
    /// failure.
    Ran(Vec<Vec<u8>>),
}

/// Captures the raw outgoing Ethernet frames on one interface, so a caller can
/// fold them by destination without knowing how the bytes were obtained.
pub trait EgressCapture: Send + Sync {
    /// Capture for up to `budget`, returning [`EgressCaptureOutcome::Ran`] with
    /// the frames seen when a capture ran, or [`EgressCaptureOutcome::CouldNotStart`]
    /// with a reason when one could not. Never panics, never blocks past
    /// `budget` (plus the brief wait to reap the killed child).
    fn capture(&self, budget: Duration) -> EgressCaptureOutcome;
}

/// The BPF filter: outgoing IP only. `-Q out` (below) restricts the *direction*;
/// this restricts it to IPv4/IPv6 packets, the ones [`types::dst_and_len`]
/// folds. Split on whitespace at the call site, the way [`crate::pcap`] applies
/// its ring filter.
const EGRESS_FILTER: &str = "ip or ip6";

/// Snap length: only the Ethernet + IP headers are read (the destination and
/// on-wire length live there); a small snaplen keeps the throwaway savefile
/// tiny even under a busy uplink. 128 bytes clears an IPv6 header plus options.
const SNAPLEN: &str = "128";

/// Upper bound on packets captured per run, so a saturated uplink cannot grow
/// the savefile without bound. `tcpdump -c` also lets a very busy interface
/// finish early; on a normal one the budget is what ends the capture.
const MAX_PACKETS: &str = "200000";

/// An [`EgressCapture`] backed by a short-lived `tcpdump -Q out` child on one
/// interface.
#[derive(Debug, Clone)]
pub struct TcpdumpEgressCapture {
    iface: String,
}

impl TcpdumpEgressCapture {
    /// Capture on `iface` (the physical uplink the daemon resolves fresh at
    /// scan time).
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
        }
    }
}

impl EgressCapture for TcpdumpEgressCapture {
    fn capture(&self, budget: Duration) -> EgressCaptureOutcome {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(e) => {
                let reason = format!("could not create temp dir for the capture: {e}");
                tracing::warn!(iface = %self.iface, error = %e, "egress capture: {reason}");
                return EgressCaptureOutcome::CouldNotStart(reason);
            }
        };
        let out = dir.path().join("egress.pcap");

        // `-Q out`: capture only packets this machine SENDS, so the fold sees
        // what leaves `en0` and never the replies coming back. Direction
        // capture is a `tcpdump` feature, not verified on this Linux sandbox —
        // a to-verify-on-Mac item (realm net-observer, node #170).
        let mut cmd = Command::new("tcpdump");
        cmd.arg("-i")
            .arg(&self.iface)
            .arg("-s")
            .arg(SNAPLEN)
            .arg("-c")
            .arg(MAX_PACKETS)
            .arg("-w")
            .arg(&out)
            .arg("-U") // packet-buffered: flush each frame so a killed child still leaves a file
            .arg("-Q")
            .arg("out");
        for token in EGRESS_FILTER.split_whitespace() {
            cmd.arg(token);
        }
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                // tcpdump missing, or no privilege to fork it: a SKIP with its
                // reason, never a zero.
                let reason = format!("could not start tcpdump (needs root + BPF): {e}");
                tracing::warn!(iface = %self.iface, error = %e, "egress capture: {reason}");
                return EgressCaptureOutcome::CouldNotStart(reason);
            }
        };

        // Drain stderr on a thread so a chatty child cannot deadlock on a full
        // pipe during the budget, and so its last words are available if it
        // exits early with an error.
        let stderr_tail = child.stderr.take().map(drain_stderr);

        // Wait until the child exits on its own (hit -c, or failed), or the
        // budget elapses and we kill it. `None` means WE ended it at the budget
        // — the normal path for a healthy capture — and is never a failure.
        let deadline = Instant::now() + budget;
        let exited = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };

        let stderr = stderr_tail.map(join_stderr).unwrap_or_default();

        // A child that exited BEFORE the budget with a non-zero status did not
        // capture — it failed to open the device or the BPF. That is a SKIP
        // with its reason, NOT the honest zero an empty capture would be: on a
        // tunneled uplink the difference is the whole security question.
        if let Some(status) = exited
            && !status.success()
        {
            let reason = if stderr.is_empty() {
                format!("tcpdump exited with {status} before capturing")
            } else {
                format!("tcpdump failed: {stderr}")
            };
            tracing::warn!(iface = %self.iface, %reason, "egress capture: {reason}");
            return EgressCaptureOutcome::CouldNotStart(reason);
        }

        let frames = crate::pcap_savefile::read_pcap_frames(&out);
        if frames.is_empty() {
            // A real zero: the capture ran and this machine sent no IP packet on
            // `en0` in the window. Recorded as OK with dst_count 0, never SKIP.
            tracing::info!(iface = %self.iface,
                "egress capture: ran, no outgoing IP packets seen this run");
        } else {
            tracing::info!(iface = %self.iface, frames = frames.len(),
                "egress capture: received outgoing IP frames");
        }
        EgressCaptureOutcome::Ran(frames)
    }
}

/// Read the child's stderr to EOF on a background thread into a bounded buffer,
/// so the budget wait never blocks on a full pipe. The thread ends at EOF,
/// which the child's exit (natural or killed) guarantees.
fn drain_stderr(mut stderr: std::process::ChildStderr) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        // A capture's stderr is a short summary line; cap it so a pathological
        // child cannot balloon memory.
        const CAP: usize = 4096;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match stderr.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() < CAP {
                        buf.extend_from_slice(&chunk[..n.min(CAP - buf.len())]);
                    }
                }
            }
        }
        String::from_utf8_lossy(&buf).trim().replace('\n', " | ")
    })
}

/// Join the stderr-drain thread and return what it read (empty on a join
/// failure — the reason is best-effort).
fn join_stderr(handle: std::thread::JoinHandle<String>) -> String {
    handle.join().unwrap_or_default()
}
