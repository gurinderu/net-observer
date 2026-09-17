//! The capture behind the passive `announce` listener: a second `tcpdump`
//! child streaming what the segment announces (ARP, mDNS, SSDP, DHCP) as a
//! pcap stream on its stdout, decoded in-process by `collector-announce`
//! (realm net-observer, node #92).
//!
//! # Why a second child, not the ring
//! The incident ring (see [`crate::pcap`]) is shared with the shell-oracle
//! daemon, its filter carries no multicast, and its files are read only on a
//! freeze — it is the wrong shape for a listener that must decode frames as
//! they arrive. So the listener opens its own `tcpdump`, filtered to the
//! four announcement protocols, writing raw pcap to a pipe instead of a
//! file (`-w -`, packet-buffered with `-U` so each frame is flushed as it
//! is captured). Nothing here touches the ring. Whole frames are taken
//! (`-s 0`): an mDNS announcement regularly runs past 512 bytes, and a DNS
//! message cut short loses its tail records; the frames are decoded and
//! discarded, never stored, so the snaplen costs nothing on disk.
//!
//! # This is the privileged, un-verifiable edge
//! Reading raw Ethernet needs root and a BPF device, so — like the ring and
//! the LLDP capture — the LIVE behaviour of this adapter is a project
//! "Ceiling" claim (AGENTS.md, Reality). It is kept THIN: the whole decode
//! path lives in `collector-announce`, tested from in-memory streams, and
//! the only untested surface is the spawn-and-pipe glue below.
//!
//! # Honest degradation
//! No `tcpdump`, no root, no BPF → [`AnnounceCapture::start`] fails and the
//! daemon logs why and runs without the listener; the neighbour-cache
//! collector's per-tick rows still say who is on the segment. A child that
//! dies later ends the pcap stream, which the source brackets with a `SKIP`
//! row naming the end.

use std::io::{self, Read};
use std::process::{Child, ChildStdout, Command, Stdio};

use collector_announce::SegmentIdentity;

use crate::dhcp_arp::SystemFacts;

/// The BPF filter: exactly the four protocols the listener decodes. Both
/// DHCP ports, so a client's requests (to 67) and a server's replies (to 68)
/// are both heard.
pub const ANNOUNCE_FILTER: &str =
    "arp or udp port 5353 or udp port 1900 or udp port 67 or udp port 68";

/// A live `tcpdump` child streaming pcap on its stdout. Reading the capture
/// reads the child's stdout; dropping it kills the child.
#[derive(Debug)]
pub struct AnnounceCapture {
    child: Child,
    stdout: ChildStdout,
}

impl AnnounceCapture {
    /// Start `tcpdump` on `iface` with [`ANNOUNCE_FILTER`], pcap to stdout.
    ///
    /// # Errors
    /// `tcpdump` could not be spawned (not installed, or no privilege to
    /// open the BPF device), or its stdout could not be taken.
    pub fn start(iface: &str) -> io::Result<Self> {
        let mut cmd = Command::new("tcpdump");
        cmd.arg("-i")
            .arg(iface)
            .arg("-nn") // no name resolution: nothing of ours on the wire for a capture
            .arg("-s")
            .arg("0") // whole frames (see the module doc)
            .arg("-U") // packet-buffered: each frame reaches the pipe as it is captured
            .arg("-w")
            .arg("-"); // raw pcap to stdout
        for token in ANNOUNCE_FILTER.split_whitespace() {
            cmd.arg(token);
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("tcpdump child spawned without a stdout pipe"))?;
        tracing::info!(
            iface,
            filter = ANNOUNCE_FILTER,
            "started tcpdump announce listener"
        );
        Ok(Self { child, stdout })
    }
}

impl Read for AnnounceCapture {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl Drop for AnnounceCapture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The real [`SegmentIdentity`]: the gateway's MAC by the one derivation
/// every neighbour writer shares ([`SystemFacts::network_key`]).
///
/// That derivation is `async` (it shells out on the daemon's runtime) while
/// the listener asks from its own blocking thread, so the call is bridged
/// with the runtime handle captured at construction — `Handle::block_on`
/// from a thread the runtime does not own is exactly the supported use.
#[derive(Debug, Clone)]
pub struct SystemSegment {
    facts: SystemFacts,
    rt: tokio::runtime::Handle,
}

impl SystemSegment {
    /// Build from the same [`SystemFacts`] the link and neighbour collectors
    /// use (so a config override is honoured) and the runtime to run it on.
    #[must_use]
    pub fn new(facts: SystemFacts, rt: tokio::runtime::Handle) -> Self {
        Self { facts, rt }
    }
}

impl SegmentIdentity for SystemSegment {
    fn network_key(&self) -> Option<String> {
        self.rt.block_on(self.facts.network_key())
    }
}
