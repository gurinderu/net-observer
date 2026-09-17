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
//! # What `start` proves
//! A spawn that succeeds proves only that a `tcpdump` binary exists. The
//! failures that matter — no BPF device, no permission, an interface that
//! is not configured — exit the child at once with the reason on stderr.
//! So [`AnnounceCapture::start`] returns `Ok` only once the child has
//! written a pcap global header (which `-U` flushes at open, well before
//! the first frame) declaring an Ethernet link layer, and it waits for that
//! at most [`HEADER_WAIT`]; a child that exits first, or writes nothing in
//! time, or writes something that is not Ethernet pcap, is killed and the
//! error carries the child's own last words from stderr. That is what
//! separates an `Unavailable` listener from a running one at startup. A
//! child that dies later ends the stream the same way: its exit status and
//! stderr tail become the reason on the `SKIP` row that brackets the end.
//!
//! # This is the privileged, un-verifiable edge
//! Reading raw Ethernet needs root and a BPF device, so — like the ring and
//! the LLDP capture — the LIVE behaviour of this adapter is a project
//! "Ceiling" claim (AGENTS.md, Reality). It is kept THIN: the whole decode
//! path lives in `collector-announce`, tested from in-memory streams, and
//! the only untested surface is the spawn-and-pipe glue below.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use collector_announce::pcap::{GLOBAL_HEADER, LINKTYPE_ETHERNET, parse_global_header};
use collector_announce::{SegmentIdentity, SegmentIdentityReading, mac_octets};
use collector_link::LinkFacts;

use crate::dhcp_arp::SystemFacts;

/// The BPF filter: exactly the four protocols the listener decodes. Both
/// DHCP ports, so a client's requests (to 67) and a server's replies (to 68)
/// are both heard.
pub const ANNOUNCE_FILTER: &str =
    "arp or udp port 5353 or udp port 1900 or udp port 67 or udp port 68";

/// How long `start` waits for the child's pcap global header. `tcpdump -U`
/// writes it at open, before any frame, so a healthy child is well inside
/// this; a child that never writes one is not capturing.
pub const HEADER_WAIT: Duration = Duration::from_secs(2);

/// How much of the child's stderr is kept: its last words, which is where
/// `tcpdump` puts the reason it could not capture.
const STDERR_TAIL: usize = 512;

/// How long to wait for an exit status once the child has closed its output.
const EXIT_WAIT: Duration = Duration::from_secs(1);

/// A live `tcpdump` child streaming pcap on its stdout. Reading the capture
/// reads the child's stdout — the global header `start` already took first;
/// dropping it kills the child.
#[derive(Debug)]
pub struct AnnounceCapture {
    child: Child,
    stdout: ChildStdout,
    /// The global header `start` read to prove the capture runs, served to
    /// the reader ahead of the child's remaining output.
    header: [u8; GLOBAL_HEADER],
    served: usize,
    stderr_tail: Arc<Mutex<VecDeque<u8>>>,
}

impl AnnounceCapture {
    /// Start `tcpdump` on `iface` with [`ANNOUNCE_FILTER`], pcap to stdout,
    /// and return only once it has produced an Ethernet pcap header.
    ///
    /// # Errors
    /// `tcpdump` could not be spawned; it exited before writing a header (no
    /// BPF device, no permission, an interface that is not configured — the
    /// error carries its stderr); it wrote nothing within [`HEADER_WAIT`];
    /// or what it wrote is not classic Ethernet pcap.
    pub fn start(iface: &str) -> io::Result<Self> {
        let mut cmd = Command::new("tcpdump");
        cmd.arg("-i")
            .arg(iface)
            .arg("-nn") // never resolve names: a capture must put nothing on the wire
            .arg("-s")
            .arg("0") // whole frames (see the module doc)
            .arg("-U") // packet-buffered: header at open, each frame as it is captured
            .arg("-w")
            .arg("-"); // raw pcap to stdout
        for token in ANNOUNCE_FILTER.split_whitespace() {
            cmd.arg(token);
        }
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (Some(mut stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("tcpdump child spawned without its pipes"));
        };
        let stderr_tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
        drain_stderr(stderr, Arc::clone(&stderr_tail));

        // The header, on a thread so the wait is bounded; the thread hands
        // stdout back with it.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut header = [0u8; GLOBAL_HEADER];
            let read = stdout.read_exact(&mut header);
            let _ = tx.send((read.map(|()| header), stdout));
        });
        let (header, stdout) = match rx.recv_timeout(HEADER_WAIT) {
            Ok((Ok(header), stdout)) => (header, stdout),
            Ok((Err(_), _)) => {
                let exit = exit_words(&mut child, &stderr_tail);
                return Err(io::Error::other(format!(
                    "tcpdump wrote no pcap header; {exit}"
                )));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "tcpdump wrote no pcap header within {HEADER_WAIT:?}: {}",
                        last_words(&stderr_tail)
                    ),
                ));
            }
        };
        let link_type = match parse_global_header(&header) {
            Ok(h) => h.link_type,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        if link_type != LINKTYPE_ETHERNET {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("tcpdump capture on {iface} has link type {link_type}, not Ethernet (1)"),
            ));
        }
        tracing::info!(
            iface,
            filter = ANNOUNCE_FILTER,
            "started tcpdump announce listener (pcap header received)"
        );
        Ok(Self {
            child,
            stdout,
            header,
            served: 0,
            stderr_tail,
        })
    }
}

impl Read for AnnounceCapture {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.served < GLOBAL_HEADER {
            let n = buf.len().min(GLOBAL_HEADER - self.served);
            buf[..n].copy_from_slice(&self.header[self.served..self.served + n]);
            self.served += n;
            return Ok(n);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let n = self.stdout.read(buf)?;
        if n == 0 {
            // The child closed its output: say why, in its own words, rather
            // than a bare end of file.
            let exit = exit_words(&mut self.child, &self.stderr_tail);
            return Err(io::Error::other(format!("tcpdump {exit}")));
        }
        Ok(n)
    }
}

impl Drop for AnnounceCapture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Keep the last [`STDERR_TAIL`] bytes the child writes to stderr, on a
/// thread that ends when the child closes it.
fn drain_stderr(mut stderr: ChildStderr, tail: Arc<Mutex<VecDeque<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 256];
        loop {
            let n = match stderr.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            let mut tail = tail.lock().unwrap_or_else(|e| e.into_inner());
            tail.extend(buf[..n].iter().copied());
            while tail.len() > STDERR_TAIL {
                tail.pop_front();
            }
        }
    });
}

/// The child's stderr tail as text, or a note that it said nothing.
fn last_words(tail: &Arc<Mutex<VecDeque<u8>>>) -> String {
    let tail = tail.lock().unwrap_or_else(|e| e.into_inner());
    let (a, b) = tail.as_slices();
    let mut bytes = Vec::with_capacity(a.len() + b.len());
    bytes.extend_from_slice(a);
    bytes.extend_from_slice(b);
    let text = String::from_utf8_lossy(&bytes);
    let text = text.trim();
    if text.is_empty() {
        "(no stderr)".to_string()
    } else {
        text.replace('\n', " | ")
    }
}

/// How the child ended, with its last words: its exit status when it has
/// exited within [`EXIT_WAIT`], else the fact that it closed its output but
/// still runs — after which it is killed either way.
fn exit_words(child: &mut Child, tail: &Arc<Mutex<VecDeque<u8>>>) -> String {
    let deadline = std::time::Instant::now() + EXIT_WAIT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Ok(None) | Err(_) => break None,
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    match status {
        Some(status) => format!("exited ({status}): {}", last_words(tail)),
        None => format!("closed its output but kept running: {}", last_words(tail)),
    }
}

/// The real [`SegmentIdentity`]: the gateway's MAC by the one derivation
/// every neighbour writer shares ([`SystemFacts::network_key`]), and the
/// interface's own MAC as the link collector reads it ([`LinkFacts::if_mac`])
/// — both read afresh for every window, since a Private Wi-Fi Address
/// rotates the latter per network.
///
/// Those reads are `async` (they shell out on the daemon's runtime) while
/// the listener asks from its own blocking thread, so the call is bridged
/// with the runtime handle captured at construction — `Handle::block_on`
/// from a thread the runtime does not own is exactly the supported use.
#[derive(Debug, Clone)]
pub struct SystemSegment {
    facts: SystemFacts,
    iface: String,
    rt: tokio::runtime::Handle,
}

impl SystemSegment {
    /// Build from the same [`SystemFacts`] the link and neighbour collectors
    /// use (so a config override is honoured), the interface the capture
    /// listens on, and the runtime to run the reads on.
    #[must_use]
    pub fn new(facts: SystemFacts, iface: String, rt: tokio::runtime::Handle) -> Self {
        Self { facts, iface, rt }
    }
}

impl SegmentIdentity for SystemSegment {
    fn identity(&self) -> SegmentIdentityReading {
        self.rt.block_on(async {
            SegmentIdentityReading {
                network_key: self.facts.network_key().await,
                own_mac: self
                    .facts
                    .if_mac(&self.iface)
                    .await
                    .as_deref()
                    .and_then(mac_octets),
            }
        })
    }
}
