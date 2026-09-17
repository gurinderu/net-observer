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
//! at most [`HEADER_WAIT`] — generous, because a LaunchDaemon started at
//! boot may find the system slow; a child that exits first, or writes
//! nothing in time, or writes something that is not Ethernet pcap, is
//! killed and the error carries the child's own last words from stderr,
//! read only after the child is reaped and its stderr drained to the end.
//! That is what separates an `Unavailable` listener from a running one at
//! startup. A child that dies later ends the stream the same way: its exit
//! status and stderr tail become the reason on the `SKIP` row that
//! brackets the end.
//!
//! # The seam
//! [`AnnounceCapture::start`] only builds the `tcpdump` command line;
//! [`AnnounceCapture::start_with`] does everything else over any
//! [`Command`], which is how the tests below drive the whole
//! spawn-header-stderr-exit path with `sh -c` stand-ins and no BPF at all.
//! Those tests run on the Mac gate (`cargo test -p macos`); on Linux this
//! crate only type-checks. What stays untestable is the one line the seam
//! excludes — that the real `tcpdump` invocation captures on a real
//! interface — a project "Ceiling" claim (AGENTS.md, Reality), like the ring
//! and the LLDP capture.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use collector_announce::pcap::{GLOBAL_HEADER, LINKTYPE_ETHERNET, parse_global_header};
use collector_announce::{SegmentIdentity, SegmentIdentityReading, is_unicast, mac_octets};
use collector_link::LinkFacts;

use crate::dhcp_arp::SystemFacts;

/// The BPF filter: exactly the four protocols the listener decodes. Both
/// DHCP ports, so a client's requests (to 67) and a server's replies (to 68)
/// are both heard.
pub const ANNOUNCE_FILTER: &str =
    "arp or udp port 5353 or udp port 1900 or udp port 67 or udp port 68";

/// How long `start` waits for the child's pcap global header. `tcpdump -U`
/// writes it at open, before any frame, so a healthy child is well inside
/// this even on a slow boot; a child that never writes one is not capturing.
pub const HEADER_WAIT: Duration = Duration::from_secs(5);

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
    stderr: StderrTail,
}

/// The child's stderr, drained on a thread into a bounded tail. The thread
/// ends at EOF, which the child's exit guarantees (`tcpdump` does not fork);
/// [`StderrTail::words`] joins it first, so what it reads is the whole of
/// what the child said.
#[derive(Debug)]
struct StderrTail {
    tail: Arc<Mutex<VecDeque<u8>>>,
    drain: Option<JoinHandle<()>>,
}

impl StderrTail {
    fn drain(mut stderr: ChildStderr) -> Self {
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL)));
        let sink = Arc::clone(&tail);
        let drain = std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            loop {
                let n = match stderr.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let mut tail = sink.lock().unwrap_or_else(|e| e.into_inner());
                tail.extend(buf[..n].iter().copied());
                while tail.len() > STDERR_TAIL {
                    tail.pop_front();
                }
            }
        });
        Self {
            tail,
            drain: Some(drain),
        }
    }

    /// The child's last words, complete: call only once the child has been
    /// reaped, so the drain thread has seen EOF and is joined here.
    fn words(&mut self) -> String {
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
        let tail = self.tail.lock().unwrap_or_else(|e| e.into_inner());
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
}

impl AnnounceCapture {
    /// Start `tcpdump` on `iface` with [`ANNOUNCE_FILTER`], pcap to stdout,
    /// and return only once it has produced an Ethernet pcap header.
    ///
    /// # Errors
    /// See [`AnnounceCapture::start_with`].
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
        let capture = Self::start_with(cmd, iface)?;
        tracing::info!(
            iface,
            filter = ANNOUNCE_FILTER,
            "started tcpdump announce listener (pcap header received)"
        );
        Ok(capture)
    }

    /// Spawn `cmd` (any program writing pcap to its stdout; `iface` names the
    /// interface in messages) and return only once it has written a pcap
    /// global header declaring an Ethernet link layer.
    ///
    /// # Errors
    /// The program could not be spawned; it exited before writing a header
    /// (the error carries its exit status and its stderr); it wrote nothing
    /// within [`HEADER_WAIT`] (`TimedOut`, with whatever it said); or what it
    /// wrote is not classic Ethernet pcap (`InvalidData`, naming the link
    /// type). In every error case the child is killed and reaped.
    pub fn start_with(mut cmd: Command, iface: &str) -> io::Result<Self> {
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let (Some(mut stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("capture child spawned without its pipes"));
        };
        let mut stderr = StderrTail::drain(stderr);

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
                let exit = exit_words(&mut child, &mut stderr);
                return Err(io::Error::other(format!(
                    "capture on {iface} wrote no pcap header; {exit}"
                )));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "capture on {iface} wrote no pcap header within {HEADER_WAIT:?}: {}",
                        stderr.words()
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
                format!("capture on {iface} has link type {link_type}, not Ethernet (1)"),
            ));
        }
        Ok(Self {
            child,
            stdout,
            header,
            served: 0,
            stderr,
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
            let exit = exit_words(&mut self.child, &mut self.stderr);
            return Err(io::Error::other(format!("capture child {exit}")));
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

/// How the child ended, with its last words: its exit status when it has
/// exited within [`EXIT_WAIT`], else the fact that it closed its output but
/// still runs — after which it is killed either way, and its stderr read
/// only once it is reaped, so the words are complete.
fn exit_words(child: &mut Child, stderr: &mut StderrTail) -> String {
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
        Some(status) => format!("exited ({status}): {}", stderr.words()),
        None => format!("closed its output but kept running: {}", stderr.words()),
    }
}

/// The real [`SegmentIdentity`]: the gateway's MAC by the one derivation
/// every neighbour writer shares ([`SystemFacts::network_key`]), and the
/// interface's own MAC as the link collector reads it ([`LinkFacts::if_mac`])
/// — both read afresh for every window, since a Private Wi-Fi Address
/// rotates the latter per network. An `ether` line that is not a unicast
/// device address (all zeros on an interface without one) is `None`: the
/// window then drops nothing as ours and says so.
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
                    .and_then(mac_octets)
                    .filter(is_unicast),
            }
        })
    }
}

/// These tests drive the whole start path with `sh -c` stand-ins for
/// `tcpdump`; they run on the Mac gate, where this crate's tests run at all.
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A 24-byte classic pcap global header (little-endian, microsecond
    /// timestamps, version 2.4, snaplen 262144, link type 1) as a POSIX
    /// `printf` argument in octal escapes, so `sh -c` can emit it.
    const HEADER_PRINTF: &str = "\\324\\303\\262\\241\\002\\000\\004\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\004\\000\\001\\000\\000\\000";

    fn sh(script: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script);
        cmd
    }

    #[test]
    fn a_child_that_exits_before_the_header_fails_with_its_words() {
        let err = AnnounceCapture::start_with(
            sh("echo 'tcpdump: (cannot open BPF device) /dev/bpf0: Permission denied' >&2; exit 1"),
            "en0",
        )
        .expect_err("no header, no capture");
        let text = err.to_string();
        assert!(text.contains("exited (exit status: 1)"), "{text}");
        assert!(text.contains("Permission denied"), "{text}");
        assert!(text.contains("en0"), "{text}");
    }

    #[test]
    fn a_header_then_exit_starts_and_then_reads_the_exit_as_an_error() {
        let script = format!("printf '{HEADER_PRINTF}'; echo 'done capturing' >&2; exit 3");
        let mut capture =
            AnnounceCapture::start_with(sh(&script), "en0").expect("a header is a start");
        // The header comes back first, byte for byte.
        let mut header = [0u8; GLOBAL_HEADER];
        capture.read_exact(&mut header).unwrap();
        assert_eq!(
            parse_global_header(&header).unwrap().link_type,
            LINKTYPE_ETHERNET
        );
        // Then the child's end, in its own words rather than a bare EOF.
        let mut rest = [0u8; 16];
        let err = capture.read(&mut rest).expect_err("the child exited");
        let text = err.to_string();
        assert!(text.contains("exited (exit status: 3)"), "{text}");
        assert!(text.contains("done capturing"), "{text}");
    }

    #[test]
    fn a_stream_that_is_not_classic_pcap_is_invalid_data() {
        let err = AnnounceCapture::start_with(
            sh("printf '\\012\\015\\015\\012\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000\\000'; exec sleep 5"),
            "en0",
        )
        .expect_err("pcapng is not a stream this listener reads");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    #[test]
    fn a_non_ethernet_link_type_is_invalid_data_naming_it() {
        // Same header with link type 12 (raw IP) instead of 1.
        let header = HEADER_PRINTF.replace(
            "\\004\\000\\001\\000\\000\\000",
            "\\004\\000\\014\\000\\000\\000",
        );
        let err =
            AnnounceCapture::start_with(sh(&format!("printf '{header}'; exec sleep 5")), "en0")
                .expect_err("raw IP is not Ethernet");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("link type 12"), "{err}");
    }

    #[test]
    fn a_child_that_never_writes_a_header_times_out_within_the_wait() {
        let started = Instant::now();
        let err = AnnounceCapture::start_with(sh("echo 'listening...' >&2; exec sleep 30"), "en0")
            .expect_err("no header in time");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
        assert!(err.to_string().contains("listening..."), "{err}");
        assert!(
            started.elapsed() < HEADER_WAIT + Duration::from_secs(2),
            "the wait is bounded: {:?}",
            started.elapsed()
        );
    }
}
