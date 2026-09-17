//! The blocking [`EventSource`] that turns a pcap stream into flushed
//! [`types::NeighborsSample`]s.
//!
//! Two threads meet here. A reader thread walks the pcap stream with
//! `read_exact` — the only honest way to wait on a pipe — and hands each
//! frame over a bounded channel. The daemon's own event thread calls
//! [`EventSource::next`], which opens a [`Window`], drains that channel until
//! the flush deadline, and returns the window as one sample. The channel is
//! what makes a wall-clock flush possible at all: a thread parked in
//! `read_exact` on a silent segment cannot be woken by a timer, but
//! `recv_timeout` can — so a silent 15 s still produces its reading ("the
//! segment said nothing"), and the frame counts still land.
//!
//! Each window opens with ONE [`SegmentIdentity`] read: the segment's key and
//! the interface's own MAC as they are at that moment. The own MAC is what
//! the window recognises this machine's own filter-matching traffic by (the
//! OS's ARP, mDNS, SSDP and DHCP — never the daemon's probes, which do not
//! pass the filter), counts and drops; it is re-read per window because a
//! Private Wi-Fi Address rotates it per network.
//!
//! When the stream ends — `tcpdump` exited, the pipe broke, the bytes
//! stopped being pcap — the final batch carries what the last window heard
//! and then a `SKIP` sample whose `reason` says why the listener stopped,
//! so the record shows the bracket rather than a silence; after that
//! `next()` is `None` and the daemon logs "event source ended".

use std::io::Read;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::time::{Duration, Instant};

use collector_core::EventSource;
use types::{HeardFrames, NeighborsSample, NeighborsVerdict, Sample};

use crate::frame::Mac;
use crate::pcap::PcapStream;
use crate::window::Window;

/// How often the listener flushes a window: the link tick, so a flush can be
/// set beside a link sample by `ASOF JOIN` and the frame counts read at the
/// same resolution as the probes. Wall time, not a frame count — a frame
/// count never fires on a silent segment, and silence is exactly a reading
/// this listener must not skip.
pub const FLUSH_EVERY: Duration = Duration::from_secs(15);

/// Frames the reader thread may run ahead of a flush. When full the reader
/// blocks and the pipe backs up into `tcpdump`'s and the kernel's own
/// capture buffers: the daemon itself buffers nothing past this, and a
/// segment chatty enough to overrun it loses frames at the capture, where
/// `tcpdump` counts them, never in a growing queue here.
const FRAME_QUEUE: usize = 4096;

/// What one window is read against: the segment it was heard on and the
/// MAC that was this machine's own at the time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SegmentIdentityReading {
    /// The gateway's MAC, normalised lowercase — the `network_key` the
    /// neighbour-cache collector writes under; `None` when it cannot be read.
    pub network_key: Option<String>,
    /// The interface's own MAC; `None` when it cannot be read, in which case
    /// the window drops nothing as ours and its flush says so.
    pub own_mac: Option<Mac>,
}

/// The segment's identity, read ONCE at the start of every window — so a
/// window that straddles a network change is keyed by the segment it was
/// actually heard on, and so the own MAC follows a Private Wi-Fi Address
/// that rotates per network rather than being the boot-time value for the
/// life of the process. The real implementation reads the default gateway's
/// ARP entry and the interface's `ether` line.
pub trait SegmentIdentity: Send {
    /// Both facts, as readable now.
    fn identity(&self) -> SegmentIdentityReading;
}

enum Feed {
    Frame(Vec<u8>),
    /// The stream ended, with why.
    End(String),
}

/// A pcap stream of announcements, flushed as neighbour samples.
pub struct AnnounceSource<R, S> {
    /// Taken by the reader thread on the first `next()`.
    reader: Option<R>,
    rx: Option<Receiver<Feed>>,
    iface: Option<String>,
    identity: S,
    flush_every: Duration,
    /// Set once the final batch has been returned.
    done: bool,
}

impl<R: Read + Send + 'static, S: SegmentIdentity> AnnounceSource<R, S> {
    /// A source over `reader` (a pcap stream: the capture child's stdout) on
    /// `iface`, reading each window's segment key and own MAC from `identity`
    /// as the window opens. Nothing is read until the first
    /// [`EventSource::next`].
    pub fn new(reader: R, iface: Option<String>, identity: S, flush_every: Duration) -> Self {
        Self {
            reader: Some(reader),
            rx: None,
            iface,
            identity,
            flush_every,
            done: false,
        }
    }

    /// Spawn the reader thread on first use; `Err` names why it could not be.
    fn feed(&mut self) -> Result<&Receiver<Feed>, String> {
        if self.rx.is_none() {
            let reader = self
                .reader
                .take()
                .ok_or_else(|| "reader already taken".to_string())?;
            let (tx, rx) = mpsc::sync_channel(FRAME_QUEUE);
            std::thread::Builder::new()
                .name("announce-pcap".into())
                .spawn(move || read_stream(reader, &tx))
                .map_err(|e| format!("could not start the capture reader thread: {e}"))?;
            self.rx = Some(rx);
        }
        Ok(self.rx.as_ref().expect("set just above"))
    }
}

/// The reader thread: every record to the channel, then how the stream ended.
fn read_stream<R: Read>(reader: R, tx: &SyncSender<Feed>) {
    let mut stream = PcapStream::new(reader);
    loop {
        match stream.next_record() {
            Ok(Some(rec)) => {
                if tx.send(Feed::Frame(rec.data)).is_err() {
                    return; // the source is gone
                }
            }
            Ok(None) => {
                let _ = tx.send(Feed::End("capture stream ended".into()));
                return;
            }
            Err(e) => {
                let _ = tx.send(Feed::End(format!("capture stream: {e}")));
                return;
            }
        }
    }
}

/// The `SKIP` row that brackets the listener's end. Not an observation — it
/// counts no frames and drops none — but the bracket the record needs even
/// through an operator pause, which is why the daemon lets it through the
/// pause drop (see `NeighborsSample::is_listener_bracket`).
fn stopped(
    ts_us: i64,
    network_key: Option<String>,
    iface: Option<String>,
    reason: String,
) -> Sample {
    Sample::Neighbors(NeighborsSample {
        ts_us,
        verdict: NeighborsVerdict::Skip,
        reason: Some(format!("announce listener stopped: {reason}")),
        network_key,
        iface,
        neighbors: Vec::new(),
        services: Vec::new(),
        heard: Some(HeardFrames {
            total: 0,
            own: Some(0),
        }),
    })
}

impl<R: Read + Send + 'static, S: SegmentIdentity> EventSource for AnnounceSource<R, S> {
    fn next(&mut self) -> Option<Vec<Sample>> {
        if self.done {
            return None;
        }
        let SegmentIdentityReading {
            network_key,
            own_mac,
        } = self.identity.identity();
        let iface = self.iface.clone();
        let flush_every = self.flush_every;
        let rx = match self.feed() {
            Ok(rx) => rx,
            Err(reason) => {
                self.done = true;
                return Some(vec![stopped(types::now_us(), network_key, iface, reason)]);
            }
        };

        let mut window = Window::new(own_mac, network_key.clone(), iface.clone());
        let deadline = Instant::now() + flush_every;
        let mut ended: Option<String> = None;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            match rx.recv_timeout(deadline - now) {
                Ok(Feed::Frame(bytes)) => window.absorb(&bytes),
                Ok(Feed::End(reason)) => {
                    ended = Some(reason);
                    break;
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    ended = Some("capture reader thread gone".into());
                    break;
                }
            }
        }

        let ts_us = types::now_us();
        let mut out = Vec::with_capacity(2);
        // A full window is a reading even when empty; a window cut short by
        // the end of the stream is one only if it heard something.
        if ended.is_none() || !window.is_empty() {
            let heard = window.heard();
            let undecoded = window.undecoded();
            let dropped = window.dropped();
            let sample = window.flush(ts_us);
            tracing::debug!(
                heard = heard.total,
                own = ?heard.own,
                undecoded,
                dropped,
                neighbours = sample.neighbors.len(),
                services = sample.services.len(),
                "announce: window flushed"
            );
            out.push(Sample::Neighbors(sample));
        }
        if let Some(reason) = ended {
            tracing::warn!(%reason, "announce: listener stopped");
            self.done = true;
            out.push(stopped(ts_us, network_key, iface, reason));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::mac_text;
    use crate::frame::tests::{GATEWAY, OWN, PEER, arp, udp4};
    use crate::mdns::tests::owner_announcement;
    use crate::pcap::tests::{MAGIC_LE_US, savefile};
    use std::io::Cursor;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// An identity that answers the same every window.
    struct Fixed(Option<&'static str>, Option<Mac>);
    impl SegmentIdentity for Fixed {
        fn identity(&self) -> SegmentIdentityReading {
            SegmentIdentityReading {
                network_key: self.0.map(str::to_string),
                own_mac: self.1,
            }
        }
    }

    /// An identity that hands out a different own MAC on every read — a
    /// Private Wi-Fi Address rotating between windows.
    struct Rotating(Mutex<std::vec::IntoIter<Option<Mac>>>);
    impl SegmentIdentity for Rotating {
        fn identity(&self) -> SegmentIdentityReading {
            SegmentIdentityReading {
                network_key: None,
                own_mac: self.0.lock().unwrap().next().flatten(),
            }
        }
    }

    /// A slow pipe: hands out its bytes, then blocks for `hold` before EOF —
    /// long enough for a flush deadline to pass with the stream still open.
    struct SlowEof {
        bytes: Cursor<Vec<u8>>,
        hold: Duration,
        held: bool,
    }
    impl Read for SlowEof {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.bytes.read(buf)?;
            if n == 0 && !self.held {
                self.held = true;
                std::thread::sleep(self.hold);
            }
            Ok(n)
        }
    }

    /// A pipe that releases its records one batch at a time, when told.
    struct Gated {
        batches: std::sync::mpsc::Receiver<Vec<u8>>,
        pending: Cursor<Vec<u8>>,
    }
    impl Read for Gated {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            loop {
                let n = self.pending.read(buf)?;
                if n > 0 {
                    return Ok(n);
                }
                match self.batches.recv() {
                    Ok(bytes) => self.pending = Cursor::new(bytes),
                    Err(_) => return Ok(0),
                }
            }
        }
    }

    fn frames() -> Vec<u8> {
        // The gateway asking for a host: its own request, which pairs it.
        let gw = arp(
            GATEWAY,
            GATEWAY,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 5),
            false,
        );
        let peer_ip = Ipv4Addr::new(192, 168, 1, 6);
        let peer = udp4(
            PEER,
            peer_ip,
            Ipv4Addr::new(224, 0, 0, 251),
            5353,
            5353,
            &owner_announcement(peer_ip),
        );
        let own = arp(
            OWN,
            OWN,
            Ipv4Addr::new(192, 168, 1, 5),
            Ipv4Addr::new(192, 168, 1, 1),
            false,
        );
        savefile(MAGIC_LE_US, &[(1, 0, &gw), (1, 1, &peer), (1, 2, &own)])
    }

    /// A stream that ends: one batch with the window heard and the SKIP that
    /// brackets the end, then `None`.
    #[test]
    fn a_finished_stream_flushes_once_then_brackets_its_end() {
        let mut src = AnnounceSource::new(
            Cursor::new(frames()),
            Some("en0".into()),
            Fixed(Some("60:22:32:aa:25:21"), Some(OWN)),
            Duration::from_secs(5),
        );
        let batch = src.next().expect("a batch");
        assert_eq!(batch.len(), 2, "{batch:?}");
        let Sample::Neighbors(flush) = &batch[0] else {
            panic!("expected a neighbours flush")
        };
        assert_eq!(flush.verdict, NeighborsVerdict::Ok);
        assert_eq!(
            flush.heard,
            Some(HeardFrames {
                total: 3,
                own: Some(1)
            })
        );
        assert_eq!(flush.network_key.as_deref(), Some("60:22:32:aa:25:21"));
        assert_eq!(flush.neighbors.len(), 2);
        assert!(flush.neighbors.iter().any(|n| n.mac == mac_text(&PEER)));
        assert_eq!(flush.services.len(), 3);
        let Sample::Neighbors(stop) = &batch[1] else {
            panic!("expected the stop bracket")
        };
        assert_eq!(stop.verdict, NeighborsVerdict::Skip);
        assert!(
            stop.reason
                .as_deref()
                .unwrap()
                .contains("capture stream ended"),
            "{:?}",
            stop.reason
        );
        assert!(stop.is_listener_flush());
        assert!(stop.is_listener_bracket());
        assert!(!flush.is_listener_bracket());
        assert!(src.next().is_none());
        assert!(src.next().is_none());
    }

    /// The wall-clock flush: a stream still open at the deadline yields the
    /// window so far, and the next window picks up where it left off.
    #[test]
    fn a_stream_still_open_at_the_deadline_flushes_what_it_heard() {
        let reader = SlowEof {
            bytes: Cursor::new(frames()),
            hold: Duration::from_millis(350),
            held: false,
        };
        let mut src = AnnounceSource::new(
            reader,
            None,
            Fixed(None, Some(OWN)),
            Duration::from_millis(150),
        );
        let first = src.next().expect("first window");
        assert_eq!(
            first.len(),
            1,
            "no bracket while the stream is open: {first:?}"
        );
        let Sample::Neighbors(s) = &first[0] else {
            panic!()
        };
        assert_eq!(s.heard.map(|h| h.total), Some(3));
        assert_eq!(s.network_key, None);
        // Second window: nothing new arrives before the deadline — a silent
        // reading, still not the end.
        let second = src.next().expect("second window");
        assert_eq!(second.len(), 1);
        let Sample::Neighbors(s) = &second[0] else {
            panic!()
        };
        assert_eq!(
            s.heard,
            Some(HeardFrames {
                total: 0,
                own: Some(0)
            })
        );
        assert_eq!(s.verdict, NeighborsVerdict::Ok);
        // Then the EOF lands: an empty cut-short window yields only the bracket.
        let last = src.next().expect("the end");
        assert_eq!(last.len(), 1, "{last:?}");
        let Sample::Neighbors(s) = &last[0] else {
            panic!()
        };
        assert_eq!(s.verdict, NeighborsVerdict::Skip);
        assert!(src.next().is_none());
    }

    /// The own MAC is read as each window opens: the same frames, heard in
    /// two windows under two own MACs, are dropped as ours by whichever MAC
    /// was ours at the time — and a window with no readable MAC drops
    /// nothing and says so.
    #[test]
    fn each_window_drops_its_own_frames_by_the_mac_read_as_it_opens() {
        let (batch_tx, batches) = std::sync::mpsc::channel::<Vec<u8>>();
        let reader = Gated {
            batches,
            pending: Cursor::new(Vec::new()),
        };
        let identity = Rotating(Mutex::new(vec![Some(OWN), Some(PEER), None].into_iter()));
        let mut src = AnnounceSource::new(reader, None, identity, Duration::from_millis(150));

        // Window 1: OWN is ours.
        batch_tx.send(frames()).unwrap();
        let w1 = src.next().expect("window 1");
        let Sample::Neighbors(s) = &w1[0] else {
            panic!()
        };
        assert_eq!(
            s.heard,
            Some(HeardFrames {
                total: 3,
                own: Some(1)
            })
        );
        assert!(s.neighbors.iter().all(|n| n.mac != mac_text(&OWN)));
        assert!(s.neighbors.iter().any(|n| n.mac == mac_text(&PEER)));

        // Window 2: the same frames again (records only — the stream's header
        // was consumed by window 1), now PEER is ours.
        batch_tx.send(frames()[24..].to_vec()).unwrap();
        let w2 = src.next().expect("window 2");
        let Sample::Neighbors(s) = &w2[0] else {
            panic!()
        };
        assert_eq!(
            s.heard,
            Some(HeardFrames {
                total: 3,
                own: Some(1)
            })
        );
        assert!(s.neighbors.iter().all(|n| n.mac != mac_text(&PEER)));
        assert!(s.neighbors.iter().any(|n| n.mac == mac_text(&OWN)));

        // Window 3: no own MAC readable — nothing dropped, and it says so.
        batch_tx.send(frames()[24..].to_vec()).unwrap();
        let w3 = src.next().expect("window 3");
        let Sample::Neighbors(s) = &w3[0] else {
            panic!()
        };
        assert_eq!(
            s.heard,
            Some(HeardFrames {
                total: 3,
                own: None
            })
        );
        assert_eq!(s.neighbors.len(), 3);
        drop(batch_tx);
    }

    /// Bytes that are not pcap end the listener with a reason naming that.
    #[test]
    fn a_stream_that_is_not_pcap_stops_with_the_reason() {
        let mut src = AnnounceSource::new(
            Cursor::new(b"not a pcap stream at all, just text".to_vec()),
            None,
            Fixed(None, None),
            Duration::from_secs(5),
        );
        let batch = src.next().unwrap();
        assert_eq!(batch.len(), 1);
        let Sample::Neighbors(s) = &batch[0] else {
            panic!()
        };
        assert_eq!(s.verdict, NeighborsVerdict::Skip);
        assert!(
            s.reason
                .as_deref()
                .unwrap()
                .contains("not a classic pcap stream"),
            "{:?}",
            s.reason
        );
        assert!(src.next().is_none());
    }
}
