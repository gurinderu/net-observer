//! A streaming reader for the classic libpcap savefile format — what
//! `tcpdump -w -` writes to its stdout.
//!
//! The format is a 24-byte global header whose 4-byte magic selects the byte
//! order (and whether timestamps carry microseconds or nanoseconds), followed
//! by records of a 16-byte header (`ts_sec`, `ts_frac`, `incl_len`,
//! `orig_len`) and `incl_len` captured bytes. Nothing else is needed to walk
//! it, and `Read::read_exact` is exactly the blocking discipline a pipe wants:
//! each call waits for precisely one record, never reads ahead, never spins.
//!
//! The reader is generic over any [`Read`] so the whole decode path is
//! exercised in tests from an in-memory buffer; on the daemon it wraps the
//! `tcpdump` child's stdout (realm net-observer, node #92).

use std::io::{self, Read};

/// Bytes of the global header.
const GLOBAL_HEADER: usize = 24;
/// Bytes of each record header.
const RECORD_HEADER: usize = 16;
/// The largest `incl_len` accepted. A classic savefile's snaplen field caps it
/// at 262144 in practice; anything past this is a corrupt stream, and a bogus
/// length must not become a giant allocation.
const MAX_INCL_LEN: usize = 1 << 20;

/// One captured frame: the link-layer bytes as the capture delivered them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Capture timestamp, epoch microseconds (nanosecond savefiles are folded
    /// to microseconds, the record's own resolution).
    pub ts_us: i64,
    /// The captured bytes, starting at the Ethernet destination MAC.
    pub data: Vec<u8>,
}

/// A stream of pcap records over a blocking reader.
pub struct PcapStream<R: Read> {
    reader: R,
    /// `None` until the global header has been read.
    layout: Option<Layout>,
}

#[derive(Debug, Clone, Copy)]
struct Layout {
    little_endian: bool,
    nanos: bool,
}

impl Layout {
    fn u32(self, b: [u8; 4]) -> u32 {
        if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    }
}

impl<R: Read> PcapStream<R> {
    /// Wrap `reader`. Nothing is read until the first [`PcapStream::next_record`].
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            layout: None,
        }
    }

    /// The next captured frame, `Ok(None)` at a clean end of stream.
    ///
    /// A stream that ends mid-record (a `tcpdump` killed mid-write) is reported
    /// as `UnexpectedEof`, like a stream that ends before its global header;
    /// the caller treats both as "the capture is gone".
    pub fn next_record(&mut self) -> io::Result<Option<Record>> {
        let layout = match self.layout {
            Some(l) => l,
            None => {
                let l = self.read_global_header()?;
                self.layout = Some(l);
                l
            }
        };
        let mut header = [0u8; RECORD_HEADER];
        match self.reader.read_exact(&mut header) {
            Ok(()) => {}
            // Ending exactly on a record boundary is the clean end.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let word =
            |at: usize| layout.u32([header[at], header[at + 1], header[at + 2], header[at + 3]]);
        let ts_sec = i64::from(word(0));
        let ts_frac = i64::from(word(4));
        let incl_len = word(8) as usize;
        if incl_len > MAX_INCL_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("pcap record claims {incl_len} bytes, more than a capture can hold"),
            ));
        }
        let mut data = vec![0u8; incl_len];
        self.reader.read_exact(&mut data)?;
        let ts_us = ts_sec * 1_000_000
            + if layout.nanos {
                ts_frac / 1000
            } else {
                ts_frac
            };
        Ok(Some(Record { ts_us, data }))
    }

    fn read_global_header(&mut self) -> io::Result<Layout> {
        let mut header = [0u8; GLOBAL_HEADER];
        self.reader.read_exact(&mut header)?;
        let layout = match [header[0], header[1], header[2], header[3]] {
            [0xa1, 0xb2, 0xc3, 0xd4] => Layout {
                little_endian: false,
                nanos: false,
            },
            [0xd4, 0xc3, 0xb2, 0xa1] => Layout {
                little_endian: true,
                nanos: false,
            },
            [0xa1, 0xb2, 0x3c, 0x4d] => Layout {
                little_endian: false,
                nanos: true,
            },
            [0x4d, 0x3c, 0xb2, 0xa1] => Layout {
                little_endian: true,
                nanos: true,
            },
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("not a classic pcap stream (magic {other:02x?})"),
                ));
            }
        };
        Ok(layout)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    /// Build a classic savefile from the fields: `magic` selects the layout,
    /// each record is `(ts_sec, ts_frac, bytes)`.
    pub(crate) fn savefile(magic: [u8; 4], records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let little = magic[0] == 0xd4 || magic[0] == 0x4d;
        let put = |out: &mut Vec<u8>, v: u32| {
            if little {
                out.extend_from_slice(&v.to_le_bytes());
            } else {
                out.extend_from_slice(&v.to_be_bytes());
            }
        };
        let mut out = Vec::new();
        out.extend_from_slice(&magic);
        put(&mut out, 2 << 16); // version 2.4 (major, minor as two u16 words)
        put(&mut out, 0); // thiszone
        put(&mut out, 0); // sigfigs
        put(&mut out, 262_144); // snaplen
        put(&mut out, 1); // link type: Ethernet
        for (sec, frac, bytes) in records {
            put(&mut out, *sec);
            put(&mut out, *frac);
            put(&mut out, bytes.len() as u32);
            put(&mut out, bytes.len() as u32);
            out.extend_from_slice(bytes);
        }
        out
    }

    pub(crate) const MAGIC_LE_US: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];

    #[test]
    fn walks_records_in_every_layout() {
        let a: &[u8] = &[0xaa, 0xbb, 0xcc];
        let b: &[u8] = &[0x11, 0x22, 0x33, 0x44];
        for (magic, nanos) in [
            ([0xa1, 0xb2, 0xc3, 0xd4], false),
            ([0xd4, 0xc3, 0xb2, 0xa1], false),
            ([0xa1, 0xb2, 0x3c, 0x4d], true),
            ([0x4d, 0x3c, 0xb2, 0xa1], true),
        ] {
            let frac = if nanos { 5_000 } else { 5 };
            let file = savefile(magic, &[(1, frac, a), (2, 0, b)]);
            let mut s = PcapStream::new(Cursor::new(file));
            let first = s.next_record().unwrap().unwrap();
            assert_eq!(first.ts_us, 1_000_005, "magic {magic:02x?}");
            assert_eq!(first.data, a);
            assert_eq!(s.next_record().unwrap().unwrap().data, b);
            assert_eq!(s.next_record().unwrap(), None);
        }
    }

    #[test]
    fn a_stream_that_is_not_pcap_is_refused_before_any_record() {
        let mut ng = vec![0x0a, 0x0d, 0x0d, 0x0a];
        ng.extend_from_slice(&[0u8; 40]);
        let err = PcapStream::new(Cursor::new(ng)).next_record().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_truncated_tail_is_an_eof_after_the_whole_records() {
        let good: &[u8] = &[1, 2, 3];
        let mut file = savefile(MAGIC_LE_US, &[(9, 0, good)]);
        // A record header promising more bytes than follow.
        file.extend_from_slice(&99u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&100u32.to_le_bytes());
        file.extend_from_slice(&100u32.to_le_bytes());
        file.extend_from_slice(&[0xde, 0xad]);
        let mut s = PcapStream::new(Cursor::new(file));
        assert_eq!(s.next_record().unwrap().unwrap().data, good);
        let err = s.next_record().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn an_absurd_length_is_invalid_data_not_an_allocation() {
        let mut file = savefile(MAGIC_LE_US, &[]);
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&u32::MAX.to_le_bytes());
        file.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = PcapStream::new(Cursor::new(file))
            .next_record()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_empty_stream_is_an_eof_not_a_record() {
        let err = PcapStream::new(Cursor::new(Vec::new()))
            .next_record()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
