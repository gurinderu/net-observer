//! A tail over a log file that is appended to by one process and rotated by
//! another (realm net-observer, node #140: `/var/log/sing-box.log`, which the
//! launchd agent `org.nixos.sing-box-logrotate` rotates every 900 s once it
//! passes 20 MB — `copytruncate`: the file is COPIED to `.1` and TRUNCATED in
//! place, so the inode never changes and the length drops below the tail's
//! offset).

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The longest partial (newline-less) trailing line the tail keeps between
/// reads. A run past it is not a log line — it is dropped whole and counted
/// as one lost line, so a writer that stops emitting newlines cannot grow the
/// buffer without bound.
pub const PARTIAL_CAP: usize = 1 << 20;

/// The open file and where the tail has read up to in it.
struct Open {
    file: File,
    ino: u64,
    /// Bytes consumed so far — the file cursor is put back here before every
    /// read, so a read that failed halfway is retried from the same place.
    offset: u64,
}

/// What one [`LogTail::read_new`] produced, beside its lines: every way the
/// tail moved on without reading, counted rather than silent.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TailRead {
    /// The complete, admitted lines appended since the previous read.
    pub lines: Vec<String>,
    /// `Some((gap, bytes))` when the tail re-attached at the end because the
    /// gap since its previous read exceeded the allowed one (the ticks did
    /// not run — an operator pause), skipping `bytes` of backlog.
    pub reattached: Option<(Duration, u64)>,
    /// Partial-line buffers dropped: one past [`PARTIAL_CAP`], or the
    /// incomplete last line of a file the tail moved off at a rotation.
    pub dropped_partials: u32,
    /// Whether this read followed a rotation.
    pub rotated: bool,
}

/// A tail attached at the END of a log: [`LogTail::read_new`] returns the
/// complete lines appended since the previous call that the admit predicate
/// accepts (scanned as bytes, so a line the reader would discard is never
/// allocated), and a partial trailing line waits in a buffer for the next
/// call — up to [`PARTIAL_CAP`], past which it is dropped and counted.
///
/// **Rotation.** The agent rotates by `copytruncate`: the same inode, its
/// length dropping below the tail's offset. The tail then seeks to 0 on the
/// handle it holds and continues; whatever the writer appended between the
/// agent's copy and its truncate is the agent's loss (milliseconds), not
/// ours. A changed inode at the path — a hand `mv`, never the agent's doing —
/// is followed as a defence: what the old inode still holds is drained first,
/// then the path is reopened from its start, so nothing of the moved file is
/// lost but its incomplete last line (counted in
/// [`TailRead::dropped_partials`]). Every rotation followed is counted in
/// [`LogTail::rotations`], on success only.
///
/// **Gaps.** The tail remembers when it last read. A read that comes more
/// than `max_gap` after the previous one (the ticks did not run: an operator
/// pause) does not read the backlog — the rows it produced would be stamped
/// with this tick and read as a burst that happened now — but re-attaches at
/// the end and reports the gap and the bytes skipped
/// ([`TailRead::reattached`]); the pause is already bracketed by the
/// observing edge, and the skipped stretch belongs to it. A tick dropped
/// whole at a probing-tier switch (the interval loop drops the in-flight
/// tick's samples at the source) has already consumed its bytes: those lines
/// are gone, bracketed by the `probing_edge` row.
///
/// **Absence.** The log not being openable is not a construction failure: the
/// path is retried on every `read_new`, which returns the I/O error until it
/// succeeds — the collector turns each such tick into an `Unreadable` row. The
/// first successful open attaches at the end, whether it happens in
/// [`LogTail::open_at_end`] or on a later read; only a rotation reads from
/// the start.
pub struct LogTail {
    path: PathBuf,
    max_gap: Duration,
    admit: fn(&[u8]) -> bool,
    open: Option<Open>,
    partial: Vec<u8>,
    rotations: u32,
    last_read: Option<Instant>,
}

impl LogTail {
    /// Attach at the end of `path`: nothing already in the file is ever read.
    /// A file that cannot be opened now is retried on each `read_new`.
    /// `max_gap` is the longest silence between two reads after which the
    /// backlog is skipped rather than read; `admit` decides, on the raw
    /// bytes, which complete lines are worth returning.
    #[must_use]
    pub fn open_at_end(
        path: impl Into<PathBuf>,
        max_gap: Duration,
        admit: fn(&[u8]) -> bool,
    ) -> Self {
        let mut tail = Self {
            path: path.into(),
            max_gap,
            admit,
            open: None,
            partial: Vec::new(),
            rotations: 0,
            last_read: None,
        };
        // A failure here is reported by the first `read_new`, which retries.
        let _ = tail.reopen(true);
        tail
    }

    /// The path this tail follows.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many rotations this tail has followed.
    #[must_use]
    pub fn rotations(&self) -> u32 {
        self.rotations
    }

    /// Bytes of partial line currently buffered.
    #[cfg(test)]
    fn buffered(&self) -> usize {
        self.partial.len()
    }

    /// The admitted complete lines appended since the previous call, `now`
    /// being the caller's monotonic clock for the gap rule (see the type
    /// docs). An error leaves the tail where it was, to be retried.
    pub fn read_new(&mut self, now: Instant) -> io::Result<TailRead> {
        let mut out = TailRead::default();
        let gap = self.last_read.map(|t| now.saturating_duration_since(t));
        self.last_read = Some(now);
        let meta = fs::metadata(&self.path)?;

        if let Some(gap) = gap
            && gap > self.max_gap
        {
            let skipped = match &self.open {
                Some(o) if o.ino == meta.ino() && meta.len() >= o.offset => meta.len() - o.offset,
                _ => meta.len(),
            };
            self.partial.clear();
            self.reopen(true)?;
            out.reattached = Some((gap, skipped));
            return Ok(out);
        }

        match &mut self.open {
            None => self.reopen(true)?,
            Some(o) if o.ino != meta.ino() => {
                // A hand `mv`: drain the old inode, then follow the path.
                o.file.seek(SeekFrom::Start(o.offset))?;
                let mut buf = Vec::new();
                o.file.read_to_end(&mut buf)?;
                self.partial.extend_from_slice(&buf);
                split_lines(&mut self.partial, self.admit, &mut out.lines);
                if !self.partial.is_empty() {
                    out.dropped_partials += 1;
                    self.partial.clear();
                }
                self.reopen(false)?;
                self.rotations = self.rotations.saturating_add(1);
                out.rotated = true;
            }
            Some(o) if meta.len() < o.offset => {
                // The agent's copytruncate: same inode, start over on it.
                o.file.seek(SeekFrom::Start(0))?;
                o.offset = 0;
                if !self.partial.is_empty() {
                    out.dropped_partials += 1;
                    self.partial.clear();
                }
                self.rotations = self.rotations.saturating_add(1);
                out.rotated = true;
            }
            Some(_) => {}
        }

        let o = self.open.as_mut().expect("opened above");
        o.file.seek(SeekFrom::Start(o.offset))?;
        let mut buf = Vec::new();
        o.file.read_to_end(&mut buf)?;
        o.offset += buf.len() as u64;
        self.partial.extend_from_slice(&buf);
        split_lines(&mut self.partial, self.admit, &mut out.lines);
        if self.partial.len() > PARTIAL_CAP {
            out.dropped_partials += 1;
            self.partial.clear();
        }
        Ok(out)
    }

    fn reopen(&mut self, at_end: bool) -> io::Result<()> {
        let mut file = File::open(&self.path)?;
        let ino = file.metadata()?.ino();
        let offset = if at_end {
            file.seek(SeekFrom::End(0))?
        } else {
            0
        };
        self.open = Some(Open { file, ino, offset });
        Ok(())
    }
}

/// Move every complete line out of `partial` into `lines` — as a `String`
/// only when `admit` accepts its bytes — leaving the trailing partial line.
fn split_lines(partial: &mut Vec<u8>, admit: fn(&[u8]) -> bool, lines: &mut Vec<String>) {
    let mut start = 0;
    while let Some(nl) = partial[start..].iter().position(|&b| b == b'\n') {
        let end = start + nl;
        let raw = &partial[start..end];
        if admit(raw) {
            lines.push(String::from_utf8_lossy(raw).into_owned());
        }
        start = end + 1;
    }
    partial.drain(..start);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TICK: Duration = Duration::from_secs(15);

    fn all(_: &[u8]) -> bool {
        true
    }

    fn errors_only(raw: &[u8]) -> bool {
        raw.windows(5).any(|w| w == b"ERROR")
    }

    fn append(path: &Path, s: &str) {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(s.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    fn lines(tail: &mut LogTail, now: Instant) -> Vec<String> {
        let read = tail.read_new(now).unwrap();
        assert_eq!(read.reattached, None, "{read:?}");
        read.lines
    }

    #[test]
    fn reads_only_what_is_appended_after_attaching() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "old line\n").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();
        assert_eq!(lines(&mut tail, t0), Vec::<String>::new());
        append(&path, "a\nb\n");
        assert_eq!(lines(&mut tail, t0 + TICK), vec!["a", "b"]);
        assert_eq!(lines(&mut tail, t0 + 2 * TICK), Vec::<String>::new());
        assert_eq!(tail.rotations(), 0);
    }

    #[test]
    fn a_partial_line_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();
        append(&path, "partial");
        assert_eq!(lines(&mut tail, t0), Vec::<String>::new());
        append(&path, " line\nnext\n");
        assert_eq!(lines(&mut tail, t0 + TICK), vec!["partial line", "next"]);
    }

    /// Only admitted lines become strings: the scan is on the bytes.
    #[test]
    fn the_admit_predicate_filters_before_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, errors_only);
        append(&path, "DEBUG noise\nERROR one\nINFO more\nERROR two\n");
        assert_eq!(
            lines(&mut tail, Instant::now()),
            vec!["ERROR one", "ERROR two"]
        );
    }

    /// The agent's rotation: copied away and truncated in place — same inode,
    /// the length below the offset. The tail starts over on the handle it
    /// holds and counts the rotation.
    #[test]
    fn copytruncate_is_followed_on_the_same_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "x\ny\n").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();
        append(&path, "before\n");
        assert_eq!(lines(&mut tail, t0), vec!["before"]);
        let ino = fs::metadata(&path).unwrap().ino();

        // 11 bytes read; the truncated file holds 2.
        fs::write(&path, "z\n").unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().ino(),
            ino,
            "copytruncate keeps the inode"
        );
        let read = tail.read_new(t0 + TICK).unwrap();
        assert_eq!(read.lines, vec!["z"]);
        assert!(read.rotated);
        assert_eq!(tail.rotations(), 1);
        append(&path, "more\n");
        assert_eq!(lines(&mut tail, t0 + 2 * TICK), vec!["more"]);
        assert_eq!(tail.rotations(), 1);
    }

    /// A hand `mv` (never the agent's): what the old inode still holds is
    /// drained before the path is reopened from its start, so only the moved
    /// file's incomplete last line is lost — and counted.
    #[test]
    fn a_moved_file_is_drained_then_the_path_reopened_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "x\ny\n").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();

        let moved = dir.path().join("sing-box.log.1");
        fs::rename(&path, &moved).unwrap();
        append(&moved, "late\nhalf");
        fs::write(&path, "fresh\n").unwrap();
        let read = tail.read_new(t0).unwrap();
        assert_eq!(read.lines, vec!["late", "fresh"]);
        assert!(read.rotated);
        assert_eq!(
            read.dropped_partials, 1,
            "the moved file's `half` is lost, counted"
        );
        assert_eq!(tail.rotations(), 1);
        append(&path, "next\n");
        assert_eq!(lines(&mut tail, t0 + TICK), vec!["next"]);
    }

    /// A read that comes long after the previous one (the ticks did not run)
    /// skips the backlog and re-attaches at the end, reporting the gap and
    /// the bytes it left behind.
    #[test]
    fn a_gap_longer_than_allowed_reattaches_at_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();
        append(&path, "seen\n");
        assert_eq!(lines(&mut tail, t0), vec!["seen"]);

        append(&path, "during the pause 1\nduring the pause 2\n");
        let read = tail.read_new(t0 + 3 * TICK).unwrap();
        assert_eq!(read.lines, Vec::<String>::new());
        assert_eq!(read.reattached, Some((3 * TICK, 38)));

        append(&path, "after\n");
        assert_eq!(lines(&mut tail, t0 + 4 * TICK), vec!["after"]);
        // Exactly the allowed gap is not a gap.
        append(&path, "on time\n");
        assert_eq!(lines(&mut tail, t0 + 6 * TICK), vec!["on time"]);
    }

    /// A run without a newline past the cap is dropped whole and counted; the
    /// buffer never keeps more than the cap, and the next real line reads
    /// clean.
    #[test]
    fn a_partial_run_past_the_cap_is_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();
        let run = "x".repeat(2 * PARTIAL_CAP);
        append(&path, &run);
        let read = tail.read_new(t0).unwrap();
        assert!(read.lines.is_empty());
        assert_eq!(read.dropped_partials, 1);
        assert_eq!(tail.buffered(), 0);
        append(&path, "clean\n");
        assert_eq!(lines(&mut tail, t0 + TICK), vec!["clean"]);
        assert!(tail.buffered() <= PARTIAL_CAP);
    }

    /// The gap between a removal and a recreation is an error this tick, not
    /// a silence — and the tail recovers on its own once the file is back.
    #[test]
    fn a_missing_file_is_an_error_until_it_appears_then_attaches_at_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        let mut tail = LogTail::open_at_end(&path, 2 * TICK, all);
        let t0 = Instant::now();
        let err = tail.read_new(t0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        fs::write(&path, "pre\n").unwrap();
        assert_eq!(lines(&mut tail, t0 + TICK), Vec::<String>::new());
        append(&path, "post\n");
        assert_eq!(lines(&mut tail, t0 + 2 * TICK), vec!["post"]);

        fs::remove_file(&path).unwrap();
        assert_eq!(
            tail.read_new(t0 + 3 * TICK).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs::write(&path, "again\n").unwrap();
        assert_eq!(lines(&mut tail, t0 + 4 * TICK), vec!["again"]);
        assert_eq!(tail.rotations(), 1);
    }
}
