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

/// The longest line the tail keeps or returns: a partial (newline-less)
/// trailing run past it is dropped and counted as one lost line, and so is a
/// complete line longer than it — a writer that stops emitting newlines, or
/// emits one enormous line, cannot grow a buffer or an allocation without
/// bound.
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
    /// same file continued but the gap since the previous read reached the
    /// allowed one (the ticks did not run — an operator pause, a sleep),
    /// skipping `bytes` of backlog.
    pub reattached: Option<(Duration, u64)>,
    /// Lines lost to the cap — a partial run past [`PARTIAL_CAP`], counted
    /// once however many reads it spans, or a complete line longer than it —
    /// plus the incomplete last line of a file the tail moved off at a
    /// rotation.
    pub dropped_partials: u32,
    /// Whether this read followed a rotation.
    pub rotated: bool,
}

/// A tail attached at the END of a log: [`LogTail::read_new`] returns the
/// complete lines appended since the previous call that the admit predicate
/// accepts (scanned as bytes, so a line the reader would discard is never
/// allocated), and a partial trailing line waits in a buffer for the next
/// call — up to [`PARTIAL_CAP`], past which the whole run, to its eventual
/// newline, is dropped and counted once.
///
/// **Rotation.** The agent rotates by `copytruncate`: the same inode, its
/// length dropping below the tail's offset. The tail then seeks to 0 on the
/// handle it holds and continues; whatever the writer appended between the
/// agent's copy and its truncate is the agent's loss (milliseconds), not
/// ours. A changed inode at the path — a hand `mv`, or a file recreated
/// after being removed — is followed as a defence: what the old inode still
/// holds is drained first, then the path is reopened from its start, so
/// nothing of the moved file is lost but its incomplete last line (counted in
/// [`TailRead::dropped_partials`]); if the reopen fails, nothing is committed
/// and the next read drains the same bytes again. Every rotation followed is
/// counted in [`LogTail::rotations`], on success only.
///
/// **Gaps.** The tail remembers when it last read. When the SAME file
/// continued and the gap since the previous read reaches `max_gap` (the ticks
/// did not run: an operator pause, a sleep), the backlog is not read — the
/// rows it produced would be stamped with this tick and read as a burst that
/// happened now — and the tail re-attaches at the end, reporting the gap and
/// the bytes skipped ([`TailRead::reattached`]); the pause is already
/// bracketed by the observing edge, and the skipped stretch belongs to it. A
/// gap short of that (one missed tick) reads the backlog, and the reader's
/// stale-line belt drops what is too old. A file that is NEW since the last
/// read — absent then present, or another inode — is read from its start
/// whatever the gap: its opening is the evidence (sing-box respawned, and its
/// first lines say so). A tick dropped whole at a probing-tier switch (the
/// interval loop drops the in-flight tick's samples at the source) has
/// already consumed its bytes: those lines are gone, bracketed by the
/// `probing_edge` row.
///
/// **Absence.** The log not being openable is not a construction failure: the
/// path is retried on every `read_new`, which returns the I/O error until it
/// succeeds — the collector turns each such tick into an `Unreadable` row.
/// [`LogTail::open_at_end`] attaches at the end of a file that exists then; a
/// file that appears on a later read is new and is read from its start.
pub struct LogTail {
    path: PathBuf,
    max_gap: Duration,
    admit: fn(&[u8]) -> bool,
    open: Option<Open>,
    partial: Vec<u8>,
    /// A run past the cap was dropped and its newline not yet seen: bytes up
    /// to and including the next newline belong to it and are skipped.
    discarding: bool,
    rotations: u32,
    last_read: Option<Instant>,
}

impl LogTail {
    /// Attach at the end of `path`: nothing already in the file is ever read.
    /// A file that cannot be opened now is retried on each `read_new`.
    /// `max_gap` is the silence between two reads of the same file at which
    /// the backlog is skipped rather than read; `admit` decides, on the raw
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
            discarding: false,
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

        // The same file continued across a gap the ticks did not cover: the
        // backlog is the gap's, not this tick's.
        if let Some(gap) = gap
            && gap >= self.max_gap
            && let Some(o) = &self.open
            && o.ino == meta.ino()
        {
            let skipped = if meta.len() >= o.offset {
                meta.len() - o.offset
            } else {
                meta.len()
            };
            self.reopen(true)?;
            self.partial.clear();
            self.discarding = false;
            out.reattached = Some((gap, skipped));
            return Ok(out);
        }

        match &mut self.open {
            // Absent until now: a new file, read from its start.
            None => self.reopen(false)?,
            Some(o) if o.ino != meta.ino() => {
                // Another inode at the path: drain what the old one still
                // holds, then follow the path from its start — committing
                // nothing unless the reopen succeeds.
                o.file.seek(SeekFrom::Start(o.offset))?;
                let mut drained = self.partial.clone();
                o.file.read_to_end(&mut drained)?;
                let mut lines = Vec::new();
                let mut discarding = self.discarding;
                let mut dropped =
                    split_lines(&mut drained, self.admit, &mut lines, &mut discarding);
                if !drained.is_empty() {
                    dropped += 1;
                }
                self.reopen(false)?;
                self.partial.clear();
                self.discarding = false;
                self.rotations = self.rotations.saturating_add(1);
                out.lines = lines;
                out.dropped_partials += dropped;
                out.rotated = true;
            }
            Some(o) if meta.len() < o.offset => {
                // The agent's copytruncate: same inode, start over on it.
                o.file.seek(SeekFrom::Start(0))?;
                o.offset = 0;
                if !self.partial.is_empty() {
                    out.dropped_partials += 1;
                }
                self.partial.clear();
                self.discarding = false;
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
        out.dropped_partials += split_lines(
            &mut self.partial,
            self.admit,
            &mut out.lines,
            &mut self.discarding,
        );
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
/// only when `admit` accepts its bytes and it is no longer than
/// [`PARTIAL_CAP`] — leaving the trailing partial line, or dropping it when
/// it passes the cap. Returns how many lines were dropped to the cap. While
/// `discarding`, bytes up to and including the next newline belong to a run
/// already dropped and counted, and are skipped without a count.
fn split_lines(
    partial: &mut Vec<u8>,
    admit: fn(&[u8]) -> bool,
    lines: &mut Vec<String>,
    discarding: &mut bool,
) -> u32 {
    let mut dropped = 0;
    let mut start = 0;
    while let Some(nl) = partial[start..].iter().position(|&b| b == b'\n') {
        let end = start + nl;
        if *discarding {
            *discarding = false;
        } else if end - start > PARTIAL_CAP {
            dropped += 1;
        } else {
            let raw = &partial[start..end];
            if admit(raw) {
                lines.push(String::from_utf8_lossy(raw).into_owned());
            }
        }
        start = end + 1;
    }
    partial.drain(..start);
    if *discarding {
        // Still inside a dropped run: none of this is a line.
        partial.clear();
    } else if partial.len() > PARTIAL_CAP {
        partial.clear();
        *discarding = true;
        dropped += 1;
    }
    dropped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TICK: Duration = Duration::from_secs(15);
    const MAX_GAP: Duration = Duration::from_secs(60);

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
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
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
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
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
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, errors_only);
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
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
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
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
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

    /// A move whose reopen fails commits nothing: the straddling partial line
    /// and the old offset stay, and the next read drains the same bytes.
    #[test]
    fn a_failed_reopen_after_a_move_leaves_the_tail_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
        let t0 = Instant::now();
        append(&path, "head");
        assert_eq!(lines(&mut tail, t0), Vec::<String>::new());
        assert_eq!(tail.buffered(), 4);

        // The new file at the path is unreadable: metadata succeeds, the
        // open fails (this test runs unprivileged; root would open it).
        use std::os::unix::fs::PermissionsExt;
        let moved = dir.path().join("sing-box.log.1");
        fs::rename(&path, &moved).unwrap();
        append(&moved, " of a line\ntail");
        fs::write(&path, "fresh\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(tail.read_new(t0 + TICK).is_err());
        assert_eq!(tail.buffered(), 4, "the partial survives the failed reopen");
        assert_eq!(tail.rotations(), 0);

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let read = tail.read_new(t0 + 2 * TICK).unwrap();
        assert_eq!(read.lines, vec!["head of a line", "fresh"]);
        assert_eq!(read.dropped_partials, 1, "`tail` of the moved file");
        assert_eq!(tail.rotations(), 1);
    }

    /// The same file continued across a gap the ticks did not cover: four
    /// intervals re-attach at the end, reporting the gap and the bytes left
    /// behind; three read the backlog (the reader's belt drops what is old).
    #[test]
    fn a_gap_of_four_intervals_reattaches_three_read_the_backlog() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
        let t0 = Instant::now();
        append(&path, "seen\n");
        assert_eq!(lines(&mut tail, t0), vec!["seen"]);

        append(&path, "one missed tick\n");
        assert_eq!(lines(&mut tail, t0 + 3 * TICK), vec!["one missed tick"]);

        append(&path, "during the pause 1\nduring the pause 2\n");
        let read = tail.read_new(t0 + 7 * TICK).unwrap();
        assert_eq!(read.lines, Vec::<String>::new());
        assert_eq!(read.reattached, Some((4 * TICK, 38)));

        append(&path, "after\n");
        assert_eq!(lines(&mut tail, t0 + 8 * TICK), vec!["after"]);
    }

    /// A file that is new since the last read is read from its start
    /// whatever the gap — its opening is the evidence: absent at
    /// construction, then present; removed, then recreated.
    #[test]
    fn a_new_file_after_a_long_gap_is_read_from_its_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
        let t0 = Instant::now();
        assert_eq!(
            tail.read_new(t0).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        fs::write(&path, "sing-box started\nupdated default interface en0\n").unwrap();
        let read = tail.read_new(t0 + 10 * TICK).unwrap();
        assert_eq!(read.reattached, None);
        assert_eq!(
            read.lines,
            vec!["sing-box started", "updated default interface en0"]
        );
        assert_eq!(tail.rotations(), 0, "nothing was rotated from");

        fs::remove_file(&path).unwrap();
        assert_eq!(
            tail.read_new(t0 + 11 * TICK).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs::write(&path, "sing-box started\n").unwrap();
        let read = tail.read_new(t0 + 21 * TICK).unwrap();
        assert_eq!(read.reattached, None);
        assert_eq!(read.lines, vec!["sing-box started"]);
        assert_eq!(tail.rotations(), 1);
    }

    /// A run without a newline past the cap is dropped whole and counted
    /// ONCE, however many reads it spans: the buffer never keeps more than
    /// the cap, the remainder up to the run's newline is skipped without a
    /// fragment, and the next real line reads clean.
    #[test]
    fn a_partial_run_past_the_cap_is_dropped_once_across_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
        let t0 = Instant::now();
        let half = "x".repeat(PARTIAL_CAP + PARTIAL_CAP / 2);
        append(&path, &half);
        let read = tail.read_new(t0).unwrap();
        assert!(read.lines.is_empty());
        assert_eq!(read.dropped_partials, 1);
        assert_eq!(tail.buffered(), 0);

        let rest = "y".repeat(PARTIAL_CAP / 2);
        append(&path, &format!("{rest}\nclean\n"));
        let read = tail.read_new(t0 + TICK).unwrap();
        assert_eq!(read.lines, vec!["clean"], "no headless fragment");
        assert_eq!(read.dropped_partials, 0, "the run was counted once");
        assert_eq!(tail.buffered(), 0);
    }

    /// A complete line longer than the cap, arriving within one read, is
    /// dropped and counted, never allocated.
    #[test]
    fn a_complete_line_past_the_cap_is_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path, MAX_GAP, all);
        let long = "z".repeat(PARTIAL_CAP + 1);
        append(&path, &format!("before\n{long}\nafter\n"));
        let read = tail.read_new(Instant::now()).unwrap();
        assert_eq!(read.lines, vec!["before", "after"]);
        assert_eq!(read.dropped_partials, 1);
    }
}
