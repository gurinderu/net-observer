//! A tail over a log file that is appended to and rotated by someone else
//! (realm net-observer, node #140: `/var/log/sing-box.log`, moved to
//! `sing-box.log.1` then gzipped by a launchd agent every 15–60 min).

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The open file and where the tail has read up to in it.
struct Open {
    file: File,
    ino: u64,
    /// Bytes consumed so far — the file cursor is put back here before every
    /// read, so a read that failed halfway is retried from the same place.
    offset: u64,
}

/// A tail attached at the END of a log: [`LogTail::read_new`] returns the
/// complete lines appended since the previous call, and a partial trailing
/// line waits in a buffer for the next one.
///
/// **Rotation.** Before each read the file at the path is compared with the
/// one held open: a different inode (the log was moved and a new file
/// created), or a length below the read offset (the log was truncated in
/// place), is a rotation, and the tail reopens the path from offset 0. What
/// the new file received between the rotation and the reopen is therefore
/// read; what the OLD file received after the previous read — up to one tick
/// of lines — is lost. A bounded loss per rotation, not a silence: every
/// rotation is counted in [`LogTail::rotations`], and the collector reports
/// the count on its tick.
///
/// **Absence.** The log not being openable is not a construction failure: the
/// path is retried on every `read_new`, which returns the I/O error until it
/// succeeds — the collector turns each such tick into an `Unreadable` row. The
/// first successful open attaches at the end, whether it happens in
/// [`LogTail::open_at_end`] or on a later read; only a rotation reopens from
/// the start.
pub struct LogTail {
    path: PathBuf,
    open: Option<Open>,
    partial: Vec<u8>,
    rotations: u32,
}

impl LogTail {
    /// Attach at the end of `path`: nothing already in the file is ever read.
    /// A file that cannot be opened now is retried on each `read_new`.
    #[must_use]
    pub fn open_at_end(path: impl Into<PathBuf>) -> Self {
        let mut tail = Self {
            path: path.into(),
            open: None,
            partial: Vec::new(),
            rotations: 0,
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

    /// How many rotations this tail has detected and followed.
    #[must_use]
    pub fn rotations(&self) -> u32 {
        self.rotations
    }

    /// The complete lines appended since the previous call (a partial trailing
    /// line is kept for the next). Detects and follows a rotation first (see
    /// the type docs). An error leaves the tail where it was, to be retried.
    pub fn read_new(&mut self) -> io::Result<Vec<String>> {
        let meta = fs::metadata(&self.path)?;
        match &self.open {
            None => self.reopen(true)?,
            Some(o) if o.ino != meta.ino() || meta.len() < o.offset => {
                self.rotations = self.rotations.saturating_add(1);
                self.partial.clear();
                self.reopen(false)?;
            }
            Some(_) => {}
        }
        let o = self.open.as_mut().expect("opened above");
        o.file.seek(SeekFrom::Start(o.offset))?;
        let mut buf = Vec::new();
        o.file.read_to_end(&mut buf)?;
        o.offset += buf.len() as u64;
        self.partial.extend_from_slice(&buf);

        let mut lines = Vec::new();
        let mut start = 0;
        while let Some(nl) = self.partial[start..].iter().position(|&b| b == b'\n') {
            let end = start + nl;
            lines.push(String::from_utf8_lossy(&self.partial[start..end]).into_owned());
            start = end + 1;
        }
        self.partial.drain(..start);
        Ok(lines)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(path: &Path, s: &str) {
        let mut f = fs::OpenOptions::new().append(true).open(path).unwrap();
        f.write_all(s.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    #[test]
    fn reads_only_what_is_appended_after_attaching() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "old line\n").unwrap();
        let mut tail = LogTail::open_at_end(&path);
        assert_eq!(tail.read_new().unwrap(), Vec::<String>::new());
        append(&path, "a\nb\n");
        assert_eq!(tail.read_new().unwrap(), vec!["a", "b"]);
        assert_eq!(tail.read_new().unwrap(), Vec::<String>::new());
        assert_eq!(tail.rotations(), 0);
    }

    #[test]
    fn a_partial_line_waits_for_its_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "").unwrap();
        let mut tail = LogTail::open_at_end(&path);
        append(&path, "partial");
        assert_eq!(tail.read_new().unwrap(), Vec::<String>::new());
        append(&path, " line\nnext\n");
        assert_eq!(tail.read_new().unwrap(), vec!["partial line", "next"]);
    }

    /// The rotation agent moves the file and a new one appears at the path:
    /// the tail follows the path, reading the new file from its start, and
    /// counts the rotation. In-place truncation is followed the same way.
    #[test]
    fn a_moved_or_truncated_file_is_reopened_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        fs::write(&path, "x\ny\n").unwrap();
        let mut tail = LogTail::open_at_end(&path);
        append(&path, "new1\n");
        assert_eq!(tail.read_new().unwrap(), vec!["new1"]);

        fs::rename(&path, dir.path().join("sing-box.log.1")).unwrap();
        fs::write(&path, "fresh\n").unwrap();
        assert_eq!(tail.read_new().unwrap(), vec!["fresh"]);
        assert_eq!(tail.rotations(), 1);

        // Truncated in place: the length falls below the offset (6 bytes read
        // of the fresh file, 2 left after the truncation).
        fs::write(&path, "z\n").unwrap();
        assert_eq!(tail.read_new().unwrap(), vec!["z"]);
        assert_eq!(tail.rotations(), 2);
        append(&path, "more\n");
        assert_eq!(tail.read_new().unwrap(), vec!["more"]);
        assert_eq!(tail.rotations(), 2);
    }

    /// The gap between the move and the new file is an error this tick, not
    /// a silence — and the tail recovers on its own once the file is back.
    #[test]
    fn a_missing_file_is_an_error_until_it_appears_then_attaches_at_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        let mut tail = LogTail::open_at_end(&path);
        let err = tail.read_new().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        fs::write(&path, "pre\n").unwrap();
        assert_eq!(tail.read_new().unwrap(), Vec::<String>::new());
        append(&path, "post\n");
        assert_eq!(tail.read_new().unwrap(), vec!["post"]);

        fs::remove_file(&path).unwrap();
        assert_eq!(tail.read_new().unwrap_err().kind(), io::ErrorKind::NotFound);
        fs::write(&path, "again\n").unwrap();
        assert_eq!(tail.read_new().unwrap(), vec!["again"]);
        assert_eq!(tail.rotations(), 1);
    }
}
