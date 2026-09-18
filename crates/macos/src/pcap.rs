//! Rolling packet capture backed by a `tcpdump` child process.
//!
//! [`PcapRing::start`] spawns `tcpdump` writing a small rotating ring
//! (`-C <ring_mb> -W 2`) with a cheap snaplen and BPF filter. On an incident,
//! [`PcapRing::freeze`] synchronously copies the current ring files into a
//! destination directory so the volatile buffer is preserved *before* any slow
//! forensic work runs. Old freeze directories are pruned to bound disk use.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::SystemTime;

/// Base name of the ring capture files inside the ring directory. Public so
/// the daemon can find the files an earlier build left there (realm
/// net-observer, node #110).
pub const RING_BASENAME: &str = "ring.pcap";

/// How many freeze directories to retain (newest-first); older ones are pruned.
const KEEP_FREEZES: usize = 12;

/// The prefix of an experiment window's two freezes
/// (`freeze-experiment-<start_us>-start` / `-end`, realm net-observer, node
/// #61). Pruned on their own budget: the window's report was read from the
/// end slice and names both directories, and the pruner otherwise keeps the
/// newest [`KEEP_FREEZES`] directories whether or not a record refers to
/// them — twelve incident freezes after a window would silently take the
/// slice its report is about.
const EXPERIMENT_FREEZE_PREFIX: &str = "freeze-experiment-";

/// How many experiment freeze directories to retain (newest-first): six
/// windows, two freezes each. Pruned apart from the incident freezes, so
/// neither kind spends the other's budget.
const KEEP_EXPERIMENT_FREEZES: usize = 12;

/// Who may read a freeze: the group and mode every copied file takes — the
/// record's own (`record_gid` / `record_mode`), because "root and staff" is
/// the reader set for everything the daemon writes, and a frozen pcap is what
/// the operator opens after an incident (realm net-observer, node #110).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeAccess {
    /// The group the freeze directory and each copied file are `chown`ed to;
    /// `None` leaves the group the directory they were created in gave them.
    pub gid: Option<u32>,
    /// The permission bits each copied file takes.
    pub mode: u32,
}

/// A live `tcpdump` ring capture. Killing the process happens on `Drop`.
#[derive(Debug)]
pub struct PcapRing {
    /// Behind a `Mutex` only because reaping the child ([`Child::try_wait`])
    /// needs `&mut`, while the ring is shared behind an `Arc` so the control
    /// socket and the supervisor can both reach it.
    child: Mutex<Child>,
    ring_dir: PathBuf,
    /// Applied to every freeze this ring produces.
    freeze_access: FreezeAccess,
}

impl PcapRing {
    /// Start `tcpdump` capturing on `iface` into a rotating ring under
    /// `ring_dir` (`-C ring_mb -W 2`), applying `filter` as the BPF expression.
    /// Every freeze the ring later produces takes `freeze_access`.
    ///
    /// # Errors
    /// Returns an error if the ring directory cannot be created or `tcpdump`
    /// cannot be spawned (e.g. not installed, or insufficient privileges).
    pub fn start(
        iface: &str,
        ring_dir: impl Into<PathBuf>,
        ring_mb: u32,
        filter: &str,
        freeze_access: FreezeAccess,
    ) -> std::io::Result<Self> {
        let ring_dir = ring_dir.into();
        std::fs::create_dir_all(&ring_dir)?;
        let ring_path = ring_dir.join(RING_BASENAME);

        let mut cmd = Command::new("tcpdump");
        cmd.arg("-i")
            .arg(iface)
            .arg("-s128")
            .arg("-w")
            .arg(&ring_path)
            .arg("-C")
            .arg(ring_mb.to_string())
            .arg("-W")
            .arg("2");
        for token in filter.split_whitespace() {
            cmd.arg(token);
        }
        let child = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;

        tracing::info!(iface, ?ring_path, ring_mb, "started tcpdump pcap ring");
        Ok(Self {
            child: Mutex::new(child),
            ring_dir,
            freeze_access,
        })
    }

    /// Copy the current ring files into `dest_dir` and return the copied paths.
    ///
    /// Runs synchronously and returns whatever it could copy (an unreadable
    /// ring yields an empty vec, never a panic). Prunes old freeze siblings.
    #[must_use]
    pub fn freeze(&self, dest_dir: &Path) -> Vec<PathBuf> {
        let copied = copy_ring_files(&self.ring_dir, dest_dir, self.freeze_access);
        if let Some(parent) = dest_dir.parent() {
            prune_freezes(parent, KEEP_FREEZES);
        }
        copied
    }

    /// Whether the `tcpdump` child is still running.
    ///
    /// Reaps the child if it has exited, so a dead ring is not left as a zombie
    /// while its handle still looks live. A `try_wait` error (or a poisoned
    /// lock) is reported as *not* alive: the supervisor then replaces the ring,
    /// which is the safe direction — a spurious restart costs a child process,
    /// a spurious "alive" costs the whole capture.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        let mut child = match self.child.lock() {
            Ok(c) => c,
            Err(_) => return false,
        };
        matches!(child.try_wait(), Ok(None))
    }
}

impl Drop for PcapRing {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Copy every `ring.pcap*` file from `ring_dir` into `dest_dir`, returning the
/// destination paths that were written.
///
/// `std::fs::copy` carries the ring file's own bits — `tcpdump`'s, under the
/// daemon's umask — and the new file takes the freeze directory's group, so
/// each copy is given `access` outright: the freeze directory is `chown`ed to
/// `access.gid`, every copied file to the same group and `access.mode`. The
/// operator opens THESE files after an incident, so they follow the record
/// (realm net-observer, node #110). A failure there is a warning and the
/// copy still counts: the evidence is on disk, root can read it. Freezes
/// made before this build keep the bits they were made with.
fn copy_ring_files(ring_dir: &Path, dest_dir: &Path, access: FreezeAccess) -> Vec<PathBuf> {
    let mut copied = Vec::new();
    if let Err(e) = std::fs::create_dir_all(dest_dir) {
        tracing::warn!(?dest_dir, error = %e, "could not create freeze dir");
        return copied;
    }
    if let Err(e) = std::os::unix::fs::chown(dest_dir, None, access.gid) {
        tracing::warn!(?dest_dir, gid = ?access.gid, error = %e, "freeze dir: chown failed");
    }
    let Ok(entries) = std::fs::read_dir(ring_dir) else {
        return copied;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with(RING_BASENAME) {
            continue;
        }
        let dest = dest_dir.join(name);
        match std::fs::copy(&path, &dest) {
            Ok(_) => {
                grant_access(&dest, access);
                copied.push(dest);
            }
            Err(e) => tracing::warn!(?path, error = %e, "failed to copy ring file"),
        }
    }
    copied
}

/// One copied file: group `access.gid`, then `access.mode`. Chown first — a
/// chown can clear mode bits, a chmod never moves a group. Each failure is a
/// warning; the file stays where the copy put it.
fn grant_access(path: &Path, access: FreezeAccess) {
    if let Err(e) = std::os::unix::fs::chown(path, None, access.gid) {
        tracing::warn!(?path, gid = ?access.gid, error = %e, "freeze file: chown failed");
    }
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(access.mode)) {
        tracing::warn!(
            ?path,
            mode = format!("{:o}", access.mode),
            error = %e,
            "freeze file: chmod failed"
        );
    }
}

/// Keep the `keep` newest sub-directories under `parent`, removing older ones.
/// An experiment window's freezes ([`EXPERIMENT_FREEZE_PREFIX`]) are pruned
/// on their own budget ([`KEEP_EXPERIMENT_FREEZES`]), never against the
/// incident freezes': the report that names them is the reason they exist,
/// and twelve incident freezes must not take the slice a report was read
/// from — nor may a season of windows grow the blob directory without bound.
fn prune_freezes(parent: &Path, keep: usize) {
    prune_freezes_with(parent, keep, KEEP_EXPERIMENT_FREEZES);
}

/// [`prune_freezes`] with both budgets explicit, so the split is testable.
fn prune_freezes_with(parent: &Path, keep: usize, keep_experiments: usize) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let mut incidents: Vec<(SystemTime, PathBuf)> = Vec::new();
    let mut experiments: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        let is_experiment = entry
            .file_name()
            .to_string_lossy()
            .starts_with(EXPERIMENT_FREEZE_PREFIX);
        if is_experiment {
            experiments.push((modified, path));
        } else {
            incidents.push((modified, path));
        }
    }
    for (mut dirs, budget) in [(incidents, keep), (experiments, keep_experiments)] {
        dirs.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified)); // newest first
        for (_, path) in dirs.into_iter().skip(budget) {
            if let Err(e) = std::fs::remove_dir_all(&path) {
                tracing::warn!(?path, error = %e, "failed to prune old freeze dir");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The group is left as created (`None`): a test process is not root
    /// and owns no other group.
    const TEST_ACCESS: FreezeAccess = FreezeAccess {
        gid: None,
        mode: 0o640,
    };

    /// Only the ring files are copied, and each copy takes the freeze's
    /// mode rather than the ring file's own — the operator opens the copy
    /// (realm net-observer, node #110).
    #[test]
    fn copies_only_ring_files_and_grants_the_freeze_mode() {
        let ring = tempfile::tempdir().unwrap();
        std::fs::write(ring.path().join("ring.pcap0"), b"aaa").unwrap();
        std::fs::write(ring.path().join("ring.pcap1"), b"bbb").unwrap();
        std::fs::write(ring.path().join("unrelated.txt"), b"ccc").unwrap();
        // The source bits are deliberately not the freeze's: `fs::copy` would
        // carry them, and the test must see the copy lose them.
        std::fs::set_permissions(
            ring.path().join("ring.pcap0"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let dest = tempfile::tempdir().unwrap();
        let copied = copy_ring_files(
            ring.path(),
            dest.path().join("freeze-1").as_path(),
            TEST_ACCESS,
        );

        assert_eq!(copied.len(), 2);
        assert!(copied.iter().all(|p| p.exists()));
        assert!(!dest.path().join("freeze-1").join("unrelated.txt").exists());
        for p in &copied {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o640, "{}", p.display());
        }
    }

    #[test]
    fn copy_from_missing_ring_is_empty() {
        let dest = tempfile::tempdir().unwrap();
        let copied = copy_ring_files(Path::new("/nonexistent/ring"), dest.path(), TEST_ACCESS);
        assert!(copied.is_empty());
    }

    #[test]
    fn prune_keeps_newest_n() {
        let root = tempfile::tempdir().unwrap();
        for i in 0..5 {
            let d = root.path().join(format!("freeze-{i}"));
            std::fs::create_dir(&d).unwrap();
        }
        prune_freezes(root.path(), 2);
        let remaining = std::fs::read_dir(root.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .count();
        assert_eq!(remaining, 2);
    }

    /// The two kinds of freeze are pruned on separate budgets: the incident
    /// freezes keep their `keep` newest whether or not experiment freezes
    /// exist, and the experiment freezes keep their own newest
    /// `keep_experiments` — neither kind spends the other's (realm
    /// net-observer, node #61).
    #[test]
    fn prune_keeps_experiment_freezes_on_their_own_budget() {
        let root = tempfile::tempdir().unwrap();
        for window in 0..3 {
            for end in ["start", "end"] {
                std::fs::create_dir(
                    root.path()
                        .join(format!("freeze-experiment-{window}-{end}")),
                )
                .unwrap();
            }
        }
        for i in 0..5 {
            std::fs::create_dir(root.path().join(format!("freeze-{i}"))).unwrap();
        }
        let listing = || {
            let mut names: Vec<String> = std::fs::read_dir(root.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().is_dir())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        let experiments = |names: &[String]| {
            names
                .iter()
                .filter(|n| n.starts_with("freeze-experiment-"))
                .count()
        };

        // A generous experiment budget: every window survives while the
        // incident freezes drop to their two.
        prune_freezes_with(root.path(), 2, 12);
        let remaining = listing();
        assert_eq!(remaining.len(), 8, "{remaining:?}");
        assert_eq!(experiments(&remaining), 6, "{remaining:?}");

        // A tight experiment budget: four experiment directories go, the two
        // incident freezes stay untouched — the budgets do not mix.
        prune_freezes_with(root.path(), 2, 2);
        let remaining = listing();
        assert_eq!(remaining.len(), 4, "{remaining:?}");
        assert_eq!(experiments(&remaining), 2, "{remaining:?}");
        assert_eq!(
            remaining.len() - experiments(&remaining),
            2,
            "the incident freezes keep their own budget: {remaining:?}"
        );
    }
}
