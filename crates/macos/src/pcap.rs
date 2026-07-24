//! Rolling packet capture backed by a `tcpdump` child process.
//!
//! [`PcapRing::start`] spawns `tcpdump` writing a small rotating ring
//! (`-C <ring_mb> -W 2`) with a cheap snaplen and BPF filter. On an incident,
//! [`PcapRing::freeze`] synchronously copies the current ring files into a
//! destination directory so the volatile buffer is preserved *before* any slow
//! forensic work runs. Old freeze directories are pruned to bound disk use.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::SystemTime;

/// Base name of the ring capture files inside the ring directory.
const RING_BASENAME: &str = "ring.pcap";

/// How many freeze directories to retain (newest-first); older ones are pruned.
const KEEP_FREEZES: usize = 12;

/// A live `tcpdump` ring capture. Killing the process happens on `Drop`.
#[derive(Debug)]
pub struct PcapRing {
    child: Child,
    ring_dir: PathBuf,
}

impl PcapRing {
    /// Start `tcpdump` capturing on `iface` into a rotating ring under
    /// `ring_dir` (`-C ring_mb -W 2`), applying `filter` as the BPF expression.
    ///
    /// # Errors
    /// Returns an error if the ring directory cannot be created or `tcpdump`
    /// cannot be spawned (e.g. not installed, or insufficient privileges).
    pub fn start(
        iface: &str,
        ring_dir: impl Into<PathBuf>,
        ring_mb: u32,
        filter: &str,
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
        Ok(Self { child, ring_dir })
    }

    /// Copy the current ring files into `dest_dir` and return the copied paths.
    ///
    /// Runs synchronously and returns whatever it could copy (an unreadable
    /// ring yields an empty vec, never a panic). Prunes old freeze siblings.
    #[must_use]
    pub fn freeze(&self, dest_dir: &Path) -> Vec<PathBuf> {
        let copied = copy_ring_files(&self.ring_dir, dest_dir);
        if let Some(parent) = dest_dir.parent() {
            prune_freezes(parent, KEEP_FREEZES);
        }
        copied
    }
}

impl Drop for PcapRing {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Copy every `ring.pcap*` file from `ring_dir` into `dest_dir`, returning the
/// destination paths that were written.
fn copy_ring_files(ring_dir: &Path, dest_dir: &Path) -> Vec<PathBuf> {
    let mut copied = Vec::new();
    if let Err(e) = std::fs::create_dir_all(dest_dir) {
        tracing::warn!(?dest_dir, error = %e, "could not create freeze dir");
        return copied;
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
            Ok(_) => copied.push(dest),
            Err(e) => tracing::warn!(?path, error = %e, "failed to copy ring file"),
        }
    }
    copied
}

/// Keep the `keep` newest sub-directories under `parent`, removing older ones.
fn prune_freezes(parent: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let mut dirs: Vec<(SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((modified, e.path()))
        })
        .collect();
    dirs.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified)); // newest first
    for (_, path) in dirs.into_iter().skip(keep) {
        if let Err(e) = std::fs::remove_dir_all(&path) {
            tracing::warn!(?path, error = %e, "failed to prune old freeze dir");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copies_only_ring_files() {
        let ring = tempfile::tempdir().unwrap();
        std::fs::write(ring.path().join("ring.pcap0"), b"aaa").unwrap();
        std::fs::write(ring.path().join("ring.pcap1"), b"bbb").unwrap();
        std::fs::write(ring.path().join("unrelated.txt"), b"ccc").unwrap();

        let dest = tempfile::tempdir().unwrap();
        let copied = copy_ring_files(ring.path(), dest.path().join("freeze-1").as_path());

        assert_eq!(copied.len(), 2);
        assert!(copied.iter().all(|p| p.exists()));
        assert!(!dest.path().join("freeze-1").join("unrelated.txt").exists());
    }

    #[test]
    fn copy_from_missing_ring_is_empty() {
        let dest = tempfile::tempdir().unwrap();
        let copied = copy_ring_files(Path::new("/nonexistent/ring"), dest.path());
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
}
