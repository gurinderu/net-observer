//! Host facts read from the OS: load via `libc::getloadavg(3)`, the record
//! volume's usage via `libc::statfs(2)`, swap via `sysctl vm.swapusage`.
//!
//! `getloadavg` is the standard 1/5/15-minute load-average interface on macOS
//! (and Linux). It reads the kernel's exponentially-weighted run-queue average,
//! the starvation discriminator (`load` in the tens while `tun=000`). Disk and
//! swap are the two resource columns the retired shell oracle carried and the
//! daemon lacked (realm net-observer, node #114): a store write that fails for
//! want of space is logged as a gap, and the volume's usage is what lets the
//! record name that cause. Every unobtainable value degrades to `None`, never a
//! panic — "absence is a signal".

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use collector_core::Readiness;
use collector_host::HostFacts;

/// One mebibyte — the unit `df -m` and `sysctl vm.swapusage` both report in.
const MIB: u64 = 1024 * 1024;

/// macOS implementation of [`HostFacts`]: `libc::getloadavg(3)` for load,
/// `libc::statfs(2)` on the record's volume for disk, `sysctl vm.swapusage`
/// for swap.
#[derive(Debug, Clone)]
pub struct HostLoad {
    /// The path whose filesystem is the record's volume — the directory
    /// holding the DB file. The daemon creates it before opening the store,
    /// so it exists from the first tick.
    volume: PathBuf,
}

impl HostLoad {
    /// Create a reader whose disk figures describe the filesystem holding
    /// `volume` (the DB file's directory).
    #[must_use]
    pub fn new(volume: impl Into<PathBuf>) -> Self {
        Self {
            volume: volume.into(),
        }
    }
}

impl HostFacts for HostLoad {
    async fn loadavg(&self) -> Option<(f64, f64, f64)> {
        let mut avg = [0f64; 3];
        // `getloadavg` is an instant syscall (reads a cached kernel average), so
        // it is called inline in the async fn — no blocking, no `spawn_blocking`.
        // SAFETY: `getloadavg` writes up to `nelem` `c_double`s into the buffer;
        // we pass a 3-element buffer and request exactly 3, matching its
        // contract. It returns the number of samples written, or -1 on failure.
        let n = unsafe { libc::getloadavg(avg.as_mut_ptr(), 3) };
        if n == 3 {
            Some((avg[0], avg[1], avg[2]))
        } else {
            None
        }
    }

    async fn disk(&self) -> Option<(f64, u64)> {
        // `statfs` on a mounted local volume answers from the in-memory
        // superblock — no I/O — so, like `getloadavg`, it is called inline.
        // The record lives under the daemon's own state directory, a local
        // volume by construction; a network mount here would be a config error,
        // not a case to design for.
        volume_usage(&self.volume)
    }

    async fn swap(&self) -> Option<u64> {
        let out = crate::dhcp_arp::run("sysctl", &["vm.swapusage"]).await?;
        parse_swap_used_mb(&out)
    }

    async fn preflight(&self) -> Readiness {
        if self.loadavg().await.is_some() {
            Readiness::Ready
        } else {
            Readiness::Unavailable("loadavg unreadable".into())
        }
    }
}

/// `statfs(2)` on `path`, mapped by [`usage_from_blocks`]. `None` when the path
/// cannot be represented or stat'ed, or the filesystem reports no blocks.
fn volume_usage(path: &Path) -> Option<(f64, u64)> {
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `statfs` writes a full `struct statfs` into `buf` and returns 0,
    // or returns -1 and leaves it untouched; the buffer is only read after the
    // return code says it was written. `c_path` is NUL-terminated by
    // construction.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        tracing::debug!(path = %path.display(), errno = ?std::io::Error::last_os_error(), "statfs failed");
        return None;
    }
    // SAFETY: `rc == 0`, so `statfs` initialised the whole struct.
    let st = unsafe { buf.assume_init() };
    usage_from_blocks(u64::from(st.f_bsize), st.f_blocks, st.f_bfree, st.f_bavail)
}

/// Pure: a filesystem's block counts → `(used fraction 0–100, free MiB)`.
///
/// Both figures are `df`'s: used is `f_blocks - f_bfree`, the denominator is
/// `used + f_bavail` (the blocks a writer can actually take, not the raw
/// total), so 100 means the next write fails even where `f_bfree` still shows
/// a reserve; free is `f_bavail` in whole MiB, what `df -m` prints as
/// `Avail`. `None` for a filesystem reporting no usable blocks at all, or
/// inconsistent counts (more free than total) — never a made-up figure.
fn usage_from_blocks(bsize: u64, blocks: u64, bfree: u64, bavail: u64) -> Option<(f64, u64)> {
    let used = blocks.checked_sub(bfree)?;
    let usable = used.checked_add(bavail)?;
    if usable == 0 {
        return None;
    }
    let used_pct = used as f64 / usable as f64 * 100.0;
    let free_mb = bavail.saturating_mul(bsize) / MIB;
    Some((used_pct, free_mb))
}

/// Parse the `used = <n>M` figure out of `sysctl vm.swapusage` output into
/// whole megabytes (nearest), or `None` when the text does not have the
/// documented shape.
///
/// The shape is taken from `sysctl(8)`'s source and documentation, NOT
/// observed on this machine: the tool renders the kernel's `xsw_usage` as
/// `vm.swapusage: total = 3072.00M  used = 1234.56M  free = 1837.44M  (encrypted)`,
/// every figure in mebibytes with an `M` suffix. Anything else — no
/// `vm.swapusage` line, no `used`, another suffix, a non-number — is `None`,
/// never a guess.
pub(crate) fn parse_swap_used_mb(text: &str) -> Option<u64> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("vm.swapusage:"))?;
    let (_, rest) = line.split_once("used = ")?;
    let token = rest.split_whitespace().next()?;
    let mb: f64 = token.strip_suffix('M')?.parse().ok()?;
    if !mb.is_finite() || mb < 0.0 {
        return None;
    }
    Some(mb.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loadavg_reads_three_finite_nonnegative_values() {
        // `getloadavg` is available on every macOS host the daemon runs on.
        let (l1, l5, l15) = HostLoad::new("/")
            .loadavg()
            .await
            .expect("loadavg readable");
        for v in [l1, l5, l15] {
            assert!(v.is_finite(), "load average must be finite: {v}");
            assert!(v >= 0.0, "load average must be non-negative: {v}");
        }
    }

    #[tokio::test]
    async fn preflight_is_ready_when_loadavg_readable() {
        assert!(HostLoad::new("/").preflight().await.is_ready());
    }

    /// The root volume is always mounted, so its usage is readable and sane.
    #[tokio::test]
    async fn disk_of_the_root_volume_is_a_sane_fraction() {
        let (pct, free_mb) = HostLoad::new("/")
            .disk()
            .await
            .expect("root volume readable");
        assert!(
            (0.0..=100.0).contains(&pct),
            "used fraction out of range: {pct}"
        );
        assert!(free_mb > 0, "root volume reports no free space");
    }

    #[tokio::test]
    async fn disk_of_a_missing_path_is_not_measured() {
        assert_eq!(
            HostLoad::new("/nonexistent/net-observer-volume")
                .disk()
                .await,
            None
        );
    }

    #[test]
    fn usage_from_blocks_is_df_capacity_and_avail() {
        // 4 KiB blocks, 1000 total, 250 free of which 200 available to a writer:
        // used = 750, capacity = 750 / (750 + 200), avail = 200 * 4 KiB.
        let (pct, free_mb) = usage_from_blocks(4096, 1000, 250, 200).expect("usage");
        assert!((pct - 78.947).abs() < 0.01, "{pct}");
        assert_eq!(free_mb, 0); // 800 KiB rounds down to zero whole MiB
        let (_, free_mb) = usage_from_blocks(4096, 1_000_000, 300_000, 262_144).expect("usage");
        assert_eq!(free_mb, 1024);
    }

    #[test]
    fn usage_from_blocks_refuses_empty_or_inconsistent_counts() {
        assert_eq!(usage_from_blocks(4096, 0, 0, 0), None);
        assert_eq!(usage_from_blocks(4096, 100, 200, 0), None);
    }

    /// The documented line shape (authored from `sysctl(8)`, not observed).
    const SWAPUSAGE_LINE: &str =
        "vm.swapusage: total = 3072.00M  used = 1234.56M  free = 1837.44M  (encrypted)\n";

    #[test]
    fn swap_used_is_parsed_from_the_documented_line() {
        assert_eq!(parse_swap_used_mb(SWAPUSAGE_LINE), Some(1235));
    }

    #[test]
    fn swap_used_is_parsed_when_no_swap_is_in_use() {
        assert_eq!(
            parse_swap_used_mb(
                "vm.swapusage: total = 0.00M  used = 0.00M  free = 0.00M  (encrypted)\n"
            ),
            Some(0)
        );
    }

    #[test]
    fn unrecognised_swapusage_shapes_are_not_measured() {
        for text in [
            "",
            "vm.swapusage: total = 3072.00M  free = 1837.44M\n",
            "vm.swapusage: total = 3072.00M  used = 1234.56K  free = 1837.44M\n",
            "vm.swapusage: total = 3072.00M  used = lots  free = 1837.44M\n",
            "vm.swapusage: total = 3072.00M  used = -1.00M  free = 1837.44M\n",
            "sysctl: unknown oid 'vm.swapusage'\n",
        ] {
            assert_eq!(parse_swap_used_mb(text), None, "{text:?}");
        }
    }
}
