//! Static [`META`], the pure [`fold_lines`] and the [`SingboxLogCollector`]
//! that wires a [`TailSource`] into the [`Collector`] abstraction the daemon
//! drives (realm net-observer, node #141).

use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::{Sample, SingboxLogClass, SingboxLogSample};

use crate::classify::classify;
use crate::parse::parse_line;
use crate::tail::{LogTail, TailRead};

/// Static metadata for the `singbox-log` collector. The log it reads is the
/// launchd-managed one of this deployment's sing-box, which runs on macOS.
pub const META: CollectorMeta = CollectorMeta {
    name: "singbox-log",
    supported_os: &[Os::MacOs],
};

/// The longest `sample_message` a row carries, in characters.
const SAMPLE_MESSAGE_MAX: usize = 200;

/// The substrings a line must carry to be parsed at all — a byte scan before
/// any parsing (and, in the tail, before any allocation), since the log is
/// DEBUG-level and large: a WARN-or-above level token, or one of the two
/// INFO lines that are evidence (a restart, and the default interface taken
/// — realm net-observer, node #141).
const ADMIT_TOKENS: [&[u8]; 6] = [
    b"ERROR",
    b"WARN",
    b"FATAL",
    b"PANIC",
    b"sing-box started",
    b"updated default interface",
];

/// How many of the collector's own intervals a line may be older than the
/// tick that reads it before it is dropped as stale — and how many intervals
/// of silence between two reads make the tail skip its backlog rather than
/// read it (both: a pause's lines belong to the pause, not to the tick after
/// it; the observing edge brackets the pause).
const STALE_INTERVALS: u32 = 2;

/// Whether a raw line is worth parsing: it carries one of [`ADMIT_TOKENS`].
#[must_use]
pub fn admits(raw: &[u8]) -> bool {
    ADMIT_TOKENS
        .iter()
        .any(|t| raw.windows(t.len()).any(|w| w == *t))
}

/// Where the collector's lines come from: the real [`LogTail`], or a scripted
/// fake in tests. `read_new` is `&mut self` because a tail advances; the
/// collector holds it behind a mutex, since `Collector::collect` takes
/// `&self`.
pub trait TailSource: Send {
    /// The admitted complete lines appended since the previous call, with
    /// what the tail skipped or dropped on the way; an error when the log
    /// could not be read this time. `now` is the caller's monotonic clock.
    fn read_new(&mut self, now: Instant) -> io::Result<TailRead>;
    /// How many rotations the source has followed so far.
    fn rotations(&self) -> u32;
}

impl TailSource for LogTail {
    fn read_new(&mut self, now: Instant) -> io::Result<TailRead> {
        LogTail::read_new(self, now)
    }
    fn rotations(&self) -> u32 {
        LogTail::rotations(self)
    }
}

/// The rows one tick folded, and the lines it dropped as stale.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Folded {
    /// One row per `(class, node)`, in first-seen order.
    pub rows: Vec<SingboxLogSample>,
    /// Admitted lines whose own timestamp was older than the tick allows.
    pub stale: u32,
}

/// The `singbox-log` collector: sing-box's own ERROR/WARN lines since the
/// last tick, classed and counted.
///
/// Passive by construction: it reads a world-readable local file and puts
/// nothing on the wire, so it is not a `types::EmissionClass` and takes no
/// `ProbingState` — like `host`, `wifi` and `connections` it keeps reading in
/// the passive tier, which is exactly where its evidence is needed (realm
/// net-observer, node #141).
///
/// The read is synchronous inside the async `collect`: the bytes since the
/// last tick are a local file's tail, a bounded read of milliseconds.
pub struct SingboxLogCollector<T: TailSource = LogTail> {
    tail: Mutex<T>,
    path: PathBuf,
    interval: Duration,
}

impl SingboxLogCollector<LogTail> {
    /// Attach to the log at `path` (at its end — nothing already there is
    /// read) and tick every `interval`. A log that cannot be opened now is
    /// retried every tick, each such tick an `Unreadable` row.
    pub fn new(path: impl Into<PathBuf>, interval: Duration) -> Self {
        let path = path.into();
        let tail = LogTail::open_at_end(&path, interval * STALE_INTERVALS, admits);
        Self::with_tail(tail, path, interval)
    }
}

impl<T: TailSource> SingboxLogCollector<T> {
    /// Construct over any [`TailSource`]; `path` names the log for the
    /// preflight check and the rows' log lines.
    pub fn with_tail(tail: T, path: PathBuf, interval: Duration) -> Self {
        Self {
            tail: Mutex::new(tail),
            path,
            interval,
        }
    }

    /// The one `Unreadable` row a tick that could not read the log writes:
    /// `count: 0`, the I/O error as its message. SKIP's spirit — the absence
    /// of a reading is itself recorded, never silence.
    fn unreadable(&self, ts_us: i64, error: &dyn std::fmt::Display) -> Vec<Sample> {
        vec![Sample::SingboxLog(SingboxLogSample {
            ts_us,
            class: SingboxLogClass::Unreadable,
            count: 0,
            node: None,
            sample_message: Some(truncate(&format!("{}: {error}", self.path.display()))),
        })]
    }
}

impl<T: TailSource> Collector for SingboxLogCollector<T> {
    fn meta(&self) -> &'static CollectorMeta {
        &META
    }

    fn source(&self) -> Source {
        Source::Interval(self.interval)
    }

    /// `Ready` iff the log exists at its path right now. The daemon logs a
    /// failed preflight (rate-limited) and takes [`Collector::skip`] instead
    /// of [`Collector::collect`], so a log that is absent for hours costs one
    /// warning, not one per tick — while every tick still lands as a row.
    async fn preflight(&self) -> Readiness {
        match std::fs::metadata(&self.path) {
            Ok(_) => Readiness::Ready,
            Err(e) => Readiness::Unavailable(format!("{}: {e}", self.path.display())),
        }
    }

    async fn collect(&self, ts_us: i64) -> Vec<Sample> {
        let (read, rotations) = {
            let mut tail = self.tail.lock().unwrap_or_else(PoisonError::into_inner);
            let read = tail.read_new(Instant::now());
            (read, tail.rotations())
        };
        let read = match read {
            Ok(read) => read,
            Err(e) => {
                tracing::warn!(collector = META.name, path = %self.path.display(), error = %e, "log unreadable this tick");
                return self.unreadable(ts_us, &e);
            }
        };
        if let Some((gap, skipped)) = read.reattached {
            tracing::info!(
                collector = META.name,
                gap_s = gap.as_secs(),
                skipped_bytes = skipped,
                "sing-box log: re-attached at end after {} s gap, {skipped} skipped",
                gap.as_secs()
            );
        }
        if read.rotated {
            tracing::info!(
                collector = META.name,
                rotations,
                "sing-box log: rotated; continuing from the start of the file"
            );
        }
        let oldest_us =
            ts_us.saturating_sub(interval_us(self.interval) * i64::from(STALE_INTERVALS));
        let folded = fold_lines(ts_us, oldest_us, read.lines.iter().map(String::as_str));
        if folded.stale > 0 || read.dropped_partials > 0 {
            tracing::info!(
                collector = META.name,
                stale_lines = folded.stale,
                dropped_partials = read.dropped_partials,
                "sing-box log: dropped lines older than {STALE_INTERVALS} intervals and partial buffers"
            );
        }
        tracing::debug!(
            collector = META.name,
            lines = read.lines.len(),
            classes = folded.rows.len(),
            rotations,
            "tick"
        );
        folded.rows.into_iter().map(Sample::SingboxLog).collect()
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        match std::fs::metadata(&self.path) {
            Err(e) => self.unreadable(ts_us, &e),
            Ok(_) => self.unreadable(ts_us, &"log not readable this tick"),
        }
    }
}

/// An interval as microseconds, saturating.
fn interval_us(interval: Duration) -> i64 {
    i64::try_from(interval.as_micros()).unwrap_or(i64::MAX)
}

/// Fold the raw lines of one tick into one [`SingboxLogSample`] per
/// `(class, node)`, in first-seen order, each stamped `ts_us` and carrying the
/// first message of its class (ANSI stripped, at most 200 characters). Lines
/// without an [`ADMIT_TOKENS`] substring are skipped before parsing; lines
/// that do not parse, or parse to an INFO/DEBUG line that is no class, are
/// skipped after. A line whose own timestamp is older than `oldest_us` is not
/// this tick's evidence — a backlog a sleep left behind — and is counted as
/// stale instead of stamped with the tick. No such line, no rows.
pub fn fold_lines<'a>(
    ts_us: i64,
    oldest_us: i64,
    lines: impl IntoIterator<Item = &'a str>,
) -> Folded {
    let mut folded = Folded::default();
    for raw in lines {
        if !admits(raw.as_bytes()) {
            continue;
        }
        let Some(line) = parse_line(raw) else {
            continue;
        };
        if line.ts_us < oldest_us {
            folded.stale = folded.stale.saturating_add(1);
            continue;
        }
        let Some((class, node)) = classify(&line) else {
            continue;
        };
        match folded
            .rows
            .iter_mut()
            .find(|r| r.class == class && r.node == node)
        {
            Some(r) => r.count = r.count.saturating_add(1),
            None => {
                // The message keeps its component so an `other` row says
                // which subsystem spoke, not only what it said.
                let message = match (line.component.as_str(), &line.tag) {
                    ("", _) => line.message,
                    (c, Some(tag)) => format!("{c}[{tag}]: {}", line.message),
                    (c, None) => format!("{c}: {}", line.message),
                };
                folded.rows.push(SingboxLogSample {
                    ts_us,
                    class,
                    count: 1,
                    node,
                    sample_message: Some(truncate(&message)),
                });
            }
        }
    }
    folded
}

/// At most [`SAMPLE_MESSAGE_MAX`] characters, cut on a character boundary.
fn truncate(s: &str) -> String {
    match s.char_indices().nth(SAMPLE_MESSAGE_MAX) {
        Some((cut, _)) => s[..cut].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;

    const NO_ROUTE: &str = "+0300 2026-09-17 20:56:25 \x1b[31mERROR\x1b[0m [\x1b[38;5;38m1\x1b[0m 0ms] connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: dial tcp 1.2.3.4:443: no route to internet";
    const NO_ROUTE_OTHER_NODE: &str = "+0300 2026-09-17 20:56:26 ERROR [2 0ms] connection: open connection to 5.6.7.8:443 using outbound/vless[vless-out-2]: dial tcp 5.6.7.8:443: no route to internet";
    const NO_IFACE: &str = "+0300 2026-09-17 20:56:26 ERROR network: missing default interface";
    const INFO: &str =
        "+0300 2026-09-17 20:25:52 \x1b[36mINFO\x1b[0m inbound/tun[0]: tun started at utun6";
    const STARTED: &str = "+0300 2026-09-17 20:25:52 \x1b[36mINFO\x1b[0m sing-box started (0.05s)";
    const IFACE_UPDATED: &str = "+0300 2026-09-17 20:25:52 \x1b[36mINFO\x1b[0m network: updated default interface en0, index 11";
    const DEBUG_WITH_TOKEN: &str =
        "+0300 2026-09-17 20:25:52 DEBUG [3 0ms] connection: an ERROR in a debug line is not one";

    /// 2026-09-17T17:56:25Z — `NO_ROUTE`'s own instant — as the tick.
    const AT: i64 = 1_789_667_785_000_000;
    const TICK_US: i64 = 15_000_000;

    fn fold<'a>(ts_us: i64, lines: impl IntoIterator<Item = &'a str>) -> Vec<SingboxLogSample> {
        let folded = fold_lines(ts_us, i64::MIN, lines);
        assert_eq!(folded.stale, 0);
        folded.rows
    }

    #[test]
    fn admits_scans_the_bytes_for_the_tokens() {
        assert!(admits(NO_ROUTE.as_bytes()));
        assert!(admits(STARTED.as_bytes()));
        assert!(admits(IFACE_UPDATED.as_bytes()));
        assert!(
            admits(DEBUG_WITH_TOKEN.as_bytes()),
            "the scan is cheap; the parse decides"
        );
        assert!(!admits(INFO.as_bytes()));
        assert!(!admits(b""));
    }

    #[test]
    fn fold_counts_per_class_and_node_and_keeps_the_first_message() {
        let rows = fold(
            42,
            [
                NO_ROUTE,
                INFO,
                NO_ROUTE_OTHER_NODE,
                NO_ROUTE,
                NO_IFACE,
                DEBUG_WITH_TOKEN,
            ],
        );
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0].ts_us, 42);
        assert_eq!(rows[0].class, SingboxLogClass::NoRoute);
        assert_eq!(rows[0].node.as_deref(), Some("vless-out-6"));
        assert_eq!(rows[0].count, 2);
        assert_eq!(
            rows[0].sample_message.as_deref(),
            Some(
                "connection: open connection to 1.2.3.4:443 using outbound/vless[vless-out-6]: \
                 dial tcp 1.2.3.4:443: no route to internet"
            )
        );
        assert_eq!(rows[1].class, SingboxLogClass::NoRoute);
        assert_eq!(rows[1].node.as_deref(), Some("vless-out-2"));
        assert_eq!(rows[1].count, 1);
        assert_eq!(rows[2].class, SingboxLogClass::NoDefaultIface);
        assert_eq!(rows[2].node, None);
        assert_eq!(
            rows[2].sample_message.as_deref(),
            Some("network: missing default interface")
        );
    }

    /// Absence of errors is the healthy state: no rows, not an empty row.
    #[test]
    fn fold_of_info_and_debug_only_is_empty() {
        assert!(fold(1, [INFO, DEBUG_WITH_TOKEN, "", "garbage"]).is_empty());
    }

    /// The two INFO lines that are evidence pass the byte scan and fold like
    /// any class: a restart with its message, the interface taken in `node`.
    #[test]
    fn fold_admits_the_restart_and_default_iface_lines_at_info() {
        let rows = fold(7, [STARTED, IFACE_UPDATED, INFO]);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(rows[0].class, SingboxLogClass::Started);
        assert_eq!(rows[0].node, None);
        assert_eq!(
            rows[0].sample_message.as_deref(),
            Some("sing-box started (0.05s)")
        );
        assert_eq!(rows[1].class, SingboxLogClass::DefaultIfaceUpdated);
        assert_eq!(rows[1].node.as_deref(), Some("en0"));
        assert_eq!(
            rows[1].sample_message.as_deref(),
            Some("network: updated default interface en0, index 11")
        );
    }

    #[test]
    fn fold_truncates_a_long_message_on_a_char_boundary() {
        let long = format!(
            "+0300 2026-09-17 20:56:26 ERROR inbound/tun[0]: {}",
            "é".repeat(400)
        );
        let rows = fold(1, [long.as_str()]);
        let msg = rows[0].sample_message.as_deref().unwrap();
        assert_eq!(msg.chars().count(), SAMPLE_MESSAGE_MAX);
        assert!(msg.starts_with("inbound/tun[0]: é"));
    }

    /// The belt for a sleep that did not stop the tick: an admitted line whose
    /// own instant is older than the tick allows is dropped and counted, not
    /// stamped with the tick; a line exactly at the horizon, or newer, stays.
    #[test]
    fn fold_drops_and_counts_lines_older_than_the_horizon() {
        // NO_IFACE's instant is 20:56:26+03:00, one second after `AT`.
        let folded = fold_lines(AT + 31_000_000, AT + 1_000_000, [NO_ROUTE, NO_IFACE, INFO]);
        assert_eq!(folded.stale, 1, "{folded:?}");
        assert_eq!(folded.rows.len(), 1);
        assert_eq!(folded.rows[0].class, SingboxLogClass::NoDefaultIface);
        assert_eq!(folded.rows[0].ts_us, AT + 31_000_000);

        let folded = fold_lines(AT, AT - 2 * TICK_US, [NO_ROUTE, NO_IFACE]);
        assert_eq!(folded.stale, 0);
        assert_eq!(folded.rows.len(), 2);
    }

    /// A scripted tail: each `read_new` pops the next answer.
    struct FakeTail {
        script: VecDeque<io::Result<TailRead>>,
        rotations: u32,
    }

    impl TailSource for FakeTail {
        fn read_new(&mut self, _: Instant) -> io::Result<TailRead> {
            self.script
                .pop_front()
                .unwrap_or_else(|| Ok(TailRead::default()))
        }
        fn rotations(&self) -> u32 {
            self.rotations
        }
    }

    fn collector(script: Vec<io::Result<TailRead>>) -> SingboxLogCollector<FakeTail> {
        SingboxLogCollector::with_tail(
            FakeTail {
                script: script.into(),
                rotations: 0,
            },
            PathBuf::from("/var/log/sing-box.log"),
            Duration::from_secs(15),
        )
    }

    fn lines(ls: &[&str]) -> io::Result<TailRead> {
        Ok(TailRead {
            lines: ls.iter().map(|l| l.to_string()).collect(),
            ..TailRead::default()
        })
    }

    fn classes(samples: &[Sample]) -> Vec<(i64, SingboxLogClass, u32)> {
        samples
            .iter()
            .map(|s| match s {
                Sample::SingboxLog(r) => (r.ts_us, r.class, r.count),
                other => panic!("expected a sing-box log sample, got {other:?}"),
            })
            .collect()
    }

    #[tokio::test]
    async fn a_tick_with_alert_lines_collects_one_sample_per_class_and_node() {
        let c = collector(vec![lines(&[NO_ROUTE, NO_IFACE, INFO]), lines(&[INFO])]);
        assert_eq!(
            classes(&c.collect(AT).await),
            vec![
                (AT, SingboxLogClass::NoRoute, 1),
                (AT, SingboxLogClass::NoDefaultIface, 1)
            ]
        );
        // A tick with nothing at WARN or above writes nothing.
        assert!(c.collect(AT + TICK_US).await.is_empty());
    }

    /// The tick after a pause: the tail re-attached at the end and returned
    /// no lines — the backlog is the pause's, not this tick's — and a line
    /// older than two intervals slipping through a normal read is dropped.
    #[tokio::test]
    async fn a_reattached_read_and_a_stale_line_write_nothing_for_them() {
        let c = collector(vec![
            Ok(TailRead {
                reattached: Some((Duration::from_secs(3600), 1 << 20)),
                ..TailRead::default()
            }),
            lines(&[NO_ROUTE, NO_IFACE]),
        ]);
        assert!(c.collect(AT + 3600 * 1_000_000).await.is_empty());
        // The next normal tick sits 10 min past the lines' own instants.
        assert!(c.collect(AT + 600 * 1_000_000).await.is_empty());
    }

    /// SKIP, never silence: a tick whose read failed leaves one row saying so.
    #[tokio::test]
    async fn a_failed_read_collects_the_unreadable_row() {
        let c = collector(vec![Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permission denied",
        ))]);
        let samples = c.collect(7).await;
        let [Sample::SingboxLog(r)] = samples.as_slice() else {
            panic!("expected one row, got {samples:?}");
        };
        assert_eq!(r.ts_us, 7);
        assert_eq!(r.class, SingboxLogClass::Unreadable);
        assert_eq!(r.count, 0);
        assert_eq!(r.node, None);
        assert_eq!(
            r.sample_message.as_deref(),
            Some("/var/log/sing-box.log: permission denied")
        );
    }

    /// The real tail on a missing log: preflight says so, `skip` writes the
    /// `Unreadable` row with the error, and once the file appears the
    /// collector reads what is appended after it.
    #[tokio::test]
    async fn a_missing_log_is_unavailable_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sing-box.log");
        let c = Arc::new(SingboxLogCollector::new(&path, Duration::from_secs(15)));
        assert!(!c.preflight().await.is_ready());
        let skipped = c.skip(1);
        let [Sample::SingboxLog(r)] = skipped.as_slice() else {
            panic!("expected one row");
        };
        assert_eq!(r.class, SingboxLogClass::Unreadable);
        assert!(
            r.sample_message
                .as_deref()
                .is_some_and(|m| m.starts_with(path.to_str().unwrap())),
            "{r:?}"
        );
        // The read path reports the same absence as a row, not a panic.
        let collected = c.collect(AT).await;
        let [Sample::SingboxLog(r)] = collected.as_slice() else {
            panic!("expected one row");
        };
        assert_eq!(r.class, SingboxLogClass::Unreadable);

        std::fs::write(&path, format!("{NO_ROUTE}\n")).unwrap();
        assert!(c.preflight().await.is_ready());
        assert!(
            c.collect(AT + TICK_US).await.is_empty(),
            "attached at the end: the pre-existing line is not read"
        );
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, format!("{NO_IFACE}\n").as_bytes()).unwrap();
        let samples = c.collect(AT + 2 * TICK_US).await;
        let [Sample::SingboxLog(r)] = samples.as_slice() else {
            panic!("expected one row, got {samples:?}");
        };
        assert_eq!(r.class, SingboxLogClass::NoDefaultIface);
        assert_eq!(r.ts_us, AT + 2 * TICK_US);
    }
}
