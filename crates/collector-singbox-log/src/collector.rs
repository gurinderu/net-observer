//! Static [`META`], the pure [`fold_lines`] and the [`SingboxLogCollector`]
//! that wires a [`TailSource`] into the [`Collector`] abstraction the daemon
//! drives (realm net-observer, node #141).

use std::io;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use collector_core::{Collector, CollectorMeta, Os, Readiness, Source};
use types::{Sample, SingboxLogClass, SingboxLogSample};

use crate::classify::classify;
use crate::parse::parse_line;
use crate::tail::LogTail;

/// Static metadata for the `singbox-log` collector. The log it reads is the
/// launchd-managed one of this deployment's sing-box, which runs on macOS.
pub const META: CollectorMeta = CollectorMeta {
    name: "singbox-log",
    supported_os: &[Os::MacOs],
};

/// The longest `sample_message` a row carries, in characters.
const SAMPLE_MESSAGE_MAX: usize = 200;

/// The level tokens a line must carry to be parsed at all — a byte scan
/// before any parsing, since the log is DEBUG-level and large.
const ALERT_TOKENS: [&str; 4] = ["ERROR", "WARN", "FATAL", "PANIC"];

/// Where the collector's lines come from: the real [`LogTail`], or a scripted
/// fake in tests. `read_new` is `&mut self` because a tail advances; the
/// collector holds it behind a mutex, since `Collector::collect` takes
/// `&self`.
pub trait TailSource: Send {
    /// The complete lines appended since the previous call; an error when
    /// the log could not be read this time.
    fn read_new(&mut self) -> io::Result<Vec<String>>;
    /// How many rotations the source has followed so far.
    fn rotations(&self) -> u32;
}

impl TailSource for LogTail {
    fn read_new(&mut self) -> io::Result<Vec<String>> {
        LogTail::read_new(self)
    }
    fn rotations(&self) -> u32 {
        LogTail::rotations(self)
    }
}

/// The tail and, beside it, the rotation count already reported — so a
/// rotation is logged once, on the tick that saw it.
struct State<T> {
    tail: T,
    rotations_reported: u32,
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
    state: Mutex<State<T>>,
    path: PathBuf,
    interval: Duration,
}

impl SingboxLogCollector<LogTail> {
    /// Attach to the log at `path` (at its end — nothing already there is
    /// read) and tick every `interval`. A log that cannot be opened now is
    /// retried every tick, each such tick an `Unreadable` row.
    pub fn new(path: impl Into<PathBuf>, interval: Duration) -> Self {
        let path = path.into();
        Self::with_tail(LogTail::open_at_end(&path), path, interval)
    }
}

impl<T: TailSource> SingboxLogCollector<T> {
    /// Construct over any [`TailSource`]; `path` names the log for the
    /// preflight check and the rows' log lines.
    pub fn with_tail(tail: T, path: PathBuf, interval: Duration) -> Self {
        Self {
            state: Mutex::new(State {
                tail,
                rotations_reported: 0,
            }),
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
        let (read, rotations, reported) = {
            let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let read = s.tail.read_new();
            let rotations = s.tail.rotations();
            let reported = std::mem::replace(&mut s.rotations_reported, rotations);
            (read, rotations, reported)
        };
        if rotations != reported {
            tracing::info!(
                collector = META.name,
                rotations,
                "the log was rotated; following the new file from its start (the old file's tail since the previous tick is lost)"
            );
        }
        let lines = match read {
            Ok(lines) => lines,
            Err(e) => {
                tracing::warn!(collector = META.name, path = %self.path.display(), error = %e, "log unreadable this tick");
                return self.unreadable(ts_us, &e);
            }
        };
        let rows = fold_lines(ts_us, lines.iter().map(String::as_str));
        tracing::debug!(
            collector = META.name,
            lines = lines.len(),
            classes = rows.len(),
            rotations,
            "tick"
        );
        rows.into_iter().map(Sample::SingboxLog).collect()
    }

    fn skip(&self, ts_us: i64) -> Vec<Sample> {
        match std::fs::metadata(&self.path) {
            Err(e) => self.unreadable(ts_us, &e),
            Ok(_) => self.unreadable(ts_us, &"log not readable this tick"),
        }
    }
}

/// Fold the raw lines of one tick into one [`SingboxLogSample`] per
/// `(class, node)`, in first-seen order, each stamped `ts_us` and carrying the
/// first message of its class (ANSI stripped, at most 200 characters). Lines
/// without a WARN-or-above level token are skipped before parsing; lines that
/// do not parse, or parse to INFO/DEBUG, are skipped after. No alert line, no
/// rows.
pub fn fold_lines<'a>(
    ts_us: i64,
    lines: impl IntoIterator<Item = &'a str>,
) -> Vec<SingboxLogSample> {
    let mut rows: Vec<SingboxLogSample> = Vec::new();
    for raw in lines {
        if !ALERT_TOKENS.iter().any(|t| raw.contains(t)) {
            continue;
        }
        let Some(line) = parse_line(raw) else {
            continue;
        };
        let Some((class, node)) = classify(&line) else {
            continue;
        };
        match rows.iter_mut().find(|r| r.class == class && r.node == node) {
            Some(r) => r.count = r.count.saturating_add(1),
            None => {
                // The message keeps its component so an `other` row says
                // which subsystem spoke, not only what it said.
                let message = match (line.component.as_str(), &line.tag) {
                    ("", _) => line.message,
                    (c, Some(tag)) => format!("{c}[{tag}]: {}", line.message),
                    (c, None) => format!("{c}: {}", line.message),
                };
                rows.push(SingboxLogSample {
                    ts_us,
                    class,
                    count: 1,
                    node,
                    sample_message: Some(truncate(&message)),
                });
            }
        }
    }
    rows
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
    const INFO: &str = "+0300 2026-09-17 20:25:52 \x1b[36mINFO\x1b[0m network: updated default interface en0, index 11";
    const DEBUG_WITH_TOKEN: &str =
        "+0300 2026-09-17 20:25:52 DEBUG [3 0ms] connection: an ERROR in a debug line is not one";

    #[test]
    fn fold_counts_per_class_and_node_and_keeps_the_first_message() {
        let rows = fold_lines(
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
        assert!(fold_lines(1, [INFO, DEBUG_WITH_TOKEN, "", "garbage"]).is_empty());
    }

    #[test]
    fn fold_truncates_a_long_message_on_a_char_boundary() {
        let long = format!(
            "+0300 2026-09-17 20:56:26 ERROR inbound/tun[0]: {}",
            "é".repeat(400)
        );
        let rows = fold_lines(1, [long.as_str()]);
        let msg = rows[0].sample_message.as_deref().unwrap();
        assert_eq!(msg.chars().count(), SAMPLE_MESSAGE_MAX);
        assert!(msg.starts_with("inbound/tun[0]: é"));
    }

    /// A scripted tail: each `read_new` pops the next answer.
    struct FakeTail {
        script: VecDeque<io::Result<Vec<String>>>,
        rotations: u32,
    }

    impl TailSource for FakeTail {
        fn read_new(&mut self) -> io::Result<Vec<String>> {
            self.script.pop_front().unwrap_or_else(|| Ok(Vec::new()))
        }
        fn rotations(&self) -> u32 {
            self.rotations
        }
    }

    fn collector(script: Vec<io::Result<Vec<String>>>) -> SingboxLogCollector<FakeTail> {
        SingboxLogCollector::with_tail(
            FakeTail {
                script: script.into(),
                rotations: 0,
            },
            PathBuf::from("/var/log/sing-box.log"),
            Duration::from_secs(15),
        )
    }

    fn lines(ls: &[&str]) -> io::Result<Vec<String>> {
        Ok(ls.iter().map(|l| l.to_string()).collect())
    }

    #[tokio::test]
    async fn a_tick_with_alert_lines_collects_one_sample_per_class_and_node() {
        let c = collector(vec![lines(&[NO_ROUTE, NO_IFACE, INFO]), lines(&[INFO])]);
        let samples = c.collect(42).await;
        let classes: Vec<_> = samples
            .iter()
            .map(|s| match s {
                Sample::SingboxLog(r) => (r.ts_us, r.class, r.count),
                other => panic!("expected a sing-box log sample, got {other:?}"),
            })
            .collect();
        assert_eq!(
            classes,
            vec![
                (42, SingboxLogClass::NoRoute, 1),
                (42, SingboxLogClass::NoDefaultIface, 1)
            ]
        );
        // A tick with nothing at WARN or above writes nothing.
        assert!(c.collect(43).await.is_empty());
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
        let collected = c.collect(2).await;
        let [Sample::SingboxLog(r)] = collected.as_slice() else {
            panic!("expected one row");
        };
        assert_eq!(r.class, SingboxLogClass::Unreadable);

        std::fs::write(&path, format!("{NO_ROUTE}\n")).unwrap();
        assert!(c.preflight().await.is_ready());
        assert!(
            c.collect(3).await.is_empty(),
            "attached at the end: the pre-existing line is not read"
        );
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, format!("{NO_IFACE}\n").as_bytes()).unwrap();
        let samples = c.collect(4).await;
        let [Sample::SingboxLog(r)] = samples.as_slice() else {
            panic!("expected one row, got {samples:?}");
        };
        assert_eq!(r.class, SingboxLogClass::NoDefaultIface);
        assert_eq!(r.ts_us, 4);
    }
}
