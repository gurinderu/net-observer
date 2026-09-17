//! One line of sing-box's log, parsed (realm net-observer, node #140 — the
//! format as observed on sing-box 1.13.19):
//!
//! ```text
//! <utc-offset> <YYYY-MM-DD> <HH:MM:SS> <LEVEL> [<conn-id> <duration>]? <component>[<tag>]?: <message>
//! ```
//!
//! ANSI colour sequences (`ESC [ … m`) wrap the level and the connection id;
//! [`strip_ansi`] removes them before anything is parsed. The bracketed
//! connection field and the bracketed tag are both optional.

use std::borrow::Cow;

/// A log level as sing-box spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
    Panic,
}

impl Level {
    fn parse(token: &str) -> Option<Level> {
        Some(match token {
            "TRACE" => Level::Trace,
            "DEBUG" => Level::Debug,
            "INFO" => Level::Info,
            "WARN" => Level::Warn,
            "ERROR" => Level::Error,
            "FATAL" => Level::Fatal,
            "PANIC" => Level::Panic,
            _ => return None,
        })
    }

    /// Whether the line is one the collector classes and counts: WARN and
    /// above. INFO and DEBUG lines are neither.
    #[must_use]
    pub fn is_alert(self) -> bool {
        matches!(
            self,
            Level::Warn | Level::Error | Level::Fatal | Level::Panic
        )
    }
}

/// One parsed log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// The line's own timestamp with its UTC offset applied: epoch
    /// microseconds (whole seconds — the log carries no finer resolution).
    pub ts_us: i64,
    pub level: Level,
    /// The component before the colon: `network`, `dns/local`,
    /// `outbound/direct`, `connection`. Empty when the line carries none (a
    /// bare message such as `sing-box started (0.05s)`).
    pub component: String,
    /// The bracketed tag after the component (`direct-out` in
    /// `outbound/direct[direct-out]`), when present.
    pub tag: Option<String>,
    /// Everything after the component's colon, ANSI stripped.
    pub message: String,
}

/// Remove every ANSI CSI sequence (`ESC [ … <final byte>`), such as the
/// `ESC[31m` / `ESC[0m` colour pair around the level. Borrows when there is
/// nothing to strip.
#[must_use]
pub fn strip_ansi(s: &str) -> Cow<'_, str> {
    if !s.contains('\x1b') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(esc) = rest.find('\x1b') {
        out.push_str(&rest[..esc]);
        let after = &rest[esc + 1..];
        match after.strip_prefix('[') {
            Some(params) => {
                // The sequence ends at the first byte in the final-byte range.
                match params.find(|c: char| ('\x40'..='\x7e').contains(&c)) {
                    Some(end) => rest = &params[end + 1..],
                    None => rest = "",
                }
            }
            // A bare ESC is dropped on its own.
            None => rest = after,
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// Parse one raw line (ANSI included). `None` when the line does not open
/// with the `<offset> <date> <time> <LEVEL>` prefix — a continuation line, or
/// something that is not sing-box's log.
#[must_use]
pub fn parse_line(raw: &str) -> Option<LogLine> {
    let stripped = strip_ansi(raw);
    let line = stripped.trim_end_matches(['\r', '\n']);
    let mut parts = line.splitn(5, ' ');
    let offset_secs = parse_offset(parts.next()?)?;
    let (y, m, d) = parse_date(parts.next()?)?;
    let (hh, mm, ss) = parse_time(parts.next()?)?;
    let level = Level::parse(parts.next()?)?;
    let rest = parts.next().unwrap_or("").trim_start();

    let secs = days_from_civil(y, m, d) * 86_400
        + i64::from(hh) * 3_600
        + i64::from(mm) * 60
        + i64::from(ss)
        - offset_secs;
    let ts_us = secs * 1_000_000;

    // The optional connection field: `[<conn-id> <duration>]`.
    let rest = match rest.strip_prefix('[') {
        Some(after) => {
            let end = after.find(']')?;
            after[end + 1..].trim_start()
        }
        None => rest,
    };

    // The component is the first token, when it ends with a colon; a line
    // without one is a bare message.
    let (head, message) = rest.split_once(' ').unwrap_or((rest, ""));
    let (component, tag) = match head.strip_suffix(':') {
        Some(component) => match component.split_once('[') {
            Some((name, tag)) => (
                name.to_string(),
                Some(tag.strip_suffix(']').unwrap_or(tag).to_string()),
            ),
            None => (component.to_string(), None),
        },
        None => {
            return Some(LogLine {
                ts_us,
                level,
                component: String::new(),
                tag: None,
                message: rest.to_string(),
            });
        }
    };
    Some(LogLine {
        ts_us,
        level,
        component,
        tag,
        message: message.to_string(),
    })
}

/// `+0300` / `-0530` → seconds east of UTC.
fn parse_offset(token: &str) -> Option<i64> {
    let (sign, digits) = match token.as_bytes().first()? {
        b'+' => (1, &token[1..]),
        b'-' => (-1, &token[1..]),
        _ => return None,
    };
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hh: i64 = digits[..2].parse().ok()?;
    let mm: i64 = digits[2..].parse().ok()?;
    if hh > 23 || mm > 59 {
        return None;
    }
    Some(sign * (hh * 3_600 + mm * 60))
}

/// `YYYY-MM-DD`.
fn parse_date(token: &str) -> Option<(i64, u32, u32)> {
    let mut it = token.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// `HH:MM:SS`.
fn parse_time(token: &str) -> Option<(u32, u32, u32)> {
    let mut it = token.split(':');
    let hh: u32 = it.next()?.parse().ok()?;
    let mm: u32 = it.next()?.parse().ok()?;
    let ss: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some((hh, mm, ss))
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (Howard
/// Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two lines as observed (realm net-observer, node #140), colours
    /// included.
    const ERROR_LINE: &str = "+0300 2026-09-17 20:56:25 \x1b[31mERROR\x1b[0m [\x1b[38;5;38m179023894\x1b[0m 15.22s] outbound/direct[direct-out]: receive ICMP echo reply: read udp 0.0.0.0:0: i/o timeout";
    const INFO_LINE: &str = "+0300 2026-09-17 20:25:52 \x1b[36mINFO\x1b[0m network: updated default interface en0, index 11";

    #[test]
    fn strip_ansi_removes_the_colour_pairs_and_borrows_when_clean() {
        assert_eq!(
            strip_ansi(ERROR_LINE),
            "+0300 2026-09-17 20:56:25 ERROR [179023894 15.22s] outbound/direct[direct-out]: \
             receive ICMP echo reply: read udp 0.0.0.0:0: i/o timeout"
        );
        assert!(matches!(strip_ansi("plain"), Cow::Borrowed("plain")));
        assert_eq!(strip_ansi("a\x1b[0"), "a");
    }

    /// 2026-09-17 20:56:25 +0300 is 17:56:25 UTC, epoch 1789667785 (checked
    /// against `date -u -d`).
    #[test]
    fn parses_the_observed_error_line_with_its_connection_field() {
        let l = parse_line(ERROR_LINE).unwrap();
        assert_eq!(l.ts_us, 1_789_667_785_000_000);
        assert_eq!(l.level, Level::Error);
        assert_eq!(l.component, "outbound/direct");
        assert_eq!(l.tag.as_deref(), Some("direct-out"));
        assert_eq!(
            l.message,
            "receive ICMP echo reply: read udp 0.0.0.0:0: i/o timeout"
        );
        assert!(l.level.is_alert());
    }

    #[test]
    fn parses_the_observed_info_line_without_a_connection_field() {
        let l = parse_line(INFO_LINE).unwrap();
        assert_eq!(l.ts_us, 1_789_665_952_000_000);
        assert_eq!(l.level, Level::Info);
        assert_eq!(l.component, "network");
        assert_eq!(l.tag, None);
        assert_eq!(l.message, "updated default interface en0, index 11");
        assert!(!l.level.is_alert());
    }

    #[test]
    fn a_tagged_component_without_a_connection_field_parses() {
        let l = parse_line(
            "+0300 2026-09-17 20:25:52 WARN inbound/tun[0]: link icmp connection from 1.1.1.1 to 2.2.2.2: icmp is not supported by default outbound: vless-auto",
        )
        .unwrap();
        assert_eq!(l.level, Level::Warn);
        assert_eq!(l.component, "inbound/tun");
        assert_eq!(l.tag.as_deref(), Some("0"));
        assert!(l.message.ends_with("default outbound: vless-auto"));
    }

    #[test]
    fn a_bare_message_keeps_an_empty_component() {
        let l = parse_line("+0000 2026-03-01 00:00:00 INFO sing-box started (0.05s)").unwrap();
        assert_eq!(l.ts_us, 1_772_323_200_000_000);
        assert_eq!(l.component, "");
        assert_eq!(l.message, "sing-box started (0.05s)");
    }

    #[test]
    fn the_offset_is_applied_in_both_directions() {
        let east = parse_line("+0300 2026-09-17 20:25:52 INFO x: y").unwrap();
        let west = parse_line("-0300 2026-09-17 20:25:52 INFO x: y").unwrap();
        assert_eq!(east.ts_us, 1_789_665_952_000_000);
        assert_eq!(west.ts_us, 1_789_676_752_000_000 + 3 * 3_600 * 1_000_000);
        // A leap day, so the civil-date arithmetic is exercised past February.
        let leap = parse_line("+0000 2024-02-29 12:34:56 INFO x: y").unwrap();
        assert_eq!(leap.ts_us, 1_709_210_096_000_000);
    }

    #[test]
    fn lines_that_are_not_sing_box_log_lines_are_none() {
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("goroutine 1 [running]:"), None);
        assert_eq!(parse_line("+0300 2026-09-17 20:25:52 LOUD x: y"), None);
        assert_eq!(parse_line("0300 2026-09-17 20:25:52 INFO x: y"), None);
        assert_eq!(parse_line("+0300 2026-13-17 20:25:52 INFO x: y"), None);
        assert_eq!(parse_line("+0300 2026-09-17 25:25:52 INFO x: y"), None);
    }
}
