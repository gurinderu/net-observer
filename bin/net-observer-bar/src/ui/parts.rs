//! Small shared elements and formatting helpers used by every window.

use std::time::{SystemTime, UNIX_EPOCH};

use gpui::prelude::*;
use gpui::{Rgba, SharedString, div, px, rgb};

use super::theme::{MENU_SEPARATOR_H, Theme};

// ---- small element helpers -------------------------------------------------

/// A hairline separator between sections — a 1px full-width rule, no borders.
pub(crate) fn separator(theme: Theme) -> impl IntoElement {
    div()
        // Test handle only (no-op without gpui's `test-support`): the hairline
        // has no other identity, and its whole contract is a height a headless
        // test can read back.
        .debug_selector(|| "separator".into())
        .h(px(MENU_SEPARATOR_H))
        // A hairline that is allowed to shrink is a hairline that disappears in
        // a tight column.
        .flex_none()
        .w_full()
        .bg(rgb(theme.separator))
}

/// One label→value list row: a muted label on the left, a colored value on the
/// right (the Tailscale-style clean list, not a bordered card).
///
/// Both sides take anything convertible into a [`SharedString`], so a `&'static
/// str` label costs no allocation at all and an owned `String` local is *moved*
/// in rather than copied — a render runs this once per row, every tick.
pub(crate) fn row<K: Into<SharedString>, V: Into<SharedString>>(
    key: K,
    value: V,
    value_color: Rgba,
    theme: Theme,
) -> impl IntoElement {
    let key: SharedString = key.into();
    let value: SharedString = value.into();
    div()
        .flex()
        .items_center()
        .justify_between()
        .py_1()
        .child(div().text_color(rgb(theme.muted)).child(key))
        .child(div().text_color(value_color).child(value))
}

/// Current wall-clock time in microseconds since the Unix epoch.
pub fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// A short "12s ago" / "3m ago" string from a microsecond timestamp.
///
/// `pub(crate)` so the map's uplink cards date a sighting in the same words the
/// rest of the panel does, rather than growing a second age formatter.
pub(crate) fn age_str(ts_us: i64, now_us: i64) -> String {
    if ts_us <= 0 {
        return "-".to_string();
    }
    let secs = (now_us - ts_us) / 1_000_000;
    if secs < 0 {
        return "just now".to_string();
    }
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_str_buckets() {
        let now = 1_000_000_000i64;
        assert_eq!(age_str(0, now), "-");
        assert_eq!(age_str(now, now), "0s ago");
        assert_eq!(age_str(now - 5_000_000, now), "5s ago");
        assert_eq!(age_str(now - 120_000_000, now), "2m ago");
        assert_eq!(age_str(now + 5_000_000, now), "just now");
    }
}
