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

// ---- one vocabulary of time ------------------------------------------------
//
// The rule, stated once for every window (realm net-observer, node #48):
//
// * A reading that is **presented** — the moment a scan was taken, a picture
//   assembled, an event logged — is dated **absolutely** ([`clock`]). That is
//   the number the operator quotes in an argument, and "2m ago" cannot be
//   quoted: it decays while it is being read.
// * A reading whose point is **freshness** — is this still true, how stale is
//   this sighting — is dated **relatively** ([`age_str`]).
// * Wherever a picture is glued from more than one reading, the divergence of
//   their moments is NAMED as soon as they are no longer one moment
//   ([`moments_diverge`]). Pairing two readings silently computes the overlap
//   against a state we had already left.
//
// The rule is one; the sentence is the window's own. These helpers hand a
// window the words, never the layout.

/// Which dating a reading gets. See the rule above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dating {
    /// The reading is presented as *what was seen, and when* — absolute.
    Presented,
    /// The reading is shown to answer *how stale is this* — relative.
    Freshness,
}

/// Date one microsecond stamp by the rule above. The window chooses the
/// [`Dating`]; the words come from here, so two windows cannot spell the same
/// kind of moment differently.
pub(crate) fn dated(kind: Dating, ts_us: i64, now_us: i64) -> String {
    match kind {
        Dating::Presented => clock(ts_us),
        Dating::Freshness => age_str(ts_us, now_us),
    }
}

/// Wall-clock time of a microsecond stamp, in the system zone, as `HH:MM:SS`.
///
/// Falls back to `--:--:--` on an out-of-range stamp; never panics. One clock
/// for every window: a format change here reaches all of them.
pub(crate) fn clock(ts_us: i64) -> String {
    match jiff::Timestamp::from_microsecond(ts_us) {
        Ok(ts) => {
            let z = ts.to_zoned(jiff::tz::TimeZone::system());
            format!("{:02}:{:02}:{:02}", z.hour(), z.minute(), z.second())
        }
        Err(_) => "--:--:--".to_string(),
    }
}

/// A microsecond span as a short duration, for saying how far apart two
/// readings are without making the reader do arithmetic.
pub(crate) fn gap_label(us: i64) -> String {
    let secs = us / 1_000_000;
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 5400 {
        format!("{}m", secs / 60)
    } else if secs < 172_800 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86_400)
    }
}

/// How far two readings may lie apart and still be shown as one moment: one
/// minute — the span of ordinary roaming, and of one collector tick.
pub(crate) const SAME_MOMENT_US: i64 = 60_000_000;

/// The one divergence rule. `Some(gap)` — already worded by [`gap_label`] —
/// when two readings are too far apart to be shown as one moment; `None` when
/// they may be paired silently.
///
/// Both arguments must be moments that exist: whether a reading HAS a moment is
/// the caller's question (it holds the `Option`, or the sample's own "no stamp"
/// state), and answering it here would silently swallow a divergence rather
/// than name it — the one thing this rule exists to prevent.
pub(crate) fn moments_diverge(a_us: i64, b_us: i64) -> Option<String> {
    let gap = (a_us - b_us).abs();
    (gap > SAME_MOMENT_US).then(|| gap_label(gap))
}

/// The type size of a provenance line — `type.micro` of the documented scale
/// (`docs/design/visual-system.md` §3.1: "timestamps in dense rows"). Every
/// window dates its picture at the same size, or the same fact reads as two
/// different kinds of fact.
pub(crate) const PROVENANCE_TEXT: f32 = 11.0;

// ---- markers whose explanation is a hover hint ------------------------------

/// The prefix every hint's hover chip carries in its debug selector, so a
/// headless test can name a hint by the words it actually shows.
///
/// The chip is built on hover and prepainted into the window's deferred layer,
/// and gpui's test platform runs that layout for real. `debug_bounds` is the
/// only query a headless test has and it matches on the selector string — so
/// putting the hint's *text* into the selector is what makes the sentence
/// observable at all, rather than merely the fact that some hint exists.
pub(crate) const HINT_TIP_SELECTOR: &str = "hint-tip:";

/// The type size of a marker and of its hover chip.
pub(crate) const HINT_TEXT: f32 = 11.0;

/// A short visible marker whose long explanation is a hover hint.
///
/// The split this helper exists to enforce: `marker` is on the screen always and
/// carries the *status of the claim* — it is what tells the reader that a number
/// is a hypothesis; `tip` carries only the elaboration: why the hypothesis is
/// weak, what had to be assumed, what the platform does not report. A bare
/// number whose status lives only in `tip` is exactly the silent-wrong-data
/// failure this project exists to prevent, so never move a status-bearing word
/// into `tip` that `marker` does not already carry.
///
/// `id` must be unique within its window: gpui keys the hover state by it.
pub(crate) fn hint<I: Into<SharedString>, M: Into<SharedString>, T: Into<SharedString>>(
    id: I,
    marker: M,
    tip: T,
    color: Rgba,
) -> impl IntoElement {
    let id: SharedString = id.into();
    let marker: SharedString = marker.into();
    let tip: SharedString = tip.into();
    let selector = id.clone();
    div()
        .id(id)
        .debug_selector(move || format!("hint:{selector}"))
        .flex_none()
        .text_size(px(HINT_TEXT))
        .text_color(color)
        .cursor_pointer()
        .child(marker)
        .tooltip(move |_window, cx| {
            let tip = tip.clone();
            cx.new(|_| HintTip(tip)).into()
        })
}

/// A hint's hover chip. Deliberately one element with one child: the whole
/// contract a test reads back is its selector, and that selector is its text.
pub(crate) struct HintTip(pub(crate) SharedString);

impl gpui::Render for HintTip {
    fn render(
        &mut self,
        _window: &mut gpui::Window,
        _cx: &mut gpui::Context<Self>,
    ) -> impl IntoElement {
        let text = self.0.clone();
        div()
            .debug_selector(move || format!("{HINT_TIP_SELECTOR}{text}"))
            .max_w(px(320.0))
            .bg(rgb(0x1f1f22))
            .text_color(rgb(0xe8e8ec))
            .text_size(px(HINT_TEXT))
            .px_2()
            .py_1()
            .rounded_md()
            .child(self.0.clone())
    }
}

/// Headless proof that a hint's *words* — not merely its existence — are
/// observable, which is what licenses moving an explanation off the screen at
/// all. If this suite cannot be made to pass, nothing that carries the status of
/// a claim may be moved into a hint.
#[cfg(test)]
mod hint_tests {
    use super::*;
    use gpui::{Modifiers, TestAppContext, VisualTestContext, point, size};

    const MARKER: &str = "hypothesis";
    const TIP: &str = "a path-loss model, not a measurement";

    struct HintHost;

    impl gpui::Render for HintHost {
        fn render(
            &mut self,
            _window: &mut gpui::Window,
            _cx: &mut gpui::Context<Self>,
        ) -> impl IntoElement {
            div()
                .size_full()
                .child(hint("spike", MARKER, TIP, gpui::rgb(0x888888)))
        }
    }

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// Hover a hint and read its chip back by the sentence it shows.
    fn hover_and_read(
        cx: &mut TestAppContext,
    ) -> (VisualTestContext, Option<gpui::Bounds<gpui::Pixels>>) {
        let window = cx.add_window(|_, _| HintHost);
        let mut cx = VisualTestContext::from_window(window.into(), cx);
        cx.simulate_resize(size(px(400.0), px(200.0)));
        cx.run_until_parked();

        let marker = cx
            .debug_bounds("hint:spike")
            .expect("the marker itself is always drawn");
        cx.simulate_mouse_move(marker.center(), None, Modifiers::default());
        cx.run_until_parked();
        // gpui waits half a second of hover before it builds the chip.
        cx.executor()
            .advance_clock(std::time::Duration::from_secs(1));
        cx.run_until_parked();
        // A second move keeps the pointer inside the marker for the frame that
        // prepaints the chip.
        cx.simulate_mouse_move(marker.center(), None, Modifiers::default());
        cx.run_until_parked();

        let found = cx.debug_bounds(leak(format!("{HINT_TIP_SELECTOR}{TIP}")));
        (cx, found)
    }

    /// The marker is on the screen with no hover at all — the part that carries
    /// the status of the claim never depends on a pointer.
    #[gpui::test]
    fn the_marker_is_drawn_without_hovering(cx: &mut TestAppContext) {
        let window = cx.add_window(|_, _| HintHost);
        let mut cx = VisualTestContext::from_window(window.into(), cx);
        cx.simulate_resize(size(px(400.0), px(200.0)));
        cx.run_until_parked();
        assert!(
            cx.debug_bounds("hint:spike").is_some(),
            "a hint's marker must never wait for a hover"
        );
        assert!(
            cx.debug_bounds(leak(format!("{HINT_TIP_SELECTOR}{TIP}")))
                .is_none(),
            "and its chip must not be drawn before one"
        );
        let _ = point(px(0.0), px(0.0));
    }

    /// The load-bearing one: after a hover the chip is found *by its text*, so a
    /// sentence moved into a hint is still an assertion a test can close.
    #[gpui::test]
    fn a_hovered_hint_is_found_by_the_words_it_shows(cx: &mut TestAppContext) {
        let (mut cx, found) = hover_and_read(cx);
        assert!(
            found.is_some(),
            "the hovered hint's chip was not found by its own text"
        );
        assert!(
            cx.debug_bounds(leak(format!("{HINT_TIP_SELECTOR}some other sentence")))
                .is_none(),
            "and a sentence the hint does not say must not be found"
        );
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

    #[test]
    fn clock_is_hh_mm_ss_and_never_panics() {
        assert_eq!(clock(i64::MIN), "--:--:--");
        assert_eq!(clock(i64::MAX), "--:--:--");
        let t = clock(1_700_000_000_000_000);
        assert_eq!(t.len(), 8, "{t}");
        assert!(t.chars().all(|c| c.is_ascii_digit() || c == ':'), "{t}");
    }

    /// The vocabulary rule itself, which the code cannot state on its own: a
    /// presented moment is absolute, a freshness reading is relative, and the
    /// two are never the same words.
    #[test]
    fn dating_rule_picks_absolute_for_presented_and_relative_for_freshness() {
        let now = 1_700_000_000_000_000i64;
        let ts = now - 120_000_000;
        assert_eq!(dated(Dating::Presented, ts, now), clock(ts));
        assert_eq!(dated(Dating::Freshness, ts, now), "2m ago");
        assert_ne!(
            dated(Dating::Presented, ts, now),
            dated(Dating::Freshness, ts, now)
        );
    }

    #[test]
    fn moments_diverge_only_past_the_same_moment_window() {
        let a = 1_700_000_000_000_000i64;
        assert_eq!(moments_diverge(a, a), None);
        assert_eq!(moments_diverge(a, a - SAME_MOMENT_US), None);
        assert_eq!(
            moments_diverge(a, a - SAME_MOMENT_US - 1_000_000),
            Some("61s".to_string())
        );
        // Symmetric: which reading is the older one does not change the fact.
        assert_eq!(
            moments_diverge(a - 4 * 3600 * 1_000_000, a),
            Some("4h".to_string())
        );
        // Whether a reading has a moment at all is the caller's question: this
        // rule never answers it by staying silent about a gap it can see.
        assert!(moments_diverge(0, a).is_some());
    }
}
