//! Small shared elements and formatting helpers used by every window.

use std::time::{SystemTime, UNIX_EPOCH};

use gpui::prelude::*;
use gpui::{IntoElement, RenderOnce, Rgba, SharedString, div, px, rgb};

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
/// This is the ONE key-value row of the bar. Windows do not re-derive it: a
/// difference a window genuinely needs is a knob below, never a second layout.
/// The knobs exist only where the difference is one of substance:
///
/// * [`Row::key_width`] — the label becomes a fixed column and the value takes
///   the rest. That is what aligns a stack of timestamps on its digits; under
///   `justify_between` each row's clock sits wherever its own value pushed it.
/// * [`Row::text_size`] / [`Row::key_text_size`] — a row drawn at a documented
///   smaller scale (e.g. [`PROVENANCE_TEXT`] for a label that is a dated
///   moment). The size carries what kind of fact this is, not a taste.
/// * [`Row::selector`] — a headless test handle; without one no claim about
///   this row is observable at all.
///
/// Both sides take anything convertible into a [`SharedString`], so a `&'static
/// str` label costs no allocation at all and an owned `String` local is *moved*
/// in rather than copied — a render runs this once per row, every tick.
pub(crate) fn row<K: Into<SharedString>, V: Into<SharedString>>(
    key: K,
    value: V,
    value_color: Rgba,
    theme: Theme,
) -> Row {
    Row {
        key: key.into(),
        value: value.into(),
        value_color,
        theme,
        key_width: None,
        text_size: None,
        key_text_size: None,
        selector: None,
    }
}

/// What a row's label half is named, given the row's own selector.
pub(crate) const ROW_KEY_SUFFIX: &str = ":key";
/// What a row's value half is named, given the row's own selector.
pub(crate) const ROW_VALUE_SUFFIX: &str = ":value";

/// The canonical key-value row. Built by [`row`].
#[derive(IntoElement)]
pub(crate) struct Row {
    key: SharedString,
    value: SharedString,
    value_color: Rgba,
    theme: Theme,
    key_width: Option<f32>,
    text_size: Option<f32>,
    key_text_size: Option<f32>,
    selector: Option<SharedString>,
}

impl Row {
    /// Give the label a fixed column of this width, so a stack of rows aligns
    /// its values — and its labels' digits — on one edge instead of on whatever
    /// each row's own text happened to measure. The column never shrinks: a
    /// column that gives way under pressure is not an alignment.
    pub(crate) fn key_width(mut self, width: f32) -> Self {
        self.key_width = Some(width);
        self
    }

    /// Draw the whole row at this type size rather than the window's base.
    pub(crate) fn text_size(mut self, size: f32) -> Self {
        self.text_size = Some(size);
        self
    }

    /// Draw the label at its own type size — for a label whose size says what
    /// kind of fact it is, such as a dated moment at [`PROVENANCE_TEXT`].
    pub(crate) fn key_text_size(mut self, size: f32) -> Self {
        self.key_text_size = Some(size);
        self
    }

    /// A handle a headless test can read this row back by.
    pub(crate) fn selector<S: Into<SharedString>>(mut self, name: S) -> Self {
        self.selector = Some(name.into());
        self
    }
}

impl RenderOnce for Row {
    fn render(self, _window: &mut gpui::Window, _cx: &mut gpui::App) -> impl IntoElement {
        let columned = self.key_width.is_some();

        let mut key = div().text_color(rgb(self.theme.muted));
        // Each half gets its own handle: the claims worth closing about this row
        // — where the label column ends, whether the value stayed inside the
        // panel — are claims about one half, not about the pair.
        if let Some(sel) = &self.selector {
            let sel = format!("{sel}{ROW_KEY_SUFFIX}");
            key = key.debug_selector(move || sel.clone());
        }
        if let Some(w) = self.key_width {
            key = key.w(px(w)).flex_none();
        }
        if let Some(s) = self.key_text_size.or(self.text_size) {
            key = key.text_size(px(s));
        }
        let key = key.child(self.key);

        let mut value = div().text_color(self.value_color);
        if let Some(sel) = &self.selector {
            let sel = format!("{sel}{ROW_VALUE_SUFFIX}");
            value = value.debug_selector(move || sel.clone());
        }
        // With a label column the value takes the remaining width; without one
        // the two ends are pushed apart. Either way the value is what gives way
        // when the row is too narrow — never the label column.
        if columned {
            value = value.flex_1().overflow_hidden();
        }
        let value = value.child(self.value);

        let mut root = div().flex().items_center().py_1();
        root = if columned {
            root.gap_2()
        } else {
            root.justify_between()
        };
        if let Some(s) = self.text_size {
            root = root.text_size(px(s));
        }
        if let Some(sel) = self.selector {
            root = root.debug_selector(move || sel.to_string());
        }
        root.child(key).child(value)
    }
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

/// Headless proof of what the shared key-value row promises, observed in a
/// harness that creates the flex pressure a live column absorbs on its own.
#[cfg(test)]
mod row_tests {
    use super::*;
    use gpui::{TestAppContext, VisualTestContext, size};

    /// The panel's own width — the pressure every row is drawn under.
    const W: f32 = 320.0;
    const KEY_W: f32 = 66.0;
    const SEL: &str = "t-row";
    /// Long enough that a value allowed to push would carry the row past `W`.
    const LONG: &str =
        "dns SERVFAIL from 192.168.1.1 after 5000 ms, resolver unreachable, retrying";

    /// A value a two-ended row really carries: short enough that there IS slack
    /// to push the two halves apart with. With `LONG` there is none, and the
    /// question the two-ended layout answers does not arise.
    const SHORT: &str = "12 ms";

    /// Narrower than the label column itself, so the deficit is pushed onto the
    /// column rather than onto the value beside it.
    const TIGHT: f32 = 48.0;

    struct RowHost {
        columned: bool,
        width: f32,
    }

    impl gpui::Render for RowHost {
        fn render(
            &mut self,
            _window: &mut gpui::Window,
            _cx: &mut gpui::Context<Self>,
        ) -> impl IntoElement {
            let theme = Theme::dark();
            let value = if self.columned { LONG } else { SHORT };
            let r = row("20:21:34", value, rgb(theme.fg), theme).selector(SEL);
            let r = if self.columned { r.key_width(KEY_W) } else { r };
            // A narrow flex column: the row must absorb the deficit itself.
            div().w(px(self.width)).flex().flex_col().child(r)
        }
    }

    fn draw(cx: &mut TestAppContext, columned: bool, width: f32) -> VisualTestContext {
        let window = cx.add_window(|_, _| RowHost { columned, width });
        let cx = VisualTestContext::from_window(window.into(), cx);
        cx.simulate_resize(size(px(width.max(W)), px(200.0)));
        cx.run_until_parked();
        cx
    }

    fn key_sel() -> &'static str {
        Box::leak(format!("{SEL}{ROW_KEY_SUFFIX}").into_boxed_str())
    }

    fn value_sel() -> &'static str {
        Box::leak(format!("{SEL}{ROW_VALUE_SUFFIX}").into_boxed_str())
    }

    /// The parameter that earns its keep: the label column is EXACTLY the width
    /// asked for — the whole basis on which a stack of clocks aligns on its
    /// digits — and stays so with a far-too-long value beside it and a container
    /// narrower than the column itself.
    ///
    /// What this closes is the requested width. `flex_none` on the label is belt
    /// and braces: at these sizes the value gives way first, so removing it
    /// changes nothing observable and no check here claims otherwise.
    #[gpui::test]
    fn a_key_column_keeps_its_exact_width_under_pressure(cx: &mut TestAppContext) {
        let mut cx = draw(cx, true, TIGHT);
        let key = cx.debug_bounds(key_sel()).expect("the label half is drawn");
        assert_eq!(
            key.size.width,
            px(KEY_W),
            "the label column gave way under pressure, so nothing aligns on it"
        );
    }

    /// The value is what gives way, and it gives way *inside* the panel: a row
    /// that runs past 320pt is a row whose value is unreadable.
    #[gpui::test]
    fn the_value_gives_way_and_stays_inside_the_panel(cx: &mut TestAppContext) {
        let mut cx = draw(cx, true, W);
        let value = cx
            .debug_bounds(value_sel())
            .expect("the value half is drawn");
        assert!(
            value.right() <= px(W),
            "the value ran past the panel's edge: right={:?}",
            value.right()
        );
    }

    /// Without a column the row is the two-ended list row: the label sits at the
    /// left edge and the value is pushed to the right one.
    #[gpui::test]
    fn without_a_column_the_two_halves_are_pushed_apart(cx: &mut TestAppContext) {
        let mut cx = draw(cx, false, W);
        let key = cx.debug_bounds(key_sel()).expect("the label half is drawn");
        let value = cx
            .debug_bounds(value_sel())
            .expect("the value half is drawn");
        assert!(
            value.left() > key.right(),
            "the value did not end up to the right of the label"
        );
        assert!(
            value.right() <= px(W),
            "the value ran past the panel's edge"
        );
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
