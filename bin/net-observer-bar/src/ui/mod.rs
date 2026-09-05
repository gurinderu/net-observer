//! The gpui panel view for the menu-bar app.
//!
//! [`Glance`] is a shared entity holding the most recent
//! [`StatusSnapshot`](net_observer_ipc::StatusSnapshot) fetched from `net-observerd` over
//! the local socket (plus the last fetch error and the socket path used to
//! refresh). The menu-bar refresh timer writes into it (see [`crate::menubar`]);
//! [`PanelView`] observes it and re-renders whenever it changes, so an open panel
//! updates live on the same ~3s cadence as the status-item dot.
//!
//! The bar is a pure socket client — it never opens the DuckDB store (the daemon
//! is the sole DB owner). When the daemon is down / the socket is absent,
//! [`read_fresh`] returns [`GlanceError::Unreachable`] and the panel renders a
//! graceful "net-observer offline" state instead of crashing. A daemon that *does*
//! answer but whose answer we cannot use ([`GlanceError::Protocol`]) is a
//! different state: the panel stays online and shows the message rather than
//! claiming the daemon is not there.
//!
//! ## Look — a Tailscale-style menu
//!
//! The panel is drawn as a clean, system-native dropdown (not bordered cards): a
//! rounded surface, a header row with the app name and a toggle switch, hairline
//! separators, and label→value list rows. It **adapts to the system appearance**
//! ([`Theme::for_appearance`] reads gpui's [`gpui::WindowAppearance`]) — a
//! near-white light theme or a dark-grey dark theme — rather than hardcoding one.
//!
//! The header **toggle switch** is bound to `snapshot.observing`: green when the
//! observer is collecting, grey when paused. Clicking it runs [`toggle_round_trip`]
//! — read the live state, send `Control(SetObserving(!live))` (see
//! [`send_set_observing`]), read it back — **on a background thread**, then applies
//! the outcome with [`Glance::apply_toggle_result`]. The socket round-trips never
//! run on the gpui main thread, so a daemon that accepts but does not answer cannot
//! park the bar. This is benign **self-control** — it pauses/resumes the observer's
//! OWN collection only; it never touches the proxy or the network and is not gated
//! by `acting.enabled`. While paused the header shows a muted "paused" state and the
//! daemon stays alive so the switch can turn collection back on.

mod control;
mod model;
mod panel;
mod parts;
mod theme;

pub(crate) use control::spawn_control_on;
pub use control::{
    GlanceError, freeze_round_trip, quiet_round_trip, read_fresh, scan_round_trip_base,
};
pub use model::Glance;
pub use panel::PanelView;
pub use parts::now_us;
pub(crate) use parts::{
    Dating, PROVENANCE_TEXT, age_str, clock, dated, gap_label, moments_diverge, separator,
};
pub(crate) use theme::{
    MENU_HEADING_H, MENU_HEADING_TEXT, MENU_ROW_H, MENU_ROW_PX, MENU_ROW_RADIUS, MENU_ROW_TEXT,
    MENU_SEPARATOR_H, Theme,
};

/// Headless UI tests: the panel drawn on gpui's own test platform, whose window
/// runs layout and scene construction for real and implements `draw(&Scene)` as a
/// no-op. No display, no daemon, no root — see `menu.rs` / `map.rs` / `menubar.rs`
/// for the sibling suites.
#[cfg(test)]
mod headless_tests {
    use super::*;
    use crate::menubar::{PANEL_H, PANEL_W};
    use gpui::prelude::*;
    use gpui::{
        Context, Entity, Modifiers, Render, TestAppContext, VisualTestContext, Window,
        WindowAppearance, div, px, size,
    };
    use net_observer_ipc::StatusSnapshot;

    /// A fresh panel window over a model in a chosen state.
    ///
    /// Fresh per test on purpose: gpui's debug-bounds map only ever grows over a
    /// window's life, so a window that once drew an element can never say it is
    /// gone. Absence is assertable only in a window opened already in the state
    /// under test.
    fn panel(
        cx: &mut TestAppContext,
        snapshot: StatusSnapshot,
        error: Option<GlanceError>,
    ) -> (Entity<Glance>, VisualTestContext) {
        let model = cx.update(|cx| {
            cx.new(|_| {
                Glance::new(
                    snapshot,
                    error,
                    "/tmp/net-observer-test-absent.sock".to_string(),
                )
            })
        });
        let for_view = model.clone();
        let window = cx.add_window(|_, cx| PanelView::new(for_view, cx));
        let vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.simulate_resize(size(px(PANEL_W as f32), px(PANEL_H as f32)));
        vcx.run_until_parked();
        (model, vcx)
    }

    /// Every control the panel draws must be laid out **inside** the panel.
    ///
    /// The panel is a fixed 320×560 popup, and gpui paints nothing outside a
    /// window: a control that lands past the edge is not clipped or scrolled to,
    /// it is simply not there. That is exactly how a footer packed with eight
    /// buttons in one row lost its last ones — visible only on a screenshot, and
    /// only if you knew to count.
    #[gpui::test]
    fn panel_controls_stay_inside_the_panel(cx: &mut TestAppContext) {
        let model = cx.update(|cx| {
            cx.new(|_| {
                Glance::new(
                    StatusSnapshot::default(),
                    None,
                    "/tmp/net-observer-test.sock".to_string(),
                )
            })
        });
        let for_view = model.clone();
        let window = cx.add_window(|_, cx| PanelView::new(for_view, cx));
        let mut cx = VisualTestContext::from_window(window.into(), cx);

        // Draw the window itself at the panel's real size, rather than the
        // element by hand: the panel's controls are wired with `cx.listener`,
        // which only resolves inside the window's own render pass.
        let panel = size(px(PANEL_W as f32), px(PANEL_H as f32));
        cx.simulate_resize(panel);
        cx.run_until_parked();
        assert_eq!(
            cx.update(|window, _| window.viewport_size()),
            panel,
            "the test window must be the panel's own size"
        );

        for selector in ["menu-trigger", "observing-toggle"] {
            let b = cx
                .debug_bounds(selector)
                .unwrap_or_else(|| panic!("`{selector}` was not laid out at all"));
            assert!(
                b.origin.x >= px(0.0) && b.origin.y >= px(0.0),
                "`{selector}` starts outside the panel: {b:?}"
            );
            assert!(
                b.origin.x + b.size.width <= panel.width,
                "`{selector}` runs past the panel's right edge ({:?} > {:?})",
                b.origin.x + b.size.width,
                panel.width
            );
            assert!(
                b.origin.y + b.size.height <= panel.height,
                "`{selector}` runs past the panel's bottom edge ({:?} > {:?})",
                b.origin.y + b.size.height,
                panel.height
            );
        }
    }

    /// The offline hint is drawn, and drawn **in the light theme**.
    ///
    /// gpui's test window reports [`WindowAppearance::Light`], so this carrier
    /// exercises the light token set — the one every direct-`Theme` unit test in
    /// this crate skips, because they all pass `WindowAppearance::Dark` by hand.
    /// The appearance is asserted rather than assumed: if gpui ever flipped its
    /// test window to dark, this test would go on passing while proving the
    /// opposite of its name.
    #[gpui::test]
    fn the_offline_hint_is_drawn_in_the_light_theme(cx: &mut TestAppContext) {
        let (_model, mut cx) = panel(
            cx,
            StatusSnapshot::default(),
            Some(GlanceError::Unreachable("no such file".to_string())),
        );
        assert!(
            matches!(
                cx.update(|window, _| window.appearance()),
                WindowAppearance::Light | WindowAppearance::VibrantLight
            ),
            "this test claims the light theme; the window must actually be in it"
        );

        let hint = cx
            .debug_bounds("offline-warn")
            .expect("an unreachable daemon must be stated in the header, not silently");
        assert!(
            hint.size.width > px(0.0) && hint.size.height > px(0.0),
            "the offline hint was laid out with no area at all: {hint:?}"
        );
        assert!(
            hint.origin.x >= px(0.0)
                && hint.origin.x + hint.size.width <= px(PANEL_W as f32)
                && hint.origin.y >= px(0.0)
                && hint.origin.y + hint.size.height <= px(PANEL_H as f32),
            "the offline hint is laid out outside the panel, where nothing is \
             painted: {hint:?}"
        );
    }

    /// The negative control for the test above, in a window that was **never**
    /// offline: a reachable daemon draws no warning at all. Without this, the
    /// hint test would pass equally well on a panel that warns permanently.
    #[gpui::test]
    fn a_reachable_daemon_draws_no_offline_hint(cx: &mut TestAppContext) {
        let (_model, mut cx) = panel(cx, StatusSnapshot::default(), None);
        assert!(
            cx.debug_bounds("offline-warn").is_none(),
            "a panel that never went offline drew the offline warning anyway"
        );
    }

    /// A disabled control is inert **and** reads as off.
    ///
    /// Offline is the one state where the switch is not a control: there is no
    /// daemon to accept a `SetObserving`. The failure this pins is the switch
    /// that still flips under the cursor and reports nothing — a panel claiming
    /// collection was turned off when nothing was ever asked.
    #[gpui::test]
    fn an_offline_toggle_neither_flips_nor_reports_an_attempt(cx: &mut TestAppContext) {
        // A daemon that WAS observing, then went unreachable: the stale snapshot
        // still says `observing: true`, so a switch that acted locally would be
        // visible as a flip to false.
        let snapshot = StatusSnapshot {
            observing: true,
            ..Default::default()
        };
        let (model, mut cx) = panel(
            cx,
            snapshot,
            Some(GlanceError::Unreachable("no such file".to_string())),
        );

        // Looks off, by the code that decides it rather than by the pixels: the
        // header hands the switch `observing && online`, and offline is not
        // online however the stale snapshot reads.
        let (observing, online) =
            cx.update(|_, cx| (model.read(cx).snapshot.observing, model.read(cx).online()));
        assert!(observing, "precondition: the stale snapshot still says ON");
        assert!(!online, "precondition: the daemon is unreachable");
        assert!(
            !(observing && online),
            "the header must draw the switch OFF while the daemon is unreachable"
        );

        let toggle = cx
            .debug_bounds("observing-toggle")
            .expect("the switch is drawn offline too, just not as a control");
        cx.simulate_click(toggle.center(), Modifiers::none());
        cx.run_until_parked();

        assert!(
            cx.update(|_, cx| model.read(cx).control_msg.is_none()),
            "clicking a disabled switch reported an attempt: {:?}",
            cx.update(|_, cx| model.read(cx).control_msg.clone())
        );
        assert!(
            cx.update(|_, cx| model.read(cx).snapshot.observing),
            "the click flipped the local snapshot without asking any daemon"
        );
    }

    /// A column that squeezes whatever is put in it: a fixed 400px block above
    /// the element under test, in a window far shorter than that. Everything in
    /// the column is over budget, so a flex child that is allowed to shrink is
    /// shrunk — a 1px rule all the way to 0px.
    ///
    /// The pressure has to be supplied here because the panel's own column does
    /// not apply it: measured on this layout, the panel's separator holds 1px at
    /// every window height from 200px down to 1px whether it carries `flex_none`
    /// or not, because the header and body absorb the whole deficit first. A
    /// check written against the live panel is therefore green however the
    /// separator is declared — it proves nothing. The element under test is
    /// still the product's own [`separator`]; only the squeeze is the test's.
    struct SqueezedColumn(Theme);

    impl Render for SqueezedColumn {
        fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
            div()
                .flex()
                .flex_col()
                .size_full()
                .child(div().h(px(400.0)))
                .child(separator(self.0))
        }
    }

    /// The panel's hairline separator does not shrink.
    ///
    /// A separator is a flex child, and a flex child shrinks: without
    /// `flex_none` a 1px rule in an overflowing column is squeezed to 0px and
    /// the sections silently run together — no error, no gap, just two blocks
    /// that now read as one. The sibling checks in `map.rs` show what the
    /// retyped copies of this function do under the same squeeze.
    #[gpui::test]
    fn the_panel_separator_keeps_its_hairline_under_shrink_pressure(cx: &mut TestAppContext) {
        let theme = Theme::for_appearance(gpui::WindowAppearance::Light);
        let window = cx.add_window(|_, _| SqueezedColumn(theme));
        let mut cx = VisualTestContext::from_window(window.into(), cx);
        cx.simulate_resize(size(px(PANEL_W as f32), px(100.0)));
        cx.run_until_parked();

        let rule = cx
            .debug_bounds("separator")
            .expect("the separator was not laid out at all");
        assert!(
            rule.size.height >= px(MENU_SEPARATOR_H),
            "the separator was squeezed below its hairline ({:?} < {:?}) — a rule \
             that is allowed to shrink disappears in a tight column",
            rule.size.height,
            px(MENU_SEPARATOR_H)
        );
    }
}
