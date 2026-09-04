//! The panel's actions menu, as a window of its own.
//!
//! The panel is a fixed 320x560 popover and its controls outgrew a row: laid out
//! in one line the last of them fell outside the panel and simply did not
//! appear. Stacking them inside the panel only moved the problem — the menu then
//! fought the body for the same fixed height.
//!
//! So the menu is a second [`WindowKind::PopUp`] window, flying out beside the
//! panel the way a native submenu does. It has to be a window: gpui draws
//! nothing outside the one it is in, so a menu that leaves the panel's edge
//! cannot be an element inside the panel.
//!
//! Two consequences are handled here rather than discovered later:
//! * Opening this window takes key focus from the panel, and the panel closes
//!   when it resigns key — hence [`Glance::menu_focus_guard`], raised for as long
//!   as the menu owns the focus.
//! * A flyout that lands half off the display is worse than a stacked one, so
//!   the anchor is clamped to the screen: it prefers the panel's right side,
//!   flips to the left when there is no room, and slides up to fit.

use gpui::{
    AnyElement, App, AppContext, Bounds, Context, Entity, InteractiveElement, IntoElement,
    ParentElement, Pixels, Render, StatefulInteractiveElement, Styled, Window,
    WindowBackgroundAppearance, WindowBounds, WindowKind, WindowOptions, div, point, px, rgb, rgba,
    size,
};
use std::sync::atomic::Ordering;

use crate::ui::{
    Glance, Theme, freeze_round_trip, quiet_round_trip, scan_round_trip_base, spawn_control_on,
};

/// Menu size in gpui logical pixels. Wide enough for the longest label
/// ("Freeze pcap"), tall enough for the entries and their three headings.
const MENU_W: f32 = 168.0;
const MENU_H: f32 = 250.0;

/// Gap between the panel's edge and the menu, so the two read as separate
/// surfaces rather than one torn one.
const GAP: f32 = 6.0;

/// The actions menu view: every control that used to crowd the footer.
pub(crate) struct MenuView {
    model: Entity<Glance>,
}

impl MenuView {
    fn entry(
        &self,
        id: &'static str,
        label: impl Into<String>,
        color: u32,
        theme: Theme,
        cx: &mut Context<Self>,
        on_click: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> AnyElement {
        div()
            .id(id)
            .flex()
            .w_full()
            .px_2()
            .py_1()
            .rounded_md()
            .text_size(px(12.0))
            .text_color(rgb(color))
            .cursor_pointer()
            .hover(|s| s.bg(rgb(theme.hover)))
            .child(label.into())
            .on_click(cx.listener(move |this, _, _window, cx| {
                on_click(this, cx);
            }))
            .into_any_element()
    }

    fn heading(label: &'static str, theme: Theme) -> AnyElement {
        div()
            .px_2()
            .pt_1()
            .text_size(px(10.0))
            .text_color(rgb(theme.muted))
            .child(label)
            .into_any_element()
    }
}

impl Render for MenuView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let quiet_on = self.model.read(cx).snapshot.quiet;

        let events = self.entry("events", "Events", theme.accent, theme, cx, |this, cx| {
            let socket = this.model.read(cx).socket_path.clone();
            let model = this.model.clone();
            crate::events::open_or_focus(cx, &model, socket);
        });
        let map = self.entry("map", "Map", theme.accent, theme, cx, |this, cx| {
            let model = this.model.clone();
            crate::map::open_or_focus(cx, &model);
        });
        let air = self.entry("air", "Air", theme.accent, theme, cx, |this, cx| {
            let socket = this.model.read(cx).socket_path.clone();
            let model = this.model.clone();
            crate::air::open_or_focus(cx, &model, socket);
        });
        let freeze = self.entry(
            "freeze",
            "Freeze pcap",
            theme.accent,
            theme,
            cx,
            |this, cx| {
                let model = this.model.clone();
                spawn_control_on(&model, cx, freeze_round_trip);
            },
        );
        // The label says what the click will do; the colour says which state the
        // daemon is in now, because a suppressed probe is a deliberate hole in
        // the measurement and must not look routine.
        let quiet = self.entry(
            "quiet",
            if quiet_on { "Unquiet" } else { "Quiet" },
            if quiet_on { theme.warn } else { theme.accent },
            theme,
            cx,
            |this, cx| {
                let model = this.model.clone();
                spawn_control_on(&model, cx, quiet_round_trip);
            },
        );
        // Scan is the only entry here that addresses other machines: acting-class,
        // refused by default, and warn-coloured for the same reason as quiet.
        let scan = self.entry("scan", "Scan", theme.warn, theme, cx, |this, cx| {
            let model = this.model.clone();
            spawn_control_on(&model, cx, scan_round_trip_base);
        });
        let refresh = self.entry("refresh", "Refresh", theme.accent, theme, cx, |this, cx| {
            this.model.update(cx, |g, cx| {
                g.refresh();
                cx.notify();
            });
        });
        let quit = self.entry("quit", "Quit", theme.bad, theme, cx, |_this, cx| {
            cx.quit();
        });

        div()
            .flex()
            .flex_col()
            .size_full()
            .gap_0p5()
            .p_1()
            .rounded(px(10.0))
            .border_1()
            .border_color(rgba(theme.edge))
            .bg(rgba(theme.surface))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .child(Self::heading("windows", theme))
            .child(events)
            .child(map)
            .child(air)
            .child(Self::heading("daemon", theme))
            .child(freeze)
            .child(quiet)
            .child(scan)
            .child(Self::heading("panel", theme))
            .child(refresh)
            .child(quit)
    }
}

/// Where the menu goes: beside the panel, and always wholly on the display.
///
/// Preference is the panel's right side, because a menu-bar panel sits near the
/// right edge more often than not and the room is usually there; when it is not,
/// the menu flips to the left rather than hanging off the screen. Vertically it
/// is bottom-aligned with the panel and then slid up if that would take it below
/// the display's edge.
fn menu_bounds(panel: Bounds<Pixels>, screen: Bounds<Pixels>) -> Bounds<Pixels> {
    let menu = size(px(MENU_W), px(MENU_H));
    let right_edge = f32::from(panel.origin.x) + f32::from(panel.size.width) + GAP;
    let fits_right =
        right_edge + MENU_W <= f32::from(screen.origin.x) + f32::from(screen.size.width);
    let x = if fits_right {
        right_edge
    } else {
        (f32::from(panel.origin.x) - GAP - MENU_W).max(f32::from(screen.origin.x))
    };

    // Bottom-aligned with the panel, then clamped into the display.
    let panel_bottom = f32::from(panel.origin.y) + f32::from(panel.size.height);
    let screen_bottom = f32::from(screen.origin.y) + f32::from(screen.size.height);
    let y = (panel_bottom - MENU_H)
        .min(screen_bottom - MENU_H)
        .max(f32::from(screen.origin.y));

    Bounds {
        origin: point(px(x), px(y)),
        size: menu,
    }
}

/// Open the actions menu next to `panel`, or focus the one already open.
pub(crate) fn open_or_focus(
    cx: &mut App,
    model: &Entity<Glance>,
    panel: Bounds<Pixels>,
    screen: Bounds<Pixels>,
) {
    if let Some(handle) = model.read(cx).menu_window {
        if handle
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
        {
            return;
        }
        model.update(cx, |g, _| g.menu_window = None);
    }

    let guard = model.read(cx).menu_focus_guard.clone();
    let panel_window = model.read(cx).panel_window;
    guard.store(true, Ordering::SeqCst);

    let model_for_view = model.clone();
    let opened = cx.open_window(
        WindowOptions {
            window_background: WindowBackgroundAppearance::Blurred,
            window_bounds: Some(WindowBounds::Windowed(menu_bounds(panel, screen))),
            titlebar: None,
            kind: WindowKind::PopUp,
            is_resizable: false,
            is_minimizable: false,
            is_movable: false,
            focus: true,
            show: true,
            ..Default::default()
        },
        move |window, cx| {
            cx.new(move |cx| {
                let view = MenuView {
                    model: model_for_view,
                };
                // Dismiss on click-away, exactly like the panel: close once the
                // menu has been active and then resigns key. Closing the menu
                // also lowers the guard and takes the panel with it, because the
                // click that dismissed the menu landed outside both.
                let mut was_active = false;
                cx.observe_window_activation(window, move |this: &mut MenuView, window, cx| {
                    if window.is_window_active() {
                        was_active = true;
                        return;
                    }
                    if !was_active {
                        return;
                    }
                    this.model.update(cx, |g, _| {
                        g.menu_window = None;
                        g.menu_focus_guard.store(false, Ordering::SeqCst);
                    });
                    if let Some(panel) = panel_window {
                        panel.update(cx, |_, window, _| window.remove_window()).ok();
                    }
                    window.remove_window();
                })
                .detach();
                view
            })
        },
    );

    match opened {
        Ok(handle) => {
            model.update(cx, |g, _| g.menu_window = Some(handle.into()));
            cx.activate(true);
        }
        Err(e) => {
            guard.store(false, Ordering::SeqCst);
            eprintln!("net-observer-bar: failed to open the actions menu: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(x: f32, y: f32, w: f32, h: f32) -> Bounds<Pixels> {
        Bounds {
            origin: point(px(x), px(y)),
            size: size(px(w), px(h)),
        }
    }

    /// The whole point of computing bounds rather than offsetting blindly: the
    /// menu must land on the display, whichever side of it the panel sits on.
    #[test]
    fn the_menu_stays_on_the_screen_on_either_side() {
        let screen = bounds(0.0, 0.0, 1470.0, 956.0);

        // Panel near the right edge — the usual menu-bar case: no room to the
        // right, so the menu flips to the panel's left.
        let panel = bounds(1150.0, 24.0, 320.0, 560.0);
        let m = menu_bounds(panel, screen);
        assert!(
            f32::from(m.origin.x) + MENU_W <= 1470.0,
            "must not hang off the right: {m:?}"
        );
        assert!(f32::from(m.origin.x) < 1150.0, "flips to the left: {m:?}");

        // Panel on the left — room to the right, so it opens there.
        let panel = bounds(40.0, 24.0, 320.0, 560.0);
        let m = menu_bounds(panel, screen);
        assert!(f32::from(m.origin.x) > 360.0, "opens rightward: {m:?}");
        assert!(f32::from(m.origin.x) + MENU_W <= 1470.0, "{m:?}");
    }

    /// A panel whose bottom is below the display's edge must not drag the menu
    /// off with it.
    #[test]
    fn the_menu_slides_up_rather_than_off_the_bottom() {
        let screen = bounds(0.0, 0.0, 1470.0, 956.0);
        let panel = bounds(40.0, 700.0, 320.0, 560.0);
        let m = menu_bounds(panel, screen);
        assert!(
            f32::from(m.origin.y) + MENU_H <= 956.0,
            "the whole menu is on screen: {m:?}"
        );
        assert!(f32::from(m.origin.y) >= 0.0, "{m:?}");
    }
}
