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
//! It is drawn on the metrics of a native macOS menu — [`MENU_ROW_H`] and its
//! neighbours in [`crate::ui`], shared with the footer row this flies out of —
//! and its groups are told apart by the same hairline [`separator`] the panel
//! uses, so a change of theme moves both lines together.
//!
//! Three consequences are handled here rather than discovered later:
//! * Opening this window takes key focus from the panel, and the panel closes
//!   when it resigns key — hence [`Glance::menu_focus_guard`], raised for as long
//!   as the menu owns the focus. The guard is lowered on every path out of this
//!   window, including the one where the window never became active: a guard left
//!   raised would make the panel undismissable for the rest of the process.
//! * Losing key focus does not by itself mean "the operator clicked away". The
//!   click may have landed *in the panel*, which deactivates this window just the
//!   same — so the menu closes at once but the panel is only closed after a short
//!   settling delay, and only if it did not become active in the meantime.
//! * A flyout that lands half off the display is worse than a stacked one, so
//!   the anchor is clamped to the screen: it prefers the panel's right side,
//!   flips to the left when there is no room, and slides up to fit.

use gpui::{
    AnyElement, App, AppContext, AsyncApp, Bounds, Context, Entity, InteractiveElement,
    IntoElement, ParentElement, Pixels, Render, StatefulInteractiveElement, Styled, Subscription,
    Window, WindowBackgroundAppearance, WindowBounds, WindowKind, WindowOptions, div, point, px,
    rgb, rgba, size,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::ui::{
    Glance, MENU_ROW_H, MENU_ROW_PX, MENU_ROW_RADIUS, MENU_ROW_TEXT, Theme, freeze_round_trip,
    quiet_round_trip, scan_round_trip_base, separator, spawn_control_on,
};

/// Menu size in gpui logical pixels. Wide enough for the longest label
/// ("Freeze pcap") at [`MENU_ROW_TEXT`], tall enough for eight rows, three
/// headings and the two rules between the groups.
const MENU_W: f32 = 184.0;
const MENU_H: f32 = 328.0;

/// Gap between the panel's edge and the menu, so the two read as separate
/// surfaces rather than one torn one.
const GAP: f32 = 6.0;

/// How long a freshly opened menu ignores losing key focus.
///
/// The dismiss rule cannot simply be "any deactivation closes me": the opening
/// itself can deliver a spurious deactivation before the window is ever shown.
/// The previous latch — ignore everything until the first activation — made that
/// robust at the price of a window that never activates never being able to
/// close, and so a focus guard raised for the rest of the process. A grace
/// window is bounded in both directions instead.
const OPEN_GRACE: Duration = Duration::from_millis(300);

/// How long the panel is given to become active before the menu decides that the
/// dismissing click landed outside both windows.
///
/// Clicking *into the panel* deactivates this menu exactly like clicking away
/// does, and at that instant the panel is not yet key. Without this delay the
/// panel closed under the operator's cursor on his own click.
const PANEL_HANDOFF: Duration = Duration::from_millis(150);

/// The actions menu view: every control that used to crowd the footer.
pub(crate) struct MenuView {
    model: Entity<Glance>,
    /// Re-render on every change of the shared model. Without it the quiet row
    /// keeps the label and colour it was born with, and since the label states
    /// what the *next* click will do, the next click does the opposite of what it
    /// says.
    _observe: Subscription,
    /// Lowered when this view is dropped — i.e. whenever the window goes away,
    /// however it went away.
    focus_guard: Arc<AtomicBool>,
}

impl Drop for MenuView {
    fn drop(&mut self) {
        self.focus_guard.store(false, Ordering::SeqCst);
    }
}

impl MenuView {
    /// One row of the menu, on the native metrics: full width, the whole row is
    /// the target, and hovering fills it with the accent rather than washing the
    /// few pixels under the label.
    ///
    /// `color` is the row's own ink — the semantic colour of what it does. On the
    /// highlight it gives way to [`Theme::knob`], because the accent fill decides
    /// the contrast there and a warn-coloured label on it would be unreadable.
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
            .items_center()
            .w_full()
            .h(px(MENU_ROW_H))
            .px(px(MENU_ROW_PX))
            .rounded(px(MENU_ROW_RADIUS))
            .text_size(px(MENU_ROW_TEXT))
            .text_color(rgb(color))
            .cursor_pointer()
            .hover(|s| s.bg(rgb(theme.accent)).text_color(rgb(theme.knob)))
            .child(label.into())
            .on_click(cx.listener(move |this, _, _window, cx| {
                on_click(this, cx);
            }))
            .into_any_element()
    }

    /// A group heading: what the rows under it do. Deliberately small and muted,
    /// with no hover and no row metrics, so it cannot be mistaken for something
    /// clickable — the rule above it is what actually separates the groups.
    fn heading(label: &'static str, theme: Theme) -> AnyElement {
        div()
            .px(px(MENU_ROW_PX))
            .pt_1()
            .pb_0p5()
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
            .child(separator(theme))
            .child(Self::heading("daemon", theme))
            .child(freeze)
            .child(quiet)
            .child(scan)
            .child(separator(theme))
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
        model.update(cx, |g, cx| {
            g.menu_window = None;
            cx.notify();
        });
    }

    let guard = model.read(cx).menu_focus_guard.clone();
    guard.store(true, Ordering::SeqCst);

    let model_for_view = model.clone();
    let guard_for_view = guard.clone();
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
                let observe = cx.observe(&model_for_view, |_, _, cx| cx.notify());
                let view = MenuView {
                    model: model_for_view,
                    _observe: observe,
                    focus_guard: guard_for_view,
                };
                // Dismiss on click-away. Losing key focus is the only signal
                // there is, and it does not distinguish the two clicks that
                // produce it: one landing outside both windows, and one landing
                // in the panel. The menu goes either way; the panel is closed
                // only after [`PANEL_HANDOFF`] and only if it did not become key
                // in the meantime — otherwise the operator's own click on the
                // panel took it out from under him.
                let opened_at = Instant::now();
                cx.observe_window_activation(window, move |this: &mut MenuView, window, cx| {
                    if window.is_window_active() || opened_at.elapsed() < OPEN_GRACE {
                        return;
                    }
                    this.model.update(cx, |g, cx| {
                        g.menu_window = None;
                        g.menu_focus_guard.store(false, Ordering::SeqCst);
                        cx.notify();
                    });
                    close_panel_unless_it_took_focus(cx, this.model.clone());
                    window.remove_window();
                })
                .detach();
                view
            })
        },
    );

    match opened {
        Ok(handle) => {
            model.update(cx, |g, cx| {
                g.menu_window = Some(handle.into());
                cx.notify();
            });
            cx.activate(true);
        }
        Err(e) => {
            guard.store(false, Ordering::SeqCst);
            eprintln!("net-observer-bar: failed to open the actions menu: {e}");
        }
    }
}

/// Close the panel after [`PANEL_HANDOFF`], unless it became key in the meantime.
///
/// Spawned on the app rather than on the menu's own view, because the menu window
/// is removed immediately after this is scheduled and a view-scoped task would go
/// with it. The handle is cleared whether the panel is closed here or found dead:
/// a handle that outlived its window reads as a live one everywhere else.
fn close_panel_unless_it_took_focus(cx: &mut App, model: Entity<Glance>) {
    let app: &mut App = cx;
    app.spawn(async move |acx: &mut AsyncApp| {
        acx.background_executor().timer(PANEL_HANDOFF).await;
        acx.update(|acx| {
            let Some(panel) = model.read(acx).panel_window else {
                return;
            };
            // `update` succeeds only while the window is still open, so `Err`
            // means the panel is already gone.
            match panel.update(acx, |_, window, _| window.is_window_active()) {
                Ok(true) => {}
                Ok(false) => {
                    panel
                        .update(acx, |_, window, _| window.remove_window())
                        .ok();
                    model.update(acx, |g, _| g.panel_window = None);
                }
                Err(_) => model.update(acx, |g, _| g.panel_window = None),
            }
        })
        .ok();
    })
    .detach();
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
