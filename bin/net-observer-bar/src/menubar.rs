//! The macOS menu-bar shell: a dockless (`.accessory`) app whose `NSStatusItem`
//! shows an icon-only health dot, and whose click toggles an anchored gpui popup
//! rendering the full [`Status`](crate::status::Status).
//!
//! Fallback rung **(a)** of the design's ladder: a real `NSStatusItem` (AppKit
//! interop via `objc2` / `objc2-app-kit`) whose click toggles an anchored gpui
//! popup (a Tailscale-style dropdown, dismissed on click-away).
//!
//! ## How the pieces fit
//!
//! gpui owns the `NSApplication` and the main run loop. We reach the *same*
//! shared `NSApplication` through `objc2-app-kit` to flip the activation policy
//! to `.accessory` (no Dock icon, no app bundle needed for dev). gpui sets the
//! policy to `.regular` in `applicationDidFinishLaunching:` *before* invoking the
//! `Application::run` closure, so setting `.accessory` inside that closure wins.
//!
//! The status-item button carries a target/action pair. AppKit delivers the
//! click on the main thread to our [`ClickTarget`] Objective-C class, which just
//! flips an `AtomicBool`. A gpui foreground task polls that flag and *toggles* the
//! panel — a Tailscale-style dropdown anchored under the icon (a borderless
//! `WindowKind::PopUp`, no titlebar): a click opens it, a click while it is open
//! closes it, and it also dismisses itself when it loses key focus (click-away).
//! Keeping all gpui/window work on gpui's own executor avoids reentering it from
//! an AppKit callback. A second foreground task re-queries the daemon over the
//! local socket every ~3s and updates both the shared model (so an open panel
//! re-renders) and the status-item dot + tooltip. When the daemon is down the
//! query fails and the shell renders a grey "offline" dot instead of crashing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use gpui::{
    App, AppContext, Application, AsyncApp, Bounds, Context, Entity, Pixels, Timer, Window,
    WindowBackgroundAppearance, WindowBounds, WindowHandle, WindowKind, WindowOptions, point, px,
    size,
};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{AnyThread, DefinedClass, MainThreadMarker, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSScreen, NSStatusBar, NSStatusBarButton,
    NSVariableStatusItemLength,
};
use objc2_foundation::NSString;

use crate::status::{render_status, status_dot};
use crate::ui::{Glance, GlanceError, PanelView, read_fresh};
use config::Config;
use net_observer_ipc::StatusSnapshot;

/// How often the glance re-reads the store and refreshes the status dot + panel.
const REFRESH: Duration = Duration::from_secs(3);
/// How often the click task polls the status-item click flag. Small enough to
/// feel instant, cheap enough to leave the CPU idle (one atomic load per tick).
const CLICK_POLL: Duration = Duration::from_millis(100);
/// Fixed size of the anchored panel (a compact dropdown, not a resizable
/// workspace). Width/height in gpui logical pixels.
pub(crate) const PANEL_W: f64 = 320.0;
// Grown by the height of the two sparklines (caption + 28pt plot each, plus their
// separator) added above the status rows.
pub(crate) const PANEL_H: f64 = 560.0;
/// After a click-away dismissal, a status-item click that arrives within this
/// window is treated as the gesture that *caused* the dismissal (so the panel
/// stays closed) rather than a request to reopen it. It must comfortably cover
/// the resign-key -> click-action ordering plus one [`CLICK_POLL`] interval.
const REOPEN_GUARD: Duration = Duration::from_millis(400);

define_class!(
    /// A tiny Objective-C object used purely as the status-item button's
    /// target/action sink. Its `handleClick:` runs on the main thread and only
    /// flips the shared flag; the gpui side does the real work.
    #[unsafe(super(NSObject))]
    #[name = "ObserverBarClickTarget"]
    #[ivars = Arc<AtomicBool>]
    struct ClickTarget;

    impl ClickTarget {
        #[unsafe(method(handleClick:))]
        fn handle_click(&self, _sender: Option<&AnyObject>) {
            self.ivars().store(true, Ordering::SeqCst);
        }
    }
);

impl ClickTarget {
    fn new(flag: Arc<AtomicBool>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(flag);
        // SAFETY: `ClickTarget`'s superclass is `NSObject` (see the `define_class!`
        // `#[unsafe(super(NSObject))]`), whose `-init` is the designated
        // initializer and takes no arguments. `this` is a freshly `alloc`ed,
        // not-yet-initialized instance with its ivars already set, so calling
        // `[super init]` on it exactly once here is the correct, required
        // initialization. `init` returns `Retained<Self>`, matching this fn's
        // return type and transferring ownership of the +1 retain to the caller.
        unsafe { msg_send![super(this), init] }
    }
}

/// Run the menu-bar app. Blocks (drives the AppKit run loop) until the user
/// quits. GUI code cannot run headlessly, so this is verified by compiling +
/// clippy; the tested surface is the data layer ([`crate::status`], [`crate::ui`]).
pub fn run(config: Option<String>, start: Option<crate::StartWindow>) {
    // Config is best-effort here: the GUI must not fail to launch just because a
    // config file is malformed — fall back to defaults and surface a down daemon
    // in the panel as an "offline" state instead. `config` is the `--config` path
    // (its `socket_path` is the daemon socket the bar talks to).
    //
    // The failure this catches is now wider than a parse error: `Config::load`
    // also fails when an explicitly named `--config` does not exist, is not a
    // regular file, or is not readable. `net-observerd` treats that as fatal — a
    // typo'd path must not have it bind a socket and open a database nobody asked
    // for — but the bar deliberately does not: a GUI that refuses to start leaves
    // the user with nothing, no panel and no way to see why.
    //
    // Non-fatal is not the same as silent: when the operator *named* a path and
    // it failed to load, the default socket is almost certainly the wrong one,
    // so the bar would render an unexplained "offline". Keep launching, but say
    // why — on stderr and (below) in the panel.
    let (cfg, config_msg) = match Config::load(config.as_deref()) {
        Ok(c) => (c, None),
        Err(e) => {
            let msg = config
                .as_deref()
                .map(|path| format!("failed to load {path}: {e}"));
            if let Some(msg) = &msg {
                eprintln!("net-observer-bar: {msg}");
            }
            (Config::default(), msg)
        }
    };
    let socket_path = cfg.socket_path.clone();

    Application::new().run(move |cx: &mut App| {
        let mtm = MainThreadMarker::new()
            .expect("gpui's Application::run closure runs on the main thread");

        // 1. Dockless: no Dock icon / no app bundle needed for dev. gpui already
        //    set `.regular` before this closure ran, so `.accessory` here wins.
        let ns_app = NSApplication::sharedApplication(mtm);
        let _ = ns_app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

        // 2. Initial snapshot (best-effort) and the shared model the panel reads.
        let (initial, initial_err) = match read_fresh(&socket_path) {
            Ok(s) => (s, None),
            Err(e) => (StatusSnapshot::default(), Some(e)),
        };
        let model = cx.new(|_| Glance::new(initial.clone(), initial_err, socket_path.clone()));
        // A bad `--config` goes into `control_msg`, not `error`: the 3s refresh
        // task rewrites `error` on every tick (it would be gone before anyone
        // could read it) but never touches `control_msg`.
        if let Some(msg) = config_msg {
            model.update(cx, |g, _| g.control_msg = Some(msg));
        }

        // 3. The status-item + its button. Keep the item retained for the whole
        //    app lifetime (see the refresh task, which owns it).
        let status_bar = NSStatusBar::systemStatusBar();
        let item = status_bar.statusItemWithLength(NSVariableStatusItemLength);
        let button = item
            .button(mtm)
            .expect("a freshly created NSStatusItem always has a button");
        apply_glyph(&button, model.read(cx));

        // A retained handle to the status-item button for the click task, so it
        // can compute the dropdown anchor *at open time*. The button is NOT laid
        // out yet during this startup closure — its frame is zero, which would put
        // the panel off-screen — so we must read the frame on the first click.
        // `Retained::clone` just bumps the refcount (same underlying button).
        let button_for_click = button.clone();
        // Shared latch stamped by the click-away dismiss, so the same click that
        // dismissed the panel doesn't immediately reopen it (see `toggle_panel`).
        let dismissed_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));

        // 4. Wire the click: button -> ClickTarget.handleClick: -> flip the flag.
        //    Seed it with the panel request so `--open` / `--window panel` pops
        //    the panel on the first poll.
        let click_flag = Arc::new(AtomicBool::new(start == Some(crate::StartWindow::Panel)));
        let target = ClickTarget::new(click_flag.clone());
        // SAFETY: `setTarget:`/`setAction:` are the standard AppKit control
        // wiring. `target_ref` points at a live `ClickTarget` (an `NSObject`
        // subclass, a valid `NSControl` target); the `handleClick:` selector
        // names the method `ClickTarget` actually defines (see the
        // `#[unsafe(method(handleClick:))]` above), with the matching
        // `(id sender)` signature AppKit invokes. `NSControl` retains its target
        // *weakly*, so `target` must outlive `button`: the click task below moves
        // `target` into itself (`let _target = target;`) and lives for the app's
        // lifetime alongside the retained status item, keeping it alive.
        unsafe {
            let target_ref: &AnyObject = &target;
            button.setTarget(Some(target_ref));
            button.setAction(Some(sel!(handleClick:)));
        }

        // 5. Refresh task: re-read every REFRESH, update model + glyph. Owns
        //    `item` and `button` (both `NSStatusItem`/button are main-thread
        //    objects) so they stay alive for the app's lifetime.
        cx.spawn({
            let model = model.clone();
            let socket_path = socket_path.clone();
            async move |acx: &mut AsyncApp| {
                // Keep the status item alive alongside the button.
                let _item = item;
                loop {
                    Timer::after(REFRESH).await;
                    let fresh = read_fresh(&socket_path);
                    let updated = acx.update(|app| {
                        model.update(app, |g, cx| {
                            match fresh {
                                Ok(s) => {
                                    g.snapshot = s;
                                    g.error = None;
                                }
                                Err(e) => g.error = Some(e),
                            }
                            // One tick = one sparkline column. Recorded here and
                            // only here, so the panel's history keeps the REFRESH
                            // cadence (see `Glance::record_tick`).
                            g.record_tick();
                            cx.notify();
                        });
                        apply_glyph(&button, model.read(app));
                    });
                    // The app is shutting down; stop the loop.
                    if updated.is_err() {
                        break;
                    }
                }
            }
        })
        .detach();

        // 6. Click task: poll the flag; on a click, toggle the anchored panel.
        cx.spawn({
            let model = model.clone();
            let dismissed_at = dismissed_at.clone();
            async move |acx: &mut AsyncApp| {
                // Keep the target alive: NSControl holds its target weakly.
                let _target = target;
                // The status-item button; the anchor is computed from its frame at
                // open time (see `open_panel`), when it is actually laid out.
                let button = button_for_click;
                let mut panel: Option<WindowHandle<PanelView>> = None;
                // The non-panel startup window, opened once on the first poll —
                // by then the app is up and the model already holds the startup
                // snapshot, so the window does not render on nothing. Same route
                // as a menu click: each window's own `open_or_focus`.
                let mut pending = match start {
                    Some(crate::StartWindow::Panel) | None => None,
                    other => other,
                };
                loop {
                    Timer::after(CLICK_POLL).await;
                    if let Some(what) = pending.take() {
                        let alive = acx.update(|app| {
                            let socket = model.read(app).socket_path.clone();
                            match what {
                                crate::StartWindow::Map => crate::map::open_or_focus(app, &model),
                                crate::StartWindow::Air => {
                                    crate::air::open_or_focus(app, &model, socket);
                                }
                                crate::StartWindow::Events => {
                                    crate::events::open_or_focus(app, &model, socket);
                                }
                                crate::StartWindow::Panel => {}
                            }
                        });
                        if alive.is_err() {
                            break;
                        }
                    }
                    if click_flag.swap(false, Ordering::AcqRel) {
                        let alive = acx.update(|app| {
                            toggle_panel(app, &mut panel, &model, &button, &dismissed_at)
                        });
                        if alive.is_err() {
                            break;
                        }
                    }
                }
            }
        })
        .detach();
    });
}

/// Set the status-item button's title (icon-only health dot) and tooltip (the
/// full multi-line [`render_status`] text, shown on hover).
///
/// The menu-bar title is just the [`status_dot`] — a single colored dot, no text
/// (Tailscale-style). The verbose detail still lives in the hover tooltip.
///
/// Four shells wrap the pure [`status_dot`]/[`render_status`] renderers (which
/// describe a live snapshot only, so they stay untouched):
/// - **offline** ([`GlanceError::Unreachable`] — daemon down / socket absent): a
///   grey `⚫` dot and a tooltip explaining why, rather than stale health shown as
///   live.
/// - **bad answer** ([`GlanceError::Protocol`]): the daemon *is* reachable — it
///   answered, we just could not use the answer (an error frame, or a decode
///   failure against an older daemon). A `⚠` glyph and a tooltip that says so,
///   never "offline", which would be a false claim about the world.
/// - **paused** (collection turned off via the panel switch): a `⏸` glyph and a
///   "paused" tooltip prefix — the daemon is alive but not collecting, so the
///   live health dot would be misleading.
/// - **observing**: the live [`status_dot`] + [`render_status`].
fn apply_glyph(button: &NSStatusBarButton, glance: &Glance) {
    let title: &str = match &glance.error {
        Some(GlanceError::Unreachable(_)) => "\u{26AB}", // ⚫ offline (daemon down)
        Some(GlanceError::Protocol(_)) => "\u{26A0}",    // ⚠ up, but the answer is unusable
        None if !glance.snapshot.observing => "\u{23F8}", // ⏸ paused (collection off)
        None => status_dot(&glance.snapshot),
    };
    button.setTitle(&NSString::from_str(title));

    let tooltip = match &glance.error {
        Some(GlanceError::Unreachable(e)) => format!("net-observer offline\n{e}"),
        Some(GlanceError::Protocol(e)) => {
            format!("net-observer: daemon reachable, but its answer failed\n{e}")
        }
        None if !glance.snapshot.observing => {
            format!("paused\n{}", render_status(&glance.snapshot))
        }
        None => render_status(&glance.snapshot),
    };
    button.setToolTip(Some(&NSString::from_str(&tooltip)));
}

/// Toggle the anchored panel: open it if closed, close it if open.
///
/// This is the *click* path. It cooperates with the click-away dismiss (which
/// closes the window when it loses key focus and stamps `dismissed_at`) to give a
/// single predictable rule — a click flips the panel's visibility — despite the
/// two racing on macOS (clicking the status item resigns the popup's key status):
///
/// - If we still hold a live window, the click landed before any resign-key
///   dismissal: close it in place.
/// - If the window is already gone, the click-away handler closed it. When that
///   happened *just now* (within [`REOPEN_GUARD`]), this very click is what
///   dismissed it, so we leave it closed; otherwise it was dismissed earlier and
///   the click means "open again".
fn toggle_panel(
    cx: &mut App,
    panel: &mut Option<WindowHandle<PanelView>>,
    model: &Entity<Glance>,
    button: &NSStatusBarButton,
    dismissed_at: &Arc<Mutex<Option<Instant>>>,
) {
    if let Some(handle) = panel.take() {
        // `update` succeeds only while the window is still open.
        if handle
            .update(cx, |_, window, _| window.remove_window())
            .is_ok()
        {
            // Closed by this click; leave `panel` cleared.
            return;
        }
        // Already dismissed by click-away. If that just happened, this click is
        // the dismissing gesture — stay closed.
        if recently_dismissed(dismissed_at) {
            return;
        }
        // Dismissed a while ago: fall through and reopen.
    }
    open_panel(cx, panel, model, button, dismissed_at);
}

/// True if the panel was dismissed by click-away within [`REOPEN_GUARD`].
fn recently_dismissed(dismissed_at: &Arc<Mutex<Option<Instant>>>) -> bool {
    dismissed_at
        .lock()
        .ok()
        .and_then(|guard| *guard)
        .is_some_and(|at| at.elapsed() < REOPEN_GUARD)
}

/// Open the anchored panel and store its handle. Wires the click-away dismiss:
/// once the popup has been key and then loses it, it stamps `dismissed_at` and
/// closes itself. Never panics — a failed open is logged, not fatal.
fn open_panel(
    cx: &mut App,
    panel: &mut Option<WindowHandle<PanelView>>,
    model: &Entity<Glance>,
    button: &NSStatusBarButton,
    dismissed_at: &Arc<Mutex<Option<Instant>>>,
) {
    let model = model.clone();
    let dismissed_at = dismissed_at.clone();
    // Raised while the actions menu owns the focus. Opening that menu takes key
    // focus from this panel, and losing key focus is exactly what dismisses the
    // panel — without the latch the panel would vanish the moment its own menu
    // appeared, taking the menu's parent out from under it.
    let menu_guard = model.read(cx).menu_focus_guard.clone();
    // Compute the anchor now, at open time: the button is laid out by now, so its
    // frame is real (a startup capture sees a zero frame and lands off-screen).
    let mtm =
        MainThreadMarker::new().expect("open_panel runs on the main thread (gpui App update)");
    let anchor = compute_anchor_bounds(button, mtm);
    let model_for_handle = model.clone();
    let options = panel_window_options(anchor);
    let opened = cx.open_window(options, move |window, cx| {
        cx.new(move |cx| {
            let view = PanelView::new(model, cx);
            wire_click_away_dismiss(window, cx, menu_guard, dismissed_at);
            view
        })
    });
    match opened {
        Ok(handle) => {
            *panel = Some(handle);
            // The menu needs its parent's handle: the click that dismisses the
            // menu landed outside both, so it closes the panel too.
            model_for_handle.update(cx, |g, _| g.panel_window = Some(handle.into()));
            // Accessory apps don't get key focus for free; activate so the panel
            // comes to the front, is interactive, and can register losing key
            // focus (the click-away dismiss).
            cx.activate(true);
        }
        Err(e) => eprintln!("net-observer-bar: failed to open panel window: {e}"),
    }
}

/// Dismiss-on-click-away via gpui's window-activation observation: close the
/// popup once it has been active and then resigns key.
///
/// The `was_active` latch skips the opening activation (and any spurious
/// deactivate before the panel is ever shown). `menu_guard` is raised while the
/// actions menu owns the focus — opening that menu takes key focus from this
/// panel, and without the latch the panel would vanish the moment its own menu
/// appeared, taking the menu's parent out from under it.
///
/// `detach` keeps the subscription alive for the window's lifetime — it is
/// dropped with the window — so we needn't store it, and `PanelView` (ui.rs)
/// stays untouched.
///
/// Split out of [`open_panel`] (whose other half needs a real `NSStatusBarButton`
/// for the anchor) so the headless UI tests can raise exactly this wiring on a
/// gpui test window.
fn wire_click_away_dismiss(
    window: &mut Window,
    cx: &mut Context<PanelView>,
    menu_guard: Arc<AtomicBool>,
    dismissed_at: Arc<Mutex<Option<Instant>>>,
) {
    let mut was_active = false;
    cx.observe_window_activation(window, move |_view, window, _cx| {
        if window.is_window_active() {
            was_active = true;
        } else if was_active && !menu_guard.load(Ordering::SeqCst) {
            if let Ok(mut guard) = dismissed_at.lock() {
                *guard = Some(Instant::now());
            }
            window.remove_window();
        }
    })
    .detach();
}

/// Window options for the anchored dropdown: a borderless, fixed-size
/// [`WindowKind::PopUp`] (no titlebar; not resizable / minimizable / movable),
/// positioned at `anchor` (see [`compute_anchor_bounds`]).
fn panel_window_options(anchor: Bounds<Pixels>) -> WindowOptions {
    WindowOptions {
        // The whole point of the look: `Blurred` installs an NSVisualEffectView
        // behind the window, which is the same mechanism Apple's own menus use.
        // The panel fill (`Theme::surface`) must stay translucent or this buys
        // nothing — an opaque fill covers the material completely.
        window_background: WindowBackgroundAppearance::Blurred,
        window_bounds: Some(WindowBounds::Windowed(anchor)),
        titlebar: None,
        kind: WindowKind::PopUp,
        is_resizable: false,
        is_minimizable: false,
        is_movable: false,
        focus: true,
        show: true,
        ..Default::default()
    }
}

/// Compute the gpui window bounds that anchor the panel directly under the
/// status-item icon, right-aligned to it — the Tailscale-style dropdown.
///
/// ## Coordinate conversion
///
/// Two coordinate systems meet here and they disagree about which way `y` runs.
/// Cocoa's `NSScreen`/`NSWindow` frames put the origin at the screen's
/// **bottom**-left, so a menu-bar item sits near `display_height`. gpui's
/// `WindowBounds::Windowed(bounds)` takes `bounds.origin` as the window's
/// **top**-left with `y` measured from the screen's *top*. So the conversion is
/// one subtraction and no panel-height term:
///
/// ```text
/// ox = btn.origin.x - screen.origin.x     // panel's left edge under the icon
/// oy = display_height - btn.origin.y      // panel's top edge at the menu-bar bottom
/// ```
///
/// Verified on a 1470x956 display: a laid-out item reports `origin (871, 923)`,
/// which yields `(871, 33)` and draws the panel directly under the icon. An
/// earlier version of this comment claimed gpui's origin was the window's bottom
/// and that `PANEL_H` had to be subtracted; that would have put the panel's top
/// at y≈1383, entirely above the screen. It was wrong.
///
/// gpui opens `display_id: None` windows on the primary display (which owns the
/// menu bar), matching `NSScreen::mainScreen`; the status item is assumed to live
/// there too, which is the usual case.
fn compute_anchor_bounds(button: &NSStatusBarButton, mtm: MainThreadMarker) -> Bounds<Pixels> {
    let panel_size = size(px(PANEL_W as f32), px(PANEL_H as f32));

    let btn = button.window().map(|w| w.frame());
    let scr = NSScreen::mainScreen(mtm).map(|s| s.frame());

    // A status-item window that has not been laid out yet reports a frame that
    // is not on the screen at all — measured: origin (0, -33) on a 1470x956
    // display, which the arithmetic below faithfully turns into an anchor below
    // the screen's bottom edge. Cocoa screen coordinates put the origin at the
    // BOTTOM-left, so a real menu-bar item sits near `display_height`, never at
    // a negative y. Treat anything else as "not laid out" and fall through to
    // the nominal top-right anchor, which is wrong by a few pixels rather than
    // off-screen. (Reproduced with `--open`, which opens the panel during
    // startup, before the item is placed.)
    let btn = btn.filter(|b| match scr {
        Some(scr) => b.origin.y > scr.size.height * 0.5,
        None => false,
    });
    match (btn, scr) {
        (Some(btn), Some(scr)) => {
            let display_height = scr.size.height;
            // Empirically, gpui-0.2.2 places the window with bounds.origin as its
            // TOP-LEFT (x from screen left, y from screen top). Anchor the panel
            // directly under the icon, hanging down and to the right (there is more
            // room to the right of a near-right menu-bar item than to its left):
            //   x = icon left edge, y = menu-bar bottom (display_height - btn.y).
            let max_x = (scr.size.width - PANEL_W).max(0.0);
            let ox = (btn.origin.x - scr.origin.x).clamp(0.0, max_x);
            let oy = (display_height - btn.origin.y).max(0.0);
            Bounds {
                origin: point(px(ox as f32), px(oy as f32)),
                size: panel_size,
            }
        }
        // No status window yet but we know the screen: anchor to its top-right,
        // just under a nominal menu bar.
        (None, Some(scr)) => Bounds {
            origin: point(px((scr.size.width - PANEL_W) as f32), px(24.0)),
            size: panel_size,
        },
        // Nothing to go on: top-left. Never panics; the human will notice.
        _ => Bounds {
            origin: point(px(0.0), px(0.0)),
            size: panel_size,
        },
    }
}

/// Headless UI tests for the panel's dismissal wiring, on gpui's own test
/// platform: real windows, real activation transitions, no display and no
/// rasterization.
#[cfg(test)]
mod headless_tests {
    use super::*;
    use gpui::{Modifiers, TestAppContext, VisualTestContext};
    use net_observer_ipc::StatusSnapshot;

    /// Open a panel window wired exactly as [`open_panel`] wires the real one.
    fn panel(
        cx: &mut TestAppContext,
    ) -> (
        Entity<Glance>,
        WindowHandle<PanelView>,
        Arc<Mutex<Option<Instant>>>,
    ) {
        let model = cx.update(|cx| {
            cx.new(|_| {
                Glance::new(
                    StatusSnapshot::default(),
                    None,
                    "/tmp/net-observer-test.sock".to_string(),
                )
            })
        });
        let dismissed_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
        let guard = cx.update(|cx| model.read(cx).menu_focus_guard.clone());
        let for_view = model.clone();
        let for_wiring = dismissed_at.clone();
        let window = cx.add_window(move |window, cx| {
            let view = PanelView::new(for_view, cx);
            wire_click_away_dismiss(window, cx, guard, for_wiring);
            view
        });
        cx.update(|cx| {
            model.update(cx, |g, _| g.panel_window = Some(window.into()));
        });
        (model, window, dismissed_at)
    }

    /// Give the actions menu the key focus, as the window server does when it
    /// opens.
    fn activate_menu(cx: &mut VisualTestContext, model: &Entity<Glance>) {
        let menu = cx
            .update(|_, cx| model.read(cx).menu_window)
            .expect("the actions menu is open");
        cx.update(|_, cx| {
            menu.update(cx, |_, window, _| window.activate_window())
                .expect("the menu window is live");
        });
        cx.run_until_parked();
    }

    fn is_open(cx: &mut TestAppContext, window: WindowHandle<PanelView>) -> bool {
        let handle: gpui::AnyWindowHandle = window.into();
        cx.windows().contains(&handle)
    }

    /// Opening the actions menu must not take the panel down with it.
    ///
    /// The panel dismisses itself when it resigns key focus, and opening its own
    /// menu is exactly that. The regression this pins: the panel vanishing under
    /// the cursor the instant its menu appeared, which was only ever visible by
    /// clicking "Menu" and watching.
    #[gpui::test]
    fn the_panel_survives_its_own_menu_taking_focus(cx: &mut TestAppContext) {
        let (model, window, _dismissed) = panel(cx);
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.update(|window, _| window.activate_window());
        vcx.run_until_parked();

        let trigger = vcx
            .debug_bounds("menu-trigger")
            .expect("the footer's Menu row was laid out");
        vcx.simulate_click(trigger.center(), Modifiers::none());
        vcx.run_until_parked();

        assert!(
            vcx.update(|_, cx| model.read(cx).menu_window.is_some()),
            "clicking the footer's Menu row must open the actions menu"
        );
        assert!(
            vcx.update(|_, cx| model
                .read(cx)
                .menu_focus_guard
                .load(std::sync::atomic::Ordering::SeqCst)),
            "the focus guard must be raised while the menu owns the focus"
        );

        // The menu takes key focus, which is what deactivates the panel — assert
        // the deactivation really happened, or "the panel survived" would be
        // true of a panel that was simply never asked to close.
        activate_menu(&mut vcx, &model);
        assert!(
            !vcx.update(|window, _| window.is_window_active()),
            "precondition: the menu taking focus deactivates the panel"
        );
        assert!(
            is_open(cx, window),
            "the panel closed when its own menu took the focus"
        );
    }

    /// The negative control: with no menu open, resigning key focus *does* close
    /// the panel. Without this, the test above would still pass on a panel that
    /// never dismisses itself at all.
    #[gpui::test]
    fn the_panel_still_dismisses_on_a_plain_click_away(cx: &mut TestAppContext) {
        let (_model, window, dismissed) = panel(cx);
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.update(|window, _| window.activate_window());
        vcx.run_until_parked();
        vcx.deactivate_window();
        vcx.run_until_parked();

        assert!(
            !is_open(cx, window),
            "a click away with no menu open must dismiss the panel"
        );
        assert!(
            dismissed.lock().expect("dismissal stamp").is_some(),
            "the dismissal must be stamped, so the next status-item click reopens \
             rather than being swallowed as the dismissing gesture"
        );
    }

    /// A click landing *in the panel* dismisses the menu and leaves the panel
    /// alone.
    ///
    /// Clicking into the panel deactivates the menu exactly like clicking away
    /// does, and at that instant the panel is not yet key — which is how the
    /// panel used to close under the operator's own click. The handoff delay is
    /// what distinguishes the two, and this drives it end to end.
    #[gpui::test]
    fn clicking_into_the_panel_closes_the_menu_but_not_the_panel(cx: &mut TestAppContext) {
        let (model, window, _dismissed) = panel(cx);
        let mut vcx = VisualTestContext::from_window(window.into(), cx);
        vcx.update(|window, _| window.activate_window());
        vcx.run_until_parked();
        let trigger = vcx
            .debug_bounds("menu-trigger")
            .expect("the footer's Menu row was laid out");
        vcx.simulate_click(trigger.center(), Modifiers::none());
        vcx.run_until_parked();
        assert!(
            vcx.update(|_, cx| model.read(cx).menu_window.is_some()),
            "precondition: the menu is open"
        );
        activate_menu(&mut vcx, &model);

        // The menu ignores losing focus for `crate::menu::OPEN_GRACE`, and that
        // grace is wall-clock (`Instant`), not the test executor's simulated
        // clock — so this one wait is real. It is the only sleep in the suite.
        std::thread::sleep(Duration::from_millis(340));
        // The operator clicks in the panel: the panel becomes key, which is the
        // menu's deactivation.
        vcx.update(|window, _| window.activate_window());
        vcx.run_until_parked();
        // `close_panel_unless_it_took_focus` waits on the executor's timer.
        vcx.executor().advance_clock(Duration::from_millis(400));
        vcx.run_until_parked();

        assert!(
            vcx.update(|_, cx| model.read(cx).menu_window.is_none()),
            "the menu must close when the click lands in the panel"
        );
        assert!(
            is_open(cx, window),
            "the panel must survive the click that dismissed its menu"
        );
    }
}
