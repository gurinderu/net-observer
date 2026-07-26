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
    App, AppContext, Application, AsyncApp, Bounds, Entity, Pixels, Timer, WindowBounds,
    WindowHandle, WindowKind, WindowOptions, point, px, size,
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
use crate::ui::{Glance, PanelView, read_fresh};
use config::Config;
use observer_ipc::StatusSnapshot;

/// How often the glance re-reads the store and refreshes the status dot + panel.
const REFRESH: Duration = Duration::from_secs(3);
/// How often the click task polls the status-item click flag. Small enough to
/// feel instant, cheap enough to leave the CPU idle (one atomic load per tick).
const CLICK_POLL: Duration = Duration::from_millis(100);
/// Fixed size of the anchored panel (a compact dropdown, not a resizable
/// workspace). Width/height in gpui logical pixels.
const PANEL_W: f64 = 320.0;
const PANEL_H: f64 = 460.0;
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
pub fn run() {
    // Config is best-effort here: the GUI must not fail to launch just because a
    // config file is malformed — fall back to defaults and surface a down daemon
    // in the panel as an "offline" state instead.
    let cfg = Config::load(None).unwrap_or_default();
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
        let click_flag = Arc::new(AtomicBool::new(false));
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
                loop {
                    Timer::after(CLICK_POLL).await;
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
/// When the last fetch failed (daemon down / socket absent) the glance carries an
/// `error`: the title becomes a grey "offline" dot (`⚫`) and the tooltip explains
/// why, rather than showing stale health as if it were live.
fn apply_glyph(button: &NSStatusBarButton, glance: &Glance) {
    let title: &str = match &glance.error {
        Some(_) => "\u{26AB}", // ⚫ offline (daemon down) — dot only, no text
        None => status_dot(&glance.snapshot),
    };
    button.setTitle(&NSString::from_str(title));

    let tooltip = match &glance.error {
        Some(e) => format!("observer offline\n{e}"),
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
    // Compute the anchor now, at open time: the button is laid out by now, so its
    // frame is real (a startup capture sees a zero frame and lands off-screen).
    let mtm =
        MainThreadMarker::new().expect("open_panel runs on the main thread (gpui App update)");
    let anchor = compute_anchor_bounds(button, mtm);
    let options = panel_window_options(anchor);
    let opened = cx.open_window(options, move |window, cx| {
        cx.new(move |cx| {
            let view = PanelView::new(model, cx);
            // Dismiss-on-click-away via gpui's window-activation observation:
            // close the popup once it has been active and then resigns key. The
            // `was_active` latch skips the opening activation (and any spurious
            // deactivate before the panel is ever shown). `detach` keeps the
            // subscription alive for the window's lifetime — it is dropped with
            // the window — so we needn't store it, and `PanelView` (ui.rs) stays
            // untouched.
            let mut was_active = false;
            cx.observe_window_activation(window, move |_view, window, _cx| {
                if window.is_window_active() {
                    was_active = true;
                } else if was_active {
                    if let Ok(mut guard) = dismissed_at.lock() {
                        *guard = Some(Instant::now());
                    }
                    window.remove_window();
                }
            })
            .detach();
            view
        })
    });
    match opened {
        Ok(handle) => {
            *panel = Some(handle);
            // Accessory apps don't get key focus for free; activate so the panel
            // comes to the front, is interactive, and can register losing key
            // focus (the click-away dismiss).
            cx.activate(true);
        }
        Err(e) => eprintln!("observer-bar: failed to open panel window: {e}"),
    }
}

/// Window options for the anchored dropdown: a borderless, fixed-size
/// [`WindowKind::PopUp`] (no titlebar; not resizable / minimizable / movable),
/// positioned at `anchor` (see [`compute_anchor_bounds`]).
fn panel_window_options(anchor: Bounds<Pixels>) -> WindowOptions {
    WindowOptions {
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
/// gpui-0.2.2's macOS backend turns `WindowBounds::Windowed(bounds)` into the
/// native window's bottom-left content-rect origin as (see gpui
/// `platform/mac/window.rs`):
///
/// ```text
/// ns.x = screen.origin.x + bounds.origin.x
/// ns.y = screen.origin.y + (display_height - bounds.origin.y)
/// ```
///
/// where `ns` is the window's **bottom-left** corner in Cocoa screen coords and
/// `display_height == main screen frame height`. So `bounds.origin.y` maps to the
/// window's *bottom*, not its top — we must account for the panel height. We pick
/// the desired native rect (right edge under the icon, top edge at the menu-bar
/// bottom `btn.origin.y`, hence Cocoa bottom `btn.origin.y - PANEL_H`) and invert
/// the mapping to get `bounds.origin`. gpui opens `display_id: None` windows on
/// the primary display (which owns the menu bar), matching `NSScreen::mainScreen`.
///
/// Captured once at startup: menu-bar status items are stable for the app's life,
/// so the frame does not move. Assumes the status item lives on the primary
/// display (the usual case); a graceful fallback covers the rare cases where the
/// status window or main screen isn't available yet.
fn compute_anchor_bounds(button: &NSStatusBarButton, mtm: MainThreadMarker) -> Bounds<Pixels> {
    let panel_size = size(px(PANEL_W as f32), px(PANEL_H as f32));

    let btn = button.window().map(|w| w.frame());
    let scr = NSScreen::mainScreen(mtm).map(|s| s.frame());

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
