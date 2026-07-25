//! The macOS menu-bar shell: a dockless (`.accessory`) app whose `NSStatusItem`
//! shows a compact health glyph, and whose click opens a gpui panel rendering
//! the full [`Status`](crate::status::Status).
//!
//! Fallback rung **(a)** of the design's ladder: a real `NSStatusItem` (AppKit
//! interop via `objc2` / `objc2-app-kit`) whose click opens a gpui panel/window.
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
//! flips an `AtomicBool`. A gpui foreground task polls that flag and opens (or
//! re-focuses) the panel window — keeping all gpui/window work on gpui's own
//! executor rather than reentering it from an AppKit callback. A second
//! foreground task re-reads the store every ~3s and updates both the shared
//! model (so an open panel re-renders) and the status-item glyph + tooltip.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gpui::{
    App, AppContext, Application, AsyncApp, Bounds, Entity, Timer, TitlebarOptions, WindowBounds,
    WindowHandle, WindowKind, WindowOptions, px, size,
};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{AnyThread, DefinedClass, MainThreadMarker, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSStatusBar, NSStatusBarButton,
    NSVariableStatusItemLength,
};
use objc2_foundation::NSString;

use crate::status::{Status, render_status, status_glyph};
use crate::ui::{Glance, PanelView, read_fresh};
use config::Config;

/// How often the glance re-reads the store and refreshes the glyph + panel.
const REFRESH: Duration = Duration::from_secs(3);
/// How often the click task polls the status-item click flag. Small enough to
/// feel instant, cheap enough to leave the CPU idle (one atomic load per tick).
const CLICK_POLL: Duration = Duration::from_millis(100);

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
/// clippy; the tested surface is the data layer ([`crate::status`], [`crate::db`]).
pub fn run() {
    // Config is best-effort here: the GUI must not fail to launch just because a
    // config file is malformed — fall back to defaults and surface DB problems in
    // the panel instead.
    let cfg = Config::load(None).unwrap_or_default();
    let db_path = cfg.db_path.clone();

    Application::new().run(move |cx: &mut App| {
        let mtm = MainThreadMarker::new()
            .expect("gpui's Application::run closure runs on the main thread");

        // 1. Dockless: no Dock icon / no app bundle needed for dev. gpui already
        //    set `.regular` before this closure ran, so `.accessory` here wins.
        let ns_app = NSApplication::sharedApplication(mtm);
        let _ = ns_app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

        // 2. Initial snapshot (best-effort) and the shared model the panel reads.
        let (initial, initial_err) = match read_fresh(&db_path) {
            Ok(s) => (s, None),
            Err(e) => (Status::default(), Some(e.to_string())),
        };
        let model = cx.new(|_| Glance::new(initial.clone(), initial_err, db_path.clone()));

        // 3. The status-item + its button. Keep the item retained for the whole
        //    app lifetime (see the refresh task, which owns it).
        let status_bar = NSStatusBar::systemStatusBar();
        let item = status_bar.statusItemWithLength(NSVariableStatusItemLength);
        let button = item
            .button(mtm)
            .expect("a freshly created NSStatusItem always has a button");
        apply_glyph(&button, model.read(cx));

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
            let db_path = db_path.clone();
            async move |acx: &mut AsyncApp| {
                // Keep the status item alive alongside the button.
                let _item = item;
                loop {
                    Timer::after(REFRESH).await;
                    let fresh = read_fresh(&db_path);
                    let updated = acx.update(|app| {
                        model.update(app, |g, cx| {
                            match fresh {
                                Ok(s) => {
                                    g.status = s;
                                    g.error = None;
                                }
                                Err(e) => g.error = Some(e.to_string()),
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

        // 6. Click task: poll the flag; on a click, open or re-focus the panel.
        cx.spawn({
            let model = model.clone();
            async move |acx: &mut AsyncApp| {
                // Keep the target alive: NSControl holds its target weakly.
                let _target = target;
                let mut panel: Option<WindowHandle<PanelView>> = None;
                loop {
                    Timer::after(CLICK_POLL).await;
                    if click_flag.swap(false, Ordering::AcqRel) {
                        let alive = acx.update(|app| toggle_panel(app, &mut panel, &model));
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

/// Set the status-item button's title (compact glyph) and tooltip (the full
/// multi-line [`render_status`] text, shown on hover).
fn apply_glyph(button: &NSStatusBarButton, glance: &Glance) {
    let title = match &glance.error {
        Some(_) => "\u{26A0} observer".to_string(), // ⚠ observer
        None => status_glyph(&glance.status),
    };
    button.setTitle(&NSString::from_str(&title));

    let tooltip = match &glance.error {
        Some(e) => format!("observer\nstore unavailable: {e}"),
        None => render_status(&glance.status),
    };
    button.setToolTip(Some(&NSString::from_str(&tooltip)));
}

/// Open the panel window, or re-focus it if it is already open.
fn toggle_panel(cx: &mut App, panel: &mut Option<WindowHandle<PanelView>>, model: &Entity<Glance>) {
    if let Some(handle) = *panel {
        // If the window is still open, bring it to the front instead of stacking
        // a second one. `update` fails once the window has been closed.
        if handle
            .update(cx, |_, window, _| window.activate_window())
            .is_ok()
        {
            cx.activate(true);
            return;
        }
    }

    let model = model.clone();
    let options = panel_window_options(cx);
    match cx.open_window(options, move |_window, cx| {
        cx.new(|cx| PanelView::new(model, cx))
    }) {
        Ok(handle) => {
            *panel = Some(handle);
            // Accessory apps don't get key focus for free; activate so the panel
            // comes to the front and is interactive.
            cx.activate(true);
        }
        Err(e) => eprintln!("observer-bar: failed to open panel window: {e}"),
    }
}

fn panel_window_options(cx: &mut App) -> WindowOptions {
    // Panel size is fixed; a compact glance, not a resizable workspace.
    let bounds = Bounds::centered(None, size(px(360.0), px(480.0)), cx);
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        titlebar: Some(TitlebarOptions {
            title: Some("observer".into()),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        kind: WindowKind::Normal,
        is_resizable: false,
        is_minimizable: false,
        focus: true,
        show: true,
        ..Default::default()
    }
}
