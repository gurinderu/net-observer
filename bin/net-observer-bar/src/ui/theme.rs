//! Theme tokens and menu-row metrics for the bar's windows.

use gpui::WindowAppearance;

/// A light/dark token set for the panel. Adapts to the system appearance so the
/// menu reads as native in either mode (see [`Theme::for_appearance`]); the view
/// never hardcodes a single palette. Colors are 24-bit RGB hex.
///
/// Shared crate-wide (also used by the event-log window in [`crate::events`]) so
/// the panel and the window read as one consistent, appearance-aware surface.
#[derive(Clone, Copy)]
pub(crate) struct Theme {
    /// Opaque surface, for the windows that are ordinary windows — the event
    /// log. Never the popover: see `surface`.
    pub(crate) bg: u32,
    /// The popover surface, **`0xRRGGBBAA`**. Deliberately translucent: the
    /// panel window is opened `Blurred`, which puts an `NSVisualEffectView`
    /// behind it, and a fully opaque fill would hide the very material that
    /// makes a menu-bar popover look like part of the menu bar. This is also
    /// why the base colour is lighter than instinct suggests — Apple's dark
    /// menu reads mid-grey, not near-black, because the desktop shows through
    /// it. Darkening the fill walks away from the target instead of toward it.
    pub(crate) surface: u32,
    /// Primary ink (labels, app name).
    pub(crate) fg: u32,
    /// Secondary text and disabled/muted values.
    pub(crate) muted: u32,
    /// Hairline separator between sections.
    pub(crate) separator: u32,
    /// The popover's outer edge, `0xRRGGBBAA`. A native menu is not a flat
    /// rectangle: it carries a faint light rim that lifts it off whatever is
    /// behind. Without it the panel reads as a hole rather than a surface.
    pub(crate) edge: u32,
    /// Semantic "good" (healthy verdicts).
    pub(crate) ok: u32,
    /// Semantic "bad" (failed/degraded verdicts, open incidents).
    pub(crate) bad: u32,
    /// Semantic "warn" (control action / offline banner).
    pub(crate) warn: u32,
    /// Accent for the neutral text action (Refresh) and the selected chip.
    pub(crate) accent: u32,
    /// The toggle track when observing (on) — green.
    pub(crate) track_on: u32,
    /// The toggle track when paused (off) — grey.
    pub(crate) track_off: u32,
    /// The toggle knob (also the ink on a filled/selected accent chip).
    pub(crate) knob: u32,
    /// Hover wash under a text action.
    pub(crate) hover: u32,
}

impl Theme {
    /// Pick the light or dark token set from the window's system appearance.
    /// Vibrant variants collapse onto their plain light/dark counterparts.
    pub(crate) fn for_appearance(appearance: WindowAppearance) -> Self {
        match appearance {
            WindowAppearance::Dark | WindowAppearance::VibrantDark => Self::dark(),
            WindowAppearance::Light | WindowAppearance::VibrantLight => Self::light(),
        }
    }

    /// Near-white surface, dark ink, hairline separators — the macOS light menu.
    pub(crate) fn light() -> Self {
        Self {
            bg: 0xf6f6f7,
            surface: 0xf2f2f4f2,
            edge: 0x00000026,
            fg: 0x1d1d1f,
            muted: 0x86868b,
            separator: 0xe4e4e7,
            ok: 0x1f9d4d,
            bad: 0xd93a3a,
            warn: 0xb26a00,
            accent: 0x0a6cff,
            track_on: 0x34c759,
            track_off: 0xcfcfd4,
            knob: 0xffffff,
            hover: 0xececef,
        }
    }

    /// Near-black surface, light ink — the macOS dark menu. The surface is
    /// deliberately darker than the app chrome around it: a menu-bar popover
    /// reads as part of the menu bar, not as a window, and a mid-grey panel
    /// floats away from it. `separator` and `hover` are pinned to this surface
    /// rather than chosen independently — lighten the background without them
    /// and the hairlines turn into visible bars.
    pub(crate) fn dark() -> Self {
        Self {
            bg: 0x1f1f22,
            // Landed by bisection against a native NSMenu shown side by side:
            // #0d0d0f read darker than the system menu, #1e1e20 read lighter,
            // so the surface sits between them. Do not "correct" this by eye
            // against the app chrome — the reference is a real menu on the same
            // display, and both directions were tried and rejected.
            surface: 0x161618f2,
            edge: 0xffffff1f,
            fg: 0xe8e8ec,
            muted: 0x9a9aa2,
            separator: 0x38383d,
            ok: 0x4fce6e,
            bad: 0xff5c5c,
            warn: 0xe6b450,
            accent: 0x6ea8fe,
            track_on: 0x34c759,
            track_off: 0x4a4a50,
            knob: 0xffffff,
            hover: 0x2c2c31,
        }
    }
}

// ---- menu row metrics ------------------------------------------------------
//
// One set of numbers for the footer's submenu trigger and for every row of the
// flyout window ([`crate::menu`]), so the row a submenu opens from and the rows
// it opens into are the same object at the same size. They are the metrics of a
// native macOS menu item: a full-width row about 28pt tall, 13pt label, 10pt of
// side padding, and the small corner radius the system highlight is drawn with.
// Colours are never hardcoded alongside them — those come from [`Theme`], so
// light and dark both follow the system appearance.

/// Height of one menu row, in gpui logical pixels.
pub(crate) const MENU_ROW_H: f32 = 28.0;
/// Horizontal padding inside a menu row.
pub(crate) const MENU_ROW_PX: f32 = 10.0;
/// Corner radius of a menu row's highlight.
pub(crate) const MENU_ROW_RADIUS: f32 = 5.0;
/// Label size inside a menu row.
pub(crate) const MENU_ROW_TEXT: f32 = 13.0;
/// The submenu chevron. A text glyph on purpose: an icon here would mean a font
/// or asset dependency for one character.
pub(crate) const MENU_CHEVRON: &str = "›";
/// Height of a group heading in the flyout menu.
///
/// Declared rather than left to the text's own line box: the flyout's window
/// height is COMPUTED from what the menu draws, and a height that only the font
/// knows cannot be added up before the window is opened.
pub(crate) const MENU_HEADING_H: f32 = 18.0;
/// Label size of a group heading — small and muted, well inside
/// [`MENU_HEADING_H`].
pub(crate) const MENU_HEADING_TEXT: f32 = 10.0;
/// Thickness of the hairline rule between groups, drawn by [`separator`].
pub(crate) const MENU_SEPARATOR_H: f32 = 1.0;
