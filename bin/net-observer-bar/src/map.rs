//! The live **network-map** view: who else is on this segment, drawn as a
//! gateway-centred star.
//!
//! The data is the latest [`NeighborsSample`] carried on the
//! [`StatusSnapshot`](net_observer_ipc::StatusSnapshot) the panel already
//! refreshes on its ~3s timer (see [`crate::menubar`]) — this module opens no
//! socket and adds no collection. It only reshapes that sample into a picture:
//! the segment's identity (the gateway, whose MAC *is* the `network_key`) sits in
//! the middle, the other neighbours ring it, and a hairline edge joins each to the
//! gateway because they share the segment.
//!
//! gpui 0.2.2 has no graph primitive, so the star is built by hand: the edges are
//! a single stroked [`gpui::PathBuilder`] path painted by a [`gpui::canvas`] laid
//! under the nodes, and each node is an absolutely-positioned chip. The geometry
//! (ring angles, node centres) is computed by the pure helpers below so it is
//! testable without a window.
//!
//! ## Its own window
//!
//! The map opens as its **own** normal, resizable window (from the panel's "Map"
//! footer control), exactly like the event-log window opens from "Events" (see
//! [`crate::events`]). [`MapView`] is the root view; [`open_or_focus`] stashes the
//! live handle on the shared [`Glance`] so a second click focuses the open window
//! instead of duplicating it. Its live-update wiring is the panel's own transport,
//! not a new one: the map reads `snapshot.neighbors` off the shared [`Glance`],
//! which the menu-bar refresh timer re-reads every ~3s (see [`crate::menubar`]).
//! [`MapView`] observes that model and re-renders on every tick — no socket, no
//! subscription of its own.

use std::f32::consts::PI;

use gpui::prelude::*;
use gpui::{
    AnyWindowHandle, App, Bounds, Context, Entity, Pixels, Rgba, SharedString, Subscription,
    TitlebarOptions, Window, WindowBounds, WindowHandle, WindowKind, WindowOptions, canvas, div,
    point, px, rgb, rgba, size,
};

use net_observer_ipc::StatusSnapshot;
use types::{LearnedVia, NeighborObs, NeighborRole, NeighborsSample, TopologyLink};

use crate::ui::{Glance, Theme};

/// Initial size of the network-map window (resizable afterwards), gpui logical px.
const WIN_W: f32 = 360.0;
const WIN_H: f32 = 320.0;

/// The upper ceiling on ring nodes. The ACTUAL cap is whichever is smaller, this
/// or [`ring_capacity`] for the current radius, so the ring never overlaps; the
/// rest are summarised as "+N more". A first-version ceiling, not a limit on what
/// the daemon records. The map decision and gateway derivation: (realm
/// net-observer, node #34, #36).
const MAX_RING: usize = 12;

/// The fixed height of the map's plot area, in gpui logical pixels. Tall enough
/// for a ring of chips around a centred gateway without the corner chips colliding
/// with the section padding.
const MAP_H: f32 = 232.0;

/// Chip footprint. Nodes are positioned by their centre, so these are used to
/// convert a centre into a top-left inset.
const CHIP_W: f32 = 84.0;
const CHIP_H: f32 = 34.0;

/// Ring radius from the gateway at the centre to each neighbour chip's centre.
/// Sized to the available [`MAP_H`] (diameter plus a chip still fits the plot).
const RING_R: f32 = 88.0;

/// Minimum clear gap between adjacent chips on the ring.
const CHIP_GAP: f32 = 8.0;

/// A neighbour reduced to what the map draws: a stable identity, a short label and
/// which reading produced it. Derived purely from a [`NeighborObs`] so the render
/// carries no parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MapNode {
    /// The neighbour's MAC — the stable node identity the later accent seam keys
    /// on. The gateway is decided from the raw `NeighborObs` before a `MapNode` is
    /// built, so this field is not itself the discriminator.
    mac: String,
    /// The short on-chip identity (hostname, else vendor OUI, else last IP octet,
    /// else a short MAC).
    label: String,
    /// The neighbour's address, shown under the identity so a node is not only a
    /// MAC-derived handle. Empty only if the observation carried no address.
    ip: String,
    /// The daemon's confidence-rated hypothesis about this neighbour's role, the
    /// discriminator the accent seam colours by. A hypothesis, drawn as a subtle
    /// dot colour — never a hard "SWITCH" label. (realm net-observer, node #33)
    role: NeighborRole,
}

impl MapNode {
    fn from_obs(obs: &NeighborObs) -> Self {
        Self {
            mac: obs.mac.clone(),
            label: node_label(obs),
            ip: obs.ip.clone(),
            role: obs.role,
        }
    }
}

/// The short identity drawn on a node chip.
///
/// Order of preference: a known hostname (only mDNS supplies one), then the raw
/// OUI prefix, then the last octet of the IPv4 address, then the last two MAC
/// octets. The OUI here is the raw first-three-octets hex, NOT a vendor name:
/// mapping OUI→vendor through the offline IEEE registry (and treating a
/// randomized/locally-administered MAC as "unknown", never a guess) is a later
/// increment, (realm net-observer, node #36). The point is a human handle without
/// a blank chip.
fn node_label(obs: &NeighborObs) -> String {
    if let Some(host) = obs.hostname.as_deref().filter(|h| !h.is_empty()) {
        return host.to_string();
    }
    if let Some(oui) = obs.oui() {
        return oui;
    }
    if obs.ip.contains('.')
        && let Some(last) = obs.ip.rsplit('.').next().filter(|s| !s.is_empty())
    {
        return format!(".{last}");
    }
    short_mac(&obs.mac)
}

/// The last two octets of a MAC, e.g. `…:2c:3d`, as a last-resort label. A MAC too
/// short to have two octets is shown whole.
fn short_mac(mac: &str) -> String {
    let octets: Vec<&str> = mac.split(':').collect();
    if octets.len() >= 2 {
        format!(
            "\u{2026}:{}:{}",
            octets[octets.len() - 2],
            octets[octets.len() - 1]
        )
    } else {
        mac.to_string()
    }
}

/// Split a sample into the gateway node (if its MAC is present as a neighbour) and
/// the surrounding ring, capped at [`MAX_RING`]. Returns the count that was
/// dropped by the cap so the caller can note it.
///
/// The gateway is **derived**, never stored: it is the neighbour whose `mac` equals
/// the sample's `network_key` (the gateway's MAC is the segment's identity). When
/// no such neighbour is present the gateway slot is `None` and the caller draws a
/// placeholder — the ring is still the segment.
fn partition(sample: &NeighborsSample) -> (Option<MapNode>, Vec<MapNode>, usize) {
    let key = sample.network_key.as_deref();
    let mut gateway = None;
    let mut ring = Vec::new();
    for obs in &sample.neighbors {
        if gateway.is_none() && key.is_some_and(|k| k.eq_ignore_ascii_case(&obs.mac)) {
            gateway = Some(MapNode::from_obs(obs));
        } else {
            ring.push(MapNode::from_obs(obs));
        }
    }
    // Cap by what the ring can actually hold without overlap, never above the
    // first-version ceiling; the remainder is summarised as "+N more".
    let cap = ring_capacity(RING_R).min(MAX_RING);
    let dropped = ring.len().saturating_sub(cap);
    ring.truncate(cap);
    (gateway, ring, dropped)
}

/// How many chips fit on a ring of radius `r` without their footprints
/// overlapping. Adjacent centres are `2·r·sin(π/n)` apart, so the largest `n`
/// that keeps that at least `CHIP_W + CHIP_GAP` is `π / asin((CHIP_W+CHIP_GAP)/(2r))`.
/// This is why the ring is capped by geometry, not by a guessed constant: a fixed
/// cap of 12 packed a narrow panel into a pile of overlapping chips (the star only
/// holds a handful at a legible size — a busy segment shows "+N more" instead).
fn ring_capacity(r: f32) -> usize {
    let arg = (CHIP_W + CHIP_GAP) / (2.0 * r);
    if arg >= 1.0 {
        // Even two chips would touch: show at most one.
        return 1;
    }
    (PI / arg.asin()).floor().max(1.0) as usize
}

/// The centre points of `n` evenly-spaced nodes on a ring of radius `r` around
/// `(cx, cy)`, starting at the top (12 o'clock) and going clockwise. Pure, so the
/// layout is testable without a window. A single neighbour still sits at the top
/// rather than overlapping the gateway.
fn ring_positions(n: usize, cx: f32, cy: f32, r: f32) -> Vec<(f32, f32)> {
    (0..n)
        .map(|i| {
            let angle = -PI / 2.0 + (2.0 * PI * i as f32) / n as f32;
            (cx + r * angle.cos(), cy + r * angle.sin())
        })
        .collect()
}

/// The dot colour for one node — its ROLE hypothesis, drawn subtly.
///
/// The gateway keeps the accent (it is also `NeighborRole::Gateway`, but the map
/// decides the gateway from the raw key before a `MapNode` exists, so honour that
/// flag first). Infra reads in `track_on` — a distinct active tint, deliberately
/// NOT the `warn` amber (which means "something is wrong" on the quiet/offline
/// chips), so network gear stands out as a role, not an alert; a host keeps the
/// primary ink; an unknown role (randomized MAC, or no OUI snapshot to reason
/// from) is muted, reading as least load-bearing. The role is a HYPOTHESIS: a
/// colour, never an asserted "SWITCH". (realm net-observer, nodes #33, #34, #36)
fn node_accent(node: &MapNode, is_gateway: bool, theme: Theme) -> Rgba {
    if is_gateway {
        return rgb(theme.accent);
    }
    match node.role {
        NeighborRole::Gateway => rgb(theme.accent),
        NeighborRole::Infra { .. } => rgb(theme.track_on),
        NeighborRole::Host => rgb(theme.fg),
        NeighborRole::Unknown => rgb(theme.muted),
    }
}

/// One node chip: a coloured dot and a short, single-line label. The gateway is
/// filled and bold so the segment's identity reads first; a neighbour is a light
/// outlined chip.
fn node_chip(node: &MapNode, is_gateway: bool, theme: Theme) -> impl IntoElement {
    let dot = node_accent(node, is_gateway, theme);
    let mut chip = div()
        .flex()
        .items_center()
        .gap_1()
        .w(px(CHIP_W))
        .h(px(CHIP_H))
        .px_1p5()
        .rounded_md()
        .overflow_hidden();
    if is_gateway {
        chip = chip.bg(rgb(theme.accent)).text_color(rgb(theme.knob));
    } else {
        chip = chip
            .bg(rgba(theme.surface))
            .border_1()
            .border_color(rgb(theme.separator))
            .text_color(rgb(theme.fg));
    }
    let dot_color = if is_gateway { rgb(theme.knob) } else { dot };
    // A subdued IP colour that stays legible on both the plain and the accented
    // (gateway) chip background.
    let ip_color = if is_gateway {
        rgb(theme.knob)
    } else {
        rgb(theme.muted)
    };
    chip.child(
        div()
            .text_size(px(8.0))
            .text_color(dot_color)
            .child("\u{25CF}"),
    )
    .child(
        // Identity on top, address beneath — the node is named AND addressed.
        div()
            .flex_1()
            .overflow_hidden()
            .flex()
            .flex_col()
            .child(
                div()
                    .overflow_hidden()
                    .text_size(px(11.0))
                    .when(is_gateway, |d| d.font_weight(gpui::FontWeight::BOLD))
                    .child(node.label.clone()),
            )
            .when(!node.ip.is_empty(), |d| {
                d.child(
                    div()
                        .overflow_hidden()
                        .text_size(px(9.0))
                        .text_color(ip_color)
                        .child(node.ip.clone()),
                )
            }),
    )
}

/// The most uplink switches/APs the strip draws before it summarises the rest as
/// "+N more". A machine has one or two real uplinks; more than this is unusual
/// (several VLAN sub-interfaces, say) and does not need to all fit at once.
const MAX_UPLINKS: usize = 3;

/// Height of the uplink strip drawn above the neighbour star, in gpui logical px.
const UPLINK_H: f32 = 58.0;

/// One LLDP/CDP-discovered uplink reduced to what the strip draws: which
/// switch/AP this machine connects to and on which of that device's ports.
/// Derived purely from a [`TopologyLink`] so the render carries no parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UplinkNode {
    /// The switch/AP's human label: its advertised system name, else its chassis
    /// identity.
    label: String,
    /// The remote device's port this machine is plugged into.
    port: String,
    /// Whether LLDP or CDP carried the advertisement.
    via: LearnedVia,
}

impl UplinkNode {
    fn from_link(link: &TopologyLink) -> Self {
        let label = link
            .remote_system_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&link.remote_chassis)
            .to_string();
        Self {
            label,
            port: link.remote_port.clone(),
            via: link.learned_via,
        }
    }
}

/// The uplink nodes to draw and the count dropped by the [`MAX_UPLINKS`] cap.
/// Deduplicated by label+port so the same switch advertised on several protocols
/// or several times is one node. Pure, so it is testable without a window.
fn uplinks(snapshot: &StatusSnapshot) -> (Vec<UplinkNode>, usize) {
    let mut nodes: Vec<UplinkNode> = Vec::new();
    for link in &snapshot.topology {
        let node = UplinkNode::from_link(link);
        if !nodes
            .iter()
            .any(|n| n.label == node.label && n.port == node.port)
        {
            nodes.push(node);
        }
    }
    let dropped = nodes.len().saturating_sub(MAX_UPLINKS);
    nodes.truncate(MAX_UPLINKS);
    (nodes, dropped)
}

/// The strip of uplink switch/AP nodes drawn above the neighbour star: each a
/// distinctly-marked chip (a square glyph in the infra tint, deliberately unlike
/// the round neighbour dots) joined by an edge down to a shared "this Mac"
/// anchor. The edge is the discovered physical path — a hypothesis LLDP/CDP
/// advertised, drawn subtly, never a hard claim. (realm net-observer, node #42)
fn uplink_strip(nodes: &[UplinkNode], dropped: usize, theme: Theme) -> impl IntoElement {
    let n = nodes.len();
    // Chip centres spread evenly across the top; the anchor sits bottom-centre.
    let width = 296.0;
    let anchor = (width / 2.0, UPLINK_H - 6.0);
    let xs: Vec<f32> = (0..n)
        .map(|i| {
            let step = width / (n as f32 + 1.0);
            step * (i as f32 + 1.0)
        })
        .collect();
    let top_y = 6.0 + CHIP_H / 2.0;

    let edge_color = rgb(theme.track_on);
    let targets: Vec<(f32, f32)> = xs.iter().map(|x| (*x, top_y)).collect();
    let edges = canvas(
        move |_bounds, _window, _cx| {},
        move |bounds: Bounds<Pixels>, _prepaint: (), window, _cx| {
            let mut builder = gpui::PathBuilder::stroke(px(1.0));
            let origin = bounds.origin;
            let a = point(origin.x + px(anchor.0), origin.y + px(anchor.1));
            for (tx, ty) in &targets {
                builder.move_to(a);
                builder.line_to(point(origin.x + px(*tx), origin.y + px(*ty)));
            }
            if let Ok(path) = builder.build() {
                window.paint_path(path, edge_color);
            }
        },
    );

    let mut area = div()
        .relative()
        .w_full()
        .h(px(UPLINK_H))
        .child(div().absolute().size_full().child(edges));

    for (node, x) in nodes.iter().zip(xs.iter()) {
        area = area.child(
            div()
                .absolute()
                .left(px(x - CHIP_W / 2.0))
                .top(px(6.0))
                .child(uplink_chip(node, theme)),
        );
    }
    let caption = if dropped > 0 {
        format!("uplinks \u{00b7} LLDP/CDP \u{00b7} +{dropped} more")
    } else {
        "uplinks \u{00b7} LLDP/CDP".to_string()
    };
    div()
        .flex()
        .flex_col()
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .pb_1()
                .child(caption),
        )
        .child(area)
}

/// One uplink chip: a square marker (distinct from the round neighbour dots) in
/// the infra tint, the switch/AP label, and its port beneath.
fn uplink_chip(node: &UplinkNode, theme: Theme) -> impl IntoElement {
    let port_line = match node.via {
        LearnedVia::Lldp => format!("{} \u{00b7} lldp", node.port),
        LearnedVia::Cdp => format!("{} \u{00b7} cdp", node.port),
    };
    div()
        .flex()
        .items_center()
        .gap_1()
        .w(px(CHIP_W))
        .h(px(CHIP_H))
        .px_1p5()
        .rounded_md()
        .overflow_hidden()
        .bg(rgba(theme.surface))
        .border_1()
        .border_color(rgb(theme.track_on))
        .text_color(rgb(theme.fg))
        .child(
            div()
                .text_size(px(9.0))
                .text_color(rgb(theme.track_on))
                .child("\u{25A0}"),
        )
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .flex()
                .flex_col()
                .child(
                    div()
                        .overflow_hidden()
                        .text_size(px(11.0))
                        .child(node.label.clone()),
                )
                .child(
                    div()
                        .overflow_hidden()
                        .text_size(px(9.0))
                        .text_color(rgb(theme.muted))
                        .child(port_line),
                ),
        )
}

/// Place a chip at a centre point inside the relative map area.
fn placed_chip(
    node: &MapNode,
    is_gateway: bool,
    cx: f32,
    cy: f32,
    theme: Theme,
) -> impl IntoElement {
    div()
        .absolute()
        .left(px(cx - CHIP_W / 2.0))
        .top(px(cy - CHIP_H / 2.0))
        .child(node_chip(node, is_gateway, theme))
}

/// The network-map section, rendered from the latest neighbour sample already on
/// the snapshot. No socket, no collection — a re-shape of `snapshot.neighbors`.
///
/// Renders an honest empty state when there is no sample yet, the reading could
/// not run, or nobody answered — never a blank panel.
pub fn network_map_section(snapshot: &StatusSnapshot, theme: Theme) -> impl IntoElement {
    let base = div().flex().flex_col().px_3().py_2();

    // Uplinks are independent of the neighbour star: an LLDP/CDP-discovered
    // switch can be known even before any neighbour reading has run.
    let (uplink_nodes_v, uplink_dropped) = uplinks(snapshot);
    let has_uplinks = !uplink_nodes_v.is_empty();

    let sample = snapshot.neighbors.as_ref();
    let neighbours_empty = sample.is_none_or(|s| s.neighbors.is_empty());

    // Only a truly empty panel — no neighbours AND no uplinks — is the honest
    // empty state; uplinks alone are still worth drawing.
    if neighbours_empty && !has_uplinks {
        let msg = match sample {
            None => "no neighbour reading yet".to_string(),
            Some(s) => match &s.reason {
                Some(reason) => format!("no neighbours: {reason}"),
                None => "no neighbours seen \u{00b7} press Scan to look".to_string(),
            },
        };
        return empty_state(base, msg, theme);
    }

    // Uplinks but no neighbour star yet: draw just the uplink strip.
    if neighbours_empty {
        return base
            .child(uplink_strip(&uplink_nodes_v, uplink_dropped, theme))
            .into_any_element();
    }
    let sample = sample.expect("neighbours non-empty implies a sample");

    let (gateway, ring, dropped) = partition(sample);

    // Centre of the plot area. The section spans the panel's content width
    // (~296pt after the px_3 padding); the ring radius keeps corner chips inside it.
    let center_x = 148.0;
    let center_y = MAP_H / 2.0;
    let positions = ring_positions(ring.len(), center_x, center_y, RING_R);

    // Edges: one stroked path from the gateway centre to each neighbour centre,
    // painted under the nodes. Captured by value so the canvas closure owns them.
    let edge_targets: Vec<(f32, f32)> = positions.clone();
    let edge_color = rgb(theme.separator);
    let edges = canvas(
        move |_bounds, _window, _cx| {},
        move |bounds: Bounds<Pixels>, _prepaint: (), window, _cx| {
            let mut builder = gpui::PathBuilder::stroke(px(1.0));
            let origin = bounds.origin;
            let gw = point(origin.x + px(center_x), origin.y + px(center_y));
            for (nx, ny) in &edge_targets {
                builder.move_to(gw);
                builder.line_to(point(origin.x + px(*nx), origin.y + px(*ny)));
            }
            if let Ok(path) = builder.build() {
                window.paint_path(path, edge_color);
            }
        },
    );

    let mut area = div()
        .relative()
        .w_full()
        .h(px(MAP_H))
        .child(div().absolute().size_full().child(edges));

    // The gateway at the centre — its real chip, or a muted placeholder when the
    // segment's identity was not itself seen as a neighbour this tick.
    match &gateway {
        Some(gw) => {
            area = area.child(placed_chip(gw, true, center_x, center_y, theme));
        }
        None => {
            area = area.child(
                div()
                    .absolute()
                    .left(px(center_x - CHIP_W / 2.0))
                    .top(px(center_y - CHIP_H / 2.0))
                    .child(node_chip(
                        &MapNode {
                            mac: String::new(),
                            label: "gateway ?".to_string(),
                            ip: String::new(),
                            role: NeighborRole::Gateway,
                        },
                        true,
                        theme,
                    )),
            );
        }
    }

    for (node, (cx, cy)) in ring.iter().zip(positions.iter()) {
        area = area.child(placed_chip(node, false, *cx, *cy, theme));
    }

    let mut section = base;
    // The uplink strip sits above the star when there is one to draw.
    if has_uplinks {
        section = section.child(uplink_strip(&uplink_nodes_v, uplink_dropped, theme));
    }
    section = section.child(caption(sample, ring.len(), gateway.is_some(), theme));
    section = section.child(area);
    if dropped > 0 {
        section = section.child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(format!("+{dropped} more not shown")),
        );
    }
    section.into_any_element()
}

/// The one-line caption above the star: the interface and how many devices the
/// segment showed. States plainly when the gateway itself was not among them.
fn caption(
    sample: &NeighborsSample,
    shown: usize,
    has_gateway: bool,
    theme: Theme,
) -> impl IntoElement {
    let iface = sample.iface.as_deref().unwrap_or("segment");
    let gw = if has_gateway {
        ""
    } else {
        " \u{00b7} gateway not seen"
    };
    div()
        .flex()
        .items_center()
        .justify_between()
        .pb_1()
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(format!("{iface}{gw}")),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .child(format!(
                    "{shown} neighbour{}",
                    if shown == 1 { "" } else { "s" }
                )),
        )
}

/// A muted, single-line honest empty state — shown instead of a blank map area.
fn empty_state(
    base: gpui::Div,
    message: impl Into<gpui::SharedString>,
    theme: Theme,
) -> gpui::AnyElement {
    base.child(
        div()
            .py_1()
            .text_color(rgb(theme.muted))
            .child(message.into()),
    )
    .into_any_element()
}

/// A hairline separator — a 1px full-width rule, matching the event window.
fn separator(theme: Theme) -> impl IntoElement {
    div().h(px(1.0)).w_full().bg(rgb(theme.separator))
}

/// The root view of the **network-map window**. Holds a handle to the shared
/// [`Glance`] and re-renders whenever it changes — the same live-update path the
/// panel uses (the menu-bar refresh timer writes the snapshot every ~3s; see
/// [`crate::menubar`]), so this window carries no socket and no subscription of its
/// own. It only reshapes `snapshot.neighbors` into the star (see
/// [`network_map_section`]).
pub(crate) struct MapView {
    model: Entity<Glance>,
    _observe: Subscription,
}

impl MapView {
    fn new(model: Entity<Glance>, cx: &mut Context<Self>) -> Self {
        // Re-render this view whenever the shared model is notified (timer tick or
        // manual refresh) — the same observation the panel registers.
        let observe = cx.observe(&model, |_, _, cx| cx.notify());
        Self {
            model,
            _observe: observe,
        }
    }
}

impl Render for MapView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let snapshot = self.model.read(cx).snapshot.clone();
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .child(separator(theme))
            .child(network_map_section(&snapshot, theme))
    }
}

/// Open the network-map window, or bring the already-open one to the front.
///
/// The live window handle is stashed on the shared [`Glance`] so a second click
/// focuses the existing window instead of opening a duplicate. A stale handle
/// (window since closed) falls through to a fresh open. Modeled exactly on
/// [`crate::events::open_or_focus`]; never panics — a failed open is logged, not
/// fatal.
pub(crate) fn open_or_focus(cx: &mut App, glance: &Entity<Glance>) {
    if let Some(existing) = glance.read(cx).map_window {
        // `update` succeeds only while the window is still open.
        if existing
            .update(cx, |_view, window, _cx| window.activate_window())
            .is_ok()
        {
            cx.activate(true);
            return;
        }
    }

    if let Some(handle) = open_window(cx, glance.clone()) {
        let any: AnyWindowHandle = handle.into();
        glance.update(cx, |g, _| g.map_window = Some(any));
        // Accessory apps don't get key focus for free; bring the new window forward.
        cx.activate(true);
    }
}

/// Create the network-map window over the shared [`Glance`]. Returns the window
/// handle, or `None` if the window failed to open.
fn open_window(cx: &mut App, model: Entity<Glance>) -> Option<WindowHandle<MapView>> {
    let options = window_options(cx);
    match cx.open_window(options, move |_window, cx| {
        cx.new(|cx| MapView::new(model, cx))
    }) {
        Ok(handle) => Some(handle),
        Err(e) => {
            eprintln!("net-observer-bar: failed to open map window: {e}");
            None
        }
    }
}

/// Window options for the network map: a normal, resizable, closable window with a
/// native titlebar ("net-observer — map"), centered on the primary display —
/// mirroring the event-log window's options.
fn window_options(cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(WIN_W), px(WIN_H)), cx)),
        titlebar: Some(TitlebarOptions {
            title: Some(SharedString::from("net-observer — map")),
            appears_transparent: false,
            traffic_light_position: None,
        }),
        kind: WindowKind::Normal,
        is_movable: true,
        is_resizable: true,
        is_minimizable: true,
        focus: true,
        show: true,
        window_min_size: Some(size(px(320.0), px(260.0))),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::NeighborSource;

    fn obs(mac: &str, ip: &str, source: NeighborSource, hostname: Option<&str>) -> NeighborObs {
        NeighborObs {
            mac: mac.to_string(),
            ip: ip.to_string(),
            source,
            hostname: hostname.map(str::to_string),
            role: NeighborRole::Unknown,
        }
    }

    /// The accent seam colours a node by its ROLE hypothesis: infra, host and
    /// unknown each read as a distinct dot, and the gateway flag overrides the
    /// role entirely. Checked in both themes so neither collapses two roles.
    #[test]
    fn node_accent_differs_by_role() {
        let node = |role| MapNode {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            label: "x".into(),
            ip: "192.168.1.2".into(),
            role,
        };
        for appearance in [gpui::WindowAppearance::Dark, gpui::WindowAppearance::Light] {
            let theme = Theme::for_appearance(appearance);
            let host = node_accent(&node(NeighborRole::Host), false, theme);
            let infra = node_accent(
                &node(NeighborRole::Infra {
                    confidence: types::RoleConfidence::Low,
                }),
                false,
                theme,
            );
            let unknown = node_accent(&node(NeighborRole::Unknown), false, theme);
            assert_ne!(infra, host, "infra must not read as a host");
            assert_ne!(infra, unknown, "infra must not read as unknown");
            assert_ne!(host, unknown, "host must not read as unknown");
            // The gateway flag wins over whatever role the node carries.
            let gw = node_accent(&node(NeighborRole::Host), true, theme);
            assert_eq!(gw, rgb(theme.accent));
        }
    }

    fn sample(network_key: Option<&str>, neighbors: Vec<NeighborObs>) -> NeighborsSample {
        NeighborsSample {
            ts_us: 1,
            verdict: types::NeighborsVerdict::Ok,
            reason: None,
            network_key: network_key.map(str::to_string),
            iface: Some("en0".to_string()),
            neighbors,
        }
    }

    #[test]
    fn label_prefers_hostname_then_oui_then_ip_then_mac() {
        assert_eq!(
            node_label(&obs(
                "a4:83:e7:1b:2c:3d",
                "192.168.1.5",
                NeighborSource::Mdns,
                Some("hub.local")
            )),
            "hub.local"
        );
        assert_eq!(
            node_label(&obs(
                "a4:83:e7:1b:2c:3d",
                "192.168.1.5",
                NeighborSource::Arp,
                None
            )),
            "a4:83:e7"
        );
        // No OUI (malformed MAC) falls back to the last IP octet.
        assert_eq!(
            node_label(&obs("bad", "192.168.1.5", NeighborSource::Arp, None)),
            ".5"
        );
        // No OUI and an IPv6 address falls back to the short MAC.
        assert_eq!(
            node_label(&obs("aa:bb", "fe80::1", NeighborSource::Arp, None)),
            "\u{2026}:aa:bb"
        );
    }

    #[test]
    fn gateway_is_the_neighbour_matching_the_network_key() {
        let s = sample(
            Some("gg:gg:gg:gg:gg:gg"),
            vec![
                obs(
                    "11:11:11:11:11:11",
                    "192.168.1.2",
                    NeighborSource::Arp,
                    None,
                ),
                obs(
                    "gg:gg:gg:gg:gg:gg",
                    "192.168.1.1",
                    NeighborSource::Arp,
                    None,
                ),
            ],
        );
        let (gateway, ring, dropped) = partition(&s);
        assert_eq!(gateway.unwrap().mac, "gg:gg:gg:gg:gg:gg");
        assert_eq!(ring.len(), 1);
        assert_eq!(ring[0].mac, "11:11:11:11:11:11");
        assert_eq!(dropped, 0);
    }

    #[test]
    fn no_matching_key_leaves_the_gateway_empty_and_rings_everyone() {
        let s = sample(
            None,
            vec![obs(
                "11:11:11:11:11:11",
                "192.168.1.2",
                NeighborSource::Arp,
                None,
            )],
        );
        let (gateway, ring, _) = partition(&s);
        assert!(gateway.is_none());
        assert_eq!(ring.len(), 1);
    }

    #[test]
    fn ring_is_capped_by_geometry_and_reports_the_overflow() {
        // Far more neighbours than a legible ring can hold.
        let big = MAX_RING + 40;
        let neighbors: Vec<NeighborObs> = (0..big)
            .map(|i| {
                obs(
                    &format!("{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}"),
                    "1.2.3.4",
                    NeighborSource::Arp,
                    None,
                )
            })
            .collect();
        let (_gw, ring, dropped) = partition(&sample(None, neighbors));
        let cap = ring_capacity(RING_R).min(MAX_RING);
        assert_eq!(
            ring.len(),
            cap,
            "the ring is capped by what fits without overlap"
        );
        assert_eq!(
            dropped,
            big - cap,
            "everything past the cap is reported as dropped"
        );
    }

    /// The whole point of the geometry cap: at the chosen capacity, adjacent chip
    /// centres are at least a chip-plus-gap apart, so nothing overlaps.
    #[test]
    fn the_ring_capacity_never_lets_chips_overlap() {
        let n = ring_capacity(RING_R);
        assert!(n >= 1);
        if n >= 2 {
            let p = ring_positions(n, 0.0, 0.0, RING_R);
            let (dx, dy) = (p[1].0 - p[0].0, p[1].1 - p[0].1);
            let spacing = (dx * dx + dy * dy).sqrt();
            assert!(
                spacing >= CHIP_W + CHIP_GAP - 0.01,
                "adjacent centres {spacing} must clear a chip+gap of {}",
                CHIP_W + CHIP_GAP
            );
        }
    }

    fn link(chassis: &str, port: &str, name: Option<&str>, via: LearnedVia) -> TopologyLink {
        TopologyLink {
            iface: "en0".into(),
            remote_chassis: chassis.into(),
            remote_port: port.into(),
            remote_system_name: name.map(str::to_string),
            capabilities: "bridge".into(),
            learned_via: via,
            ts_us: 1,
        }
    }

    /// The uplink reducer prefers the advertised system name, dedups a switch
    /// seen twice, caps at [`MAX_UPLINKS`] and reports the overflow.
    #[test]
    fn uplinks_prefer_the_name_dedup_and_cap() {
        let mut snap = StatusSnapshot {
            topology: vec![
                link(
                    "00:11:22:33:44:55",
                    "Gi0/1",
                    Some("core-sw"),
                    LearnedVia::Lldp,
                ),
                // Same switch+port advertised again (e.g. via CDP too): one node.
                link(
                    "00:11:22:33:44:55",
                    "Gi0/1",
                    Some("core-sw"),
                    LearnedVia::Cdp,
                ),
            ],
            ..Default::default()
        };
        let (nodes, dropped) = uplinks(&snap);
        assert_eq!(nodes.len(), 1, "a switch seen twice is one node");
        assert_eq!(nodes[0].label, "core-sw");
        assert_eq!(nodes[0].port, "Gi0/1");
        assert_eq!(dropped, 0);

        // More distinct uplinks than the cap: capped, remainder reported.
        let many: Vec<TopologyLink> = (0..MAX_UPLINKS + 2)
            .map(|i| {
                link(
                    &format!("sw{i}"),
                    &format!("Gi0/{i}"),
                    None,
                    LearnedVia::Lldp,
                )
            })
            .collect();
        snap.topology = many;
        let (nodes, dropped) = uplinks(&snap);
        assert_eq!(nodes.len(), MAX_UPLINKS);
        assert_eq!(dropped, 2);
        // With no system name the chassis is the label.
        assert_eq!(nodes[0].label, "sw0");
    }

    /// A snapshot with uplinks but no neighbour reading still renders the strip
    /// instead of the empty state — the map is not blank when a switch is known.
    #[test]
    fn a_snapshot_with_only_uplinks_is_not_empty() {
        let snap = StatusSnapshot {
            topology: vec![link(
                "00:11:22:33:44:55",
                "Gi0/1",
                Some("core-sw"),
                LearnedVia::Lldp,
            )],
            ..Default::default()
        };
        // Building the element must not panic and must see the uplink.
        let (nodes, _) = uplinks(&snap);
        assert_eq!(nodes.len(), 1);
        let _ = network_map_section(&snap, Theme::for_appearance(gpui::WindowAppearance::Dark));
    }

    #[test]
    fn ring_positions_start_at_the_top() {
        let p = ring_positions(1, 100.0, 100.0, 50.0);
        assert_eq!(p.len(), 1);
        assert!((p[0].0 - 100.0).abs() < 0.001, "x centred");
        assert!((p[0].1 - 50.0).abs() < 0.001, "y above centre");
    }
}
