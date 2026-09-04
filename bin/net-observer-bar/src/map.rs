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
use types::{LearnedVia, NeighborObs, NeighborRole, NeighborsSample, RoleConfidence, TopologyLink};

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

/// The **smallest** the map's plot area is allowed to get, in gpui logical
/// pixels. It is a floor, not the size: the plot grows with the window (see
/// [`plot_for`]), so a maximised window draws a large star rather than a small
/// one pinned to the top-left corner.
const MAP_MIN_H: f32 = 232.0;

/// Chip footprint. Nodes are positioned by their centre, so these are used to
/// convert a centre into a top-left inset.
///
/// The width is sized to the widest thing a chip must show **without losing a
/// character**: a full dotted-quad address (`192.168.100.129`, 15 chars) at the
/// 9px address size, plus the role glyph, the gaps and the horizontal padding.
/// An address with a digit cut off is not a smaller address, it is a different
/// device — so the chip is sized for it and the *label* above it is the line
/// allowed to ellipsize. The height is a floor only ([`node_chip`] uses
/// `min_h`), so a chip grows to its content instead of clipping it.
const CHIP_W: f32 = 118.0;
const CHIP_H: f32 = 40.0;

/// Minimum clear gap between adjacent chips on the ring.
const CHIP_GAP: f32 = 8.0;

/// The smallest ring radius at which a ring chip cannot overlap the **centre**
/// (gateway) chip, whatever angle it sits at.
///
/// Two centre-aligned rectangles miss each other when their centres differ by at
/// least `CHIP_W + CHIP_GAP` horizontally **or** `CHIP_H + CHIP_GAP` vertically.
/// For a chip at angle θ off the top, those offsets are `r·sin θ` and `r·cos θ`,
/// and the worst angle is the one where both constraints bind at once; solving it
/// gives `r ≥ hypot(CHIP_W + CHIP_GAP, CHIP_H + CHIP_GAP)`.
///
/// [`ring_capacity`] only ever spaced chips from *each other*, which is why a
/// "gateway ?" placeholder could sit under the neighbour above it. This is the
/// missing constraint, applied as a floor in [`plot_for`].
fn min_ring_radius() -> f32 {
    ((CHIP_W + CHIP_GAP).powi(2) + (CHIP_H + CHIP_GAP).powi(2)).sqrt()
}

/// The star's geometry for one render, derived from the space the window actually
/// gives it rather than from a fixed constant.
///
/// Everything the layout needs is decided here and nowhere else, so the rule
/// "a bigger window shows a bigger star and hides fewer nodes" is one pure,
/// tested function instead of a scatter of magic numbers. (realm net-observer,
/// node #34)
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Plot {
    /// Plot area size in gpui logical px.
    w: f32,
    h: f32,
    /// Centre of the star — where the gateway chip goes.
    cx: f32,
    cy: f32,
    /// Ring radius from the centre to each neighbour chip's centre.
    r: f32,
    /// How many ring chips this radius can hold without overlap.
    capacity: usize,
}

/// Fit the star to an available `w` × `h` of plot area.
///
/// The radius is the largest that keeps a whole chip inside the box on every
/// side, floored at [`min_ring_radius`] so the ring can never collide with the
/// centre chip — even in a window too small to honour it, where a chip
/// overflowing the box is the lesser fault against overlapping the gateway.
/// Capacity follows the radius, so widening the window admits nodes that a
/// smaller one summarised as "+N more".
fn plot_for(w: f32, h: f32) -> Plot {
    let w = w.max(CHIP_W + CHIP_GAP);
    let h = h.max(MAP_MIN_H);
    // Half the box, less the half-chip that must stay inside the edge.
    let fit = (w / 2.0 - CHIP_W / 2.0).min(h / 2.0 - CHIP_H / 2.0);
    let r = fit.max(min_ring_radius());
    Plot {
        w,
        h,
        cx: w / 2.0,
        cy: h / 2.0,
        r,
        capacity: ring_capacity(r),
    }
}

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
fn partition(sample: &NeighborsSample, capacity: usize) -> (Option<MapNode>, Vec<MapNode>, usize) {
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
    // Cap by what the ring at THIS window's radius can hold without overlap,
    // never above the first-version ceiling; the remainder is summarised as
    // "+N more" — and is always fully visible in the list view, which has no
    // geometry to run out of.
    let cap = capacity.min(MAX_RING);
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

/// The text glyph standing for a role hypothesis. Deliberately a plain character
/// (no icon font, no new dependency) and deliberately paired everywhere with the
/// role's own words — [`role_label`] and [`role_basis`] — so the glyph is a
/// shorthand for a hypothesis the reader can unfold, never a badge asserting a
/// device type as fact. (realm net-observer, nodes #33, #36)
fn role_glyph(role: NeighborRole, is_gateway: bool) -> &'static str {
    if is_gateway {
        return "\u{21C5}";
    }
    match role {
        // Up/down arrows: everything leaves the segment through here.
        NeighborRole::Gateway => "\u{21C5}",
        // A framed square, echoing the uplink marker: network gear.
        NeighborRole::Infra { .. } => "\u{25A3}",
        NeighborRole::Host => "\u{25CF}",
        // Not a guess dressed as one.
        NeighborRole::Unknown => "?",
    }
}

/// The role in words, always hedged where the daemon hedges it.
fn role_label(role: NeighborRole, is_gateway: bool) -> String {
    if is_gateway {
        return "gateway".to_string();
    }
    match role {
        NeighborRole::Gateway => "gateway".to_string(),
        NeighborRole::Infra { confidence } => format!(
            "infra? ({})",
            match confidence {
                RoleConfidence::Low => "low",
                RoleConfidence::Medium => "medium",
                RoleConfidence::High => "high",
            }
        ),
        NeighborRole::Host => "host".to_string(),
        NeighborRole::Unknown => "unknown".to_string(),
    }
}

/// What the role hypothesis rests on — the answer to "why does it say that?",
/// so the glyph is never the only thing the operator has to go on. Mirrors the
/// derivation documented on [`NeighborRole`]; the gateway is the one near-certain
/// classification because it needs no vendor guess.
fn role_basis(role: NeighborRole, is_gateway: bool) -> &'static str {
    if is_gateway {
        return "its MAC is the segment key";
    }
    match role {
        NeighborRole::Gateway => "its MAC is the segment key",
        NeighborRole::Infra {
            confidence: RoleConfidence::Low,
        } => "guess: an infra vendor OUI alone",
        NeighborRole::Infra {
            confidence: RoleConfidence::Medium,
        } => "guess: a management port answered",
        NeighborRole::Infra {
            confidence: RoleConfidence::High,
        } => "guess: infra vendor OUI and a management port",
        NeighborRole::Host => "vendor is not network gear",
        NeighborRole::Unknown => "randomized MAC, or no vendor data",
    }
}

/// One node chip: a role glyph and a short label over the address. The gateway is
/// filled and bold so the segment's identity reads first; a neighbour is a light
/// outlined chip.
///
/// The chip's height is a **floor**, not a fixed size, and both text lines are
/// single-line with an ellipsis: a long hostname is shortened visibly, and an
/// address is never wrapped onto a second line and cut off by the chip's bottom
/// edge (which made `192.168.0.129` read as `192.168.0.12`).
fn node_chip(node: &MapNode, is_gateway: bool, theme: Theme) -> impl IntoElement {
    let dot = node_accent(node, is_gateway, theme);
    // Test handles only: no-ops unless gpui's `test-support` is on (dev-dependency),
    // where they make the chip's and the label's laid-out bounds readable, so the
    // headless UI tests can assert that chips do not overlap each other or the
    // centre, and that a label stays inside its own chip (see `headless_ui.rs`).
    let chip_selector = format!("map-chip:{}", node.label);
    let label_selector = format!("map-label:{}", node.label);
    let mut chip = div()
        .debug_selector(move || chip_selector)
        .flex()
        .items_center()
        .gap_1()
        .w(px(CHIP_W))
        .min_h(px(CHIP_H))
        .px_1p5()
        .py_0p5()
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
            .flex_shrink_0()
            .text_size(px(10.0))
            .text_color(dot_color)
            .child(role_glyph(node.role, is_gateway)),
    )
    .child(
        // Identity on top, address beneath — the node is named AND addressed.
        div()
            .flex_1()
            .overflow_hidden()
            .flex()
            .flex_col()
            .child(
                // The label is the line that may be shortened: a hostname has
                // no fixed width and an ellipsis says plainly that it was cut.
                div()
                    .debug_selector(move || label_selector)
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .text_size(px(11.0))
                    .when(is_gateway, |d| d.font_weight(gpui::FontWeight::BOLD))
                    .child(node.label.clone()),
            )
            .when(!node.ip.is_empty(), |d| {
                d.child(
                    div()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
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

/// Width of the left gutter the uplink tree's rail and stubs occupy, in gpui
/// logical px — the visual edge from the "this Mac" anchor down to each uplink.
const UPLINK_RAIL_W: f32 = 14.0;

/// One LLDP/CDP-discovered uplink reduced to what the tree draws: which switch/AP
/// this machine connects to, on which of that device's ports, over which local
/// interface, by which protocol, with what it said about itself and when it was
/// last heard. Derived purely from a [`TopologyLink`] so the render carries no
/// parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UplinkNode {
    /// The switch/AP's human label: its advertised system name, else its chassis
    /// identity.
    label: String,
    /// The chassis identity as advertised. Shown as its own line when the label
    /// came from a system name, so the identity behind a friendly name stays
    /// visible — a spoofed name is only recognisable against its chassis id.
    chassis: String,
    /// The remote device's port this machine is plugged into.
    port: String,
    /// The local interface the frame arrived on — the machine's end of the edge.
    iface: String,
    /// The device's advertised capability tokens (`bridge`, `wlan_ap`, ...),
    /// split from the comma-joined wire form. Empty when it advertised none.
    caps: Vec<String>,
    /// Whether LLDP or CDP carried the advertisement.
    via: LearnedVia,
    /// When the daemon last received an advertisement for this uplink.
    ///
    /// This is a **sighting** time, not a first-seen time: `first_seen` lives in
    /// the store's `topology_link` row and is served by the offline reader, not
    /// on the socket, so the bar — a pure socket client — cannot draw it.
    /// (realm net-observer, node #43)
    ts_us: i64,
}

impl UplinkNode {
    fn from_link(link: &TopologyLink) -> Self {
        let named = link.remote_system_name.as_deref().filter(|s| !s.is_empty());
        Self {
            label: named.unwrap_or(&link.remote_chassis).to_string(),
            chassis: link.remote_chassis.clone(),
            port: link.remote_port.clone(),
            iface: link.iface.clone(),
            caps: link
                .capabilities
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            via: link.learned_via,
            ts_us: link.ts_us,
        }
    }

    /// True when [`Self::label`] is an advertised system name rather than the
    /// chassis id — the chassis then deserves its own line.
    fn has_name(&self) -> bool {
        self.label != self.chassis
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

/// Join the non-empty parts of a line with the map's " · " separator.
///
/// The separator belongs BETWEEN two things that exist. Formatting it in
/// unconditionally is what left a chip reading `Bridge0 ·` with nothing after the
/// dot — a field that was absent rendered as a field that was lost. Every
/// multi-field line in this module goes through here.
fn join_parts(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" \u{00b7} ")
}

/// How the uplink was learned, said so a reader can weigh it: the protocol that
/// carried the advertisement, never bare.
fn uplink_via_label(via: LearnedVia) -> &'static str {
    match via {
        LearnedVia::Lldp => "advertised over LLDP",
        LearnedVia::Cdp => "advertised over CDP",
        // A protocol a newer daemon learned this uplink by that this bar does not
        // know — do not name an unbacked protocol.
        LearnedVia::Unknown => "advertised over an unknown protocol",
    }
}

/// The provenance line under an uplink: which local interface heard it and how
/// long ago. Deliberately says *heard*, not *connected since*: the socket carries
/// the latest sighting, while `first_seen` is a store column the bar never reads.
/// (realm net-observer, node #43)
fn uplink_seen_line(node: &UplinkNode, now_us: i64) -> String {
    let where_ = if node.iface.is_empty() {
        String::new()
    } else {
        format!("heard on {}", node.iface)
    };
    join_parts(&[&where_, &crate::ui::age_str(node.ts_us, now_us)])
}

/// The caption above the uplink tree. It names the reading as a hypothesis in the
/// same voice the channel-overlap and vulnerability hypotheses use: an LLDP/CDP
/// frame is unauthenticated and spoofable, so an edge here is what the wire
/// claimed, never a proven physical connection. (realm net-observer, node #43)
fn uplink_caption(dropped: usize) -> String {
    let base =
        "uplink hypothesis \u{00b7} what LLDP/CDP frames claimed, not a proven physical link";
    if dropped > 0 {
        format!("{base} \u{00b7} +{dropped} more")
    } else {
        base.to_string()
    }
}

/// The uplink tree drawn above the neighbour star: a "this Mac" anchor at the
/// top and, hanging off a left rail, one card per discovered switch/AP carrying
/// what identified it (LLDP or CDP), the chassis and port it named, what it says
/// it can do, and which of this machine's interfaces heard it.
///
/// Everything here is a hypothesis the caption names as one — the frames are
/// unauthenticated. (realm net-observer, node #43)
fn uplink_strip(nodes: &[UplinkNode], dropped: usize, theme: Theme) -> impl IntoElement {
    let now = crate::ui::now_us();
    let rail = div()
        .absolute()
        .left(px(UPLINK_RAIL_W / 2.0))
        .top(px(10.0))
        .bottom(px(10.0))
        .w(px(1.0))
        .bg(rgb(theme.track_on));

    let mut tree = div()
        .relative()
        .flex()
        .flex_col()
        .gap_1()
        .child(rail)
        .child(uplink_anchor(nodes, theme));
    for node in nodes {
        tree = tree.child(uplink_card(node, now, theme));
    }

    div()
        .flex()
        .flex_col()
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.muted))
                .pb_1()
                .child(uplink_caption(dropped)),
        )
        .child(tree)
}

/// The tree's root row: this Mac, and the interfaces the uplinks were heard on —
/// the machine's own end of every edge below it.
fn uplink_anchor(nodes: &[UplinkNode], theme: Theme) -> impl IntoElement {
    let mut ifaces: Vec<&str> = Vec::new();
    for n in nodes {
        if !ifaces.contains(&n.iface.as_str()) {
            ifaces.push(&n.iface);
        }
    }
    let label = if ifaces.is_empty() {
        "this Mac".to_string()
    } else {
        format!("this Mac \u{00b7} {}", ifaces.join(", "))
    };
    div()
        .flex()
        .items_center()
        .gap_1()
        .child(
            div()
                .w(px(UPLINK_RAIL_W))
                .flex()
                .justify_center()
                .text_size(px(9.0))
                .text_color(rgb(theme.accent))
                .child("\u{25CF}"),
        )
        .child(
            div()
                .text_size(px(11.0))
                .text_color(rgb(theme.fg))
                .child(label),
        )
}

/// One uplink card: a square marker (distinct from the round neighbour dots) in
/// the infra tint, the switch/AP label, and beneath it the chassis identity, the
/// protocol and remote port, the advertised capabilities, and where and when the
/// advertisement was heard.
fn uplink_card(node: &UplinkNode, now_us: i64, theme: Theme) -> impl IntoElement {
    // "?" is the decoder's literal for "the frame named no port at all", and an
    // empty port is no port either: neither earns a "port" clause, let alone a
    // separator introducing one.
    let port = if node.port.is_empty() || node.port == "?" {
        String::new()
    } else {
        format!("port {}", node.port)
    };
    let port_line = join_parts(&[uplink_via_label(node.via), &port]);
    let mut body = div().flex_1().overflow_hidden().flex().flex_col().child(
        div()
            .overflow_hidden()
            .text_size(px(11.0))
            .child(node.label.clone()),
    );
    if node.has_name() {
        body = body.child(
            div()
                .overflow_hidden()
                .text_size(px(9.0))
                .text_color(rgb(theme.muted))
                .child(format!("chassis {}", node.chassis)),
        );
    }
    body = body.child(
        div()
            .overflow_hidden()
            .text_size(px(9.0))
            .text_color(rgb(theme.muted))
            .child(port_line),
    );
    if !node.caps.is_empty() {
        body = body.child(
            div()
                .overflow_hidden()
                .text_size(px(9.0))
                .text_color(rgb(theme.track_on))
                .child(format!("claims {}", node.caps.join(", "))),
        );
    }
    body = body.child(
        div()
            .overflow_hidden()
            .text_size(px(9.0))
            .text_color(rgb(theme.muted))
            .child(uplink_seen_line(node, now_us)),
    );

    div()
        .flex()
        .items_start()
        .gap_1()
        // The horizontal stub joining this card to the rail on the left.
        .child(
            div()
                .w(px(UPLINK_RAIL_W))
                .h(px(CHIP_H / 2.0))
                .flex()
                .items_center()
                .justify_end()
                .child(
                    div()
                        .w(px(UPLINK_RAIL_W / 2.0))
                        .h(px(1.0))
                        .bg(rgb(theme.track_on)),
                ),
        )
        .child(
            div()
                .flex()
                .items_start()
                .gap_1()
                .flex_1()
                .p_1p5()
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
                .child(body),
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
pub(crate) fn network_map_section(
    snapshot: &StatusSnapshot,
    plot: Plot,
    theme: Theme,
) -> impl IntoElement {
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

    let (gateway, ring, dropped) = partition(sample, plot.capacity);

    // Centre and radius come from the window's real size (see `plot_for`), so a
    // maximised window spreads the star over it instead of pinning a fixed-size
    // picture to the top-left corner.
    let center_x = plot.cx;
    let center_y = plot.cy;
    let positions = ring_positions(ring.len(), center_x, center_y, plot.r);

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
        .h(px(plot.h))
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
                .child(format!(
                    "+{dropped} that the ring has no room for \u{00b7} the list shows every one"
                )),
        );
    }
    section = section.child(role_legend(theme));
    section.into_any_element()
}

/// The glyph key under the star, and the sentence that keeps it a hypothesis.
///
/// Without this the glyphs are an unexplained alphabet, and a `▣` reads as a
/// measured fact about a device. The roles are inferred from the OUI vendor and
/// from behaviour, never measured. (realm net-observer, node #36)
fn role_legend(theme: Theme) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .pt_1()
        .text_size(px(10.0))
        .text_color(rgb(theme.muted))
        .child(div().child(join_parts(&[
            "\u{21C5} gateway",
            "\u{25A3} infra?",
            "\u{25CF} host",
            "? unknown",
        ])))
        .child(div().child(
            "role is inferred from vendor OUI and behaviour, not measured \u{00b7} \
                 the list gives the grounds for each",
        ))
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

/// The neighbour **list**: every device the latest reading returned, one row each.
///
/// This is the star's complement, not a decoration. The ring is bounded by
/// geometry and summarises the overflow as "+N more"; the list has no geometry to
/// run out of, so whatever the ring could not seat is still readable here. It is
/// also where a role glyph is unfolded into the grounds it rests on
/// ([`role_basis`]), which a chip has no room for.
///
/// Columns are what the socket actually carries: role, identity, address, MAC and
/// which reading found it. There is deliberately **no first/last-seen column** —
/// `NeighborObs` carries no lifetime bounds, those live in the store's `neighbor`
/// table and reach only the offline reader, and the bar is a pure socket client.
/// (realm net-observer, node #43)
fn neighbour_list(snapshot: &StatusSnapshot, theme: Theme) -> gpui::AnyElement {
    let base = div().flex().flex_col().px_3().py_2();
    let Some(sample) = snapshot.neighbors.as_ref() else {
        return empty_state(base, "no neighbour reading yet", theme);
    };
    if sample.neighbors.is_empty() {
        let msg = match &sample.reason {
            Some(reason) => format!("no neighbours: {reason}"),
            None => "no neighbours seen \u{00b7} press Rescan to look".to_string(),
        };
        return empty_state(base, msg, theme);
    }

    let key = sample.network_key.as_deref();
    let mut rows = div().flex().flex_col().w_full();
    rows = rows.child(
        div()
            .flex()
            .w_full()
            .pb_1()
            .text_size(px(10.0))
            .text_color(rgb(theme.muted))
            .child(div().w(px(96.0)).flex_shrink_0().child("role"))
            .child(div().flex_1().min_w(px(80.0)).child("name"))
            .child(div().w(px(120.0)).flex_shrink_0().child("address"))
            .child(div().w(px(140.0)).flex_shrink_0().child("MAC"))
            .child(div().w(px(64.0)).flex_shrink_0().child("via")),
    );
    rows = rows.child(separator(theme));

    for obs in &sample.neighbors {
        let is_gateway = key.is_some_and(|k| k.eq_ignore_ascii_case(&obs.mac));
        let node = MapNode::from_obs(obs);
        let accent = node_accent(&node, is_gateway, theme);
        let name = obs
            .hostname
            .as_deref()
            .filter(|h| !h.is_empty())
            .map_or_else(|| node.label.clone(), str::to_string);
        rows = rows.child(
            div()
                .flex()
                .w_full()
                .py_0p5()
                .items_start()
                .text_size(px(11.0))
                .child(
                    div()
                        .w(px(96.0))
                        .flex_shrink_0()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(
                            div()
                                .text_color(accent)
                                .child(role_glyph(node.role, is_gateway)),
                        )
                        .child(
                            div()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .child(role_label(node.role, is_gateway)),
                        ),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w(px(80.0))
                        .flex()
                        .flex_col()
                        .overflow_hidden()
                        .child(
                            div()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .child(name),
                        )
                        // The grounds for the role, so the glyph is never the
                        // whole story.
                        .child(
                            div()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .text_size(px(9.0))
                                .text_color(rgb(theme.muted))
                                .child(role_basis(node.role, is_gateway)),
                        ),
                )
                .child(
                    div()
                        .w(px(120.0))
                        .flex_shrink_0()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .child(obs.ip.clone()),
                )
                .child(
                    div()
                        .w(px(140.0))
                        .flex_shrink_0()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .text_color(rgb(theme.muted))
                        .child(obs.mac.clone()),
                )
                .child(
                    div()
                        .w(px(64.0))
                        .flex_shrink_0()
                        .text_size(px(10.0))
                        .text_color(rgb(theme.muted))
                        .child(format!("{:?}", obs.source).to_lowercase()),
                ),
        );
    }

    base.child(
        div()
            .pb_1()
            .text_size(px(11.0))
            .text_color(rgb(theme.muted))
            .child(join_parts(&[
                sample.iface.as_deref().unwrap_or("segment"),
                &format!(
                    "{} neighbour{}",
                    sample.neighbors.len(),
                    if sample.neighbors.len() == 1 { "" } else { "s" }
                ),
                "no first/last seen on the socket \u{2014} that is a store column",
            ])),
    )
    .child(rows)
    .into_any_element()
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
    /// Which of the two readings of the same sample is on screen. The star is the
    /// shape of the segment; the list is its full contents.
    mode: MapMode,
    _observe: Subscription,
}

/// The two ways this window shows one neighbour sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MapMode {
    /// The gateway-centred star.
    Graph,
    /// Every neighbour as a row (see [`neighbour_list`]).
    List,
}

/// Vertical space the window's own chrome (header row, control line, captions,
/// legend and the uplink tree) takes before the star gets any, in gpui logical
/// px. Subtracted from the viewport so the plot is sized to what is actually
/// left rather than to the whole window.
const MAP_CHROME_H: f32 = 150.0;

/// Horizontal padding the section applies (`px_3` on both sides).
const MAP_SIDE_PAD: f32 = 24.0;

impl MapView {
    fn new(model: Entity<Glance>, cx: &mut Context<Self>) -> Self {
        // Re-render this view whenever the shared model is notified (timer tick or
        // manual refresh) — the same observation the panel registers.
        let observe = cx.observe(&model, |_, _, cx| cx.notify());
        Self {
            model,
            mode: MapMode::Graph,
            _observe: observe,
        }
    }
}

impl Render for MapView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        let glance = self.model.read(cx);
        let snapshot = glance.snapshot.clone();
        let control_msg = glance.control_msg.clone();
        let mode = self.mode;

        // The star is fitted to the space this window actually has right now.
        let viewport = window.viewport_size();
        let plot = plot_for(
            f32::from(viewport.width) - MAP_SIDE_PAD,
            f32::from(viewport.height) - MAP_CHROME_H,
        );

        let body = match mode {
            MapMode::Graph => network_map_section(&snapshot, plot, theme).into_any_element(),
            MapMode::List => neighbour_list(&snapshot, theme),
        };

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme.bg))
            .text_color(rgb(theme.fg))
            .font_family(".SystemUIFont")
            .text_size(px(13.0))
            .child(map_toolbar(mode, control_msg, theme, cx))
            .child(separator(theme))
            .child(body)
    }
}

/// The map window's own controls: the graph/list switch and Rescan.
///
/// Rescan runs the **same** acting-gated round-trip the panel's "Scan" button
/// runs ([`crate::ui::scan_round_trip_base`]) — a neighbour sweep addresses other
/// machines, so a daemon without `acting.enabled` refuses it and answers
/// `ok: false` with a reason, which lands in the line below the buttons as
/// `failed: …`. There is no timer behind it: it fires on a click and only on a
/// click. (v1 = observe, never act — this is the one operator-initiated exception
/// the daemon itself gates.)
fn map_toolbar(
    mode: MapMode,
    control_msg: Option<String>,
    theme: Theme,
    cx: &mut Context<MapView>,
) -> impl IntoElement {
    let tab = |label: &'static str, this: MapMode, theme: Theme, cx: &mut Context<MapView>| {
        let selected = mode == this;
        div()
            .id(label)
            .px_2()
            .py_1()
            .rounded_md()
            .text_size(px(12.0))
            .cursor_pointer()
            .text_color(rgb(if selected { theme.accent } else { theme.muted }))
            .when(selected, |d| d.bg(rgb(theme.hover)))
            .hover(|s| s.bg(rgb(theme.hover)))
            .child(label)
            .on_click(cx.listener(move |view, _, _window, cx| {
                view.mode = this;
                cx.notify();
            }))
    };

    let rescan = div()
        .id("map-rescan")
        .px_2()
        .py_1()
        .rounded_md()
        .text_size(px(12.0))
        // Warn-coloured for the same reason the panel's Scan is: this one is not
        // routine, it addresses machines that are not this one.
        .text_color(rgb(theme.warn))
        .cursor_pointer()
        .hover(|s| s.bg(rgb(theme.hover)))
        .child("Rescan")
        .on_click(cx.listener(|view, _, _window, cx| {
            crate::ui::spawn_control_on(&view.model, cx, crate::ui::scan_round_trip_base);
        }));

    div()
        .flex()
        .flex_col()
        .px_3()
        .py_1()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(tab("Graph", MapMode::Graph, theme, cx))
                        .child(tab("List", MapMode::List, theme, cx)),
                )
                .child(rescan),
        )
        // The outcome of the last control action, shown verbatim: a refusal
        // ("acting disabled") must read as a refusal, never as a silent no-op.
        .when_some(control_msg, |d, msg| {
            let failed = msg.starts_with("failed");
            d.child(
                div()
                    .pt_1()
                    .text_size(px(10.0))
                    .text_color(rgb(if failed { theme.warn } else { theme.muted }))
                    .child(msg),
            )
        })
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
        let (gateway, ring, dropped) = partition(&s, test_plot().capacity);
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
        let (gateway, ring, _) = partition(&s, test_plot().capacity);
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
        let plot = test_plot();
        let (_gw, ring, dropped) = partition(&sample(None, neighbors), plot.capacity);
        let cap = plot.capacity.min(MAX_RING);
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
        let r = test_plot().r;
        let n = ring_capacity(r);
        assert!(n >= 1);
        if n >= 2 {
            let p = ring_positions(n, 0.0, 0.0, r);
            let (dx, dy) = (p[1].0 - p[0].0, p[1].1 - p[0].1);
            let spacing = (dx * dx + dy * dy).sqrt();
            assert!(
                spacing >= CHIP_W + CHIP_GAP - 0.01,
                "adjacent centres {spacing} must clear a chip+gap of {}",
                CHIP_W + CHIP_GAP
            );
        }
    }

    /// The geometry of a default-sized map window — the layout the pre-resize
    /// tests were written against.
    fn test_plot() -> Plot {
        plot_for(WIN_W - MAP_SIDE_PAD, WIN_H - MAP_CHROME_H)
    }

    /// A ring chip can never land on top of the centre (gateway) chip, at any
    /// angle and at any window size — the collision the owner saw between
    /// "gateway ?" and the node above it.
    #[test]
    fn no_ring_chip_can_overlap_the_gateway() {
        // Includes a window far too small to honour the radius: the floor still
        // holds, because overlapping the gateway is the worse failure.
        for (w, h) in [
            (80.0, 60.0),
            (336.0, 170.0),
            (1440.0, 900.0),
            (3000.0, 1800.0),
        ] {
            let plot = plot_for(w, h);
            let n = plot.capacity.clamp(1, MAX_RING);
            for (x, y) in ring_positions(n, plot.cx, plot.cy, plot.r) {
                let dx = (x - plot.cx).abs();
                let dy = (y - plot.cy).abs();
                assert!(
                    dx >= CHIP_W + CHIP_GAP - 0.01 || dy >= CHIP_H + CHIP_GAP - 0.01,
                    "chip at ({x},{y}) overlaps the centre in a {w}x{h} window",
                );
            }
        }
    }

    /// A bigger window is a bigger star that hides fewer nodes — the defect was a
    /// fixed-size picture in the corner of a maximised window, summarising nodes
    /// as "+N more" with room to spare.
    #[test]
    fn the_plot_grows_with_the_window() {
        let small = plot_for(336.0, 170.0);
        let large = plot_for(1440.0, 900.0);
        assert!(large.r > small.r, "radius follows the window");
        assert!(large.cx > small.cx, "the star stays centred, not cornered");
        assert!(large.cy > small.cy);
        assert!(
            large.capacity > small.capacity,
            "more room must mean more nodes shown: {} vs {}",
            large.capacity,
            small.capacity
        );
        // The floor is never breached, however small the window gets.
        assert!(plot_for(10.0, 10.0).r >= min_ring_radius() - 0.01);
    }

    /// A separator is only ever written between two fields that exist — the
    /// `Bridge0 ·` defect.
    #[test]
    fn an_absent_field_leaves_no_dangling_separator() {
        assert_eq!(join_parts(&["a", "b"]), "a \u{00b7} b");
        assert_eq!(join_parts(&["a", ""]), "a");
        assert_eq!(join_parts(&["", "b"]), "b");
        assert_eq!(join_parts(&["", "  "]), "");

        // A frame that named no port carries the decoder's literal "?": the card
        // must then say nothing about a port, not trail a separator.
        let mut l = link("sw", "?", None, LearnedVia::Lldp);
        l.capabilities = String::new();
        let node = UplinkNode::from_link(&l);
        let line = join_parts(&[uplink_via_label(node.via), ""]);
        assert!(!line.ends_with('\u{00b7}'), "{line}");
        assert!(!line.contains("port"), "{line}");

        // And an uplink heard on no named interface does not trail one either.
        let mut anon = UplinkNode::from_link(&link("sw", "Gi0/1", None, LearnedVia::Lldp));
        anon.iface = String::new();
        let seen = uplink_seen_line(&anon, anon.ts_us);
        assert!(
            !seen.starts_with('\u{00b7}') && !seen.ends_with('\u{00b7}'),
            "{seen}"
        );
    }

    /// Every role glyph is paired with words, and no hedged role is ever stated
    /// flatly: an inferred role must not read as a measured one.
    #[test]
    fn a_role_glyph_never_stands_as_a_fact() {
        let roles = [
            NeighborRole::Gateway,
            NeighborRole::Infra {
                confidence: RoleConfidence::Low,
            },
            NeighborRole::Infra {
                confidence: RoleConfidence::High,
            },
            NeighborRole::Host,
            NeighborRole::Unknown,
        ];
        for role in roles {
            assert!(!role_glyph(role, false).is_empty());
            assert!(!role_label(role, false).is_empty());
            assert!(
                !role_basis(role, false).is_empty(),
                "every role must say what it rests on"
            );
        }
        // The one near-certain classification is the only one stated plainly.
        assert_eq!(role_label(NeighborRole::Gateway, true), "gateway");
        // An inference is marked as one and carries its confidence.
        let infra = role_label(
            NeighborRole::Infra {
                confidence: RoleConfidence::Low,
            },
            false,
        );
        assert!(infra.contains('?'), "{infra}");
        assert!(infra.contains("low"), "{infra}");
        assert!(
            role_basis(
                NeighborRole::Infra {
                    confidence: RoleConfidence::Low
                },
                false
            )
            .contains("guess"),
            "an infra hypothesis names itself a guess"
        );
        // The gateway flag wins over whatever role the observation carried.
        assert_eq!(
            role_glyph(NeighborRole::Host, true),
            role_glyph(NeighborRole::Gateway, false)
        );
    }

    /// The list renders from a sample with neighbours, and its empty states are
    /// honest rather than blank.
    #[test]
    fn the_list_renders_every_neighbour_and_states_its_absences() {
        let theme = Theme::for_appearance(gpui::WindowAppearance::Dark);
        let many: Vec<NeighborObs> = (0..MAX_RING + 20)
            .map(|i| {
                obs(
                    &format!("{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}"),
                    "192.168.0.129",
                    NeighborSource::Arp,
                    None,
                )
            })
            .collect();
        let snap = StatusSnapshot {
            neighbors: Some(sample(None, many)),
            ..Default::default()
        };
        // The list has no geometry to run out of: building it must not panic.
        let _ = neighbour_list(&snap, theme);
        let _ = neighbour_list(&StatusSnapshot::default(), theme);
        let _ = neighbour_list(
            &StatusSnapshot {
                neighbors: Some(sample(None, vec![])),
                ..Default::default()
            },
            theme,
        );
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

    /// An uplink node carries everything the card draws: the identity behind a
    /// friendly name, the port, the local interface, and the advertised
    /// capabilities split out of their comma-joined wire form.
    #[test]
    fn an_uplink_node_carries_the_whole_advertisement() {
        let mut l = link(
            "00:11:22:33:44:55",
            "Gi0/1",
            Some("core-sw"),
            LearnedVia::Cdp,
        );
        l.capabilities = "bridge, wlan_ap".into();
        l.ts_us = 5_000_000;
        let node = UplinkNode::from_link(&l);
        assert_eq!(node.label, "core-sw");
        assert_eq!(node.chassis, "00:11:22:33:44:55");
        assert!(node.has_name(), "a named switch shows its chassis too");
        assert_eq!(node.iface, "en0");
        assert_eq!(node.caps, vec!["bridge", "wlan_ap"]);

        // Without a system name the label IS the chassis, so no duplicate line.
        let anon = UplinkNode::from_link(&link("sw-x", "Gi0/2", None, LearnedVia::Lldp));
        assert!(!anon.has_name());
        // No advertised capabilities means no claims line, not an empty one.
        assert!(
            UplinkNode::from_link(&{
                let mut e = link("sw-y", "Gi0/3", None, LearnedVia::Lldp);
                e.capabilities = String::new();
                e
            })
            .caps
            .is_empty()
        );
    }

    /// Every line the card writes names the reading as an advertisement, never
    /// as a proven physical connection — and the sighting is dated as *heard*,
    /// since `first_seen` is a store column the bar cannot reach.
    #[test]
    fn uplink_text_stays_a_hypothesis() {
        let caption = uplink_caption(0);
        assert!(caption.contains("hypothesis"), "{caption}");
        assert!(caption.contains("not a proven physical link"), "{caption}");
        assert!(uplink_caption(2).contains("+2 more"));

        assert!(uplink_via_label(LearnedVia::Lldp).contains("LLDP"));
        assert!(uplink_via_label(LearnedVia::Cdp).contains("CDP"));
        // An unrecognised protocol must not be reported as LLDP or CDP.
        let unknown = uplink_via_label(LearnedVia::Unknown);
        assert!(
            !unknown.contains("LLDP") && !unknown.contains("CDP"),
            "{unknown}"
        );

        let node = UplinkNode::from_link(&link("sw", "Gi0/1", None, LearnedVia::Lldp));
        let seen = uplink_seen_line(&node, node.ts_us + 120_000_000);
        assert!(seen.starts_with("heard on en0"), "{seen}");
        assert!(seen.contains("2m ago"), "{seen}");
        assert!(
            !seen.contains("since"),
            "a sighting is not a first-seen: {seen}"
        );
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
        let _ = network_map_section(
            &snap,
            test_plot(),
            Theme::for_appearance(gpui::WindowAppearance::Dark),
        );
    }

    #[test]
    fn ring_positions_start_at_the_top() {
        let p = ring_positions(1, 100.0, 100.0, 50.0);
        assert_eq!(p.len(), 1);
        assert!((p[0].0 - 100.0).abs() < 0.001, "x centred");
        assert!((p[0].1 - 50.0).abs() < 0.001, "y above centre");
    }
}

/// Headless UI tests for the network map, on gpui's own test platform: layout
/// and scene construction run for real, rasterization does not.
#[cfg(test)]
mod headless_tests {
    use super::*;
    use crate::ui::Glance;
    use gpui::{Size, TestAppContext, VisualTestContext};
    use types::NeighborSource;

    fn obs(host: &str, last_octet: u8) -> NeighborObs {
        NeighborObs {
            mac: format!("aa:bb:cc:dd:ee:{last_octet:02x}"),
            ip: format!("192.168.1.{last_octet}"),
            source: NeighborSource::Arp,
            hostname: Some(host.to_string()),
            role: NeighborRole::Unknown,
        }
    }

    /// Chips fit the window, never sit on top of each other or on the centre, and
    /// every label stays inside its own chip — at a small window and a large one.
    ///
    /// The star is laid out from the space the window actually gives it
    /// ([`plot_for`]), so its correctness is a function of window size, and the
    /// old failures were exactly size-dependent: chips crowding the gateway at
    /// the centre, and labels spilling past a chip's edge. Both were caught by
    /// eye on screenshots, at whatever size the screenshot happened to be.
    #[gpui::test]
    fn map_chips_fit_and_never_collide_at_several_window_sizes(cx: &mut TestAppContext) {
        let neighbors = vec![
            obs("gw", 1),
            obs("alpha", 20),
            obs("bravo", 21),
            obs("charlie", 22),
            obs("delta", 23),
        ];
        let gateway_mac = neighbors[0].mac.clone();
        let snapshot = StatusSnapshot {
            neighbors: Some(NeighborsSample {
                ts_us: 1,
                verdict: types::NeighborsVerdict::Ok,
                reason: None,
                network_key: Some(gateway_mac),
                iface: Some("en0".to_string()),
                neighbors,
            }),
            ..Default::default()
        };
        let model = cx.update(|cx| {
            cx.new(|_| {
                Glance::new(
                    snapshot.clone(),
                    None,
                    "/tmp/net-observer-test.sock".to_string(),
                )
            })
        });
        let for_view = model.clone();
        let window = cx.add_window(|_, cx| MapView::new(for_view, cx));
        let mut cx = VisualTestContext::from_window(window.into(), cx);

        // The real window is drawn at each size — `MapView::render` fits the star
        // to `viewport_size()`, so the layout under test is size-dependent by
        // construction and one size proves nothing about the other.
        //
        // `fits` says whether the box is big enough for [`plot_for`] to honour
        // its own fit: below that the radius is floored at [`min_ring_radius`]
        // and a chip is *deliberately* allowed past the edge, because overlapping
        // the gateway would be the worse fault. The map window's own default
        // (`WIN_W`×`WIN_H`) is in that regime, so containment is asserted only
        // where the code claims it — never suppressed where it does.
        for (w, h, fits) in [
            (WIN_W, WIN_H, false),
            (460.0_f32, 520.0_f32, true),
            (900.0_f32, 700.0_f32, true),
        ] {
            let viewport = size(px(w), px(h));
            cx.simulate_resize(viewport);
            cx.run_until_parked();
            assert_eq!(
                cx.update(|window, _| window.viewport_size()),
                viewport,
                "the test window must be {w}x{h}"
            );

            // What this size actually draws: over capacity the surplus is
            // summarised as "+N more" rather than crammed onto the ring.
            let plot = plot_for(w - MAP_SIDE_PAD, h - MAP_CHROME_H);
            let sample = snapshot
                .neighbors
                .as_ref()
                .expect("the fixture carries a neighbours sample");
            let (gateway, ring, _more) = partition(sample, plot.capacity);
            let mut expected: Vec<String> = ring.iter().map(|n| n.label.clone()).collect();
            expected.extend(gateway.iter().map(|n| n.label.clone()));

            let mut chips = Vec::new();
            for label in &expected {
                let chip_sel: &'static str =
                    Box::leak(format!("map-chip:{label}").into_boxed_str());
                let label_sel: &'static str =
                    Box::leak(format!("map-label:{label}").into_boxed_str());
                let chip = cx
                    .debug_bounds(chip_sel)
                    .unwrap_or_else(|| panic!("chip `{label}` was not laid out at {w}x{h} at all"));
                assert!(
                    !fits || contains(viewport, chip),
                    "chip `{label}` leaves the {w}x{h} window: {chip:?}"
                );
                let text = cx
                    .debug_bounds(label_sel)
                    .unwrap_or_else(|| panic!("label of `{label}` was not laid out at {w}x{h}"));
                assert!(
                    within(chip, text),
                    "the label of `{label}` spills out of its own chip at {w}x{h}: \
                     label {text:?} vs chip {chip:?}"
                );
                chips.push((label.clone(), chip));
            }

            for (i, (a_id, a)) in chips.iter().enumerate() {
                for (b_id, b) in chips.iter().skip(i + 1) {
                    assert!(
                        !overlaps(*a, *b),
                        "chips `{a_id}` and `{b_id}` overlap at {w}x{h}: {a:?} vs {b:?}"
                    );
                }
            }
        }
    }

    /// `inner` lies wholly inside a viewport of `outer` anchored at the origin.
    fn contains(outer: Size<Pixels>, inner: Bounds<Pixels>) -> bool {
        inner.origin.x >= px(0.0)
            && inner.origin.y >= px(0.0)
            && inner.origin.x + inner.size.width <= outer.width
            && inner.origin.y + inner.size.height <= outer.height
    }

    /// `inner` lies wholly inside `outer`, both in absolute window coordinates.
    /// A half-pixel of slack absorbs the rounding of a flex layout, not a spill.
    fn within(outer: Bounds<Pixels>, inner: Bounds<Pixels>) -> bool {
        let slack = px(0.5);
        inner.origin.x + slack >= outer.origin.x
            && inner.origin.y + slack >= outer.origin.y
            && inner.origin.x + inner.size.width <= outer.origin.x + outer.size.width + slack
            && inner.origin.y + inner.size.height <= outer.origin.y + outer.size.height + slack
    }

    /// Half-open rectangle intersection: touching edges are not an overlap.
    fn overlaps(a: Bounds<Pixels>, b: Bounds<Pixels>) -> bool {
        a.origin.x < b.origin.x + b.size.width
            && b.origin.x < a.origin.x + a.size.width
            && a.origin.y < b.origin.y + b.size.height
            && b.origin.y < a.origin.y + a.size.height
    }
}
