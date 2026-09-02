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

use std::f32::consts::PI;

use gpui::prelude::*;
use gpui::{Bounds, Pixels, Rgba, canvas, div, point, px, rgb, rgba};

use net_observer_ipc::StatusSnapshot;
use types::{NeighborObs, NeighborSource, NeighborsSample};

use crate::ui::Theme;

/// The most neighbours the ring will draw. Beyond this the star turns into an
/// unreadable tangle, so the extras are summarised as a "+N more" note rather than
/// crammed in. A first-version cap, not a hard limit on what the daemon records.
const MAX_RING: usize = 12;

/// The fixed height of the map's plot area, in gpui logical pixels. Tall enough
/// for a ring of chips around a centred gateway without the corner chips colliding
/// with the section padding.
const MAP_H: f32 = 210.0;

/// Chip footprint. Nodes are positioned by their centre, so these are used to
/// convert a centre into a top-left inset.
const CHIP_W: f32 = 84.0;
const CHIP_H: f32 = 24.0;

/// Ring radius from the gateway at the centre to each neighbour chip's centre.
const RING_R: f32 = 74.0;

/// A neighbour reduced to what the map draws: a stable identity, a short label and
/// which reading produced it. Derived purely from a [`NeighborObs`] so the render
/// carries no parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MapNode {
    /// The neighbour's MAC — the stable key, and what decides the gateway.
    mac: String,
    /// The short on-chip identity (hostname, else vendor OUI, else last IP octet,
    /// else a short MAC).
    label: String,
    /// Which reading produced this observation (passive cache vs operator scan).
    source: NeighborSource,
}

impl MapNode {
    fn from_obs(obs: &NeighborObs) -> Self {
        Self {
            mac: obs.mac.clone(),
            label: node_label(obs),
            source: obs.source,
        }
    }
}

/// The short identity drawn on a node chip.
///
/// Order of preference: a known hostname (only mDNS supplies one), then the vendor
/// OUI, then the last octet of the IPv4 address, then the last two MAC octets. The
/// point is to name the device by the most human handle available without ever
/// showing a blank chip.
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
        if gateway.is_none() && key.is_some_and(|k| k == obs.mac) {
            gateway = Some(MapNode::from_obs(obs));
        } else {
            ring.push(MapNode::from_obs(obs));
        }
    }
    let dropped = ring.len().saturating_sub(MAX_RING);
    ring.truncate(MAX_RING);
    (gateway, ring, dropped)
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

/// The dot colour for one node.
///
/// **Seam for the later vulnerability increment.** Today this only distinguishes
/// the gateway (accent) from a passively-seen neighbour (fg) and an
/// operator-scanned one (muted): a scanned host was reached by putting packets on
/// the wire, so it reads as less load-bearing than one the kernel already knew. A
/// future increment will colour each node by its security findings — attach that
/// here, keyed on the node's identity, without touching the layout.
fn node_accent(node: &MapNode, is_gateway: bool, theme: Theme) -> Rgba {
    if is_gateway {
        return rgb(theme.accent);
    }
    match node.source {
        NeighborSource::Arp | NeighborSource::Ndp => rgb(theme.fg),
        NeighborSource::Sweep | NeighborSource::Mdns => rgb(theme.muted),
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
    chip.child(
        div()
            .text_size(px(8.0))
            .text_color(dot_color)
            .child("\u{25CF}"),
    )
    .child(
        div()
            .flex_1()
            .overflow_hidden()
            .text_size(px(11.0))
            .when(is_gateway, |d| d.font_weight(gpui::FontWeight::BOLD))
            .child(node.label.clone()),
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

    let Some(sample) = &snapshot.neighbors else {
        return empty_state(base, "no neighbour reading yet", theme);
    };
    if sample.neighbors.is_empty() {
        let msg = match &sample.reason {
            Some(reason) => format!("no neighbours: {reason}"),
            None => "no neighbours seen \u{00b7} press Scan to look".to_string(),
        };
        return empty_state(base, msg, theme);
    }

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
                            source: NeighborSource::Arp,
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

    let mut section = base.child(caption(sample, ring.len(), gateway.is_some(), theme));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(mac: &str, ip: &str, source: NeighborSource, hostname: Option<&str>) -> NeighborObs {
        NeighborObs {
            mac: mac.to_string(),
            ip: ip.to_string(),
            source,
            hostname: hostname.map(str::to_string),
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
    fn ring_is_capped_and_reports_the_overflow() {
        let neighbors: Vec<NeighborObs> = (0..(MAX_RING + 5))
            .map(|i| {
                obs(
                    &format!("11:11:11:11:11:{i:02x}"),
                    "10.0.0.1",
                    NeighborSource::Sweep,
                    None,
                )
            })
            .collect();
        let s = sample(Some("gg:gg:gg:gg:gg:gg"), neighbors);
        let (_, ring, dropped) = partition(&s);
        assert_eq!(ring.len(), MAX_RING);
        assert_eq!(dropped, 5);
    }

    #[test]
    fn ring_positions_start_at_the_top() {
        let p = ring_positions(1, 100.0, 100.0, 50.0);
        assert_eq!(p.len(), 1);
        assert!((p[0].0 - 100.0).abs() < 0.001, "x centred");
        assert!((p[0].1 - 50.0).abs() < 0.001, "y above centre");
    }
}
