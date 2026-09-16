use std::collections::BTreeMap;

use crate::window::{LinkProvenance, RecentWindow};
use types::{
    DnsVerdict, GwVerdict, LinkMedium, LinkSample, NeighborsVerdict, ProxySample, TcpVerdict,
    normalize_mac,
};

/// How many recent DNS samples the `fakeip` condition scans (one polling tick
/// emits several probe rows, so a small window covers the latest tick).
const FAKEIP_SCAN: usize = 16;

/// Whether `name` is a `.ru` name — either the short `ru` probe label or a
/// fully-qualified `*.ru` domain. A fakeip answer on such a name is always a bug.
fn is_ru_name(name: &str) -> bool {
    name == "ru" || name.ends_with(".ru")
}

/// A fired condition, carrying a human-readable detail string.
pub struct Fire {
    pub detail: String,
}

/// A trigger condition evaluated against the recent-sample window.
///
/// `Send + Sync` so a `Box<dyn Condition>` inside a [`crate::engine::Trigger`] keeps the
/// whole [`crate::engine::TriggerEngine`] shareable across tokio tasks in the daemon.
pub trait Condition: Send + Sync {
    fn id(&self) -> &'static str;
    fn eval(&self, w: &RecentWindow) -> Option<Fire>;
}

/// One proxy TICK as the tun-reading conditions see it: the rows sharing one
/// `ts_us`, folded.
///
/// Proxy rows arrive one per ENDPOINT with the tick's shared `tun_code`
/// replicated across them, so rows must be folded into ticks before any
/// counting. The first cut of `wedge` counted ROWS, which made `consecutive` a
/// fraction of ONE tick — a single transient transport failure opened an
/// incident (observed live 2026-09-10: two wedge incidents minutes apart while
/// the shell oracle's TICK log showed tun=204 on every surrounding probe).
///
/// A tick is MEASURED when a probe of it ran: a `tun_code` is present (the
/// tun probe was attempted — an HTTP status, or `0` for no status at all),
/// or a row is not `Skip` (the endpoints were probed). A Skip placeholder
/// tick (a lone Skip row with no `tun_code`: the pipeline's preflight skip, or
/// a tick the passive probing tier withheld) is the absence of a measurement
/// (the rule `GwDrop` documents: realm net-observer, node #25) — every reader
/// here treats it as transparent, never as a dead tun.
///
/// `tun_code` is the tick's code, folded exactly as the offline
/// `proxy_tick` CTE folds it (`max(tun_code)` over the rows — replicated, so
/// one value): `Some(status)` for an answered probe, `Some(0)` for one
/// attempted with no status (the record's `0`, the shell oracle's curl
/// `000`), `None` for one not attempted (`NULL`). Three rules read it three
/// ways, so the readings are methods on the ONE fold rather than three folds:
/// [`ProxyTick::dead`] (`wedge`), [`ProxyTick::unanswered`] (`starvation`),
/// [`ProxyTick::answered`] (`established-stall`).
struct ProxyTick {
    measured: bool,
    tun_code: Option<u16>,
}

impl ProxyTick {
    /// The probe did not answer exactly 204 — the shell watchdog's
    /// `tun != 204`, what `wedge` counts as a dead tick. A tick not probed at
    /// all is "dead" by this reading too, which is why `wedge` only ever
    /// applies it to a measured tick.
    fn dead(&self) -> bool {
        self.tun_code != Some(204)
    }

    /// The probe was attempted and got no HTTP status: the record's
    /// `tun_code = 0`, the same `0` `why` and `wedge-or-starvation` read as the
    /// dead tun, so live `starvation` and the offline readings agree — a
    /// captive portal's 200 under load never opens a live incident the record
    /// calls healthy. `None` (not probed) is NOT unanswered.
    fn unanswered(&self) -> bool {
        self.tun_code == Some(0)
    }

    /// The probe got an HTTP status — any status: the fresh path through the
    /// tun still carries requests, whatever the answer was.
    fn answered(&self) -> bool {
        matches!(self.tun_code, Some(code) if code != 0)
    }
}

/// Fold `rows` (newest first, as [`RecentWindow::recent_proxy`] yields them)
/// into [`ProxyTick`]s, newest first.
fn proxy_ticks<'a>(rows: &'a [&'a ProxySample]) -> impl Iterator<Item = ProxyTick> + 'a {
    let mut i = 0;
    std::iter::from_fn(move || {
        let ts = rows.get(i)?.ts_us;
        let mut tick = ProxyTick {
            measured: false,
            tun_code: None,
        };
        while let Some(r) = rows.get(i).filter(|r| r.ts_us == ts) {
            if r.tun_code.is_some() || r.tcp != TcpVerdict::Skip {
                tick.measured = true;
            }
            // `max`, like the CTE: the code is replicated across the tick's
            // rows, so this is the one value, and `Some` beats `None`.
            tick.tun_code = tick.tun_code.max(r.tun_code);
            i += 1;
        }
        Some(tick)
    })
}

/// How many recent proxy rows `wedge` scans for its dead-tick run. The
/// reach in time depends on what a tick emits: a MEASURED tick emits one row
/// per endpoint, ~7 rows with the daemon's defaults, so 64 rows ≈ 9 ticks
/// ≈ 2 min at the 15 s cadence; a tick whose preflight skipped emits one
/// placeholder row, so a run of those — the #96 scenario — stretches the
/// same 64 rows to ≈ 64 ticks ≈ 16 min, which is how far behind the present
/// a dead run can still be counted. The run it counts is the daemon's
/// `WEDGE_CONSECUTIVE = 3`, so a few measured ticks beyond that suffice; an
/// unbounded scan reached across the whole 2048-sample window (≈ 40 min)
/// and fired on a dead run any number of unmeasured ticks old. Tunable by
/// the owner.
const WEDGE_SCAN: usize = 64;

/// Fires when the last `consecutive` link samples all have `direct == Ok` while
/// the last `consecutive` MEASURED proxy ticks all found the tun dead (anything
/// but a 204 from the probe — mirroring the shell watchdog's `tun != 204`).
pub struct Wedge {
    pub consecutive: usize,
}
impl Condition for Wedge {
    fn id(&self) -> &'static str {
        "wedge"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let links = w.recent_link(self.consecutive);
        if links.len() < self.consecutive {
            return None;
        }
        if !links.iter().all(|l| l.direct == TcpVerdict::Ok) {
            return None;
        }
        // Count MEASURED ticks only (see [`ProxyTick`]): a placeholder neither
        // advances nor resets the dead run; a measured healthy tick breaks it.
        // The scan is bounded by `WEDGE_SCAN`: a dead run further back than
        // that is history, not the present.
        let rows = w.recent_proxy(WEDGE_SCAN);
        let mut dead_ticks = 0usize;
        for tick in proxy_ticks(&rows).filter(|t| t.measured) {
            if !tick.dead() {
                return None;
            }
            dead_ticks += 1;
            if dead_ticks == self.consecutive {
                return Some(Fire {
                    detail: format!("tun dead {} ticks, direct OK", self.consecutive),
                });
            }
        }
        None
    }
}

/// Measurement-context gate around a fault condition.
///
/// The first live-trial days produced a stream of incidents whose only cause
/// was an invalid measurement context: `endpoint-block` fired while the
/// machine had no uplink at all (every raw probe fails when there is no
/// interface to probe from), `per-client-block` fired a minute into a freshly
/// joined network and during host starvation, `established-stall` fired
/// seconds after a network move (the old flows legally died with the NAT).
/// The shell watchdog has carried the equivalent guards for months — its
/// load1 gate and its direct-path requirement; this wrapper gives the fault
/// conditions the same discipline without teaching each one about hosts and
/// links.
///
/// Each gate is optional so every signature keeps exactly the guards its
/// semantics allow (`per-client-block` measures a DEAD gateway, so it must
/// not require a working direct path):
///   - `require_direct`: the newest MEASURED link sample within the last
///     [`GATE_DIRECT_SCAN`] must say the direct path works. A
///     destination-fault verdict is meaningless while the uplink itself is
///     down. `Skip` rows are the absence of a measurement and satisfy
///     nothing (node #25), and a `direct` reading older than the scan is not
///     evidence the uplink works now.
///   - `load_below`: the newest host sample's `load1` must be below this —
///     above it, probe failures measure the run queue, not the network
///     (measured 2026-07-30: at load1 ≥ 64 half of all probes fail). No host
///     sample yet = no starvation evidence = the gate stays open.
///   - `settle_us`: the network identity (`dhcp_router`) must not have
///     changed within this window — right after a move every layer is
///     legitimately in flux.
pub struct Gated<C> {
    pub inner: C,
    pub require_direct: bool,
    pub load_below: Option<f64>,
    pub settle_us: Option<i64>,
}

/// How many recent link samples the direct-path gate scans for a measured
/// `direct`: 8 at the 15 s link cadence is ≈ 2 min. Only that lookup uses it
/// — `gw-change`'s own predecessor scan keeps [`GW_CHANGE_SCAN`], because a
/// change straddling a long quiet run is still a change, while a `direct`
/// reading that old is not evidence the uplink works now (#96).
const GATE_DIRECT_SCAN: usize = 8;

impl<C: Condition> Condition for Gated<C> {
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        if self.require_direct {
            let direct_ok = w
                .recent_link(GATE_DIRECT_SCAN)
                .into_iter()
                .find(|l| l.direct != TcpVerdict::Skip)
                .is_some_and(|l| l.direct == TcpVerdict::Ok);
            if !direct_ok {
                return None;
            }
        }
        if let Some(threshold) = self.load_below
            && w.last_host().is_some_and(|h| h.load1 >= threshold)
        {
            return None;
        }
        if let Some(settle_us) = self.settle_us {
            let links = w.recent_link(GW_CHANGE_SCAN);
            if let Some(newest) = links.first() {
                let horizon = newest.ts_us.saturating_sub(settle_us);
                let mut identities = links
                    .iter()
                    .take_while(|l| l.ts_us >= horizon)
                    .filter_map(|l| l.dhcp_router.as_deref());
                if let Some(first) = identities.next()
                    && identities.any(|r| r != first)
                {
                    return None;
                }
            }
        }
        self.inner.eval(w)
    }
}

/// How far back `gw-change` looks for a comparable (non-`SKIP`) predecessor when
/// the echo has been withheld for a run of ticks — by the operator's quiet mode
/// or by the passive probing tier; the other change signatures
/// (`gw-mac-change`, `roam`) reach back the same way past ticks that could not
/// read their field. It therefore bounds the rule's reach across a passive
/// stretch: a change straddling a stretch longer than this many ticks is not
/// named by `gw-change` (its basis has left the window), while `gw-drop` still
/// catches a `FAIL` on the first measured tick after it.
const GW_CHANGE_SCAN: usize = 64;

/// Fires when the newest link sample's gateway verdict is `Fail` or `NoGw`.
///
/// `Skip` (quiet mode: the echo was deliberately not sent) is NOT a drop — it is
/// the absence of a measurement — and the match is exhaustive over the verdict so
/// a future token cannot join the fault set by accident.
/// The rule this obeys: realm `net-observer`, node #25.
pub struct GwDrop;
impl Condition for GwDrop {
    fn id(&self) -> &'static str {
        "gw-drop"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        match last.gw {
            GwVerdict::Fail | GwVerdict::NoGw => true,
            GwVerdict::Ok | GwVerdict::Skip => false,
        }
        .then(|| Fire {
            detail: format!("gateway {}", last.gw),
        })
    }
}

/// Fires on any change in the gateway verdict between the two newest link samples
/// — or, on the first sample after a resume, against the change basis carried
/// across the observation gap (see [`RecentWindow::prev_link_with_provenance`]).
pub struct GwChange;
impl Condition for GwChange {
    fn id(&self) -> &'static str {
        "gw-change"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        // A `SKIP` tick carries no measurement, so it can be neither side of a
        // change: `OK -> SKIP` is the operator flipping quiet on or the tier
        // to passive, not the gateway moving, and firing on it would
        // manufacture an incident out of a control-socket click.
        if last.gw == GwVerdict::Skip {
            return None;
        }
        // Reach back past a withheld run (quiet, or the passive tier) for the
        // newest predecessor that actually measured something. Without this
        // the change the run straddled (`OK` -> withheld -> `FAIL`) would be
        // suppressed once and then never seen again — silence, exactly what
        // the SKIP token exists to prevent.
        let recent = w.recent_link(GW_CHANGE_SCAN);
        let withheld_run = recent
            .iter()
            .skip(1)
            .take_while(|l| l.gw == GwVerdict::Skip)
            .count();
        let (prev, provenance) = measured_predecessor(w, &recent, |l| l.gw != GwVerdict::Skip)?;
        // A change measured against the basis carried across a pause is real —
        // the oracle freezes on ANY gateway change — but it is not two
        // consecutive ticks, and the incident must not read as though it were.
        // A change straddling a withheld run is real for the same reason, and
        // is labelled for the same reason — "withheld", because quiet and the
        // passive tier both produce it and a SKIP run does not say which.
        let across = match (provenance, withheld_run) {
            (LinkProvenance::AcrossGap, _) => " (across an observation gap)".to_string(),
            (LinkProvenance::Contiguous, 0) => String::new(),
            (LinkProvenance::Contiguous, n) => format!(" (across {n} withheld tick(s))"),
        };
        (last.gw != prev.gw).then(|| Fire {
            detail: format!("gateway {} -> {}{}", prev.gw, last.gw, across),
        })
    }
}

/// Fires when the newest link sample's ARP-resolved gateway MAC differs from the
/// newest comparable predecessor's, while the DHCP-leased router IP is unchanged
/// — the same address answered by a different MAC.
///
/// A predecessor is comparable only if it carries both the router IP and a MAC
/// that normalises: an empty ARP cache is common for a tick or two right after
/// a link flap, which is exactly when the MAC changes, so the scan reaches
/// back past those ticks rather than comparing against the immediate
/// neighbour and losing the change for good. Both sides of the comparison —
/// and the MACs named in the fire detail — go through [`normalize_mac`], so a
/// row stored before the source-side fix landed (raw, unpadded octets) does
/// not read as a change against a normalised successor at the same gateway
/// (realm net-observer, node #94). A comparison made across an operator pause
/// or across unreadable ticks is labelled as such, so the incident never
/// reads as two consecutive measurements. (realm net-observer, node #32)
pub struct GwMacChange;
impl Condition for GwMacChange {
    fn id(&self) -> &'static str {
        "gw-mac-change"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let last_router = last.dhcp_router.as_deref()?;
        let last_mac = normalize_mac(last.gw_arp_mac.as_deref()?)?;
        // Both sides through the same fold as `bssid`/`if_mac`: a row written
        // before the source-side normalisation still carries `arp -n`'s raw,
        // unpadded form, and comparing it unfolded against a normalised
        // successor would read as a MAC change on the very first tick after
        // the upgrade at an unchanged gateway (realm net-observer, node #94).
        let comparable = |l: &LinkSample| {
            l.dhcp_router.is_some()
                && l.gw_arp_mac
                    .as_deref()
                    .is_some_and(|m| normalize_mac(m).is_some())
        };
        let recent = w.recent_link(GW_CHANGE_SCAN);
        let unreadable = recent.iter().skip(1).take_while(|l| !comparable(l)).count();
        let (prev, provenance) = measured_predecessor(w, &recent, comparable)?;
        let prev_router = prev.dhcp_router.as_deref()?;
        let prev_mac = normalize_mac(prev.gw_arp_mac.as_deref()?)?;
        if last_router != prev_router {
            return None;
        }
        if last_mac == prev_mac {
            return None;
        }
        let across = match (provenance, unreadable) {
            (LinkProvenance::AcrossGap, _) => " (across an observation gap)".to_string(),
            (LinkProvenance::Contiguous, 0) => String::new(),
            (LinkProvenance::Contiguous, n) => {
                format!(" (across {n} tick(s) without an ARP entry)")
            }
        };
        Some(Fire {
            detail: format!("gateway {last_router} mac {prev_mac} -> {last_mac}{across}"),
        })
    }
}

/// The newest link sample older than the newest one in which `measured`
/// holds, with the provenance of the answer: found inside `recent` (newest
/// first, the newest itself at index 0) as a contiguous predecessor, else the
/// basis carried across a pause — which must itself be measured. `None` when
/// nothing measured precedes the newest sample. The one predecessor scan of
/// the change signatures (`gw-change`, `gw-mac-change`, `roam`): reaching
/// back past unmeasured ticks is how a change that quiet mode, an empty ARP
/// cache or an unreadable identity straddled is still seen, and falling back
/// to the carried basis is how a change DURING a pause is seen at resume.
fn measured_predecessor<'w>(
    w: &'w RecentWindow,
    recent: &[&'w LinkSample],
    measured: impl Fn(&LinkSample) -> bool,
) -> Option<(&'w LinkSample, LinkProvenance)> {
    match recent.iter().skip(1).find(|l| measured(l)) {
        Some(prev) => Some((prev, LinkProvenance::Contiguous)),
        None => match w.prev_link_with_provenance()? {
            (prev, _) if !measured(prev) => None,
            (prev, provenance) => Some((prev, provenance)),
        },
    }
}

/// Whether a link sample was read on a link whose medium was MEASURED as
/// Wi-Fi (`LinkSample::medium`, from the hardware-port table). The invariant
/// the identity rules rest on: `LinkSample` has no interface name (a future
/// field), and `if_mac` is the DEFAULT-ROUTE interface's MAC, so a dock or
/// undock moves it between the wired and the Wi-Fi adapter — the medium is
/// what tells a roam from a dock. It is never inferred from a readable SSID
/// or BSSID: the deployed daemon reads as root, where the SSID is
/// `<redacted>` (realm net-observer, node #93) and the BSSID line is
/// unproven (node #108), so readable names would make every Wi-Fi tick look
/// wired and leave `roam` and `wifi-churn` inert. `None` — the medium not
/// determinable — is the absence of a measurement on the medium itself
/// (#25's second obligation: the field's absence is not the medium's
/// absence), and such a tick is transparent to the address comparison like a
/// wired one: neither compared nor a comparison basis.
fn on_wifi(l: &LinkSample) -> bool {
    l.medium == Some(LinkMedium::Wifi)
}

/// The link address of a tick measured as Wi-Fi; `None` on a wired or
/// undetermined medium, where the address may belong to another adapter
/// ([`on_wifi`]).
fn wifi_if_mac(l: &LinkSample) -> Option<&str> {
    if on_wifi(l) {
        l.if_mac.as_deref()
    } else {
        None
    }
}

/// Fires when the link's Wi-Fi identity moved between the newest link sample
/// and its newest measured predecessor: the associated access point
/// (`bssid`) changed, whatever the SSID did — band steering, or the #57 twin
/// SSIDs, which have different names (5 GHz / 6 GHz) — or, on a Wi-Fi tick,
/// the link's own address (`if_mac`) changed, which under Private Wi-Fi
/// Address is a new DHCP identity toward the network. Either is a roam, and
/// both on one tick are one roam whose detail names both. The masquerade
/// this unmasks: a roam otherwise lands as `gw-drop` or `per-client-block`
/// with the move itself readable nowhere. (realm net-observer, node #59)
///
/// The detail says what happened and suppresses nothing: `roam: BSSID <old>
/// -> <new>`, then `, SSID <old> -> <new>` when the SSID moved, then the link
/// address class, then `; router <old> -> <new>` when the DHCP router also
/// changed in the same comparison — whether the hop was a move to another
/// segment is the reader's call from that record. The address class is what
/// separates the harmless hop from the harmful one (node #109): with the
/// address kept, each hop is a sub-second DHCP INIT-REBOOT on the same IP —
/// `link address kept`; with a per-SSID private address rotating, DHCP
/// starts from scratch and the link has a 10–20 s hole — `link address
/// <old> -> <new> (new DHCP identity)`. A BSSID hop whose address could not
/// be read on either side is `link address unmeasured`, never claimed kept.
///
/// Each field is compared against the newest OLDER sample in which that
/// field is measured, so a tick that could not read the identity is
/// transparent; `None` on either side is the absence of a measurement and
/// never one half of a change. The address is compared only between ticks
/// whose medium was MEASURED as Wi-Fi — a wired or undetermined medium is
/// transparent to it ([`on_wifi`]): a dock or undock is not a roam, and an
/// unmeasured medium is no basis. The ARP-resolved gateway
/// MAC is never read here: it is stored raw and is not comparable to a
/// normalised BSSID (node #94). Like `gw-change`, this asserts only on the
/// tick where the newest sample differs from its predecessor, so the
/// engine's clear edge closes the incident on the next unchanged tick; a
/// comparison against the basis carried across a pause is labelled, so the
/// incident never reads as two consecutive ticks. The daemon registers it
/// with NO firing backoff: the #57 cadence is a hop every 2.5–3 min, and
/// each hop at the field cadence is its own incident — the shared 5 min
/// backoff would silently drop most of them. Hops on consecutive ticks merge
/// into one incident under the engine's latch (the condition never returns
/// `None` between them), and the link rows still record both. The
/// aggregate's rate limit lives on `wifi-churn`.
pub struct Roam;
impl Condition for Roam {
    fn id(&self) -> &'static str {
        "roam"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let recent = w.recent_link(GW_CHANGE_SCAN);
        let mut across_gap = false;
        // The access point, with the SSID move named when there was one and
        // the predecessor kept as the router comparison's basis.
        let bssid_hop = if let Some(new_ap) = last.bssid.as_deref()
            && let Some((prev, provenance)) =
                measured_predecessor(w, &recent, |l| l.bssid.is_some())
            && let Some(old_ap) = prev.bssid.as_deref()
            && old_ap != new_ap
        {
            across_gap |= provenance == LinkProvenance::AcrossGap;
            let ssid = match (prev.ssid.as_deref(), last.ssid.as_deref()) {
                (Some(old), Some(new)) if old != new => format!(", SSID {old} -> {new}"),
                _ => String::new(),
            };
            Some((format!("BSSID {old_ap} -> {new_ap}{ssid}"), prev))
        } else {
            None
        };
        // The link address, compared the same way — on Wi-Fi ticks only.
        enum Address<'w> {
            Moved(String, &'w LinkSample),
            Kept,
            Unmeasured,
        }
        let address = if let Some(new_mac) = wifi_if_mac(last)
            && let Some((prev, provenance)) =
                measured_predecessor(w, &recent, |l| wifi_if_mac(l).is_some())
            && let Some(old_mac) = prev.if_mac.as_deref()
        {
            if old_mac == new_mac {
                Address::Kept
            } else {
                across_gap |= provenance == LinkProvenance::AcrossGap;
                Address::Moved(
                    format!("link address {old_mac} -> {new_mac} (new DHCP identity)"),
                    prev,
                )
            }
        } else {
            Address::Unmeasured
        };
        // The predecessor the router is compared against: the access point's
        // when the access point hopped, else the address's.
        let (address, basis) = match (&bssid_hop, address) {
            (_, Address::Moved(moved, prev)) => (moved, bssid_hop.as_ref().map_or(prev, |h| h.1)),
            (None, _) => return None,
            (Some((_, prev)), Address::Kept) => ("link address kept".to_string(), *prev),
            (Some((_, prev)), Address::Unmeasured) => {
                ("link address unmeasured".to_string(), *prev)
            }
        };
        let router = match (basis.dhcp_router.as_deref(), last.dhcp_router.as_deref()) {
            (Some(old), Some(new)) if old != new => format!("; router {old} -> {new}"),
            _ => String::new(),
        };
        let across = if across_gap {
            " (across an observation gap)"
        } else {
            ""
        };
        let detail = match bssid_hop {
            Some((ap, _)) => format!("roam: {ap}; {address}{router}{across}"),
            None => format!("roam: {address}{router}{across}"),
        };
        Some(Fire { detail })
    }
}

/// The fewest identity changes inside [`WIFI_CHURN_WINDOW_S`] that read as
/// churn: the field pattern is a hop every ~2.5–3 min, so four is a quarter
/// hour of it. Tunable by the owner.
const WIFI_CHURN_MIN_CHANGES: usize = 4;

/// How far behind the newest link sample `wifi-churn` counts identity
/// changes, in seconds. Tunable by the owner.
const WIFI_CHURN_WINDOW_S: i64 = 900;

/// How many recent link samples `wifi-churn` walks: the same reach as
/// `ban-cycle`, the engine window itself, because the reading an in-horizon
/// change is measured against may sit any number of unmeasured ticks behind
/// the horizon.
const WIFI_CHURN_SCAN: usize = BAN_CYCLE_SCAN;

/// The ticks at which `field` changed, newest first: a tick whose measured
/// reading differs from the previous MEASURED reading of the same field, and
/// whose `ts_us` is at or after `horizon`. A tick with the field unmeasured
/// is skipped in the comparison and is never a change. Walked newest-first,
/// so the reading each change is measured against may lie behind the
/// horizon.
fn identity_changes(
    links: &[&LinkSample],
    horizon: i64,
    field: fn(&LinkSample) -> Option<&str>,
) -> Vec<i64> {
    let mut changes = Vec::new();
    // The newest measured reading walked so far and the tick it was read on.
    let mut newer: Option<(&str, i64)> = None;
    for l in links {
        let Some(value) = field(l) else {
            continue;
        };
        if let Some((newer_value, newer_ts)) = newer
            && newer_value != value
            && newer_ts >= horizon
        {
            changes.push(newer_ts);
        }
        newer = Some((value, l.ts_us));
    }
    changes
}

/// Fires when the window holds at least [`WIFI_CHURN_MIN_CHANGES`] Wi-Fi
/// identity changes within [`WIFI_CHURN_WINDOW_S`] of the newest link sample
/// — an identity change being a tick whose measured `bssid` or `if_mac`
/// differs from the previous measured reading of the same field. The field
/// pattern: macOS hopping between the twin SSIDs of one access point every
/// ~2.5–3 min, each hop otherwise its own `roam` incident with the churn
/// itself readable nowhere. This one names the churn, its span and how the
/// identity moved (per-field counts), and stays asserted while the pattern
/// is in the window so the engine's clear edge closes the one incident when
/// it ages out. The daemon registers it WITH the shared firing backoff
/// (5 min): that is the aggregate's rate limit the field asked for, while
/// `roam` itself runs with none so that each hop at the field cadence stays
/// its own incident (hops on consecutive ticks merge into one under the
/// engine's latch; the rows still record both). (realm net-observer,
/// node #109)
///
/// A tick with a field unmeasured (`None`) is skipped in that field's
/// comparison and never counted as a change (node #25); the address is
/// counted only between ticks whose medium was MEASURED as Wi-Fi, so a
/// wired or undetermined tick is neither counted nor a comparison basis
/// ([`on_wifi`]). A tick where both fields
/// moved is one change; the per-field counts in the detail say which moved.
/// The detail is written when the incident opens, so its counts and span are
/// those of the first firing.
pub struct WifiChurn;
impl Condition for WifiChurn {
    fn id(&self) -> &'static str {
        "wifi-churn"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let horizon = last.ts_us.saturating_sub(WIFI_CHURN_WINDOW_S * 1_000_000);
        let links = w.recent_link(WIFI_CHURN_SCAN);
        let bssid_changes = identity_changes(&links, horizon, |l| l.bssid.as_deref());
        let mac_changes = identity_changes(&links, horizon, wifi_if_mac);
        // One change per tick, however many fields moved on it.
        let mut ticks: Vec<i64> = bssid_changes
            .iter()
            .chain(mac_changes.iter())
            .copied()
            .collect();
        ticks.sort_unstable();
        ticks.dedup();
        let n = ticks.len();
        if n < WIFI_CHURN_MIN_CHANGES {
            return None;
        }
        let span_s = (ticks.last()? - ticks.first()?) / 1_000_000;
        Some(Fire {
            detail: format!(
                "wifi identity churn: {n} changes in ~{span_s}s (bssid: {b}, link address: {m})",
                b = bssid_changes.len(),
                m = mac_changes.len(),
            ),
        })
    }
}

/// Fires when the newest `neighbors` reading holds two different MACs claiming
/// the same IP — an address collision, provable only from that table.
/// (realm net-observer, node #32)
pub struct NeighborMacCollision;
impl Condition for NeighborMacCollision {
    fn id(&self) -> &'static str {
        "neighbor-mac-collision"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_neighbors()?;
        if last.verdict != NeighborsVerdict::Ok {
            return None;
        }
        // Ordered by IP, and every collision reported: the same reading must
        // produce the same incident text, and a second collision in one reading
        // is a second fact, not a duplicate of the first.
        let mut macs_by_ip: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for n in &last.neighbors {
            let macs = macs_by_ip.entry(n.ip.as_str()).or_default();
            if !macs.contains(&n.mac.as_str()) {
                macs.push(&n.mac);
            }
        }
        let collisions: Vec<String> = macs_by_ip
            .into_iter()
            .filter(|(_, macs)| macs.len() > 1)
            .map(|(ip, mut macs)| {
                macs.sort_unstable();
                format!("ip {ip} claimed by {}", macs.join(", "))
            })
            .collect();
        (!collisions.is_empty()).then(|| Fire {
            detail: collisions.join("; "),
        })
    }
}

/// Fires on a fake-IP DNS answer for a `.ru` name — the sing-box fakeip range
/// leaking onto a control domain that must resolve to a real address. Driven by
/// the `dns` collector's [`types::DnsSample`]s in the window.
pub struct FakeIp;
impl Condition for FakeIp {
    fn id(&self) -> &'static str {
        "fakeip"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        w.recent_dns(FAKEIP_SCAN)
            .into_iter()
            .find(|d| d.verdict == DnsVerdict::FakeIp && is_ru_name(&d.probe))
            .map(|d| Fire {
                detail: format!(
                    "fakeip on {} via {} -> {}",
                    d.probe,
                    d.server,
                    d.ip.as_deref().unwrap_or("?")
                ),
            })
    }
}

/// Fires when the tun is dead while host load exceeds `load_threshold` — the
/// starvation discriminator: a wedge caused by CPU/IO pressure rather than a
/// network fault. `load1` is read from the `host` collector's newest sample.
///
/// "Dead" is a MEASUREMENT, and it is the offline record's: the newest proxy
/// tick whose probe ran (the [`ProxyTick`] fold `wedge` shares) was attempted
/// and got no HTTP status — `tun_code = 0`, the same `0` `why` and
/// `wedge-or-starvation` read, so live and offline agree on the dead tun. A
/// tick that answered (a captive portal's 200, a 5xx) is not starvation
/// however high the load; `wedge`'s `!= 204` is a different reading and stays
/// its own. A tick not probed at all — `tun_code` `NULL`: the preflight skip,
/// or every tick of the passive probing tier — is no measurement and no fire:
/// a loaded host with no probe sent is not a starved tun, and reading it as
/// one opened an incident on every passive tick under load (realm
/// net-observer, node #88). The scan is bounded by [`WEDGE_SCAN`] like
/// `wedge`'s: a measured tick further back than that is history, not a
/// starvation happening now.
pub struct Starvation {
    pub load_threshold: f64,
}
impl Condition for Starvation {
    fn id(&self) -> &'static str {
        "starvation"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let rows = w.recent_proxy(WEDGE_SCAN);
        let newest_measured = proxy_ticks(&rows).find(|t| t.measured)?;
        // Load from the newest `host` sample; absent ⇒ 0.0 (cannot be starvation).
        let load1 = w.last_host().map_or(0.0, |h| h.load1);
        (newest_measured.unanswered() && load1 > self.load_threshold).then(|| Fire {
            detail: format!("tun dead under load {load1:.2}"),
        })
    }
}

/// How many recent proxy samples `endpoint-block` scans when grouping rows into
/// per-tick cohorts: `consecutive + 1` cohorts of at most seven endpoint rows
/// fit in 64 several times over, so the scan stops long before the window's
/// [`crate::WINDOW_CAP`].
const ENDPOINT_BLOCK_SCAN: usize = 64;

/// Fires when, for the `consecutive` proxy cohorts (one cohort = the
/// per-endpoint rows sharing one `ts_us`) before the newest one, every
/// endpoint's underlay TCP verdict is `Fail` while the newest link sample's
/// `direct` probe is `Ok` — the selective-block / middlebox signature: the
/// network path to the whole upstream fleet is dead from the underlay while
/// the reference host answers.
///
/// Distinct from `wedge`, which reads the TUN probe (the proxy PROCESS path):
/// this one reads the per-endpoint underlay TCP verdicts and fires even while
/// the tun probe still passes. A cohort containing a `Skip` row is the absence
/// of a measurement (the `-` skip row means no endpoints were parsed) and
/// breaks the run; a cohort with any `Ok` is not a fleet-wide block.
/// (realm net-observer, node #69)
///
/// The engine evaluates on every row, so the newest cohort in the window is
/// always still being written. It is never judged: it is the end marker of
/// the cohort before it — the cohort-end marker #73 asked for. The fire lands
/// on the first row after the last of `consecutive` all-`Fail` cohorts,
/// whatever that row's own verdict: at most one tick late, never suppressed,
/// and no guessing at the fleet's size (a fleet that grows mid-block is read
/// row by row and judged only once ended). Proxy history does not survive a
/// resume (only the link change basis is carried), so after
/// `clear_for_resume` this needs `consecutive + 1` fresh cohorts —
/// `consecutive` to judge and one to end them. (realm net-observer, node #73)
pub struct EndpointBlock {
    pub consecutive: usize,
}

/// One per-tick cohort of proxy rows as `endpoint-block` folds them.
struct Cohort {
    ts_us: i64,
    rows: usize,
    all_fail: bool,
}

impl Condition for EndpointBlock {
    fn id(&self) -> &'static str {
        "endpoint-block"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        // The reference host must have answered, or this is a whole-network
        // outage, not a selective block. Exhaustive over the verdict: `Skip`
        // is the absence of a measurement, never a healthy reference.
        let last = w.last_link()?;
        match last.direct {
            TcpVerdict::Ok => {}
            TcpVerdict::Fail | TcpVerdict::Skip => return None,
        }
        // Per-tick cohorts, newest first. One `collect()` stamps every
        // per-endpoint row with one `ts_us`, so the shared timestamp is the
        // cohort key.
        let mut cohorts: Vec<Cohort> = Vec::new();
        for p in w.recent_proxy(ENDPOINT_BLOCK_SCAN) {
            // Exhaustive over the verdict: `Skip` carries no measurement, so
            // it can never count toward "every endpoint failed".
            let fail = match p.tcp {
                TcpVerdict::Fail => true,
                TcpVerdict::Ok | TcpVerdict::Skip => false,
            };
            match cohorts.last_mut() {
                Some(c) if c.ts_us == p.ts_us => {
                    c.rows += 1;
                    c.all_fail = c.all_fail && fail;
                }
                _ => {
                    // A new cohort begins. `consecutive + 1` are read: the
                    // newest is the end marker and is never judged, so the
                    // run is the `consecutive` cohorts after it.
                    if cohorts.len() > self.consecutive {
                        break;
                    }
                    cohorts.push(Cohort {
                        ts_us: p.ts_us,
                        rows: 1,
                        all_fail: fail,
                    });
                }
            }
        }
        // The newest cohort is still being written and is set aside; what is
        // left holds at most `consecutive` ended cohorts.
        let judged = cohorts.get(1..).unwrap_or_default();
        if judged.len() < self.consecutive {
            return None;
        }
        if !judged.iter().all(|c| c.all_fail) {
            return None;
        }
        let n = judged.first()?.rows;
        Some(Fire {
            detail: format!(
                "all {n} endpoints dead from the underlay across {k} ticks \
while the reference host answers",
                k = self.consecutive
            ),
        })
    }
}

/// Fires when the newest link sample's gateway echo went unanswered while at
/// least one LAN neighbor probed on that same tick answered — the
/// per-client-ban signature: the segment is alive, and the gateway is silent
/// only toward this client.
///
/// `lan_probed`/`lan_alive` are `None` on any tick that did not probe (healthy
/// gateway, quiet mode, no gateway): no measurement, no fire. A probed tick
/// where nobody answered is the whole segment dead — `gw-drop` territory, not
/// a selective ban. The gateway match is exhaustive so a future verdict token
/// cannot join the fault set by accident. (realm net-observer, node #70)
pub struct PerClientBlock;
impl Condition for PerClientBlock {
    fn id(&self) -> &'static str {
        "per-client-block"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        match last.gw {
            GwVerdict::Fail => {}
            GwVerdict::Ok | GwVerdict::NoGw | GwVerdict::Skip => return None,
        }
        let probed = last.lan_probed?;
        let alive = last.lan_alive?;
        if probed == 0 || alive == 0 {
            return None;
        }
        Some(Fire {
            detail: format!("gateway silent while {alive}/{probed} LAN neighbors answer"),
        })
    }
}

/// How many recent link samples `ban-cycle` scans for ban starts: 160 at the
/// 15 s link cadence is 40 min, the reach of the engine window itself
/// ([`crate::WINDOW_CAP`] holds ≈ 157 ticks of the daemon's per-tick mix).
const BAN_CYCLE_SCAN: usize = 160;

/// The fewest measured dead readings (`Fail`/`NoGw`) a run needs to be a ban:
/// Wi-Fi jitter loses single echoes, and one lost echo is not a ban. Tunable
/// by the owner.
const BAN_MIN_RUN_TICKS: usize = 2;

/// The shortest mean interval between ban starts that reads as the cycle: a
/// cycle shorter than a minute is not the field pattern (2–4 minutes per
/// round). Tunable by the owner.
const BAN_MIN_PERIOD_S: i64 = 60;

/// Fires when the window holds at least `min_bans` gateway bans — a ban being
/// a maximal run of dead gateway readings (`Fail` or `NoGw`: one run class,
/// the same fold the CLI's `gw_drops()` uses) of at least
/// `BAN_MIN_RUN_TICKS` measured ticks with an `Ok` reading on either side,
/// the newest run possibly still open, holding at least one `Fail` — and the
/// mean interval between ban starts is at least `BAN_MIN_PERIOD_S`. The
/// coworking ban-cycle signature: the client is admitted, blocked, admitted
/// again, and each round otherwise lands as its own
/// `gw-drop`/`gw-change`/`per-client-block` incident with the cycle itself
/// readable nowhere. This one names the cycle and its period, and stays
/// asserted while the pattern is in the window so the engine's clear edge
/// closes the one incident when it ages out.
///
/// The detail is written when the incident opens, so the count and span it
/// carries are those of the first firing — `min_bans` bans; the full count
/// and span of the episode live in the recorded link samples, not in this
/// detail. `Skip` is the absence of a measurement and is transparent: it
/// neither splits a run nor starts one (node #25). `NoGw` at the roam (the
/// default gateway momentarily absent before the echoes start failing) is the
/// start of that ban, not a wall that hides it — but a run of `NoGw` alone is
/// no route (the interface was down, or the roam was still in progress), not
/// a gateway that answered and then went silent toward this client: without
/// a `Fail` it is not a ban, so three Wi-Fi toggles do not read as a cycle
/// (node #97). A run the window cut off (no `Ok` older than it) has no known
/// start and is not counted. The match is exhaustive over the verdict so a
/// future token cannot join a set by accident. A cycle has a period only from
/// two bans on, so `min_bans` below 2 reads as 2.
///
/// The daemon registers this behind the settle gate on purpose: a different
/// router IP is a different segment, not one gateway's ban, so a roam that
/// re-leases a new router does not feed this count. (realm net-observer,
/// node #60)
pub struct BanCycle {
    pub min_bans: usize,
}
impl Condition for BanCycle {
    fn id(&self) -> &'static str {
        "ban-cycle"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        // Ban starts, newest first: the `ts_us` of the oldest dead reading in
        // each run, recorded once the `Ok` before that run is reached — if
        // the run measured enough dead ticks, at least one of them a `Fail`,
        // to be a ban.
        let mut starts: Vec<i64> = Vec::new();
        // The run being walked: its oldest dead reading so far, how many
        // measured dead readings it holds, and whether any of them is a
        // `Fail` (a `NoGw`-only run is no route, not a ban).
        let mut run: Option<(i64, usize, bool)> = None;
        for l in w.recent_link(BAN_CYCLE_SCAN) {
            match l.gw {
                GwVerdict::Fail | GwVerdict::NoGw => {
                    let (ticks, failed) =
                        run.map_or((0, false), |(_, ticks, failed)| (ticks, failed));
                    run = Some((l.ts_us, ticks + 1, failed || l.gw == GwVerdict::Fail));
                }
                GwVerdict::Ok => {
                    if let Some((start, ticks, failed)) = run.take()
                        && ticks >= BAN_MIN_RUN_TICKS
                        && failed
                    {
                        starts.push(start);
                    }
                }
                GwVerdict::Skip => {}
            }
        }
        let n = starts.len();
        if n < self.min_bans.max(2) {
            return None;
        }
        let intervals: Vec<i64> = starts.windows(2).map(|pair| pair[0] - pair[1]).collect();
        let span_us = starts.first()? - starts.last()?;
        // Mean interval between consecutive ban starts; the sum of the
        // intervals is the span, and `n >= 2` makes the divisor at least 1.
        let period_us = span_us / i64::try_from(intervals.len()).ok()?;
        if period_us < BAN_MIN_PERIOD_S * 1_000_000 {
            return None;
        }
        let min_us = intervals.iter().copied().min().unwrap_or(0);
        let max_us = intervals.iter().copied().max().unwrap_or(0);
        let secs = |us: i64| us / 1_000_000;
        Some(Fire {
            detail: format!(
                "gateway ban cycle: {n} bans in ~{span}s, period ~{period}s (min {min}s, max {max}s)",
                span = secs(span_us),
                period = secs(period_us),
                min = secs(min_us),
                max = secs(max_us),
            ),
        })
    }
}

/// An interface a fakeip-pool address may legitimately resolve to: a tunnel it
/// is SUPPOSED to enter (`utun`/`tun`/`ipsec`/`gif`/`stf`), or loopback (`lo`),
/// where a blackhole/reject or kill-switch route drops the packet — the
/// opposite of leaking out a real egress. A hijack is anything else.
fn is_tunnel_or_discard_iface(name: &str) -> bool {
    const PREFIXES: [&str; 6] = ["utun", "tun", "ipsec", "gif", "stf", "lo"];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Fires when the newest link sample resolved the fakeip-pool probe address to
/// a real egress interface (not a tunnel, not loopback/discard) WHILE the
/// tunnel is up — the AWDL-collision class: a fakeip answer is only meaningful
/// inside the tunnel, so a pool address routing out `awdl0`/`en0` sends traffic
/// addressed to a phantom range out a real interface.
///
/// Two gates keep an ordinary outage from reading as a hijack, and both come
/// from the SAME link sample so there is no cross-sample skew. First,
/// loopback/tunnel destinations are not a leak ([`is_tunnel_or_discard_iface`]):
/// a kill-switch/reject route resolves to `lo0` (packet dropped), the semantic
/// opposite of the leak. Second, sing-box must actually be up this tick — when
/// sing-box is down, `route get` falls through to the physical route for the
/// pool, which is "the tunnel is simply down" (`wedge`/`gw-drop` territory),
/// not a hijack. The discriminator is `singbox_tun_if`: sing-box's OWN TUN
/// address is assigned to an interface only while sing-box runs, so its
/// presence proves sing-box specifically is up. It is deliberately NOT "any
/// `utun*` owns the default" — tailscale/netbird create utuns too, and a
/// foreign utun owning the default while sing-box is down would fabricate this
/// incident. Nor the public TUN probe's 204, which travels whatever route
/// reaches gstatic and still succeeds over the physical default when the tunnel
/// is down.
///
/// `None` means the pool route could not be determined (no config, no range, no
/// route) or sing-box's TUN is not up: the absence of a measurement, never a
/// hijack. (realm net-observer, node #71)
pub struct FakeIpHijack;
impl Condition for FakeIpHijack {
    fn id(&self) -> &'static str {
        "fakeip-hijack"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let ifname = last.fakeip_route_if.as_deref()?;
        if is_tunnel_or_discard_iface(ifname) {
            return None;
        }
        // sing-box must be up, proven by its OWN TUN interface being present
        // this tick (a foreign VPN's utun does not carry sing-box's address).
        // `None` = sing-box down, so a pool address on a real interface is just
        // the outage's route fall-through, not a hijack. Same tick as the pool
        // reading, so no skew — and not a 204 that would travel the leaked path.
        let tun_if = last.singbox_tun_if.as_deref()?;
        Some(Fire {
            detail: format!(
                "fakeip pool routes via {ifname} while sing-box's TUN is up on {tun_if}"
            ),
        })
    }
}

/// Fires when the established reference stream through the tunnel has died
/// while the fresh tun probe still answers — the long-flow stall signature
/// measured all day 2026-09-08: an established stream silently stops carrying
/// while a brand-new connection succeeds instantly. Fresh probes alone cannot
/// see it, and without the discriminator the incident gets labeled by hand.
///
/// The direct underlay stream localizes the fault, spelled out in the detail:
/// it surviving means the stall is scoped to the proxied path
/// (endpoint/protocol — the thing loosely called DPI); both dying means the
/// underlay's treatment of long flows (NAT idle-eviction / radio), not the
/// proxy. `None` on either side is the absence of a measurement (the stream
/// was only just opened, or could not be opened): no fire on the tunnel side,
/// an explicit "unmeasured" in the detail on the direct side. A dead fresh
/// probe alongside is a plain outage — `wedge`/`gw-drop` territory, not a
/// stall of established flows.
///
/// The "endpoint-scoped" verdict requires the surviving direct stream to be at
/// least as old as the stalled tunnel stream. The two streams reconnect
/// independently, so on a real underlay stall the direct stream can have died
/// and come back young while the tunnel stream reports its long life at death;
/// a young direct stream is not proof the underlay was healthy across the
/// window, so it reads "underlay-ambiguous" rather than exonerating the
/// underlay. Proxy history does not survive a resume, so after
/// `clear_for_resume` this waits for a fresh reading. (realm net-observer, node #72)
pub struct EstablishedStall;
impl Condition for EstablishedStall {
    fn id(&self) -> &'static str {
        "established-stall"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let p = w.last_proxy()?;
        if p.est_tun_alive? {
            return None;
        }
        // The fresh path must still ANSWER, or this is a plain outage (or no
        // measurement at all), not a long-flow stall. Read off the newest
        // tick's fold — the one `wedge` and `starvation` share — so "the
        // record's `0` = probed, no status" and "`NULL` = not probed" are
        // decided in one place: neither is an answer.
        let rows = w.recent_proxy(WEDGE_SCAN);
        if !proxy_ticks(&rows).next()?.answered() {
            return None;
        }
        let tun_age = p.est_tun_age_s.unwrap_or(0);
        let direct_age = p.est_direct_age_s.unwrap_or(0);
        let detail = match p.est_direct_alive {
            // A surviving direct stream exonerates the underlay only if it is at
            // least as old as the tunnel stream that died — else it may have
            // reconnected young through the same underlay hiccup.
            Some(true) if direct_age >= tun_age => format!(
                "established stream through the tunnel stalled after ~{tun_age}s (fresh OK); \
direct underlay stream survived ~{direct_age}s -> endpoint/protocol-scoped"
            ),
            Some(true) => format!(
                "established stream through the tunnel stalled after ~{tun_age}s (fresh OK); \
direct underlay stream too young to compare (~{direct_age}s) -> underlay-ambiguous"
            ),
            Some(false) => format!(
                "established streams through the tunnel and the direct underlay both stalled \
after ~{tun_age}s/~{direct_age}s (fresh OK) -> underlay (NAT/radio), not proxy-scoped"
            ),
            None => format!(
                "established stream through the tunnel stalled after ~{tun_age}s (fresh OK); \
direct underlay stream unmeasured"
            ),
        };
        Some(Fire { detail })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::{RecentWindow, WINDOW_CAP};
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, LinkMedium, LinkSample, NeighborObs,
        NeighborRole, NeighborSource, NeighborsSample, NeighborsVerdict, ProxySample, Sample,
        TcpVerdict,
    };

    fn dns(ts: i64, probe: &str, verdict: DnsVerdict, ip: Option<&str>) -> Sample {
        Sample::Dns(DnsSample {
            ts_us: ts,
            probe: probe.into(),
            server: "sb".into(),
            verdict,
            ip: ip.map(str::to_string),
            rtt_ms: None,
        })
    }
    fn host(ts: i64, load1: f64) -> Sample {
        Sample::Host(HostSample {
            ts_us: ts,
            load1,
            load5: load1,
            load15: load1,
            disk_used_pct: None,
            disk_free_mb: None,
            swap_used_mb: None,
        })
    }

    fn link(ts: i64, direct: TcpVerdict) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    /// A link sample with an explicit gateway verdict (the existing [`link`]
    /// helper varies `direct` and pins `gw` to OK).
    fn link_gw(ts: i64, gw: GwVerdict) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    fn proxy(ts: i64, tun: u16) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us: ts,
            server_ip: "1".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(tun),
            selector: None,
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
        })
    }

    /// A per-endpoint proxy row: pins the endpoint string and the underlay TCP
    /// verdict, with a HEALTHY tun (`endpoint-block` reads the underlay
    /// verdicts and must fire even while the tun probe still passes). The
    /// existing [`proxy`] builder pins a single server and varies the tun
    /// instead.
    fn proxy_ep(ts: i64, endpoint: &str, tcp: TcpVerdict) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us: ts,
            server_ip: endpoint.into(),
            tcp,
            rtt_ms: None,
            tun_code: Some(204),
            selector: None,
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
        })
    }

    /// A link sample carrying only what `GwMacChange` reads: the DHCP router IP
    /// and the ARP-resolved gateway MAC, either possibly absent.
    fn link_router_mac(ts: i64, router: Option<&str>, mac: Option<&str>) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: router.map(str::to_string),
            dhcp_dns: None,
            gw_arp_mac: mac.map(str::to_string),
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    fn nobs(ip: &str, mac: &str) -> NeighborObs {
        NeighborObs {
            mac: mac.into(),
            ip: ip.into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        }
    }

    fn neighbors(ts: i64, verdict: NeighborsVerdict, obs: Vec<NeighborObs>) -> Sample {
        Sample::Neighbors(NeighborsSample {
            ts_us: ts,
            verdict,
            reason: None,
            network_key: None,
            iface: None,
            neighbors: obs,
        })
    }

    #[test]
    fn wedge_fires_after_three_dead_ticks() {
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        for t in 0..2 {
            w.push(link(t * 2, TcpVerdict::Ok));
            w.push(proxy(t * 2 + 1, 0));
            assert!(c.eval(&w).is_none());
        }
        w.push(link(4, TcpVerdict::Ok));
        w.push(proxy(5, 0));
        assert!(c.eval(&w).is_some());
    }
    #[test]
    fn wedge_silent_when_direct_also_down() {
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        for t in 0..3 {
            w.push(link(t * 2, TcpVerdict::Fail));
            w.push(proxy(t * 2 + 1, 0));
        }
        assert!(c.eval(&w).is_none()); // whole-network down, not a wedge
    }

    /// The pipeline's preflight-skip placeholder: a lone Skip row carrying no
    /// measurement at all (mirrors `ProxyCollector::skip`).
    fn skip_proxy(ts: i64) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us: ts,
            server_ip: "-".into(),
            tcp: TcpVerdict::Skip,
            rtt_ms: None,
            tun_code: None,
            selector: None,
            est_direct_alive: None,
            est_direct_age_s: None,
            est_tun_alive: None,
            est_tun_age_s: None,
        })
    }

    #[test]
    fn wedge_counts_ticks_not_rows() {
        // One tick emits one row per ENDPOINT, all sharing ts_us. A burst of
        // dead rows from a single tick must not satisfy `consecutive` — this
        // is the 2026-09-10 false-positive shape: one transient transport
        // failure, seven rows, incident.
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        w.push(link(0, TcpVerdict::Ok));
        w.push(link(2, TcpVerdict::Ok));
        w.push(link(4, TcpVerdict::Ok));
        for _ in 0..3 {
            w.push(proxy(5, 0));
        }
        assert!(c.eval(&w).is_none());
    }

    #[test]
    fn wedge_skip_placeholder_is_transparent() {
        // A preflight-skip tick is the absence of a measurement: it neither
        // advances nor resets the dead run (node #25), so three measured dead
        // ticks around one still fire.
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        w.push(link(0, TcpVerdict::Ok));
        w.push(link(2, TcpVerdict::Ok));
        w.push(link(4, TcpVerdict::Ok));
        w.push(proxy(1, 0));
        w.push(skip_proxy(3));
        w.push(proxy(5, 0));
        w.push(proxy(7, 0));
        assert!(c.eval(&w).is_some());
    }

    #[test]
    fn wedge_healthy_measured_tick_breaks_the_run() {
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        w.push(link(0, TcpVerdict::Ok));
        w.push(link(2, TcpVerdict::Ok));
        w.push(link(4, TcpVerdict::Ok));
        w.push(proxy(1, 0));
        w.push(proxy(3, 0));
        w.push(proxy(5, 204));
        assert!(c.eval(&w).is_none());
    }

    /// The dead-tick scan is bounded by `WEDGE_SCAN` proxy rows: a dead run
    /// that far behind the present is history, not a wedge now. Three dead
    /// ticks followed by exactly enough skip placeholders to be the oldest
    /// rows of the scan still fire; one placeholder more pushes the run out
    /// of reach. Dies under the unbounded `usize::MAX` scan (#96), which
    /// fired on a run any number of unmeasured ticks old.
    #[test]
    fn wedge_does_not_reach_past_the_scan_bound() {
        let c = Wedge { consecutive: 3 };
        let stream = |placeholders: usize| {
            let mut w = RecentWindow::new(WINDOW_CAP);
            push_wedge_ticks(&mut w, 0, 3);
            for i in 0..placeholders {
                w.push(skip_proxy(100 + i as i64));
            }
            w
        };
        assert!(
            c.eval(&stream(WEDGE_SCAN - 3)).is_some(),
            "the dead run as the oldest rows of the scan still fires"
        );
        assert!(
            c.eval(&stream(WEDGE_SCAN - 2)).is_none(),
            "a dead run beyond WEDGE_SCAN rows is not the present"
        );
    }

    /// A link sample whose only interesting field is the network identity
    /// (`dhcp_router`) — the settle gate's input.
    fn link_router(ts: i64, router: Option<&str>) -> Sample {
        match link(ts, TcpVerdict::Ok) {
            Sample::Link(mut l) => {
                l.dhcp_router = router.map(str::to_string);
                Sample::Link(l)
            }
            other => other,
        }
    }

    /// A condition that always asserts — the gate around it is what's under test.
    struct AlwaysFire;
    impl Condition for AlwaysFire {
        fn id(&self) -> &'static str {
            "always"
        }
        fn eval(&self, _: &RecentWindow) -> Option<Fire> {
            Some(Fire {
                detail: "always".into(),
            })
        }
    }

    #[test]
    fn gate_requires_a_measured_direct_ok() {
        let mut w = RecentWindow::new(16);
        let c = Gated {
            inner: AlwaysFire,
            require_direct: true,
            load_below: None,
            settle_us: None,
        };
        assert!(
            c.eval(&w).is_none(),
            "no link sample at all is no measurement, not a pass"
        );
        w.push(link(1, TcpVerdict::Fail));
        assert!(c.eval(&w).is_none(), "uplink down voids the verdict");
        w.push(link(2, TcpVerdict::Ok));
        assert!(c.eval(&w).is_some());
    }

    /// A `direct` reading is evidence the uplink works NOW only within the
    /// last `GATE_DIRECT_SCAN` link samples: an `Ok` that many quiet ticks
    /// ago is the oldest reading the gate still accepts, one tick older and
    /// the gate refuses. Dies under the `GW_CHANGE_SCAN` reach the gate used
    /// to share with `gw-change` (#96), which accepted a `direct` from 64
    /// ticks back as the present.
    #[test]
    fn gate_refuses_a_direct_reading_older_than_its_scan() {
        let c = Gated {
            inner: AlwaysFire,
            require_direct: true,
            load_below: None,
            settle_us: None,
        };
        let stream = |quiet: usize| {
            let mut w = RecentWindow::new(WINDOW_CAP);
            w.push(link(0, TcpVerdict::Ok));
            for i in 0..quiet {
                w.push(link(1 + i as i64, TcpVerdict::Skip));
            }
            w
        };
        assert!(
            c.eval(&stream(GATE_DIRECT_SCAN - 1)).is_some(),
            "an Ok as the oldest sample of the scan still passes"
        );
        assert!(
            c.eval(&stream(GATE_DIRECT_SCAN)).is_none(),
            "an Ok older than GATE_DIRECT_SCAN samples is not evidence now"
        );
    }

    #[test]
    fn gate_suppresses_under_host_starvation() {
        let mut w = RecentWindow::new(16);
        let c = Gated {
            inner: AlwaysFire,
            require_direct: false,
            load_below: Some(10.0),
            settle_us: None,
        };
        assert!(
            c.eval(&w).is_some(),
            "no host sample = no starvation evidence, the gate stays open"
        );
        w.push(host(1, 42.0));
        assert!(
            c.eval(&w).is_none(),
            "probes under load measure the run queue"
        );
        w.push(host(2, 3.0));
        assert!(c.eval(&w).is_some());
    }

    #[test]
    fn gate_holds_through_a_network_move_settle_window() {
        let mut w = RecentWindow::new(16);
        let c = Gated {
            inner: AlwaysFire,
            require_direct: false,
            load_below: None,
            settle_us: Some(100),
        };
        w.push(link_router(1, Some("10.0.0.1")));
        w.push(link_router(50, Some("192.168.0.1")));
        assert!(
            c.eval(&w).is_none(),
            "identity changed inside the settle window"
        );
        w.push(link_router(200, Some("192.168.0.1")));
        assert!(
            c.eval(&w).is_some(),
            "the old identity aged out of the settle horizon"
        );
    }

    /// Push `n` wedge-shaped tick pairs (direct healthy, tun dead) starting at
    /// `from`, two microseconds apart.
    fn push_wedge_ticks(w: &mut RecentWindow, from: i64, n: i64) {
        for t in 0..n {
            w.push(link(from + t * 2, TcpVerdict::Ok));
            w.push(proxy(from + t * 2 + 1, 0));
        }
    }

    #[test]
    fn wedge_does_not_fire_across_a_cleared_window() {
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        push_wedge_ticks(&mut w, 0, 2);
        // The resume edge drops everything on the far side of the observation
        // gap, so the two pre-pause ticks can never combine with a post-resume
        // one into "tun dead 3 ticks" — a continuity that never existed.
        w.clear_for_resume();
        push_wedge_ticks(&mut w, 1_000, 1);
        assert!(c.eval(&w).is_none());
    }

    #[test]
    fn wedge_fires_without_a_clear() {
        // The control half of the pair: the very same three tick pairs, with no
        // clear between them, DO fire — so the test above measures the clear
        // and not a fixture that simply never populated the window.
        let mut w = RecentWindow::new(16);
        let c = Wedge { consecutive: 3 };
        push_wedge_ticks(&mut w, 0, 2);
        push_wedge_ticks(&mut w, 1_000, 1);
        assert!(c.eval(&w).is_some());
    }

    #[test]
    fn fakeip_fires_on_ru_fakeip_answer() {
        let mut w = RecentWindow::new(16);
        // A healthy .ru answer and a monitored-domain answer do not fire.
        w.push(dns(1, "ru", DnsVerdict::Ok, Some("87.250.250.242")));
        w.push(dns(2, "nks", DnsVerdict::Ok, Some("10.0.0.1")));
        assert!(FakeIp.eval(&w).is_none());
        // A fakeip answer on the .ru control domain fires.
        w.push(dns(3, "ru", DnsVerdict::FakeIp, Some("198.18.0.7")));
        let fire = FakeIp
            .eval(&w)
            .expect("fakeip must fire on a .ru fakeip answer");
        assert!(fire.detail.contains("198.18.0.7"));
    }

    #[test]
    fn fakeip_silent_when_fakeip_is_not_a_ru_name() {
        let mut w = RecentWindow::new(16);
        // Fakeip on the monitored (non-.ru) domain is expected routing, not a bug.
        w.push(dns(1, "nks", DnsVerdict::FakeIp, Some("198.18.0.9")));
        assert!(FakeIp.eval(&w).is_none());
    }

    #[test]
    fn starvation_fires_when_tun_dead_under_high_load() {
        let mut w = RecentWindow::new(16);
        let c = Starvation {
            load_threshold: 10.0,
        };
        // Dead tun but no host sample yet ⇒ load defaults to 0.0 ⇒ no fire.
        w.push(proxy(1, 0));
        assert!(c.eval(&w).is_none());
        // Dead tun under a low load ⇒ no fire.
        w.push(host(2, 3.0));
        assert!(c.eval(&w).is_none());
        // Dead tun under a high load ⇒ starvation fires.
        w.push(host(3, 12.5));
        let fire = c.eval(&w).expect("starvation must fire under high load");
        assert!(fire.detail.contains("12.5"));
    }

    #[test]
    fn starvation_silent_when_tun_alive_under_high_load() {
        let mut w = RecentWindow::new(16);
        let c = Starvation {
            load_threshold: 10.0,
        };
        w.push(proxy(1, 204)); // tun healthy
        w.push(host(2, 20.0)); // high load, but the tun is fine
        assert!(c.eval(&w).is_none());
    }

    /// A passive tick lands as the proxy Skip placeholder (`tcp = SKIP`, no
    /// `tun_code`): no probe ran, so there is no dead tun to blame the load
    /// for. Dies under reading an absent `tun_code` as a dead tun — which
    /// opened a `starvation` incident on every passive tick under load.
    #[test]
    fn starvation_needs_a_measured_dead_tun_not_a_skip_placeholder() {
        let mut w = RecentWindow::new(16);
        let c = Starvation {
            load_threshold: 10.0,
        };
        w.push(skip_proxy(1));
        w.push(host(2, 12.0));
        assert!(
            c.eval(&w).is_none(),
            "a Skip placeholder is no measurement, so no starvation"
        );
        // The placeholder is transparent, as for `wedge`: the newest MEASURED
        // tick decides. A measured dead tick before it still fires...
        w.push(proxy(3, 0));
        w.push(skip_proxy(4));
        assert!(
            c.eval(&w).is_some(),
            "the newest measured tick is dead and the load is high"
        );
        // ...and a measured healthy tick before it does not, however many
        // placeholders follow.
        w.push(proxy(5, 204));
        w.push(skip_proxy(6));
        w.push(skip_proxy(7));
        assert!(c.eval(&w).is_none(), "the newest measured tick is healthy");
    }

    /// Starvation's "dead" is the record's `tun_code = 0` — a probe attempted
    /// with no HTTP status, the value the collector writes for a transport
    /// failure and `why` / `wedge-or-starvation` read as dead — so live and
    /// offline read the same `0`. A tun that ANSWERED (a captive portal's
    /// 200, a 5xx) is not dead for starvation however high the load, because
    /// `why` calls that tick healthy and a live incident the record contradicts
    /// is worse than none; and a `NULL` code is "not probed", not "no answer".
    /// (`wedge`'s `!= 204` is a different, pre-existing reading.)
    #[test]
    fn starvation_reads_the_records_zero_and_nothing_else_as_dead() {
        let mut w = RecentWindow::new(16);
        let c = Starvation {
            load_threshold: 10.0,
        };
        w.push(host(1, 20.0));
        w.push(proxy(2, 200));
        assert!(c.eval(&w).is_none(), "a captive portal's 200 is an answer");
        w.push(proxy(3, 502));
        assert!(c.eval(&w).is_none(), "a 5xx is an answer too");
        // A measured tick with NO tun code (the endpoints were probed, the tun
        // was not) is "not probed" for the tun: neither an answer nor the
        // absence of one, so nothing to blame the load for.
        w.push(Sample::Proxy(ProxySample {
            tun_code: None,
            ..match proxy(4, 0) {
                Sample::Proxy(p) => p,
                other => panic!("{other:?}"),
            }
        }));
        assert!(c.eval(&w).is_none(), "NULL is not probed, not unanswered");
        // Attempted, no status — the record's `0` — IS the dead tun.
        w.push(proxy(5, 0));
        assert!(c.eval(&w).is_some(), "tun_code 0 under load is starvation");
    }

    /// The scan is bounded like `wedge`'s: a dead measured tick further back
    /// than `WEDGE_SCAN` rows, with only unmeasured placeholders since, is
    /// history — not a starvation happening now.
    #[test]
    fn starvation_does_not_reach_past_the_scan_bound() {
        let mut w = RecentWindow::new(WINDOW_CAP);
        let c = Starvation {
            load_threshold: 10.0,
        };
        w.push(host(1, 20.0));
        w.push(proxy(2, 0));
        assert!(c.eval(&w).is_some(), "the dead tick is the newest measured");
        // WEDGE_SCAN placeholders push the dead tick out of the scanned rows.
        for i in 0..WEDGE_SCAN as i64 {
            w.push(skip_proxy(10 + i));
        }
        assert!(
            c.eval(&w).is_none(),
            "a dead tick beyond the scan bound must not fire"
        );
    }

    #[test]
    fn gw_drop_and_change() {
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Ok));
        assert!(GwDrop.eval(&w).is_none());
        assert!(GwChange.eval(&w).is_none()); // no prev
        w.push(link_gw(2, GwVerdict::Fail));
        assert!(GwDrop.eval(&w).is_some());
        assert!(GwChange.eval(&w).is_some()); // Ok -> Fail
    }

    /// Quiet mode suppresses the echo, so the tick reports `SKIP`. That is the
    /// absence of a measurement, not a dead gateway: it must not fire `gw-drop`,
    /// and turning quiet on or off must not fire `gw-change` either.
    #[test]
    fn quiet_skip_ticks_are_neither_a_drop_nor_a_change() {
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Ok));
        // Quiet on: OK -> SKIP is the operator, not the network.
        w.push(link_gw(2, GwVerdict::Skip));
        assert!(GwDrop.eval(&w).is_none(), "SKIP is not a gateway drop");
        assert!(
            GwChange.eval(&w).is_none(),
            "turning quiet on must not fire gw-change"
        );
        w.push(link_gw(3, GwVerdict::Skip));
        assert!(GwChange.eval(&w).is_none());
        // Quiet off with the gateway unchanged: SKIP -> OK is not a change either.
        w.push(link_gw(4, GwVerdict::Ok));
        assert!(
            GwChange.eval(&w).is_none(),
            "turning quiet off must not fire gw-change when nothing moved"
        );
    }

    /// A gateway change that happened WHILE quiet was on is still a change: the
    /// first measured tick after the quiet run is compared against the last
    /// measured tick before it, and the detail says the run was straddled.
    #[test]
    fn gw_change_fires_across_a_quiet_run() {
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Ok));
        w.push(link_gw(2, GwVerdict::Skip));
        w.push(link_gw(3, GwVerdict::Skip));
        w.push(link_gw(4, GwVerdict::Fail));
        let fire = GwChange
            .eval(&w)
            .expect("a change straddling a quiet run must still fire");
        assert!(
            fire.detail
                .contains(&format!("{} -> {}", GwVerdict::Ok, GwVerdict::Fail)),
            "detail must name both measured verdicts: {}",
            fire.detail
        );
        // Quiet and the passive tier both withhold the echo, and a SKIP run
        // does not say which: the label names the withholding, not quiet.
        assert!(
            fire.detail.ends_with(" (across 2 withheld tick(s))"),
            "the detail must say the change straddled withheld ticks: {}",
            fire.detail
        );
    }

    /// With nothing measured before the quiet run there is no basis at all, so
    /// the first real tick after it is not reported as a change.
    #[test]
    fn gw_change_silent_when_only_skips_precede() {
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Skip));
        w.push(link_gw(2, GwVerdict::Ok));
        assert!(GwChange.eval(&w).is_none());
    }

    #[test]
    fn gw_change_fires_across_a_resume_clear() {
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Ok));
        // The gateway changes DURING the pause. The pcap ring is not gated by
        // `observing`, so the packets around that change are still in it at
        // resume — the oracle freezes on ANY gateway change, so this must fire.
        w.clear_for_resume();
        w.push(link_gw(10, GwVerdict::Fail));
        let fire = GwChange
            .eval(&w)
            .expect("a gateway change during a pause must still fire at resume");
        // Rendered from the verdicts themselves, so the assertion tracks the
        // verdict vocabulary instead of restating it.
        assert!(
            fire.detail
                .contains(&format!("{} -> {}", GwVerdict::Ok, GwVerdict::Fail)),
            "detail must name both verdicts: {}",
            fire.detail
        );
        // …and must not read as two consecutive ticks to an offline reader.
        assert!(
            fire.detail.contains("across an observation gap"),
            "a cross-gap change must be marked as such: {}",
            fire.detail
        );
    }

    #[test]
    fn gw_change_silent_across_a_resume_when_the_gateway_is_unchanged() {
        // The control for the test above: without it, "always fire at resume"
        // would pass just as well.
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Ok));
        w.clear_for_resume();
        w.push(link_gw(10, GwVerdict::Ok));
        assert!(GwChange.eval(&w).is_none());
    }

    #[test]
    fn gw_drop_does_not_fire_on_the_carried_basis() {
        // The basis is a comparison partner, never the present state: it must be
        // invisible to `last_link`. This breaks loudly if the carry is ever
        // implemented by re-pushing the sample into the buffer.
        let mut w = RecentWindow::new(8);
        w.push(link_gw(1, GwVerdict::Fail));
        w.clear_for_resume();
        assert!(GwDrop.eval(&w).is_none());
    }

    #[test]
    fn gw_mac_change_fires_on_same_ip_different_mac() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        assert!(GwMacChange.eval(&w).is_none(), "no predecessor yet");
        w.push(link_router_mac(
            2,
            Some("192.168.1.1"),
            Some("cc:cc:cc:cc:cc:cc"),
        ));
        let fire = GwMacChange
            .eval(&w)
            .expect("same gateway IP with a different MAC must fire");
        assert!(fire.detail.contains("192.168.1.1"));
        assert!(fire.detail.contains("aa:aa:aa:aa:aa:aa"));
        assert!(fire.detail.contains("cc:cc:cc:cc:cc:cc"));
    }

    /// The upgrade boundary itself: a predecessor stored before the
    /// source-side normalisation landed carries `arp -n`'s raw, unpadded
    /// form, and the successor carries the same gateway's now-normalised
    /// form. Comparing unfolded would read this as a MAC change on the very
    /// first tick after the upgrade — one false incident per machine — so it
    /// must stay silent (realm net-observer, node #94).
    #[test]
    fn gw_mac_change_silent_across_the_normalisation_upgrade() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("0:1e:6:ab:cd:ef"),
        ));
        w.push(link_router_mac(
            2,
            Some("192.168.1.1"),
            Some("00:1e:06:ab:cd:ef"),
        ));
        assert!(GwMacChange.eval(&w).is_none());
    }

    /// A genuine change is still caught even when the predecessor is in the
    /// pre-upgrade raw form: the fold must not paper over a real difference,
    /// only the padding one.
    #[test]
    fn gw_mac_change_fires_when_a_real_change_crosses_the_upgrade_boundary() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("0:1e:6:ab:cd:ef"),
        ));
        w.push(link_router_mac(
            2,
            Some("192.168.1.1"),
            Some("cc:cc:cc:cc:cc:cc"),
        ));
        let fire = GwMacChange
            .eval(&w)
            .expect("a real change must still fire across the upgrade boundary");
        assert!(fire.detail.contains("00:1e:06:ab:cd:ef"));
        assert!(fire.detail.contains("cc:cc:cc:cc:cc:cc"));
    }

    #[test]
    fn gw_mac_change_silent_when_mac_is_unchanged() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        w.push(link_router_mac(
            2,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        assert!(GwMacChange.eval(&w).is_none());
    }

    /// A genuine IP change (moving to a different router entirely) is `gw-change`
    /// territory, not this signature — firing here too would double-report an
    /// ordinary network switch as an ARP anomaly.
    #[test]
    fn gw_mac_change_silent_when_the_router_ip_also_changed() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        w.push(link_router_mac(
            2,
            Some("10.0.0.1"),
            Some("cc:cc:cc:cc:cc:cc"),
        ));
        assert!(GwMacChange.eval(&w).is_none());
    }

    /// Missing ARP/DHCP data on either side (never observed yet, or the
    /// `default_gw()` lookup failed that tick) breaks the comparison rather than
    /// firing — an absent measurement is not evidence of a MAC change.
    #[test]
    fn gw_mac_change_silent_when_either_side_is_missing_data() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(1, None, None));
        w.push(link_router_mac(
            2,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        assert!(GwMacChange.eval(&w).is_none());
    }

    /// A MAC change that happened during a pause is still detectable at resume:
    /// `GwMacChange` rides `prev_link`'s carried basis exactly like `GwChange`.
    #[test]
    fn gw_mac_change_fires_across_a_resume() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        w.clear_for_resume();
        w.push(link_router_mac(
            10,
            Some("192.168.1.1"),
            Some("cc:cc:cc:cc:cc:cc"),
        ));
        assert!(GwMacChange.eval(&w).is_some());
    }

    /// The ARP cache is routinely empty for a tick or two right after a link
    /// flap — which is exactly when the gateway MAC changes. Comparing only
    /// against the immediate predecessor loses the change permanently: the tick
    /// after the unreadable one already agrees with itself.
    #[test]
    fn gw_mac_change_survives_a_transient_arp_miss() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        w.push(link_router_mac(2, Some("192.168.1.1"), None));
        w.push(link_router_mac(
            3,
            Some("192.168.1.1"),
            Some("cc:cc:cc:cc:cc:cc"),
        ));
        let fire = GwMacChange
            .eval(&w)
            .expect("a MAC change straddling an unreadable tick must still fire");
        assert!(fire.detail.contains("aa:aa:aa:aa:aa:aa"));
        assert!(fire.detail.contains("cc:cc:cc:cc:cc:cc"));
        assert!(
            fire.detail.contains("without an ARP entry"),
            "the comparison is not two consecutive measurements and must say so: {}",
            fire.detail
        );
    }

    /// Across a pause the same gateway IP answered by a new MAC is equally well
    /// explained by an ARP spoof and by a move to a different network that
    /// happens to use the same address plan. The incident must not present the
    /// first reading as the only one, so the provenance is labelled.
    #[test]
    fn gw_mac_change_across_a_resume_is_labelled() {
        let mut w = RecentWindow::new(8);
        w.push(link_router_mac(
            1,
            Some("192.168.1.1"),
            Some("aa:aa:aa:aa:aa:aa"),
        ));
        w.clear_for_resume();
        w.push(link_router_mac(
            10,
            Some("192.168.1.1"),
            Some("cc:cc:cc:cc:cc:cc"),
        ));
        let fire = GwMacChange.eval(&w).expect("must fire across a resume");
        assert!(
            fire.detail.contains("across an observation gap"),
            "a comparison across a pause must be attributable: {}",
            fire.detail
        );
    }

    /// A link sample carrying only what `Roam` reads: the measured medium of
    /// the default-route interface, the Wi-Fi network name, the associated
    /// access point and the interface's own MAC, each possibly unmeasured.
    /// Gateway and direct are healthy, everything else absent.
    fn link_on(
        ts: i64,
        medium: Option<LinkMedium>,
        ssid: Option<&str>,
        bssid: Option<&str>,
        if_mac: Option<&str>,
    ) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: ssid.map(str::to_string),
            bssid: bssid.map(str::to_string),
            if_mac: if_mac.map(str::to_string),
            medium,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    /// [`link_on`] a link whose medium was measured as Wi-Fi — what every
    /// identity reading in these tests is unless it says otherwise.
    fn link_identity(
        ts: i64,
        ssid: Option<&str>,
        bssid: Option<&str>,
        if_mac: Option<&str>,
    ) -> Sample {
        link_on(ts, Some(LinkMedium::Wifi), ssid, bssid, if_mac)
    }

    /// [`link_on`] a link whose medium was measured as wired: no Wi-Fi
    /// identity, the wired adapter's own address as `if_mac`.
    fn link_wired(ts: i64, if_mac: &str) -> Sample {
        link_on(ts, Some(LinkMedium::Wired), None, None, Some(if_mac))
    }

    const AP_A: &str = "aa:aa:aa:aa:aa:01";
    const AP_B: &str = "aa:aa:aa:aa:aa:02";
    const MAC_A: &str = "cc:cc:cc:cc:cc:01";
    const MAC_B: &str = "cc:cc:cc:cc:cc:02";

    /// Band steering: the same SSID answered by a new BSSID is a roam, and the
    /// detail names both access points (an unmoved SSID is not named).
    /// The harmless class: the link address survived the hop, so the DHCP
    /// exchange was a sub-second INIT-REBOOT on the same IP — and the detail
    /// says so (node #109).
    #[test]
    fn roam_fires_when_the_bssid_moves_at_the_same_ssid() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        assert!(Roam.eval(&w).is_none(), "no predecessor yet");
        w.push(link_identity(2, Some("Office"), Some(AP_B), Some(MAC_A)));
        let fire = Roam
            .eval(&w)
            .expect("a new BSSID at the same SSID must fire");
        assert_eq!(
            fire.detail,
            format!("roam: BSSID {AP_A} -> {AP_B}; link address kept")
        );
    }

    /// Private Wi-Fi Address rotating the link's own address is a new DHCP
    /// identity toward the network — DHCP from scratch, the harmful class — a
    /// roam even with the access point unchanged (node #109).
    #[test]
    fn roam_fires_when_the_link_address_moves() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office"), Some(AP_A), Some(MAC_B)));
        let fire = Roam.eval(&w).expect("a new link address must fire");
        assert_eq!(
            fire.detail,
            format!("roam: link address {MAC_A} -> {MAC_B} (new DHCP identity)")
        );
    }

    /// Both identities moving on one tick is one roam of the harmful class,
    /// and the one detail names both moves.
    #[test]
    fn roam_names_both_moves_in_one_detail() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office"), Some(AP_B), Some(MAC_B)));
        let fire = Roam.eval(&w).expect("both moves must fire once");
        assert_eq!(
            fire.detail,
            format!(
                "roam: BSSID {AP_A} -> {AP_B}; \
link address {MAC_A} -> {MAC_B} (new DHCP identity)"
            )
        );
    }

    /// A BSSID hop whose link address could not be read on either side
    /// cannot be classified: the detail says the address is unmeasured
    /// rather than claiming it was kept.
    #[test]
    fn roam_says_when_the_link_address_is_unmeasured() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office"), Some(AP_B), None));
        let fire = Roam
            .eval(&w)
            .expect("a BSSID hop fires whatever the link address reading");
        assert_eq!(
            fire.detail,
            format!("roam: BSSID {AP_A} -> {AP_B}; link address unmeasured")
        );
    }

    /// The #57 twin SSIDs have DIFFERENT names (5 GHz / 6 GHz): a hop between
    /// them is a BSSID change whatever the SSID did, and the detail names the
    /// SSID move too. With the link address kept it is the harmless class.
    /// Dies under a "same SSID" guard on the BSSID comparison.
    #[test]
    fn roam_fires_on_a_twin_ssid_hop_with_the_address_kept() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office-5G"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office-6G"), Some(AP_B), Some(MAC_A)));
        let fire = Roam.eval(&w).expect("a hop between twin SSIDs must fire");
        assert_eq!(
            fire.detail,
            format!("roam: BSSID {AP_A} -> {AP_B}, SSID Office-5G -> Office-6G; link address kept")
        );
    }

    /// The same twin-SSID hop with Private Wi-Fi Address rotating the link
    /// address per SSID: both the SSID move and the new address are in the
    /// detail — the harmful class.
    #[test]
    fn roam_fires_on_a_twin_ssid_hop_with_a_per_ssid_address() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office-5G"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office-6G"), Some(AP_B), Some(MAC_B)));
        let fire = Roam
            .eval(&w)
            .expect("a twin-SSID hop with a per-SSID address must fire");
        assert_eq!(
            fire.detail,
            format!(
                "roam: BSSID {AP_A} -> {AP_B}, SSID Office-5G -> Office-6G; \
link address {MAC_A} -> {MAC_B} (new DHCP identity)"
            )
        );
    }

    /// The same sample with a DHCP router set — what `Roam` appends when the
    /// router moved in the same comparison.
    fn with_router(sample: Sample, router: Option<&str>) -> Sample {
        match sample {
            Sample::Link(mut l) => {
                l.dhcp_router = router.map(str::to_string);
                Sample::Link(l)
            }
            other => other,
        }
    }

    /// A router that changed in the same comparison is appended, not
    /// suppressed: the record says what happened, and whether the hop was a
    /// move to another segment is the reader's call.
    #[test]
    fn roam_names_a_router_change_in_the_same_comparison() {
        let mut w = RecentWindow::new(8);
        w.push(with_router(
            link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)),
            Some("10.0.0.1"),
        ));
        w.push(with_router(
            link_identity(2, Some("Office"), Some(AP_B), Some(MAC_A)),
            Some("192.168.0.1"),
        ));
        let fire = Roam.eval(&w).expect("a BSSID hop fires");
        assert_eq!(
            fire.detail,
            format!(
                "roam: BSSID {AP_A} -> {AP_B}; link address kept; router 10.0.0.1 -> 192.168.0.1"
            )
        );
    }

    /// `if_mac` is the default-route interface's MAC and the sample carries
    /// no interface name, so a dock or undock moves it between the wired and
    /// the Wi-Fi adapter. A tick whose medium was measured as wired is
    /// transparent: a wired hop is no roam, and the Wi-Fi identity on either
    /// side of it compares against itself. Dies under an `if_mac` comparison
    /// that ignores the medium.
    #[test]
    fn roam_ignores_a_wired_hop() {
        let mut w = RecentWindow::new(8);
        w.push(link_wired(1, MAC_A));
        w.push(link_wired(2, MAC_B));
        assert!(
            Roam.eval(&w).is_none(),
            "a new address on a wired link is not a roam"
        );
        // Undock onto Wi-Fi, dock back, undock again: the Wi-Fi identity is
        // unchanged across the wired tick, so nothing fires at any step.
        w.push(link_identity(3, Some("Office"), Some(AP_A), Some(MAC_A)));
        assert!(
            Roam.eval(&w).is_none(),
            "the first Wi-Fi tick has no Wi-Fi predecessor and is no roam"
        );
        w.push(link_wired(4, MAC_B));
        assert!(Roam.eval(&w).is_none(), "docking is not a roam");
        w.push(link_identity(5, Some("Office"), Some(AP_A), Some(MAC_A)));
        assert!(
            Roam.eval(&w).is_none(),
            "undocking onto the same Wi-Fi identity is not a roam"
        );
    }

    /// The medium is judged from the measurement, never from whether a Wi-Fi
    /// name was readable: a Wi-Fi tick whose SSID and BSSID are both
    /// unreadable — the root reader's view (nodes #93, #108) — still
    /// compares its address, so a per-SSID address rotation fires as a roam
    /// with nothing else observable. Dies under a medium inferred from
    /// `bssid`/`ssid`, which made the rule inert on the deployed daemon.
    #[test]
    fn roam_fires_on_a_root_shaped_address_hop() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, None, None, Some(MAC_A)));
        w.push(link_identity(2, None, None, Some(MAC_B)));
        let fire = Roam
            .eval(&w)
            .expect("an address hop on a measured Wi-Fi link fires without names");
        assert_eq!(
            fire.detail,
            format!("roam: link address {MAC_A} -> {MAC_B} (new DHCP identity)")
        );
    }

    /// `medium = None` is the absence of a measurement on the medium itself
    /// — #25's second obligation: the field's absence is not the medium's
    /// absence, and an address whose medium is unknown on either side is
    /// neither compared nor a comparison basis. The BSSID branch, which
    /// carries its medium in the reading itself, is unaffected.
    #[test]
    fn roam_does_not_compare_the_address_across_an_unmeasured_medium() {
        let mut w = RecentWindow::new(8);
        w.push(link_on(1, None, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office"), Some(AP_A), Some(MAC_B)));
        assert!(
            Roam.eval(&w).is_none(),
            "a predecessor of unknown medium is no basis for the address"
        );
        w.push(link_on(3, None, Some("Office"), Some(AP_A), Some(MAC_A)));
        assert!(
            Roam.eval(&w).is_none(),
            "a newest tick of unknown medium does not compare its address"
        );
        w.push(link_on(4, None, Some("Office"), Some(AP_B), Some(MAC_A)));
        let fire = Roam
            .eval(&w)
            .expect("the BSSID branch does not need the medium");
        assert_eq!(
            fire.detail,
            format!("roam: BSSID {AP_A} -> {AP_B}; link address unmeasured")
        );
    }

    /// `None` on either side is the absence of a measurement (not associated,
    /// or not determinable this tick), never one half of a change.
    #[test]
    fn roam_silent_when_either_side_is_unmeasured() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), None, None));
        w.push(link_identity(2, Some("Office"), Some(AP_A), Some(MAC_A)));
        assert!(
            Roam.eval(&w).is_none(),
            "an unmeasured predecessor is no basis"
        );
        w.push(link_identity(3, Some("Office"), None, None));
        assert!(
            Roam.eval(&w).is_none(),
            "an unmeasured newest tick is nothing to compare"
        );
    }

    /// A tick that could not read the identity sits between the two readings
    /// and is transparent: the comparison reaches back past it to the newest
    /// measured predecessor, so the roam is not lost.
    #[test]
    fn roam_reaches_back_past_an_unmeasured_tick() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office"), None, None));
        w.push(link_identity(3, Some("Office"), Some(AP_B), Some(MAC_A)));
        let fire = Roam
            .eval(&w)
            .expect("a roam straddling an unmeasured tick must still fire");
        assert!(fire.detail.contains(AP_A), "{}", fire.detail);
        assert!(fire.detail.contains(AP_B), "{}", fire.detail);
    }

    /// The condition asserts only on the tick where the identity moved: the
    /// next tick agrees with its predecessor, so the engine's clear edge can
    /// close the incident.
    #[test]
    fn roam_clears_on_the_next_unchanged_tick() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.push(link_identity(2, Some("Office"), Some(AP_B), Some(MAC_B)));
        assert!(Roam.eval(&w).is_some());
        w.push(link_identity(3, Some("Office"), Some(AP_B), Some(MAC_B)));
        assert!(Roam.eval(&w).is_none());
    }

    /// A roam during an operator pause is still a roam at resume: like
    /// `gw-change`, the comparison falls back to the basis carried across the
    /// clear, and the detail says the two readings are not consecutive ticks.
    #[test]
    fn roam_fires_across_a_resume_and_is_labelled() {
        let mut w = RecentWindow::new(8);
        w.push(link_identity(1, Some("Office"), Some(AP_A), Some(MAC_A)));
        w.clear_for_resume();
        w.push(link_identity(10, Some("Office"), Some(AP_B), Some(MAC_A)));
        let fire = Roam
            .eval(&w)
            .expect("a roam during a pause must fire at resume");
        assert!(
            fire.detail.contains("across an observation gap"),
            "a comparison across a pause must be attributable: {}",
            fire.detail
        );
    }

    /// One Wi-Fi identity reading at 15 s tick `tick` on the `Office` SSID.
    fn push_identity(w: &mut RecentWindow, tick: i64, bssid: Option<&str>, if_mac: Option<&str>) {
        w.push(link_identity(tick * TICK_US, Some("Office"), bssid, if_mac));
    }

    /// The field pattern: macOS hopping between the twin SSIDs of one access
    /// point every ~3 min. Four identity changes inside 15 min read as churn,
    /// the detail carries the per-field counts, and the condition stays
    /// asserted while the pattern is in the window (node #109). Dies under
    /// three hops counted as four, and under a per-field sum in place of a
    /// per-tick count (the tick where both moved would then be two changes).
    #[test]
    fn wifi_churn_fires_on_four_changes_in_fifteen_minutes() {
        let mut w = RecentWindow::new(WINDOW_CAP);
        // The identity held between hops, one reading per tick: a BSSID hop,
        // both moving at once, a link-address rotation alone, a BSSID hop.
        let hops = [
            (0, AP_A, MAC_A),
            (12, AP_B, MAC_A),
            (24, AP_A, MAC_B),
            (36, AP_A, MAC_A),
            (48, AP_B, MAC_A),
        ];
        let at = |tick: i64| hops.iter().rev().find(|(t, _, _)| *t <= tick).unwrap();
        for tick in 0..48 {
            let (_, ap, mac) = at(tick);
            push_identity(&mut w, tick, Some(ap), Some(mac));
        }
        assert!(WifiChurn.eval(&w).is_none(), "three hops are not churn");
        let (_, ap, mac) = at(48);
        push_identity(&mut w, 48, Some(ap), Some(mac));
        let fire = WifiChurn
            .eval(&w)
            .expect("four identity changes in 15 min must fire");
        assert_eq!(
            fire.detail,
            "wifi identity churn: 4 changes in ~540s (bssid: 3, link address: 2)"
        );
        push_identity(&mut w, 49, Some(ap), Some(mac));
        assert!(
            WifiChurn.eval(&w).is_some(),
            "the condition asserts while the pattern is in the window"
        );
    }

    /// Three changes are three roams, not churn. Dies under `>=` slack on
    /// `WIFI_CHURN_MIN_CHANGES`.
    #[test]
    fn wifi_churn_silent_on_three_changes() {
        let mut w = RecentWindow::new(WINDOW_CAP);
        for (tick, ap) in [(0, AP_A), (12, AP_B), (24, AP_A), (36, AP_B)] {
            push_identity(&mut w, tick, Some(ap), Some(MAC_A));
        }
        assert!(WifiChurn.eval(&w).is_none());
    }

    /// A tick that could not read the identity is unmeasured: it is skipped
    /// in the comparison and never counted as a change. Dies under `None`
    /// read as a value (every gap then becomes two changes).
    #[test]
    fn wifi_churn_does_not_count_unmeasured_gaps() {
        let mut w = RecentWindow::new(WINDOW_CAP);
        for tick in 0..12 {
            if tick % 2 == 0 {
                push_identity(&mut w, tick, Some(AP_A), Some(MAC_A));
            } else {
                push_identity(&mut w, tick, None, None);
            }
        }
        push_identity(&mut w, 12, Some(AP_B), Some(MAC_A));
        assert!(
            WifiChurn.eval(&w).is_none(),
            "six gaps around one identity and one hop are one change, not churn"
        );
    }

    /// A tick whose medium was measured as wired carries the wired adapter's
    /// `if_mac`, and docking and undocking must not count as identity changes.
    /// Six dock/undock cycles in a quarter hour are no churn. Dies under an
    /// `if_mac` count that ignores the medium.
    #[test]
    fn wifi_churn_ignores_wired_ticks() {
        let mut w = RecentWindow::new(WINDOW_CAP);
        for tick in 0..12 {
            if tick % 2 == 0 {
                push_identity(&mut w, tick, Some(AP_A), Some(MAC_A));
            } else {
                push_identity_wired(&mut w, tick, MAC_B);
            }
        }
        assert!(WifiChurn.eval(&w).is_none());
    }

    /// One reading at 15 s tick `tick` on a link measured as wired: no Wi-Fi
    /// identity, the wired adapter's own address as `if_mac`.
    fn push_identity_wired(w: &mut RecentWindow, tick: i64, if_mac: &str) {
        w.push(link_wired(tick * TICK_US, if_mac));
    }

    /// Four changes spread over 20 min are not the pattern: only the changes
    /// within `WIFI_CHURN_WINDOW_S` of the newest sample count, and the
    /// oldest of the four falls outside it. Dies under an unbounded horizon.
    #[test]
    fn wifi_churn_silent_when_the_changes_span_twenty_minutes() {
        let mut w = RecentWindow::new(WINDOW_CAP);
        // A hop every 27 ticks (405 s): the four hops span 1215 s, and the
        // 15 min horizon behind the newest reading holds only three.
        for (tick, ap) in [(0, AP_A), (27, AP_B), (54, AP_A), (81, AP_B), (108, AP_A)] {
            push_identity(&mut w, tick, Some(ap), Some(MAC_A));
        }
        assert!(WifiChurn.eval(&w).is_none());
    }

    /// The #57 episode replayed: macOS hopping between the twin SSIDs of one
    /// access point (different names, 5 GHz / 6 GHz) every 12 ticks — 3 min
    /// at 15 s — first with a per-SSID private address (regime A: every hop
    /// is DHCP from scratch), then with the address aligned across the twins
    /// (regime B: every hop keeps it). Each hop fires `roam` in its class,
    /// naming the SSID move, and nothing fires between hops; `wifi-churn` —
    /// the observe-only aggregate the oracle raised — fires in both regimes
    /// once four BSSID changes sit inside a quarter hour, and its detail
    /// says how the identity moved.
    #[test]
    fn twin_ssid_episode_replays_as_roams_and_churn() {
        const HOP_TICKS: i64 = 12;
        const REGIME_B_FROM: i64 = 60;
        let identity = |tick: i64| -> (&str, &str, &str) {
            let on_6g = (tick / HOP_TICKS) % 2 == 1;
            let (ssid, ap) = if on_6g {
                ("cowork-6g", AP_B)
            } else {
                ("cowork-5g", AP_A)
            };
            let mac = if tick < REGIME_B_FROM && on_6g {
                MAC_B
            } else {
                MAC_A
            };
            (ssid, ap, mac)
        };
        let mut w = RecentWindow::new(WINDOW_CAP);
        for tick in 0..=96 {
            let (ssid, ap, mac) = identity(tick);
            w.push(link_identity(
                tick * TICK_US,
                Some(ssid),
                Some(ap),
                Some(mac),
            ));
            let churn = WifiChurn.eval(&w);
            match tick {
                47 => assert!(churn.is_none(), "three hops are not churn"),
                48 => assert_eq!(
                    churn
                        .expect("the fourth hop of regime A completes the churn")
                        .detail,
                    "wifi identity churn: 4 changes in ~540s (bssid: 4, link address: 4)"
                ),
                96 => assert_eq!(
                    churn
                        .expect("regime B churns too, with the address kept")
                        .detail,
                    "wifi identity churn: 6 changes in ~900s (bssid: 6, link address: 2)"
                ),
                _ => {}
            }
            let roam = Roam.eval(&w);
            if tick == 0 || tick % HOP_TICKS != 0 {
                assert!(roam.is_none(), "tick {tick}: nothing moved");
                continue;
            }
            let (old_ssid, old_ap, old_mac) = identity(tick - 1);
            let fire = roam.unwrap_or_else(|| panic!("tick {tick}: a hop must fire roam"));
            let address = if tick < REGIME_B_FROM {
                format!("link address {old_mac} -> {mac} (new DHCP identity)")
            } else {
                "link address kept".to_string()
            };
            assert_eq!(
                fire.detail,
                format!("roam: BSSID {old_ap} -> {ap}, SSID {old_ssid} -> {ssid}; {address}"),
                "tick {tick}"
            );
        }
    }

    /// The same episode as the deployed root daemon sees it (nodes #93,
    /// #108): the SSID reads `<redacted>` and is recorded as `None`, the
    /// BSSID line is unproven and `None`, and only the measured medium says
    /// the link is Wi-Fi. Regime A's per-SSID address rotation is then the
    /// whole observable signal: every hop fires `roam` in the harmful class
    /// and `wifi-churn` counts the four address changes; regime B's aligned
    /// address leaves nothing observable, and the churn ages out. Dies under
    /// a medium inferred from readable names, which made both rules inert
    /// exactly here.
    #[test]
    fn twin_ssid_episode_as_root_replays_the_address_hops() {
        const HOP_TICKS: i64 = 12;
        const REGIME_B_FROM: i64 = 60;
        let mac_at = |tick: i64| {
            let on_6g = (tick / HOP_TICKS) % 2 == 1;
            if tick < REGIME_B_FROM && on_6g {
                MAC_B
            } else {
                MAC_A
            }
        };
        let mut w = RecentWindow::new(WINDOW_CAP);
        for tick in 0..=96 {
            let mac = mac_at(tick);
            w.push(link_identity(tick * TICK_US, None, None, Some(mac)));
            let churn = WifiChurn.eval(&w);
            match tick {
                47 => assert!(churn.is_none(), "three address hops are not churn"),
                48 => assert_eq!(
                    churn
                        .expect("the fourth address hop completes the churn")
                        .detail,
                    "wifi identity churn: 4 changes in ~540s (bssid: 0, link address: 4)"
                ),
                96 => assert!(
                    churn.is_none(),
                    "with the address aligned, the changes age out of the horizon"
                ),
                _ => {}
            }
            let roam = Roam.eval(&w);
            if tick == 0 || tick % HOP_TICKS != 0 || tick >= REGIME_B_FROM {
                assert!(
                    roam.is_none(),
                    "tick {tick}: nothing observable moved for a root reader"
                );
                continue;
            }
            let fire = roam.unwrap_or_else(|| panic!("tick {tick}: an address hop must fire"));
            assert_eq!(
                fire.detail,
                format!(
                    "roam: link address {} -> {mac} (new DHCP identity)",
                    mac_at(tick - 1)
                ),
                "tick {tick}"
            );
        }
    }

    #[test]
    fn neighbor_mac_collision_fires_on_two_macs_for_one_ip() {
        let mut w = RecentWindow::new(8);
        w.push(neighbors(
            1,
            NeighborsVerdict::Ok,
            vec![
                nobs("192.168.1.50", "aa:aa:aa:aa:aa:aa"),
                nobs("192.168.1.50", "bb:bb:bb:bb:bb:bb"),
                nobs("192.168.1.51", "cc:cc:cc:cc:cc:cc"),
            ],
        ));
        let fire = NeighborMacCollision
            .eval(&w)
            .expect("two MACs claiming the same IP must fire");
        assert!(fire.detail.contains("192.168.1.50"));
        assert!(fire.detail.contains("aa:aa:aa:aa:aa:aa"));
        assert!(fire.detail.contains("bb:bb:bb:bb:bb:bb"));
    }

    /// Two collisions in one reading are two facts. Reporting whichever the
    /// hash order happened to yield made the incident text differ between runs
    /// on identical data and dropped the second collision entirely — neither is
    /// acceptable in a record meant to be produced as evidence.
    #[test]
    fn neighbor_mac_collision_reports_every_collision_in_ip_order() {
        let mut w = RecentWindow::new(8);
        w.push(neighbors(
            1,
            NeighborsVerdict::Ok,
            vec![
                nobs("192.168.1.51", "cc:cc:cc:cc:cc:cc"),
                nobs("192.168.1.51", "dd:dd:dd:dd:dd:dd"),
                nobs("192.168.1.50", "aa:aa:aa:aa:aa:aa"),
                nobs("192.168.1.50", "bb:bb:bb:bb:bb:bb"),
            ],
        ));
        let fire = NeighborMacCollision.eval(&w).expect("both must fire");
        assert_eq!(
            fire.detail,
            "ip 192.168.1.50 claimed by aa:aa:aa:aa:aa:aa, bb:bb:bb:bb:bb:bb; \
ip 192.168.1.51 claimed by cc:cc:cc:cc:cc:cc, dd:dd:dd:dd:dd:dd"
        );
    }

    #[test]
    fn neighbor_mac_collision_silent_when_every_ip_has_one_mac() {
        let mut w = RecentWindow::new(8);
        w.push(neighbors(
            1,
            NeighborsVerdict::Ok,
            vec![
                nobs("192.168.1.50", "aa:aa:aa:aa:aa:aa"),
                nobs("192.168.1.51", "cc:cc:cc:cc:cc:cc"),
            ],
        ));
        assert!(NeighborMacCollision.eval(&w).is_none());
    }

    /// A `SKIP` reading (the sweep could not run) carries no observations, so it
    /// must not be scanned for a collision that was never measured.
    #[test]
    fn neighbor_mac_collision_silent_on_a_skip_reading() {
        let mut w = RecentWindow::new(8);
        w.push(neighbors(
            1,
            NeighborsVerdict::Skip,
            vec![
                nobs("192.168.1.50", "aa:aa:aa:aa:aa:aa"),
                nobs("192.168.1.50", "bb:bb:bb:bb:bb:bb"),
            ],
        ));
        assert!(NeighborMacCollision.eval(&w).is_none());
    }

    #[test]
    fn neighbor_mac_collision_silent_with_no_neighbors_sample_yet() {
        let w = RecentWindow::new(8);
        assert!(NeighborMacCollision.eval(&w).is_none());
    }

    /// Push one all-`Fail` two-endpoint cohort at `ts` — the fleet-wide-block
    /// tick shape as `endpoint-block` reads it.
    fn push_dead_cohort(w: &mut RecentWindow, ts: i64) {
        w.push(proxy_ep(ts, "1.1.1.1:443", TcpVerdict::Fail));
        w.push(proxy_ep(ts, "2.2.2.2:2053", TcpVerdict::Fail));
    }

    /// The first row of the next tick — the end marker of the cohort before
    /// it. Its own verdict is irrelevant to the judgement, and a healthy row
    /// is used so a fire cannot be read as coming from this row.
    fn push_end_marker(w: &mut RecentWindow, ts: i64) {
        w.push(proxy_ep(ts, "1.1.1.1:443", TcpVerdict::Ok));
    }

    /// The measured 2026-09-08 signature: every endpoint dead from the underlay
    /// for `consecutive` ticks while the reference host answers. The mid-way
    /// assertion dies under counting ROWS instead of cohorts — one tick's two
    /// rows would already read as two "ticks".
    #[test]
    fn endpoint_block_fires_when_every_endpoint_fails_while_direct_answers() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        assert!(
            c.eval(&w).is_none(),
            "one cohort of two rows must not count as two ticks"
        );
        push_dead_cohort(&mut w, 20);
        push_end_marker(&mut w, 30);
        let fire = c
            .eval(&w)
            .expect("two ended all-fail cohorts with direct OK must fire");
        assert!(
            fire.detail.contains("all 2 endpoints"),
            "the detail must carry the newest judged cohort size: {}",
            fire.detail
        );
        assert!(
            fire.detail.contains("2 ticks"),
            "the detail must carry the run length: {}",
            fire.detail
        );
    }

    /// The engine evaluates on every row, so the newest cohort is always
    /// still being written: it is never judged, it is the end marker of the
    /// cohort before it. Two all-`Fail` cohorts alone are one judged cohort;
    /// the first row of a third — whatever its verdict — ends the second and
    /// fires. Dies under judging the newest cohort by any completeness
    /// guess. (node #73)
    #[test]
    fn endpoint_block_judges_only_cohorts_with_a_successor() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        push_dead_cohort(&mut w, 20);
        assert!(
            c.eval(&w).is_none(),
            "the newest cohort is unfinished: two cohorts alone are one judged"
        );
        w.push(proxy_ep(30, "1.1.1.1:443", TcpVerdict::Ok));
        assert!(
            c.eval(&w).is_some(),
            "the first row of a third cohort ends the second, whatever its verdict"
        );
    }

    /// The review's fleet-growth probe: the fleet grows from two to three
    /// endpoints during a block and the new cohort arrives `Fail, Fail, Ok`.
    /// Its first two rows look like a complete two-endpoint all-`Fail` cohort;
    /// a row-count completeness guess fired there and closed one row later —
    /// a false incident. Judging only ended cohorts never fires here: the
    /// cohort has an `Ok` once it is ended.
    #[test]
    fn endpoint_block_silent_when_the_fleet_grows_into_a_partial_block() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        w.push(proxy_ep(20, "1.1.1.1:443", TcpVerdict::Fail));
        assert!(c.eval(&w).is_none());
        w.push(proxy_ep(20, "2.2.2.2:2053", TcpVerdict::Fail));
        assert!(
            c.eval(&w).is_none(),
            "two rows matching the previous cohort's size is not a finished cohort"
        );
        w.push(proxy_ep(20, "3.3.3.3:443", TcpVerdict::Ok));
        assert!(c.eval(&w).is_none());
        push_end_marker(&mut w, 30);
        assert!(
            c.eval(&w).is_none(),
            "ended, the grown cohort holds an Ok and is not a block"
        );
    }

    /// The other half of fleet growth: the fleet grows from two to three
    /// endpoints and STAYS fully blocked. Once the three-row cohorts are ended
    /// the run fires, and the detail names the grown fleet — three endpoints,
    /// read from the newest judged cohort, not the older two-row ones.
    #[test]
    fn endpoint_block_fires_on_a_grown_fleet_that_stays_blocked() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        push_dead_cohort(&mut w, 20);
        for ts in [30, 40] {
            push_dead_cohort(&mut w, ts);
            w.push(proxy_ep(ts, "3.3.3.3:443", TcpVerdict::Fail));
        }
        push_end_marker(&mut w, 50);
        let fire = c
            .eval(&w)
            .expect("two ended all-fail three-row cohorts must fire");
        assert!(
            fire.detail.contains("all 3 endpoints"),
            "the detail must name the grown fleet: {}",
            fire.detail
        );
    }

    /// One endpoint still answering means the fleet is not blocked as a whole.
    /// Dies under `any(Fail)` in place of `all(Fail)` within a cohort.
    #[test]
    fn endpoint_block_silent_when_one_endpoint_still_answers() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        w.push(proxy_ep(20, "1.1.1.1:443", TcpVerdict::Fail));
        w.push(proxy_ep(20, "2.2.2.2:2053", TcpVerdict::Ok));
        push_end_marker(&mut w, 30);
        assert!(c.eval(&w).is_none());
    }

    /// The `-` skip row means no endpoints were parsed — the absence of a
    /// measurement, not a dead fleet. Dies under a non-exhaustive
    /// `tcp != TcpVerdict::Ok` check that lets `Skip` count as a failure.
    #[test]
    fn endpoint_block_silent_on_skip_cohorts() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        w.push(proxy_ep(10, "-", TcpVerdict::Skip));
        w.push(proxy_ep(20, "-", TcpVerdict::Skip));
        push_end_marker(&mut w, 30);
        assert!(c.eval(&w).is_none());
    }

    /// A skip placeholder is a row like any other as an END MARKER (the fire
    /// lands on it), and the absence of a measurement once it is itself
    /// judged: the cohort after it finds a broken run.
    #[test]
    fn endpoint_block_skip_placeholder_ends_a_run_and_then_breaks_it() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        push_dead_cohort(&mut w, 20);
        w.push(proxy_ep(30, "-", TcpVerdict::Skip));
        assert!(
            c.eval(&w).is_some(),
            "the skip row ends the second dead cohort like any other row"
        );
        push_end_marker(&mut w, 40);
        assert!(
            c.eval(&w).is_none(),
            "judged, the skip cohort is the absence of a measurement and breaks the run"
        );
    }

    /// With the reference host dead too there is nothing SELECTIVE about the
    /// endpoints failing — that is a whole-network outage, `gw-drop` territory.
    #[test]
    fn endpoint_block_silent_when_direct_is_down_too() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Fail));
        push_dead_cohort(&mut w, 10);
        push_dead_cohort(&mut w, 20);
        push_end_marker(&mut w, 30);
        assert!(c.eval(&w).is_none());
    }

    /// Dies under an off-by-one in the cohort count (`<` -> `<=`, or a scan
    /// that seeds a phantom empty cohort).
    #[test]
    fn endpoint_block_silent_one_cohort_short() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        push_end_marker(&mut w, 20);
        assert!(c.eval(&w).is_none());
    }
    /// A link sample pinning what `PerClientBlock` reads: the gateway verdict
    /// and the probe-on-suspicion counts (direct Ok, everything else absent).
    fn link_lan(ts: i64, gw: GwVerdict, probed: Option<u16>, alive: Option<u16>) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            wifi_capture_present: false,
            lan_probed: probed,
            lan_alive: alive,
            fakeip_route_if: None,
            singbox_tun_if: None,
        })
    }

    /// The measured 2026-09-08 16:44:52 signature: the gateway silent while
    /// probed neighbors answer.
    #[test]
    fn per_client_block_fires_when_neighbors_answer_a_silent_gateway() {
        let mut w = RecentWindow::new(8);
        w.push(link_lan(1, GwVerdict::Fail, Some(3), Some(2)));
        let fire = PerClientBlock
            .eval(&w)
            .expect("a silent gateway with live neighbors must fire");
        assert!(
            fire.detail.contains("2/3"),
            "the detail must carry the alive/probed counts: {}",
            fire.detail
        );
    }

    /// Nobody on the segment answering is the whole segment dead — `gw-drop`
    /// territory, not a selective ban. Dies under `alive >= 0`-style slack.
    #[test]
    fn per_client_block_silent_when_no_neighbor_answers() {
        let mut w = RecentWindow::new(8);
        w.push(link_lan(1, GwVerdict::Fail, Some(3), Some(0)));
        assert!(PerClientBlock.eval(&w).is_none());
    }

    /// `None` counts mean the tick did not probe (a pre-field daemon's replay,
    /// or a probe that could not run): absence of a measurement must not fire.
    #[test]
    fn per_client_block_silent_when_the_tick_did_not_probe() {
        let mut w = RecentWindow::new(8);
        w.push(link_lan(1, GwVerdict::Fail, None, None));
        assert!(PerClientBlock.eval(&w).is_none());
        // Probed nothing (empty ARP cache) is equally not a ban signature.
        w.push(link_lan(2, GwVerdict::Fail, Some(0), Some(0)));
        assert!(PerClientBlock.eval(&w).is_none());
    }

    /// The signature is anchored to a FAILED gateway echo: a healthy or
    /// quiet/absent gateway must stay silent even if counts are present.
    #[test]
    fn per_client_block_silent_unless_the_gateway_failed() {
        let mut w = RecentWindow::new(8);
        for gw in [GwVerdict::Ok, GwVerdict::Skip, GwVerdict::NoGw] {
            w.push(link_lan(1, gw, Some(3), Some(2)));
            assert!(
                PerClientBlock.eval(&w).is_none(),
                "gateway {gw} must not fire per-client-block"
            );
        }
    }

    /// A link sample pinning what `FakeIpHijack` reads: the egress interface the
    /// route table resolved for the fakeip-pool probe address (`route_if`) and
    /// the interface carrying sing-box's own TUN address (`tun_if`, `None` =
    /// sing-box down) — both on one tick, as the daemon records them. Gateway
    /// and direct are healthy, everything else absent.
    fn link_fakeip(ts: i64, route_if: Option<&str>, tun_if: Option<&str>) -> Sample {
        Sample::Link(LinkSample {
            ts_us: ts,
            gw: GwVerdict::Ok,
            gw_rtt_ms: None,
            direct: TcpVerdict::Ok,
            direct_rtt_ms: None,
            dhcp_router: None,
            dhcp_dns: None,
            gw_arp_mac: None,
            ssid: None,
            bssid: None,
            if_mac: None,
            medium: None,
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: route_if.map(str::to_string),
            singbox_tun_if: tun_if.map(str::to_string),
        })
    }

    /// The AWDL-collision signature: the pool routes out a real interface while
    /// sing-box's own TUN is up — a genuine leak, not an outage.
    #[test]
    fn fakeip_hijack_fires_when_the_pool_leaks_while_singbox_is_up() {
        let mut w = RecentWindow::new(8);
        w.push(link_fakeip(1, Some("awdl0"), Some("utun6")));
        let fire = FakeIpHijack
            .eval(&w)
            .expect("a pool leak while sing-box's TUN is up must fire");
        assert!(
            fire.detail.contains("awdl0"),
            "the detail must name the hijacking interface: {}",
            fire.detail
        );
    }

    /// The pool routing into the tunnel is the healthy state, whatever the
    /// utun's number is.
    #[test]
    fn fakeip_hijack_silent_on_a_tunnel_interface() {
        let mut w = RecentWindow::new(8);
        w.push(link_fakeip(1, Some("utun8"), Some("utun6")));
        assert!(FakeIpHijack.eval(&w).is_none());
    }

    /// A pool address on loopback is a blackhole/reject or kill-switch drop —
    /// the packet is discarded, the opposite of leaking out a real egress — so
    /// it must not fire even with sing-box up. Dies under the old
    /// `!starts_with("utun")` test, which flagged `lo0` as a hijack.
    #[test]
    fn fakeip_hijack_silent_on_a_loopback_route() {
        let mut w = RecentWindow::new(8);
        w.push(link_fakeip(1, Some("lo0"), Some("utun6")));
        assert!(FakeIpHijack.eval(&w).is_none());
    }

    /// When sing-box is down its TUN interface is absent, so a pool address on a
    /// real interface is just the outage's route fall-through, not a hijack.
    #[test]
    fn fakeip_hijack_silent_when_singbox_is_down() {
        let mut w = RecentWindow::new(8);
        // sing-box down: its TUN address is on no interface; the pool falls
        // through to the physical route.
        w.push(link_fakeip(1, Some("en0"), None));
        assert!(
            FakeIpHijack.eval(&w).is_none(),
            "a route fall-through while sing-box's TUN is down is not a hijack"
        );
    }

    /// THE round-3 trap: sing-box is DOWN but a FOREIGN VPN utun (tailscale /
    /// netbird) owns the default route, and the pool has a leftover route via
    /// awdl0. `singbox_tun_if` is `None` because the foreign utun does not carry
    /// sing-box's own TUN address, so this must stay silent. Dies under any
    /// "some utun owns the default" gate (which would fire on the foreign utun).
    #[test]
    fn fakeip_hijack_silent_when_only_a_foreign_utun_is_up() {
        let mut w = RecentWindow::new(8);
        // The foreign utun never surfaces as `singbox_tun_if`; the sample the
        // daemon would record for this state has it `None`.
        w.push(link_fakeip(1, Some("awdl0"), None));
        assert!(
            FakeIpHijack.eval(&w).is_none(),
            "a foreign VPN utun owning the default while sing-box is down is not a hijack"
        );
    }

    /// `None` pool route = it could not be determined (no config, no range, no
    /// route): the absence of a measurement must not read as a hijack.
    #[test]
    fn fakeip_hijack_silent_when_the_pool_route_is_unknown() {
        let mut w = RecentWindow::new(8);
        w.push(link_fakeip(1, None, Some("utun6")));
        assert!(FakeIpHijack.eval(&w).is_none());
    }

    /// A proxy row pinning what `EstablishedStall` reads: the fresh tun probe
    /// code and the two held-stream `(alive, age_s)` readings (`None` = no
    /// measurement). Underlay TCP is Ok, endpoint fixed.
    fn proxy_est(
        ts: i64,
        tun_code: Option<u16>,
        est_tun: Option<(bool, u32)>,
        est_direct: Option<(bool, u32)>,
    ) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us: ts,
            server_ip: "1.1.1.1:443".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code,
            selector: None,
            est_direct_alive: est_direct.map(|(alive, _)| alive),
            est_direct_age_s: est_direct.map(|(_, age)| age),
            est_tun_alive: est_tun.map(|(alive, _)| alive),
            est_tun_age_s: est_tun.map(|(_, age)| age),
        })
    }

    /// The 2026-09-08 signature: the established proxied stream stalls while a
    /// fresh connection succeeds — and the surviving direct stream scopes the
    /// fault to the proxied path.
    #[test]
    fn established_stall_scopes_to_the_endpoint_when_the_direct_stream_survives() {
        let mut w = RecentWindow::new(8);
        w.push(proxy_est(
            1,
            Some(204),
            Some((false, 45)),
            Some((true, 120)),
        ));
        let fire = EstablishedStall
            .eval(&w)
            .expect("a stalled tunnel stream with fresh OK must fire");
        assert!(
            fire.detail.contains("endpoint/protocol-scoped"),
            "a surviving direct stream must scope the verdict: {}",
            fire.detail
        );
        assert!(
            fire.detail.contains("~45s"),
            "the detail must carry the age at death: {}",
            fire.detail
        );
    }

    /// A direct stream that survived but is YOUNGER than the stalled tunnel
    /// stream may have reconnected through the very same underlay hiccup, so it
    /// does not exonerate the underlay — the verdict is ambiguous, not
    /// endpoint-scoped. Dies under the un-gated `Some(true) =>
    /// endpoint/protocol-scoped` that ignored the ages.
    #[test]
    fn established_stall_is_ambiguous_when_the_direct_stream_is_young() {
        let mut w = RecentWindow::new(8);
        w.push(proxy_est(
            1,
            Some(204),
            Some((false, 300)),
            Some((true, 20)),
        ));
        let fire = EstablishedStall
            .eval(&w)
            .expect("a stalled tunnel with fresh OK still fires");
        assert!(
            fire.detail.contains("underlay-ambiguous"),
            "a young direct stream must not be read as exonerating the underlay: {}",
            fire.detail
        );
        assert!(
            !fire.detail.contains("endpoint/protocol-scoped"),
            "a young direct stream must not scope the fault to the endpoint: {}",
            fire.detail
        );
    }

    /// Both established streams dying on the same tick is the underlay's
    /// treatment of long flows, and the detail must say the proxy is not the
    /// scope. Dies under reading only the tunnel side.
    #[test]
    fn established_stall_scopes_to_the_underlay_when_both_streams_die() {
        let mut w = RecentWindow::new(8);
        w.push(proxy_est(
            1,
            Some(204),
            Some((false, 45)),
            Some((false, 50)),
        ));
        let fire = EstablishedStall
            .eval(&w)
            .expect("both dead must still fire");
        assert!(
            fire.detail
                .contains("underlay (NAT/radio), not proxy-scoped"),
            "both streams dying must scope the verdict to the underlay: {}",
            fire.detail
        );
    }

    /// Healthy held streams are the quiet case, and the None it returns is
    /// also what re-arms the engine after a real firing.
    #[test]
    fn established_stall_silent_while_the_tunnel_stream_carries() {
        let mut w = RecentWindow::new(8);
        w.push(proxy_est(
            1,
            Some(204),
            Some((true, 300)),
            Some((true, 300)),
        ));
        assert!(EstablishedStall.eval(&w).is_none());
    }

    /// With the fresh tun probe dead too this is a plain outage (`wedge`
    /// territory), not a stall of established flows.
    #[test]
    fn established_stall_silent_when_the_fresh_probe_is_dead_too() {
        let mut w = RecentWindow::new(8);
        w.push(proxy_est(1, Some(0), Some((false, 45)), Some((true, 120))));
        assert!(EstablishedStall.eval(&w).is_none());
        w.push(proxy_est(2, None, Some((false, 60)), Some((true, 135))));
        assert!(EstablishedStall.eval(&w).is_none());
    }

    /// `None` on the tunnel side is the absence of a measurement — the stream
    /// was only just (re-)opened or could not be opened — never a stall.
    #[test]
    fn established_stall_silent_without_a_tunnel_measurement() {
        let mut w = RecentWindow::new(8);
        w.push(proxy_est(1, Some(204), None, Some((true, 120))));
        assert!(EstablishedStall.eval(&w).is_none());
    }

    /// Proxy history does not survive a resume (only the link change basis is
    /// carried), so a pre-pause cohort must not combine with a post-resume one
    /// into a continuity that never existed. Fresh, the run needs
    /// `consecutive + 1` cohorts: `consecutive` to judge and one to end them.
    /// The inline control — the third fresh cohort's first row fires — proves
    /// the silence measures the clear and not a fixture that could never fire.
    #[test]
    fn endpoint_block_waits_for_fresh_cohorts_after_a_resume() {
        let mut w = RecentWindow::new(16);
        let c = EndpointBlock { consecutive: 2 };
        w.push(link(1, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 10);
        w.clear_for_resume();
        w.push(link(100, TcpVerdict::Ok));
        push_dead_cohort(&mut w, 110);
        assert!(
            c.eval(&w).is_none(),
            "one fresh cohort must not complete a pre-pause run"
        );
        push_dead_cohort(&mut w, 120);
        assert!(
            c.eval(&w).is_none(),
            "two fresh cohorts are one judged and one end marker, not a run"
        );
        push_end_marker(&mut w, 130);
        assert!(
            c.eval(&w).is_some(),
            "consecutive + 1 fresh cohorts complete the run on their own"
        );
    }

    /// The link collector's cadence, in microseconds.
    const TICK_US: i64 = 15_000_000;

    /// Push one gateway reading per verdict at 15-second ticks starting at
    /// tick `from` (direct Ok, everything else absent — [`link_gw`]); returns
    /// the next free tick.
    fn push_gw_ticks(w: &mut RecentWindow, from: i64, verdicts: &[GwVerdict]) -> i64 {
        for (i, gw) in verdicts.iter().enumerate() {
            w.push(link_gw((from + i as i64) * TICK_US, *gw));
        }
        from + verdicts.len() as i64
    }

    /// One coworking ban round: admitted for two ticks, blocked for three,
    /// admitted for five — a 150 s period with the ban starting at tick 2.
    const BAN_ROUND: [GwVerdict; 10] = [
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::Fail,
        GwVerdict::Fail,
        GwVerdict::Fail,
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::Ok,
    ];

    /// The coworking signature: three ban rounds 150 s apart read as ONE
    /// incident carrying the count, the span and the period — the whole
    /// detail is pinned because it is what the reader gets.
    #[test]
    fn ban_cycle_fires_on_three_bans_with_a_period() {
        let mut w = RecentWindow::new(64);
        let c = BanCycle { min_bans: 3 };
        let mut next = 0;
        for _ in 0..3 {
            next = push_gw_ticks(&mut w, next, &BAN_ROUND);
        }
        let fire = c.eval(&w).expect("three bans in the window must fire");
        assert_eq!(
            fire.detail,
            "gateway ban cycle: 3 bans in ~300s, period ~150s (min 150s, max 150s)"
        );
    }

    /// The newest ban may still be in progress (the client is blocked right
    /// now): with `BAN_MIN_RUN_TICKS` dead readings and an `Ok` before it, it
    /// is a ban start.
    #[test]
    fn ban_cycle_counts_the_open_newest_ban() {
        let mut w = RecentWindow::new(64);
        let c = BanCycle { min_bans: 3 };
        let mut next = 0;
        for _ in 0..2 {
            next = push_gw_ticks(&mut w, next, &BAN_ROUND);
        }
        push_gw_ticks(
            &mut w,
            next,
            &[
                GwVerdict::Ok,
                GwVerdict::Ok,
                GwVerdict::Fail,
                GwVerdict::Fail,
            ],
        );
        let fire = c
            .eval(&w)
            .expect("an open newest ban still counts as a ban start");
        assert!(
            fire.detail.starts_with("gateway ban cycle: 3 bans"),
            "the open ban must be counted: {}",
            fire.detail
        );
    }

    /// Two bans are two outages, not a cycle. Dies under `>=` slack on
    /// `min_bans`.
    #[test]
    fn ban_cycle_silent_on_two_bans() {
        let mut w = RecentWindow::new(64);
        let c = BanCycle { min_bans: 3 };
        let mut next = 0;
        for _ in 0..2 {
            next = push_gw_ticks(&mut w, next, &BAN_ROUND);
        }
        assert!(c.eval(&w).is_none());
    }

    /// Quiet-mode `Skip` ticks are the absence of a measurement (node #25):
    /// one inside a run does not split the ban, two between `Ok`s do not
    /// start one. Dies under `Skip` read as `Ok` (each `Fail` is then a lone
    /// tick below the run bound: no ban at all) and under `Skip` read as
    /// `Fail` (the between-`Ok` pair becomes a second ban per round: six).
    #[test]
    fn ban_cycle_skip_neither_splits_nor_starts_a_ban() {
        let mut w = RecentWindow::new(64);
        let c = BanCycle { min_bans: 3 };
        let round = [
            GwVerdict::Ok,
            GwVerdict::Skip,
            GwVerdict::Fail,
            GwVerdict::Skip,
            GwVerdict::Fail,
            GwVerdict::Ok,
            GwVerdict::Skip,
            GwVerdict::Skip,
            GwVerdict::Ok,
            GwVerdict::Ok,
        ];
        let mut next = 0;
        for _ in 0..3 {
            next = push_gw_ticks(&mut w, next, &round);
        }
        let fire = c.eval(&w).expect("three bans around skips must fire");
        assert_eq!(
            fire.detail,
            "gateway ban cycle: 3 bans in ~300s, period ~150s (min 150s, max 150s)"
        );
    }

    /// One ban round shaped like the field episode: at the roam the default
    /// gateway is momentarily absent (`NoGw`) before the echoes start failing,
    /// and quiet mode drops one reading inside the run. Same period and ban
    /// start as [`BAN_ROUND`].
    const FIELD_ROUND: [GwVerdict; 10] = [
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::NoGw,
        GwVerdict::Fail,
        GwVerdict::Skip,
        GwVerdict::Fail,
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::Ok,
        GwVerdict::Ok,
    ];

    /// `NoGw` is a dead reading like `Fail` — one run class, the fold the
    /// CLI's `gw_drops()` uses — so a `NoGw` tick at the roam is the start of
    /// the ban, not a wall that hides it. Dies under `NoGw => break`, which
    /// read every field round as no ban at all.
    #[test]
    fn ban_cycle_counts_a_no_gateway_tick_as_dead() {
        let c = BanCycle { min_bans: 3 };
        let mut w = RecentWindow::new(64);
        let mut next = 0;
        for _ in 0..3 {
            next = push_gw_ticks(&mut w, next, &FIELD_ROUND);
        }
        let fire = c
            .eval(&w)
            .expect("three field-shaped rounds with NoGw at the roam must fire");
        assert_eq!(
            fire.detail,
            "gateway ban cycle: 3 bans in ~300s, period ~150s (min 150s, max 150s)"
        );
    }

    /// A run of `NoGw` alone is no route — the interface was down, or the
    /// roam was still in progress — not a gateway that answered and then
    /// went silent toward this client. Three Wi-Fi toggles must not read as
    /// a ban cycle: a run is a ban only if it holds a `Fail`. Dies under the
    /// one-run-class fold that counted `NoGw`-only runs (node #97).
    #[test]
    fn ban_cycle_ignores_runs_of_no_gateway_alone() {
        let c = BanCycle { min_bans: 3 };
        let mut w = RecentWindow::new(64);
        let round = [
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::NoGw,
            GwVerdict::NoGw,
            GwVerdict::NoGw,
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Ok,
            GwVerdict::Ok,
        ];
        let mut next = 0;
        for _ in 0..3 {
            next = push_gw_ticks(&mut w, next, &round);
        }
        assert!(c.eval(&w).is_none());
    }

    /// Wi-Fi jitter loses single echoes: a one-tick `Fail` or `NoGw` between
    /// two `Ok`s is not a ban, however many of them the window holds. Dies
    /// under no lower bound on the run length ("3 bans in ~120s, period ~60s").
    #[test]
    fn ban_cycle_ignores_single_tick_echo_losses() {
        let c = BanCycle { min_bans: 3 };
        let mut w = RecentWindow::new(64);
        let mut next = 0;
        for lost in [GwVerdict::Fail, GwVerdict::NoGw, GwVerdict::Fail] {
            next = push_gw_ticks(
                &mut w,
                next,
                &[GwVerdict::Ok, GwVerdict::Ok, lost, GwVerdict::Ok],
            );
        }
        assert!(c.eval(&w).is_none());
    }

    /// A cycle shorter than a minute is not the field pattern: three two-tick
    /// bans 45 s apart stay silent, and the same bans 60 s apart fire — the
    /// bound is on the mean period, inclusive.
    #[test]
    fn ban_cycle_silent_below_the_minimum_period() {
        let c = BanCycle { min_bans: 3 };
        let stream = |round: &[GwVerdict]| {
            let mut w = RecentWindow::new(64);
            let mut next = 0;
            for _ in 0..3 {
                next = push_gw_ticks(&mut w, next, round);
            }
            w
        };
        assert!(
            c.eval(&stream(&[GwVerdict::Ok, GwVerdict::Fail, GwVerdict::Fail]))
                .is_none(),
            "a 45 s period is below BAN_MIN_PERIOD_S"
        );
        let fire = c
            .eval(&stream(&[
                GwVerdict::Ok,
                GwVerdict::Fail,
                GwVerdict::Fail,
                GwVerdict::Ok,
            ]))
            .expect("a 60 s period is the bound itself and fires");
        assert!(
            fire.detail.contains("period ~60s"),
            "the detail must carry the period: {}",
            fire.detail
        );
    }

    /// One long ban is one ban: a continuous `Fail` run has one start, however
    /// long it lasts. And a run the window cut off — no `Ok` older than it —
    /// has no known start and is not counted at all.
    #[test]
    fn ban_cycle_silent_on_one_continuous_ban() {
        let c = BanCycle { min_bans: 3 };
        let mut w = RecentWindow::new(64);
        push_gw_ticks(&mut w, 0, &[GwVerdict::Ok]);
        push_gw_ticks(&mut w, 1, &[GwVerdict::Fail; 30]);
        assert!(c.eval(&w).is_none(), "one long ban is one ban");

        let mut w = RecentWindow::new(64);
        push_gw_ticks(&mut w, 0, &[GwVerdict::Fail; 30]);
        assert!(
            c.eval(&w).is_none(),
            "a run with no Ok older than it has no known start"
        );
    }

    /// A run cut off by the window edge is not a ban start, so with two whole
    /// bans in front of it the count is two, not three. Dies under counting a
    /// run that never met its `Ok`.
    #[test]
    fn ban_cycle_ignores_a_run_cut_by_the_window_edge() {
        let c = BanCycle { min_bans: 3 };
        let mut w = RecentWindow::new(64);
        let next = push_gw_ticks(&mut w, 0, &[GwVerdict::Fail, GwVerdict::Fail]);
        let next = push_gw_ticks(&mut w, next, &BAN_ROUND);
        push_gw_ticks(&mut w, next, &BAN_ROUND);
        assert!(c.eval(&w).is_none());
    }

    /// Push one daemon tick's realistic sample mix at tick `tick`: the link
    /// reading plus seven endpoint rows, three DNS rows and a host row — what
    /// the engine window actually fills up with between two link readings
    /// (no wifi helper exists here, so four of the five kinds).
    fn push_field_tick(w: &mut RecentWindow, tick: i64, gw: GwVerdict) {
        let ts = tick * TICK_US;
        w.push(link_gw(ts, gw));
        for ep in [
            "1.1.1.1:443",
            "2.2.2.2:2053",
            "3.3.3.3:443",
            "4.4.4.4:443",
            "5.5.5.5:443",
            "6.6.6.6:443",
            "7.7.7.7:443",
        ] {
            w.push(proxy_ep(ts + 1, ep, TcpVerdict::Ok));
        }
        for probe in ["ru", "nks", "doh"] {
            w.push(dns(ts + 2, probe, DnsVerdict::Ok, Some("10.0.0.1")));
        }
        w.push(host(ts + 3, 1.0));
    }

    /// The window is shared by every sample kind, so its capacity — not
    /// `BAN_CYCLE_SCAN` — bounds how far back `ban-cycle` can see. At the
    /// daemon's `WINDOW_CAP` three field rounds 150 s apart are all in view
    /// and fire; at the 64 the daemon used to hold, the same stream keeps only
    /// the last few ticks and the signature can never fire — the review's red
    /// state.
    #[test]
    fn ban_cycle_needs_the_engine_window_to_hold_three_field_rounds() {
        let c = BanCycle { min_bans: 3 };
        let fill = |cap: usize| {
            let mut w = RecentWindow::new(cap);
            for round in 0..3 {
                for (i, gw) in BAN_ROUND.iter().copied().enumerate() {
                    push_field_tick(&mut w, round * 10 + i as i64, gw);
                }
            }
            w
        };
        assert!(
            c.eval(&fill(WINDOW_CAP)).is_some(),
            "the engine window must hold three field rounds of the daemon's per-tick mix"
        );
        assert!(
            c.eval(&fill(64)).is_none(),
            "a 64-sample window holds a handful of ticks and cannot see a cycle"
        );
    }
}
