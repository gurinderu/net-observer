use std::collections::BTreeMap;

use crate::window::{LinkProvenance, RecentWindow};
use types::{DnsVerdict, GwVerdict, LinkSample, NeighborsVerdict, TcpVerdict};

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

/// Fires when the last `consecutive` link samples all have `direct == Ok` while the
/// last `consecutive` proxy tun_codes are `0`/`None` (tun dead but direct path healthy).
pub struct Wedge {
    pub consecutive: usize,
}
impl Condition for Wedge {
    fn id(&self) -> &'static str {
        "wedge"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let links = w.recent_link(self.consecutive);
        let proxies = w.recent_proxy(self.consecutive);
        if links.len() < self.consecutive || proxies.len() < self.consecutive {
            return None;
        }
        let direct_ok = links.iter().all(|l| l.direct == TcpVerdict::Ok);
        let tun_dead = proxies.iter().all(|p| p.tun_code.unwrap_or(0) == 0);
        (direct_ok && tun_dead).then(|| Fire {
            detail: format!("tun dead {} ticks, direct OK", self.consecutive),
        })
    }
}

/// How far back `gw-change` looks for a comparable (non-`SKIP`) predecessor when
/// the operator's quiet mode has suppressed the echo for a run of ticks.
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
        // change: `OK -> SKIP` is the operator flipping quiet on, not the gateway
        // moving, and firing on it would manufacture an incident out of a
        // control-socket click.
        if last.gw == GwVerdict::Skip {
            return None;
        }
        // Reach back past a quiet run for the newest predecessor that actually
        // measured something. Without this the change that quiet mode straddled
        // (`OK` -> quiet -> `FAIL`) would be suppressed once and then never seen
        // again — silence, exactly what the SKIP token exists to prevent.
        let recent = w.recent_link(GW_CHANGE_SCAN);
        let quiet_run = recent
            .iter()
            .skip(1)
            .take_while(|l| l.gw == GwVerdict::Skip)
            .count();
        let (prev, provenance) = match recent.iter().skip(1).find(|l| l.gw != GwVerdict::Skip) {
            Some(prev) => (*prev, LinkProvenance::Contiguous),
            // Nothing comparable in the window: fall back to the basis carried
            // across a pause, which must itself be a measurement.
            None => match w.prev_link_with_provenance()? {
                (prev, _) if prev.gw == GwVerdict::Skip => return None,
                (prev, provenance) => (prev, provenance),
            },
        };
        // A change measured against the basis carried across a pause is real —
        // the oracle freezes on ANY gateway change — but it is not two
        // consecutive ticks, and the incident must not read as though it were.
        // A change straddling a quiet run is real for the same reason, and is
        // labelled for the same reason.
        let across = match (provenance, quiet_run) {
            (LinkProvenance::AcrossGap, _) => " (across an observation gap)".to_string(),
            (LinkProvenance::Contiguous, 0) => String::new(),
            (LinkProvenance::Contiguous, n) => format!(" (across {n} quiet tick(s))"),
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
/// A predecessor is comparable only if it carries both the router IP and the
/// MAC: an empty ARP cache is common for a tick or two right after a link flap,
/// which is exactly when the MAC changes, so the scan reaches back past those
/// ticks rather than comparing against the immediate neighbour and losing the
/// change for good. A comparison made across an operator pause or across
/// unreadable ticks is labelled as such, so the incident never reads as two
/// consecutive measurements. (realm net-observer, node #32)
pub struct GwMacChange;
impl Condition for GwMacChange {
    fn id(&self) -> &'static str {
        "gw-mac-change"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let last_router = last.dhcp_router.as_deref()?;
        let last_mac = last.gw_arp_mac.as_deref()?;
        let comparable = |l: &LinkSample| l.dhcp_router.is_some() && l.gw_arp_mac.is_some();
        let recent = w.recent_link(GW_CHANGE_SCAN);
        let unreadable = recent.iter().skip(1).take_while(|l| !comparable(l)).count();
        let (prev, provenance) = match recent.iter().skip(1).find(|l| comparable(l)) {
            Some(prev) => (*prev, LinkProvenance::Contiguous),
            // Nothing comparable in the window: fall back to the basis carried
            // across a pause, which must itself carry both values.
            None => match w.prev_link_with_provenance()? {
                (prev, _) if !comparable(prev) => return None,
                (prev, provenance) => (prev, provenance),
            },
        };
        let prev_router = prev.dhcp_router.as_deref()?;
        let prev_mac = prev.gw_arp_mac.as_deref()?;
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
pub struct Starvation {
    pub load_threshold: f64,
}
impl Condition for Starvation {
    fn id(&self) -> &'static str {
        "starvation"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_proxy()?;
        // Load from the newest `host` sample; absent ⇒ 0.0 (cannot be starvation).
        let load1 = w.last_host().map_or(0.0, |h| h.load1);
        (last.tun_code.unwrap_or(0) == 0 && load1 > self.load_threshold).then(|| Fire {
            detail: format!("tun dead under load {load1:.2}"),
        })
    }
}

/// How many recent proxy samples `endpoint-block` scans when grouping rows into
/// per-tick cohorts. The daemon retains at most 64 samples (its `WINDOW_CAP`),
/// so this scan ceiling is the window itself.
const ENDPOINT_BLOCK_SCAN: usize = 64;

/// Fires when, for the newest `consecutive` proxy cohorts (one cohort = the
/// per-endpoint rows sharing one `ts_us`), every endpoint's underlay TCP
/// verdict is `Fail` while the newest link sample's `direct` probe is `Ok` —
/// the selective-block / middlebox signature: the network path to the whole
/// upstream fleet is dead from the underlay while the reference host answers.
///
/// Distinct from `wedge`, which reads the TUN probe (the proxy PROCESS path):
/// this one reads the per-endpoint underlay TCP verdicts and fires even while
/// the tun probe still passes. A cohort containing a `Skip` row is the absence
/// of a measurement (the `-` skip row means no endpoints were parsed) and
/// breaks the run; a cohort with any `Ok` is not a fleet-wide block. Proxy
/// history does not survive a resume (only the link change basis is carried),
/// so after `clear_for_resume` this simply waits for `consecutive` fresh
/// cohorts. (realm net-observer, node: pending — rationale in the PR body
/// until a graph session records it)
pub struct EndpointBlock {
    pub consecutive: usize,
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
        // Per-tick cohorts, newest first: `(ts_us, rows, all Fail so far)`.
        // One `collect()` stamps every per-endpoint row with one `ts_us`, so
        // the shared timestamp is the cohort key.
        let mut cohorts: Vec<(i64, usize, bool)> = Vec::new();
        for p in w.recent_proxy(ENDPOINT_BLOCK_SCAN) {
            // Exhaustive over the verdict: `Skip` carries no measurement, so
            // it can never count toward "every endpoint failed".
            let fail = match p.tcp {
                TcpVerdict::Fail => true,
                TcpVerdict::Ok | TcpVerdict::Skip => false,
            };
            match cohorts.last_mut() {
                Some((ts, rows, all_fail)) if *ts == p.ts_us => {
                    *rows += 1;
                    *all_fail = *all_fail && fail;
                }
                _ => {
                    // A new cohort begins; past `consecutive` of them the
                    // verdict is already decided.
                    if cohorts.len() == self.consecutive {
                        break;
                    }
                    cohorts.push((p.ts_us, 1, fail));
                }
            }
        }
        if cohorts.len() < self.consecutive {
            return None;
        }
        if !cohorts.iter().all(|(_, _, all_fail)| *all_fail) {
            return None;
        }
        let (_, n, _) = *cohorts.first()?;
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
/// cannot join the fault set by accident. (realm net-observer, node: pending —
/// rationale in the PR body until a graph session records it)
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

/// Fires when the newest link sample resolved the fakeip-pool probe address to
/// an egress interface that is not a tunnel (`utun*`) — the AWDL-collision
/// class: a fakeip answer is only meaningful inside the tunnel, so a pool
/// address routing via `awdl0`/`en0` sends traffic addressed to a phantom
/// range out a real interface.
///
/// `None` means the route could not be determined (no config, no range, no
/// route): the absence of a measurement, never a hijack. (realm net-observer,
/// node: pending — rationale in the PR body until a graph session records it)
pub struct FakeIpHijack;
impl Condition for FakeIpHijack {
    fn id(&self) -> &'static str {
        "fakeip-hijack"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let ifname = last.fakeip_route_if.as_deref()?;
        (!ifname.starts_with("utun")).then(|| Fire {
            detail: format!("fakeip pool routes via {ifname}"),
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
/// stall of established flows. Proxy history does not survive a resume, so
/// after `clear_for_resume` this waits for a fresh reading. (realm
/// net-observer, node: pending — rationale in the PR body until a graph
/// session records it)
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
        // The fresh path must still answer, or this is a plain outage, not a
        // long-flow stall (`unwrap_or(0) == 0` is the wedge's dead-tun read).
        if p.tun_code.unwrap_or(0) == 0 {
            return None;
        }
        let age = p.est_tun_age_s.unwrap_or(0);
        let detail = match p.est_direct_alive {
            Some(true) => format!(
                "established stream through the tunnel stalled after ~{age}s (fresh OK); \
direct underlay stream survived -> endpoint/protocol-scoped"
            ),
            Some(false) => format!(
                "established streams through the tunnel and the direct underlay both stalled \
after ~{age}s/~{da}s (fresh OK) -> underlay (NAT/radio), not proxy-scoped",
                da = p.est_direct_age_s.unwrap_or(0)
            ),
            None => format!(
                "established stream through the tunnel stalled after ~{age}s (fresh OK); \
direct underlay stream unmeasured"
            ),
        };
        Some(Fire { detail })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::RecentWindow;
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, LinkSample, NeighborObs, NeighborRole,
        NeighborSource, NeighborsSample, NeighborsVerdict, ProxySample, Sample, TcpVerdict,
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
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
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
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
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
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: None,
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
        assert!(
            fire.detail.contains("quiet"),
            "the detail must say the change straddled quiet ticks: {}",
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
            Some("bb:bb:bb:bb:bb:bb"),
        ));
        let fire = GwMacChange
            .eval(&w)
            .expect("same gateway IP with a different MAC must fire");
        assert!(fire.detail.contains("192.168.1.1"));
        assert!(fire.detail.contains("aa:aa:aa:aa:aa:aa"));
        assert!(fire.detail.contains("bb:bb:bb:bb:bb:bb"));
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
            Some("bb:bb:bb:bb:bb:bb"),
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
            Some("bb:bb:bb:bb:bb:bb"),
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
            Some("bb:bb:bb:bb:bb:bb"),
        ));
        let fire = GwMacChange
            .eval(&w)
            .expect("a MAC change straddling an unreadable tick must still fire");
        assert!(fire.detail.contains("aa:aa:aa:aa:aa:aa"));
        assert!(fire.detail.contains("bb:bb:bb:bb:bb:bb"));
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
            Some("bb:bb:bb:bb:bb:bb"),
        ));
        let fire = GwMacChange.eval(&w).expect("must fire across a resume");
        assert!(
            fire.detail.contains("across an observation gap"),
            "a comparison across a pause must be attributable: {}",
            fire.detail
        );
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
        let fire = c
            .eval(&w)
            .expect("two all-fail cohorts with direct OK must fire");
        assert!(
            fire.detail.contains("all 2 endpoints"),
            "the detail must carry the newest cohort size: {}",
            fire.detail
        );
        assert!(
            fire.detail.contains("2 ticks"),
            "the detail must carry the run length: {}",
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
        assert!(c.eval(&w).is_none());
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
            wifi_capture_present: false,
            lan_probed: probed,
            lan_alive: alive,
            fakeip_route_if: None,
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

    /// A link sample pinning what `FakeIpHijack` reads: the egress interface
    /// the route table resolved for the fakeip-pool probe address (gateway and
    /// direct healthy, everything else absent).
    fn link_fakeip(ts: i64, route_if: Option<&str>) -> Sample {
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
            wifi_capture_present: false,
            lan_probed: None,
            lan_alive: None,
            fakeip_route_if: route_if.map(str::to_string),
        })
    }

    /// The AWDL-collision signature: the pool routes out a real interface.
    #[test]
    fn fakeip_hijack_fires_on_a_non_tunnel_interface() {
        let mut w = RecentWindow::new(8);
        w.push(link_fakeip(1, Some("awdl0")));
        let fire = FakeIpHijack
            .eval(&w)
            .expect("a fakeip pool routing via awdl0 must fire");
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
        w.push(link_fakeip(1, Some("utun8")));
        assert!(FakeIpHijack.eval(&w).is_none());
    }

    /// `None` = the route could not be determined (no config, no range, no
    /// route): the absence of a measurement must not read as a hijack.
    #[test]
    fn fakeip_hijack_silent_when_the_route_is_unknown() {
        let mut w = RecentWindow::new(8);
        w.push(link_fakeip(1, None));
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
    /// into a continuity that never existed. The inline control — a second
    /// fresh cohort fires — proves the silence measures the clear and not a
    /// fixture that could never fire.
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
            c.eval(&w).is_some(),
            "two fresh cohorts complete the run on their own"
        );
    }
}
