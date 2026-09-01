use crate::window::{LinkProvenance, RecentWindow};
use types::{DnsVerdict, GwVerdict, TcpVerdict};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::RecentWindow;
    use types::{
        DnsSample, DnsVerdict, GwVerdict, HostSample, LinkSample, ProxySample, Sample, TcpVerdict,
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
}
