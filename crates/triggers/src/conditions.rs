use crate::window::RecentWindow;
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

/// Fires when the newest link sample's gateway verdict is `Fail` or `NoGw`.
pub struct GwDrop;
impl Condition for GwDrop {
    fn id(&self) -> &'static str {
        "gw-drop"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        matches!(last.gw, GwVerdict::Fail | GwVerdict::NoGw).then(|| Fire {
            detail: format!("gateway {}", last.gw),
        })
    }
}

/// Fires on any change in the gateway verdict between the two newest link samples.
pub struct GwChange;
impl Condition for GwChange {
    fn id(&self) -> &'static str {
        "gw-change"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_link()?;
        let prev = w.prev_link()?;
        (last.gw != prev.gw).then(|| Fire {
            detail: format!("gateway {} -> {}", prev.gw, last.gw),
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
        use crate::window::RecentWindow;
        use types::{GwVerdict, LinkSample, Sample, TcpVerdict};
        let mk = |ts: i64, gw: GwVerdict| {
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
        };
        let mut w = RecentWindow::new(8);
        w.push(mk(1, GwVerdict::Ok));
        assert!(GwDrop.eval(&w).is_none());
        assert!(GwChange.eval(&w).is_none()); // no prev
        w.push(mk(2, GwVerdict::Fail));
        assert!(GwDrop.eval(&w).is_some());
        assert!(GwChange.eval(&w).is_some()); // Ok -> Fail
    }
}
