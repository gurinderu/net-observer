use crate::window::RecentWindow;
use types::{GwVerdict, TcpVerdict};

/// A fired condition, carrying a human-readable detail string.
pub struct Fire {
    pub detail: String,
}

/// A trigger condition evaluated against the recent-sample window.
pub trait Condition {
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

/// Fires on a fake-IP DNS answer. Dormant in v1 (returns `None`) until the `dns`
/// collector lands; defined now so the engine wires the full rule set.
pub struct FakeIp;
impl Condition for FakeIp {
    fn id(&self) -> &'static str {
        "fakeip"
    }
    fn eval(&self, _w: &RecentWindow) -> Option<Fire> {
        None
    }
}

/// Fires when the tun is dead while host load exceeds `load_threshold`. Dormant in v1:
/// `load1` arrives via the `host` collector (post-v1) and defaults to `0.0`, so this
/// never fires yet; defined now so the engine wires the full rule set.
pub struct Starvation {
    pub load_threshold: f64,
}
impl Condition for Starvation {
    fn id(&self) -> &'static str {
        "starvation"
    }
    fn eval(&self, w: &RecentWindow) -> Option<Fire> {
        let last = w.last_proxy()?;
        // `load1` is not yet in the window (no `host-metrics` collector in v1); default 0.0.
        let load1 = 0.0_f64;
        (last.tun_code.unwrap_or(0) == 0 && load1 > self.load_threshold).then(|| Fire {
            detail: format!("tun dead under load {load1:.2}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::RecentWindow;
    use types::{GwVerdict, LinkSample, ProxySample, Sample, TcpVerdict};

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
