use std::collections::VecDeque;

use types::{DnsSample, HostSample, LinkSample, ProxySample, Sample};

/// Ring buffer of the most recent `cap` [`Sample`]s.
pub struct RecentWindow {
    cap: usize,
    buf: VecDeque<Sample>,
}

impl RecentWindow {
    /// Create a window that retains at most `cap` samples.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: VecDeque::with_capacity(cap),
        }
    }

    /// Append a sample, evicting the oldest when over capacity.
    pub fn push(&mut self, s: Sample) {
        self.buf.push_back(s);
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
    }

    /// Drop every retained sample, keeping the allocated capacity.
    ///
    /// Called on a collection RESUME edge. The window is push-only and the
    /// count-based conditions (`Wedge`, `GwChange`) carry no time bound, so
    /// pre-pause samples left in it would let two bad ticks from before an
    /// arbitrary observation gap combine with one after it into an incident
    /// asserting a continuity that never existed ("tun dead 3 ticks").
    ///
    /// This forgets *samples* only. The trigger engine's re-arm/latch state is
    /// deliberately NOT reset — a trigger not re-firing across a pause is
    /// intended dedup, not a bug.
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    /// Whether the window currently holds no samples.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The most recent `n` link samples, newest first.
    pub fn recent_link(&self, n: usize) -> Vec<&LinkSample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Link(l) => Some(l),
                Sample::Proxy(_) | Sample::Dns(_) | Sample::Route(_) | Sample::Host(_) => None,
            })
            .take(n)
            .collect()
    }

    /// The most recent `n` proxy samples, newest first.
    pub fn recent_proxy(&self, n: usize) -> Vec<&ProxySample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Proxy(p) => Some(p),
                Sample::Link(_) | Sample::Dns(_) | Sample::Route(_) | Sample::Host(_) => None,
            })
            .take(n)
            .collect()
    }

    /// The newest link sample, if any.
    pub fn last_link(&self) -> Option<&LinkSample> {
        self.buf.iter().rev().find_map(|s| match s {
            Sample::Link(l) => Some(l),
            Sample::Proxy(_) | Sample::Dns(_) | Sample::Route(_) | Sample::Host(_) => None,
        })
    }

    /// The newest proxy sample, if any.
    pub fn last_proxy(&self) -> Option<&ProxySample> {
        self.buf.iter().rev().find_map(|s| match s {
            Sample::Proxy(p) => Some(p),
            Sample::Link(_) | Sample::Dns(_) | Sample::Route(_) | Sample::Host(_) => None,
        })
    }

    /// The most recent `n` DNS samples, newest first.
    pub fn recent_dns(&self, n: usize) -> Vec<&DnsSample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Dns(d) => Some(d),
                Sample::Link(_) | Sample::Proxy(_) | Sample::Route(_) | Sample::Host(_) => None,
            })
            .take(n)
            .collect()
    }

    /// The newest DNS sample, if any.
    pub fn last_dns(&self) -> Option<&DnsSample> {
        self.buf.iter().rev().find_map(|s| match s {
            Sample::Dns(d) => Some(d),
            Sample::Link(_) | Sample::Proxy(_) | Sample::Route(_) | Sample::Host(_) => None,
        })
    }

    /// The newest host sample, if any.
    pub fn last_host(&self) -> Option<&HostSample> {
        self.buf.iter().rev().find_map(|s| match s {
            Sample::Host(h) => Some(h),
            Sample::Link(_) | Sample::Proxy(_) | Sample::Dns(_) | Sample::Route(_) => None,
        })
    }

    /// The second-newest link sample, if any.
    pub fn prev_link(&self) -> Option<&LinkSample> {
        self.buf
            .iter()
            .rev()
            .filter_map(|s| match s {
                Sample::Link(l) => Some(l),
                Sample::Proxy(_) | Sample::Dns(_) | Sample::Route(_) | Sample::Host(_) => None,
            })
            .nth(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{GwVerdict, TcpVerdict};

    fn link(ts: i64) -> Sample {
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
        })
    }

    fn proxy(ts: i64) -> Sample {
        Sample::Proxy(ProxySample {
            ts_us: ts,
            server_ip: "1".into(),
            tcp: TcpVerdict::Ok,
            rtt_ms: None,
            tun_code: Some(0),
            selector: None,
        })
    }

    #[test]
    fn clear_empties_the_window() {
        let mut w = RecentWindow::new(16);
        w.push(link(1));
        w.push(proxy(2));
        assert!(!w.is_empty());

        w.clear();

        // Nothing from before the gap survives, through any accessor.
        assert!(w.is_empty());
        assert!(w.last_link().is_none());
        assert!(w.last_proxy().is_none());
        assert!(w.recent_link(3).is_empty());
        assert!(w.recent_proxy(3).is_empty());
        assert!(w.prev_link().is_none());

        // A cleared window is still a usable window, not a poisoned one.
        w.push(link(10));
        w.push(proxy(11));
        w.push(link(12));
        assert!(!w.is_empty());
        assert_eq!(w.last_link().map(|l| l.ts_us), Some(12));
        assert_eq!(w.prev_link().map(|l| l.ts_us), Some(10));
        assert_eq!(w.last_proxy().map(|p| p.ts_us), Some(11));
        assert_eq!(w.recent_link(3).len(), 2);
    }
}
