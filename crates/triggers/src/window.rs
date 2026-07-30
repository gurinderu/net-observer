use std::collections::VecDeque;

use types::{DnsSample, HostSample, LinkSample, ProxySample, Sample};

/// Where [`RecentWindow::prev_link`]'s answer came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkProvenance {
    /// Both samples were observed inside one uninterrupted session.
    Contiguous,
    /// The predecessor is the last link sample seen BEFORE a pause: the two are
    /// separated by an observation gap of unknown length, so a change between
    /// them is real but its timing is not attributable to a tick.
    AcrossGap,
}

/// Ring buffer of the most recent `cap` [`Sample`]s.
pub struct RecentWindow {
    cap: usize,
    buf: VecDeque<Sample>,
    /// The newest link sample from before the most recent
    /// [`RecentWindow::clear_for_resume`] — the gateway CHANGE BASIS, and the only
    /// thing that survives a resume. Reachable solely through
    /// [`RecentWindow::prev_link`] / [`RecentWindow::prev_link_with_provenance`].
    carried_link: Option<LinkSample>,
    /// Link samples pushed since that clear. The basis is retired by the SECOND
    /// one, so it can never resurface as the neighbour of a much later sample
    /// after eviction has emptied the window of links again.
    links_since_clear: u32,
}

impl RecentWindow {
    /// Create a window that retains at most `cap` samples.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: VecDeque::with_capacity(cap),
            carried_link: None,
            links_since_clear: 0,
        }
    }

    /// Append a sample, evicting the oldest when over capacity.
    ///
    /// A link push also retires the carried change basis once the window holds a
    /// link of its own: from the second post-clear link onward the in-window
    /// predecessor is the truthful comparison, and a basis left behind could
    /// otherwise resurface much later — after eviction had emptied the window of
    /// links again — as the partner for an unrelated sample.
    pub fn push(&mut self, s: Sample) {
        if matches!(s, Sample::Link(_)) {
            if self.links_since_clear >= 1 {
                self.carried_link = None;
            }
            self.links_since_clear = self.links_since_clear.saturating_add(1);
        }
        self.buf.push_back(s);
        while self.buf.len() > self.cap {
            self.buf.pop_front();
        }
    }

    /// Drop every retained sample, keeping the allocated capacity — and carry the
    /// newest link sample forward as the gateway-change basis.
    ///
    /// Called on a collection RESUME edge. The window is push-only and the
    /// count-based conditions (`Wedge`) carry no time bound, so pre-pause samples
    /// left in it would let two bad ticks from before an arbitrary observation gap
    /// combine with one after it into an incident asserting a continuity that
    /// never existed ("tun dead 3 ticks").
    ///
    /// ONE thing survives: the newest [`types::LinkSample`], reachable only
    /// through [`RecentWindow::prev_link`] / [`RecentWindow::prev_link_with_provenance`].
    /// The behavioural oracle freezes the pcap ring on ANY gateway change and that
    /// ring keeps capturing while collection is paused, so a gateway that changed
    /// DURING the pause must still be detectable at resume; change detection needs
    /// exactly one prior sample, never a run of them. `last_link`, `recent_link`,
    /// `recent_proxy`, `recent_dns` and `is_empty` never see the basis, so the
    /// count-based conditions still cannot span the gap and `GwDrop` /
    /// `Starvation` cannot assert pre-pause state as the present.
    ///
    /// A resume with no link sample in the window KEEPS the basis already carried:
    /// the last gateway state this daemon actually observed remains the truthful
    /// thing to compare against, however many gaps sit in between.
    ///
    /// This forgets *samples*. Re-arming the trigger engine is the pipeline's
    /// separate, explicit job on the same edge
    /// ([`crate::engine::TriggerEngine::rearm_all`]) — see its doc for the
    /// re-fire guarantee.
    pub fn clear_for_resume(&mut self) {
        if let Some(latest) = self.last_link().cloned() {
            self.carried_link = Some(latest);
        }
        self.buf.clear();
        self.links_since_clear = 0;
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

    /// The link sample the newest one should be compared against, with the
    /// provenance of the answer.
    ///
    /// Normally the second-newest link sample in the window
    /// ([`LinkProvenance::Contiguous`]). Immediately after a
    /// [`RecentWindow::clear_for_resume`] the window holds at most one, and the
    /// predecessor is the basis carried across that clear
    /// ([`LinkProvenance::AcrossGap`]) — which is what keeps a gateway change that
    /// happened DURING a pause detectable at resume. `None` when there is no
    /// newest link sample at all: with nothing to compare, there is nothing to
    /// precede, and the basis must never be mistaken for the present state.
    pub fn prev_link_with_provenance(&self) -> Option<(&LinkSample, LinkProvenance)> {
        let mut links = self.buf.iter().rev().filter_map(|s| match s {
            Sample::Link(l) => Some(l),
            Sample::Proxy(_) | Sample::Dns(_) | Sample::Route(_) | Sample::Host(_) => None,
        });
        links.next()?;
        match links.next() {
            Some(prev) => Some((prev, LinkProvenance::Contiguous)),
            None => self
                .carried_link
                .as_ref()
                .map(|carried| (carried, LinkProvenance::AcrossGap)),
        }
    }

    /// The link sample immediately preceding [`RecentWindow::last_link`] — see
    /// [`RecentWindow::prev_link_with_provenance`] for the resume-boundary case.
    pub fn prev_link(&self) -> Option<&LinkSample> {
        self.prev_link_with_provenance().map(|(l, _)| l)
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
    fn clear_for_resume_keeps_only_the_change_basis() {
        let mut w = RecentWindow::new(16);
        w.push(link(1));
        w.push(proxy(2));
        assert!(!w.is_empty());

        w.clear_for_resume();

        // Nothing from before the gap is *observable* as the present: every
        // accessor the count-based conditions use reads an empty window.
        assert!(w.is_empty());
        assert!(w.last_link().is_none());
        assert!(w.last_proxy().is_none());
        assert!(w.recent_link(3).is_empty());
        assert!(w.recent_proxy(3).is_empty());
        // With no newest link there is nothing to precede, so the basis must not
        // surface on its own either.
        assert!(w.prev_link().is_none());

        // The one exception: the first post-resume link sample gets the carried
        // basis as its predecessor, so a gateway that changed DURING the pause is
        // still detectable.
        w.push(link(10));
        assert_eq!(w.last_link().map(|l| l.ts_us), Some(10));
        assert_eq!(w.prev_link().map(|l| l.ts_us), Some(1));
        assert_eq!(
            w.prev_link_with_provenance().map(|(_, p)| p),
            Some(LinkProvenance::AcrossGap),
        );
        // …and only as a predecessor: the basis must never count as a tick.
        assert_eq!(w.recent_link(4).len(), 1);
    }

    /// PRECEDENCE: with two links in the window the in-window predecessor answers,
    /// the carried basis is not consulted at all, and the provenance says so.
    ///
    /// This does NOT pin the basis's RETIREMENT. Deleting the `carried_link = None`
    /// branch in `push` leaves it green, because `prev_link_with_provenance` reaches
    /// the basis only as a FALLBACK and two in-window links never reach it — see
    /// `the_change_basis_is_retired_by_the_second_post_resume_link` for that.
    ///
    /// What it uniquely owns is the [`LinkProvenance::Contiguous`] label, asserted
    /// nowhere else in the workspace: relabelling it `AcrossGap` would append
    /// " (across an observation gap)" to the signature of every ordinary two-tick
    /// gateway-change incident, marking routine ticks as spanning a pause that
    /// never happened.
    #[test]
    fn the_in_window_predecessor_wins_over_the_carried_basis() {
        let mut w = RecentWindow::new(16);
        w.push(link(1));
        w.clear_for_resume();
        w.push(link(10));
        w.push(link(11));
        // Two fresh links straddle no gap: the in-window predecessor is the
        // truthful comparison and the basis is gone.
        assert_eq!(w.prev_link().map(|l| l.ts_us), Some(10));
        assert_eq!(
            w.prev_link_with_provenance().map(|(_, p)| p),
            Some(LinkProvenance::Contiguous),
        );
    }

    /// RETIREMENT: the SECOND post-resume link drops the basis for good, so it can
    /// never resurface as the neighbour of a much later sample once eviction has
    /// emptied the window of links again.
    ///
    /// The basis is only *reachable* while the window holds exactly one link, so
    /// the fixture retires it with a second link and then evicts only the OLDER of
    /// the two — restoring the one shape in which a surviving basis would be read.
    /// It dies under both mutations of the retirement: deleting the
    /// `carried_link = None` branch, and widening its condition to
    /// `links_since_clear >= 2` (an off-by-one that survives the rest of the
    /// suite, because every other fixture pushes a third link before reading).
    ///
    /// The `None` at the end is the retirement and not a window that never carried
    /// anything: `clear_for_resume_keeps_only_the_change_basis` runs the same
    /// opening with only ONE post-resume link and reads the basis back as
    /// `AcrossGap`. There is deliberately no eviction-based control beyond that —
    /// with one post-resume link, the link that follows the eviction is itself the
    /// second one and retires the basis, so both arms would read `None` and the
    /// control would prove nothing.
    #[test]
    fn the_change_basis_is_retired_by_the_second_post_resume_link() {
        let mut w = RecentWindow::new(4);
        w.push(link(1));
        w.clear_for_resume(); // carried = link(1), links_since_clear = 0
        w.push(link(10)); // first post-resume link: nothing retired
        w.push(link(11)); // the second one: the basis is retired HERE
        // Precedence still answers while both links are in the window, so the
        // retirement is not observable yet.
        assert_eq!(w.prev_link().map(|l| l.ts_us), Some(10));

        // Evict only the OLDER link, so the newest one has no in-window
        // predecessor again — the exact shape a surviving basis would fill.
        w.push(proxy(100));
        w.push(proxy(101));
        w.push(proxy(102));
        assert_eq!(
            w.last_link().map(|l| l.ts_us),
            Some(11),
            "only the OLDER link may be evicted, or `prev_link` is None for the wrong reason"
        );
        assert!(
            w.prev_link().is_none(),
            "a retired basis must never resurface as a much later sample's predecessor"
        );
    }

    /// The distinct "no link history at all" case: eviction takes BOTH post-resume
    /// links, so a retirement implemented by scanning the buffer would have found
    /// nothing to retire against and left the basis standing.
    ///
    /// The `last_link()` assertion is what makes the `None` mean that: without it
    /// the test also passes against a `push` that drops link samples on the floor,
    /// reading `None` for a reason that has nothing to do with retirement.
    #[test]
    fn an_evicted_link_history_reads_as_absent() {
        let mut w = RecentWindow::new(4);
        w.push(link(1));
        w.clear_for_resume();
        w.push(link(10));
        w.push(link(20)); // second post-resume link: the basis is retired here
        // A burst of other samples evicts both links again — the window now holds
        // no link history at all, which retirement by buffer scan would have missed.
        for t in 0..4 {
            w.push(proxy(100 + t));
        }
        w.push(link(30));
        assert_eq!(
            w.last_link().map(|l| l.ts_us),
            Some(30),
            "the window must still hold the newest link, or `prev_link` is None for the wrong reason"
        );
        assert!(
            w.prev_link().is_none(),
            "an evicted neighbour must never be replaced by a pre-pause one"
        );
    }

    #[test]
    fn two_resumes_without_a_link_sample_keep_the_basis() {
        let mut w = RecentWindow::new(16);
        w.push(link(1));
        w.clear_for_resume();
        // A second resume with nothing observed in between must not forget the
        // last gateway state this daemon actually saw.
        w.clear_for_resume();
        w.push(link(10));
        assert_eq!(w.prev_link().map(|l| l.ts_us), Some(1));
    }
}
