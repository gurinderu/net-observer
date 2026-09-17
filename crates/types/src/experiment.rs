//! The experiment window's report (realm net-observer, node #61): what this
//! machine itself put on the wire during a measured passive stretch, next
//! to what the network did in the same minutes — the manual "switch
//! everything off and count by hand" procedure, as a record.
//!
//! One struct, two sinks, like [`ProbingEdge`](crate::ProbingEdge): the
//! daemon stores the report as JSON in the `experiment` table, so it
//! survives a restart, and answers `Query(Experiment { id })` with the same
//! values flattened to `key | value` rows by [`ExperimentReport::rows`]. The
//! verdict line is derived from the counts each time it is rendered, never
//! stored, so two readers of one stored report cannot disagree about it.

use serde::{Deserialize, Serialize};

use crate::ProbingTier;

/// The bounds of one window and the two pcap freezes that bracket it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentWindow {
    /// When the window opened: the `ts_us` of its opening `probing_edge` row.
    pub start_us: i64,
    /// When it closed: the instant the end freeze was taken, BEFORE the tier
    /// was restored, so the end freeze holds no frame from after the window.
    pub end_us: i64,
    /// The tier in force before the window, restored at its end.
    pub tier_before: ProbingTier,
    /// Every record the START freeze's ring files held, inside the window or
    /// not; `None` when the ring was not running or its files could not be
    /// read — never a zero.
    pub frames_pcap_start: Option<u64>,
    /// The same for the END freeze — the slice the own-frame count reads.
    pub frames_pcap_end: Option<u64>,
}

/// What one frozen pcap slice held, and how many of its frames inside the
/// window this machine itself sent, by protocol.
///
/// Counted by `collector_announce::own_frames::count_own_frames` over the
/// ring's own filter (`arp or icmp or udp port 67/68 or ether broadcast`), so
/// the four buckets are the only classes a frame from this machine can land
/// in there. The daemon's periodic probes that do NOT pass that filter (TCP,
/// DNS) are outside what this slice can prove either way — the tier's own
/// `SKIP` rows are the record for those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OwnFrames {
    /// Every record the slice held, inside the window or not.
    pub records: u64,
    /// The earliest capture timestamp in the slice, so a reader can tell
    /// whether the ring still reached back to the window's start.
    pub earliest_us: Option<i64>,
    /// The latest capture timestamp in the slice.
    pub latest_us: Option<i64>,
    /// The slice ended mid-record (a ring file copied while `tcpdump` was
    /// writing it): the counts are of what was readable, and say so.
    pub truncated: bool,
    /// Frames inside `[start_us, end_us]`, from any source.
    pub in_window: u64,
    /// ICMP echo REQUESTS from this machine's MAC inside the window — the
    /// daemon's own probes (the gateway echo, the LAN probe), expected 0
    /// under the passive tier. An echo REPLY from this MAC is the OS
    /// answering someone else's ping and lands in `other`.
    pub icmp_echo: u64,
    /// ARP from this machine's MAC — the OS resolving addresses.
    pub arp: u64,
    /// DHCP (UDP 67/68) from this machine's MAC — the OS's lease traffic.
    pub dhcp: u64,
    /// Anything else the ring's filter let through from this machine's MAC.
    pub other: u64,
}

impl OwnFrames {
    /// Frames from this machine inside the window, every bucket summed.
    #[must_use]
    pub fn own_total(&self) -> u64 {
        self.icmp_echo + self.arp + self.dhcp + self.other
    }

    /// Fold a second slice's counts (the ring's other file) into this one.
    pub fn absorb(&mut self, other: &OwnFrames) {
        self.records += other.records;
        self.earliest_us = match (self.earliest_us, other.earliest_us) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.latest_us = match (self.latest_us, other.latest_us) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        self.truncated |= other.truncated;
        self.in_window += other.in_window;
        self.icmp_echo += other.icmp_echo;
        self.arp += other.arp;
        self.dhcp += other.dhcp;
        self.other += other.other;
    }

    /// Whether the slice reaches back to `start_us`: `false` means the ring
    /// rolled over inside the window and its first minutes are gone from the
    /// slice, so a zero own count covers only the part that survived.
    #[must_use]
    pub fn covers_from(&self, start_us: i64) -> bool {
        self.earliest_us.is_some_and(|e| e <= start_us)
    }
}

/// The newest flow-table tick at or before a moment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowTotals {
    pub ts_us: i64,
    /// The tick's verdict token (`OK` | `SKIP`). On `SKIP` the totals below
    /// are zero because nothing was read, not because nothing flowed.
    pub verdict: String,
    pub flows: u64,
    pub upload: u64,
    pub download: u64,
}

/// What the record says the network did inside the window, with no probe of
/// ours in it. Every count is over rows whose `ts_us` lies in the window.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NetworkFacts {
    /// `route_event` rows.
    pub route_events: u64,
    /// Every incident opened inside the window: `(id, trigger_id)`.
    pub incidents: Vec<(String, String)>,
    /// The `link_sample.gw` verdict distribution: `(verdict, rows)`. Under
    /// the passive tier every row is `SKIP` — withheld, not failed.
    pub gw_verdicts: Vec<(String, u64)>,
    /// Announce-listener flushes, and the frames they heard in total.
    pub announce_flushes: u64,
    pub announce_heard_frames: u64,
    /// The flow table's newest tick at or before the start, and at or before
    /// the end; `None` when the record has no tick there.
    pub flows_at_start: Option<FlowTotals>,
    pub flows_at_end: Option<FlowTotals>,
    /// The Wi-Fi signal's range over the window; `None` when no sample
    /// carried an RSSI.
    pub rssi_min_dbm: Option<i64>,
    pub rssi_max_dbm: Option<i64>,
}

impl NetworkFacts {
    /// How many of the window's incidents `trigger_id` opened.
    #[must_use]
    pub fn incidents_by(&self, trigger_id: &str) -> u64 {
        self.incidents
            .iter()
            .filter(|(_, t)| t == trigger_id)
            .count() as u64
    }

    /// Whether every gateway verdict in the window was withheld — the
    /// expected shape under passive, said outright instead of left to be
    /// read off a column of `SKIP`s.
    #[must_use]
    pub fn gw_all_skip(&self) -> bool {
        !self.gw_verdicts.is_empty() && self.gw_verdicts.iter().all(|(v, _)| v == "SKIP")
    }
}

/// One finished experiment window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentReport {
    /// `experiment-<start_us>`.
    pub id: String,
    pub window: ExperimentWindow,
    /// This machine's interface MAC as read once at the window's end;
    /// `None` when it could not be read, and then `our_frames` is `None`
    /// too — a count against no address would be a count of nothing.
    pub own_mac: Option<String>,
    /// The END freeze read against `own_mac`. `None` when there was no slice
    /// to read or no MAC to read it against — reported as not counted,
    /// never as zero.
    pub our_frames: Option<OwnFrames>,
    /// The record's own counts; `None` when the store could not be read.
    pub network: Option<NetworkFacts>,
    /// What could not be measured, and why — one line each.
    pub notes: Vec<String>,
}

impl ExperimentReport {
    /// The window's length in minutes, to one decimal.
    #[must_use]
    pub fn minutes(&self) -> f64 {
        (self.window.end_us - self.window.start_us) as f64 / 60_000_000.0
    }

    /// The one line the operator reads: our probes on the left, the network
    /// on the right, in plain words. A count that could not be taken is
    /// named as such, never printed as a zero.
    #[must_use]
    pub fn verdict(&self) -> String {
        let minutes = format!("{:.1}", self.minutes());
        let ours = match &self.our_frames {
            Some(f) => {
                let mut s = if f.icmp_echo == 0 {
                    format!("our probes: 0 frames in {minutes} minutes — the daemon was silent")
                } else {
                    format!(
                        "our probes: {} ICMP echoes in {minutes} minutes — the daemon was NOT silent",
                        f.icmp_echo
                    )
                };
                let os = f.arp + f.dhcp + f.other;
                if os > 0 {
                    s.push_str(&format!(
                        " (the OS sent {} ARP, {} DHCP, {} other)",
                        f.arp, f.dhcp, f.other
                    ));
                }
                if !f.covers_from(self.window.start_us) {
                    s.push_str(match f.earliest_us {
                        Some(_) => " [the ring rolled over inside the window; the count covers its tail only]",
                        None => " [the slice held no frame]",
                    });
                }
                if f.truncated {
                    s.push_str(" [slice cut mid-record]");
                }
                s
            }
            None => format!(
                "our probes: not counted in {minutes} minutes ({})",
                if self.own_mac.is_none() {
                    "own MAC unreadable"
                } else {
                    "no pcap slice to read"
                }
            ),
        };
        let theirs = match &self.network {
            Some(n) => {
                let ids = if n.incidents.is_empty() {
                    String::from("none")
                } else {
                    n.incidents
                        .iter()
                        .map(|(id, t)| format!("{id} [{t}]"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!(
                    "the network showed: {} route events, {} incidents ({ids}), {} roams",
                    n.route_events,
                    n.incidents.len(),
                    n.incidents_by("roam")
                )
            }
            None => String::from("the network: the record could not be read"),
        };
        format!("{ours}; {theirs}")
    }

    /// The report as `key | value` rows — the wire shape of the answer to
    /// `Query(Experiment { id })`, rendered by the CLI's table printer. Every
    /// absent measurement is a word, not an empty cell.
    #[must_use]
    pub fn rows(&self) -> Vec<[String; 2]> {
        let mut rows: Vec<[String; 2]> = Vec::new();
        let mut put = |k: &str, v: String| rows.push([k.to_string(), v]);
        let w = &self.window;
        put("id", self.id.clone());
        put("start_us", w.start_us.to_string());
        put("end_us", w.end_us.to_string());
        put("minutes", format!("{:.1}", self.minutes()));
        put("tier_before", w.tier_before.as_str().to_string());
        put(
            "frames_pcap_start",
            count_or(w.frames_pcap_start, "not read"),
        );
        put("frames_pcap_end", count_or(w.frames_pcap_end, "not read"));
        put(
            "own_mac",
            self.own_mac.clone().unwrap_or_else(|| "unreadable".into()),
        );
        match &self.our_frames {
            Some(f) => {
                put(
                    "pcap_earliest_us",
                    f.earliest_us
                        .map_or_else(|| "no frame".into(), |t| t.to_string()),
                );
                put(
                    "pcap_covers_window",
                    if f.covers_from(w.start_us) {
                        "yes"
                    } else {
                        "no"
                    }
                    .into(),
                );
                put(
                    "pcap_truncated",
                    if f.truncated { "yes" } else { "no" }.into(),
                );
                put("frames_in_window", f.in_window.to_string());
                put("our_icmp_echo", f.icmp_echo.to_string());
                put("our_arp", f.arp.to_string());
                put("our_dhcp", f.dhcp.to_string());
                put("our_other", f.other.to_string());
                put("our_total", f.own_total().to_string());
            }
            None => {
                let why = if self.own_mac.is_none() {
                    "not counted: own MAC unreadable"
                } else {
                    "not counted: no pcap slice"
                };
                for k in [
                    "pcap_earliest_us",
                    "pcap_covers_window",
                    "pcap_truncated",
                    "frames_in_window",
                    "our_icmp_echo",
                    "our_arp",
                    "our_dhcp",
                    "our_other",
                    "our_total",
                ] {
                    put(k, why.into());
                }
            }
        }
        match &self.network {
            Some(n) => {
                put("route_events", n.route_events.to_string());
                put("incidents", n.incidents.len().to_string());
                put(
                    "incident_ids",
                    if n.incidents.is_empty() {
                        "none".into()
                    } else {
                        n.incidents
                            .iter()
                            .map(|(id, t)| format!("{id} [{t}]"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                );
                put(
                    "gw_verdicts",
                    if n.gw_verdicts.is_empty() {
                        "no link sample".into()
                    } else {
                        let mut s = n
                            .gw_verdicts
                            .iter()
                            .map(|(v, c)| format!("{v}={c}"))
                            .collect::<Vec<_>>()
                            .join(", ");
                        if n.gw_all_skip() {
                            s.push_str(" (all withheld: passive)");
                        }
                        s
                    },
                );
                put("roam_incidents", n.incidents_by("roam").to_string());
                put(
                    "wifi_churn_incidents",
                    n.incidents_by("wifi-churn").to_string(),
                );
                put("announce_flushes", n.announce_flushes.to_string());
                put("announce_heard_frames", n.announce_heard_frames.to_string());
                put("flows_at_start", flows_text(n.flows_at_start.as_ref()));
                put("flows_at_end", flows_text(n.flows_at_end.as_ref()));
                put(
                    "rssi_dbm",
                    match (n.rssi_min_dbm, n.rssi_max_dbm) {
                        (Some(lo), Some(hi)) => format!("min {lo}, max {hi}"),
                        _ => "no sample".into(),
                    },
                );
            }
            None => {
                for k in [
                    "route_events",
                    "incidents",
                    "incident_ids",
                    "gw_verdicts",
                    "roam_incidents",
                    "wifi_churn_incidents",
                    "announce_flushes",
                    "announce_heard_frames",
                    "flows_at_start",
                    "flows_at_end",
                    "rssi_dbm",
                ] {
                    put(k, "not read: the record could not be read".into());
                }
            }
        }
        put(
            "notes",
            if self.notes.is_empty() {
                "none".into()
            } else {
                self.notes.join("; ")
            },
        );
        put("verdict", self.verdict());
        rows
    }
}

fn count_or(v: Option<u64>, absent: &str) -> String {
    v.map_or_else(|| absent.to_string(), |n| n.to_string())
}

fn flows_text(f: Option<&FlowTotals>) -> String {
    match f {
        None => "no tick".into(),
        Some(t) if t.verdict != "OK" => format!("{} at {}", t.verdict, t.ts_us),
        Some(t) => format!(
            "{} flows (up {} B, down {} B) at {}",
            t.flows, t.upload, t.download, t.ts_us
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(icmp_echo: u64) -> OwnFrames {
        OwnFrames {
            records: 40,
            earliest_us: Some(50),
            latest_us: Some(400),
            truncated: false,
            in_window: 30,
            icmp_echo,
            arp: 2,
            dhcp: 1,
            other: 0,
        }
    }

    fn report(our: Option<OwnFrames>, network: Option<NetworkFacts>) -> ExperimentReport {
        ExperimentReport {
            id: "experiment-100".into(),
            window: ExperimentWindow {
                start_us: 100,
                end_us: 100 + 5 * 60_000_000,
                tier_before: ProbingTier::Active,
                frames_pcap_start: Some(10),
                frames_pcap_end: Some(40),
            },
            own_mac: our.map(|_| "f0:18:98:0a:0b:0c".to_string()),
            our_frames: our,
            network,
            notes: Vec::new(),
        }
    }

    fn quiet_network() -> NetworkFacts {
        NetworkFacts {
            route_events: 2,
            incidents: vec![("gw-drop-1".into(), "gw-drop".into())],
            gw_verdicts: vec![("SKIP".into(), 20)],
            ..NetworkFacts::default()
        }
    }

    /// The line the operator reads: silence on the left when no echo of ours
    /// was in the slice, and the network's counts on the right.
    #[test]
    fn a_silent_window_reads_as_silent() {
        let r = report(Some(frames(0)), Some(quiet_network()));
        assert_eq!(
            r.verdict(),
            "our probes: 0 frames in 5.0 minutes — the daemon was silent \
             (the OS sent 2 ARP, 1 DHCP, 0 other); \
             the network showed: 2 route events, 1 incidents (gw-drop-1 [gw-drop]), 0 roams"
        );
    }

    /// One echo of ours is the whole point of the count: the line says NOT
    /// silent, with the number.
    #[test]
    fn an_echo_of_ours_is_named_not_silent() {
        let r = report(Some(frames(3)), Some(quiet_network()));
        assert!(
            r.verdict().starts_with(
                "our probes: 3 ICMP echoes in 5.0 minutes — the daemon was NOT silent"
            ),
            "{}",
            r.verdict()
        );
    }

    /// A count that could not be taken is a word, never a zero — in the
    /// verdict and in every row it would have filled.
    #[test]
    fn an_unreadable_mac_is_not_counted_never_zero() {
        let r = report(None, Some(quiet_network()));
        assert!(
            r.verdict()
                .starts_with("our probes: not counted in 5.0 minutes (own MAC unreadable)"),
            "{}",
            r.verdict()
        );
        let rows = r.rows();
        let cell = |k: &str| {
            rows.iter()
                .find(|[key, _]| key == k)
                .map(|[_, v]| v.clone())
                .unwrap_or_else(|| panic!("no row {k}"))
        };
        assert_eq!(cell("own_mac"), "unreadable");
        assert_eq!(cell("our_icmp_echo"), "not counted: own MAC unreadable");
        assert_eq!(cell("our_total"), "not counted: own MAC unreadable");
        assert_eq!(cell("gw_verdicts"), "SKIP=20 (all withheld: passive)");
        assert_eq!(cell("verdict"), r.verdict());
    }

    /// A ring that rolled over inside the window cannot vouch for its first
    /// minutes; the line says so instead of letting a zero stand for them.
    #[test]
    fn a_ring_that_rolled_over_is_flagged() {
        let mut f = frames(0);
        f.earliest_us = Some(200); // after start_us = 100
        let r = report(Some(f), Some(quiet_network()));
        assert!(
            r.verdict()
                .contains("the ring rolled over inside the window"),
            "{}",
            r.verdict()
        );
        let rows = r.rows();
        assert!(rows.contains(&["pcap_covers_window".to_string(), "no".to_string()]));
    }

    /// Two ring files fold into one count, keeping the earliest and latest
    /// stamp of either and the truncation of either.
    #[test]
    fn absorb_folds_two_slices() {
        let mut a = frames(1);
        let mut b = frames(2);
        b.earliest_us = Some(10);
        b.latest_us = Some(900);
        b.truncated = true;
        a.absorb(&b);
        assert_eq!(a.records, 80);
        assert_eq!(a.in_window, 60);
        assert_eq!(a.icmp_echo, 3);
        assert_eq!(a.own_total(), 3 + 4 + 2);
        assert_eq!(a.earliest_us, Some(10));
        assert_eq!(a.latest_us, Some(900));
        assert!(a.truncated);
        let mut empty = OwnFrames::default();
        empty.absorb(&frames(0));
        assert_eq!(empty.earliest_us, Some(50));
    }

    /// The stored JSON and the rendered rows come from one value; the JSON
    /// round-trips whole, so a report read back after a restart renders the
    /// same rows it did live.
    #[test]
    fn a_report_round_trips_through_json() {
        let r = report(Some(frames(0)), Some(quiet_network()));
        let json = serde_json::to_string(&r).unwrap();
        let back: ExperimentReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.rows(), r.rows());
    }

    /// The rows carry the network's absence as words too, and a flow tick
    /// that was a SKIP does not print as zero flows.
    #[test]
    fn network_rows_name_what_is_absent() {
        let r = report(Some(frames(0)), None);
        let rows = r.rows();
        assert!(rows.contains(&[
            "route_events".to_string(),
            "not read: the record could not be read".to_string()
        ]));
        assert!(
            r.verdict()
                .ends_with("the network: the record could not be read")
        );

        let n = NetworkFacts {
            flows_at_start: Some(FlowTotals {
                ts_us: 90,
                verdict: "SKIP".into(),
                flows: 0,
                upload: 0,
                download: 0,
            }),
            flows_at_end: Some(FlowTotals {
                ts_us: 300,
                verdict: "OK".into(),
                flows: 12,
                upload: 100,
                download: 2000,
            }),
            rssi_min_dbm: Some(-70),
            rssi_max_dbm: Some(-55),
            ..NetworkFacts::default()
        };
        let rows = report(Some(frames(0)), Some(n)).rows();
        assert!(rows.contains(&["flows_at_start".to_string(), "SKIP at 90".to_string()]));
        assert!(rows.contains(&[
            "flows_at_end".to_string(),
            "12 flows (up 100 B, down 2000 B) at 300".to_string()
        ]));
        assert!(rows.contains(&["rssi_dbm".to_string(), "min -70, max -55".to_string()]));
        assert!(rows.contains(&["gw_verdicts".to_string(), "no link sample".to_string()]));
    }
}
