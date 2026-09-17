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

use crate::{ObservingEdge, ProbingEdge, ProbingReason, ProbingTier, local_instant};

/// The bounds of one window and the two pcap freezes that bracket it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentWindow {
    /// When the window opened: the `ts_us` of its opening `probing_edge` row.
    pub start_us: i64,
    /// When it closed: the instant the end freeze was taken, BEFORE the tier
    /// was restored, so the end freeze holds no frame from after the window.
    /// Wall clock, not the sleep that timed the window: the two differ by
    /// however long the machine slept inside it (see
    /// [`ExperimentWindow::slept_s`]).
    pub end_us: i64,
    /// The length the operator asked for. The window's real length is
    /// `end_us - start_us`; the difference is the machine's sleep.
    /// `serde(default)` on this and the five fields below: a report stored
    /// before they existed still reads, each absent value as its default.
    #[serde(default)]
    pub requested_minutes: u32,
    /// The link collector's tick, as configured — the yardstick for a sleep
    /// inside the window and for the straddling tick (see
    /// [`OwnFrames::first_echo_us`]).
    #[serde(default)]
    pub link_interval_us: i64,
    /// The tier in force before the window, read under the same lock that
    /// switched to passive.
    pub tier_before: ProbingTier,
    /// The tier in force after the window's closing edge; unrecorded, it
    /// reads as the daemon's default tier, like every unrecorded tier.
    #[serde(default)]
    pub tier_at_end: ProbingTier,
    /// What the closing edge did about `tier_before`; unrecorded, it reads
    /// as unverified, never as restored.
    #[serde(default)]
    pub restore: TierRestore,
    /// Where the START freeze copied the ring (`blob_dir/freeze-experiment-
    /// <start_us>-start`); `None` when nothing was copied. Each copied file
    /// also has a `blob_ref` row (`kind = pcap`) against the window's id, and
    /// the freeze pruner keeps `freeze-experiment-*` on its own budget, so
    /// the slice the report was read from outlives the incident freezes'
    /// churn.
    #[serde(default)]
    pub freeze_start_dir: Option<String>,
    /// The same for the END freeze.
    #[serde(default)]
    pub freeze_end_dir: Option<String>,
    /// Every record the START freeze's ring files held, inside the window or
    /// not; `None` when the ring was not running or its files could not be
    /// read — never a zero.
    pub frames_pcap_start: Option<u64>,
    /// The same for the END freeze — the slice the own-frame count reads.
    pub frames_pcap_end: Option<u64>,
}

impl ExperimentWindow {
    /// The window's real length in minutes, to one decimal.
    #[must_use]
    pub fn minutes(&self) -> f64 {
        (self.end_us - self.start_us) as f64 / 60_000_000.0
    }

    /// Whether the window was recorded with the two fields the sleep
    /// comparison needs. A report stored before `requested_minutes` and
    /// `link_interval_us` existed decodes both as `0` (`serde(default)`),
    /// and against a zero request the whole window would read as an
    /// overrun — a fabricated sleep. Such a window says "not recorded".
    #[must_use]
    pub fn sleep_recorded(&self) -> bool {
        self.requested_minutes > 0 && self.link_interval_us > 0
    }

    /// Seconds the machine slept inside the window, when the wall clock ran
    /// past the requested length by more than one link interval — the
    /// window's end task sleeps on a monotonic clock, which a sleeping
    /// machine does not advance. `None` when the overrun is within a tick,
    /// and `None` when the window was not recorded with the fields that make
    /// the comparison meaningful ([`ExperimentWindow::sleep_recorded`]).
    #[must_use]
    pub fn slept_s(&self) -> Option<i64> {
        if !self.sleep_recorded() {
            return None;
        }
        let overrun_us =
            (self.end_us - self.start_us) - i64::from(self.requested_minutes) * 60_000_000;
        (overrun_us > self.link_interval_us).then_some(overrun_us / 1_000_000)
    }
}

/// What the window's closing edge did about the tier in force before it.
///
/// The window restores `tier_before` only when the tier is still the
/// passive it set AND no operator edge landed inside the window; otherwise
/// the operator's choice stands and the closing edge merely marks the end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierRestore {
    /// `tier_before` was restored.
    Restored,
    /// An operator's `SetProbing` landed inside the window, at `at_us`:
    /// their choice stands, the restore was skipped.
    OperatorMoved { at_us: i64 },
    /// The tier was not the window's passive at the end (a switch the record
    /// did not show as a control edge): left as found, the restore skipped.
    NotPassive { found: ProbingTier },
    /// The window could not verify the conditions above — its boundary rows
    /// could not be read, or no closing edge was written: left as found, the
    /// restore skipped, `why` naming the gap. A restore it cannot vouch for
    /// would be a switch the operator did not ask for.
    Unverified { why: String },
}

impl Default for TierRestore {
    /// A report from before the field existed recorded nothing about its
    /// closing edge; it reads as unverified, never as restored.
    fn default() -> Self {
        Self::Unverified {
            why: "not recorded".into(),
        }
    }
}

/// What one frozen pcap slice held, and how many of its frames inside the
/// window this machine itself sent, by protocol.
///
/// Counted by `collector_announce::own_frames::count_own_frames` over the
/// ring's own filter (recorded on the report as
/// [`ExperimentReport::ring_filter`]), so the four buckets are the only
/// classes a frame from this machine can land in there. The daemon's
/// periodic probes that do NOT pass that filter (TCP, DNS) are outside what
/// this slice can prove either way — the tier's own `SKIP` rows are the
/// record for those — and an ICMP echo from this MAC is not necessarily
/// the daemon's: the shell oracle and a hand-run `ping` share the address.
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
    /// daemon's own probes (the gateway echo, the LAN probe) when the daemon
    /// sent them, expected 0 under the passive tier. An echo REPLY from this
    /// MAC is the OS answering someone else's ping and lands in `other`.
    pub icmp_echo: u64,
    /// The capture timestamp of the first and last of those echoes. A link
    /// tick that read `active` a moment before the flip still sends its echo
    /// after `start_us`; the offset says so instead of the count hiding it.
    #[serde(default)]
    pub first_echo_us: Option<i64>,
    #[serde(default)]
    pub last_echo_us: Option<i64>,
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
        self.earliest_us = min_opt(self.earliest_us, other.earliest_us);
        self.latest_us = max_opt(self.latest_us, other.latest_us);
        self.truncated |= other.truncated;
        self.in_window += other.in_window;
        self.icmp_echo += other.icmp_echo;
        self.first_echo_us = min_opt(self.first_echo_us, other.first_echo_us);
        self.last_echo_us = max_opt(self.last_echo_us, other.last_echo_us);
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

    /// Whether every own echo lies within one link interval of the start —
    /// the shape of the one tick that straddled the flip, not of a daemon
    /// still probing.
    #[must_use]
    pub fn echoes_are_the_straddling_tick(&self, start_us: i64, link_interval_us: i64) -> bool {
        self.icmp_echo > 0
            && self
                .last_echo_us
                .is_some_and(|t| t - start_us <= link_interval_us)
    }
}

fn min_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn max_opt(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
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

/// The boundary rows the record holds inside the window: every pause or
/// resume, and every tier switch that was not the window's own bracket. A
/// zero read against them means something different from a zero read
/// against an unbroken window.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WindowEdges {
    /// The collection state in force AT `start_us`: the newest
    /// `observing_edge` at or before it, `None` when the record holds none
    /// that early. `Some(false)` is a window that opened inside a pause — the
    /// daemon refuses to open one while paused, but a pause landing between
    /// that check and the opening edge writes its row BEFORE `start_us`,
    /// where the list below cannot see it (realm net-observer, node #61).
    #[serde(default)]
    pub observing_at_start: Option<bool>,
    /// `observing_edge` rows with `ts_us` inside `[start_us, end_us]`.
    pub observing: Vec<ObservingEdge>,
    /// `probing_edge` rows inside the same bounds — the window's own opening
    /// edge included, since it sits at `start_us`; the readers below skip
    /// the experiment reasons.
    pub probing: Vec<ProbingEdge>,
}

impl WindowEdges {
    /// The pauses inside the window: the edges that switched collection off.
    pub fn pauses(&self) -> impl Iterator<Item = &ObservingEdge> {
        self.observing.iter().filter(|e| !e.observing)
    }

    /// The tier switches inside the window that were not the window's own
    /// bracket — an operator's `SetProbing`, or a startup edge from a restart.
    pub fn operator_probing(&self) -> impl Iterator<Item = &ProbingEdge> {
        self.probing.iter().filter(|e| {
            !matches!(
                e.reason,
                ProbingReason::Experiment | ProbingReason::ExperimentEnd
            )
        })
    }
}

/// One finished experiment window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentReport {
    /// `experiment-<start_us>`.
    pub id: String,
    pub window: ExperimentWindow,
    /// The BPF filter the pcap ring captures with, as configured — the whole
    /// of what the own-frame count can see.
    #[serde(default)]
    pub ring_filter: String,
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
    /// The boundary rows inside the window.
    #[serde(default)]
    pub edges: WindowEdges,
    /// What could not be measured, and why — one line each.
    pub notes: Vec<String>,
}

impl ExperimentReport {
    /// The window's real length in minutes, to one decimal.
    #[must_use]
    pub fn minutes(&self) -> f64 {
        self.window.minutes()
    }

    /// The one line the operator reads: what the ring showed of ours on the
    /// left, the network on the right, in plain words. A count that could
    /// not be taken is named as such, never printed as a zero; the ring's
    /// filter bounds what "ours" can mean here, so the line never claims
    /// more than the slice can show.
    #[must_use]
    pub fn verdict(&self) -> String {
        let w = &self.window;
        let minutes = format!("{:.1}", self.minutes());
        let ours = match &self.our_frames {
            Some(f) => {
                let mut s = format!(
                    "our ICMP echo requests in the ring: {} in {minutes} minutes \
                     (what the ring's filter passes — see ring_filter; the shell oracle and a hand-run ping share this MAC)",
                    f.icmp_echo
                );
                if let Some(first) = f.first_echo_us {
                    s.push_str(&format!(
                        "; first own echo at +{:.1} s",
                        (first - w.start_us) as f64 / 1_000_000.0
                    ));
                    if f.echoes_are_the_straddling_tick(w.start_us, w.link_interval_us) {
                        s.push_str(" (the straddling tick)");
                    }
                }
                let os = f.arp + f.dhcp + f.other;
                if os > 0 {
                    s.push_str(&format!(
                        "; the OS sent {} ARP, {} DHCP, {} other",
                        f.arp, f.dhcp, f.other
                    ));
                }
                if !f.covers_from(w.start_us) {
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
                "our ICMP echo requests in the ring: not counted in {minutes} minutes ({})",
                if self.own_mac.is_none() {
                    "own MAC unreadable"
                } else {
                    "no pcap slice to read"
                }
            ),
        };
        let mut integrity = Vec::new();
        if self.edges.observing_at_start == Some(false) {
            integrity.push("paused at the start".to_string());
        }
        let pauses = self.edges.pauses().count();
        if pauses > 0 {
            integrity.push(format!("{pauses} pauses inside the window"));
        }
        if let Some(e) = self.edges.operator_probing().next() {
            integrity.push(format!(
                "the tier was moved inside the window at {}",
                local_instant(e.ts_us)
            ));
        }
        if let Some(s) = w.slept_s() {
            integrity.push(format!("machine slept for ~{s} s inside the window"));
        }
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
        let mut line = format!("{ours}; {theirs}");
        if !integrity.is_empty() {
            line.push_str(&format!(" [{}]", integrity.join("; ")));
        }
        line
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
        put("requested_minutes", w.requested_minutes.to_string());
        put("minutes", format!("{:.1}", self.minutes()));
        put(
            "machine_slept",
            match w.slept_s() {
                Some(s) => format!("~{s} s inside the window"),
                None if w.sleep_recorded() => "no".into(),
                None => "not recorded".into(),
            },
        );
        put("tier_before", w.tier_before.as_str().to_string());
        put(
            "tier_at_end",
            match &w.restore {
                TierRestore::Restored => format!(
                    "{} (restored from the window's passive)",
                    w.tier_at_end.as_str()
                ),
                TierRestore::OperatorMoved { at_us } => format!(
                    "{} (changed by the operator at {}; restore skipped)",
                    w.tier_at_end.as_str(),
                    local_instant(*at_us)
                ),
                TierRestore::NotPassive { found } => format!(
                    "{} (found {} at the end, not the window's passive; restore skipped)",
                    w.tier_at_end.as_str(),
                    found.as_str()
                ),
                TierRestore::Unverified { why } => {
                    format!("{} (restore skipped: {why})", w.tier_at_end.as_str())
                }
            },
        );
        put("ring_filter", self.ring_filter.clone());
        put(
            "freeze_start_dir",
            w.freeze_start_dir.clone().unwrap_or_else(|| "none".into()),
        );
        put(
            "freeze_end_dir",
            w.freeze_end_dir.clone().unwrap_or_else(|| "none".into()),
        );
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
                put(
                    "first_own_echo",
                    match f.first_echo_us {
                        None => "none".into(),
                        Some(first) => {
                            let mut s =
                                format!("+{:.1} s", (first - w.start_us) as f64 / 1_000_000.0);
                            if f.echoes_are_the_straddling_tick(w.start_us, w.link_interval_us) {
                                s.push_str(" (the straddling tick)");
                            }
                            s
                        }
                    },
                );
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
                    "first_own_echo",
                    "our_arp",
                    "our_dhcp",
                    "our_other",
                    "our_total",
                ] {
                    put(k, why.into());
                }
            }
        }
        put(
            "pauses_inside_window",
            format!(
                "{}{}",
                if self.edges.observing_at_start == Some(false) {
                    "paused at the start; "
                } else {
                    ""
                },
                edges_text(
                    self.edges.pauses().count(),
                    self.edges
                        .pauses()
                        .map(|e| local_instant(e.ts_us))
                        .collect::<Vec<_>>(),
                )
            ),
        );
        put(
            "probing_edges_inside_window",
            edges_text(
                self.edges.operator_probing().count(),
                self.edges
                    .operator_probing()
                    .map(|e| {
                        format!(
                            "{} {} ({})",
                            local_instant(e.ts_us),
                            e.tier.as_str(),
                            e.reason.as_str()
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
        );
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
                put(
                    "gw_change_incidents",
                    n.incidents_by("gw-change").to_string(),
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
                    "gw_change_incidents",
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

fn edges_text(n: usize, stamps: Vec<String>) -> String {
    if n == 0 {
        "0".into()
    } else {
        format!("{n} ({})", stamps.join(", "))
    }
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
    use crate::ObservingCause;

    const START: i64 = 100;
    const FIVE_MIN: i64 = 5 * 60_000_000;
    const LINK: i64 = 15_000_000;

    fn frames(icmp_echo: u64) -> OwnFrames {
        OwnFrames {
            records: 40,
            earliest_us: Some(50),
            latest_us: Some(400),
            truncated: false,
            in_window: 30,
            icmp_echo,
            first_echo_us: (icmp_echo > 0).then_some(START + 3_200_000),
            last_echo_us: (icmp_echo > 0).then_some(START + 3_200_000),
            arp: 2,
            dhcp: 1,
            other: 0,
        }
    }

    fn report(our: Option<OwnFrames>, network: Option<NetworkFacts>) -> ExperimentReport {
        ExperimentReport {
            id: "experiment-100".into(),
            window: ExperimentWindow {
                start_us: START,
                end_us: START + FIVE_MIN,
                requested_minutes: 5,
                link_interval_us: LINK,
                tier_before: ProbingTier::Active,
                tier_at_end: ProbingTier::Active,
                restore: TierRestore::Restored,
                freeze_start_dir: Some(
                    "/var/lib/observer/blobs/freeze-experiment-100-start".into(),
                ),
                freeze_end_dir: Some("/var/lib/observer/blobs/freeze-experiment-100-end".into()),
                frames_pcap_start: Some(10),
                frames_pcap_end: Some(40),
            },
            ring_filter: "arp or icmp or udp port 67 or udp port 68 or ether broadcast".into(),
            own_mac: our.map(|_| "f0:18:98:0a:0b:0c".to_string()),
            our_frames: our,
            network,
            edges: WindowEdges::default(),
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

    fn cell(rows: &[[String; 2]], k: &str) -> String {
        rows.iter()
            .find(|[key, _]| key == k)
            .map(|[_, v]| v.clone())
            .unwrap_or_else(|| panic!("no row {k}"))
    }

    /// The line the operator reads says what the ring can show — echo
    /// requests from this MAC, with the filter's limits named — never
    /// "silent"; the network's counts sit on the right.
    #[test]
    fn a_window_without_echoes_names_what_the_ring_can_show() {
        let r = report(Some(frames(0)), Some(quiet_network()));
        assert_eq!(
            r.verdict(),
            "our ICMP echo requests in the ring: 0 in 5.0 minutes \
             (what the ring's filter passes — see ring_filter; the shell oracle and a hand-run ping share this MAC); \
             the OS sent 2 ARP, 1 DHCP, 0 other; \
             the network showed: 2 route events, 1 incidents (gw-drop-1 [gw-drop]), 0 roams"
        );
        assert!(!r.verdict().contains("silent"));
        assert_eq!(
            cell(&r.rows(), "ring_filter"),
            "arp or icmp or udp port 67 or udp port 68 or ether broadcast"
        );
        assert_eq!(cell(&r.rows(), "first_own_echo"), "none");
    }

    /// An echo of ours is counted with its offset from the start, and when
    /// every echo lies within one link interval of the start the line says
    /// it is the tick that straddled the flip — named, never excluded.
    #[test]
    fn an_early_echo_is_named_as_the_straddling_tick() {
        let r = report(Some(frames(3)), Some(quiet_network()));
        let v = r.verdict();
        assert!(
            v.starts_with("our ICMP echo requests in the ring: 3 in 5.0 minutes"),
            "{v}"
        );
        assert!(
            v.contains("; first own echo at +3.2 s (the straddling tick)"),
            "{v}"
        );
        assert_eq!(
            cell(&r.rows(), "first_own_echo"),
            "+3.2 s (the straddling tick)"
        );

        // A later echo is not the straddling tick: the daemon (or someone on
        // this MAC) was still sending.
        let mut f = frames(3);
        f.last_echo_us = Some(START + 4 * LINK);
        let r = report(Some(f), Some(quiet_network()));
        assert!(
            r.verdict().contains("; first own echo at +3.2 s;"),
            "{}",
            r.verdict()
        );
        assert!(!r.verdict().contains("straddling"), "{}", r.verdict());
        assert_eq!(cell(&r.rows(), "first_own_echo"), "+3.2 s");
    }

    /// A count that could not be taken is a word, never a zero — in the
    /// verdict and in every row it would have filled.
    #[test]
    fn an_unreadable_mac_is_not_counted_never_zero() {
        let r = report(None, Some(quiet_network()));
        assert!(
            r.verdict().starts_with(
                "our ICMP echo requests in the ring: not counted in 5.0 minutes (own MAC unreadable)"
            ),
            "{}",
            r.verdict()
        );
        let rows = r.rows();
        assert_eq!(cell(&rows, "own_mac"), "unreadable");
        assert_eq!(
            cell(&rows, "our_icmp_echo"),
            "not counted: own MAC unreadable"
        );
        assert_eq!(
            cell(&rows, "first_own_echo"),
            "not counted: own MAC unreadable"
        );
        assert_eq!(cell(&rows, "our_total"), "not counted: own MAC unreadable");
        assert_eq!(
            cell(&rows, "gw_verdicts"),
            "SKIP=20 (all withheld: passive)"
        );
        assert_eq!(cell(&rows, "gw_change_incidents"), "0");
        assert_eq!(cell(&rows, "verdict"), r.verdict());
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
        assert_eq!(cell(&r.rows(), "pcap_covers_window"), "no");
    }

    /// The closing edge's outcome is a sentence on the `tier_at_end` row:
    /// restored, or left as the operator set it at a named instant.
    #[test]
    fn the_restore_outcome_is_named() {
        let mut r = report(Some(frames(0)), Some(quiet_network()));
        assert_eq!(
            cell(&r.rows(), "tier_at_end"),
            "active (restored from the window's passive)"
        );
        r.window.restore = TierRestore::OperatorMoved { at_us: 777 };
        r.window.tier_at_end = ProbingTier::Active;
        assert_eq!(
            cell(&r.rows(), "tier_at_end"),
            format!(
                "active (changed by the operator at {}; restore skipped)",
                local_instant(777)
            )
        );
        r.window.restore = TierRestore::NotPassive {
            found: ProbingTier::Active,
        };
        assert_eq!(
            cell(&r.rows(), "tier_at_end"),
            "active (found active at the end, not the window's passive; restore skipped)"
        );
        r.window.restore = TierRestore::Unverified {
            why: "the window's boundary rows could not be read".into(),
        };
        r.window.tier_at_end = ProbingTier::Passive;
        assert_eq!(
            cell(&r.rows(), "tier_at_end"),
            "passive (restore skipped: the window's boundary rows could not be read)"
        );
    }

    /// The boundary rows inside the window are listed with their instants,
    /// the window's own bracket left out, and the verdict carries them so
    /// the zeros on its left read against them.
    #[test]
    fn edges_inside_the_window_are_named_with_their_instants() {
        let mut r = report(Some(frames(0)), Some(quiet_network()));
        r.edges = WindowEdges {
            observing_at_start: Some(true),
            observing: vec![
                ObservingEdge {
                    ts_us: 150,
                    observing: false,
                    peer_uid: Some(501),
                    cause: ObservingCause::Control,
                },
                ObservingEdge {
                    ts_us: 160,
                    observing: true,
                    peer_uid: Some(501),
                    cause: ObservingCause::Control,
                },
            ],
            probing: vec![
                ProbingEdge {
                    ts_us: START,
                    tier: ProbingTier::Passive,
                    peer_uid: Some(501),
                    reason: ProbingReason::Experiment,
                },
                ProbingEdge {
                    ts_us: 170,
                    tier: ProbingTier::Active,
                    peer_uid: Some(501),
                    reason: ProbingReason::Control,
                },
            ],
        };
        // Instants on the human rows are clocks, not epochs (the raw
        // `start_us` / `end_us` rows stay pastable).
        let rows = r.rows();
        assert_eq!(
            cell(&rows, "pauses_inside_window"),
            format!("1 ({})", local_instant(150))
        );
        assert!(!cell(&rows, "pauses_inside_window").contains("(150)"));
        assert_eq!(
            cell(&rows, "probing_edges_inside_window"),
            format!("1 ({} active (control))", local_instant(170))
        );
        let v = r.verdict();
        assert!(
            v.ends_with(&format!(
                "[1 pauses inside the window; the tier was moved inside the window at {}]",
                local_instant(170)
            )),
            "{v}"
        );

        // A window that opened inside a pause — the pause's row sits before
        // `start_us`, so only the state at the start can say so.
        r.edges = WindowEdges {
            observing_at_start: Some(false),
            ..WindowEdges::default()
        };
        assert_eq!(
            cell(&r.rows(), "pauses_inside_window"),
            "paused at the start; 0"
        );
        assert!(
            r.verdict().ends_with("[paused at the start]"),
            "{}",
            r.verdict()
        );

        r.edges = WindowEdges::default();
        assert_eq!(cell(&r.rows(), "pauses_inside_window"), "0");
        assert!(
            !r.verdict().contains("inside the window") && !r.verdict().contains("paused"),
            "{}",
            r.verdict()
        );
    }

    /// A report stored before the round-two fields existed still reads: the
    /// absent fields take their defaults, and none of them claims a
    /// restore or a recorded tier that never was.
    #[test]
    fn a_report_without_the_newer_window_fields_still_reads() {
        let json = r#"{"id":"experiment-1","window":{"start_us":1,"end_us":2,
            "tier_before":"active","frames_pcap_start":null,"frames_pcap_end":null},
            "own_mac":null,"our_frames":null,"network":null,"notes":[]}"#;
        let r: ExperimentReport = serde_json::from_str(json).unwrap();
        assert_eq!(r.window.requested_minutes, 0);
        assert_eq!(r.window.link_interval_us, 0);
        assert_eq!(r.window.tier_at_end, ProbingTier::Passive);
        assert_eq!(
            r.window.restore,
            TierRestore::Unverified {
                why: "not recorded".into()
            }
        );
        assert_eq!(r.window.freeze_start_dir, None);
        assert_eq!(r.ring_filter, "");
        assert_eq!(r.edges, WindowEdges::default());
        assert_eq!(r.edges.observing_at_start, None);
        assert_eq!(
            cell(&r.rows(), "tier_at_end"),
            "passive (restore skipped: not recorded)"
        );
        // A zero request and a zero tick are not a request and a tick: the
        // sleep comparison is not made, so a window that never slept is not
        // told it slept for its whole length.
        assert!(!r.window.sleep_recorded());
        assert_eq!(r.window.slept_s(), None);
        assert_eq!(cell(&r.rows(), "machine_slept"), "not recorded");
        assert!(!r.verdict().contains("slept"), "{}", r.verdict());
        // Either field alone is not enough to make the comparison.
        let mut w = r.window.clone();
        w.requested_minutes = 5;
        assert!(!w.sleep_recorded());
        assert_eq!(w.slept_s(), None);
        w.link_interval_us = 15_000_000;
        w.requested_minutes = 0;
        assert!(!w.sleep_recorded());
        assert_eq!(w.slept_s(), None);
    }

    /// The window is measured on the wall clock: an end more than one link
    /// interval past the requested length is a sleep, said in seconds.
    #[test]
    fn a_wall_clock_overrun_beyond_one_tick_is_a_sleep() {
        let mut r = report(Some(frames(0)), Some(quiet_network()));
        assert_eq!(r.window.slept_s(), None);
        assert_eq!(cell(&r.rows(), "machine_slept"), "no");
        r.window.end_us = START + FIVE_MIN + LINK; // exactly one tick: not a sleep
        assert_eq!(r.window.slept_s(), None);
        r.window.end_us = START + FIVE_MIN + LINK + 1_000_000 + 600_000_000;
        assert_eq!(r.window.slept_s(), Some(616));
        assert_eq!(cell(&r.rows(), "machine_slept"), "~616 s inside the window");
        assert!(
            r.verdict()
                .ends_with("[machine slept for ~616 s inside the window]"),
            "{}",
            r.verdict()
        );
        assert_eq!(cell(&r.rows(), "minutes"), "15.3");
    }

    /// Two ring files fold into one count, keeping the earliest and latest
    /// stamp of either, the first and last echo of either, and the
    /// truncation of either.
    #[test]
    fn absorb_folds_two_slices() {
        let mut a = frames(1);
        let mut b = frames(2);
        b.earliest_us = Some(10);
        b.latest_us = Some(900);
        b.first_echo_us = Some(START + 1_000_000);
        b.last_echo_us = Some(START + 9_000_000);
        b.truncated = true;
        a.absorb(&b);
        assert_eq!(a.records, 80);
        assert_eq!(a.in_window, 60);
        assert_eq!(a.icmp_echo, 3);
        assert_eq!(a.own_total(), 3 + 4 + 2);
        assert_eq!(a.earliest_us, Some(10));
        assert_eq!(a.latest_us, Some(900));
        assert_eq!(a.first_echo_us, Some(START + 1_000_000));
        assert_eq!(a.last_echo_us, Some(START + 9_000_000));
        assert!(a.truncated);
        let mut empty = OwnFrames::default();
        empty.absorb(&frames(0));
        assert_eq!(empty.earliest_us, Some(50));
        assert_eq!(empty.first_echo_us, None);
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
        assert_eq!(
            cell(&rows, "route_events"),
            "not read: the record could not be read"
        );
        assert!(
            r.verdict()
                .ends_with("the network: the record could not be read"),
            "{}",
            r.verdict()
        );

        let n = NetworkFacts {
            incidents: vec![("gw-change-2".into(), "gw-change".into())],
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
        assert_eq!(cell(&rows, "flows_at_start"), "SKIP at 90");
        assert_eq!(
            cell(&rows, "flows_at_end"),
            "12 flows (up 100 B, down 2000 B) at 300"
        );
        assert_eq!(cell(&rows, "rssi_dbm"), "min -70, max -55");
        assert_eq!(cell(&rows, "gw_verdicts"), "no link sample");
        assert_eq!(cell(&rows, "gw_change_incidents"), "1");
        assert_eq!(
            cell(&rows, "freeze_end_dir"),
            "/var/lib/observer/blobs/freeze-experiment-100-end"
        );
    }
}
