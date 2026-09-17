//! Neighbours on the local segment: who else is on this network.
//!
//! Unlike every other collector's output, a neighbour is not a point in time but
//! an entity with a lifetime — the same device keeps the same MAC across ticks
//! while its IP, name and reachability move under it. Writing one row per tick
//! per device would bury the database, so the store keeps two shapes: the
//! per-tick [`NeighborsSample`] (what the reading was, including a SKIP) and a
//! long-lived `neighbor` row per `(network_key, mac)` carrying first/last seen.
//!
//! Passive by default: the ARP and NDP caches are read, never filled. Rows whose
//! [`NeighborSource`] is `Sweep` or `Mdns` exist only because an operator pressed
//! the scan button — the daemon does not probe the segment on a timer. Rows
//! whose source is `Announce` came from the device itself: a frame it put on
//! the segment, heard by the passive listener (realm net-observer, node #92).

use serde::{Deserialize, Serialize};

use crate::verdict::{AnnounceKind, NeighborSource, NeighborsVerdict};

/// A confidence-rated hypothesis about what kind of device a neighbour is.
///
/// Never an asserted fact — a wrong guess rendered as certainty is worse than no
/// guess (realm net-observer, node #33). The variants keep the certain-ish case
/// (`Gateway`, decided by the segment's own key) apart from the inferred ones,
/// and `Infra` carries how strong the inference is so the reader can weigh it.
///
/// Internally tagged (`{"kind": ...}`). Forward-compatible in BOTH directions
/// via [`NeighborRole::Unknown`]: `#[serde(default)]` on the field decodes an
/// older peer that never sent a `role`, and `#[serde(other)]` on `Unknown`
/// decodes a NEWER peer's role variant this build does not know — either way the
/// reader sees `Unknown` instead of failing the whole `NeighborObs`/`Response`
/// decode and going blank. (realm net-observer, node #36)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NeighborRole {
    /// The segment's gateway: this neighbour's MAC is the sample's `network_key`.
    /// The one near-certain classification — it needs no vendor guess.
    Gateway,
    /// Network gear (switch / AP / router), a hypothesis. `confidence` says how
    /// much to trust it: vendor-only is weak, vendor plus a management port is
    /// strong. (realm net-observer, node #36)
    Infra {
        /// How strongly the infra hypothesis is held.
        confidence: RoleConfidence,
    },
    /// An end host: a universally-administered MAC whose vendor is not network
    /// gear (or is unknown), with no management port open.
    Host,
    /// Nothing to go on: a randomized/locally-administered MAC, or no OUI
    /// snapshot to resolve a vendor against. Never a guessed vendor. Also the
    /// `#[serde(other)]` sink for a role variant a newer peer sends that this
    /// build does not know — an unknown role reads as "nothing to go on", never
    /// a decode failure.
    #[default]
    #[serde(other)]
    Unknown,
}

/// How strongly an [`NeighborRole::Infra`] hypothesis is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleConfidence {
    /// A single weak signal — an infra-vendor OUI alone.
    Low,
    /// A stronger standalone signal — a management protocol (SNMP) answering.
    Medium,
    /// Corroborated — an infra-vendor OUI *and* a management port open.
    High,
}

/// One neighbour as observed in a single reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborObs {
    /// Normalised lowercase `aa:bb:cc:dd:ee:ff`.
    pub mac: String,
    /// The address the neighbour answered on (v4 or v6, as text).
    pub ip: String,
    /// Which reading produced this observation.
    pub source: NeighborSource,
    /// Name, when one is known. Only mDNS supplies it today.
    pub hostname: Option<String>,
    /// A confidence-rated hypothesis about the neighbour's role on the segment.
    /// `#[serde(default)]` so a sender that predates the field decodes to
    /// [`NeighborRole::Unknown`]. Filled by the inference step (gateway + OUI
    /// vendor passively; refined with open ports after a scan); left `Unknown`
    /// when there is no OUI snapshot to reason from.
    ///
    /// Deliberately EPHEMERAL — a live-map hint, not written to the `neighbor`
    /// table. It is a derived view of what is persisted (the `oui`, and the
    /// scanned `neighbor_port` ports), recomputed each read against the current
    /// vendor snapshot, so it never goes stale in the store the way a cached
    /// hypothesis would.
    #[serde(default)]
    pub role: NeighborRole,
}

impl NeighborObs {
    /// The OUI — the vendor-assigned first three octets of the MAC, lowercase
    /// `aa:bb:cc`. Kept as its own column so a network can be recognised by the
    /// mix of hardware in it without parsing MACs in SQL.
    #[must_use]
    pub fn oui(&self) -> Option<String> {
        let mut parts = self.mac.split(':');
        let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
        Some(format!("{a}:{b}:{c}"))
    }
}

/// How long a neighbour has been on record: the lifetime bounds the store keeps
/// for one `(network_key, mac)` row.
///
/// A **sibling** of [`NeighborObs`], deliberately not a field of it. An obs is
/// what a single reading saw; a lifetime is what the record remembers across
/// every reading and every restart, and the two answer different questions. The
/// daemon reads these from the `neighbor` table and puts them on the status
/// snapshot beside the reading, so a pure socket client (the bar) can show
/// "since when" without ever opening the database.
///
/// A neighbour present in a reading may have NO lifetime here — the store write
/// may have failed, or the daemon may predate this field. A reader must render
/// that as *unknown*, never as *now*. (realm net-observer, node #43)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborLifetime {
    /// The neighbour this bounds, by the same normalised MAC [`NeighborObs::mac`]
    /// carries — the key a reader joins on.
    pub mac: String,
    /// When this `(network_key, mac)` was first written. Never reset by a later
    /// sighting.
    pub first_seen_us: i64,
    /// When it was most recently sighted, as the record has it.
    pub last_seen_us: i64,
}

/// Which slice of one segment's recorded history to read: a single instant, or
/// a window. The predicate is over a [`NeighborLifetime`]'s bounds (and the
/// same bounds on the ports and vulns the store keeps per neighbour).
///
/// Lives here, not in `store`, because it travels: the CLI parses it from
/// `--at` / `--since` / `--until`, `store::diagnosis::history_sql` turns it into
/// SQL, and `net_observer_ipc::DiagnosticQuery::History` carries it to a running
/// daemon — one type on both sides of the socket, and the bar (a pure socket
/// client) never has to depend on `store` to name it. (realm net-observer,
/// node #58)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryWindow {
    /// The neighbours (and their ports/vulns) live at exactly this `ts_us`:
    /// `first_seen_us <= at <= last_seen_us`.
    At(i64),
    /// The neighbours (and their ports/vulns) whose lifetime overlaps
    /// `[since, until]`: `first_seen_us <= until AND last_seen_us >= since`.
    Range { since: i64, until: i64 },
}

/// A service a neighbour announced on the segment, heard passively by the
/// `announce` listener (realm net-observer, node #92).
///
/// `service` is WHAT was announced — an mDNS service type
/// (`_companion-link._tcp`), an SSDP notification type
/// (`urn:schemas-upnp-org:device:MediaRenderer:1`, `upnp:rootdevice`), or a
/// DHCP role (`dhcp-server`, `vendor-class`) — and `detail` the specifics that
/// came with it (the mDNS instance name, the SSDP `SERVER` string, the DHCP
/// message type or vendor class). The store keys a service by
/// `(network_key, mac, service)`, so the same announcement repeated every few
/// seconds is one row with first/last seen, never a row per frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnouncedService {
    /// The announcer, by the same normalised MAC [`NeighborObs::mac`] carries.
    pub mac: String,
    /// The address the announcement came from, when the frame carried one a
    /// device can be reached at (`None` for a DHCP client still without one).
    pub ip: Option<String>,
    /// The announced type — see the struct doc.
    pub service: String,
    /// Which protocol carried the announcement.
    pub kind: AnnounceKind,
    /// The specifics that came with the announcement, when any.
    pub detail: Option<String>,
}

/// What the `announce` listener heard in one window, counted at the frame
/// level so the record shows the listener was alive and how much of what it
/// heard was this machine's own chatter (realm net-observer, node #92).
///
/// Present on a [`NeighborsSample`] exactly when the reading is a listener
/// flush rather than a neighbour-cache tick or a scan — that is how the daemon
/// tells the two apart, and why it is an `Option` on the sample instead of two
/// zero-defaulting counters: `None` is "this reading counted no frames because
/// it is not a listener's", `Some(0 / 0)` is "the listener heard nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeardFrames {
    /// Every frame the capture delivered in the window, our own included.
    pub total: u32,
    /// Of those, the frames this machine itself sent that match the capture
    /// filter — the OS's own traffic and, during an operator-pressed scan,
    /// the sweep's ARP and the mDNS browse; never the periodic probes (ICMP,
    /// TCP and DNS do not pass the filter). Recognised
    /// by the interface's own MAC, re-read at every window's start because a
    /// Private Wi-Fi Address rotates it per network; dropped from the
    /// neighbour map — a machine is not its own neighbour — but counted, so
    /// the record shows the listener saw itself and ignored it. `None` when
    /// the window's own MAC could not be read: nothing was dropped as ours,
    /// and the reading says so rather than claiming a zero. This counter is
    /// NOT the passivity proof — that stays the frozen pcap slice (realm
    /// net-observer, node #88).
    pub own: Option<u32>,
    /// Observations the window's caps refused — a sighting past the device
    /// cap, an address or service past its per-device cap, a DHCP name past
    /// the pending cap, a service announced on another host's behalf (a Sleep
    /// Proxy's) — so a flush that lost something says how much. `0` when
    /// nothing was refused; `serde(default)` so a flush from before the
    /// counter still decodes.
    #[serde(default)]
    pub dropped: u32,
}

/// One tick of the `neighbors` collector.
///
/// `network_key` is what separates the coworking segment from the home one: the
/// gateway's MAC, which survives a duplicated `192.168.1.0/24` that an SSID or a
/// subnet does not. `None` when no gateway ARP entry was readable.
///
/// Three readings share this shape: the per-tick neighbour-cache read, an
/// operator-pressed scan's findings, and the passive `announce` listener's
/// flush — the last carries `heard = Some(_)` and announced `services`, the
/// first two never do. The `serde(default)` fields keep a sample from a daemon
/// that predates the listener decodable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborsSample {
    pub ts_us: i64,
    pub verdict: NeighborsVerdict,
    /// Why the reading could not run. `Some` iff `verdict == Skip`.
    pub reason: Option<String>,
    pub network_key: Option<String>,
    pub iface: Option<String>,
    pub neighbors: Vec<NeighborObs>,
    /// Services heard announced in this reading. Only the `announce` listener
    /// fills it; every other reading leaves it empty.
    #[serde(default)]
    pub services: Vec<AnnouncedService>,
    /// The listener's frame counts — `Some` iff this reading is a listener
    /// flush (see [`HeardFrames`]).
    #[serde(default)]
    pub heard: Option<HeardFrames>,
}

impl NeighborsSample {
    /// Whether this reading is a flush of the passive `announce` listener
    /// rather than a neighbour-cache tick or a scan. A listener flush is the
    /// segment's last few seconds of announcements, not the whole neighbour
    /// table, so the daemon writes and publishes it but never lets it replace
    /// the live snapshot's cache reading (realm net-observer, node #92).
    #[must_use]
    pub fn is_listener_flush(&self) -> bool {
        self.heard.is_some()
    }

    /// Whether this reading is the `SKIP` row that brackets the listener's
    /// end: a listener flush carrying the `Skip` verdict. Not an observation
    /// — it counts no frames and drops none — but the bracket the record
    /// needs even through an operator pause, so the daemon lets it past the
    /// pause drop that swallows every other event batch (realm net-observer,
    /// node #92).
    #[must_use]
    pub fn is_listener_bracket(&self) -> bool {
        self.is_listener_flush() && self.verdict == NeighborsVerdict::Skip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oui_is_the_first_three_octets() {
        let n = NeighborObs {
            mac: "a4:83:e7:1b:2c:3d".into(),
            ip: "192.168.1.5".into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        };
        assert_eq!(n.oui().as_deref(), Some("a4:83:e7"));
    }

    #[test]
    fn a_malformed_mac_has_no_oui() {
        let n = NeighborObs {
            mac: "incomplete".into(),
            ip: "192.168.1.5".into(),
            source: NeighborSource::Arp,
            hostname: None,
            role: NeighborRole::Unknown,
        };
        assert_eq!(n.oui(), None);
    }

    /// A snapshot from a peer that predates the `role` field must still decode —
    /// the same forward-compatibility the whole socket surface relies on. The
    /// missing field defaults to [`NeighborRole::Unknown`], never a decode error.
    #[test]
    fn an_older_obs_without_a_role_decodes_to_unknown() {
        let older =
            r#"{"mac":"a4:83:e7:1b:2c:3d","ip":"192.168.1.5","source":"Arp","hostname":null}"#;
        let n: NeighborObs = serde_json::from_str(older).expect("older obs must decode");
        assert_eq!(n.role, NeighborRole::Unknown);
    }

    /// A role VARIANT a newer peer might send that this build does not know must
    /// decode to `Unknown`, not fail the whole `NeighborObs` — otherwise adding a
    /// role later blanks every un-upgraded reader. This is the `#[serde(other)]`
    /// half of the forward-compatibility (the field-default is the other half).
    #[test]
    fn an_unknown_role_tag_decodes_to_unknown_not_an_error() {
        let obs = r#"{"mac":"a4:83:e7:1b:2c:3d","ip":"192.168.1.5","source":"Arp","hostname":null,"role":{"kind":"future_variant","confidence":"high"}}"#;
        let n: NeighborObs = serde_json::from_str(obs).expect("an unknown role tag must not fail");
        assert_eq!(n.role, NeighborRole::Unknown);
    }

    /// A sample from a daemon that predates the `announce` listener carries
    /// neither `services` nor `heard`; it must decode as a cache reading, not
    /// fail — and a listener flush round-trips with both.
    #[test]
    fn an_older_sample_without_listener_fields_is_a_cache_reading() {
        let older = r#"{"ts_us":1,"verdict":"Ok","reason":null,"network_key":null,"iface":"en0","neighbors":[]}"#;
        let s: NeighborsSample = serde_json::from_str(older).expect("older sample must decode");
        assert!(s.services.is_empty());
        assert_eq!(s.heard, None);
        assert!(!s.is_listener_flush());

        let flush = NeighborsSample {
            ts_us: 2,
            verdict: NeighborsVerdict::Ok,
            reason: None,
            network_key: Some("aa:bb:cc:dd:ee:ff".into()),
            iface: Some("en0".into()),
            neighbors: vec![],
            services: vec![AnnouncedService {
                mac: "11:22:33:44:55:66".into(),
                ip: Some("192.168.1.6".into()),
                service: "_companion-link._tcp".into(),
                kind: AnnounceKind::Mdns,
                detail: Some("0xFF".into()),
            }],
            heard: Some(HeardFrames {
                total: 7,
                own: Some(2),
                dropped: 0,
            }),
        };
        assert!(flush.is_listener_flush());
        let json = serde_json::to_string(&flush).unwrap();
        assert_eq!(
            serde_json::from_str::<NeighborsSample>(&json).unwrap(),
            flush
        );
    }

    /// The role is internally tagged: `{"kind": ...}`, with the confidence carried
    /// inside the infra hypothesis. A round-trip keeps both.
    #[test]
    fn role_is_tagged_and_round_trips() {
        let infra = NeighborRole::Infra {
            confidence: RoleConfidence::High,
        };
        let json = serde_json::to_string(&infra).unwrap();
        assert!(json.contains("\"kind\":\"infra\""), "got {json}");
        assert!(json.contains("\"confidence\":\"high\""), "got {json}");
        assert_eq!(serde_json::from_str::<NeighborRole>(&json).unwrap(), infra);

        let gw = NeighborRole::Gateway;
        assert_eq!(serde_json::to_string(&gw).unwrap(), r#"{"kind":"gateway"}"#);
    }
}
