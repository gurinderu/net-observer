pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS link_sample (
  ts_us BIGINT, gw VARCHAR, gw_rtt_ms DOUBLE, direct VARCHAR, direct_rtt_ms DOUBLE,
  dhcp_router VARCHAR, dhcp_dns VARCHAR, gw_arp_mac VARCHAR, ssid VARCHAR, wifi_capture_present BOOLEAN);
-- Probe-on-suspicion neighbor-ping counts, measured only on a gateway-FAIL
-- tick (NULL on every other tick: not probed, never a zero). Added after the
-- link table first shipped, so an older database file keeps its column set
-- until these ALTERs run on open, exactly like `neighbor_port.banner` below.
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS lan_probed USMALLINT;
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS lan_alive USMALLINT;
-- The egress interface the route table resolves for a fakeip-pool address
-- (NULL when it could not be determined). Same migration treatment.
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS fakeip_route_if VARCHAR;
-- The interface carrying sing-box's own TUN address (the sing-box-alive fact;
-- that address is present only while sing-box runs). NULL when sing-box's TUN
-- is not up. Same migration treatment.
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS singbox_tun_if VARCHAR;
-- The link's identity pair: the BSSID of the access point associated with and
-- the interface's own (Private Wi-Fi Address, per-SSID) MAC, both lowercase.
-- A BSSID change at the same SSID is a roam the SSID column cannot show; an
-- if_mac change is a new DHCP identity toward the network (realm net-observer,
-- node #59). NULL = not associated / not determinable. Same migration
-- treatment.
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS bssid VARCHAR;
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS if_mac VARCHAR;
-- The medium of the default-route interface (`wifi` | `wired`), measured from
-- the hardware-port table, so an if_mac change can be judged as a Wi-Fi roam
-- or a dock/undock without a readable SSID or BSSID (under root neither is:
-- realm net-observer, nodes #93, #108). NULL = not determinable. Same
-- migration treatment.
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS medium VARCHAR;
-- The current DHCP lease's start (epoch microseconds, NULL when absent /
-- unparseable / a DST fold-gap made the local time ambiguous) and length
-- (seconds), both from the same `ipconfig getsummary` parse as bssid above; a
-- lease-start change is a fresh DHCP exchange, an INIT-REBOOT every few
-- minutes a roam. `if_mac_private` is whether if_mac's U/L bit reads as an
-- administratively-assigned (Private Wi-Fi) address rather than the
-- hardware-burned one; NULL exactly when if_mac is (realm net-observer, node
-- #93 item 1; node #109 item 1). Same migration treatment.
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS lease_start_us BIGINT;
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS lease_secs UINTEGER;
ALTER TABLE link_sample ADD COLUMN IF NOT EXISTS if_mac_private BOOLEAN;
-- `tun_code`: the HTTP status the TUN probe got; 0 = probed, no HTTP status
-- (the shell oracle's curl 000) — the dead tun every reading takes it for;
-- NULL = not probed (passive tier, preflight skip), neither health nor fault.
CREATE TABLE IF NOT EXISTS proxy_sample (
  ts_us BIGINT, server_ip VARCHAR, tcp VARCHAR, rtt_ms DOUBLE, tun_code USMALLINT, selector VARCHAR);
-- Established-flow discriminator: whether the held reference streams (direct
-- underlay / through the tunnel) still carried data this tick, and their age at
-- the check (on a dead check: the age at death). Per-tick facts replicated
-- across the tick's rows like tun_code; NULL = no measurement. Added after the
-- proxy table first shipped — same migration treatment as link_sample above.
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS est_direct_alive BOOLEAN;
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS est_direct_age_s UINTEGER;
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS est_tun_alive BOOLEAN;
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS est_tun_age_s UINTEGER;
-- sing-box's OWN URL test of one node under the selector group, as its Clash
-- API shows it THIS tick (`GET /proxies/<node>` -> history), read each tick
-- for every node under the group and never triggered by this daemon (realm
-- net-observer, node #62). `urltest_node` names the node whose reading this
-- row carries; a row carries at most one, on the row of the node's own
-- endpoint (server_ip), so `tcp` beside it is that listener's raw
-- reachability -- or on a reading-only row (tcp = SKIP, no rtt) when the
-- endpoint's row is taken by another node on the same endpoint, or unknown,
-- or was not probed (the passive tier: a local read, so the reading still
-- lands). `urltest_ms` is the newest entry's delay and `urltest_at_us` its
-- time; sing-box writes an entry only for a SUCCESSFUL test -- 0 ms is a real
-- sub-millisecond answer -- and DELETES the node's entry on a failed one, so
-- a failure shows only as the entry going ABSENT: `urltest_absent_since_us`
-- is the tick the collector first read the history empty after having seen
-- an entry, kept across later empty reads and cleared by an entry (its
-- memory is per process: a restart, bracketed by the startup observing edge,
-- starts it over). Dated ONLY for a member of a URLTest-typed group, the one
-- kind sing-box re-tests on an interval: a node selected directly in a
-- Selector is never re-tested, and its entry vanishing on a sing-box restart
-- or a failed manual test is not evidence, so the column stays NULL for it.
-- NULL node = no reading on this row; NULL `urltest_ms` with NULL
-- `urltest_absent_since_us` under a named node = never seen tested, or not a
-- re-tested node: not measured. Same migration treatment.
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS urltest_ms UINTEGER;
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS urltest_at_us BIGINT;
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS urltest_node VARCHAR;
ALTER TABLE proxy_sample ADD COLUMN IF NOT EXISTS urltest_absent_since_us BIGINT;
CREATE TABLE IF NOT EXISTS incident (
  id VARCHAR PRIMARY KEY, opened_us BIGINT, closed_us BIGINT, trigger_id VARCHAR, signature VARCHAR);
CREATE TABLE IF NOT EXISTS blob_ref (
  id VARCHAR, incident_id VARCHAR, ts_us BIGINT, kind VARCHAR, path VARCHAR);
CREATE TABLE IF NOT EXISTS trigger_fired (
  ts_us BIGINT, trigger_id VARCHAR, incident_id VARCHAR, detail VARCHAR);
CREATE TABLE IF NOT EXISTS dns_sample (
  ts_us BIGINT, probe VARCHAR, server VARCHAR, verdict VARCHAR, ip VARCHAR, rtt_ms DOUBLE);
CREATE TABLE IF NOT EXISTS route_event (
  ts_us BIGINT, kind VARCHAR, iface VARCHAR, detail VARCHAR);
CREATE TABLE IF NOT EXISTS host_sample (
  ts_us BIGINT, load1 DOUBLE, load5 DOUBLE, load15 DOUBLE);
-- The usage of the volume holding this very file (used fraction 0-100 and
-- free MiB, as `df` computes them) and the swap in use, MiB: the ENOSPC and
-- memory-pressure discriminators the retired shell oracle carried, measured
-- as decided at (realm net-observer, node #123). A store write that fails for
-- want of space is logged as a gap; these columns let the record name the
-- cause. NULL = not measured, never a zero. Added after the host table first
-- shipped — same migration treatment as link_sample above.
ALTER TABLE host_sample ADD COLUMN IF NOT EXISTS disk_used_pct DOUBLE;
ALTER TABLE host_sample ADD COLUMN IF NOT EXISTS disk_free_mb UBIGINT;
ALTER TABLE host_sample ADD COLUMN IF NOT EXISTS swap_used_mb UBIGINT;
-- Wi-Fi air quality. `rssi_dbm`/`noise_dbm` are the raw pair as CoreWLAN reported
-- them and `snr_db` is derived from them, so a later change of derivation can be
-- recomputed from the columns that were actually measured.
CREATE TABLE IF NOT EXISTS wifi_sample (
  ts_us BIGINT, wifi VARCHAR, reason VARCHAR, rssi_dbm INTEGER, noise_dbm INTEGER,
  snr_db INTEGER, tx_rate_mbps DOUBLE, phy_mode VARCHAR, channel INTEGER,
  channel_width_mhz INTEGER, channel_band VARCHAR);
-- The radio environment: the foreign access points audible from here.
-- Two tables, and NOT the two shapes `neighbor` uses. There is no long-lived
-- entity table for a foreign AP, because the system report carries no BSSID at
-- all (realm net-observer, node #47): two APs on one channel are indistinguishable
-- between scans, so an AP cannot be followed through time and a row keyed by
-- identity would be a fiction. What the record holds is therefore a series of
-- SLICES: `air_sample` is the scan (including its SKIPs, so a stretch where the
-- radio could not be scanned stays visible) and `air_ap` the access points that
-- one scan heard, joined back by `ts_us`.
-- `air = 'OK'` with `ap_count = 0` is a real reading — the scan ran and heard
-- nobody. `air = 'SKIP'` is the different fact that it could not look, and
-- `reason` says why; the two must never be conflated.
-- Overlap with our own channel is deliberately NOT a column: it is derived by
-- the reader against the `wifi_sample` of the moment, and it is a HYPOTHESIS,
-- since no channel-occupancy figure exists on this platform (node #48).
CREATE TABLE IF NOT EXISTS air_sample (
  ts_us BIGINT, air VARCHAR, reason VARCHAR, ap_count INTEGER);
CREATE TABLE IF NOT EXISTS air_ap (
  ts_us BIGINT, channel INTEGER, channel_band VARCHAR, channel_width_mhz INTEGER,
  phy_mode VARCHAR, security VARCHAR, rssi_dbm INTEGER, noise_dbm INTEGER);
-- Neighbours on the local segment. Two shapes on purpose: `neighbor_sample` is
-- the per-tick reading (including its SKIPs, so a stretch where the caches could
-- not be read stays visible), and `neighbor` is the long-lived entity — one row
-- per (network_key, mac) with first/last seen, upserted on every sighting.
-- Writing a row per device per tick would bury the file for no added fact.
-- `network_key` is the gateway's MAC: it tells the coworking 192.168.1.0/24 from
-- the home one, which neither the subnet nor the SSID does.
-- `source` is how the device was LAST seen: 'arp'/'ndp' means the daemon merely
-- read a cache, 'sweep'/'mdns' that an operator scan found it, 'announce' that
-- the device said so itself — an ARP, mDNS, SSDP or DHCP frame it put on the
-- segment, heard by the passive listener (realm net-observer, node #92). A
-- passive tick after a scan therefore sets it back to 'arp' — the authoritative
-- record of the daemon ever having spoken is `neighbor_scan`, not this column.
-- A hostname a scan or an announcement learned survives, because the upsert
-- coalesces it.
CREATE TABLE IF NOT EXISTS neighbor_sample (
  ts_us BIGINT, network_key VARCHAR, iface VARCHAR, verdict VARCHAR, reason VARCHAR,
  neighbor_count INTEGER);
-- The announce listener's frame counts for the window this reading flushed:
-- `heard_frames` is every frame the capture delivered; `own_frames` is, of
-- those, the frames this machine itself sent that match the capture filter —
-- the OS's own traffic and, during an operator-pressed scan, the sweep's
-- ARP and the mDNS browse; never the periodic probes (ICMP, TCP and DNS do
-- not pass the filter) — recognised by the interface's own MAC as read at
-- that window's start, counted and dropped from the neighbour map. It says the listener saw itself and ignored it, nothing
-- more: the passivity proof stays the frozen pcap slice (realm net-observer,
-- node #88). Both NULL on a neighbour-cache tick and on a scan (they count no
-- frames), never a zero; `heard_frames = 0` is a window in which the segment
-- said nothing, and `own_frames` NULL under a non-NULL `heard_frames` is a
-- window whose own MAC could not be read, so nothing was dropped as ours
-- (realm net-observer, node #92). Added after the table first shipped — same
-- migration treatment as link_sample.
ALTER TABLE neighbor_sample ADD COLUMN IF NOT EXISTS heard_frames UINTEGER;
ALTER TABLE neighbor_sample ADD COLUMN IF NOT EXISTS own_frames UINTEGER;
-- Observations the window's caps refused (a sighting past the device cap, an
-- address or service past its per-device cap, a DHCP name past the pending
-- cap, a service announced on another host's behalf): how much a flush lost.
-- NULL exactly when heard_frames is (not a listener flush); 0 when nothing
-- was refused. Same migration treatment.
ALTER TABLE neighbor_sample ADD COLUMN IF NOT EXISTS dropped_obs UINTEGER;
CREATE TABLE IF NOT EXISTS neighbor (
  network_key VARCHAR, mac VARCHAR, ip VARCHAR, iface VARCHAR, oui VARCHAR,
  hostname VARCHAR, source VARCHAR, first_seen_us BIGINT, last_seen_us BIGINT,
  PRIMARY KEY (network_key, mac));
-- A service a neighbour announced, heard passively by the announce listener.
-- Keyed by (network_key, mac, service) with first/last seen, like
-- `neighbor_port`: "this device has been announcing _companion-link._tcp since
-- X" is the queryable fact, and an announcement repeated every few seconds is
-- one row. `service` is WHAT was announced (an mDNS service type, an SSDP
-- notification type, a DHCP role such as 'dhcp-server' or 'vendor-class'),
-- `kind` which protocol carried it ('mdns' | 'ssdp' | 'dhcp'), `detail` the
-- specifics that came with it (the mDNS instance name, the SSDP SERVER string,
-- the DHCP message type or vendor class), `ip` the address it was announced
-- from (NULL for a DHCP client still without one). A later sighting that
-- carries no ip or detail keeps the ones already learned. (realm net-observer,
-- node #92)
CREATE TABLE IF NOT EXISTS neighbor_service (
  network_key VARCHAR, mac VARCHAR, ip VARCHAR, service VARCHAR, kind VARCHAR,
  detail VARCHAR, first_seen_us BIGINT, last_seen_us BIGINT,
  PRIMARY KEY (network_key, mac, service));
-- One row per operator-pressed scan: what was asked for, how far it reached and
-- what came back. Without it, "these hosts accumulated passively" and "I went and
-- probed the segment" become indistinguishable after the fact.
CREATE TABLE IF NOT EXISTS neighbor_scan (
  ts_us BIGINT, network_key VARCHAR, iface VARCHAR, method VARCHAR, target VARCHAR,
  found INTEGER, duration_ms BIGINT, detail VARCHAR);
-- Open ports found on a neighbour by an operator-pressed port scan. Keyed by
-- (network_key, mac, port) with first/last seen, like `neighbor`: "445 has been
-- open on this device since X" is the queryable fact. A port is attributed to a
-- device by joining the finding's IP to the neighbour that owns it; a port on an
-- address no neighbour claims is dropped, because the row is keyed by MAC.
CREATE TABLE IF NOT EXISTS neighbor_port (
  network_key VARCHAR, mac VARCHAR, ip VARCHAR, port INTEGER,
  first_seen_us BIGINT, last_seen_us BIGINT,
  PRIMARY KEY (network_key, mac, port));
-- `banner` is the raw text a service volunteered when the banner rung grabbed it
-- (NULL when that rung did not run or nothing readable came back). Added after
-- the port table first shipped, so an older database file keeps its column set
-- until this ALTER runs on open, exactly like `observing_edge.cause` below.
ALTER TABLE neighbor_port ADD COLUMN IF NOT EXISTS banner VARCHAR;
-- A CVE the `cve` rung hypothesised for an open port, from matching its grabbed
-- banner against the local snapshot. Keyed by (network_key, mac, port, cve_id)
-- with first/last seen, like `neighbor_port`: "this CVE has been hypothesised
-- for 22 on this device since X". Every row is a HYPOTHESIS, not an asserted
-- fact -- `confidence` (low|medium|high) and `known_exploited` say how much to
-- trust it, and `cvss` its severity when the record carried one (NULL otherwise).
CREATE TABLE IF NOT EXISTS neighbor_vuln (
  network_key VARCHAR, mac VARCHAR, port INTEGER, cve_id VARCHAR,
  confidence VARCHAR, known_exploited BOOLEAN, cvss DOUBLE,
  first_seen_us BIGINT, last_seen_us BIGINT,
  PRIMARY KEY (network_key, mac, port, cve_id));
-- Switch-topology links learned passively from received LLDP/CDP frames: which
-- switch/AP an interface uplinks to, and on which of that device's ports. Keyed
-- by (iface, remote_chassis, remote_port) with first/last seen, like `neighbor`
-- and `neighbor_port` — "this interface has uplinked to that switch:port since
-- X" is the queryable fact. `learned_via` is 'lldp' or 'cdp'. Every row is a
-- HYPOTHESIS: LLDP/CDP are unauthenticated and spoofable. Added after the store
-- first shipped, so `CREATE TABLE IF NOT EXISTS` lets an older DB file migrate on
-- open. (realm net-observer, node #42)
CREATE TABLE IF NOT EXISTS topology_link (
  iface VARCHAR, remote_chassis VARCHAR, remote_port VARCHAR,
  remote_system_name VARCHAR, capabilities VARCHAR, learned_via VARCHAR,
  first_seen_us BIGINT, last_seen_us BIGINT,
  PRIMARY KEY (iface, remote_chassis, remote_port));
-- What this machine talks to: the live flows sing-box carries, read from its
-- Clash API each tick and aggregated by (host, dst_ip, dst_port, process,
-- network, chain) — `count` is how many flows shared the key, `upload` /
-- `download` their bytes summed (realm net-observer, nodes #75, #127). One row
-- per aggregate row per tick, the tick's `verdict` replicated across them. A
-- tick with NO rows — the API did not answer (`SKIP`) or it listed nothing
-- (`OK`) — writes ONE row with every key column NULL, carrying the verdict:
-- so "could not look" and "nothing is talking" are different rows, and both
-- are rows rather than an absent tick. A stretch with no rows at all before
-- some instant is pruned time, not absent ticks, exactly when a `record_prune`
-- row (below) brackets it. `network` is NULL only on that row.
-- `chain` is the outbound that actually carried the flow — the first element
-- of the Clash API's `chains` (sing-box lists them node-first; the last is the
-- constant top-level selector).
CREATE TABLE IF NOT EXISTS connection_sample (
  ts_us BIGINT, verdict VARCHAR, host VARCHAR, dst_ip VARCHAR, dst_port USMALLINT,
  process VARCHAR, network VARCHAR, chain VARCHAR, count UINTEGER, upload UBIGINT,
  download UBIGINT);
-- Where `dst_ip` lies ('internal' | 'lan' | 'external'), judged once by the
-- collector against sing-box's own listeners from its rendered config, so the
-- readers can show the world by default and fold the plumbing — 1023 of 1080
-- flows in one measured tick were DNS queries to the TUN address (realm
-- net-observer, node #75). NULL on the empty-tick marker row, and on rows
-- written before the column existed; a reader treats that NULL as 'external'
-- (shown, never hidden). Added after the table first shipped — same migration
-- treatment as `observing_edge.cause` below.
ALTER TABLE connection_sample ADD COLUMN IF NOT EXISTS scope VARCHAR;
-- The egress interface the flow actually left through, derived once by the
-- collector from `chain` and sing-box's rendered config (realm net-observer,
-- node #75, third paragraph): the TUN interface name for a tunneled flow,
-- the physical interface for a `direct`-typed outbound, the literal
-- 'blocked' for a `block`-typed one. NULL on the empty-tick marker row, on a
-- chain naming an outbound the config does not, and on rows written before
-- the column existed — never invented. Same migration treatment as `scope`
-- above.
ALTER TABLE connection_sample ADD COLUMN IF NOT EXISTS iface VARCHAR;
-- sing-box's own ERROR/WARN lines, read passively from its log and classed
-- (realm net-observer, nodes #140, #141): one row per (class, node) per tick
-- of the `singbox-log` collector, `count` lines of that class seen in the
-- tick, `node` the outbound the line names (NULL when it names none),
-- `sample_message` the first such line's message, ANSI stripped and bounded.
-- A tick with no ERROR/WARN line writes NO row: the absence of errors is the
-- healthy state, and the tick itself is evidenced by the other collectors. A
-- tick on which the log could not be read writes one `unreadable` row with
-- count 0 and the I/O error as its message — SKIP's spirit, never silence.
-- Added after the store first shipped, so an older DB file gains the table on
-- open like `topology_link` above.
CREATE TABLE IF NOT EXISTS singbox_log_sample (
  ts_us BIGINT, class VARCHAR, count UINTEGER, node VARCHAR, sample_message VARCHAR);
CREATE TABLE IF NOT EXISTS observing_edge (
  ts_us BIGINT, observing BOOLEAN, peer_uid BIGINT, cause VARCHAR);
-- `cause` was added after the first daemon shipped rows without it. A database
-- file written by that daemon keeps its three-column table (CREATE TABLE IF NOT
-- EXISTS does nothing to an existing one), and the CLI's offline `query` path
-- opens whatever file it is handed — so the column is added on open. Existing
-- rows read back with a NULL cause, which the gap derivation treats as
-- 'control': that is what they in fact were.
ALTER TABLE observing_edge ADD COLUMN IF NOT EXISTS cause VARCHAR;
-- One row per switch of the probing tier (realm net-observer, node #88). A
-- passive stretch is not a gap — every withheld probe still lands as a SKIP
-- row — but this is what says WHY those rows carry no measurement and who
-- asked for it. `tier` is the tier entered ('passive' / 'active'); `peer_uid`
-- is NULL for the startup edge, which records the configured default so a
-- record that begins passive says so. Added after the store first shipped, so
-- an older DB file gains the table on open like `topology_link` above.
CREATE TABLE IF NOT EXISTS probing_edge (
  ts_us BIGINT, tier VARCHAR, peer_uid BIGINT);
-- `reason` names what produced the edge ('control' | 'startup' | 'experiment'
-- | 'experiment-end'), added when the experiment window landed (realm
-- net-observer, node #61): a passive stretch the operator asked for as a
-- measurement is told apart from one asked for as a state. Rows written
-- before it read back NULL, which the reader treats as 'control' — what
-- they in fact were. Same migration treatment as `observing_edge.cause`.
ALTER TABLE probing_edge ADD COLUMN IF NOT EXISTS reason VARCHAR;
-- One row per finished experiment window (realm net-observer, node #61):
-- its bounds, the tier in force before it, where its two pcap freezes
-- landed (NULL when a freeze copied nothing), and the whole report as JSON
-- — the same `ExperimentReport` the daemon answers `Query(Experiment { id })`
-- with, kept here so a report outlives the daemon process that computed
-- it. Each copied ring file also has a `blob_ref` row (`kind = 'pcap'`,
-- `incident_id` = the window's id), like an incident's freeze. A window the
-- daemon was restarted under leaves no row: its opening `probing_edge`
-- (reason 'experiment') without a closing one is the trace.
CREATE TABLE IF NOT EXISTS experiment (
  id VARCHAR PRIMARY KEY, start_us BIGINT, end_us BIGINT, tier_before VARCHAR,
  report_json VARCHAR);
-- Where the two freezes landed, added after the table first shipped with the
-- five columns above: a file written by that daemon keeps its column set until
-- these ALTERs run on open, exactly like `probing_edge.reason`. Rows from
-- before read back NULL — no path was recorded, not an empty one.
ALTER TABLE experiment ADD COLUMN IF NOT EXISTS freeze_start_dir VARCHAR;
ALTER TABLE experiment ADD COLUMN IF NOT EXISTS freeze_end_dir VARCHAR;
-- One row per retention prune that deleted anything (realm net-observer,
-- node #130): which table, the cutoff it cut at, how many rows went. The
-- bracket for pruned time, as `observing_edge` is for a pause: a table that
-- holds nothing before some instant is either a record that started there or
-- one that was pruned there, and this row is what tells the two apart. A
-- prune that deleted nothing leaves no row. Added after the store first
-- shipped, so an older DB file gains the table on open like `probing_edge`.
CREATE TABLE IF NOT EXISTS record_prune (
  ts_us BIGINT, "table" VARCHAR, cutoff_us BIGINT, deleted UBIGINT);
"#;

/// The record's SAMPLE tables — the ones that take a row per tick (or per
/// event, or per scan slice) and grow without bound. Every table here has a
/// `ts_us` column, and the record's own observation bound
/// ([`crate::DuckdbStore::latest_sample_ts_us`]) is the newest `ts_us`
/// across all of them.
///
/// Not here: `incident`, `blob_ref`, `trigger_fired` (evidence),
/// `observing_edge` / `probing_edge` / `record_prune` (brackets),
/// `neighbor_scan` (the record of the daemon having spoken on the segment),
/// `experiment`, and the keyed entity tables (`neighbor*`, `topology_link`),
/// which hold one row per thing seen and do not grow per tick.
pub const SAMPLE_TABLES: &[&str] = &[
    "link_sample",
    "proxy_sample",
    "dns_sample",
    "route_event",
    "host_sample",
    "wifi_sample",
    "air_sample",
    "air_ap",
    "neighbor_sample",
    "connection_sample",
    "singbox_log_sample",
];

/// The subset of [`SAMPLE_TABLES`] a retention prune may touch — the only
/// names [`crate::Store::prune_older_than`] accepts (realm net-observer, node
/// #130).
///
/// The complement of what the gap derivation reads: `diagnosis::SAMPLE_TS_CTE`
/// takes a tick of `link_sample`, `proxy_sample`, `host_sample`, `dns_sample`
/// or `route_event` as "the daemon was collecting at this instant", and from
/// those instants derives every stop and sleep. Prune one of the five and
/// the derivation reads the pruned stretch as a silence — a fabricated stop
/// or sleep that poisons `verdict_at` and `incident_context` for the
/// incidents the prune kept. So those five are never prunable, whatever
/// config says. `air_sample` and `air_ap` are one scan slice joined by
/// `ts_us`; naming either prunes both halves, each in its own transaction and
/// bracketed by its own `record_prune` row (see [`AIR_SLICE`]).
pub const PRUNABLE_TABLES: &[&str] = &[
    "connection_sample",
    "air_sample",
    "air_ap",
    "wifi_sample",
    "neighbor_sample",
    "singbox_log_sample",
];

/// The two halves of one air scan — the scan row and the access points it
/// heard, joined by `ts_us`. Cutting one without the other leaves orphan
/// `air_ap` rows or scans that read as having heard nobody, so config naming
/// either half makes the sweep prune both, each bracketed by its own
/// `record_prune` row; a failure between the two leaves the slice half-pruned
/// until the next sweep, which is what the two brackets then show.
pub const AIR_SLICE: [&str; 2] = ["air_sample", "air_ap"];
