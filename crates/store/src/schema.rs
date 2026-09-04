pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS link_sample (
  ts_us BIGINT, gw VARCHAR, gw_rtt_ms DOUBLE, direct VARCHAR, direct_rtt_ms DOUBLE,
  dhcp_router VARCHAR, dhcp_dns VARCHAR, gw_arp_mac VARCHAR, ssid VARCHAR, wifi_capture_present BOOLEAN);
CREATE TABLE IF NOT EXISTS proxy_sample (
  ts_us BIGINT, server_ip VARCHAR, tcp VARCHAR, rtt_ms DOUBLE, tun_code USMALLINT, selector VARCHAR);
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
-- read a cache, 'sweep'/'mdns' that an operator scan found it. A passive tick
-- after a scan therefore sets it back to 'arp' — the authoritative record of the
-- daemon ever having spoken is `neighbor_scan`, not this column. A hostname a
-- scan learned survives, because the upsert coalesces it.
CREATE TABLE IF NOT EXISTS neighbor_sample (
  ts_us BIGINT, network_key VARCHAR, iface VARCHAR, verdict VARCHAR, reason VARCHAR,
  neighbor_count INTEGER);
CREATE TABLE IF NOT EXISTS neighbor (
  network_key VARCHAR, mac VARCHAR, ip VARCHAR, iface VARCHAR, oui VARCHAR,
  hostname VARCHAR, source VARCHAR, first_seen_us BIGINT, last_seen_us BIGINT,
  PRIMARY KEY (network_key, mac));
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
CREATE TABLE IF NOT EXISTS observing_edge (
  ts_us BIGINT, observing BOOLEAN, peer_uid BIGINT, cause VARCHAR);
-- `cause` was added after the first daemon shipped rows without it. A database
-- file written by that daemon keeps its three-column table (CREATE TABLE IF NOT
-- EXISTS does nothing to an existing one), and the CLI's offline `query` path
-- opens whatever file it is handed — so the column is added on open. Existing
-- rows read back with a NULL cause, which the gap derivation treats as
-- 'control': that is what they in fact were.
ALTER TABLE observing_edge ADD COLUMN IF NOT EXISTS cause VARCHAR;
"#;
