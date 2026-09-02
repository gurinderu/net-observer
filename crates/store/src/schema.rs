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
-- Neighbours on the local segment. Two shapes on purpose: `neighbor_sample` is
-- the per-tick reading (including its SKIPs, so a stretch where the caches could
-- not be read stays visible), and `neighbor` is the long-lived entity — one row
-- per (network_key, mac) with first/last seen, upserted on every sighting.
-- Writing a row per device per tick would bury the file for no added fact.
-- `network_key` is the gateway's MAC: it tells the coworking 192.168.1.0/24 from
-- the home one, which neither the subnet nor the SSID does.
-- `source` says whether the daemon merely read a cache ('arp'/'ndp') or actually
-- spoke on the segment ('sweep'/'mdns'), which only an operator scan does.
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
