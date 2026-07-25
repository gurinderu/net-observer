# observer v1.1 — dns/route/host collectors + gpui menu-bar

> **For agentic workers:** extends the green v1 at HEAD `44bab30`. Keep `cargo test --all` + clippy green. Mirror the EXISTING patterns in `collector-link`/`collector-proxy` and `macos` exactly. Steps use `- [ ]` checkboxes.

**Goal:** Add three collectors — `collector-dns` (Interval), `collector-route` (**Event**/PF_ROUTE), `collector-host` (Interval) — activating the dormant `FakeIp` + `Starvation` trigger conditions, and a read-only gpui menu-bar `bin/observer-bar`.

**Spec:** `docs/superpowers/specs/2026-07-24-observer-net-collector-design.md` (Collector abstraction, cadence Interval/Event, verdict vocabulary).

## Existing patterns to mirror (read these first)
- `crates/collector-link/src/{facts.rs,sample.rs,collector.rs,lib.rs}` — port trait (+`preflight`), pure `build_*` fn with fake-based tests, `META` + `Collector` impl (Interval).
- `crates/collector-core/src/collector.rs` — `Collector`, `Source::{Interval,Event}`, `EventSource`.
- `crates/macos/src/{net.rs,dhcp_arp.rs,clash.rs,lib.rs}` — adapter style; `SystemFacts`/`ProxySystemFacts` impl the port traits.
- `bin/observerd/src/main.rs` — collector registration + OS/preflight/cadence dispatch; `crates/triggers/src/{conditions.rs,window.rs}` — `FakeIp`/`Starvation` stubs + window accessors.

## Dependency graph
```
Wave A (serial): types (+3 samples) + store (schema+writes) + root members/deps + 4 stub crates
Wave B (parallel): collector-dns | collector-route | collector-host | observer-bar
Wave C (serial): macos adapters (DnsProber, PfRouteSource, HostMetrics)
Wave D (serial): observerd wiring + activate FakeIp/Starvation (+ window accessors)
Final gate: cargo test --all + clippy + commit
```

---

## Task A: types + store + workspace scaffolding (serial)

**Files:** `crates/types/src/sample.rs`, `crates/types/src/lib.rs`, `crates/store/src/schema.rs`, `crates/store/src/duckdb_store.rs`, root `Cargo.toml`, + stub crates.

- [ ] **A.1 types** — add to `sample.rs` (mirror existing structs; all `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]`):

```rust
use crate::verdict::DnsVerdict;   // add to imports

/// One resolver probe. `probe` is the queried name label (e.g. "nks"), `server`
/// the resolver path label ("sb" | "rtr" | "doh" | "ru"), per the oracle's DNS columns.
pub struct DnsSample {
    pub ts_us: i64,
    pub probe: String,
    pub server: String,
    pub verdict: DnsVerdict,
    pub ip: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// A kernel routing-socket event (PF_ROUTE): iface up/down, addr add/loss, default-route change.
pub struct RouteEvent {
    pub ts_us: i64,
    pub kind: String,     // "iface" | "addr" | "route"
    pub iface: Option<String>,
    pub detail: String,
}

/// Host load sample (1/5/15-min averages) — the starvation discriminator.
pub struct HostSample {
    pub ts_us: i64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
}
```
Extend the `Sample` enum with `Dns(DnsSample)`, `Route(RouteEvent)`, `Host(HostSample)` and add their `ts_us()` match arms. Re-export the three structs from `lib.rs`. Add unit-test arms to the existing `sample_ts_dispatch` test asserting `ts_us()` for each new variant.

- [ ] **A.2 store schema** — append to `SCHEMA_SQL` in `schema.rs`:
```sql
CREATE TABLE IF NOT EXISTS dns_sample (
  ts_us BIGINT, probe VARCHAR, server VARCHAR, verdict VARCHAR, ip VARCHAR, rtt_ms DOUBLE);
CREATE TABLE IF NOT EXISTS route_event (
  ts_us BIGINT, kind VARCHAR, iface VARCHAR, detail VARCHAR);
CREATE TABLE IF NOT EXISTS host_sample (
  ts_us BIGINT, load1 DOUBLE, load5 DOUBLE, load15 DOUBLE);
```

- [ ] **A.3 store writes** — add match arms to `Store::write_sample` in `duckdb_store.rs` for `Sample::Dns/Route/Host` (mirror the existing `Link`/`Proxy` arms). Add a test like the existing `write_and_count_*` for one new variant (e.g. a `host_sample` insert + count).

- [ ] **A.4 scaffolding** — add `crates/collector-dns`, `crates/collector-route`, `crates/collector-host`, `bin/observer-bar` to root `[workspace] members` and `[workspace.dependencies]` (path deps). Add `gpui` and `objc2` to `[workspace.dependencies]` (pick the latest resolving versions; note them). Create COMPILABLE STUBS (Cargo.toml + `src/lib.rs`/`src/main.rs`) for all four so the workspace parses. Do NOT modify macos/observerd yet.

- [ ] **A.5 verify** — `cargo test -p types && cargo test -p store && cargo build` green (600000ms timeout). No commit.

---

## Task B: four crates in parallel

Each new collector crate depends on `types` + `collector-core`; mirror `collector-link` file-for-file. Both port traits gain `preflight(&self) -> Readiness`. Each declares `META { name, supported_os: &[Os::MacOs] }`. Interval collectors set `Source::Interval(interval)`; the route collector sets `Source::Event`.

### B1 — `collector-dns` (Interval)
- `DnsFacts` port: `fn resolve(&self, probe: &str, server: &str) -> (DnsVerdict, Option<String>, Option<f64>);` + `fn probes(&self) -> Vec<(String,String)>;` (the (name,server) pairs to run) + `fn preflight(&self) -> Readiness` (Ready iff at least one resolver path is configured).
- `build_dns_samples(ts_us, &dyn DnsFacts) -> Vec<DnsSample>` — one row per probe pair; fakes in tests. FAKEIP on a `.ru` name is preserved as-is (the facts return the verdict; the collector just records it).
- `META { name:"dns", ... }`, `DnsCollector { facts: Arc<dyn DnsFacts>, interval }` impl `Collector` (collect → `Sample::Dns`; skip → one `DnsSample` with `verdict: DnsVerdict::Skip`).
- Test: fake DnsFacts returning a FAKEIP row ⇒ `build_dns_samples` yields it; preflight unavailable ⇒ not ready.

### B2 — `collector-route` (Event)
- `RouteCollector` holding a `Box<dyn EventSource>` (injected — the real PF_ROUTE source is `macos` in Task C) and `META { name:"route", ... }`.
- `source()` → `Source::Event`; `preflight()` → delegate to a small `RoutePreflight` port (`fn preflight(&self) -> Readiness`, Ready iff a PF_ROUTE socket can be opened) OR accept a `Readiness` at construction from macos. Keep it simple: `RouteCollector::new(source: Box<dyn EventSource>, ready: Readiness)`; `into_event_source()` returns the source.
- Test: a fake `EventSource` yielding two `RouteEvent` batches then `None`; drive `into_event_source().next()` and assert the samples pass through; `preflight()` reflects the constructed `Readiness`.

### B3 — `collector-host` (Interval)
- `HostFacts` port: `fn loadavg(&self) -> Option<(f64,f64,f64)>;` + `fn preflight(&self) -> Readiness` (Ready if loadavg readable).
- `build_host_sample(ts_us, &dyn HostFacts) -> Option<HostSample>` (None when unreadable → collector emits skip).
- `META { name:"host", ... supported_os: &[Os::MacOs, Os::Linux] }` (loadavg exists on both), `HostCollector` impl `Collector`.
- Test: fake returning `(1.0,2.0,3.0)` ⇒ one HostSample; None ⇒ skip.

### B4 — `bin/observer-bar` (gpui, read-only)
- Depends on `store`, `types`, `gpui`, `objc2`. A macOS **menu-bar** app (LSUIElement — no dock icon): an `NSStatusItem` (via `objc2`/`objc2-app-kit`) whose click opens a small gpui panel.
- Data: **read-only** queries against the DuckDB file at the configured `db_path` (open with `DuckdbStore::open` or a read-only connection): the latest `link_sample` (gw/direct), latest `proxy_sample` (tun_code/selector), and the last N `incident` rows.
- Keep the data layer testable: a pure `fn render_status(snapshot: &Status) -> String` (or a `Status` struct built from query rows) with a unit test; the gpui/objc2 view is thin glue verified manually.
- ⚠️ gpui menu-bar is non-standard: if `NSStatusItem`+gpui-panel integration proves infeasible in a first pass, fall back to a plain gpui window titled "observer" showing the same `Status`, and leave a `TODO(menu-bar)` — do NOT block the wave on the status-item glue. Note whichever path was taken in the result.
- Verify: `cargo build -p observer-bar` + `cargo test -p observer-bar` (the `render_status`/`Status` test). Running the GUI is manual.

Each B-unit: touch ONLY its crate dir, own `CARGO_TARGET_DIR`, no root edits, no commit.

---

## Task C: macOS adapters (serial, `macos` crate)

Add to `crates/macos`, implementing the new port traits (mirror `SystemFacts`/`ProxySystemFacts`). Update `macos/Cargo.toml` deps (add `collector-dns`, `collector-route`, `collector-host`) and `lib.rs` exports.

- **`DnsResolver: collector_dns::DnsFacts`** — resolve a name via: sing-box TUN DNS (system resolver), the DHCP resolver (queried directly), Cloudflare DoH (`reqwest` to `https://1.1.1.1/dns-query`), each bound appropriately. `.ru` fakeip detection: if a `.ru` name resolves into the sing-box fakeip range ⇒ `DnsVerdict::FakeIp`. Config-driven probe set (see Task D config).
- **`PfRouteSource: collector_core::EventSource`** — open a `PF_ROUTE` socket (`socket(AF_ROUTE, SOCK_RAW, 0)` via `libc`), `next()` does a blocking `read()` and parses the `rt_msghdr` message type (`RTM_IFINFO`/`RTM_NEWADDR`/`RTM_DELADDR`/`RTM_ADD`/`RTM_DELETE`/`RTM_CHANGE`) into a `RouteEvent`. Hold the socket for the life of the source (the "persistent PF_ROUTE socket" engineering win). Provide a `PfRouteSource::open() -> io::Result<Self>` for the collector's readiness check.
- **`HostLoad: collector_host::HostFacts`** — `libc::getloadavg`.
- Verify: `cargo test -p macos` (parsing/logic tests where feasible; raw socket paths verified manually) + clippy.

---

## Task D: observerd wiring + activate triggers (serial)

- **config** (`crates/config/src/lib.rs`): add `DnsCfg { enabled, interval, monitored_domain: String (default "nks.lab.mirari.ru"), ru_control_domain: String (default a .ru control), doh_url: String (default "https://1.1.1.1/dns-query") }`, `RouteCfg { enabled }`, `HostCfg { enabled, interval }` to `Collectors`, with defaults in `impl Default`. Update `observer.example.toml`.
- **observerd** (`bin/observerd/src/main.rs`): build and push `DnsCollector`, `RouteCollector` (with `macos::PfRouteSource`), `HostCollector` into the `Vec<Box<dyn Collector>>` when enabled. The existing OS/preflight/cadence dispatch already routes `route` through the **Event** branch — no dispatch changes needed. (Confirm the Event branch spawns it.)
- **triggers** — activate the dormant conditions:
  - `window.rs`: add `last_dns() -> Option<&DnsSample>`, `recent_dns(n)`, `last_host() -> Option<&HostSample>` accessors (mirror `last_proxy`/`recent_proxy`).
  - `conditions.rs`: `FakeIp::eval` → fire if any recent `DnsSample` on a `.ru` name has `verdict == DnsVerdict::FakeIp`. `Starvation::eval` → read `last_host().load1` (instead of the hard-coded `0.0`) alongside `last_proxy().tun_code == 0`.
  - Update/extend the existing condition unit tests to cover the now-live behavior (a FAKEIP dns sample fires FakeIp; a high-load host sample + dead tun fires Starvation).
- Verify: `cargo test -p config && cargo test -p triggers && cargo test -p observerd && cargo build --all`.

---

## Final gate
- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`, all green.
- [ ] Update `ARCHITECTURE.md` crate graph + DuckDB table list (dns/route/host) and note `observer-bar`.
- [ ] Commit: `git add -A && git commit -m "feat: dns/route/host collectors (route is Event/PF_ROUTE) + activate fakeip/starvation + gpui menu-bar (read-only)"`.

## Self-review
- Spec coverage: dns/route/host collectors as own crates (B1–B3) ✓; route = Event cadence via EventSource (B2 + C PfRouteSource) ✓; FakeIp/Starvation activated (D) ✓; OS meta + preflight on each (B) ✓; gpui read-only bar (B4) ✓.
- Behavior preserved: existing samples/tables/conditions untouched except additive; new match arms exhaustive (Sample gains 3 variants → update every `match` on Sample: `write_sample`, `ts_us`, and any window push logic — grep `match .*Sample` / `Sample::` to catch all).
- Type consistency: `DnsSample`/`RouteEvent`/`HostSample` fields identical across types↔store↔collectors↔window↔conditions.
