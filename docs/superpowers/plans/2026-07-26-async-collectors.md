# observer — make collectors async (native async fn, enum dispatch)

> **For agentic workers:** refactor of the green project at HEAD `d65310b`. Keep `cargo test --all` + clippy green; a live smoke follows. Small crates only here (no gpui/duckdb in the touched crates except macos/observerd which use the default warm target).

**Goal:** Collectors and their probe ports become **native `async fn`** (no `async-trait` macro). macOS adapters use async-native I/O. Heterogeneous dispatch via an `enum AnyCollector` in `observerd` (no `dyn`-async, no boxing). The only unavoidable blocking probe (PF_ROUTE `read`) stays on a dedicated thread bridged by a channel.

**Spec:** `docs/superpowers/specs/2026-07-24-observer-net-collector-design.md` → "Collector abstraction" / "Async collectors".

## Principles
- Native `async fn` in traits (Rust ≥1.75). Use static dispatch (generics / the daemon enum) — NOT `dyn` — so no future-boxing and no macro. `#[allow(async_fn_in_trait)]` if the advisory lint fires (internal workspace, not a published API).
- Keep the pure sample-assembly SYNC: `collect()` awaits probes, then a sync `build_*` composes the `Sample`. Async lives only in the probe fakes; mapping tests stay sync-simple.
- No `spawn_blocking` on the interval path. Event (PF_ROUTE) stays thread+channel.

## Graph
```
Wave 1 (serial): collector-core — async Collector trait + async Pinger/TcpProber
Wave 2 (parallel): collector-{link,proxy,dns,route,host} — async ports + async collect + sync build_* + async tests
Wave 3 (serial): macos — async adapters (surge-ping / tokio TcpStream+socket2 / reqwest async / tokio::process); drop ureq
Wave 4 (serial): observerd — enum AnyCollector + async interval loop + event thread-bridge
Final gate: cargo test --all + clippy + commit;  then a live smoke (separate, manual)
```

---

## Wave 1: `collector-core` async trait

**Files:** `crates/collector-core/src/{collector,probes}.rs`.
- `Pinger`/`TcpProber`: methods become `async fn` (`async fn ping_gw(&self, gw:&str) -> PingOutcome`, `async fn connect_bound(&self, host:&str, port:u16, iface:&str) -> PingOutcome`). Keep `: Send + Sync` supertraits.
- `Collector`: `async fn collect(&self, ts_us) -> Vec<Sample>` (default `Vec::new()`); `async fn preflight(&self) -> Readiness`; `source()`/`meta()` stay sync; `skip()` stays sync; `into_event_source()` unchanged.
- `EventSource` stays sync (`fn next(&mut self) -> Option<Vec<Sample>>`) — it runs on a dedicated thread.
- No tokio dependency needed (native async fn). Add `#[allow(async_fn_in_trait)]` on the traits if the lint fires.
- Verify: `cargo test -p collector-core && cargo clippy -p collector-core -- -D warnings`.

## Wave 2: five collector crates (parallel)

Each: port facts trait → `async fn`; `Collector::collect` → `async fn` that awaits the probes then calls the SYNC `build_*`; fakes in tests become `async fn` under `#[tokio::test]`; add `tokio` dev-dep (macros, rt) for tests. Each crate depends on `collector-core` (Wave 1). Own `CARGO_TARGET_DIR` (small crates, cold build is cheap).
- **collector-link**: `LinkFacts` methods `async`; `build_link_sample` stays a SYNC pure fn taking fetched values (`ping: PingOutcome, direct: PingOutcome, gw_addr, dhcp, arp, ssid, wifi_present`) → `LinkSample`. `LinkCollector::collect` awaits `ping_gw`/`connect_bound`/facts, then `build_link_sample(...)`.
- **collector-proxy**: `ProxyFacts` async (`server_endpoints`, `tun_probe`, `selector`, `preflight`); `build_proxy_samples` sync from fetched values; `collect` awaits then builds.
- **collector-dns**: `DnsFacts` async; `build_dns_samples` sync; `collect` awaits.
- **collector-host**: `HostFacts` async (`loadavg`); `build_host_sample` sync; `collect` awaits.
- **collector-route**: Event cadence unchanged — `into_event_source()` returns the (sync) `EventSource`; `collect` stays the default. `preflight` becomes `async` (trivial). Minimal change.
- Verify each: `CARGO_TARGET_DIR=… cargo test -p <crate> && … clippy -p <crate> -- -D warnings`.

## Wave 3: `macos` async adapters (serial)

**Files:** `crates/macos/src/{net,dhcp_arp,wifi,clash,dns,route,host}.rs`, `crates/macos/Cargo.toml`, root `Cargo.toml`.
- **net.rs**: `IcmpPinger` on **surge-ping** async API (`async fn ping_gw`); `BoundTcpProber` via `socket2` (set `IP_BOUND_IF`) → `TcpStream::from_std`/`tokio::net::TcpStream` + `tokio::time::timeout` (`async fn connect_bound`).
- **clash.rs / dns.rs**: swap **ureq → `reqwest` async** (tun-204 status, Clash `now` JSON, DoH JSON with `Accept: application/dns-json`); `reqwest = { workspace = true }` (async; the workspace dep is `default-features=false, rustls-tls, json`). Methods become `async fn`.
- **dhcp_arp.rs / wifi.rs**: subprocesses via `tokio::process::Command` (`.output().await`); methods `async fn`.
- **host.rs**: `getloadavg` stays a sync inline call inside the `async fn loadavg` (instant syscall, no blocking).
- **route.rs**: `PfRouteSource` stays a sync `EventSource` (blocking `read` on a dedicated thread — unchanged).
- Cargo: ensure `tokio` (features: `net`, `time`, `process`, `rt`), `socket2`, `surge-ping`, `reqwest` are deps; **remove `ureq`** from macos and from root `[workspace.dependencies]`.
- Verify: `cargo test -p macos && cargo build --all && cargo clippy -p macos -- -D warnings`.

## Wave 4: `observerd` — enum dispatch + async loop (serial)

**Files:** `bin/observerd/src/{main,pipeline}.rs`.
- Define `enum AnyCollector { Link(LinkCollector), Proxy(ProxyCollector), Dns(DnsCollector), Route(RouteCollector), Host(HostCollector) }` with inherent async methods delegating by match: `async fn collect(&self, ts) -> Vec<Sample>`, `async fn preflight(&self) -> Readiness`, `fn source(&self)`, `fn meta(&self)`, `fn skip(&self, ts)`, `fn into_event_source(self)`.
- Build `Vec<AnyCollector>` from config (replacing `Vec<Box<dyn Collector>>`). Filter by `meta().supports(os)` then `preflight().await`.
- `spawn_interval_collector`: `tokio::time::interval` loop `await`ing `collect(ts).await` (NO `spawn_blocking`); on a collector-internal error the collect returns SKIP samples (collectors handle their own probe errors; the daemon no longer catches a JoinError). Send onto the mpsc.
- `spawn_event_collector`: unchanged (dedicated thread draining the sync `EventSource` into the channel via `blocking_send`).
- Verify: `cargo test -p observerd && cargo build -p observerd`.

## Final gate
- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`, all green.
- [ ] `grep -rn "spawn_blocking" bin/observerd/src` shows none on the interval path (event thread-bridge is fine); `grep -rn "ureq" .` (outside lockfile) is empty.
- [ ] Update ARCHITECTURE.md (async collectors + enum dispatch).
- [ ] Commit: `git add -A && git commit -m "refactor: async collectors (native async fn) + enum dispatch; macOS adapters on async I/O; drop ureq for reqwest async"`.

## After the gate (owner-run): live smoke
Re-run the smoke (short socket path) to prove the async daemon starts, collects rows, serves status, and refuses kickstart when acting is disabled — same checks as before.

## Self-review
- Native async fn, no async-trait macro; enum static dispatch, no dyn/boxing. ✓
- Pure `build_*` stays sync (mapping tests trivial); async only in probe fakes. ✓
- Async-native I/O (surge-ping/tokio/reqwest/tokio::process); PF_ROUTE stays thread-bridged (only true blocker). ✓
- ureq removed; reqwest used ASYNC (the `reqwest::blocking`-in-tokio bug cannot recur). ✓
- No spawn_blocking on the interval path. ✓
