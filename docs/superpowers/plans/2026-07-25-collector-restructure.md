# observer — collector restructure (per-crate + OS meta + preflight)

> **For agentic workers:** this is a REFACTOR of an already-built, green v1 (HEAD builds and `cargo test --all` passes). Keep tests green throughout. Steps use `- [ ]` checkboxes.

**Goal:** Split the monolithic `crates/collectors` into `collector-core` (abstractions only) + one crate per collector (`collector-link`, `collector-proxy`), add static per-collector **OS metadata** and a runtime **preflight** capability probe, and rewire `macos` + `observerd` accordingly.

**Starting point:** commit `9623d34` (v1 through `observerd`, green). The existing collector code to move:
- `crates/collectors/src/probes.rs` — `PingOutcome`, `Pinger`, `TcpProber`, `LinkFacts`, `ProxyFacts`.
- `crates/collectors/src/link.rs` — `build_link_sample` (+ tests).
- `crates/collectors/src/proxy.rs` — `build_proxy_samples` (+ tests).
- `crates/macos/*` — impls `SystemFacts: LinkFacts`, `ProxySystemFacts: ProxyFacts`, `IcmpPinger: Pinger`, `BoundTcpProber: TcpProber`.
- `bin/observerd/src/main.rs` — `spawn_link_collector`/`spawn_proxy_collector` bespoke wiring.

## Target crate graph

```
types ──┬── collector-core ──┬── collector-link ──┐
        │                     └── collector-proxy ─┤
        │                                          ├── macos ── observerd
store ──┴──────────────────── triggers ───────────┘
```

- `collector-core` depends on: `types`.
- `collector-link` / `collector-proxy` depend on: `types`, `collector-core`.
- `macos` depends on: `collector-core`, `collector-link`, `collector-proxy` (to impl their port traits) + its I/O crates.
- `observerd` depends on: all of the above.
- `crates/collectors` is DELETED at the end.

## Global constraints

- Preserve every existing behavior and test. `build_link_sample` / `build_proxy_samples` logic and their unit tests move verbatim (only their crate/import paths change).
- Verdict vocabulary, SKIP-not-silence, and the streaming pipeline are unchanged.
- macOS-only v1: both collectors declare `supported_os: &[Os::MacOs]`.

---

## Task A: `collector-core` (abstractions only)

**Files:**
- Create: `crates/collector-core/Cargo.toml`, `crates/collector-core/src/lib.rs`, `.../probes.rs`, `.../meta.rs`, `.../collector.rs`
- Modify: root `Cargo.toml` (add `crates/collector-core` to members; add `collector-core = { path = "crates/collector-core" }` to `[workspace.dependencies]`)

**Interfaces produced:**
- `collector_core::{PingOutcome, Pinger, TcpProber}` — moved verbatim from `collectors::probes` (generic net probes). Add `: Send + Sync` supertrait to `Pinger` and `TcpProber`.
- `collector_core::Os { MacOs, Linux }` with `fn current() -> Os` (`cfg!(target_os="macos")` → MacOs, `cfg!(target_os="linux")` → Linux; default MacOs for v1 with a `#[allow]` note).
- `collector_core::CollectorMeta { name: &'static str, supported_os: &'static [Os] }` + `fn supports(&self, os: Os) -> bool`.
- `collector_core::Readiness { Ready, Unavailable(String) }` with `fn is_ready(&self) -> bool`.
- `collector_core::Source { Interval(std::time::Duration), Event }` — a collector's cadence.
- `collector_core::EventSource: Send` trait: `fn next(&mut self) -> Option<Vec<types::Sample>>` (blocking; `None` ends the stream).
- `collector_core::Collector: Send + Sync` trait:
  ```rust
  fn meta(&self) -> &'static CollectorMeta;
  fn source(&self) -> Source;
  fn preflight(&self) -> Readiness;
  fn collect(&self, ts_us: i64) -> Vec<types::Sample> { Vec::new() }   // interval collectors
  fn skip(&self, ts_us: i64) -> Vec<types::Sample> { Vec::new() }
  fn into_event_source(self: Box<Self>) -> Option<Box<dyn EventSource>> { None }  // event collectors
  ```
  `collector-core` must NOT depend on tokio — `Source`/`EventSource` keep it runtime-agnostic; the async driving of both cadences lives in `observerd`.

`Cargo.toml`:
```toml
[package]
name = "collector-core"
edition.workspace = true

[dependencies]
types.workspace = true
```

- [ ] **Step 1: Create the crate**, move `PingOutcome`/`Pinger`/`TcpProber` from `crates/collectors/src/probes.rs` into `crates/collector-core/src/probes.rs` (add `Send + Sync` supertraits). Do NOT move `LinkFacts`/`ProxyFacts` (they go to their collector crates in Task B).

- [ ] **Step 2: Write `meta.rs`** with `Os`, `CollectorMeta`, `Readiness` + a unit test:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supports_matches_declared_os() {
        const M: CollectorMeta = CollectorMeta { name: "x", supported_os: &[Os::MacOs] };
        assert!(M.supports(Os::MacOs));
        assert!(!M.supports(Os::Linux));
    }
}
```

- [ ] **Step 3: Write `collector.rs`** with the `Collector` trait (signatures above) and `lib.rs` re-exporting everything.

- [ ] **Step 4: Verify** (isolated target): `cargo test -p collector-core` and `cargo clippy -p collector-core -- -D warnings` pass.

---

## Task B: `collector-link` and `collector-proxy` (parallel)

Both new crates depend on `types` + `collector-core`. Each `Cargo.toml`:
```toml
[dependencies]
types.workspace = true
collector-core.workspace = true
[dev-dependencies]        # link/proxy tests use only the above
```
Add both to root `members` + `[workspace.dependencies]` (`collector-link`/`collector-proxy` path deps).

### B1 — `collector-link`

**Interfaces produced:**
- `collector_link::LinkFacts` — the port trait moved from `collectors::probes::LinkFacts`, PLUS a new method `fn preflight(&self) -> collector_core::Readiness;` and `: Send + Sync` supertrait.
- `collector_link::build_link_sample(ts_us, &dyn Pinger, &dyn TcpProber, &dyn LinkFacts) -> LinkSample` — moved verbatim from `collectors::link` (imports rebased onto `collector_core` + local `LinkFacts`). Move its three unit tests too; the fake `LinkFacts` in tests must also impl `preflight()` (return `Readiness::Ready`).
- `collector_link::META: CollectorMeta = { name: "link", supported_os: &[Os::MacOs] }`.
- `collector_link::LinkCollector` implementing `collector_core::Collector`:
  - holds `Arc<dyn Pinger>`, `Arc<dyn TcpProber>`, `Arc<dyn LinkFacts>`, and `interval: Duration`.
  - `meta()` → `&META`; `source()` → `Source::Interval(self.interval)`; `preflight()` → `self.facts.preflight()`;
  - `collect(ts_us)` → `vec![Sample::Link(build_link_sample(ts_us, &*self.ping, &*self.tcp, &*self.facts))]`;
  - `skip(ts_us)` → one `Sample::Link` with `direct: TcpVerdict::Skip`, `gw: GwVerdict::NoGw` (move the existing `link_skip` body here).
  - constructor `LinkCollector::new(ping, tcp, facts, interval)`.

- [ ] **B1.1** Create crate; move `build_link_sample` + tests; add `LinkFacts` (with `preflight`).
- [ ] **B1.2** Add `META` + `LinkCollector`. Unit test: a fake collector with a fake `LinkFacts` returning `Unavailable` yields `preflight().is_ready() == false`; with `Ready` yields a `collect()` of one `Sample::Link`.
- [ ] **B1.3** Verify `cargo test -p collector-link` + `cargo clippy -p collector-link -- -D warnings`.

### B2 — `collector-proxy`

Symmetric to B1:
- `collector_proxy::ProxyFacts` — moved from `collectors::probes::ProxyFacts` + new `fn preflight(&self) -> Readiness;` + `Send + Sync`.
- `collector_proxy::build_proxy_samples(...)` — moved verbatim from `collectors::proxy` (+ tests; fake `ProxyFacts` also impl `preflight` → Ready).
- `collector_proxy::META = { name: "proxy", supported_os: &[Os::MacOs] }`.
- `collector_proxy::ProxyCollector` implementing `Collector`: holds `Arc<dyn TcpProber>`, `Arc<dyn ProxyFacts>`, `tun_url: String`, `iface: String`, `interval: Duration`; `collect` maps `build_proxy_samples(...)` into `Sample::Proxy`; `skip` = the existing `proxy_skip` body; `preflight` delegates to `self.facts.preflight()`.

- [ ] **B2.1–B2.3** mirror B1.1–B1.3 for proxy. Verify `cargo test -p collector-proxy` + clippy.

---

## Task C: rewire `macos` + `observerd`, delete `collectors` (serial)

**Files:**
- Modify: `crates/macos/Cargo.toml` (replace `collectors` dep with `collector-core`, `collector-link`, `collector-proxy`), `crates/macos/src/*` (import `LinkFacts` from `collector_link`, `ProxyFacts` from `collector_proxy`, probes from `collector_core`; ADD `preflight()` to the `SystemFacts: LinkFacts` and `ProxySystemFacts: ProxyFacts` impls).
- Modify: `bin/observerd/Cargo.toml` (deps: add the three collector crates, drop `collectors`), `bin/observerd/src/main.rs` (new generic wiring).
- Delete: `crates/collectors/` and its `members` entry + `[workspace.dependencies]` line.

**macOS preflight impls:**
- `SystemFacts::preflight()` → `if self.phys_iface().is_some() { Ready } else { Unavailable("no physical interface".into()) }`.
- `ProxySystemFacts::preflight()` → Ready if the sing-box config path exists on disk OR a clash api base is set; else `Unavailable("no sing-box config / clash api".into())`.

**New observerd wiring (replaces `spawn_link_collector`/`spawn_proxy_collector`):**
```rust
// Build the enabled collectors as Box<dyn Collector>.
let mut collectors: Vec<Box<dyn Collector>> = Vec::new();
if cfg.collectors.link.enabled {
    collectors.push(Box::new(LinkCollector::new(
        Arc::new(IcmpPinger::new()),
        Arc::new(BoundTcpProber::new()),
        Arc::new(SystemFacts::new(cfg.collectors.link.gw.clone(), cfg.collectors.link.phys_iface.clone())),
        cfg.collectors.link.interval,
    )));
}
if cfg.collectors.proxy.enabled {
    collectors.push(Box::new(ProxyCollector::new(
        Arc::new(BoundTcpProber::new()),
        Arc::new(ProxySystemFacts::new(SINGBOX_CONFIG_PATH, cfg.collectors.proxy.clash_api.clone(), CLASH_SELECTOR_GROUP)),
        cfg.collectors.proxy.tun_probe_url.clone(),
        phys_iface.clone().unwrap_or_default(),
        cfg.collectors.proxy.interval,
    )));
}

// Filter by OS meta + preflight, then spawn survivors with one uniform loop.
let os = Os::current();
let mut handles = Vec::new();
for c in collectors {
    let name = c.meta().name;
    if !c.meta().supports(os) {
        tracing::warn!(collector = name, ?os, "unsupported OS; skipping");
        continue;
    }
    if !c.preflight().is_ready() {
        if let Readiness::Unavailable(reason) = c.preflight() {
            tracing::warn!(collector = name, %reason, "preflight failed; skipping");
        }
        continue;
    }
    // Dispatch on cadence — timer vs event stream.
    match c.source() {
        Source::Interval(_) => handles.push(spawn_interval_collector(c, tx.clone())),
        Source::Event => handles.push(spawn_event_collector(c, tx.clone())),
    }
}
```

`pipeline.rs` gains two spawners (replacing the old closure-based `spawn_collector`):

```rust
/// Interval cadence: drive a timer loop, running collect() on the blocking pool.
pub fn spawn_interval_collector(c: Box<dyn Collector>, tx: mpsc::Sender<Sample>) -> JoinHandle<()> {
    let Source::Interval(interval) = c.source() else { unreachable!("interval spawner") };
    let name = c.meta().name;
    let c: Arc<dyn Collector> = Arc::from(c);
    tokio::spawn(async move {
        let mut ticker = time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let ts_us = types::now_us();
            let c2 = Arc::clone(&c);
            let samples = match tokio::task::spawn_blocking(move || c2.collect(ts_us)).await {
                Ok(s) => s,
                Err(e) => { tracing::warn!(collector = name, error = %e, "probe failed; SKIP"); c.skip(ts_us) }
            };
            for s in samples { if tx.send(s).await.is_err() { return; } }
        }
    })
}

/// Event cadence: a long-lived blocking source belongs on its own OS thread
/// (not repeated spawn_blocking), forwarding via the channel's blocking_send.
pub fn spawn_event_collector(c: Box<dyn Collector>, tx: mpsc::Sender<Sample>) -> JoinHandle<()> {
    let name = c.meta().name;
    let Some(mut src) = c.into_event_source() else {
        tracing::error!(collector = name, "Event cadence but into_event_source() is None");
        return tokio::spawn(async {});
    };
    // Bridge the blocking source into async via a dedicated thread.
    tokio::task::spawn_blocking(move || {
        while let Some(samples) = src.next() {
            for s in samples {
                if tx.blocking_send(s).is_err() { return; }  // consumer gone
            }
        }
        tracing::info!(collector = name, "event source ended");
    })
}
```
No `Event` collector ships in v1 (route-events is `[next]`); this spawner + the
`source()` dispatch exist so an event collector plugs in later with zero daemon
changes. Update the `pipeline.rs` collector test to build a tiny fake
`Box<dyn Collector>` (a 1-tick `Source::Interval` collector) and drive it through
`spawn_interval_collector`.

- [ ] **C.1** Rewire `macos` (imports + preflight impls); `cargo test -p macos` + clippy green.
- [ ] **C.2** Rewrite observerd wiring + `spawn_collector`; keep the pipeline integration test green (adapt the fake collector). `cargo test -p observerd`.
- [ ] **C.3** Delete `crates/collectors` + its root Cargo.toml entries. Confirm nothing references `collectors::`.

---

## Task D: finish `observer-cli` + CI + docs

(The interrupted final wave; the WIP is stashed as `wip-cli-final-wave` — you may `git stash show -p` it for reference or redo fresh.)
- `observer-cli`: `status` / `incidents` / `query <SQL>` subcommands + a `format_incidents` unit test (per original plan Task 14). If the store needs a `QueryTable` helper for `query`, add it to `store` with a test.
- `.github/workflows/lints.yml` + `tests.yml`.
- `ARCHITECTURE.md` (mermaid pipeline + the NEW crate graph above + DuckDB tables), `AGENTS.md` + `CLAUDE.md` symlink, `README.md`.

- [ ] **D.1** Implement cli + tests; `cargo test -p observer-cli`.
- [ ] **D.2** Write CI + docs.

---

## Final gate

- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`, all green (duckdb build may take up to 10 min).
- [ ] Confirm `crates/collectors` is gone and the workspace has `collector-core` + `collector-link` + `collector-proxy`.
- [ ] Commit: `git add -A && git commit -m "refactor: split collectors into per-collector crates with OS meta + preflight; finish cli/ci/docs"`.

## Self-review

- Spec coverage: per-collector crates (A, B) ✓; collector-core abstractions-only (A) ✓; OS metadata (A meta.rs, B META) ✓; preflight probe (A Readiness/Collector, B port `preflight`, C macOS impls + daemon filter) ✓; cli/ci/docs (D) ✓.
- Behavior preserved: `build_*` logic + tests moved verbatim; pipeline/verdicts/SKIP unchanged.
- Type consistency: `Collector`/`CollectorMeta`/`Os`/`Readiness` names used identically across A→C; `spawn_collector` new signature updated in both `pipeline.rs` and its caller + test.
