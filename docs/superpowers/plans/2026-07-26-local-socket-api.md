# observer — local socket API (daemon is the sole DB owner)

> **For agentic workers:** extends the green project at HEAD `318e2bb`. Keep `cargo test --all` + clippy green. The bar must END this change with NO `duckdb` dependency.

**Goal:** `observerd` becomes the only process touching DuckDB and exposes a Unix-domain socket serving a live in-memory `StatusSnapshot`. `observer-bar` stops opening the DB and becomes a pure socket client.

**Why:** DuckDB takes a per-process file lock — a second opener (even read-only) is blocked while the daemon runs, so the bar could only read offline. Routing all reads through the daemon's socket fixes this and gives a truly live glance.

**Spec:** `docs/superpowers/specs/2026-07-24-observer-net-collector-design.md` → "Local API (the daemon is the sole DB owner)".

## Graph
```
Wave 1 (serial): crates/observer-ipc (protocol + blocking client) + config socket fields + workspace member
Wave 2 (parallel): observerd (in-mem snapshot + UnixListener server) | observer-bar (drop duckdb, socket client)
Final gate: cargo test --all + clippy + commit
```

---

## Task 1: `observer-ipc` crate + config (serial)

**Files:** create `crates/observer-ipc/{Cargo.toml,src/lib.rs}`; modify root `Cargo.toml` (member + `[workspace.dependencies]` `observer-ipc = { path = "crates/observer-ipc" }`); modify `crates/config/src/lib.rs` + `observer.example.toml`.

`crates/observer-ipc/Cargo.toml` deps: `types.workspace = true`, `serde.workspace = true`, `serde_json.workspace = true`. **No tokio** (stays runtime-agnostic; the async server lives in observerd).

**Interfaces produced (`observer_ipc::`):**
```rust
use types::{DnsSample, HostSample, LinkSample, ProxySample};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Request { Status, Incidents { limit: usize } }

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct IncidentSummary {
    pub id: String, pub opened_us: i64, pub closed_us: Option<i64>,
    pub trigger_id: String, pub signature: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct StatusSnapshot {
    pub generated_us: i64,
    pub link: Option<LinkSample>,
    pub proxy: Option<ProxySample>,
    pub dns: Option<DnsSample>,
    pub host: Option<HostSample>,
    pub incidents: Vec<IncidentSummary>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Response { Status(StatusSnapshot), Incidents(Vec<IncidentSummary>), Error(String) }

/// Blocking client for the bar: connect, write one newline-JSON request, read one
/// newline-JSON response. Framing = serde_json + '\n'. Connection-refused / no
/// socket ⇒ Err (the caller renders an "offline" state).
pub fn query(sock_path: &str, req: &Request) -> std::io::Result<Response>;

/// std::io framing helpers reused by both sides (server may read them via its own
/// runtime, but these keep the wire format in one place).
pub fn write_frame<W: std::io::Write, T: serde::Serialize>(w: &mut W, v: &T) -> std::io::Result<()>;
pub fn read_frame<R: std::io::BufRead, T: serde::de::DeserializeOwned>(r: &mut R) -> std::io::Result<T>;
```

**config additions** (top-level `Config`, not per-collector): `pub socket_path: String` (default `"/var/lib/observer/observer.sock"`), `pub socket_mode: u32` (default `0o666`). Update `impl Default` + `observer.example.toml`.

- [ ] TDD: a `write_frame`→`read_frame` round-trip test for `StatusSnapshot`/`Request`; a config default test asserting `socket_path`/`socket_mode`.
- [ ] Verify: `cargo test -p observer-ipc && cargo test -p config && cargo build`.

---

## Task 2: `observerd` — in-memory snapshot + socket server (parallel with Task 3)

**Files:** `bin/observerd/Cargo.toml` (add `observer-ipc.workspace = true`), `bin/observerd/src/{main.rs,pipeline.rs}` (+ maybe a new `src/api.rs`).

- **Shared live snapshot:** `let snapshot = Arc::new(std::sync::Mutex::new(observer_ipc::StatusSnapshot::default()));`
  - `pipeline::run` takes the `Arc<Mutex<StatusSnapshot>>`; after `store.write_sample(&sample)`, lock it and set the field for the sample's variant (`link`/`proxy`/`dns`/`host`) + `generated_us = sample.ts_us()`.
  - **Incidents:** add a passive handler `SnapshotHandler { snapshot: Arc<Mutex<StatusSnapshot>>, cap: usize }` implementing `triggers::handlers::Handler`; `on_fire` pushes an `IncidentSummary` (front, truncate to `cap`, e.g. 20). Add it to EVERY trigger's handler list alongside `RecordHandler` in `build_engine`. (DuckDB is still the durable record; this ring is just for the live API.)
- **Socket server:** a tokio task `api::serve(socket_path, socket_mode, snapshot)`:
  - remove any stale socket file, `UnixListener::bind(socket_path)`, then `std::fs::set_permissions(socket_path, Permissions::from_mode(socket_mode))` so the unprivileged bar (daemon runs as root) can connect;
  - per connection: read one newline-JSON `Request`, match: `Status` ⇒ reply `Response::Status(snapshot.lock().clone())`; `Incidents{limit}` ⇒ `Response::Incidents(first `limit` of the ring)`; write newline-JSON, close.
  - spawn it from `main` after opening the store; abort on shutdown alongside the collectors.
- Keep the existing pipeline/trigger behavior otherwise unchanged.
- [ ] Integration test: build a snapshot via the pipeline (fake samples through `run`) and assert the snapshot's `link`/`proxy` fields update; unit-test `SnapshotHandler` caps the ring. (Socket round-trip over a real `UnixListener` may be an `#[ignore]`/tokio test binding a temp path.)
- [ ] Verify: `cargo test -p observerd && cargo build -p observerd`.

SCOPE: `bin/observerd/**` only (config socket fields already added in Task 1). Own `CARGO_TARGET_DIR`, no commit.

---

## Task 3: `observer-bar` — drop DuckDB, become a socket client (parallel with Task 2)

**Files:** `bin/observer-bar/Cargo.toml` (REMOVE `duckdb.workspace`; ADD `observer-ipc.workspace = true`), delete `bin/observer-bar/src/db.rs`, rework `bin/observer-bar/src/status.rs`, update `menubar.rs`/`ui.rs`/`main.rs`.

- Delete `ReadOnlyDb`/`db.rs` and the `duckdb` dep entirely (confirm `grep -rn duckdb bin/observer-bar` is empty afterwards).
- `status.rs`: render an `observer_ipc::StatusSnapshot` (not DuckDB rows). Keep a pure `render_status(&StatusSnapshot) -> String` (or the glyph/`Status` view struct) with unit tests fed a synthetic snapshot. The old `QuerySource`/`read_status`-from-DB is replaced by fetching via the socket.
- Fetch path: the refresh timer calls `observer_ipc::query(&cfg.socket_path, &Request::Status)`. On `Ok(Response::Status(s))` render `s`; on `Err` (daemon down / no socket) render a graceful **"observer offline"** state (grey glyph, message in the panel) — never panic.
- The gpui menu-bar UI (NSStatusItem + panel + `.accessory`) stays; only its data source changes from DB to socket.
- [ ] Verify: `cargo build -p observer-bar && cargo test -p observer-bar && cargo clippy -p observer-bar -- -D warnings`; and `grep -rn "duckdb" bin/observer-bar` returns nothing.

SCOPE: `bin/observer-bar/**` only. Own `CARGO_TARGET_DIR`, no commit.

---

## Final gate
- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`, all green.
- [ ] Confirm `grep -rn duckdb bin/observer-bar` is empty (bar no longer touches the DB).
- [ ] Update `ARCHITECTURE.md`: add `observer-ipc`, the daemon socket server, and the bar-as-client data flow.
- [ ] Commit: `git add -A && git commit -m "feat(ipc): local socket API — observerd serves live StatusSnapshot; observer-bar is a pure socket client (no DuckDB)"`.

## Self-review
- Sole-owner invariant: only `observerd` depends on `store`/`duckdb` for reads on the live path; `observer-bar` has no `duckdb` dep (gate grep). ✓
- Live data: snapshot served from memory, updated by the consumer + incident ring — no DB read on the request path, no lock contention. ✓
- Graceful offline: bar renders an offline state when the socket is absent. ✓
- Type consistency: `StatusSnapshot`/`Request`/`Response`/`IncidentSummary` defined once in `observer-ipc`, used by both daemon and bar. ✓
