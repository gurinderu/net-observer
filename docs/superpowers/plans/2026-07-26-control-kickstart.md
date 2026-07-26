# observer — control path: manual kickstart (conservative Act layer)

> **For agentic workers:** extends the green project at HEAD `8bfa52b`. Keep `cargo test --all` + clippy green. gpui is warm in the default target — use the DEFAULT target (no CARGO_TARGET_DIR) so observer-bar builds incrementally.

**Goal:** Add a **write/control** path to the local socket with ONE safe action — manually restart sing-box (`launchctl kickstart`). Gated OFF by default; socket hardened for the control path. No automatic watchdog, no kill-switch/portal.

**Spec:** `docs/superpowers/specs/2026-07-24-observer-net-collector-design.md` → "Control path — manual acting".

## Invariants
- `config.acting.enabled = false` by default ⇒ every control request is refused with `ControlResult { ok:false, "acting disabled" }`. Acting NEVER happens automatically — only on an explicit `Control` request.
- Only `observerd` (root) executes actions. Clients just send requests.
- When `socket_owner_uid` is set, the daemon `chown`s the socket to it; operators set mode `0600` when enabling acting.

## Graph
```
Task 1 (serial): observer-ipc Control types + config ActingCfg/socket_owner_uid
Task 2 (serial): observerd actuator (launchctl kickstart) + api Control gating + socket chown
Task 3 (serial): observer-bar "Restart sing-box" action + observer-cli `kickstart` subcommand
Final gate: cargo test --all + clippy + commit
```

---

## Task 1: `observer-ipc` control types + config

**Files:** `crates/observer-ipc/src/lib.rs`, `crates/config/src/lib.rs`, `observer.example.toml`.

- `observer-ipc`: extend the wire protocol (all serde):
```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Request { Status, Incidents { limit: usize }, Control(ControlCmd) }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ControlCmd { KickstartProxy }   // extensible; one action for now

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlResult { pub ok: bool, pub message: String }

// add to Response:
pub enum Response { Status(StatusSnapshot), Incidents(Vec<IncidentSummary>), Control(ControlResult), Error(String) }
```
  Update any exhaustive `match` on `Request`/`Response` accordingly. Add a serde round-trip test for `Request::Control(ControlCmd::KickstartProxy)`.
- `config`: add to `Config`:
```rust
pub socket_owner_uid: Option<u32>,   // default None; when Some, daemon chowns the socket to this uid
pub acting: ActingCfg,

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActingCfg {
    pub enabled: bool,            // default false
    pub singbox_service: String,  // launchctl service target, default "system/sing-box"
}
```
  Add defaults in `impl Default`; update `observer.example.toml` with a commented `[acting]` block + `socket_owner_uid` + a note to set mode `0600` when enabling.
- Verify: `cargo test -p observer-ipc && cargo test -p config && cargo build`.

---

## Task 2: `observerd` — actuator + control handling + socket hardening

**Files:** `bin/observerd/src/api.rs`, a new `bin/observerd/src/acting.rs`, `bin/observerd/src/main.rs`, `bin/observerd/Cargo.toml` (add `libc.workspace = true` if needed for chown-by-uid; `std::os::unix::fs::chown` is stable so libc may be unnecessary).

- **Actuator** (`acting.rs`):
```rust
/// Restart the sing-box LaunchDaemon. observerd runs as root, so it can kickstart
/// a system service. Returns Ok(msg) / Err(msg) — never panics.
pub fn kickstart_proxy(service: &str) -> Result<String, String>;
```
  Implementation: run `launchctl kickstart -k <service>` via `std::process::Command`, capture status/stderr, map to Ok/Err with a readable message. `-k` kills-then-restarts.
- **api::serve** gains the acting config: pass `acting_enabled: bool`, `singbox_service: String`, and `socket_owner_uid: Option<u32>` (or the whole relevant config slice).
  - After bind + set_permissions, if `socket_owner_uid` is `Some(uid)`, `std::os::unix::fs::chown(&socket_path, Some(uid), None)` (log on failure, don't crash).
  - Handle `Request::Control(cmd)`:
    - if `!acting_enabled` ⇒ `Response::Control(ControlResult { ok:false, message:"acting disabled (set acting.enabled=true)".into() })`.
    - else match `cmd`: `KickstartProxy` ⇒ call `acting::kickstart_proxy(&singbox_service)` ⇒ `Response::Control(ControlResult{ ok, message })`.
- **main.rs**: thread the acting config + `socket_owner_uid` into the `api::serve` spawn.
- Tests: unit-test the "acting disabled ⇒ refused" branch (a handler fn that maps a `Request::Control` + `enabled=false` to a refusing `Response::Control` without running anything). Do NOT actually run `launchctl` in tests. Keep the existing socket test green.
- Verify: `cargo test -p observerd && cargo build -p observerd`.

SCOPE: `bin/observerd/**` only (config already has the fields from Task 1). Default target; no commit.

---

## Task 3: clients — bar action + cli subcommand

**Files:** `bin/observer-bar/src/*` (menubar/ui/main), `bin/observer-cli/src/main.rs`.

- **observer-bar**: add a "Restart sing-box" control (menu item / button in the panel) that sends `observer_ipc::query(&cfg.socket_path, &Request::Control(ControlCmd::KickstartProxy))` and surfaces the `ControlResult.message` (e.g. a transient line in the panel). Errors/daemon-down ⇒ graceful message, no panic. Keep the read/refresh path unchanged.
- **observer-cli**: add a `kickstart` subcommand that sends the same `Control(KickstartProxy)` and prints the `ControlResult` (ok/message); non-zero exit on `ok:false` or socket error. Never panic.
- Verify: `cargo build -p observer-bar && cargo build -p observer-cli && cargo test -p observer-cli && cargo clippy -p observer-bar -p observer-cli -- -D warnings`.

SCOPE: `bin/observer-bar/**`, `bin/observer-cli/**`. Default target; no commit.

---

## Final gate
- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`, all green.
- [ ] Sanity: `acting.enabled=false` is the default (grep config default); no code path calls `launchctl` unless a `Control` request arrives AND acting is enabled.
- [ ] Update `ARCHITECTURE.md`: note the control path (Request::Control → actuator, gated by acting.enabled) + socket ownership.
- [ ] Commit: `git add -A && git commit -m "feat(control): manual sing-box kickstart over the socket (acting gated off by default) + bar/cli controls"`.

## Self-review
- Acting off by default; control refused unless explicitly enabled. ✓
- Only observerd executes; clients only request. ✓
- Socket hardening (chown to socket_owner_uid) present. ✓
- One safe action (kickstart); kill-switch/portal + auto-watchdog deferred. ✓
- Wire types (`ControlCmd`/`ControlResult`) defined once in observer-ipc, used by daemon + both clients. ✓
