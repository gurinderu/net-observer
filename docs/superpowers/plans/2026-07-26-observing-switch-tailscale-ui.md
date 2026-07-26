# observer — observing on/off switch + Tailscale-style bar UI

> Extends the green project at HEAD `6d7c934`. Keep `cargo test --all` + clippy green; gpui is warm in the default target. GUI look is verified by the human after; automated bar = build + clippy + data-layer tests.

**Goal:** A master **switch** in the menu-bar that turns the observer's **observation on/off** (pause/resume collection — the daemon stays alive and reachable), and a **Tailscale-style redesign** of the panel.

**Not sing-box, not system acting.** The switch controls the daemon's OWN collection only (self-control), so it is NOT gated by `acting.enabled` and never touches the network/proxy.

## Behavior
- `observing = true` (default): collectors run, samples flow to DuckDB, triggers evaluate.
- `observing = false`: collectors are paused — interval collectors skip their probe on each tick; the event (PF_ROUTE) collector stops forwarding; no new samples/incidents. The daemon stays alive, the socket keeps serving (so the switch can turn it back on), and the last snapshot is retained but marked paused.

## Graph
```
Wave 1 (serial): observer-ipc  — ControlCmd::SetObserving(bool) + StatusSnapshot.observing
Wave 2 (serial): observerd     — observing AtomicBool wired into the collector loops + control handler + snapshot
Wave 3 (serial): observer-bar  — Tailscale-style redesign + toggle switch bound to `observing`
Wave 4 (serial): observer-cli  — `observe on|off` subcommand
Final gate: cargo test --all + clippy + commit; then a live relaunch for visual confirmation
```

---

## Wave 1: `observer-ipc`
**Files:** `crates/observer-ipc/src/lib.rs`.
- `ControlCmd` gains `SetObserving(bool)` (alongside `KickstartProxy`).
- `StatusSnapshot` gains `pub observing: bool` (default `true` via `#[derive(Default)]` — set the default explicitly so `Default` yields `true`; if `derive(Default)` gives `false`, implement `Default` by hand so a fresh snapshot reads `observing: true`).
- Add a serde round-trip test for `ControlCmd::SetObserving(true)`.
- Verify: `cargo test -p observer-ipc && cargo build`.

## Wave 2: `observerd`
**Files:** `bin/observerd/src/{main.rs,pipeline.rs,api.rs}`.
- Add `let observing = Arc::new(AtomicBool::new(true));` in `main`.
- **Pause the collectors:** `spawn_interval_collector` and `spawn_event_collector` take an `Arc<AtomicBool>` observing flag:
  - interval: after `ticker.tick().await`, `if !observing.load(Ordering::Acquire) { continue; }` (skip the probe entirely while paused).
  - event: before forwarding each batch, `if !observing.load(Ordering::Acquire) { continue; }` (drop while paused).
- **Snapshot:** add `observing` to what the in-memory `StatusSnapshot` reports — set `snapshot.observing` whenever the flag changes (in the control handler) and initialize it `true`. The api `Status` response carries it.
- **Control handler** (`api.rs`): handle `ControlCmd::SetObserving(b)` → `observing.store(b, Ordering::Release)`, update `snapshot.observing`, reply `ControlResult { ok: true, message: format!("observing {}", if b {"on"} else {"off"}) }`. This is NOT gated by `acting.enabled` (it is benign self-control, not a system action) — but it is still a `Control` request over the same socket; keep the socket-owner hardening as is.
- Verify: `cargo test -p observerd && cargo build -p observerd`.

## Wave 3: `observer-bar` — Tailscale-style redesign + switch
**Files:** `bin/observer-bar/src/ui.rs` (+ `menubar.rs` if the glyph should reflect paused).
- **Visual (Tailscale menu feel):**
  - Adapt to system appearance: read `window.appearance()` (gpui `WindowAppearance`) and pick a LIGHT or DARK token set (don't hardcode dark). Light: near-white surface, dark ink, hairline separators; Dark: dark grey surface. Rounded popover, generous padding.
  - Layout as a clean list (not bordered cards): a header row (app name + the toggle switch on the right), a hairline divider, then label→value rows (gw, direct, tun, selector), a divider, an incidents line, a footer with subtle text actions (Restart sing-box, Refresh, Quit). System font; ~13px rows, ~11px secondary; semantic color only on the values (OK green / bad red / muted).
  - Keep `render_status`/`Status`/`read_fresh`/`send_kickstart` and their tests intact; this is a layout/token change to the view.
- **Toggle switch** (Tailscale-style): a gpui-drawn pill track (`rounded_full`) + a circular knob that sits left (off) / right (on); green track when `snapshot.observing`, grey when off; `.cursor_pointer()` + `on_click` → send `Control(SetObserving(!observing))` (add `send_set_observing(socket, bool)` in ui.rs mirroring `send_kickstart`), then refresh. When off, the header shows a muted "paused" state (grey health dot + "paused").
- Verify: `cargo build -p observer-bar && cargo test -p observer-bar && cargo clippy -p observer-bar -- -D warnings`.

## Wave 4: `observer-cli`
**Files:** `bin/observer-cli/src/main.rs`.
- Add `observe <on|off>` subcommand → sends `Control(SetObserving(bool))`, prints the `ControlResult`; non-zero exit on failure/socket error. Never panic.
- Verify: `cargo build -p observer-cli && cargo test -p observer-cli && cargo clippy -p observer-cli -- -D warnings`.

## Final gate
- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Update `ARCHITECTURE.md`: the observing toggle (self-control, not acting) + the socket `SetObserving` command.
- [ ] Commit: `git add -A && git commit -m "feat: observing on/off switch (pause/resume collection) + Tailscale-style bar UI"`.

## Self-review
- Switch pauses the observer's OWN collection (self-control), not sing-box, not the network — NOT gated by acting.enabled. ✓
- Daemon stays alive + socket serves while paused, so the switch can turn it back on. ✓
- `observing` defaults to `true`; reflected in the snapshot so the switch shows the real state. ✓
- Tailscale look adapts to system light/dark; data-layer tests intact. ✓
