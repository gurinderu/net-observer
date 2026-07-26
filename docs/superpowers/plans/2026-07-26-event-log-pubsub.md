# observer — realtime event log window (pub/sub over the socket)

> Extends the green project at HEAD `ba1928e`. Keep `cargo test --all` + clippy green; gpui warm in the default target. GUI verified by the human after; automated bar = build + clippy + data-layer tests.

**Goal:** A **realtime event log** — a real, resizable, closable window that shows events (samples + incidents) live as they happen, with a **type selector**. Fed by **pub/sub over the local socket** (the daemon pushes; the window subscribes — no polling). The daemon stays the sole DB owner.

## Data flow (push, not poll)
`observerd` runs an internal `tokio::sync::broadcast::Sender<Event>`. The pipeline consumer publishes every `Sample` as an `Event`; incidents publish `Event::Incident` when a trigger fires. A `Request::Subscribe { kinds }` connection is held open and streamed newline-JSON `Event` frames (filtered) until the client disconnects. The window opens ONE persistent subscription (a background thread reading the stream → a gpui model), never polls. When `observing` is off, no samples flow, so subscribers naturally go quiet.

## Graph
```
Wave 1 (serial): observer-ipc  — Event / EventKind / Request::Subscribe + a blocking subscription client
Wave 2 (serial): observerd     — broadcast bus, publish events, streaming Subscribe handler
Wave 3 (serial): observer-bar  — Event-log window (WindowKind::Normal, selector, live list) + open button; remove "Restart sing-box"; ensure separators + Quit
Wave 4 (serial): observer-cli  — `events [--kind K]` live subscribe (also the pub/sub smoke)
Final gate: cargo test --all + clippy + commit; then relaunch for visual confirmation
```

---

## Wave 1: `observer-ipc` (no tokio — stays std/blocking)
**Files:** `crates/observer-ipc/src/lib.rs`.
- `EventKind { Link, Proxy, Dns, Route, Host, Incident }` (serde; `Copy, PartialEq`).
- `Event` enum (serde), tagging each payload:
  `Link(LinkSample) | Proxy(ProxySample) | Dns(DnsSample) | Route(RouteEvent) | Host(HostSample) | Incident(IncidentSummary)`,
  with `fn kind(&self) -> EventKind` and `fn ts_us(&self) -> i64`.
- `Request::Subscribe { kinds: Option<Vec<EventKind>> }` (None = all kinds).
- Streaming semantics: a `Subscribe` connection is NOT answered by a single `Response` — the server streams `Event` frames (newline-JSON via the existing `write_frame`). Client side: a blocking helper `pub fn subscribe(sock_path: &str, req: &Request) -> std::io::Result<Subscription>` where `Subscription` wraps a `BufReader<UnixStream>` and implements `Iterator<Item = std::io::Result<Event>>` (loops `read_frame::<Event>`). One-shot `query()` (Status/Incidents/Control) is unchanged.
- Tests: serde round-trip for `Event::Incident(..)` and `Request::Subscribe { kinds: Some(vec![EventKind::Route]) }`; `Event::kind()`/`ts_us()` for one variant.
- Verify: `cargo test -p observer-ipc && cargo build`.

## Wave 2: `observerd` — broadcast bus + streaming handler
**Files:** `bin/observerd/src/{main.rs,pipeline.rs,api.rs}`.
- Create `let (events_tx, _) = tokio::sync::broadcast::channel::<Event>(1024);` in `main`; pass `events_tx` into the pipeline consumer and the api server.
- **Publish:** in `pipeline::run`, after receiving each `Sample`, send the matching `Event` on `events_tx` (ignore send error when there are no subscribers). Incidents: where a trigger fires and an `Incident`/`IncidentSummary` is recorded (the `SnapshotHandler` path), also publish `Event::Incident`. (Respect `observing`: since paused collectors emit no samples, nothing is published while paused — no extra gating needed.)
- **Subscribe handler** (`api.rs`): on `Request::Subscribe { kinds }`, `let mut rx = events_tx.subscribe();` then loop `rx.recv().await`:
  - `Ok(ev)` → if `kinds` is None or contains `ev.kind()`, `write_frame(&mut stream, &ev).await` (async write); on write error (client gone) break.
  - `Err(Lagged(n))` → log + continue (a slow UI drops old events; acceptable for a tail).
  - `Err(Closed)` → break.
  Keep the connection open for the loop's duration (do NOT close after one write). One-shot requests keep their single-response-then-close path.
- Verify: `cargo test -p observerd && cargo build -p observerd`.

## Wave 3: `observer-bar` — event-log window + bar cleanups
**Files:** `bin/observer-bar/src/*` (new `events.rs` for the window; `ui.rs`; `menubar.rs`).
- **Open it:** add an "Events" action in the panel footer (next to Refresh / Quit) that opens the event-log window.
- **Window:** a real `WindowKind::Normal`, resizable, with a titlebar + close button ("observer — events"). It holds:
  - a **selector** at the top (segmented buttons or a row of toggle chips): `All · incident · route · dns · link · proxy · host`;
  - a **scrollable live list** of rows (`HH:MM:SS` + kind + one-line detail), newest at the bottom, autoscroll to the tail.
- **Subscription:** on open, `observer_ipc::subscribe(&socket_path, &Request::Subscribe { kinds: None })` on a dedicated `std::thread`; each `Event` is pushed into a shared gpui model (an `Entity<EventLog>` holding a capped `VecDeque<Event>`, e.g. last 1000) via the same bridge pattern as the refresh task; the view observes it and re-renders. The selector filters the displayed rows client-side by `EventKind` (subscribe to all; filter in the view) — no re-subscribe needed. On disconnect/daemon-down, show an "offline — reconnecting" note and retry the subscription; never panic.
- **Bar cleanups (as requested):**
  - REMOVE the "Restart sing-box" control from the panel (`control_card`/button). The kickstart capability stays in the daemon + `observer-cli` — just not surfaced in the bar.
  - Ensure the Tailscale list has clear **hairline separators** between sections, and **Quit** is pinned at the **bottom** of the panel (footer).
- Keep `render_status`/`Status`/`read_fresh` + tests intact; add a small pure test for the event-row formatting (`format_event(&Event) -> String`).
- Verify: `cargo build -p observer-bar && cargo test -p observer-bar && cargo clippy -p observer-bar -- -D warnings` AND `! grep -rn "sing-box\|Kickstart\|kickstart" bin/observer-bar/src` (the bar no longer references the restart control).

## Wave 4: `observer-cli`
**Files:** `bin/observer-cli/src/main.rs`.
- Add `events [--kind <link|proxy|dns|route|host|incident>]` → `observer_ipc::subscribe(...)` and print each event live (`ts kind detail`) until Ctrl-C; a missing `--kind` subscribes to all. Graceful on socket error; never panic. (Also the pub/sub smoke.)
- Verify: `cargo build -p observer-cli && cargo test -p observer-cli && cargo clippy -p observer-cli -- -D warnings`.

## Final gate
- [ ] `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all-targets --all-features -- -D warnings`.
- [ ] Confirm `grep -rn "sing-box\|kickstart" bin/observer-bar/src` is empty (Restart removed from the bar).
- [ ] Update `ARCHITECTURE.md`: the broadcast bus + `Subscribe` streaming + the event-log window (pub/sub, not polling).
- [ ] Commit: `git add -A && git commit -m "feat: realtime event-log window via socket pub/sub (broadcast Subscribe stream); remove Restart-sing-box from bar"`.

## Self-review
- Push, not poll: broadcast bus + held-open `Subscribe` stream; the window subscribes once. ✓
- Daemon sole DB owner; window is a socket client. ✓
- Selector filters client-side over a single all-kinds subscription. ✓
- observing=off ⇒ no samples ⇒ stream naturally quiet. ✓
- Restart-sing-box removed from the bar (kept in daemon + cli); separators + Quit ensured. ✓
