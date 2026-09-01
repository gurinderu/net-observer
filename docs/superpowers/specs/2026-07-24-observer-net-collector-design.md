# net-observer — Rust network-forensics collector (design)

_Date: 2026-07-24. Seed: `~/projects/wiki/.raw/2026-07-24-net-collector-idea.md`.
Behavioral oracle: `~/projects/nix-config/hosts/mac_aarch64/net-observer.nix`._

## Purpose

Replace the hand-rolled shell daemon `net-observer` (~470-line bash LaunchDaemon)
with a Rust daemon that collects structured network/system telemetry into a
queryable database, so post-incident analysis is a SQL query ("что было в 17:26")
instead of grepping a columnar text log.

**North star: incident forensics.** Optimize for a rich, queryable snapshot of
state *around outages*. Not a live dashboard, not long-term analytics (both can
come later on top of the same DB).

## Scope

**v1 = observation + detection. No acting.** No `launchctl kickstart`, no
watchdog in v1. The daemon collects telemetry and *fires triggers* when a
condition is met, but a trigger's v1 action is passive (record an incident,
freeze the pcap ring, capture one-shot forensics). Notification and acting
(kickstart) are later handlers behind the same interface.

Out of scope for v1: the macOS menu-bar UI, runtime config reload / control
socket, notification channels, any recovery action.

## Locked decisions

- **Maximize Rust.** Prefer pure-Rust crates for every component where a viable
  one exists. Native (C/C++) dependencies are allowed only where there is no
  adequate pure-Rust equivalent, and each such exception is named and justified
  in this doc. Current known native deps: **DuckDB** (C++; the one core
  exception — no pure-Rust engine offers native `ASOF JOIN`, see below) and, for
  v1 only, the **`tcpdump` child** used by `pcap-ring` (the pure-Rust target is
  the `pcap` crate / in-process BPF — see Subsystems).
- **UI: gpui.** Any GUI (the future macOS menu-bar / toolbar) is built with
  `gpui` (Zed's GPU-accelerated Rust UI framework), keeping the UI in Rust too.
  The macOS status-bar item (`NSStatusItem`) needs thin AppKit interop via
  `objc2`; the panel/popover content is gpui. Post-v1, a separate unprivileged
  binary talking to the daemon over a local socket.
- **Language / layout:** Rust cargo workspace, structured like `lightmare`/`beam`
  — `bin/` for binaries, `crates/` for libraries, `flake.nix` + direnv +
  `rust-toolchain.toml`, `Justfile`, `AGENTS.md` (with `CLAUDE.md` symlink),
  `ARCHITECTURE.md`, CI under `.github/workflows`. Config via `figment`, async
  via `tokio`, errors via `thiserror` (libs) / `anyhow` (bins), logging via
  `tracing`.
- **Database: DuckDB**, behind a `Store` trait. Chosen for the forensics north
  star — analytical SQL, columnar scans over months of ticks, and native
  `ASOF JOIN` / `time_bucket`. The correlation work done by hand in the wiki
  ("every gateway-drop is preceded ~5–40s by a CoreCapture Wi-Fi event") is an
  ASOF join. Big blobs (pcap freezes, `log show` dumps, CoreCapture refs) live
  as files on disk, referenced by path from a `blob_ref` row; only metadata in
  the DB.
- **Three layers, v1 ships the first two:** Collect → Detect/Trigger → (Act
  later). The trigger engine is a first-class, generic abstraction:
  `condition → handler`. Concrete actions are swappable handler implementations.
- **Per-subsystem toggles, not a verbosity tier.** Each collector is
  independently enabled/disabled with its own frequency (a constructor, not an
  off/normal/debug dial).
- **Privilege split:** `net-observerd` is a headless **root** LaunchDaemon (needs raw
  ICMP, PF_ROUTE, tcpdump, `arp -d`, reading the sing-box config). `net-observer-cli`
  is unprivileged and reads the DB. A future toolbar is a separate unprivileged
  UI over a local socket — never the daemon itself.

## Architecture

```
Collectors ──Sample──▶ [stream: mpsc/broadcast] ──┬──▶ StoreWriter ──▶ DuckDB
                                                   └──▶ TriggerEngine ──▶ Handlers
```

- **Collectors** — one tokio task per subsystem, each on its own interval,
  emitting typed `Sample`s onto the stream.
- **StoreWriter** — batches `Sample`s into DuckDB via the Appender API (single
  writer). Big blobs are written to disk; a `blob_ref` row records the path.
- **TriggerEngine** — holds a small in-memory window of the last N ticks.
  Two-level rules:
  - **Hot rules** (wedge, gw-drop) evaluated synchronously on each `Sample` off
    the stream, so a freeze happens *before* the slow `arp`/`log show` work and
    before the pcap ring rotates over the packets around the drop.
  - **Analytical rules** (ASOF correlations) expressed as SQL views over DuckDB
    for post-hoc analysis.
- **net-observerd** — the root daemon: load config, spawn enabled collectors + the
  store writer + the trigger engine, supervise them.
- **net-observer-cli** — ad-hoc DB queries, status, manual trigger/dump (debugging).

### Communication model (chosen: streaming pipeline)

Considered: (A) event-stream pipeline, (B) store-centric SQL polling, (C) hybrid
with a shared in-memory ring. Chosen **A** with a small recent-window kept inside
the TriggerEngine (a light C). Rationale: clean collect/store/detect separation,
synchronous freeze timing, and the future toolbar becomes just another stream
subscriber. SQL polling (B) was rejected because freeze-before-slow-work timing
is hard when triggers wait on DB round-trips.

## Data model (DuckDB)

Normalized per subsystem — each has its own timestamp and cadence; cross-stream
correlation is via `ASOF JOIN`.

- `link_sample(ts, gw_verdict, gw_rtt_ms, direct_verdict, direct_rtt_ms,
  dhcp_router, dhcp_dns, gw_arp_mac, ssid, wifi_capture_present)`
- `dns_sample(ts, probe, server, verdict, ip, rtt_ms)` — probe/server dims:
  `nks[sb]`, `ru[sb]`, `nks[rtr]`, `nks[doh]`, `site`
- `proxy_sample(ts, server_ip, tcp_verdict, rtt_ms, tun_code, selector)`
- `host_sample(ts, load1, load5, load15)`
- `route_event(ts, kind, iface, detail)` — PF_ROUTE event stream
- `incident(id, opened_ts, closed_ts, trigger_id, signature)`
- `blob_ref(id, incident_id, ts, kind, path)` — pcap freeze, `log show` dumps,
  CoreCapture refs
- `trigger_event(ts, trigger_id, incident_id, detail)`

**Verdict vocabulary** ported from the oracle: DNS
`OK / FAKEIP / EMPTY / SERVFAIL / NXDOMAIN / TIMEOUT / SKIP`; gateway
`OK / FAIL / NOGW`. `FAKEIP` on a `.ru` name is always a bug. `SKIP` means a
prerequisite was missing — it is recorded explicitly, never omitted (absence of
a signal is itself diagnostic).

## Trigger engine

```rust
trait Condition { fn eval(&self, window: &RecentWindow) -> Option<Fire>; }
trait Handler   { async fn on_fire(&self, ctx: &FireCtx) -> Result<Vec<BlobRef>>; }

struct Trigger {
    id: TriggerId,
    condition: Box<dyn Condition>,
    handlers: Vec<Box<dyn Handler>>,
    backoff: Duration,     // min interval between fires
    armed: bool,           // disarm on fire, re-arm on return to OK
}
```

- **Re-arm / backoff** mirror net-observer: fire → disarm; return to OK → re-arm;
  at most one fire per 5 minutes per trigger (a captive portal can mimic a wedge
  signature — don't storm).
- **v1 handlers (passive):** `OpenIncident`, `FreezePcap`, `CaptureDumps`
  (`log show`, CoreCapture refs).
- **Later, same interface:** `Notify` (Notification Center / ntfy), `Act`
  (kickstart sing-box).
- **Starter rules** (ported from the oracle):
  - **wedge:** `tun=000 && direct=OK` for 3 consecutive ticks (~2 min).
  - **gw-drop:** `gw=FAIL` / `NOGW`.
  - **unconditional pcap freeze on any gateway change** (fast router-side drops
    fail over within one tick — the 2026-07-15 coworking signature).
  - **fakeip:** a `.ru` name answered from the fakeip range.
  - **starvation:** `load` in the tens while `tun=000`.

## Subsystems (per-subsystem toggle + interval)

- `link` — gw ping, direct TCP to 1.1.1.1 bound to the physical iface, DHCP
  lease router/dns, gw ARP entry, Wi-Fi CoreCapture presence, SSID. **[v1]**
- `proxy-probes` — per-VLESS TCP reachability, tun HTTP 204, clash selector
  (`now` via Clash API on 127.0.0.1:9090), sing-box pid. **[v1]**
- `pcap-ring` — continuous small ring capture (control traffic only:
  `arp or icmp or udp port 67/68 or ether broadcast`, `-s128`, ~8 MB) on the
  physical iface, frozen on incident. v1 wraps a `tcpdump` child and freezes by
  copying the ring files (the proven net-observer path); the pure-Rust target is
  in-process capture via the `pcap` crate / raw BPF, which also serves the
  "fewer subprocess spawns" goal — migrate once v1 parity is proven. **[v1]**
- `dns` — resolver probes (sing-box TUN DNS, DHCP resolver, DoH, control
  domain). **[v1.1]**
- `route-events` — persistent PF_ROUTE socket monitor (iface up/down, addr
  add/loss, default-route changes); first **Event**-cadence collector. **[v1.1]**
- `host-metrics` — host load / starvation signals. **[v1.1]**

## Collector abstraction (`collector-core`)

Every collector implements one trait and carries two capability signals — a
static OS declaration and a runtime preflight — so the daemon can decide, per
collector, whether to run it at all.

```rust
pub enum Os { MacOs, Linux }
impl Os { pub fn current() -> Os; }        // via cfg!(target_os = ...)

pub struct CollectorMeta {
    pub name: &'static str,
    pub supported_os: &'static [Os],        // static: which OSes this collector targets
}
impl CollectorMeta { pub fn supports(&self, os: Os) -> bool; }

pub enum Readiness { Ready, Unavailable(String) }   // runtime: CAN it work here/now?

/// How a collector produces samples — not everything is a timer.
pub enum Source {
    Interval(Duration),   // poll on a timer: link, proxy, dns, host
    Event,                // driven by an OS event stream: route-events (PF_ROUTE), ...
}

/// A blocking system-event source. `next()` blocks until the next event and
/// returns its sample(s); `None` ends the stream. A blocking read on a PF_ROUTE
/// socket maps onto this directly; the daemon runs it on the blocking pool.
pub trait EventSource: Send {
    fn next(&mut self) -> Option<Vec<Sample>>;
}

pub trait Collector: Send + Sync {
    fn meta(&self) -> &'static CollectorMeta;
    fn source(&self) -> Source;                       // Interval(d) or Event (sync metadata)
    async fn preflight(&self) -> Readiness;           // deps present? perms? reachable?
    // Interval collectors implement collect()/skip(); event collectors override into_event_source().
    async fn collect(&self, ts_us: i64) -> Vec<Sample> { Vec::new() }  // one async tick
    fn skip(&self, ts_us: i64) -> Vec<Sample> { Vec::new() }           // SKIP on probe failure (pure)
    fn into_event_source(self: Box<Self>) -> Option<Box<dyn EventSource>> { None }
}
```

**Async collectors (native `async fn`, no macro).** The probe ports
(`Pinger`/`TcpProber`/`LinkFacts`/`ProxyFacts`/`DnsFacts`/`HostFacts`) and
`Collector::{collect, preflight}` are native `async fn`. The macOS adapters use
async-native I/O: `surge-ping` (ICMP), `tokio::net::TcpStream` + `socket2`
(`IP_BOUND_IF`), `reqwest` async (tun-204 / DoH / Clash), `tokio::process`
(`ipconfig`/`arp`/`networksetup`/`tcpdump`), `getloadavg` inline. **No
`spawn_blocking` on the interval path.** The pure sample-assembly (`build_link_sample`
etc.) stays SYNC — `collect()` `await`s the probes, then a sync `build_*`
composes the `Sample` from the fetched values, so mapping stays trivially
testable while async lives only in the probe fakes (`#[tokio::test]`).

Heterogeneous dispatch without `dyn`-async friction: `net-observerd` holds an
`enum AnyCollector { Link(..), Proxy(..), Dns(..), Route(..), Host(..) }` and
matches per method (native `async fn`, zero boxing, zero macros). `collector-core`
defines the trait but cannot enumerate the concrete collectors, so the enum lives
in the daemon.

**Cadence — timer vs event.** The daemon dispatches on `source()`:
- `Interval(d)` — a `tokio::time::interval` loop `await`ing `collect(ts_us)` every `d`.
- `Event` — the collector's `into_event_source()` blocking `next()` runs on a
  dedicated OS thread bridged to the async daemon via a channel. PF_ROUTE's
  `read(2)` is genuinely uninterruptible-blocking, so it stays on a thread
  regardless — the only truly blocking probe. `collector-core` still declares no
  tokio dependency it can avoid; the async driving lives in `net-observerd`.

`pcap-ring` is not a sample-producing collector — it is continuous capture
infrastructure (in `macos`) frozen on a trigger, not a stream of `Sample` rows.

- **Static OS metadata** (`supported_os`) — v1 collectors declare `&[Os::MacOs]`;
  a future Linux collector adds `Os::Linux`. The daemon skips a collector whose
  meta does not `supports(Os::current())`.
- **Preflight probe** (`preflight`) — the runtime "can this collector work at
  all here?" check, delegated to the collector's port facts:
  - `link` — Ready iff a physical interface is resolvable; else
    `Unavailable("no physical interface")`.
  - `proxy` — Ready iff the sing-box config path exists (or the Clash API is
    configured); else `Unavailable("no sing-box config / clash api")`.
  A collector that fails preflight is not spawned; the reason is logged (absence
  of a signal is itself diagnostic) and may be recorded as an incident later.

The daemon holds `Vec<Box<dyn Collector>>`, filters by `meta().supports(...)`
then `preflight()`, and spawns the survivors with one uniform interval loop
(replacing the per-collector `spawn_link`/`spawn_proxy` glue). The port traits
(`Pinger`, `TcpProber` in `collector-core`; `LinkFacts` in `collector-link`,
`ProxyFacts` in `collector-proxy`, each gaining a `preflight()`) keep all
mapping logic unit-testable with fakes; `macos` provides the real adapters.

## Workspace layout

```
observer/
  bin/
    net-observerd/        # headless root LaunchDaemon
    net-observer-cli/     # ad-hoc queries, status, manual trigger/dump
    # net-observer-bar/   # [post-v1] gpui menu-bar UI over a local socket
  crates/
    types/            # Sample, Verdict enums, Incident, TriggerEvent
    store/            # Store trait + DuckDB backend, schema, migrations, blob refs
    collector-core/   # ABSTRACTIONS ONLY: Collector trait, probe ports (Pinger/
                      #   TcpProber), CollectorMeta (name + supported OS), Os,
                      #   Readiness + preflight. No concrete collectors.
    collector-link/   # link collector: LinkFacts port, build_link_sample, META, preflight
    collector-proxy/  # proxy collector: ProxyFacts port, build_proxy_samples, META, preflight
    # collector-dns/ collector-route/ collector-host/  [next] — one crate each
    triggers/         # Condition/Handler/Trigger + engine, re-arm/backoff
    config/           # figment: per-subsystem toggles (constructor, not a dial)
    macos/            # PF_ROUTE socket, raw ICMP, IP_BOUND_IF, CoreCapture, Clash API;
                      #   implements the collector port traits (+ preflight checks)
```

Each collector is its own crate; `collector-core` holds only the shared
abstractions. Adding a subsystem (`dns`, `route`, `host`) means adding a crate
that depends on `collector-core`, never touching the others.

## Configuration

`figment` (file + env), like lightmare. Per-subsystem section, e.g.:

```toml
[collectors.link]
enabled  = true
interval = "15s"

[collectors.pcap_ring]
enabled  = true
ring_mb  = 8
```

v1 config is static (change → Nix rebuild). Runtime reload / control socket is a
later addition for the toolbar; the config type is shaped so a subsystem knob can
become runtime-mutable without reworking collectors.

## Error handling & isolation

- `thiserror` in crates, `anyhow` in bins.
- One collector failing must **not** take down the others: each runs as a
  supervised task (log + retry). A probe that cannot run emits a `SKIP` verdict
  rather than going silent — absence of a signal is itself diagnostic.
- StoreWriter write failures are buffered and retried; a DB outage must not drop
  the live stream on the floor silently (log the gap).

## Testing

- Unit tests per crate. `store` tested against an in-memory DuckDB.
- **Trigger engine tested by replaying real incident signatures** from the wiki
  as synthetic `Sample` streams: gw-drop (2026-07-15 coworking), wedge
  (2026-07-03), fakeip. Assert the right trigger fires, disarms, and re-arms.
- `net-observer.nix` is the behavioral oracle: the verdict vocabulary is
  cross-checked against recorded log excerpts so the rewrite does not silently
  drift from months of hard-won incident-capture behavior.

## Regression risks to preserve (from the oracle)

- **pcap ring freeze timing** — freeze BEFORE the slow arp/`log show` work and
  before the 8 MB buffer rotates; freeze UNCONDITIONALLY on any gateway change.
- **"Absence of a fresh CoreCapture is itself the diagnostic"** — no
  beacon-loss/deauth capture near a drop ⇒ L2 was fine ⇒ router-side drop, a
  different failure class than an RF drop. Encode the absence, not just presence.
- **DHCP-vs-unicast DNS nuance** — `type: dhcp` probing hit deadlines at the
  coworking while plain unicast to the same gateway resolved fine; slow DNS
  failure induces macOS Wi-Fi reassociation (manufacturing the very drop we
  hunt).
- **Coworking gateway signature** (user memory `coworking-gw-ping-issue`): link
  active, gw ARP alive, +100 broadcast dupes, but gw silent on unicast — Mode B
  (router-side), triggered by full-tunnel VPN ~2 min after lease.
- Keep the shell net-observer alive alongside during migration as a cross-check
  oracle (its watchdog kickstart is the only current auto-recovery — do not lose
  it before an acting handler replaces it).

## Engineering wins to preserve as goals

- **Fewer subprocess spawns** — do per-tick probes in-process (raw ICMP, a DNS
  crate, an HTTP client) instead of forking route/curl/dig/jq/awk/… every 15 s.
  (Ironic given a recent incident was load *starving* the TUN path.)
- **Persistent PF_ROUTE socket** — hold the socket properly, unlike sing-tun's
  darwin monitor (opens/closes a socket per message and misses events) and the
  shell `route -n monitor`.
- **Structured, queryable data** instead of columnar text meant for `awk`.

## v1.1 — in progress

Plan: `docs/superpowers/plans/2026-07-25-next-collectors-and-bar.md`.

- `dns`, `route-events`, `host-metrics` collectors (own crates), activating the
  `FakeIp` and `Starvation` trigger conditions with real data. `route-events` is
  the first **Event**-cadence collector (PF_ROUTE via `EventSource`).
- **gpui menu-bar** (`bin/net-observer-bar`) — `NSStatusItem` (via `objc2`) + a gpui
  panel showing the last tick per collector + recent incidents. No toggles yet.

## Local API (the daemon is the sole DB owner)

`net-observerd` is the **only** process that touches the DuckDB store (DuckDB takes a
per-process file lock — a second opener, even read-only, is blocked while the
daemon runs). Every other component reads through a **local API**, never the DB.

- **`net-observerd` exposes a Unix-domain socket** (`/var/lib/observer/observer.sock`,
  path + mode configurable; the root daemon `chmod`s it so the logged-in user's
  UI can connect). Served async via `tokio::net::UnixListener`.
- The daemon keeps an **in-memory live snapshot** (`tokio::sync::watch`) updated
  by the pipeline consumer on every sample, plus a small ring of recent
  incidents pushed when a trigger fires. The socket answers **from memory** — no
  DB read on the request path, zero contention with the writer, always live.
- **`crates/net-observer-ipc`** holds the shared protocol: `Request { Status,
  Incidents { limit } }`, `StatusSnapshot { link/proxy/dns/host: Option<*Sample>,
  incidents: Vec<IncidentSummary>, generated_us }` (reuses `types`), newline-JSON
  framing, a blocking `query()` client (for the bar) + an async serve helper.
- **`net-observer-bar` is a pure socket client** — no `duckdb` dependency at all. Its
  refresh timer calls `net_observer_ipc::query(sock, Request::Status)` and renders;
  daemon-down ⇒ a graceful "offline" state. `net-observer-cli`'s `status`/`incidents`
  also go through the socket; only its offline `query <SQL>` opens the DB directly.

## Control path — manual acting (conservative first step)

The Act layer starts with ONE safe, human-in-the-loop action; automatic acting
(watchdog) stays deferred.

- **`Request::Control(ControlCmd)`** with `ControlCmd::KickstartProxy` (extensible),
  answered by `Response::Control(ControlResult { ok, message })`.
- **`net-observerd` runs the action as root** — `launchctl kickstart -k <service>`
  (service label from config), the same recovery net-observer's watchdog used,
  but triggered manually.
- **Gated OFF by default:** `config.acting.enabled = false` ⇒ any control request
  is refused (`ControlResult { ok: false, "acting disabled" }`). No automatic
  triggering — a control action happens only on an explicit user request.
- **Socket hardening for the control path:** when the daemon has a
  `socket_owner_uid`, it `chown`s the socket to that uid; operators set mode
  `0600` when enabling acting so only the owner can send commands (a world-
  connectable read socket must not also accept privileged actions).
- **Clients:** `net-observer-bar` gets a "Restart sing-box" action; `net-observer-cli`
  gets a `kickstart` subcommand — both send `Control(KickstartProxy)`.

## Open questions still deferred

- **Automatic** acting (a watchdog that kickstarts on the wedge signature without
  a human) — the manual control action lands first; auto-acting stays deferred,
  shell net-observer remains the automatic recovery meanwhile.
- **kill-switch / portal** toggles (manipulate pf / routes) — riskier than a
  proxy restart; deferred until the manual-kickstart control path is proven.
- Notification channel(s) for a `Notify` handler.
- Runtime config reload over the control socket.
- Migrating `pcap-ring` from the `tcpdump` child to in-process capture
  (`pcap` crate / BPF).
