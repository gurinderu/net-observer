# Architecture

`observer` is a Rust network-forensics collector for macOS. It replaces a
hand-rolled ~470-line `bash` LaunchDaemon (`net-observer`) with a structured,
queryable pipeline whose north star is **incident forensics**: a rich, SQL-able
snapshot of network/system state *around outages*, so post-incident analysis is
a query ("что было в 17:26") instead of grepping a columnar text log.

**v1 scope = observe + detect, never act.** The daemon collects telemetry and
fires *passive* triggers (record an incident, freeze the pcap ring). No
`launchctl kickstart`, no watchdog, no notifications in v1 — those are later
handlers behind the same `Condition → Handler` interface. The shell
`net-observer` remains the behavioral oracle (see `AGENTS.md`).

## Pipeline

Collectors emit typed `Sample`s onto an mpsc stream. A single consumer persists
each sample into DuckDB, keeps a small in-memory recent window, and evaluates the
trigger engine on every sample so a freeze can happen *before* the slow
`arp`/`log show` work and before the pcap ring rotates over the packets around a
drop.

```mermaid
flowchart LR
    subgraph collectors["Collectors (one task each)"]
        link["link\nInterval(15s)"]
        proxy["proxy\nInterval(15s)"]
        dns["dns\nInterval"]
        host["host\nInterval"]
        evt["route-events\nEvent (PF_ROUTE)"]
    end

    link -- "Sample::Link" --> stream
    proxy -- "Sample::Proxy" --> stream
    dns -- "Sample::Dns" --> stream
    host -- "Sample::Host" --> stream
    evt -- "Sample::Route (event)" --> stream

    stream(["mpsc stream (Sample)"]) --> consumer{{"consumer loop\n(pipeline::run)"}}

    consumer -->|write_sample| store[("DuckDB\n(Store trait)")]
    consumer -->|"latest sample / incident"| snap["StatusSnapshot\n(in-memory, live)"]
    consumer -->|push| window["RecentWindow\n(last N ticks)"]
    window --> engine["TriggerEngine\nre-arm / backoff"]

    engine -->|fire| record["RecordHandler\nopen/close incident"]
    engine -->|fire| snaph["SnapshotHandler\nincident ring"]
    engine -->|"fire (gw-change)"| freeze["FreezePcapHandler"]
    record --> store
    snaph --> snap
    freeze --> ring[["pcap ring\n(tcpdump child)"]]
    freeze -->|blob_ref| store

    snap --> apisrv{{"api::serve\nUnixListener socket"}}
    bar["observer-bar\n(unprivileged socket client)"] <-->|"Request/Response\n(observer-ipc)"| apisrv
    cli["observer-cli\n(status/incidents: socket;\nquery <SQL>: offline DB)"] <-->|"Request/Response\n(observer-ipc)"| apisrv
    cli -->|"query <SQL>\n(offline, read-only)"| store
```

- **Collectors** — one task per subsystem, each on its own cadence. `link`,
  `proxy`, `dns`, and `host` are `Interval` collectors (timer →
  `collect(ts_us)` on the blocking pool). `route-events` is the first **Event**
  collector: the daemon takes its `EventSource` and drives the blocking
  `next()` loop (a PF_ROUTE socket `recv`) on the blocking pool, forwarding
  samples as the kernel announces interface/route changes.
- **Consumer** (`bin/observerd/src/pipeline.rs::run`) — drains the stream,
  writes each sample to the store (a write error is *logged as a gap*, never
  silently dropped), mirrors the sample into the live `StatusSnapshot`, pushes
  into the `RecentWindow`, and evaluates the engine.
- **TriggerEngine** — starter rules ported from the oracle: `wedge`, `gw-drop`,
  `gw-change` (unconditional pcap freeze on any gateway change), `fakeip`,
  `starvation`. Each fires at most once per 5 min (backoff) and disarms until the
  signal returns to OK.
- **Live snapshot + local socket API** — the consumer keeps an in-memory
  `StatusSnapshot` (the latest sample per collector + `generated_us`) current on
  every tick, and a passive `SnapshotHandler` mirrors each fired incident into a
  bounded ring (newest first). `observerd` serves this snapshot over a
  Unix-domain socket (`bin/observerd/src/api.rs::serve`, a tokio `UnixListener`),
  answering entirely from memory — no DB read on the request path, zero contention
  with the writer. See [Local socket API](#local-socket-api) below.
- **observerd** — the root LaunchDaemon: load config → open the store → spawn the
  socket API server → build enabled collectors as `Box<dyn Collector>` → filter
  by `meta().supports(Os::current())` then `preflight()` → spawn survivors → run
  the consumer → clean SIGTERM/SIGINT shutdown (the API task is aborted alongside
  the collectors).
- **observer-cli** — unprivileged; `status` / `incidents` read the daemon's live
  `StatusSnapshot` over the socket (`observer_ipc::query`), so they work *while the
  daemon runs* with zero DB contention. `query <SQL>` is the only DB path: it opens
  the DuckDB file read-only for ad-hoc forensics, which succeeds only when no daemon
  holds the store (the file lock otherwise blocks the open — reported as a clear
  message, never a panic).
- **observer-bar** — unprivileged **menu-bar** app and a *pure socket client*: it
  never opens the DB, fetching the live `StatusSnapshot` from the daemon over the
  socket via `observer_ipc::query`.

### Collector capability model

Every collector carries two capability signals so the daemon decides, per
collector, whether to run it at all:

- **Static OS metadata** — `CollectorMeta { name, supported_os }`; v1 collectors
  declare `&[Os::MacOs]`. A collector whose meta does not `supports(Os::current())`
  is skipped.
- **Runtime preflight** — `preflight() -> Readiness` (`Ready` /
  `Unavailable(String)`), delegated to the port facts: `link` is Ready iff a
  physical interface resolves; `proxy` iff the sing-box config exists or the
  Clash API is set. A failing preflight is logged (absence of a signal is itself
  diagnostic) and the collector is not spawned.

## Crate graph

The monolithic `collectors` crate is split into `collector-core` (abstractions
only) plus one crate per collector. Adding a subsystem (`dns`, `route`, `host`)
means adding a crate that depends on `collector-core`, never touching the others.

```mermaid
graph TD
    types["types\nSample, verdicts, Incident"]
    ipc["observer-ipc\nRequest/Response, StatusSnapshot,\nnewline-JSON framing (query/serve)"]
    store["store\nStore trait + DuckDB"]
    ccore["collector-core\nCollector, Pinger/TcpProber,\nOs, CollectorMeta, Readiness, Source"]
    clink["collector-link\nLinkFacts, build_link_sample,\nLinkCollector, META"]
    cproxy["collector-proxy\nProxyFacts, build_proxy_samples,\nProxyCollector, META"]
    cdns["collector-dns\nDnsFacts, build_dns_samples,\nDnsCollector, META (Interval)"]
    croute["collector-route\nRouteCollector, META (Event);\nEventSource-driven"]
    chost["collector-host\nHostFacts, build_host_sample,\nHostCollector, META (Interval)"]
    triggers["triggers\nCondition/Handler/Trigger, engine"]
    config["config\nfigment per-subsystem toggles"]
    macos["macos\nreal adapters: ICMP, IP_BOUND_IF,\nClash API, DHCP/ARP, pcap ring,\nDNS resolve, PF_ROUTE, loadavg"]
    observerd["bin/observerd\nroot LaunchDaemon"]
    cli["bin/observer-cli\nstatus/incidents via socket;\nquery <SQL> via offline DB"]
    bar["bin/observer-bar\ngpui menu-bar (NSStatusItem\n+ panel); socket client (no DB)"]

    types --> ccore
    types --> store
    types --> triggers
    types --> ipc
    ccore --> clink
    ccore --> cproxy
    ccore --> cdns
    ccore --> croute
    ccore --> chost
    types --> clink
    types --> cproxy
    types --> cdns
    types --> croute
    types --> chost

    ccore --> macos
    clink --> macos
    cproxy --> macos
    cdns --> macos
    croute --> macos
    chost --> macos

    store --> triggers

    ccore --> observerd
    clink --> observerd
    cproxy --> observerd
    cdns --> observerd
    croute --> observerd
    chost --> observerd
    macos --> observerd
    store --> observerd
    triggers --> observerd
    config --> observerd
    types --> observerd
    ipc --> observerd

    store --> cli
    types --> cli
    ipc --> cli
    config --> cli

    ipc --> bar
    types --> bar
    config --> bar
```

- `collector-core` depends on `types` only — and **not** on tokio; `Source` /
  `EventSource` keep it runtime-agnostic. The async driving of both cadences
  lives in `observerd`.
- `collector-link` / `collector-proxy` / `collector-dns` / `collector-host` are
  `Interval` collectors; each depends on `types` + `collector-core` and holds its
  port trait (`LinkFacts` / `ProxyFacts` / `DnsFacts` / `HostFacts`), the pure
  `build_*` mapping logic (unit-tested with fakes), a static `META`, and the
  `Collector` impl.
- `collector-route` is the first **Event**-cadence collector: it wraps a
  `Box<dyn EventSource>` (the real PF_ROUTE source lives in `macos`) and reports
  `Source::Event`; `observerd` drives its blocking `next()` loop on the blocking
  pool.
- `macos` implements every port trait with the real adapters (raw ICMP,
  `IP_BOUND_IF` TCP probes, Clash API, DHCP/ARP facts, DNS resolve, the
  persistent PF_ROUTE `EventSource`, `getloadavg`) plus the pcap ring and the
  per-collector `preflight()` checks.
- `observer-ipc` is the shared local-socket protocol crate: the wire types
  (`Request`, `Response`, `StatusSnapshot`, `IncidentSummary`), the
  newline-delimited JSON framing (`write_frame` / `read_frame`), and a blocking
  `query` client. It depends on `types` + serde only and is deliberately
  **runtime-agnostic** — no tokio — so both the async server in `observerd` and
  the blocking client in `observer-bar` share one definition of the format.
- `bin/observerd` wires everything and owns the DuckDB store; `bin/observer-cli`
  reads `store` read-only, while `bin/observer-bar` reads live status over the
  socket via `observer-ipc` and **never touches the DB**. `bin/observer-bar` is a
  macOS **menu-bar app**: a dockless (`.accessory`) `NSStatusItem` (AppKit interop
  via `objc2` / `objc2-app-kit`) whose glyph shows the latest link/proxy health
  and whose click opens a **gpui** panel rendering the full `StatusSnapshot`
  (latest link/proxy tick + recent incidents), re-queried on a ~3s timer; a down
  daemon / absent socket degrades to a graceful "observer offline" state. gpui's
  build script needs the macOS **Metal Toolchain**, so the crate is a full
  workspace member but is excluded from `default-members` — a bare `cargo build`
  needs no GUI toolchain; build the bar with `--workspace` / `-p observer-bar` on
  a machine that has the Metal Toolchain installed.

## Data model (DuckDB)

Normalized per subsystem — each stream has its own timestamp and cadence;
cross-stream correlation is via DuckDB's native `ASOF JOIN`. Big blobs (pcap
freezes, `log show` dumps) live as files on disk; only a `blob_ref` metadata row
goes in the DB. Timestamps are microseconds since the epoch (`ts_us BIGINT`).

| Table | Columns | Notes |
| --- | --- | --- |
| `link_sample` | `ts_us, gw, gw_rtt_ms, direct, direct_rtt_ms, dhcp_router, dhcp_dns, gw_arp_mac, ssid, wifi_capture_present` | Local path: gateway ping, direct TCP (bound to phys iface), DHCP/ARP facts, Wi-Fi SSID + CoreCapture presence. |
| `proxy_sample` | `ts_us, server_ip, tcp, rtt_ms, tun_code, selector` | Per-VLESS TCP reachability, tun HTTP 204 (`tun_code`), Clash selector. |
| `dns_sample` | `ts_us, probe, server, verdict, ip, rtt_ms` | One row per resolver probe (name label × resolver path); `verdict` drives the `fakeip` trigger. |
| `route_event` | `ts_us, kind, iface, detail` | PF_ROUTE event stream (`kind` = `iface` / `addr` / `route`): iface up/down, addr add/loss, default-route change. |
| `host_sample` | `ts_us, load1, load5, load15` | Host load averages — the `starvation` discriminator. |
| `incident` | `id PK, opened_us, closed_us, trigger_id, signature` | Open incident ⇒ `closed_us IS NULL`. |
| `blob_ref` | `id, incident_id, ts_us, kind, path` | On-disk forensics blobs (pcap freeze, dumps) referenced by path. |
| `trigger_fired` | `ts_us, trigger_id, incident_id, detail` | One row per trigger fire. |

`dns_sample`, `route_event`, and `host_sample` are created by the v1.1 `dns`,
`route-events`, and `host-metrics` collectors respectively.

### Verdict vocabulary

Ported from the oracle and cross-checked against recorded log excerpts:

- DNS: `OK / FAKEIP / EMPTY / SERVFAIL / NXDOMAIN / TIMEOUT / SKIP`
- Gateway: `OK / FAIL / NOGW`
- TCP: `OK / FAIL / SKIP`

`FAKEIP` on a `.ru` name is always a bug. **`SKIP` means a prerequisite was
missing — it is recorded explicitly, never omitted**: absence of a signal is
itself diagnostic.

## Local socket API

The daemon exposes live status over a Unix-domain socket so unprivileged clients
(the bar) read a fresh view *while the daemon runs* — the case the read-only
DuckDB open cannot serve, because the daemon holds the file lock. The DB stays
the durable record; the socket is the live, low-latency read path.

- **Wire protocol** (`crates/observer-ipc`) — a request/response pair framed as
  newline-delimited JSON:
  - `Request::Status` → `Response::Status(StatusSnapshot)`
  - `Request::Incidents { limit }` → `Response::Incidents(Vec<IncidentSummary>)`
  - a malformed request → `Response::Error(String)`

  `StatusSnapshot` is the latest sample per collector (`link` / `proxy` / `dns` /
  `host`), a `generated_us` stamp, and a bounded, newest-first ring of recent
  `IncidentSummary`s. `write_frame` / `read_frame` pin the exact framing
  (`serde_json` + `'\n'`); the crate is runtime-agnostic (no tokio) so the async
  server and the blocking client share one format definition.

- **Server** (`bin/observerd/src/api.rs::serve`) — a tokio `UnixListener`. On
  start it removes any stale socket file, binds `cfg.socket_path`, and `chmod`s it
  to `cfg.socket_mode` so the unprivileged bar can connect to the root-owned
  socket. One task per connection: read one `Request`, answer from the shared
  `Arc<Mutex<StatusSnapshot>>` the pipeline keeps current, write one `Response`,
  close. The lock is held only long enough to clone what the reply needs — never
  across an `.await`, so a slow client can never stall the collector pipeline. The
  server is spawned by the daemon and `abort()`ed on shutdown alongside the
  collectors; a bind failure is logged but never takes the daemon down (no API,
  still collecting).

- **Client** (`observer_ipc::query`, used by `bin/observer-bar` and by
  `observer-cli`'s `status` / `incidents`) — a *blocking* round-trip: connect, write
  one request frame, read one response frame. A missing socket / connection-refused
  (daemon down) / protocol error all map to an `Err`, which the bar renders as the
  "observer offline" state and retries on its next ~3s tick, and which the CLI turns
  into a clear "observerd not running" message with a non-zero exit. Neither client
  links an async runtime for this.

```mermaid
sequenceDiagram
    participant Bar as observer-bar (client)
    participant Sock as observer.sock
    participant Srv as observerd api::serve
    participant Snap as StatusSnapshot (in-memory)
    Bar->>Sock: connect + write Request::Status\n
    Sock->>Srv: accept -> per-conn task
    Srv->>Snap: lock, clone snapshot, unlock
    Srv-->>Bar: Response::Status(..)\n ; close
    Note over Bar: on connect/read error -> "observer offline"
```

## Privilege split

`observerd` is a headless **root** LaunchDaemon (needs raw ICMP, PF_ROUTE,
`tcpdump`, reading the sing-box config) and is the **sole owner** of the DuckDB
store. DuckDB 1.x takes a per-process file lock, so a second opener — even
read-only — is blocked while the daemon runs.

- `observer-cli` is **unprivileged**. Its `status` / `incidents` commands read the
  daemon's live snapshot over the socket (`observer_ipc::query`), so they work while
  the daemon runs. Only `query <SQL>` opens the DuckDB file `read_only`, and that
  open succeeds only when no `observerd` holds the store (offline forensics); while
  the daemon runs it holds the lock and the open fails with a clear message.
- `observer-bar` is **unprivileged** and does **not** open the DB at all: it is a
  pure client of the daemon's local socket (see [Local socket API](#local-socket-api)),
  so it reads *live* status while the daemon runs — the concurrent-live-access
  case the read-only open could never cover. A down daemon degrades to a graceful
  "observer offline" glyph, retried each tick.

The menu-bar UI stays a separate unprivileged binary — never the daemon itself.
The daemon relaxes the socket file's mode (config `socket_mode`, default `0666`)
so the logged-in user's UI can connect to the root-owned socket.
