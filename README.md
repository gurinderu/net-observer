# net-observer

A Rust network-forensics collector daemon for macOS. It collects network and
system telemetry into a queryable DuckDB database, so post-incident analysis is
a SQL query instead of grepping a text log.

**North star: incident forensics** — a rich, queryable snapshot of state *around
outages*. Not a live dashboard, not long-term analytics.

**v1 = observe + detect, never act.** The daemon collects telemetry and fires
*passive* triggers (record an incident, freeze a pcap ring). Acting (kickstart)
and notifications are later handlers behind the same interface.

## Components

- **`net-observerd`** — the headless **root** LaunchDaemon. Loads config, spawns the
  enabled collectors onto a stream, writes samples to DuckDB, and evaluates the
  trigger engine on every sample.
- **`net-observer-cli`** — an **unprivileged** reader for the same database.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the pipeline, crate graph, and data
model, and [`AGENTS.md`](AGENTS.md) for contributor/agent conventions.

## Build & test

The toolchain is pinned in `rust-toolchain.toml`; a Nix dev shell is provided
(`flake.nix` + direnv). Common recipes (see `Justfile`):

```sh
just test     # cargo test --all
just clippy   # cargo clippy --all-targets --all-features -- -D warnings
just run      # cargo run -p net-observerd -- <args>
```

> The `duckdb` dependency builds its C++ engine from source (`bundled`), so the
> first build can take several minutes.

## Running the daemon

`net-observerd` needs root (raw ICMP, PF_ROUTE, `tcpdump`, reading the sing-box
config). Configuration is via a TOML file plus `NET_OBSERVER_*` environment
overrides; every field has a built-in default. Copy the example and edit:

```sh
cp net-observer.example.toml net-observer.toml
sudo cargo run -p net-observerd -- --config net-observer.toml
```

A `--config` path you name explicitly must exist and be a readable regular file:
a typo is an error, not a silent fall-back to the built-in defaults — which for
the daemon would mean binding a socket and opening a database nobody asked for.
(`net-observer-bar` is deliberately exempt: it still launches and surfaces the reason
in its panel and on stderr, because a GUI that refuses to start leaves the user
with nothing.)

Each collector is independently toggled with its own interval, e.g.:

```toml
[collectors.link]
enabled  = true
interval = "15s"
```

Env overrides use `__` for nested keys, e.g.
`NET_OBSERVER_COLLECTORS__LINK__INTERVAL="5s"`.

## Querying the store

`net-observer-cli` reads the DuckDB file written by the daemon:

```sh
# Row counts per table + the last sample timestamp.
net-observer-cli --db /var/lib/observer/observer.duckdb status

# Incidents (open and closed), newest first.
net-observer-cli --db /var/lib/observer/observer.duckdb incidents

# Arbitrary read-only SQL — DuckDB has native ASOF JOIN for cross-stream
# correlation ("the nearest proxy sample at or before each gateway drop").
net-observer-cli --db /var/lib/observer/observer.duckdb query \
  "SELECT * FROM link_sample WHERE gw = 'FAIL' ORDER BY ts_us DESC LIMIT 20"
```

## Status

v1 ships the `link` and `proxy` collectors plus the pcap ring, with the
wedge / gw-drop / gw-change / fakeip / starvation triggers. The `dns`,
`route-events`, and `host-metrics` collectors, a menu-bar UI (gpui), and acting
handlers are planned next. macOS-only for v1.
