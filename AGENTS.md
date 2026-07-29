# AGENTS.md

Guidance for coding agents (and humans) working in this repo. `CLAUDE.md` is a
symlink to this file.

## What this is

`observer` — a Rust network-forensics collector daemon for macOS. It replaces the
hand-rolled `net-observer` bash LaunchDaemon with a structured pipeline that
writes queryable telemetry into DuckDB. Read `ARCHITECTURE.md` for the pipeline,
crate graph, and data model; `README.md` for a quick start; and the design +
plan under `docs/superpowers/` for the full rationale.

## Workspace layout

A Cargo workspace (`edition = "2024"`, toolchain pinned in `rust-toolchain.toml`).

```
bin/
  observerd/        # headless root LaunchDaemon: config → collectors → store + triggers
  observer-cli/     # unprivileged reader: status / incidents (live via socket), query <SQL> (offline DB)
crates/
  types/            # Sample, verdict enums, Incident, BlobRef, TriggerFired
  store/            # Store trait + DuckDB backend, schema, QueryTable
  collector-core/   # ABSTRACTIONS ONLY: Collector trait, Pinger/TcpProber ports,
                    #   Os, CollectorMeta, Readiness, Source/EventSource. No tokio.
  collector-link/   # link collector: LinkFacts port, build_link_sample, LinkCollector, META
  collector-proxy/  # proxy collector: ProxyFacts port, build_proxy_samples, ProxyCollector, META
  triggers/         # Condition/Handler/Trigger + engine (re-arm/backoff)
  config/           # figment: per-subsystem toggles (a constructor, not a verbosity dial)
  macos/            # real adapters: raw ICMP, IP_BOUND_IF, Clash API, DHCP/ARP, pcap ring
```

Each collector is its own crate depending on `collector-core`. Adding a subsystem
(`dns`, `route`, `host`) means adding a crate — never editing the others.

## Just recipes

```
just clippy   # cargo clippy --all-targets --all-features -- -D warnings
just test     # cargo test --all
just run ARGS # cargo run -p observerd -- ARGS
```

Before finishing any change, keep it green:
`cargo fmt --all` → `cargo build --all` → `cargo test --all` →
`cargo clippy --all-targets --all-features -- -D warnings`.
Note: the `duckdb` crate builds its C++ engine from source (`bundled`), so a cold
build can take up to ~10 minutes — use generous timeouts.

## Design rules

- **Maximize Rust.** Prefer a pure-Rust crate for every component where a viable
  one exists. Native (C/C++) deps are allowed only where there is no adequate
  pure-Rust equivalent, and each exception is named and justified in the design
  doc. Current exceptions: **DuckDB** (C++; the one core engine — no pure-Rust DB
  offers native `ASOF JOIN`) and, for v1 only, the **`tcpdump` child** behind the
  pcap ring (the pure-Rust target is in-process capture via the `pcap` crate /
  BPF). Any future GUI is `gpui`.
- **v1 = observe + detect, never act.** No `launchctl kickstart`, no watchdog, no
  notifications. Triggers fire *passive* handlers only (record an incident,
  freeze the pcap ring). Acting/notifying are later handlers behind the same
  `Condition → Handler` interface — do not add them to v1.
- **SKIP, never silence.** A probe that cannot run emits a `SKIP` verdict rather
  than going quiet — absence of a signal is itself diagnostic. Preserve this and
  the verdict vocabulary (see `ARCHITECTURE.md`). The **one** sanctioned
  exception is an operator pause (`ControlCmd::SetObserving`): a paused daemon
  stops collecting outright instead of emitting per-tick synthetic `SKIP`
  samples. That silence is *bracketed*, never bare — each pause/resume **edge**
  writes a durable `observing_edge` boundary row through the `Store` and
  publishes the same transition as a `StreamFrame::Observing` frame on the
  realtime bus, so the gap is bounded and attributable (to a `ts_us` and a
  control-socket `peer_uid`) offline and after the fact. Silence that is *not*
  bracketed by those records is a bug. Samples the bounded post-resume drain keeps
  out of the trigger window are **not** a second exception: each is still written
  to DuckDB and still published on the bus, and the drain itself is bounded by a
  monotonic deadline and a drop cap and reports its totals, so "filtered from the
  trigger window" never becomes "dropped from the record". The observing state
  itself is process-scoped and deliberately never persisted — a restart always
  resumes collecting.
- **Isolation.** One collector failing must never take down the others; each runs
  as a supervised task (log + keep ticking). Store write failures are logged as a
  gap, not silently dropped.
- **Errors:** `thiserror` in library crates, `anyhow` in binaries. **Config:**
  `figment` (file + `OBSERVER_*` env). **Async:** `tokio` (kept out of
  `collector-core`). **Logging:** `tracing`.

## Behavioral oracle

The shell `net-observer` LaunchDaemon is the behavioral oracle for this rewrite:
`~/projects/nix-config/hosts/mac_aarch64/net-observer.nix`. Its verdict
vocabulary and incident-capture behavior (freeze timing, DHCP-vs-unicast DNS
nuance, the coworking gateway signature, "absence of a fresh CoreCapture is
itself the diagnostic") are the ground truth the Rust rewrite must not silently
drift from. Keep the shell daemon running alongside during migration — its
watchdog kickstart is the only current auto-recovery and must not be lost before
an acting handler replaces it. Trigger rules are tested by replaying real
recorded incident signatures as synthetic `Sample` streams.

## Testing

Unit tests live per crate; `store` is tested against an in-memory DuckDB. The
pure mapping logic (`build_link_sample` / `build_proxy_samples`) is tested with
fake port impls, so no live network or root is needed. Keep new behavior covered.
