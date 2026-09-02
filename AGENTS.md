# `net-observer`
A Rust network-forensics daemon for macOS: writes layered telemetry into DuckDB so that after the network dies you can prove which layer failed.

## What this project is
- **Language of the repo is English** — code, comments, docs, commit messages, this file. The graph is written in Russian; do not translate graph node names when you reference them.
- **Nature**: `sandbox`, for now. That describes the stakes, not a licence: **no working principle is relaxed**, and the gate below is not optional. What sandbox buys you is that breakage is cheap and recoverable — one machine, one user, nothing downstream. It stops being cheap the moment the shell oracle is retired and this daemon is the only record of an outage.
- **Realm**: `net-observer` (`r210`) — every session starts with `iskron_orient` here.
- **Focus holon**: `#1 «🛰 Контур сетевой форензики мака»`.
- **Agent role**: `#2 «🔧 Сопровождающий демона net-observer»` — adhikarin, steward of the focus holon. Your inbox: `iskron_orient(realm="r210", focus="#2")` at session start.
- **Owner role**: `#3 «🧭 Владелец расследования»` (svatantra 主) — questions beyond your mandate go here as `posed_to` vimarshas.
- **Stack**: Rust edition 2024 (toolchain pinned in `rust-toolchain.toml`), tokio, DuckDB (`bundled`), figment, thiserror/anyhow, tracing, gpui for the menu bar.
- **Production statement**: ships nowhere and to no one. It runs on its author's own Mac, and its only consumer is the person reading an incident afterwards. The cost of breakage is not downtime — it is a missed incident: an outage that happened and left no usable record, and therefore an argument with the network's operators that cannot be made. Silent wrong data is worse than no data, which is why `SKIP` and the bracketed pause exist.

## Persistence rules
State lives in the **repo** or in the **graph** — nowhere else. The harness's built-in memory (per-project memory directory, conversation summaries, `/tmp`, machine-local files) is **forbidden entirely, not by category**: no project fact, no user preference, no note on working style. (why: local memory is invisible to every other agent and machine, so it drifts silently and breaks the reproducibility that makes a second machine or agent possible.)
- **Repo**: code, configs, conventions, code gotchas, branch state.
- **Graph**: methodology, design decisions, open questions (vimarshas), plans, handovers, lessons. Do not restate graph content in the repo; link the vimarsha or holon.
- **Fetch state; never reconstruct it from memory.** No source for "we decided…"? Stop and read the graph or the repo before acting.
- **Design and spec drafts written in this repo are a view, not the record**: the graph (realm `net-observer`, `r210`) holds the decisions, and such a file is one rendering of them. A dated plan is a historical trace of what was decided then — do not edit it to match current state.
- **This overrides the harness's own memory instruction**, which invites a `project` category. Route instead, asking **whose fact is this?** Repo convention, code fact, this project's procedures and dated debts → this file or a node in the `net-observer` realm; work state, decision, open question → a vimarsha in the graph. A fact that is the user's own and serves no single project (personal machines, deadlines, people, cross-project lessons) → their personal realm `@nick/mind`; a fact about another project → that project's realm. Standing preferences are instructions, not facts: project-scoped ones here, cross-project ones in the user's global instruction file.
- Before finishing a task, check that every durable fact from context is persisted by this routing: an unpersisted fact is a failed task, not a nicety.
- The local memory directory is **evacuated and frozen**: its `MEMORY.md` is a one-line prohibition stub, and the `PreToolUse` memory-guard hook blocks any write there with exit 2.

## Session lifecycle
Graph = the work (structure, open questions, what is next). Git = how we got here (SHAs, branches, PRs). **Git references never enter the graph** — no SHAs, no branch names, no PR numbers.
- **Session start:** orient in the `net-observer` realm, focus `#1`; read the ACTIVE BIANHUA map (`lens="bianhua"`). The `iskron:entry` skill drives the protocol. Then open your agenda: `iskron_orient(realm="r210", focus="#2")` — incoming `posed_to` vimarshas are your inbox; take each or defer it explicitly.
- **Start with the graph, then the project, then the code.** Three beats: graph reconnaissance (what is recorded about the site of the change, what was decided and what was rejected) → integration field (`iskron:integrity`) → design (`iskron:design`) → code. The only exception is explicit: the human said "just work". Silence is not "just work".
- **A decision is recorded when it is made, not when it ships** — with the modes it actually has right now: epistemic no higher than `anumita`, ontic `anagata`, volitive `chanda`/`adhimoksha`. (why: a decision left in the conversation that carried it dies with that conversation.)
- **Every task is described before it is begun, and recorded as what it is.** A one-off act is an anga vimarsha on the transformation it moves; **a kriya is only a repeatable transition**, where every run eats the same ahara and produces the same utpatti.
- **Every merge → update the graph.** A push that only opened a PR shipped nothing. On merge: check against reality (the deployed artifact, not the diff), advance the transformation map, close along the axis (`addressed_by` records the answer; release is a separate act), sweep the shipped holon, work the inbox, run `iskron:reconcile`.
- **Vocabulary pass.** Re-read what you are about to land for borrowed project-management words (ticket, backlog, sprint, epic, story, done, blocker). Do not substitute on your own: name each to the user and ask what it is called in this project.
- **A claim you made is not a claim you accept.** Behavioral claims ("the fix works", "the daemon writes that line") are closed by the cold `verifier` subagent's verdict, never by your own re-reading — give it the claim, the carrier and the falsifier, and wait for the verdict. Review of an open change goes to `reviewer` the same way. Role files live in `.claude/agents/`; their descriptions say when to call each and what not to trust.
- **The rituals above are wired as hooks** in `.claude/settings.json`: session-start orientation, a post-`git push` reminder, and a blocking memory-guard. The `Stop` anti-freeze hook is NOT wired — its decision-block format was not specified well enough to write without guessing.
- **Keep this file honest.** Compare the contract number in the stamp below with the first word of the installed `iskron:iskronify` skill description — it sits in every session's context, so the check costs no call. If they differ, running `iskron:iskronify` is the session's first move.

### After a green push: self-review
Gate green and the iteration done → re-read your own diff for bugs, fragile spots, weak error handling, DRY violations, missing tests, god units. Fix in the same branch — or say plainly that nothing surfaced. Do not invent findings. Per stage, not only at the end.

### Branch discipline
One branch until it merges — commit follow-ups into it. After a merge: `git checkout main && git pull`, delete the merged branch, weave the shipped state into the holon, confirm the cleanup before the next task.

## Working principles
1. **Think before code.** Name assumptions; ask when unsure — naming *what exactly* is unclear. **Questions to the human are asked as text**; never use an interactive option-picker (a list of options replaces the question with an answer and hides what is actually unclear). Check repo + graph before writing. Questions beyond your mandate become `posed_to` vimarshas on `#3`.
2. **Simplicity first.** The minimum code for the task. No speculative features, no abstractions for single-use code. Validate at boundaries; trust internal invariants.
3. **Stay inside the repo boundary.** Do not leave this working directory. A change belonging to another holon (e.g. the shell daemon in `nix-config`) is a vimarsha on that holon's node in its own realm, not an edit across the border.
4. **A second implementation is an event to report.** About to write something that already exists? Name both places and propose either reunification or a named, deliberate fork.
5. **Surgical changes.** Touch only what the task needs. Do not reformat or refactor neighbouring code. Delete only dead code your change created.
6. **Goal-driven execution.** Bugs: pin with a failing test before the patch. Name the falsifier before you look, and observe the carrier itself, not the source that should have produced it.
7. **Read before answering an open question.** Tasks framed as "discuss / think through / design" are answered from recorded thinking, not from training data: ask the graph first. Driven by `iskron:entry`.
8. **Think in the graph, speak the project's language.** The structural vocabulary (kriya, phenomenon, holon, vimarsha, modes) is for reasoning; it does not appear in what you say to the user until they use it first.

## Shared surfaces
One surface here has more than one consumer, and it is derived from the code, not from prose: the local socket protocol.

| Shared surface | Traversal anchor | What leads to the consumers |
|---|---|---|
| `net-observer-ipc` — `Request`/`Response`, `ControlCmd`, `StatusSnapshot`, `StreamFrame` | holon `#7` «Подсистема чтения» in realm `r210` | `context` edges into `#7` reach the readers; the writing side is `bin/net-observerd` (`api.rs`), which serves the same types |

Do not keep a consumer list in this file — walk the graph. Three consumers exist today: `net-observerd` serves, `net-observer-cli` and `net-observer-bar` call. The bar is the one that used to break silently, because nothing built it; `cargo build --all` inside `nix develop` now covers it, and CI has a step for it whose outcome on a GitHub runner is still unproven. Run the `--all` gate when you touch these types, or the bar is back to breaking out of sight. `serde(default)` on new fields is the standing mitigation — it kept a pre-quiet daemon decodable — but it does not save a *sender* that forgot a field.

Touching this surface obliges the walk; adding a consumer obliges the edge, or the next walk will not know it exists.

## External surfaces — what you use and do not own
There are many here and they are undocumented: private macOS tools and logs (`wdutil`, `ipconfig getpacket`, `scutil --nwi`, CoreCapture, `symptomsd netepochs`), sing-box's Clash API, DuckDB.
- **Before the work, pin the part of the surface the work will touch** — as a graph node, with the macOS/crate version you looked at.
- **Sources rank by seniority — pratyaksha before shabda.** First-hand observation (real command output on this machine) outranks documentation; documentation outranks memory; **memory is not a source at all**. Write `pratyakshita` only for what you observed yourself.
- **Weave the link.** An external-surface node is `upadhi` to the kriya acting through it. Without the edge it is an orphan label.
- **The reference works both ways.** Source that touches an external surface carries `(realm net-observer, node #N)` — and you read that node before the work.

## Reality — what a claim is checked against
Only the rows below are settled; the owner has not yet named carriers for the rest, so they sit in *Ceiling* rather than as aspirational lines.

| Claim class | Canonical carrier | How to observe | Who |
|---|---|---|---|
| Pure logic (sample mapping, trigger conditions, wire round-trip) | the test binaries of the default members | `cargo test` — read its own exit code, never a pipeline's | agent |
| Compiles and lints clean | the default-member build | `cargo build` then `cargo clippy --all-targets --all-features -- -D warnings`, each exit code read separately | agent |
| The menu bar compiles and lints | a compiled `net-observer-bar` | inside `nix develop`: `cargo build -p net-observer-bar`, `cargo clippy -p net-observer-bar --all-targets -- -D warnings` | agent |

**Ceiling** — claim classes with no reachable observation, and why:
- **The menu bar actually renders / a click does what it says.** Compiling it is reachable (row above); *running* it and seeing the panel is not something the agent can observe. A claim that the bar builds is confirmable; a claim about what the operator sees is not.
- **The daemon's live behavior** (it really writes that row, the ring really freezes, quiet really silences the wire). Needs a root run on this Mac against a real network, and the owner has not named how he wants that observed. Until he does, such a claim is closed only by an observation named aloud *before* looking — never by re-reading the diff.

**The table grows by use.** The moment a session learns a carrier this table does not hold, write the row then — in that session, before the work that taught it closes.

## Graph ↔ repo: where things live
| Concern | Repo | Graph |
|---|---|---|
| Code, configs, lockfiles | ✓ | |
| Commands, conventions, gotchas, stack | ✓ (AGENTS.md) | |
| Branch state, what is in flight | git + PR body | ✓ (`genre=hint` for work without a PR) |
| Methodology, ontology | | ✓ |
| Design decisions, open questions | | ✓ (vimarshas) |
| Plans, session handovers | | ✓ |
| Commit history, PRs, SHAs | git | (never in the graph) |

**No `HANDOVER.md` — that is a decision, not an oversight.** Branch and what is in flight live in `git branch`/`log` and the open PR; why it was decided and what is open lives in the graph; work without a PR lives in a `genre=hint` seed. (why: hand-written prose must be updated by whoever is busy with something else, and "the branch moved on" is the one event they learn about last.)

## Project structure
A Cargo workspace. Each collector is its own crate depending on `collector-core`; adding a subsystem means adding a crate, never editing the neighbours.

```
bin/
  net-observerd/        # headless root LaunchDaemon: config → collectors → store + triggers
  net-observer-cli/     # unprivileged reader: status / incidents (live via socket), query <SQL> (offline DB)
  net-observer-bar/     # gpui menu bar; a pure socket client, never touches the DB
crates/
  types/                # Sample, verdict enums, Incident, BlobRef, TriggerFired
  store/                # Store trait + DuckDB backend, schema, QueryTable
  collector-core/       # ABSTRACTIONS ONLY: Collector, Pinger/TcpProber, Os, Readiness. No tokio.
  collector-{link,proxy,dns,route,host,wifi}/   # one collector per crate
  triggers/             # Condition/Handler/Trigger + engine (re-arm/backoff)
  config/               # figment: per-subsystem toggles
  macos/                # real adapters: raw ICMP, IP_BOUND_IF, Clash API, DHCP/ARP, pcap ring
  net-observer-ipc/     # local socket protocol: Request/Response, StreamFrame
```

`ARCHITECTURE.md` holds the pipeline, crate graph and data model; `README.md` the quick start.

## Commands
| What | Command |
|---|---|
| build | `cargo build --all` |
| test | `just test` → `cargo test --all` |
| lint | `just clippy` → `cargo clippy --all --all-targets --all-features -- -D warnings` |
| format | `cargo fmt --all` |
| run | `just run ARGS` → `cargo run -p net-observerd -- ARGS` |

Green means the sequence `cargo fmt --all` → `cargo build --all` → `cargo test --all` → `cargo clippy --all --all-targets --all-features -- -D warnings`, **run from inside `nix develop`** — the `--all` steps include the menu bar, which only compiles there (see the gotcha below).

Run each step so its **own** exit code is visible. Piping cargo into `tail`/`head` makes the pipeline exit status that of the pager, so a failing build reports success — this has already produced a false "green" in this repo, and the unformatted commit it let through was caught only by CI.

Every step carries `--all`. Without it cargo uses `default-members`, which excludes `net-observer-bar` — a clippy run that looks workspace-wide but never checks the GUI is exactly how a `type_complexity` error reached `main`.

`clippy::pedantic` is deliberately NOT enabled: measured on 2026-09-01 it raises **215** warnings (largest groups `doc_markdown`, `must_use_candidate`, `cast_possible_truncation`, `map_unwrap_or`). Turning it on is a refactoring commitment, not a flag — it needs an explicit decision, not a bootstrap.

## Code conventions
- **Meaning lives in the graph, code references it.** A comment carrying the rationale for a decision or the alternatives rejected is a graph node: move the meaning into the graph and leave `(realm net-observer, node #N)` in the code. Step mechanics belong in the comment; rationale and integration field belong in the graph. Having cited a node, check that it really says what you cited it for.
- **Maximize Rust.** Prefer a pure-Rust crate for every component. Native (C/C++) deps are allowed only where no adequate equivalent exists, and each exception is named here. Current exceptions: **DuckDB** (no pure-Rust DB offers native `ASOF JOIN`) and, for v1 only, the **`tcpdump` child** behind the pcap ring. Any future GUI is `gpui`.
- **v1 = observe + detect, never act.** No `launchctl kickstart`, no watchdog, no notifications. Triggers fire *passive* handlers only (record an incident, freeze the pcap ring). Acting handlers sit behind the same `Condition → Handler` interface but are not in v1.
- **SKIP, never silence.** A probe that cannot run emits a `SKIP` verdict rather than going quiet — absence of a signal is itself diagnostic. Quiet mode is not an exception to this: `SetQuiet(true)` withholds the gateway echo but the link collector keeps emitting one sample per tick with `gw = SKIP`, and the triggers read that as no measurement — never as a healthy gateway, never as a drop. The one sanctioned exception is an operator pause (`ControlCmd::SetObserving`): a paused daemon stops collecting outright instead of emitting per-tick synthetic `SKIP` samples. That silence is *bracketed*: each pause/resume edge writes a durable `observing_edge` row through the `Store` and publishes a `StreamFrame::Observing` on the realtime bus, so the gap is bounded and attributable (to a `ts_us` and a control-socket `peer_uid`). Unbracketed silence is a bug. Samples the bounded post-resume drain keeps out of the trigger window are not a second exception: each is still written to DuckDB and published on the bus, and the drain is bounded by a monotonic deadline and a drop cap and reports its totals. The observing state is process-scoped and deliberately never persisted — a restart always resumes collecting.
- **Isolation.** One collector failing must never take down the others; each runs as a supervised task (log and keep ticking). Store write failures are logged as a gap, never swallowed.
- **Errors:** `thiserror` in library crates, `anyhow` in binaries. **Config:** `figment` (file + `NET_OBSERVER_*`). **Async:** `tokio`, kept out of `collector-core`. **Logging:** `tracing`.
- **Test discipline**: unit tests per crate; `store` is tested against an in-memory DuckDB; the pure mapping logic (`build_link_sample` / `build_proxy_samples`) uses fake port impls, so no live network or root is needed. Trigger rules are tested by replaying real recorded incident signatures as synthetic `Sample` streams. Keep new behavior covered.
- **Gotchas**:
  - The `duckdb` crate builds its C++ engine from source (`bundled`): a cold build reaches ~10 minutes. Use generous timeouts; a long build is not a hang.
  - `net-observer-bar` is outside `default-members`, so a plain `cargo build` / `cargo test` never sees it — a break there is invisible until someone asks for it by name. Use `--all` (or `-p net-observer-bar`) when your change touches the socket types.
  - Building the bar needs Apple's Metal shader compiler, which nixpkgs cannot redistribute. The `xcrun` nix puts on PATH is xcbuild's reimplementation and has no `metal`, so gpui's build script fails with "missing Metal Toolchain" even where Xcode ships one. The dev shell shims **only** `xcrun` (see `flake.nix`): exporting `DEVELOPER_DIR` for the whole shell finds `metal` but repoints `cc`/`ld` at Xcode's SDK and linking against the nix toolchain then fails. **Build the bar from inside `nix develop`**; outside it, expect the Metal error.
  - The daemon's runtime paths stay under `/var/lib/observer/*` even though the project is called `net-observer`: the shell oracle daemon owns `/var/lib/net-observer` and `/var/log/net-observer.log` and, by the owner's decision, keeps running alongside during the migration. Move onto shared paths only once the shell daemon is retired, or the two fight over the pcap ring and the request drop-box.
  - The behavioral oracle for this rewrite is the shell daemon at `~/projects/nix-config/hosts/mac_aarch64/net-observer.nix`. Its verdict vocabulary and incident-capture behavior (freeze timing, the DHCP-vs-unicast DNS nuance, the coworking gateway signature, "absence of a fresh CoreCapture is itself the diagnostic") are the ground truth this rewrite must not silently drift from. It is also the only current auto-recovery (watchdog kickstart) — do not lose it before an acting handler replaces it.

## What to update when
- `AGENTS.md` — by the inverted default: **if it can be learned by reading a graph node, it is not here.** This file holds only what is needed BEFORE an agent reaches the graph: commands, the entry into orientation, code invariants no linter expresses, and forks that must stop you before you act.
- `CLAUDE.md` — a symlink to `AGENTS.md`; never edited separately.
- `docs/roadmap.{md,html}` — a **generated snapshot**, not a source. Regenerate with `iskron:product-roadmap`; never hand-edit, because a hand edit survives until the next regeneration and reads as current the whole time. Where it disagrees with the realm or the code, they are right.
- The `net-observer` realm — every merge (see "Session lifecycle").

## Git workflow
- **Conventional commits** (`feat:`/`fix:`/`chore:`/`refactor:`/`docs:`/`test:`). Branches `feat/…`, `fix/…`, `chore/…`.
- **No co-author trailer and no Claude attribution** — not in commits, not in PR bodies.
- **Forge**: GitHub, `origin` = `git@github.com:gurinderu/net-observer.git`. CLI is `gh` (installed, authenticated as `gurinderu`); watch checks with `gh pr checks <n> --watch`.
- **Local gate**: there is no pre-commit hook in this repo — run `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all` by hand before pushing.
- **CI**: two workflows on `macos-latest`, both gating pull requests *and* pushes to `main` — `lints` (`cargo fmt --all --check`, clippy with `-D warnings`, `RUSTFLAGS: -D warnings`) and `tests` (`cargo build --all`, `cargo test --all`). There are no post-merge-only jobs, so PR↔main parity is complete. `net-observer-bar` is not built in CI: it is outside `default-members` and `--workspace` is not passed, so the GUI only breaks locally.
- **Definition of done**: a pull request into `main`, `gh pr checks <n> --watch` green, merged without conflicts. Branch discipline keys on that merge, not on a push: a push that only opened or updated the PR has shipped nothing.
- **Never** `--no-verify`, `--force`, `--no-gpg-sign`, or `git reset --hard` without an explicit instruction from the user. Stage explicit paths only — never `git add -A` / `.` / `-u`.

*(iskronify: contract `5`, stamp `2026-09-01` (full pass) — re-run when the installed
iskronify's description names a higher contract, or when the sources this file
was derived from have moved since that date.)*

Every authored slot is now filled. The *Reality* table is deliberately partial:
its *Ceiling* names the claim classes with no reachable observation instead of
pretending they have one.
