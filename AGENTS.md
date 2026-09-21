# `net-observer`
A Rust network-forensics daemon for macOS: writes layered telemetry into DuckDB so that after the network dies you can prove which layer failed.

## Cover
Answers stand as a table, not prose: slot, value, source (`derived` — from the repo by reading; `agreed: <who>`; `<not agreed — #N>` — a consolidation node). Takt 1 of iskronify writes it, the `iskron:iskron` door's start fills open slots from the consolidation node, the full arc re-projects it.

| Slot | Value | Source |
|---|---|---|
| Nature | `sandbox`, for now — that describes the stakes, not a licence: no working principle is relaxed and the gate is not optional; breakage is cheap only until the shell oracle is retired and this daemon is the only record of an outage | agreed: owner |
| Realm | `net-observer` (`r210`) — every session starts here | agreed: owner |
| Focus holon | `#1 «🛰 Контур сетевой форензики мака»` | derived |
| Repository | `github.com/gurinderu/net-observer` — the holon's `repository` attribute, from origin | derived |
| Agent role | `#2 «🔧 Сопровождающий демона net-observer»` — adhikarin, steward of `#1`; inbox: `iskron_orient(realm="r210", focus="#2")` | derived |
| Owner role | `#3 «🧭 Владелец расследования»` — svatantra, the `posed_to` address for questions beyond the mandate | derived |
| Stack | Rust edition 2024 (toolchain pinned in `rust-toolchain.toml`), tokio, DuckDB (`bundled`), figment, thiserror/anyhow, tracing, gpui | derived |
| Gate | `just gate` — one call, run inside `nix develop` | agreed: owner |
| Consumers | the owner, reading an incident afterwards; it ships nowhere and to no one else | agreed: owner |
| Cost of breakage | a missed incident: an outage that happened and left no usable record, and therefore an argument with the network's operators that cannot be made. Silent wrong data is worse than no data — `SKIP` and the bracketed pause exist for this | agreed: owner |
| Reality | the table in “Reality” below | agreed: owner |
| Cross-project memory | the user's personal realm `@nick/mind`; no global instruction file; never the harness memory directory | agreed: owner |
| Feedback reflection | yes | agreed: owner |
| Workflow-suite interop | none — the suite was removed at the owner's word (2026-09-21) | agreed: owner |
| Consolidation | — (every slot agreed) | |

Language of the repo is English — code, comments, docs, commit messages, this file. The graph is written in Russian; never translate graph node names when referencing them.

## Persistence rules
State lives in the **repo** or in the **graph** — nowhere else. The harness's built-in memory (per-project memory directory, conversation summaries, `/tmp`, machine-local files) is **forbidden entirely, not by category**: no project fact, no user preference, no note on working style. The one file in the session's temp directory is the session ledger (the `iskron:iskron` door's start): it dies with the session and never moves to memory — that is not storage. (why: local memory is invisible to every other agent and machine, so it drifts silently and breaks the reproducibility that makes a second machine or agent possible.)
- **Repo**: code, configs, rituals (how to act here), branch state — the artifact itself.
- **Graph**: methodology, design decisions, open questions (vimarshas), plans, handovers, lessons, gotchas, hints — the thinking around it. Do not restate graph content in the repo; link the vimarsha or holon.
- **Routing for “remember / think through / learn”:** how to act in this repository (ritual, command, order of steps) → this file; a fact about the user themselves → their personal realm; knowledge about the project, its meanings, ideas and gotchas → the graph, never this file.
- **Fetch state; never reconstruct it from memory.** No source for “we decided…”? Stop and read the graph or the repo before acting.
- **External design/spec files are drafts for intake**, not the record: the graph holds the decisions; such a file is one rendering of them.
- **The shelters are named, and there are three.** Under pressure, laziness finds the undisciplined surface: prose in this file; a sinn-phenomenon for something that acts; a lone `context` arrow that silences the detector. The finish line of any record: **a node is not written until its puller is named** — which kriya breaks if the node disappears? None — that is parking, not recording. And the fork is read BEFORE writing, not from a warning after: a thing enters the graph as the place a doer acts through — `upadhi` on the kriya that goes through it — not as a thing-in-itself or its concept.
- **This overrides the harness's own memory instruction**, which invites a `project` category and will keep inviting it — the pull is strongest exactly when something feels worth saving and this file is long out of context. Route instead, always — and **before finishing, check that every durable fact from the context is persisted by this routing: an unpersisted fact is a failed task, not a nicety** — by asking **whose fact is this?**
  A repo convention, a code fact, this project's procedures, **its servers, deploy pipeline and dated debts** → this file / docs / code, or a node in this repo's realm; work state, a decision, an open question → a vimarsha in the graph. A dated debt (renewal, deadline) is a node carrying the date in `attrs`. A project's rules never land in another project's or the user's graph.
  A fact that is the **user's own** and serves no single project — their machines, deadlines, people, cross-project lessons → their personal realm `@nick/mind` (`iskron:minding`), written at the moment of learning, not at session end; a fact about **another** project → that project's realm. Standing preferences split by whose they are: personal (how to talk to the user) → `@nick/mind`; anything affecting the process and result of development → this file or the project realm. Agent behavior is configured **only** by committed worktree files (AGENTS.md, the hooks file) and the project graph — never by files outside the worktree: a global instruction file, harness memory and user-level hooks are machine-local and break the flow on other machines and for other people.
- The local memory directory is **evacuated and frozen**: its `MEMORY.md` is a one-line prohibition stub, and the memory-guard `PreToolUse` hook blocks any write there (exit 2) at the moment the saving instinct fires.

## Session lifecycle
Graph = the work (structure, open questions, what is next). Git = how we got here (SHAs, branches, PRs). **Git references never enter the graph** — no SHAs, no branch names, no PR numbers, no “shipped/merged” in node bodies.
- **Session start:** the Start section of the `iskron:iskron` door — it ends in readiness, not in reading: realm and role named, standing taken with one `iskron_stand` call only on watch (the word «вахта», `start`, an invitation line, a frame), the greeting delivered; the role's queue and the maps are read on occasion, not at start. Addresses live in the Cover above. Address the owner by the seq of role `#3`, not the `me` sentinel.
- **Starting work: graph first, then project, then code.** A substantive task enters in three beats: (1) **graph reconnaissance** — what is recorded about the site of the change, which vimarshas are open, what was decided and rejected, **and what is recorded about the external surfaces the work will touch** (a recorded observation outranks your memory of a foreign API); driven by `iskron:entry`; (2) **integration field** — from the focus holon, its steward role and the nodes of the change, derive consumers, effects and neighbouring holons via `iskron:integrity`; walk the relays with `lens="trace"`; design the missing kriyas/phenomena, weave broken links with `iskron:weaving`; (3) **design** of the change (`iskron:design`) — and only then code. The one exception is explicit: the human said “just work” — then go to code and pay the reconnaissance debt at the task-end reconcile. Silence is not “just work”.
- **A decision is recorded the moment it is made, not when it ships** — wherever it arrives (chat, socket, two agents agreeing), it stands in the graph at once, with the modes it actually has right now: epistemic no higher than `anumita`, ontic `anagata`, volitive `chanda`/`adhimoksha`. Record who decided and what counts as done. (why: a decision left in the conversation that carried it dies with that conversation; a late record is the same failure delayed — what you remember deciding is not what was decided.)
- **Every task is described before it is begun — and recorded as what it is.** Before the first change outside the graph, the work stands in the graph by its carrier: a one-off act — an anga vimarsha on the transformation it moves (a large one — its own bianhua); **a kriya only for a repeatable transition** whose every run eats the same ahara and yields the same utpatti. The one-glance test: ask the “kriya” what it will eat and produce on the *next* run — no answer means it is a task. While work runs, the graph moves with it.
- **Every merge → update the graph.** A push that only opened or updated a PR shipped nothing. The post-merge sequence hangs on the merge **event** — never on a lull. When merged, each act below is mandatory:
  - **Check against reality.** Record what positions the change in the target system (architecture, module APIs, delivery, integration); pure repo mechanics (lockfile noise, internal refactors, file moves) stay in git. Updating the graph means weaving, not editing prose: a paragraph about your work swelling in someone else's node body is a smell — almost always a kriya or phenomenon you did not create and an edge you did not draw. Zero nodes and zero arrows after a substantive wave is an unfinished step — say so plainly if truly nothing, and name why.
  - **Advance the map.** Keep open work attached by `anga` to the transformation it moves. The `genre=hint` seed is one per transformation, not a journal: only what matters after the session.
  - **Close along the axis, not by the feeling of “done”.** Record the answer as `addressed_by` on the node that carries it. Release (`visarjana`) is a separate volitive act: a distinction is answered by its form; a behavioral claim needs an observation on its carrier (*Reality*). Release yourself when three things meet: the answer stands in the graph as a node; the repo shows it; reality shows it as far as it is reachable — where unreachable, the user's word stands instead, and you asked for it. Otherwise prepare the release and present it to the owner.
  - **Sweep the shipped holon.** A push realizing designed nodes switches their modes (anagata→vartamana, kalpita→pratyakshita) across the *whole* designed contour, not only the touched nodes, and ends the design vimarshas the shipment resolved.
  - **Work the inbox.** `posed_to` questions the work answered end by the rule above; do not judge the rest by age.
  - **Reconcile code and graph.** The end of every substantive task is the `iskron:reconcile` sweep: area nodes against the code (ontics, names, honest modes; a task does not pose as a kriya), code against the graph (a meaning-bearing comment → graph, a reference in code), all three outcomes of every considered alternative recorded. Remaining debts — as vimarshas, not narrative.
  - **Feedback reflection** — on a merge, and on closing a session no merge crowned: examine the session's experience *of the method itself* — where a skill, rule or surface failed, surprised, or worked for the wrong reason; check against what is already said and record only a case worth recording, **addressed**: into the graph of that system's work, anchored on the tool's node or holon, `posed_to` its steward; method-in-general → the owner role. Driven by `iskron:feedback`. **An empty reflection is a valid outcome: zero records beat an opinion.**
  - **Vocabulary pass.** Re-read what you are about to land — repo text and graph nodes — for borrowed project-management words (ticket, backlog, sprint, epic, story, done, blocker, committed). Do not substitute on your own: name each to the user and ask what it is called in this project. (why: a renaming is the owner's act, and a confidently wrong replacement reads as native and is never questioned again.)
- **Design is not done until its decisions, risks and lifecycles are in the graph** — whatever elicited it. A design/spec file written by another toolset is a draft view: intake it (`iskron:intake`, then `iskron:design`) **in the same session**, never deferred to a push. Decisions and risks born during execution still land in the graph before session end.
- **A claim you made is not a claim you accept.** Behavioral claims (“the fix works”, “the daemon writes that line”) are closed by the cold `verifier` subagent's verdict, never by your own re-reading — give it the claim, the carrier and the falsifier from *Reality*, and **wait for the verdict**. (why: you see your change as intended, not as it is.)
- **Hook merging.** Where the harness has a hooks file, entries of different toolsets coexist — add alongside, never overwrite foreign ones.
- These reminders are automated where the harness can: the session-start hook, the push hook, the merge hook and the memory-guard live in `.claude/settings.json` — one line each; check all four are wired. No spec-write hook: workflow-suite interop is `none`.
- **Keep this file honest.** It is generated by `iskron:iskronify` and stamped below with its contract. Propose a re-run when the installed skill's description names a higher contract (its number is the description's first word — the check costs no call), or when the sources this file is derived from moved after the stamp date (`git log -1 --format=%cd -- <files>` against it).
- **Keep the toolchain fresh.** Updates are on by default: take them as the channel delivers, do not pin. (why: a stale skill drifts from the tool surface it names and degrades you silently.)

### Stage self-review
Gate green and a coherent stage done — a PR opened or updated, or you are about to touch nodes beyond those you started with — re-read your branch diff against the trunk for: bugs, fragile spots, weak error handling, DRY violations, repeated patterns, missing or useless tests, god units mixing concerns. Fix in the **same branch** and push again — or say plainly that nothing surfaced. Do not invent findings. **Per stage, not only at the end.**

### Cold stage review
**Self-review does not replace cold review.** Re-reading your own work you see what you meant, not what you wrote. Both, in this order: yours first, then the cold one.

After the self-review of an opened/updated PR or a finished major stage, **open a review by a top-tier subagent** (role `reviewer`) — **in a separate worktree** where the spawning tool offers isolation (in Claude Code, the `isolation` parameter). If it cannot run, say plainly that no cold review happened. **Only the push has a watchdog** — a stage closed without a push reminds nobody; there the review is held by you alone, an acknowledged gap.

The reviewer's field is four things, all mandatory: the **branch diff against the trunk** (the whole branch, as the merger will see it); the **repository itself** (a diff without surroundings reads as style, not correctness); the **focus holon and its steward role** from the Cover; **references to the graph nodes entering the diff** — the leading vimarsha and every kriya, phenomenon and rule the branch's change embodies; never your retelling. The reviewer runs `iskron:integrity` read-only from those nodes and returns, besides code findings, an **integration report**: affected holons and roles, relays walked or broken, open questions, neighbours' readiness by available evidence, whom to wake via `iskron:standing`. Unknown stays `unknown`, never “ready”.

If references are missing or a trace breaks, the reviewer returns `NEEDS_CONTEXT` and names the gap: that is a graph defect, not a briefing nit — design the missing nodes, weave the edges, then repeat the review. Findings are fixed in the same branch; a finding you disagree with is declined with a recorded “why” (in the PR or on the node): silently dropped review teaches the next one not to review.

### Branch discipline
One branch until it merges — commit follow-ups into it; no new branches on top before the merge. After a merge (see *Definition of done*):
1. `git checkout main && git pull`.
2. Delete the merged branch; prune others already in `main`.
3. Update the graph: the change is on `main`, not in a branch — weave the shipped state into the holon, end what the merge resolved (`iskron:weaving`).
4. Confirm the cleanup before the next task.

## Working principles
1. **Think before code.** Name assumptions; ask when unsure — naming *what exactly* is unclear, not just “which option”. **Questions to the human are asked as text** — never through an interactive option picker: a list of options replaces the question with an answer, imposes your frame and hides what is actually unclear. Raise competing readings; object when you see a simpler path or a false premise. Check repo + graph before writing; fetch, don't recall. Touch the live system before trusting a type, a name, a doc. Questions beyond the boundary or mandate become vimarshas `posed_to` the owner role — not silent decisions, not chat-only questions.
2. **Simplicity first.** The minimum code for the task. No speculative features, no abstractions for single-use code, no handling of impossible errors. Validate at boundaries; trust internal invariants. 200 lines that could be 50 → rewrite.
3. **Stay inside the repo boundary.** Never leave this working directory. A change belonging to another holon — another repo, service, someone else's contour (e.g. anything in `nix-config`) — is not yours across the border: record it as a vimarsha on that holon's node in its own realm, anchored where its owner orients, `anga` to the transformation it serves.
4. **A second implementation is an event to report.** About to write what already exists — the same component for a second consumer, the same rule in a second service? First derive both places through the integration field (`iskron:integrity`), then name them to the user and propose reunification or a named, deliberate fork. A new consumer gets its edges to the kriyas and phenomena in the same move it appears in code.
5. **Surgical changes.** Touch only what the task needs. Do not reformat or refactor neighbouring code; the linter is the authority on style. Delete only dead code your change created; flag the rest, don't delete.
6. **Goal-driven execution.** Tasks → verifiable goals. Bugs: pin with a failing test before the patch (no ad-hoc curl/bash debugging). Multi-step work: a plan of `step → check` pairs, looped until each passes. Runtimes are verified in the real environment — *Reality* names this project's carriers and who reaches them. Name the falsifier before you look (“what observation would refute this?”) and observe the carrier itself, never the source that should have produced it. Ending the questions your change touched goes by the Session lifecycle — along the axis, not by feeling.
7. **Read before answering an open question.** Tasks framed as *discuss / think through / investigate / design / plan / analyze / “what do you think”* — anything beyond “do X specifically” — are answered from recorded thinking, not training data: ask the graph first, several ways (one miss ≠ absence). Driven by `iskron:entry`.
8. **Think in the graph, speak the project's language.** The structural vocabulary — kriya, phenomenon, holon, role, vimarsha, the three mode axes — is for reasoning; it never appears in what you say to the user until they use it first. Talk *about* work in plain words: a question, a change, what is open, what it resolves — never ticket/sprint/backlog. (why: a borrowed word arrives with its method's script, and then you act out the borrowed script instead of what is in front of you.)

## Integration field — from the graph only
The focus holon `#1` and its steward role `#2` are the only permanent root of traversal. A list of shared surfaces, consumers and dependencies is **not kept in this file and not asked of the human**: such prose goes stale during the very work and cancels the real traversal with a false sense of completeness.

For every change, name the graph nodes whose embodiment enters the diff and run `iskron:integrity`. Trace a phenomenon both ways with `iskron_orient(lens="trace")`; walk a kriya's `next` thread and its `ahara`/`utpatti`/`upadhi` relays; an exit into another holon leads to its steward role. One standing anchor: the local socket protocol (`net-observer-ipc`) lives at holon `#7 «Подсистема чтения»` — `context` edges into it reach the readers; the serving side is `bin/net-observerd`. Touching that surface obliges the walk; adding a consumer obliges the edge.

A dependency the traversal did not find is a model defect, not a reason to append a list: design the missing kriyas and phenomena, weave the unwoven edges (`iskron:weaving`), put waiting-on-someone as a vimarsha and wake the addressee via `iskron:standing`.

## External surfaces — what you use and do not own
Foreign APIs, SDKs, CLIs, protocols, vendor schemas — here mostly undocumented: private macOS tools and logs (`wdutil`, `ipconfig getpacket`, `scutil --nwi`, CoreCapture, `symptomsd netepochs`), sing-box's Clash API and log, DuckDB. The agent **guesses** these by construction: it remembers them from training, and memory is indistinguishable from knowledge from the inside. The cost is not ignorance but confidence — a field that does not exist looks in code exactly like one that does, and diverges on the live call, not at build.

- **Before the work, pin the part of the surface the work will touch** — as a graph node, with the macOS/crate/vendor version you looked at: the version is part of the surface's identity.
- **Sources rank by seniority — pratyaksha before shabda.** First-hand observation (a real call, `--help` of the installed binary, output you saw on this machine) outranks documentation; documentation outranks memory; **memory is not a source at all**. Write `pratyakshita` only for what you observed yourself, `anumita` for what docs imply; never raise it because “that's how it usually is”.
- **Weave the link.** An external-surface node is `upadhi` to the kriya acting through it (or `ahara`/`utpatti` when it feeds or receives data). Without the edge it is an orphan label.
- **Keep it current.** Found a divergence, or the vendor moved a version — fix the node in the same move, and lower its epistemics if you did not observe the new state. A silently diverged node is worse than none: people act on it.
- **The reference works both ways, and the second way matters more here.** Source touching an external surface carries `(realm net-observer, node #N)` — and you **read that node before the work**: it is your own first move against guessing.

## Reality — what a claim is checked against
Only the rows below are settled; classes without a named carrier sit in *Ceiling* rather than as aspirational lines.

| Claim class | Canonical carrier | How to observe | Who |
|---|---|---|---|
| Pure logic (sample mapping, trigger conditions, wire round-trip) | the test binaries of the default members | `cargo test` — read its own exit code, never a pipeline's | agent |
| Compiles and lints clean | the default-member build | `cargo build` then `cargo clippy --all-targets --all-features -- -D warnings`, each exit code read separately | agent |
| The `macos` crate compiles and its tests type-check (not run) | the crate's own compile for the real target | `cargo check -p macos --tests --target aarch64-apple-darwin` and `cargo clippy -p macos --all-targets --target aarch64-apple-darwin -- -D warnings` on any host with the pinned toolchain — the crate has no DuckDB dependency, so the cross-compile reaches it; running the tests still needs a Mac | agent |
| The menu bar compiles and lints | a compiled `net-observer-bar` | inside `nix develop`: `cargo build -p net-observer-bar`, `cargo clippy -p net-observer-bar --all-targets -- -D warnings` | agent |
| A bar element is drawn where the layout says (presence, position, containment) | the bar's headless windows on gpui's test platform | inside `nix develop`: `cargo test -p net-observer-bar` — `debug_selector` + `VisualTestContext::debug_bounds` | agent |
| The words a bar tooltip shows | the same headless window, hovered | `simulate_mouse_move` onto the element, `advance_clock` past the hover delay, then `debug_bounds` for a selector carrying the tip's own text | agent |
| A bar element is NOT drawn in a view (absence) | a headless window opened ALREADY in that mode | same run, fresh window: gpui's debug-bounds map only grows over a window's life, so a window that once drew the element can never say it is gone | agent |
| The nix packages build (daemon, CLI, bar) — from a fresh `Cargo.nix` | the derivations `nix build .#net-observerd`, `.#net-observer-cli`, `.#net-observer-bar` produce | the `nix-build` workflow on macos-latest, one job per package (`gh pr checks <n>`) — first green run 2026-09-16 (cold: daemon ~30 min, CLI ~23 min, bar ~21 min); from Linux the darwin attributes evaluate (`nix eval --raw .#packages.aarch64-darwin.net-observerd.drvPath`) but cannot be built | agent (via CI) |
| The crate2nix route builds DuckDB from source (`buildRustCrate` driving `libduckdb-sys`) | the `store` and `triggers` crate derivations from the same `Cargo.nix` | `nix build .#checks.<system>.store-crate --print-build-logs`, then `.#checks.<system>.triggers-crate`, each exit code on its own — observed on x86_64-linux 2026-09-16 (~25 min cold on 22 cores) | agent |
| The checked-in `Cargo.nix` is fresh | the regenerated file | inside `nix develop`: `crate2nix generate`, then `git diff --exit-code Cargo.nix crate-hashes.json` — the same pair CI runs | agent |
| Pure logic inside an Apple-only crate (bar folds/captions, `macos` parsers, capture-start seam) — on a Linux box | the same functions compiled in a scratch crate OUTSIDE the repo against the real workspace crates | copy the gpui-free / objc-free functions and their tests into a throwaway crate in the scratchpad, point `[dependencies]` at the workspace crates by path, `cargo test` and `cargo clippy -- -D warnings` there — first used 2026-09-17; the gpui/objc half stays a CI claim | agent |
| The daemon's live behavior, read over the socket (status, incidents, named diagnoses) | the running daemon's control socket on the owner's Mac — `0660 root:staff`, the ssh user is in staff | `ssh <mac> "printf '\"Status\"\n' \| nc -U -w 5 /var/lib/observer/observer.sock"` — newline-delimited JSON: `"Status"`, `{"Incidents":{"limit":N}}`, `{"Query":"Silences"}`, `{"Query":{"Why":{"ts_us":…}}}`, `{"Query":{"Connections":{"group_by":"process"}}}`; first used 2026-09-17 | agent |
| The record's contents (rows really written) | a copy of the Mac's `observer.duckdb` + `.wal` (group-readable `staff`), read offline on Linux | `scp` both files, `cargo build -p net-observer-cli`, `target/debug/net-observer-cli --db <copy>/observer.duckdb query "<SQL>"` — the first open replays the WAL and takes minutes; later queries are fast; first used 2026-09-17 | agent |

**Ceiling** — claim classes with no reachable observation, and why:
- **The menu bar actually renders / a click does what it says.** Compiling and headless layout are reachable (rows above); *running* it and seeing the panel is not something the agent can observe — that claim is closed only by the owner's eyes.
- **The daemon's live behavior where neither the socket nor the record shows it** (the ring really freezes, the passive tier really silences the wire, the bar shows what the daemon said). What remains out of reach is the bar's window; such a claim is closed only by an observation named aloud *before* looking — never by re-reading the diff.
- **A change rebuilt only the affected crates.** Reachable only by reading a `nix build --print-build-logs` run after a real change on a warm store; a green build alone says nothing about reuse.

**The table grows by use.** The moment a session learns a carrier this table does not hold — a named carrier, an observation that turned out reachable, or unreachable (→ *Ceiling*), a wrong command here — write the row then, in that session, before the work that taught it closes. (why: an unwritten carrier is the one the next agent will not find, and the same claim gets accepted on weaker evidence next time.)

## Graph ↔ repo: where things live
| Concern | Repo | Graph |
|---|---|---|
| Code, configs, lockfiles | ✓ | |
| Commands, conventions, stack | ✓ (AGENTS.md) | |
| Branch state, what is in flight | git + PR body | ✓ (`genre=hint` seed — only what matters after the session) |
| Methodology, ontology | | ✓ |
| Design decisions, open questions, gotchas | | ✓ (vimarshas / nodes; code and this file carry references) |
| Plans, session handovers | | ✓ |
| Commit history, PRs, SHAs | git | (never in the graph) |

**`HANDOVER.md` is not kept — a decision, not an oversight.** Branch state already has homes, and a hand-written file is the only one that diverges silently: the branch and what is in flight — `git branch`/`log` and the open PR (its body is assembled from the session ledger); how a claim is checked — *Reality*; why it was decided and what is open — the graph; running work — the modes of its nodes. (why: hand-written prose must be updated by whoever is busy with something else, and “the branch moved on” is the event they learn about last.)

## Commands
| What | Command |
|---|---|
| gate (the whole thing) | `just gate` → fmt-check → `cargo build --all` → `cargo test --all` → clippy `-D warnings` |
| build | `cargo build --all` |
| test | `just test` → `cargo test --all` |
| lint | `just clippy` → `cargo clippy --all --all-targets --all-features -- -D warnings` |
| format | `cargo fmt --all` |
| run | `just run ARGS` → `cargo run -p net-observerd -- ARGS` |

- **The gate is one call — `just gate`, run inside `nix develop`** (the bar only compiles there). Never assemble the steps by hand: a hand-built chain silently drops a step and still ends green. CI is the recorded exception: it splits the same checks across three workflows for parallelism and per-job caches — when the workflows change, re-audit that they still cover the gate's chain.
- Run every cargo step so its **own** exit code is visible. Piping cargo into `tail`/`head` makes the pipeline's status the pager's — this has already produced a false green here.
- Every step carries `--all`: without it cargo uses `default-members`, which excludes `net-observer-bar` — a workspace-looking clippy run that never checks the GUI is exactly how a `type_complexity` error reached `main`.
- On a Linux box `cargo build --all` cannot succeed (gpui/objc are Apple-only) — use the per-crate carriers from *Reality*; the full gate runs on a Mac or CI.
- `clippy::pedantic` is deliberately NOT enabled: measured 2026-09-01 at **215** warnings. Turning it on is a refactoring commitment, not a flag.
- The `duckdb` crate builds its C++ engine from source (`bundled`): a cold build reaches ~10 minutes — generous timeouts; a long build is not a hang.

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
  collector-{link,proxy,dns,route,host,wifi,neighbors,air,connections,announce,singbox-log}/
  triggers/             # Condition/Handler/Trigger + engine (re-arm/backoff)
  config/               # figment: per-subsystem toggles
  macos/                # real adapters: raw ICMP, IP_BOUND_IF, Clash API, DHCP/ARP, pcap ring
  net-observer-ipc/     # local socket protocol: Request/Response, StreamFrame
```

`ARCHITECTURE.md` holds the pipeline, crate graph and data model; `README.md` the quick start; `docs/roadmap.{md,html}` is a **generated snapshot** (regenerate with `iskron:product-roadmap`, never hand-edit).

## Code conventions
- **Meaning lives in the graph, code references it.** A comment carrying a decision's rationale, rejected alternatives or integration wiring is a graph node living away from home: move the meaning to the graph, leave `(realm net-observer, node #N)` in the code. Step mechanics stay in comments; the boundary is *why* vs *how*. **The reference works both ways:** put `#N` where the next reader would otherwise start guessing — and having cited a node, check it really says what you cited it for; if it diverged, fix the node in the same move.
- **Maximize Rust.** Prefer a pure-Rust crate for every component. Native deps only where no adequate equivalent exists, each named here: **DuckDB** (no pure-Rust DB with native `ASOF JOIN`) and, v1 only, **`tcpdump` as a child process** — three times: the pcap ring, the LLDP/CDP patrol capture, the announce listener's stream. The child is only ever the *capture*; every frame is decoded in-process by pure Rust, never tcpdump's text output (realm net-observer, node #92). Any future GUI is `gpui`.
- **v1 = observe + detect, never act.** No `launchctl kickstart`, no watchdog, no notifications — resolved by the owner: the daemon's outward interface is the event bus (`incident`, `incident-closed`); a reactor, if ever needed, subscribes externally (realm net-observer, node #20). An operator's own control command is never gated by config — the invocation is the sanction; only the peer-uid check applies (node #91).
- **SKIP, never silence.** A probe that cannot run emits a `SKIP` verdict rather than going quiet — absence of a signal is itself diagnostic. The passive probing tier withholds every probe but keeps one sample per tick with the withheld fields `SKIP`; triggers read that as no measurement — never healthy, never a drop. Two sanctioned withholdings, both bracketed by durable rows and bus frames: the operator pause (`observing_edge`) and the probing-tier switch (`probing_edge`, node #88) — a tick in flight across either edge is dropped whole at the source, bracketed and logged. Post-resume drained samples are still written and published, the drain bounded and reported. The observing state is process-scoped, never persisted — a restart always resumes collecting. Unbracketed silence is a bug.
- **Isolation.** One collector failing must never take down the others; each runs as a supervised task (log and keep ticking). Store write failures are logged as a gap, never swallowed.
- **Errors:** `thiserror` in library crates, `anyhow` in binaries. **Config:** `figment` (file + `NET_OBSERVER_*`). **Async:** `tokio`, kept out of `collector-core`. **Logging:** `tracing`.
- **Test discipline:** unit tests per crate; `store` against in-memory DuckDB; pure mapping logic on fake port impls (no network or root); trigger rules replay recorded incident signatures as synthetic `Sample` streams. Keep new behavior covered.
- **Wire invariants (`net-observer-ipc`):** `serde(default)` on new fields is the standing mitigation, but it saves neither a sender that forgot a field nor a new enum variant at an old receiver (observed live). Reach for: `subscribe_or_widen` (daemon can't read the request → retry `kinds: None`, filter client-side, report whether narrowed); `control` → `ControlOutcome::Unsupported`; `decode_handshake` as the single place telling a one-shot `Response::Error` from an in-band `StreamFrame::Error`; `decode_stream_frame` → `StreamFrame::Unrecognized` (one frame lost and named, never the stream). Run the `--all` gate when touching these types.
- **Rituals with teeth** (the rationale nodes are the reference):
  - `net-observer-bar` is outside `default-members` — a plain `cargo build`/`test` never sees it; use `--all` or `-p net-observer-bar`.
  - **Build the bar inside `nix develop`** — the pinned toolchain; a bindgen failure there is a libclang lookup problem, not Metal (why: the workspace pins gpui's `runtime_shaders`, so no Metal toolchain is needed at build time; bindgen over `dispatch.h` still needs libclang + SDK headers — nix takes both from `bindgenHook`, a Mac from the Command Line Tools).
  - Runtime paths stay under `/var/lib/observer/*` — `/var/lib/net-observer` and `/var/log/net-observer.log` belong to the shell oracle, which still runs alongside (why: two daemons fight over the pcap ring and drop-box). Its watchdog is already gone and nothing auto-recovers, by decision (node #20); its verdict vocabulary remains the behavioral ground truth this rewrite must not silently drift from (`~/projects/nix-config/hosts/mac_aarch64/net-observer.nix`).
  - `Cargo.nix` is CHECKED IN, generated by the crate2nix CLI in the dev shell (node #95). Whenever `Cargo.lock` changes: `crate2nix generate` inside `nix develop`, commit `Cargo.nix` + `crate-hashes.json`; CI regenerates and fails on a diff. Native-crate overrides live in `crateOverrides` in `flake.nix`, one comment per override (node #80).
  - The schema is additive **forward only**: an older build's positional writes to a widened table are refused by DuckDB's binder and dropped as gaps — never switch the Mac back to an older revision without expecting a gap; the daemon warns once per widened table at startup (node #150).

## What to update when
- `AGENTS.md` — by the inverted default: **if it can be learned by reading a graph node, it is not here.** This file holds only what is needed BEFORE an agent reaches the graph: commands, the entry into orientation, code invariants no linter expresses, forks that must stop you before acting — and it changes when THOSE change. (why: a paragraph here taxes every future session; a graph node is paid for only by the session that needs it — and this file accepts sloppy writing silently, the graph does not.) Pruning existing prose is a reconcile move with transfer into carrying nodes, never deletion first.
- `CLAUDE.md` — a symlink to `AGENTS.md`; never edited separately.
- `docs/roadmap.{md,html}` — regenerate with `iskron:product-roadmap`; where it disagrees with the realm or the code, they are right.
- The `net-observer` realm — every merge (Session lifecycle).

## Git workflow
- **Conventional commits** (`feat:`/`fix:`/`chore:`/`refactor:`/`docs:`/`test:`). Branches `feat/…`, `fix/…`, `chore/…`. PR titles in the same format.
- **No co-author trailer and no AI attribution — ever**: not in commits, PR bodies, issues or reviews.
- **Local gate — one call**: `just gate` inside `nix develop` (see Commands). There is no pre-commit hook in this repo — run the gate by hand before pushing.
- **Forge**: GitHub, `origin` = `git@github.com:gurinderu/net-observer.git`. CLI is `gh` (authenticated as `gurinderu`); watch checks with `gh pr checks <n> --watch`.
- **CI**: three workflows on `macos-latest`, all gating pull requests *and* pushes to `main` — `lints`, `tests` (each with a dedicated bar step), and `nix-build` (three jobs, one per package; `nix-build-daemon` first diffs `crate2nix generate` against the checked-in `Cargo.nix`). Caches save only on `main` (10 GB cap); the nix jobs pull from and, on `main`, push to the Cachix cache `net-observer` — what the owner's Mac substitutes from (node #133). PR↔main parity is complete: no post-merge-only jobs.
- **Definition of done**: a pull request into `main`, `gh pr checks <n> --watch` green, merged without conflicts. Branch discipline keys on that merge, not on a push.
- **Never** `--no-verify`, `--force`, `--no-gpg-sign`, or `git reset --hard` without an explicit instruction from the user. Stage explicit paths only — never `git add -A` / `.` / `-u`.

*(iskronify: контракт `12`, штамп `2026-09-21` — предложи перезапуск, когда описание
установленного iskronify называет контракт выше или когда источники, из которых
выведен этот файл, сдвинулись после этой даты.)*
