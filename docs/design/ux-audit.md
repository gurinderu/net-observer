# UX audit — the operator's path from a question to an answer

**Date:** 2026-09-04. **Method:** the five operator scenarios the owner named, walked
step by step against the code as it stands on `main` (bar: `bin/net-observer-bar/src/`,
readers: `bin/net-observer-cli/src/`, wire: `crates/net-observer-ipc/src/lib.rs`).
No code was changed. Every "as it is now" step below is cited to a file and line.

This is a view, not the record: the decisions live in realm `net-observer` (`r210`).
Where a proposal touches something the owner has not decided, it is not proposed —
it is named at the bottom under *What only the owner can settle*.

## What this product is for, and what the interface is measured against

The daemon exists so that after the network dies, the operator can prove **which layer
failed** and take that proof to whoever runs the network. So the interface is judged on
one question only: *how far is the operator from a defensible statement about a layer?*
Graphs are not the product. A sentence a network administrator cannot wave away is.

Two structural facts shape everything below and are worth stating once, up front.

**Fact 1 — the record and the live view are mutually exclusive.** The daemon is the sole
owner of the DuckDB file; DuckDB takes a per-process lock, so nothing else may open it
while the daemon runs (`bin/net-observer-cli/src/main.rs:3-16`). Every historical answer
— `why`, `incident-context`, `wedge-or-starvation`, `gateway-ramp`, `gaps`, `neighbors`,
`vulns`, `topology`, `segments`, `history`, `query` — is offline-only. To ask the record
what happened, the operator must **stop the daemon that is recording**. The CLI says so
politely (`main.rs:716-728`: *"net-observerd is running and holds the DuckDB lock; stop
it for offline SQL…"*), but the politeness does not remove the trade: investigating the
last outage means being blind to the next one.

**Fact 2 — the bar cannot ask the record anything.** `Request` has exactly four variants
— `Status`, `Incidents { limit }`, `Control(cmd)`, `Subscribe { kinds }`
(`crates/net-observer-ipc/src/lib.rs:48-67`). There is no historical query on the wire at
all. The bar is a pure socket client by design, so **none of the eleven offline analyses
is reachable from the GUI, and none could be without a new request variant.** The bar
shows the present tense and nothing else.

Everything painful in scenarios 2 and 3 descends from these two facts.

---

## Scenario 1 — "the network is slow right now"

### As it is now

1. The operator looks at the menu-bar icon. It is one glyph, no text
   (`menubar.rs:299-306`): `⚫` daemon unreachable, `⚠` daemon answered unusably,
   `⏸` collection paused, else the health dot `🟢`/`🔴`/`⚪` (`status.rs:119-125`).
2. Hovering gives a tooltip with the full `render_status` block — link and proxy lines
   plus incident lines, timestamps as **raw epoch microseconds** (`status.rs:17-60`,
   `menubar.rs:308-318`).
3. Clicking opens the 320×560 panel (`menubar.rs:59-62`). Body, in order
   (`ui.rs:648-670`): two sparklines (`gw rtt`, `load`), six status rows
   (`gw`, `direct`, `link` age, `tun`, `selector`, `proxy` age), then up to five
   incidents as `trigger_id → open · 12s ago` (`ui.rs:912-951`).
4. If the answer is not on that one screen, there is nowhere to click. The panel has
   **exactly two interactive elements** — the observing toggle (`ui.rs:808`) and the
   `Menu` row (`ui.rs:1029`). `ui::row` (`ui.rs:1326-1341`) is an inert `div`: no
   `.id()`, no `.on_click()`. Every verdict and every incident is a dead label.

So: 1 glance, 1 click, and then the trail ends. For the narrow question *"is the gateway
answering and is the tunnel up"* the panel is genuinely good — two facts, colour-coded,
with six minutes of history behind them.

### What obstructs

- **The health dot is derived from two facts out of eight.** `health()` reads only the
  gateway verdict and the tun probe code (`status.rs:83-105`). DNS, host load, Wi-Fi,
  neighbours and route never move it. "Slow right now" caused by a saturated host or a
  collapsing radio shows a **green** icon. The panel's own body has the same shape: it
  renders link and proxy, and never renders `snapshot.dns`, `snapshot.wifi`,
  `snapshot.neighbors` or `snapshot.topology` at all, though all four are fetched on
  every 3-second poll.
- **"Slow" has no representation.** The verdict vocabulary answers *up or down*. The one
  latency signal is the `gw rtt` sparkline, and it has no axis, no time labels, no
  min/max and no hover readout — the only number is the latest value in the caption
  (`ui.rs:1180-1268`). A gateway degrading from 8 ms to 240 ms over ten minutes is
  visible as a shape and unavailable as a number.
- **Sparkline history is the bar's own, in-process, and dies with the process**
  (`ui.rs:303`, `menubar.rs:216`). Restart the bar during an incident and the window
  goes blank. Nothing in the UI says the history is the bar's rather than the record's,
  so an empty plot reads as "the network was fine".
- **Quiet mode is ambiguous at the icon.** Under quiet the gateway verdict is `SKIP`, and
  `health()` maps `SKIP` + healthy tun to `NoData` → `⚪` (`status.rs:87`) — the same
  glyph as "the bar just launched and has measured nothing". The panel does disambiguate
  with a muted `quiet` sub-label (`ui.rs:706-710`), so this costs one click, not a wrong
  belief. Still: the one glyph that means "a hole was deliberately put in the
  measurement" is the same glyph that means "no measurement yet".
- **Offline is hover-only in the panel.** With the daemon down the rows keep rendering
  the last snapshot with no staleness marking, and the footer freshness line keeps
  counting up off those frozen timestamps (`ui.rs:1398-1409`). The only in-panel signal
  is a `⚠` glyph whose meaning is in a tooltip (`ui.rs:743-757`). A stalled daemon and a
  stalling network look alike.

### Proposed

1. **Widen the health classifier, or say out loud that it is narrow.** Either fold DNS
   and host load into `health()`, or add a second line under the header naming what the
   dot does *not* cover. The current state — a green dot beside a `load 14.0` sparkline
   — is the one shape a forensics tool must not have.
2. **Render `dns` and `host` as status rows.** They are already in the snapshot on every
   poll and cost one row each. `load5`/`load15` likewise (today `host` reaches the UI
   only as a sparkline).
3. **Give the sparklines a hover readout** — value and age at the hovered column. gpui
   tooltips already exist in this crate (`ui.rs:743-757`), so this is a known pattern,
   not new machinery.
4. **Mark the sparkline as the bar's own short window**, e.g. a caption `last 6 min ·
   this session`, so an empty plot cannot be misread as a calm network.
5. **Distinguish quiet at the icon.** A distinct glyph (or the dot plus a modifier) so
   "I muted the probe" never renders as "nothing measured".
6. **Show staleness in the body when offline**, not only on hover: dim the rows and
   replace the freshness line with `last answer {age} ago` computed from the last
   successful fetch rather than from sample timestamps.

### Cost

(1) is a decision before it is code (see owner list). (2), (4) and (6) are small,
local edits inside `ui.rs` with existing data — cheap. (3) is a modest addition (hit
testing over the 120 columns). (5) is one glyph plus a branch in `apply_glyph`.

---

## Scenario 2 — "there was an outage in the night; work it out in the morning"

This is where the interface fails hardest, and the failure is structural rather than
cosmetic.

### As it is now

1. Icon → panel. The incident is there, if it is among the five most recent:
   `gw-drop → closed · 7h ago` (`ui.rs:912-947`). Beyond five: `+{n} older — see Events`.
2. The operator clicks the incident row. **Nothing happens** — the row is inert
   (`ui.rs:1326-1341`).
3. The operator follows the hint and opens `Events`. The event-log window opens **one
   live subscription for its lifetime** and has **no backfill of any kind**
   (`events.rs:1-13`, `events.rs:627`). Last night's frames were never in this process.
   The window shows the `Ready` ack and then whatever is happening now.
4. There is no other window to try. The map draws the current neighbour sample
   (`map.rs:24-28`); the air map draws the latest slice only (`air.rs:38-41`).
5. The operator now has to leave the GUI entirely. To reach the record they must
   **stop the daemon** and then run, in the terminal: `net-observer-cli why --at
   '03:40'`, `incident-context`, `wedge-or-starvation`, `gateway-ramp`, `gaps`
   (`main.rs:399-437`).
6. Those commands are excellent. `why` prints `gw / gw_rtt_ms / direct / vless /
   tun_code / load1` and then `layer` — the blame — and refuses honestly inside a pause
   (`layer  gap - REFUSED, the daemon was not observing`). `wedge-or-starvation` gives
   the one verdict that decides whether a restart is even the cure, and says `unknown`
   rather than guessing. This is the product working as intended. It is simply not in
   the interface.

### What obstructs

- **The morning-after path does not exist in the GUI at all.** Not "it takes too many
  clicks" — there is no click that reaches it. The panel names an incident and the
  events window cannot show its surroundings, because the surroundings are in DuckDB
  and the bar cannot read DuckDB (Facts 1 and 2).
- **The incident summary is truncated where it matters most.** The panel shows
  `trigger_id`, open/closed and an age. `IncidentSummary.signature` — the diagnostic
  sentence — and `.id` are fetched on every poll and displayed **nowhere** in the bar.
  In the event log the incident row does show the signature, but the id and `closed_us`
  are dropped, so an incident closing looks like nothing at all.
- **The bar never asks for the incident list.** It uses only the bounded ring inside
  `StatusSnapshot`; `Request::Incidents { limit }` has no caller in the bar. Even "show
  me the last fifty incidents" is CLI-only, though the daemon already serves it live.
- **The event log fights anyone reading history.** `want_scroll` is set on *every* model
  change and every filter change, and the render scrolls to the bottom
  (`events.rs:306-311`). An operator scrolled back to an older row is yanked to the tail
  by the next arriving frame. There is no scroll lock, no pause-tail, and no search.
- **Nothing in the bar can be copied.** No keyboard handling exists anywhere in the crate
  — no `on_key_down`, no `key_context`, no `actions!`, no focus handle, no `⌘C`, no Esc.
  A row of evidence can leave the bar only as a screenshot.
- **Investigating costs you the next incident.** Stopping the daemon to run the offline
  commands is a deliberate blind window, and nothing warns the operator that they are
  now unmonitored, or reminds them to restart.

### Proposed

1. **The one change that unlocks this scenario: a historical request on the wire.** Add a
   read-only request the daemon answers *from its own open DuckDB handle* — it is the
   only process that may — returning the canned `store::diagnosis` results the CLI
   already computes: at minimum `why --at`, `incident-context`, `gaps`. The daemon
   already owns the connection; the analyses already exist as SQL in `store::diagnosis`;
   the CLI's renderers already exist in `diagnose.rs`. This removes both Fact 1 and Fact
   2 for the common case, and turns "stop the daemon and open a terminal" into "click the
   incident".
2. **Make the incident row the entry point.** Clicking an incident in the panel opens a
   context view: the signature, the layer verdict from just before it opened, and the
   gateway RTT series across it. With (1) this is a window; without (1) it can at least
   show the signature and the open/close instants, which are already in hand.
3. **Show `IncidentSummary.signature` in the panel.** It is the sentence the whole product
   exists to produce and it is currently fetched and thrown away. This is cheap and does
   not wait on (1).
4. **Scroll lock in the event log**: stop autoscrolling once the operator has scrolled
   away from the tail, with a `jump to latest` affordance. Standard, small, and it makes
   the one scrollable window usable.
5. **A copy path.** At minimum `⌘C` on a selected event row and a "copy as text" on any
   context view. This is the first keyboard binding in the crate, so it also opens the
   door to Esc-to-close.
6. **Warn about the blind window.** If the offline route survives (i.e. (1) is not taken),
   the CLI should say on every offline command that the daemon is stopped and the machine
   is currently unmonitored.

### Cost

(1) is the large one: a new `Request` variant, a daemon-side handler, forward-compatible
decoding on both sides (the `subscribe_or_widen` / `ControlOutcome::Unsupported`
mitigations show the shape), and a GUI surface to render it. It is also the single
highest-value change in this document. (2) depends on (1) for its full form. (3), (4)
are small. (5) is small but new ground — no keyboard infrastructure exists yet.

---

## Scenario 3 — "prove to the coworking space that it isn't me"

### As it is now

1. The operator has the incident (panel or `incidents`), and the analyses that make the
   argument: `gateway-ramp` shows the gateway's RTT climbing before the drop with a
   least-squares slope, and refuses to fit across an observation gap
   (`main.rs:420-433`, `diagnose.rs:409-490`). `wedge-or-starvation` separates "my proxy
   wedged" from "my machine starved" from "the record cannot tell". `why` names the
   layer.
2. `Freeze pcap` in the flyout copies the ring out as an artifact (`menu.rs:263-273`).
3. To hand any of it over, the operator screenshots a terminal, or copy-pastes
   fixed-width text out of it.

### What obstructs

- **There is no export, in either surface.** Every CLI output is space-padded plain text
  (`main.rs:839-854`, `diagnose.rs:158-176`); there is no `--json`, no `--format`, no
  CSV, no export subcommand. The bar has no clipboard path at all.
- **The two commands most likely to be quoted are the least quotable.** `status` and
  `incidents` print **raw epoch microseconds only** — `generated_us 1756731900000000`,
  `OPENED_US`, `CLOSED_US` — with no human timestamp. `events` prints `HH:MM:SS` in UTC
  **with no date**. A pasted incident list cannot be dated by its recipient. Meanwhile
  the `diagnose.rs` commands do this correctly: `stamp` (`diagnose.rs:123-128`) prints
  `<raw ts_us> (<local ISO>)`, deliberately keeping the raw value pasteable back into
  `--at`. The good idiom exists; it just has not reached the live commands.
- **The hypothesis caveats are in `--help`, not in the output.** `vulns` and `topology`
  are documented as hypotheses — CVE matches from banner grabs, spoofable LLDP/CDP — but
  they print through the generic table printer with **no legend**. Pasted into an email
  they read as asserted fact. `air` shows how it should be done: it carries `AIR_LEGEND`
  stating what the number is *not*. The same discipline has not reached `vulns`,
  `topology`, `neighbors`, `segments`, `history`.
- **SQL `NULL` prints as blank whitespace** in the generic printer — indistinguishable
  from an empty string. `diagnose.rs:17-23` names this exact failure and fixes it only
  for its own commands.
- **No output identifies its provenance.** No machine name, no tool version, no
  "generated at". A text block with no provenance is weak evidence by construction.
- **`Freeze pcap` gives almost no feedback, and often none at all.** The menu row has no
  confirmation, no state (you cannot tell whether a ring exists or a freeze is in
  flight), and reports only into `control_msg`. But `control_msg` renders in the panel
  footer — and opening the flyout and clicking a row *closes the panel*
  (`menu.rs:509-528`, `PANEL_HANDOFF` 150 ms). So the outcome of a freeze is written to a
  surface the operator can no longer see. Worse, **`control_msg` is never cleared** — it
  is set and never reset to `None` (`ui.rs:401`, `ui.rs:461-467`) — so an hours-old
  `failed: acting disabled` sits under the map toolbar and in the panel footer, undated,
  looking current.
- **The frozen slice has no address in the interface.** Nothing in the bar or the CLI
  says where a freeze landed or lists past freezes; `blob_ref` is a store table reachable
  only through `query`.

### Proposed

1. **A machine-readable output mode** — `--json` (or `--format json`) across the CLI. It
   makes the record quotable, scriptable, and attachable, and it is the cheapest possible
   route to "evidence I can send".
2. **Human timestamps in `status` and `incidents`, and a date in `events`.** Reuse
   `diagnose::stamp` verbatim: `<ts_us> (<local ISO>)`. Small, and it repairs the two
   outputs most likely to be pasted.
3. **Move the hypothesis caveats from `--help` into the printed output**, as `air`
   already does. A `vulns` table without its caveat is the one output in this project
   that could cause real harm if believed.
4. **Distinguish NULL in the generic printer** — `(none)`, the token `diagnose.rs`
   already uses.
5. **A provenance header on every output**: host, tool version, generated-at. One line.
6. **Give `control_msg` a timestamp and an expiry**, and render it somewhere that
   survives the panel closing (or keep the panel open when a control row is clicked, as
   opposed to a window row).
7. **Make freezes addressable**: report the freeze path in the control result, and add a
   way to list past freezes.

### Cost

(1) is moderate — a serialization pass over the existing result types, mechanical but
touching every command. (2), (4), (5) are each nearly trivial and reuse existing helpers.
(3) is copy plus a print site. (6) is small and repairs a bug-shaped behaviour. (7) needs
the daemon to report the path, so it is small on both sides.

---

## Scenario 4 — "the Wi-Fi is bad"

### As it is now

1. Icon → panel. **Wi-Fi is invisible here**: `snapshot.wifi` is fetched every poll and
   rendered nowhere, and does not enter `health()`. So the complaint has no
   representation on the first screen at all.
2. Menu → `Air`. The row exists only if the daemon declares the collector; it is drawn
   muted as `Air (off)` when disabled, and **absent entirely** when the daemon does not
   declare it (`menu.rs:238-262`). A daemon too old to declare capabilities silently
   loses the row, with no explanation anywhere.
3. The air window is the best-designed surface in the product. It distinguishes five
   states honestly — the collector is off, this daemon cannot collect air, no scan yet,
   the scan ran and failed (`SKIP` plus reason), the scan ran and heard nobody — and only
   the last is drawn as empty air (`air.rs:903-981`). It states its own limits in the
   window rather than only in a comment: overlap is *"a HYPOTHESIS about where the bands
   sit, not measured interference: macOS reports channel occupancy (CCA / airtime) to
   nobody"*, and no element is coloured by severity, so nothing can read as a measurement.
4. It draws each band as one channel axis, our own channel highlighted across it, foreign
   APs as bars whose opacity is signal strength, packed so that crossings on the page are
   crossings in the air. Under it, one line per AP ranked by overlap then loudness, each
   ending `hypothesis: covers 47% of our channel · medium confidence`.
5. `Scan now` sends `ControlCmd::ScanAir` — self-control, not acting — with a real state
   machine: `Asking…` → `Scanning… (a few seconds)`, the button disabled while busy, the
   daemon's refusal quoted verbatim, and `Unsupported` rendered as a *different sentence*
   from a refusal (`air.rs:1091-1146`).

The conclusion "an access point on channel X is sitting in mine" is genuinely reachable
here, honestly hedged, in two clicks from the icon. This scenario is the closest to
working.

### What obstructs

- **The window cannot scroll.** There is no scroll handling in `air.rs` at all. Three
  bands, up to 24 lane rows each, plus a tall caveat paragraph in the header, in a 560px
  window: content past the bottom is simply unreachable. This is the most serious
  interaction defect in the file, and it lands directly on the ranked list of APs — the
  part that answers the question.
- **The plot is a fixed 560 px** regardless of window width (`air.rs:117`), so resizing
  wider gains nothing and narrower clips the axis.
- **`noise_dbm` is carried and never rendered** (`crates/types/src/air.rs:42`), for
  foreign APs and for our own association alike. From the paired `WifiSample` the window
  uses only channel geometry: `rssi_dbm`, `noise_dbm`, `snr_db`, `tx_rate_mbps`,
  `phy_mode` and `reason` are all discarded. **SNR — the single most useful "my Wi-Fi is
  bad" number, already on the wire — is shown nowhere in the product.**
- **A `WifiVerdict::Skip` loses its reason**: it collapses to `own = None` and prints
  *"not associated, or the channel was not reported"*, discarding what the daemon
  actually said. That is a small violation of this project's own SKIP-never-silence rule,
  inside the window that otherwise follows it most rigorously.
- **`StreamFrame::Gap` is applied but produces no visible row** (`air.rs:287`) — the one
  place in these windows where a known hole in the stream is silent.
- **`ScanState::Scanning` has no timeout** (`air.rs:1104`): a scan the daemon accepts but
  never completes leaves the button claiming it is scanning forever.
- **`wifi` and `air` have no chip in the event log** — three of the nine `EventKind`
  variants (`wifi`, `neighbors`, `air`) are unfilterable and their existence is
  undiscoverable from the chip row (`events.rs:355-361`).
- **The air map has no history and cannot have one**, because the system report carries
  no BSSID — correctly documented, and correctly not faked. Named here as a ceiling, not
  a defect.

### Proposed

1. **Make the air window scroll.** Everything else in it is undermined by content the
   operator cannot reach.
2. **Show SNR and noise** — our own association's SNR in the header, `noise_dbm` per lane.
   Both are already on the wire.
3. **Surface Wi-Fi on the first screen**: a `wifi` status row in the panel (SSID, channel,
   SNR) so the complaint has somewhere to land before the operator knows to open the air
   map.
4. **Let the plot use the window width** instead of a fixed 560 px.
5. **Keep the `Skip` reason** for our own association, as the window already does for the
   scan.
6. **Render `Gap` as a note**, as the event log does.
7. **Time out `Scanning`** and say what happened when it elapses.
8. **Add the missing chips** (`wifi`, `neighbors`, `air`) to the event log.

### Cost

All eight are local to one or two files and use data already in hand. (1) is the largest
and is still a contained change. There is no wire work and no owner decision in any of
them — this is the cheapest high-value cluster in the audit.

---

## Scenario 5 — "who is actually on my network"

### As it is now

1. Menu → `Map`. It draws `snapshot.neighbors` as a gateway-centred star, with the
   `topology` uplinks as a strip above, captioned *"uplink hypothesis · what LLDP/CDP
   frames claimed, not a proven physical link"* (`map.rs:584`).
2. Roles are glyph-encoded with a legend, and the legend says the grounds are inferred:
   *"role is inferred from vendor OUI and behaviour, not measured · the list gives the
   grounds for each"* (`map.rs:895-912`). `List` mode then gives each row its grounds in
   words — *"guess: an infra vendor OUI alone"*, *"guess: infra vendor OUI and a
   management port"*, *"vendor is not network gear"*, *"randomized MAC, or no vendor
   data"*. This is exactly right: the hypothesis carries its warrant.
3. `Rescan` sends `ControlCmd::ScanNeighbors` — acting-class, refused unless
   `acting.enabled`.
4. Vulnerabilities are **not here**. Nothing in `StatusSnapshot` or the event stream
   carries CVE matches; they exist only as DuckDB rows, reachable only by stopping the
   daemon and running `net-observer-cli vulns`.

### What obstructs

- **The list cannot scroll** (`map.rs` has no scroll handling), and List mode is the mode
  that advertises itself as complete: the graph says *"+N that the ring has no room for ·
  the list shows every one"* — and then the list silently truncates at the window edge.
  Forty neighbours means most of them are unreachable.
- **Nothing is clickable**: three elements in the whole window (`Graph`, `List`,
  `Rescan`). A neighbour dead-ends — no ports, no vendor detail, no history, no vulns, no
  route to any incident. A MAC cannot even be copied.
- **`Rescan` is the least honest control in the product, and the most consequential.**
  It is the one command that addresses machines that are not this one. It has no
  confirmation, no busy state, no disabled state, no progress; the label never changes
  and the operator can click it repeatedly during a multi-second subnet sweep. Compare
  the air window's `ScanAir` — the *harmless* one — which has a full four-state machine.
  The gradient runs exactly backwards: the self-control scan explains itself carefully;
  the scan that puts packets toward the neighbours explains itself least.
- **The same is true of the flyout's `Scan` row** — one word, warn-coloured, no
  confirmation, sending `ScanNeighbors` (`menu.rs:288-293`). It sits two rows below
  `Freeze pcap` and one above `Refresh`. It is easy to press by accident and hard to
  learn the consequence of.
- **The scan's rungs are unreachable from the GUI.** `ScanOptions { ports, banners, cve }`
  is hard-coded to all-false from the bar (`ui.rs:556-566`). So the GUI can never produce
  the port and CVE data that `vulns` reads — the scenario cannot be completed from the
  interface even in principle today.
- **The map has no freshness and no offline state.** `NeighborsSample.ts_us` is never
  rendered; `Glance::error` is never consulted in `map.rs`. With the daemon down the map
  keeps drawing a stale star with nothing saying so. Of the three windows there are three
  different freshness idioms — none, `scanned at HH:MM:SS`, and a per-row clock.
- **A debug rendering reaches the operator**: the `via` column is
  `format!("{:?}", obs.source).to_lowercase()` (`map.rs:1080`), the only place in these
  windows that bypasses an explicit label.
- **A wording mismatch**: the empty-state in Graph mode says *"press Scan to look"* while
  the button in that window is labelled `Rescan` (`map.rs:768-794` vs `map.rs:1248`).

### Proposed

1. **Make the list scroll**, since it is the view that promises completeness.
2. **Give `Rescan`/`Scan` the treatment `ScanAir` already has**: a busy state, a disabled
   button while in flight, and — because this one speaks to other machines — a
   confirmation that says in one sentence what it will do (*"address every host on this
   subnet"*). The pattern exists; it needs copying to the command that needs it more.
3. **Expose the scan rungs** (`ports`, `banners`, `cve`) as checkboxes on the
   confirmation, each showing whether the daemon permits it. Without this, the GUI cannot
   reach the vulnerability data at all.
4. **A freshness line on the map**, and an offline state that consults `Glance::error`.
   Better: one freshness idiom shared by all three windows.
5. **Make a neighbour selectable**, with a detail line: MAC, vendor, grounds, source,
   ports if known — and a copy action.
6. **Replace the debug-formatted `via`** with an explicit label function.
7. **Fix the `Scan`/`Rescan` wording mismatch.**

### Cost

(1), (4), (6), (7) are small and local. (2) is small-to-moderate and is the highest-value
safety change in the audit. (3) needs a small UI surface but no wire work — `ScanOptions`
already carries the rungs and the daemon already reports dropped ones. (5) is moderate.
Reaching the *stored* vulns from the GUI needs the historical request from scenario 2.

---

## Scenario 6 (added) — "the daemon is not where I left it"

Worth naming separately because it cuts across all five.

- **A paused daemon is well handled and honestly bracketed** — `⏸` at the icon, `paused`
  in the header, an `observing collection off` row in the event log, `Ready` carrying the
  state at subscribe time, and durable `observing_edge` rows in the store so the gap is
  attributable. The offline analyses refuse rather than interpolate across it. This is
  the part of the product that most clearly knows what it is for.
- **But the bar never says when the pause began or who paused it**, though the daemon
  records exactly that. And the *historical* gap set (`gaps`) is offline-only: the bar
  sees only edges that happen while it is watching.
- **The acting gate is rendered wrong on the panel path.** The panel and flyout use
  `control_query` (`ui.rs:274-281`), not `net_observer_ipc::control`, so
  `ControlOutcome::Unsupported` **cannot occur on that path**: a daemon too old to decode
  a command is rendered identically to a daemon that decoded it and refused — both become
  `failed: {msg}`. The distinction exists in the protocol precisely so those two facts
  are not confused (`lib.rs:1021-1038`), and the air window honours it
  (`air.rs:866-872`). The panel does not. Fixing this is small and repairs a stated
  invariant.
- **`kickstart` — the one acting recovery — is CLI-only**, with no bar caller. That may
  well be deliberate (v1 = observe, never act; keeping the acting command off the
  one-click surface is a defensible choice), but it is not written down as a decision
  anywhere I could find. Named for the owner rather than proposed.
- **Symmetric asymmetries:** `FreezePcap` and `SetQuiet` are reachable from the bar but
  have no CLI subcommand; `Incidents { limit }` and `KickstartProxy` are reachable from
  the CLI but have no bar caller. Neither gap looks intentional.

---

## Ranked by value against cost

**Cheap and clearly worth it** (local, existing data, no owner decision):

1. Show `IncidentSummary.signature` in the panel — the product's own conclusion, fetched
   and discarded today.
2. Make the air window scroll; make the map's List mode scroll. Two windows currently
   render content nobody can reach.
3. Human timestamps in `status` and `incidents`; a date in `events`. Reuse
   `diagnose::stamp`.
4. Render the hypothesis caveats and the NULL token in `vulns` / `topology` / `neighbors`
   / `segments` / `history`, as `air` already does.
5. Scroll lock in the event log — stop yanking the operator to the tail.
6. Add `dns`, `host` and `wifi` rows to the panel; show SNR and noise in the air window.
7. Give `control_msg` a timestamp and an expiry, and stop rendering an hour-old failure as
   current.
8. Use `net_observer_ipc::control` on the panel path so `Unsupported` stops masquerading
   as a refusal.
9. Small honesty repairs: keep the `WifiVerdict::Skip` reason, render `Gap` in the air
   window, time out `Scanning`, replace the debug-formatted `via`, fix `Scan`/`Rescan`
   wording, add the missing event chips.

**Moderate, high value:**

10. A confirmation, busy state and rung checkboxes for the neighbour scan — the one
    control that speaks to other machines and today explains itself least.
11. A `--json` output mode across the CLI, plus a provenance header. This is what turns
    the record into something sendable.
12. A freshness and offline idiom shared by all three windows.
13. Sparkline hover readouts, and a caption saying the history is this session's.
14. The first keyboard bindings: Esc to close, `⌘C` to copy a row.

**Expensive, and the largest single win:**

15. A historical read request on the wire, answered by the daemon from its own DB handle,
    surfacing at minimum `why --at`, `incident-context` and `gaps` — and with it, a
    clickable incident that opens its own context. This is the change that makes
    scenario 2 possible at all, unlocks the stored vulns for scenario 5, and removes the
    trade where investigating the last outage means being blind to the next one.

---

## What only the owner can settle

1. **Should the health dot cover more than gateway-and-tun?** Widening it makes the icon
   answer "is anything wrong", narrowing it keeps the icon's claim precise. Both are
   defensible; the current state — a green dot beside a load of 14 — is the one that is
   not.
2. **Should the daemon serve historical reads at all?** It breaks the clean "the bar is a
   pure socket client, the daemon is the sole DB owner" line, and adds query surface to a
   root process. The alternative is that the morning-after path stays a terminal path
   forever. This is the central architectural question in this audit.
3. **If not (2): should the CLI warn that stopping the daemon leaves the machine
   unmonitored**, and should there be a supported "investigate now" procedure?
4. **Is `kickstart`'s absence from the bar deliberate?** Keeping the only acting command
   off the one-click surface reads as a decision, but it is not recorded as one.
5. **Should the GUI be able to request the scan rungs (`ports`, `banners`, `cve`) at
   all?** They are acting-class and they are the only route to the vulnerability data.
   Today the GUI can never produce it.
6. **How much hedging belongs in the interface versus in the export?** The air window's
   caveat paragraph is correct and eats a large share of a default window. There may be a
   split: short in the window, full in whatever gets sent to a third party.
7. **What is the evidence artifact?** Today there is none — no export, no bundle, no
   addressable freeze. "What exactly does the operator hand to the network's
   administrators" is a product question, not a UI one, and it is the question scenario 3
   is really asking.
8. **Vocabulary.** This document uses *incident*, *operator*, *evidence*, *record* and
   *scenario*. `incident`, `record` and `operator` are already the project's own words.
   *Scenario* and *evidence* are mine and may not be what these are called here — please
   name them.

---

## Ceiling — asked for, and not proposed

Named so they are not re-proposed later:

- **Direction or distance to an access point.** Not observable; the system report gives
  no bearing.
- **Identity of a foreign AP across scans.** No BSSID is reported, so "that same
  neighbour again" cannot be said. The air window is correct to draw one slice only.
- **Channel occupancy / airtime.** macOS reports CCA to no process. Overlap stays a
  geometric hypothesis.
- **Anything that acts.** No auto-restart, no watchdog, no notification-that-fixes.
  Where a scenario wants the network repaired, that is a limit of v1, not a gap in the
  UI. `kickstart` exists behind `acting.enabled` and is the boundary case, which is why
  it appears in the owner's list rather than in a proposal.

---

## Confidence

Every "as it is now" statement above is read from the code on this branch and cited.
Claims about what an operator *sees* on screen are inferences from that code, not
observations: per `AGENTS.md`, the rendered behaviour of the bar is not something this
agent can observe, so nothing here should be taken as a verified claim about what the
panel looks like — only about what the code instructs it to draw.
