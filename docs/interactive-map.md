# Interactive code maps

A design document. **Phases 1, 2, 3 and 5 are implemented**: `MapSpec`, `MapBudget`,
`MapModel`, all ten views, the Sugiyama layout, the Canvas renderer,
`understand map show`, `understand map views`, `understand map explain`, and the
tests. Phase 4 (the MCP surface) and the OffscreenCanvas half of Phase 6 are
described here and do not exist yet.

## Status

| Phase | Delivered | Where |
|---|---|---|
| 1. Model, module view, renderer, CLI | **yes** | `engine/code_map.py`, `reporting/html_map.py`, `cli.py::_cmd_map` |
| 2. Traversal views (call, inheritance, dependency, test) | **yes** | `engine/code_map.py::_symbol_map`, `_resolve_root`, `_traverse`, `_wrap_width` |
| 3. Flow views (event, obligation, influence) | **yes** | `engine/code_map.py::VIEW_KINDS`, `_symbol_map` |
| 3b. Data-flow view | **yes** | `engine/code_map.py::_data_flow_map`, `_hop_node`, `_pseudo_node` |
| 4. MCP tool `get_code_map` | no | planned |
| 5. Finding map and `map explain` | **yes** | `engine/code_map.py::_finding_map`, `explain_finding`, `cli.py::_cmd_map_explain` |
| 6. Performance work | **partly** | adaptive quality ships (section 2.1.3); OffscreenCanvas does not |

A node now explains itself. Clicking one shows the source lines of that symbol, every
finding attached to it with the reasoning the analyzer recorded, and — as its own
section headed "What this analysis did NOT prove" — the gap between what was matched and
what was established. `understand map explain FINDING_ID` does the same as prose in a
terminal and prints the exact `map show` command that draws the path it describes. Both
were added after a click produced a list of ids and severities that answered nothing a
reader could act on; section 2.12 describes the argument each one now makes.

```bash
understand map explain SEC-FLOW-001 --scan-id scan-20261019-eb775652
understand map explain SEC-FLOW-001-bb8c7e93f9af --scan-id scan-20261019-eb775652 --json
```

`--scan-id` is optional: without it the command searches the 25 most recent scans for
that finding id and says which one it used. Guessing "the newest scan" would explain the
wrong report, and a finding id is not unique across scans.

What exists today, verified on microsoft/playwright (3,024 files, 285,307 edges):
`understand map show <scan_id> --output map.html` writes one 2.7 MB file with 1,321
nodes and 8,000 edges laid out in 9 dependency layers. It opens in a browser with no
network access, it zooms and pans, and its own status bar states exactly which 2,575
edges the budget removed, how many of the 8,000 are drawn at the current zoom, and how
many of the 58,962 unresolved call targets it did not draw.

```bash
understand map show scan-20261018-e9b97d48 --output map.html
understand map show scan-20261018-e9b97d48 --root packages --view module --json
understand map show scan-20261018-e9b97d48 --view call --root handlePage --depth 3
understand map show scan-20261018-e9b97d48 --view test \
  --root examples/mock-battery/tests/update-battery-status.spec.js::BatteryMock._setLevel
understand map views
```

Phase 2 was verified the same way. The Playwright `test` view resolves its root to
`BatteryMock._setLevel`, draws 31 nodes and 33 `tests` edges in 5 layers, and opens
at 79% fit-zoom with every label legible. A wrong `--root` does not produce a
plausible-looking wrong map: an ambiguous name returns an `empty_reason` naming the
candidate ids, and an unknown one says so.

**Two decisions were reversed during implementation, both after looking at real
output.** Section 5 originally specified a seeded Fruchterman-Reingold layout with
Barnes-Hut for every view; for the module view that is the wrong algorithm, and the
first version rendered one unreadable hairball before a directory-tree layout replaced
it. Then the directory tree turned out to answer the wrong question — "what is in this
folder" rather than "what depends on what" — and plain longest-path layering over the
nodes collapsed into a single horizontal smear. What ships is a real Sugiyama layered
layout over the condensation, described in section 2.1. Force layout remains the right
answer for the call and finding views, which are not trees. The renderer moved from SVG
to Canvas 2D at the same time, because one DOM element per node does not survive two
thousand nodes.

## What this document is for

UNDERSTAND has a complete relation vocabulary now — all twenty `EdgeKind` members are
produced — but it can only hand you the graph as JSON through `trace_execution`,
`analyze_change_impact` and the report payload. A human cannot read 285,307 edges, and a
model reading them pays for every one. An interactive map is the missing surface between
the graph and a person.

The requirement set, in order of importance:

1. Every one of the twenty relation kinds must be renderable. A map that silently drops
   `influences` because it was hard to draw is worse than no map.
2. It must work on a repository with 285,000 edges as well as on a 40-file project.
3. It must be a single local file. No server, no CDN, no network call at view time.
4. It must not invent anything. A map is a rendering of edges that exist in the scan; if
   an edge is `inferred`, the map says so.

## Non-goals

- No editing. The map is read-only.
- No live re-scan. It renders one stored scan.
- No account, no server, no telemetry.
- No external JavaScript or CSS. The file has to work offline, forever, because that is
  the only way a security tool can honestly ship a renderer.

## 1. Data contract

Three layers, each independently testable.

### MapSpec — the request

A frozen model describing *what to draw*, never *what to show*. It carries no coordinates,
no colours, no layout choices. Those belong to the renderer.

| Field | Type | Meaning |
|---|---|---|
| `scan_id` | str | the stored scan to render |
| `view` | enum | which map (see §2) |
| `root` | str | optional symbol id or file path the view is anchored on |
| `depth` | int | how far to walk from `root`, default 3, max 6 |
| `direction` | enum | `out`, `in`, `both` — only for traversal views |
| `kinds` | list[EdgeKind] | relation filter; empty means all twenty |
| `include_findings` | bool | overlay findings on the nodes they belong to |
| `budget` | MapBudget | explicit ceilings (§4) |

Validation lives here, not in the renderer: a bad `view`, an unknown symbol id, an empty
`kinds` after filtering — all rejected before any work happens.

### MapModel — the bounded payload

What the renderer actually receives. This is the only object the HTML ever sees.

| Field | Type | Notes |
|---|---|---|
| `meta` | dict | scan id, repository, revision, generated_at, tool version |
| `nodes` | list[MapNode] | never exceeds `budget.max_nodes` |
| `edges` | list[MapEdge] | never exceeds `budget.max_edges` |
| `legend` | list[dict] | one entry per relation kind present, with its colour and glyph |
| `stats` | dict | counts, omitted counts, per-kind breakdown |
| `honesty` | dict | unresolved counts, confidence distribution, the standard caveats |

`MapNode` carries `id`, `name`, `kind` (symbol kind: module/class/function/method/interface),
`file`, `start_line`, `end_line`, `language`, `exported`, plus rendering-side annotations:
`depth_from_root`, `finding_severity` (highest severity of any finding on that node, or
null), `finding_count`, `unresolved_calls`.

`MapEdge` carries `src`, `dst`, `kind`, `origin`, `file`, `line`, `label`, plus
`confidence` derived from `origin`. The `origin` field is not decoration — the renderer
draws an inferred edge differently from a `type_resolved` one, and the legend says why.

### Why two models

A separate request model means the same MapSpec can be served by the CLI, by an MCP tool,
and by a future HTTP endpoint without the renderer knowing which one asked. It also means
the budget can be enforced in one place.

## 2. The views

Ten views. Each is a different question about the repository, not a different layout
setting.
### 2.1 Module map — implemented

The coarsest view: one node per file, edges collapsed from every symbol relation to the
module level. The question is "what talks to what at the file level", which is the one
question a person can answer by looking at a diagram.

Aggregation rule as implemented: two files are joined when *any* edge joins a symbol in
one to a symbol in the other, and **one edge is emitted per (src, dst, kind) triple**
rather than one with a set of kinds. The `count` on that edge is how many symbol edges
collapsed into it, and the label reads `calls x128`, so the UI can say "128 calls
collapsed" instead of pretending it is one. Splitting by kind is what lets the legend
and the kind filter mean anything at all.

Nodes whose snapshot entry carries no file path are not modules and are dropped; on
microsoft/playwright those are the pseudo-symbols the graph invents for unresolved call
targets, and drawing them as files would be a lie about where code lives.

If no relation survives at all, the files are still drawn. An empty map would read as
"this repository has no files", which is a different and wrong claim.

Layout: the layered method of Sugiyama, Tagawa and Toda (1981), computed in Python so two
runs on one scan produce identical bytes. Three earlier layouts were implemented and
rejected against real data before this one stuck:

- a force-directed layout (Fruchterman-Reingold) rendered 1,321 modules as an unreadable
  hairball, and an O(n^2) repulsion loop in pure Python cost minutes for a worse picture;
- a directory tree answered "what is in this folder", which is not the question a module
  map is asked — "what depends on what" is a DAG, and a tree hides it;
- plain longest-path layering over the nodes collapsed into a single horizontal smear,
  because a repository's modules import each other in large mutually recursive groups and
  every one of them ends up on the same lane.

What ships instead:

1. **Tarjan's strongly connected components**, iteratively (recursion overflows on a
   repository-sized graph). Each group becomes one node for layout purposes and is drawn
   as a stack of files inside its lane. Groups larger than one file are marked `in_cycle`.
2. **Longest-path layering over the condensation**, measured *from the sources* so an
   arrow always points downwards: the caller is drawn above what it calls. Measuring
   towards the sinks instead puts every leaf at the top and inverts the diagram.
3. **Crossing reduction** with the barycenter heuristic, ELK's `LAYER_SWEEP` strategy:
   alternating downward and upward passes, re-sorting one lane at a time, ties broken by
   node id so the result is identical on every run and platform.
4. **Lane wrapping**. A lane holding 668 files in one row is 120,000 pixels wide and no
   viewport can show it. Lanes wrap at 26 groups per row, which took the real Playwright
   map from 185,102 x 14,226 pixels to 6,639 x 16,770 — roughly 1:2.5 instead of 13:1.

On microsoft/playwright (`scan-20261018-e9b97d48`) this yields 9 layers, 927 components,
3 cycles broken and 31 edge crossings left after four sweeps.

### 2.1.1 Rendering — Canvas, not SVG

The first implementation drew an SVG with one DOM element per node. That is the standard
choice until roughly two thousand nodes, past which the DOM is the bottleneck rather than
the drawing. The renderer is now a **Canvas 2D surface with a camera**, and the pieces
that matter are these:

- **Anchored zoom.** The image point under the cursor stays under the cursor:
  `ratio = next/scale; tx = cx - ratio*(cx - tx)`. The cursor is converted to
  canvas-local coordinates with `getBoundingClientRect()` on *both* axes.
- **Pan stores a start, it does not accumulate.** `pointerdown` records
  `panStart = {tx, ty}` and every `pointermove` recomputes from it. Accumulating deltas
  drifts visibly over a long drag.
- **Zoom input is coalesced per frame.** Wheel deltas accumulate in the handler and one
  `flushZoom()` folds them into a single anchored camera update at the top of the next
  animation frame. Safari dispatches wheel events on its own cadence, unaligned to
  `requestAnimationFrame`, and applying the update per event forces a synchronous layout
  on every one of them.
- **Wheel units are normalised** (`deltaMode` 1 and 2 are lines and pages, not pixels),
  and a trackpad pinch — which arrives as a synthesized `ctrl`+wheel with small fractional
  deltas — gets a different sensitivity from a real wheel.
- **Safari's proprietary pinch** `GestureEvent`s are prevented, otherwise they trigger
  Safari's own full-page zoom.
- **The backing store is scaled by `devicePixelRatio`**, without which the whole map is
  blurred on a HiDPI display.
- **Level of detail.** Labels switch on at 28% zoom and edge labels at 60%; the flag flips
  only when the camera crosses the threshold, never inside the draw loop, or it oscillates.
- **A uniform spatial grid** over node boxes drives viewport culling and hit testing, so a
  zoomed-in view does not walk every node on every frame.
- **An edge budget by zoom.** Drawing all 8,000 edges of this repository at fit-to-view
  produces a solid green wall that hides the diagram underneath it. The drawn subset is a
  stable prefix of a priority order — structural relations first, collapsed calls last,
  and within a kind the edges joining the most-connected nodes — so the picture never
  flickers as the camera moves. The status bar says "showing 725 of 8,000 edges at this
  zoom" rather than implying the picture is complete.
- **Edges fade with density** (`alpha = min(0.85, 0.18 + 0.7*min(1, scale*2.5))`), so
  overlap reads as shading instead of saturating to a solid block.
- **Nodes have a minimum drawn size** of three screen pixels, because a 220-pixel-wide
  file at fit-to-view is about ten pixels wide and one pixel tall.
- **A minimap**, click-to-jump, plus keyboard (`+`, `-`, `0`, `/`) and three buttons.

Positions still arrive pre-computed in the model. Layout runs in Python, not in the
browser, which is what makes the output byte-identical and diffable in a pull request.


### 2.2 Call graph -- implemented

`view: call`, the direct visual form of `trace_execution`. Honours `root`, `direction`,
`depth`. Uses the already-resolved `CALLS` edges, so an unresolved callee renders as a
distinct ghost node — outlined, not filled — labelled with the bare callee name. That
distinction is the whole point: 58,962 unresolved call targets on Playwright is the number
that says how much of the graph is guesswork, and it has to be visible rather than buried
in a caveat.

### 2.3 Inheritance tree -- implemented

`inherits` and `implements` only. Rendered as a layered DAG, roots at the top, ordered by
subtree size so the most depended-upon base is first. Multiple inheritance is normal and
must lay out without crossing edges wherever possible.

### 2.4 Dependency map -- implemented

`depends_on` and `imports` at module or package granularity, with cycle detection. Import
cycles are a finding in their own right; this view should draw them as a highlighted ring
rather than requiring the reader to spot them.

### 2.5 Data-flow map

The taint flows the analysis already proves, rendered as source → hops → sink. Each hop is
an edge labelled with the variable name. The visual grammar: a solid path is `proven`,
a dashed path is `inferred`. Downgraded flows (the ones whose origin could not be tied to
a source line) render in the muted colour and carry their `assumptions` text in the side
panel, because that text is the reason the severity went down.

### 2.6 Event map

`registers` and `handles_event` together, which is the pair that only makes sense as a
whole: who publishes an event and who subscribes. Rendered as two columns with the emitter
and the handler, joined by the event name.

### 2.7 Obligation map

`validates`, `authorizes`, `sends_data_to`, `opens_resource`, `closes_resource`. This view
answers "what does this function require, and what is allowed to leave through it", which
is the question a security reviewer actually asks. Requires a strong-origin or same-file
target, per the rule already in `engine/relations.py`.

### 2.8 Test coverage map -- implemented

`tests` edges, from test function to subject. Subjects with no incoming test edge are the
point of the view. Render them as a distinct unfilled node with the count of uncovered
subjects in the stats bar.

### 2.9 Influence map

`configures` and `influences`. Anchored on a config key or an environment variable read,
showing which symbols change behaviour when it changes. Small by construction — this is
the most actionable view per node in the whole set.

### 2.10 Finding map

The whole repository with findings as the primary object. Nodes sized by finding count,
coloured by highest severity, edges from the relation kinds the finding evidence actually
uses. This is the view that replaces reading a table of 1,591 findings, and it is the one
that most needs the `origin` and `confidence` distinction to be drawn rather than
labelled.

### 2.11 How the four symbol views share one implementation

`call`, `inheritance`, `dependency` and `test` are four questions, not four
renderers. They all run the same code path: `_symbol_map` in
`engine/code_map.py`, reached through `_BUILDERS`. Duplicating the traversal per
view would guarantee that a bug fixed in one stays broken in three.

What differs between them is only `VIEW_KINDS` -- the relation kinds each draws.
`reads` and `writes` are deliberately absent from the call view: they relate a
method to its own fields rather than to another function, so on a call map they
would be self-loops drawn between neighbours. The `test` view draws only `tests`,
because the subject of a test edge is the thing under test; the test's own calls
answer a different question.

**Root resolution.** `--root` accepts a full `file::symbol` id, a bare symbol
name, a qualified `Class.method`, or a file path. Four rules govern it, and each
one exists because the alternative produced a map rooted at the wrong symbol:

| Rule | Why it is there |
| --- | --- |
| An exact id match wins outright | Ids are unambiguous. |
| A file path returns *every* symbol in that file | Treating a file that matches six symbols as "ambiguous" made `--root some/file.py` unusable on any real file. |
| A bare name matching more than one symbol is **refused**, listing the candidates | Silently taking the alphabetically first match drew a map of `::B` when the user asked for `BatteryMock`, and nothing in the output said so. |
| A qualified `Class.method` falls back to the bare method name | Method names are stored unqualified, so a trailing-`::` match never finds them. |

**Depth.** `--depth` bounds a breadth-first walk from the root. The root is
depth 0, so `--depth 3` reaches three hops out. With no `--root` there is nothing
to walk from, so the whole snapshot becomes the neighbourhood, ranked by degree
so the budget keeps the busiest symbols rather than the alphabetically first
2,000. Rendering nothing there would claim a 35,000-symbol repository is empty.

**Aspect-aware wrapping.** A fixed wrap width produced a drawing 40 times wider
than it was tall for a fan-out call graph, which fit-to-view can only show by
zooming out until no label is legible. Rows are now wrapped so the finished
drawing lands near `TARGET_ASPECT = 1.6` -- the same reason Eclipse ELK exposes
`Aspect Ratio` as a layout option. A real `test` view over Playwright went from a
40:1 band to 1.19:1 and from 21% to 79% fit-zoom.

## 3. Node and edge vocabulary

One vocabulary across all ten views, so the legend does not change when the view does.

**Node shapes** — module: square. class/interface: rounded rectangle. function: circle.
method: circle with a filled left edge. external or unresolved target: dashed outline.
directory or package: large rounded rectangle used as a grouping frame, not a node.

**Node colours** — by finding severity, not by symbol kind. Severity is the thing a reader
is scanning for. A repository with no findings on a node draws it in the neutral colour, so
a colourful map means something and a grey map means something too.

**Edge styles** — `static_direct` and `type_resolved`: solid. `inferred`: dashed.
`unresolved`: dotted, drawn toward a ghost node. The distinction has to survive at small
zoom levels, which is the actual constraint — a legend nobody can resolve is decoration.

**Edge colour** — by relation kind, twenty distinguishable hues. Twenty is past the point
where colour alone works, so each kind also gets a distinct dash pattern and a short glyph
in the legend, and colourblind-safe palettes are a hard requirement rather than a nicety.

## 4. Scale, budgets and honesty

`MapBudget` is part of the request, not a hidden constant:

| Field | Default | Hard max |
|---|---|---|
| `max_nodes` | 2,000 | 20,000 |
| `max_edges` | 8,000 | 60,000 |
| `max_depth` | 3 | 6 |

When a budget binds, the payload says so. `stats.omitted_nodes`, `stats.omitted_edges` and
a per-kind `budget_omitted` count go into the payload, and the UI states it in the status
bar. The same rule already governs the text report: a truncated list says it is truncated,
because a truncated map that looks complete is a lie about the codebase.

The proportional per-kind allocation in `graph_snapshot._balanced` is the model to copy.
Filling a budget in insertion order lets `calls` consume all of it, which is exactly the
bug that was fixed there.

Two additional caps that are not about the graph:

- **File size.** A single self-contained HTML with 20,000 nodes and 60,000 edges is
  roughly 40–70 MB. The writer enforces a byte ceiling and, above it, falls back to the
  module-level view rather than producing a file that will not open.
- **Server-side only.** The map is built in Python and written to disk. Nothing is
  computed in the browser.

## 5. Layout

Layout is deterministic. The same scan produces the same file, byte for byte, so a map can
be committed, diffed and reviewed in a pull request. A seed derived from the scan id
drives any stochastic component.

| View | Algorithm | Why |
|---|---|---|
| Module, dependency | **shipped**: Sugiyama layered over the condensation, lanes wrapped | a module map is a DAG of imports; see section 2.1 for the three layouts that failed first |
| Call | layered by `depth_from_root`, edges as splines | the question is "how far does this reach" |
| Inheritance | longest-path layering, roots first | a tree has a correct answer |
| Data flow | force-directed with a strong source→sink rank bias | direction must be unambiguous |
| Event, obligation, influence | bipartite — sources left, sinks right | the whole point is the pairing |
| Test coverage | two-column, tests right | the gap is the message |
| Finding | force-directed, size by count | no structure to exploit |

The layered algorithm is not the only option that would work for the module view; force
layout with a layered bias is the fallback if a repository turns out to have structure a
layered layout cannot express. It was not chosen first because it is O(n^2) in pure
Python without a quadtree.

Layout runs in Python at build time, not in the browser. That costs a few seconds
on a large map and buys determinism, an offline file, and a layout the reader cannot
accidentally change by dragging something.

For the views that do need force layout, the implementation is a seeded
Fruchterman–Reingold with Barnes–Hut approximation so a 20,000 node graph is minutes
rather than hours, capped at a fixed iteration budget with an explicit `converged: false`
when it does not finish. Barnes–Hut needs a quadtree; writing one is a day of work and
the alternative is a layout that cannot finish on the largest repositories.

## 6. Interaction

Open the file in a browser, nothing else required.

- Hover a node: name, kind, file and line, exported flag, finding count, highest severity.
- Click a node: side panel with the full detail, its relations grouped by kind, and its
  findings listed with rule id, location and snippet.
- Click an edge: source description, sink description, the `origin` value, the line, and
  the CWE reference when the kind has one.
- Filter box: filter by name, file, kind or relation. Filtering is client-side over the
  already-loaded payload, so it is instant.
- Kind toggles: twenty checkboxes, all on by default, each with its live edge count.
- Severity toggle: show only nodes at or above a chosen severity.
- Focus: double-click to re-root the view on that node, loading more of the graph on
  demand from a second embedded payload.
- Search: `/` focuses it.
- Export: copy the current filtered subgraph as JSON, which is how a person hands a
  specific slice to a model.

No hover-only information. Every edge style and colour distinction must also exist as
text in the side panel, because "the dashed edges are inferred" is not an answer to
someone who cannot see the dashes.

## 7. Interfaces

### CLI

New verbs rather than a new format flag, because a map needs arguments a format string
cannot express. As implemented:

```
understand map show <scan_id> [--view module] [--root <path>] [--depth 3]
                    [--direction out|in|both] [--kind calls] [--kind reads]
                    [--no-findings] [--max-nodes 2000] [--max-edges 8000]
                    [--json] [--output map.html] [--open] [--storage PATH]
understand map views                      # every view, what it answers, and its status
understand map explain <finding_id>       # Phase 5; currently refused with a hint
```

`understand map explain` is the one that answers the question a person actually has. It
takes the finding, resolves its evidence, builds a minimal MapSpec around it, and writes
both the map and a short prose account of the causal chain: what the source is, what the
sink is, what has to be true for this to be exploitable, and what has not been proven. That
last part is the reason the feature exists. A tool that draws a diagram without saying what
it does not know is how a diagram becomes a false claim. Until it exists it is refused
with an explicit hint rather than silently drawing a map the caller did not ask for.

`--open` shells out to the platform opener. It is the one place the CLI touches the OS, and
it must be a best-effort call that reports failure rather than raising — implemented in
`_best_effort_open`, which swallows every exception because a headless box failing to
launch a browser must never turn a successful map build into a failed command.

The output path goes through `safe_map_output_path`, which calls `safe_output_path`
unchanged and only then requires an `.html`/`.htm` suffix. Every rule the other formats
obey — no `..` escape, no symlink, no protected directory, no hostile filename — applies
to a map exactly as it does to a SARIF file. A map is a separate command, not a separate
format, so `--format html` deliberately does not exist.

### MCP

Two additions, and nothing removed. The nine tools stay; the surface widens.

A tenth tool, `get_code_map`, takes the same `MapSpec` and returns the `MapModel` as
structured content with an envelope identical to the existing nine, plus a `html` field
only when the caller asks for it and the result fits the byte ceiling. Returning the model
rather than only the HTML matters: a model that gets 2,000 nodes as structured content can
reason about them, and one that gets 40 MB of HTML cannot.

A third resource, `understand://map-schema`, returning the `MapSpec`/`MapModel` JSON
Schema, so a client can validate a request before sending it.

Do not add a tool that writes files. A map is built and returned; writing is the caller's
decision, made with the path they already control.

## 8. Security

The renderer is the part that touches a browser, so it gets the same scrutiny as the git
subprocess.

**No network.** No CDN, no web font, no analytics. The output is one file with inline CSS
and inline JavaScript. This is verifiable by grepping the output for `http`.

**No `innerHTML`.** Every string that came from the analysed repository — symbol names,
file paths, snippets, finding titles, remediation text — is set via `textContent`. A
repository is untrusted input; a snippet containing `<img onerror=...>` must render as that
literal text. One helper, used everywhere:

```javascript
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
```

**No `javascript:` URLs, no `data:` URLs, no inline event handlers.** Navigation to a
location is a user action through a real `<a href>` that the writer validates against the
scan's own file list.

**Output path.** `safe_output_path()` is used exactly as the reports use it, with
`fmt` extended to recognise the map format. The protected-directory check is the
resolve-then-normcase version that was fixed for Windows.

**Size.** The byte ceiling is enforced before writing, so a runaway map cannot fill a disk.

**Honesty carried into the file.** The `honesty` block is rendered visibly in the UI, not
hidden in a metadata field: unresolved call count, confidence distribution, what the
analysis did not do. A map file that travels without its caveats is a map that will be read
as more certain than it is.

## 9. Testing

**MapSpec validation** — bad view, unknown kind, empty kind list after filtering, depth
out of range. Unit.

**Every kind reaches every view that claims it.** One test per view per kind that view
uses, asserting the kind appears in the payload. This is the test that stops a future
change from quietly dropping a relation.

**Budgets bind honestly.** Build a synthetic graph over budget and assert `omitted_*` is
non-zero, that the per-kind counts add up, and that no kind is starved to zero while
others fill the budget.

**Determinism.** Build the same map twice, compare bytes. Then build it from a report whose
findings are reordered, and assert the node positions are identical while the finding
annotation follows the node.

**XSS.** A fixture whose symbol name and finding snippet both contain
`<img src=x onerror=alert(1)>` and `</script>`. Assert the escaping helper is used, assert
the output contains no `onerror=` outside the escaped form, and — the test that actually
matters — render it in a headless browser and assert no dialog appears.

**No network.** Assert the output contains no `http://` or `https://` outside the CWE
reference strings, which are plain text in a side panel and not links.

**Budget ceiling.** Assert the writer refuses a payload over the ceiling rather than
writing it.

**Round trip.** `--format json` on the map model, reload it, assert it matches.

## 10. Delivery

Each phase is independently useful and independently shippable. Nothing in a later phase
depends on a decision made in an earlier one.

**Phase 1 — the model and one view.** `MapSpec`, `MapModel`, `MapBudget`, the validator,
the module map, the deterministic renderer, the single-file writer, `understand map show
--view module`, and the full test suite for those. No browser interaction beyond
highlighting. This alone is worth having: it is the dependency picture nobody can currently
see.

**Phase 2 — traversal views.** Call graph, inheritance, dependency, test coverage. Reuses
the existing `TraceService` and the snapshot's per-kind filtering.

**Phase 3 — the flow views.** Data flow, event, obligation, influence. The hardest
rendering work, because the honest distinction between proven and inferred is the whole
value and it has to survive at small zoom.

**Phase 4 — the MCP surface.** `get_code_map` and `understand://map-schema`. Only after
the CLI paths are proven on real repositories, because the MCP tool inherits every defect
in the model layer.

**Phase 5 — the finding map and `map explain`.** The view that answers the question people
came for, built last because it depends on everything above being correct.

**Phase 6 — performance.** Barnes–Hut, the incremental focus payloads, and the byte
ceiling tuning against the largest repositories available.

## 11. What has to be decided before Phase 1 starts

- **Canvas or SVG.** Canvas draws 60,000 edges in a second and needs a hit-test tree.
  SVG gives free hit-testing and native zooming and dies around 10,000 elements. The answer
  is almost certainly canvas with a quadtree index, which is the same structure Phase 2
  needs for Barnes–Hut, so the two can share it — but that is a real decision, not a detail.
- **Whether the file embeds the payload as JSON or a compact binary encoding.** JSON is
  readable, diffable and reviewable. Binary is roughly a third of the size. My reading is
  that a security tool's output should be reviewable in a pull request, so JSON, with the
  byte ceiling handling the pathological case.
- **Whether maps are a report format or a separate command.** Format means `--format html`
  and inherits every existing path, including SARIF-style validation. Command means new
  verbs and a new surface area. The command wins on expressiveness and loses on
  discoverability. My reading is the command, because `--view`, `--root`, `--depth` and
  `--kind` are arguments, not format options.
- **What the 20,000-node ceiling costs.** It will exclude most of a large monorepo. The
  alternative is a map that cannot be opened. The honest answer is that the ceiling is
  right and the module-level view is what large repositories get; that is a limitation to
  state in the UI, not to engineer around.

## 12. Related

- `docs/architecture.md` — the relation vocabulary and the origin rule these views render
- `docs/extending.md` — how to add a relation kind, and what it has to do before a view can
  show it
- `docs/mcp-protocol.md` — the envelope the tenth tool has to match
- `src/understand/engine/graph_snapshot.py` — `snapshot_graph(index, graph, kinds=...)` and
  the balanced budget allocation to copy
- `src/understand/engine/relations.py` — where the twenty kinds come from
</content>

### 2.1.2 Why the map used to freeze, and what stopped it

The first Canvas version still froze. Zooming or dragging produced one
250-650 ms frame per input event. It was measured, not guessed: a
`requestAnimationFrame` sampler inside the page records every frame gap while
the test drives real mouse and wheel input from outside, so no automation
latency lands inside the number.

Four separate causes were found, and none of them was the drawing itself.

**Layout thrashing.** `getBoundingClientRect()` was called twice per wheel
event to find the cursor position in canvas coordinates, while the status bar
rebuilt roughly ten DOM elements every frame. Writing to the DOM invalidates
layout; reading a layout value immediately afterwards forces the browser to
recompute it synchronously. That is the definition of thrashing, and it is why
the rAF-coalescing added to fix Safari jank made this worse rather than better.
The canvas origin is now measured once in `resize()` and refreshed on scroll,
and the status bar rebuilds only when a value it displays has changed.

**A stroke state change per edge.** Every edge set `strokeStyle`, `lineWidth`
and `setLineDash` individually, up to eight thousand times per frame. Dashed
strokes are markedly more expensive than solid ones. Edges are now bucketed by
kind and origin, so each bucket is one `beginPath`, one `stroke()` and one
`fill()` for all its arrow heads.

**A font assignment per node.** `ctx.font`, `textAlign` and `textBaseline`
were set inside the node loop, so the browser redid font matching two thousand
times a frame. They are now set once per frame.

**Level of detail did not scale down far enough.** Edges were drawn as
antialiased cubic beziers even when an edge was a few pixels long, arrow heads
were drawn below the scale at which they are readable, and the edge budget grew
linearly with zoom, which allowed roughly 3,500 curves on screen at 36%.

What the map does now, and what was measured on the Playwright `call` view
(2,000 nodes, 8,000 edges, a 3.3 MB single file):

| | before | after |
| --- | --- | --- |
| zoom, worst frame | 586-657 ms | 58.8 ms |
| zoom, frames over 33 ms | 20 of 102 | 3 of 115 |
| pan, worst frame | 296 ms | 12.4 ms |
| pan, frames over 33 ms | 40 of 124 | 0 of 151 |

The rule is that the map shows a coarser picture rather than a late one: while
the camera is moving, edges are straight lines instead of beziers, arrow heads
are dropped, the edge budget is a fifth, node labels are hidden, and only the
400 most connected nodes are drawn. Full detail returns when the input stops. A
zoom gesture has no `pointerup` to mark its end, so it is timed instead. The
status bar says which of this is in force and how many nodes and edges were
left out, because a temporarily simplified picture that does not say it was
simplified is a false claim.

Two limits are worth stating. These numbers were measured in headless
Chromium, which has no GPU; with the filter set so that zero nodes match, a
frame still costs about 35 ms, so a substantial part of what remains is the
software rasteriser rather than this code. And a real GPU moves the compositing
cost, not the ones already fixed, so the numbers there should be better rather
than worse.


### 2.12 What a node and a finding actually say

Clicking a node used to print a name, a kind, a file:line, and a list of
severities. That is a directory listing of the analysis, not an explanation of
it. Two things were added, both in the same spirit: the map stopped describing
itself and started defending its own conclusions.

**The node carries its own source.** `engine/code_map.py::_attach_source` reads
the recorded repository path and copies the symbol's own lines into the model,
capped at 24 lines with an explicit "… N more line(s)" tail. The stored snapshot
deliberately carries no source, because a trace has to work without the
repository; a map is read by somebody looking at code, and a symbol id cannot
answer "what does this function do". When the repository is a remote clone that
has since been deleted, every node says so and the reason is in the caveats —
rather than an empty box that reads like an empty function.

**The panel makes the analyzer's argument in its own order.** Per finding:
severity, rule, confidence and verification status; what was found; why it
matters; the impact; each data-flow path as a numbered chain from source to
sink; the evidence with its file, line and real snippet; what must be true for
it to matter; **what this analysis did not prove**; why that confidence; the
fix; the references. The sixth block is the point. An impact sentence sitting
next to a severity badge reads as a demonstrated defect; the same sentence
beside an explicit statement of the gap reads as what it is.

**`understand map explain FINDING_ID` is the same account as prose.** It exists
because the question is an argument, not a picture. It prints the path source to
sink, the evidence under it, the preconditions, the assumptions, and a closing
"Read this before acting" section carrying the scan's own unresolved-call count
and snapshot-truncation state. The command it recommends at the end resolves its
root against the stored node ids first: a hop says `ParquetReporter.onEnd`, the
snapshot calls it `tests/config/parquetReporter.ts::ParquetReporter.onEnd`, and
recommending the bare name would produce a command that draws an empty map and
looks like a clean repository.

Two honesty bugs were found while building this and fixed at the source rather
than in the view. The XSS rule's `assumptions` repeated its precondition
verbatim, so the "did not prove" block printed the same sentence twice — it now
states what the rule genuinely failed to establish, which is that no untrusted
input was traced to the assignment. And a symbol with no file of its own was
reported as "the source is unavailable", which is a claim about the repository;
it now says it is a pivot the analyzer made.

### 2.13 The two views that are not traversals

Seven views are traversals: start at a root, walk outward, draw the kinds the view
declares. `data_flow` and `finding` are not, and putting them on the same builder
would have been the easy mistake.

A traversal answers "what is near this". Neither of these two can be answered that
way. A data flow is a path the analyzer traced from untrusted input to a sink, and
that trace lives on the finding — the graph holds every call in the repository, so
drawing the graph under the name "data flow" would be a call graph wearing a label.
A finding map's question is where the findings cluster, and the cluster is a
property of the findings, not of the graph.

#### Reading the hops

`finding.data_flows` is written as prose, because the report reads better that way:

```
['entered from ParquetReporter.onBegin', 'env var process.env.OUT (line 12)',
 'in ParquetReporter.onEnd', 'sink: sql-exec']
```

Two of those four hops name symbols the graph indexes. The other two name the
*origin* and the *destination of the value*, which the graph has no node for.
Dropping them would draw a path that starts in mid-air, so each becomes an anchored
node with its own glyph:

| Role | Glyph | Meaning |
| --- | --- | --- |
| `source` | diamond | where an untrusted value enters |
| `sink` | square | where it is used |
| `caller` | pill | the function the path arrived from |
| `via` / `symbol` | circle | a step, or an indexed symbol |

`<module>` hops are dropped: the analyzer uses it as a stand-in for "the file as a
whole", and it is not a place a value travelled through.

#### Solid versus dashed

`cross_module_trace`, `test_backed` and `reproduced` mean the value was actually
followed. `static_evidence` means a source pattern and a sink pattern were found
and nothing in between was checked. The edge `origin` carries that, so the existing
solid/dashed/dotted vocabulary already draws it, and the caveat states the split:

```
101 of 120 edge(s) were followed across modules or reproduced (84%); the rest match
a source pattern and a sink pattern without the value in between being traced.
Solid edges are traced, dashed edges are matched.
```

#### What a data-flow map refuses to draw

- A path the analyzer never traced. It may well exist; drawing it would be a guess
  about where untrusted input goes.
- More than three flows per finding, and any flow whose hops mostly name things the
  graph does not index. Both are counted in `stats.flows_omitted` and stated in the
  caveats rather than dropped silently.
- A flow that resolves to a single node. That is a source or a sink on its own, and
  an edge to a phantom would invent the connection the view exists to show.

#### The finding map

Nodes are symbols a finding landed on, ranked by worst severity and then by how many
findings they carry. Edges are the snapshot's, restricted to pairs where both ends
are placed. One finding touching five symbols is counted on each, and the caveat
says so rather than letting the totals read as five separate problems.

### 2.14 Three relation kinds nothing else drew

`event`, `obligation` and `influence` exist because eleven of the twenty relation
kinds had no view that drew them. They are ordinary traversals over `_symbol_map`;
what is new is that each one declares a kind set nothing else uses:

| View | Kinds | Why together |
| --- | --- | --- |
| `event` | `registers`, `handles_event` | Half an event map is not an event map — the emitter with no listener and the listener with no emitter are both real questions. |
| `obligation` | `validates`, `authorizes`, `sends_data_to`, `opens_resource`, `closes_resource` | All five are promises a caller should know about before relying on the function. |
| `influence` | `configures`, `influences` | Config keys and environment reads are the two ways a repository's behaviour is decided from outside its code. |

A repository with none of these relations is not an error, and the empty map says
which of two things happened: nothing connects the requested root, or the analyzer
recorded no such relation anywhere. Before the second distinction existed, both
produced the same message, and they send a reader to different next steps.

### 2.15 Two defects a reader found, and what they actually were

A reader of the shipped map reported that "some functions" showed no code, and that
the map had become very small and was not showing everything. Both were real, and
neither was the renderer's fault.

**The nodes with no code are not functions.** A name with no file of its own is
the *name* of something the analysed code calls that the analyzer could not bind
to a definition in the repository: `Error`, `async`, `path.join`, `fs.promises.unlink`.
The call is real; the definition lives in the standard library, a third-party
dependency, or is chosen at run time. The first version drew those with the same
glyph as a function and the panel said "this node has no file of its own; it is a
pivot the analyzer made", which reads as a broken tool rather than as an honest
limit. They are now drawn hollow with a dashed outline, counted in
`stats.placeholder_nodes`, listed in the legend, and each one carries its own
`placeholder_reason` saying which of the three cases it is -- a qualified name
whose receiver is unresolved, an unqualified name from outside the repository, or
an end of a traced data-flow path.

**The tiny map was the wrapping heuristic lying to itself.** `_wrap_width`
estimated the finished height as `layer_count * tallest_group` and returned the
widest allowed row whenever the total width fitted inside that estimate. The
estimate is wrong in a way that compounds: a row count above one multiplies the
real height by the number of rows while leaving the width alone, so the function
argued itself into the widest option. On real Playwright that produced a drawing
6,639 x 16,626 -- five times taller than wide -- which fit-to-view zooms out to
4% and turns every node into a speck. The row count is now *solved* for: the same
sums the placement code would perform are computed for every candidate row count,
and the one closest to `TARGET_ASPECT` in log space wins.

| | before | after |
|---|---|---|
| module view extent | 6,639 x 16,626 | 24,503 x 14,546 |
| aspect | 0.40 (three times too tall) | 1.68 |
| call view extent | 5,611 x 8,786 | 11,361 x 5,666 |
| aspect | 0.64 | 2.01 |

**"Not everything shows" was the edge budget, and it was too timid at rest.**
The settled budget was `200 + 6000 * scale^2`, which at a 5% fit zoom is 214
edges out of 8,000 -- a picture that looks empty and reads as "the tool hid
things". The cap that exists for the *moving* camera is separate
(`INTERACT_EDGE_CAP`), and drawing 3,014 edges in one settled frame measured
16 ms with the adaptive controller untouched at quality 1.0. The settled floor is
now 3,000. The camera cap is unchanged, so panning and zooming still bound their
own cost.
