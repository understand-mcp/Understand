"""The layout engine of the code map.

Given the nodes and the edges of a map model this module decides where every
node sits: which layer it belongs to, how wide it is, how the rows are stacked
and how the crossings are reduced.  It is deterministic: the same scan and the
same spec always produce the same coordinates, so a map can be diffed in a
review.

The layout knows nothing about repositories.  It receives a model and a spec
and returns coordinates.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Any

from .code_map_common import (
    EDGE_STYLES,
    FINDING_DETAIL_BUDGET,
    FLOWS_PER_FINDING,
    NODE_FINDING_CAP,
    NODE_SHAPES,
    SEVERITY_ORDER,
    SEVERITY_RANKS,
)

if TYPE_CHECKING:  # pragma: no cover - the import exists for type checkers only
    from .code_map import MapSpec

def _rank_to_severity(rank: int) -> str:
    """Turn a :class:`Severity` rank back into its name."""

    for name in SEVERITY_ORDER:
        if SEVERITY_RANKS.get(name) == rank:
            return name
    return "info"


def _files_within(paths: Iterable[str], root: str) -> set[str]:
    prefix = root if root.endswith("/") else root + "/"
    return {path for path in paths if path == root or path.startswith(prefix)}


def _relative_depth(path: str, root: str) -> int:
    """Layer index used to bias the layout.

    With an explicit root this is the distance below that root. Without one,
    every path would come out at depth 0 and the depth bias would do nothing at
    all, which turns the module map into an unreadable hairball. So the
    fallback is the path's own nesting below the shallowest directory shared
    by every node, which is what makes a repository look like a repository.
    """

    if root:
        if path == root:
            return 0
        prefix = root if root.endswith("/") else root + "/"
        if not path.startswith(prefix):
            return 0
        return 1 + path[len(prefix) :].count("/")
    return path.count("/")


def _depth_floor(paths: Sequence[str]) -> int:
    """The smallest nesting depth present, so layers start at zero."""

    depths = [path.count("/") for path in paths]
    return min(depths) if depths else 0


def _severity_name(raw: Any) -> str:
    value = getattr(raw, "value", raw)
    text = str(value)
    return text if text in SEVERITY_ORDER else "info"


def _worst_severity(counts: dict[str, int]) -> str:
    for name in SEVERITY_ORDER:
        if counts.get(name):
            return name
    return ""


def _collapsed_symbols(symbol_count: int, node_count: int) -> int:
    return max(0, symbol_count - node_count)


def _edge_counts(edges: Sequence[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in edges:
        kind = str(edge.get("kind") or "")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #
def _seed(spec: MapSpec) -> int:
    return int(hashlib_digest_int(spec.scan_id, spec.view))


def hashlib_digest_int(text: str, salt: str) -> int:
    """A small stable integer from a string.

    ``hash()`` is randomised per process, so it cannot be used for anything that
    must be byte-identical between runs.
    """

    import hashlib

    digest = hashlib.sha256(f"{salt}\x00{text}".encode()).hexdigest()
    return int(digest[:8], 16)


#: Geometry.  Coordinates are in real pixels and are NOT normalised onto a
#: fixed canvas: the renderer owns a camera that fits whatever extent it is
#: given, and squashing 1,300 nodes into 2,000 units makes every lane land on
#: top of every other lane.
NODE_HEIGHT = 26.0
NODE_PADDING = 16.0
CHAR_WIDTH = 7.2  # measured for the 11px UI monospace stack
LABEL_CHARS = 26  # long names are truncated with an ellipsis, not drawn in full
LAYER_GAP = 150.0
# Horizontal spacing between two groups standing side by side in one lane.
# This is much tighter than the vertical layer gap on purpose: lanes get wide
# with hundreds of files, and a generous horizontal gap would push the whole
# map past the point where fit-to-view is readable.
GROUP_GAP = 36.0
# A lane holding hundreds of files in one row produces a 120,000 pixel wide
# smear that no viewport can show, and a lane holding one group per row produces
# the opposite failure: a picture three times taller than it is wide, which
# fit-to-view zooms out until every node is a speck.  The bound is therefore
# only a ceiling on how bad a row may get -- _wrap_width searches the range for
# the row count that actually lands on TARGET_ASPECT, and this is simply the
# widest it is allowed to consider.
MAX_PER_ROW = 128
# Below this a single layer becomes one tall column and the drawing goes the
# other way, which is the same legibility problem with the axes swapped.
MIN_PER_ROW = 4
ROW_GAP = 48.0
# Target width/height ratio for the finished drawing. ELK Layered defaults its
# ``Aspect Ratio`` option to 1.6 for the same reason: a diagram that is ten times
# wider than it is tall has to be zoomed out until nothing is legible, so the
# rows are wrapped until the two dimensions are comparable.
TARGET_ASPECT = 1.6
MIN_NODE_WIDTH = 90.0
CROSSING_SWEEPS = 4


def _node_width(node: dict[str, Any]) -> float:
    name = str(node.get("name") or "")
    if len(name) > LABEL_CHARS:
        name = name[: LABEL_CHARS - 1] + "…"
    return max(MIN_NODE_WIDTH, len(name) * CHAR_WIDTH + NODE_PADDING * 2)


def _layout_module(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    spec: MapSpec,
) -> dict[str, Any]:
    """Layer the files with the Sugiyama method.

    Phase 1 of the design note assumed a directory-tree arrangement and the
    plan itself assumed Fruchterman-Reingold for the graph views. Both were
    wrong for this view and both were replaced after seeing real data:

    * A force layout over a repository is a hairball. Repulsion is O(n^2) in
      pure Python, so 1,300 nodes took minutes, and the picture was worse than
      the tree it replaced.
    * A directory tree answers "what is in this folder", which is not the
      question a module map is asked. The question is "what depends on what",
      and that is a DAG.

    What is implemented here is the layered method of Sugiyama, Tagawa and Toda
    (1981) as it is implemented by Eclipse ELK's Layered algorithm: break
    cycles, assign layers, reduce crossings by repeated sweeps of the barycenter
    heuristic, then place coordinates. ELK defaults to ``NETWORK_SIMPLEX``
    layering and ``LAYER_SWEEP`` crossing minimisation; this uses longest-path
    layering and barycenter sweeps, which is the ``LONGEST_PATH`` /
    ``LAYER_SWEEP`` pair of the same algorithm family and is deterministic by
    construction. Coordinates are real pixels.
    """

    if not nodes:
        return {
            "algorithm": "layered",
            "seed": _seed(spec),
            "converged": True,
            "layers": 0,
            "crossings": 0,
            "cycles_broken": 0,
            "width": 0.0,
            "height": 0.0,
        }

    index_of = {str(node["id"]): i for i, node in enumerate(nodes)}

    # Only edges between two drawn nodes can influence the drawing. Duplicates
    # are collapsed here so the crossing count below is not inflated by the
    # `calls x128` bookkeeping.
    adjacency: list[set[int]] = [set() for _ in nodes]
    for edge in edges:
        src = index_of.get(str(edge.get("src")))
        dst = index_of.get(str(edge.get("dst")))
        if src is None or dst is None or src == dst:
            continue
        adjacency[src].add(dst)

    component_of, cycles = _strongly_connected(nodes, adjacency)

    # Layering runs on the condensation, not on the nodes. A repository's
    # modules import each other in large mutually recursive groups; laying the
    # nodes out directly puts every one of them on the same lane and the whole
    # map collapses into a single horizontal smear. Each strongly connected
    # group becomes one node for layout purposes and is drawn as a stack of
    # files inside its lane.
    members: dict[int, list[int]] = {}
    for node, group in enumerate(component_of):
        members.setdefault(group, []).append(node)
    for group in members:
        members[group].sort(key=lambda i: str(nodes[i]["id"]))

    count = len(members)
    group_adjacency: list[set[int]] = [set() for _ in range(count)]
    for src, targets in enumerate(adjacency):
        for dst in targets:
            left, right = component_of[src], component_of[dst]
            if left != right:
                group_adjacency[left].add(right)

    reverse = _build_reverse(group_adjacency, count)
    # `_assign_layers` indexes a membership list by node id; for the condensed
    # graph each node is its own group, so the identity list is the membership.
    layers = _assign_layers(list(range(count)), reverse, count)
    order = _reduce_crossings(group_adjacency, layers, count)
    _assign_component_coordinates(nodes, members, order, layers, component_of)
    crossings = _count_crossings(group_adjacency, layers, order)

    min_x = min(float(node["x"]) for node in nodes)
    max_x = max(float(node["x"]) + float(node["w"]) for node in nodes)
    min_y = min(float(node["y"]) for node in nodes)
    max_y = max(float(node["y"]) + NODE_HEIGHT for node in nodes)

    return {
        "algorithm": "layered",
        "seed": _seed(spec),
        "converged": True,
        "layers": (max(layers) + 1) if layers else 0,
        "components": count,
        "crossings": crossings,
        "cycles_broken": cycles,
        "width": round(max_x - min_x + 40.0, 2),
        "height": round(max_y - min_y + 40.0, 2),
        "layer_gap": LAYER_GAP,
        "crossing_sweeps": CROSSING_SWEEPS,
    }


def _wrap_width(
    order: dict[int, list[int]],
    box_width: dict[int, float],
    box_height: dict[int, float],
) -> int:
    """How many strongly connected groups may sit side by side in one row.

    The row count is *solved* for, not guessed.  An earlier version estimated
    the finished height as ``layer_count * tallest_group`` and returned the
    widest allowed row whenever the total width fit inside that estimate.  That
    estimate is wrong in a way that compounds: a row count above one multiplies
    the real height by the number of rows while leaving the width alone, so the
    function talked itself into the widest option and produced a drawing three
    times taller than it was wide.  Fit-to-view then zoomed out to fit the
    height and every node became a speck.

    So this computes the *exact* width and height the placement code would
    produce for each candidate -- the same sums, in the same order -- and picks
    the row count whose drawing is closest to ``TARGET_ASPECT`` in log space,
    which is the only place a ratio can be compared meaningfully.  If no
    candidate reaches the target, the closest one wins and the model reports the
    aspect it actually achieved rather than the one it wanted.
    """

    layer_groups = [order[depth] for depth in sorted(order)] if order else []
    if not layer_groups:
        return MAX_PER_ROW

    def extent(per_row: int) -> tuple[float, float]:
        width = 0.0
        height = 0.0
        for groups in layer_groups:
            rows = [groups[i : i + per_row] for i in range(0, len(groups), per_row)] or [[]]
            row_widths = [
                sum(box_width[group] for group in row) + GROUP_GAP * max(0, len(row) - 1)
                for row in rows
            ]
            width = max(width, max(row_widths) if row_widths else 0.0)
            # Same arithmetic as _assign_component_coordinates: each wrapped row
            # advances the cursor by its tallest group plus ROW_GAP, and each
            # layer adds LAYER_GAP.
            for row in rows:
                height += max((box_height[group] for group in row), default=0.0) + ROW_GAP
            height += LAYER_GAP
        return width, max(height - ROW_GAP, 1.0)

    target = math.log(TARGET_ASPECT)
    best = MAX_PER_ROW
    best_cost: float | None = None
    for per_row in range(MIN_PER_ROW, MAX_PER_ROW + 1):
        width, height = extent(per_row)
        cost = abs(math.log(max(width, 1.0) / height) - target)
        if best_cost is None or cost < best_cost:
            best, best_cost = per_row, cost
    return best


def _assign_component_coordinates(
    nodes: list[dict[str, Any]],
    members: dict[int, list[int]],
    order: dict[int, list[int]],
    layers: list[int],
    component_of: list[int],
) -> None:
    """Place each strongly connected group as a vertical stack in its lane.

    A lane is as tall as its tallest group, so groups that sit side by side do
    not overlap even when they hold very different numbers of files.
    """

    box_width = {
        group: max(_node_width(nodes[item]) for item in items)
        for group, items in members.items()
    }
    box_height = {
        group: len(items) * (NODE_HEIGHT + 6.0) + 12.0
        for group, items in members.items()
    }

    per_row = _wrap_width(order, box_width, box_height)
    cursor_y = 0.0
    widest = 0.0
    for depth in sorted(order):
        groups = order[depth]
        rows = [groups[i : i + per_row] for i in range(0, len(groups), per_row)] or [[]]
        row_widths = [
            sum(box_width[group] for group in row) + GROUP_GAP * max(0, len(row) - 1)
            for row in rows
        ]
        lane_width = max(row_widths) if row_widths else 0.0
        widest = max(widest, lane_width)
        top = cursor_y
        lane_height = 0.0
        for row, row_width in zip(rows, row_widths, strict=False):
            # Centre each wrapped row inside the lane so the wrapping reads as
            # one block rather than as a ragged left edge. The horizontal cursor
            # is reset per row: leaving it running turned the wrap into one
            # extremely wide row, which is the smear this wrapping exists to
            # prevent.
            offset = (lane_width - row_width) / 2.0
            cursor_x = 0.0
            height_here = 0.0
            for group in row:
                items = members[group]
                x = cursor_x + offset + (box_width[group] - _node_width(nodes[items[0]])) / 2.0
                y = cursor_y
                for item in items:
                    record = nodes[item]
                    record["_x"] = x
                    record["_y"] = y
                    record["layer"] = depth
                    record["in_cycle"] = len(items) > 1
                    y += NODE_HEIGHT + 6.0
                height_here = max(height_here, y - cursor_y)
                cursor_x += box_width[group] + GROUP_GAP
            cursor_y += height_here + ROW_GAP
            lane_height += height_here + ROW_GAP
        cursor_y = top + lane_height - ROW_GAP + LAYER_GAP

    min_x = min(float(node["_x"]) for node in nodes)
    min_y = min(float(node["_y"]) for node in nodes)
    for node in nodes:
        # Shifted to the positive quadrant: negative coordinates are valid for a
        # renderer but make every downstream consumer that measures a bounding
        # box have to handle two origins.
        node["x"] = round(float(node.pop("_x")) - min_x, 2)
        node["y"] = round(float(node.pop("_y")) - min_y, 2)
        node["w"] = round(_node_width(node), 2)
        node["h"] = NODE_HEIGHT


def _strongly_connected(
    nodes: list[dict[str, Any]],
    adjacency: list[set[int]],
) -> tuple[list[int], int]:
    """Tarjan's strongly connected components, iterative.

    Recursion would blow the stack on a repository-sized graph. Each component
    that contains a real cycle collapses into one lane, because a cycle has no
    layering and pretending otherwise is the single most common way a layered
    diagram lies about the code.
    """

    count = len(nodes)
    index = [-1] * count
    low = [0] * count
    on_stack = [False] * count
    stack: list[int] = []
    component_of = [-1] * count
    component: list[int] = []
    cycles = 0
    timer = 0

    for root in range(count):
        if index[root] != -1:
            continue
        work: list[tuple[int, list[int]]] = [(root, sorted(adjacency[root]))]
        index[root] = low[root] = timer
        timer += 1
        stack.append(root)
        on_stack[root] = True
        while work:
            node, pending = work[-1]
            if pending:
                nxt = pending.pop(0)
                if index[nxt] == -1:
                    index[nxt] = low[nxt] = timer
                    timer += 1
                    stack.append(nxt)
                    on_stack[nxt] = True
                    work.append((nxt, sorted(adjacency[nxt])))
                elif on_stack[nxt]:
                    low[node] = min(low[node], index[nxt])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                size = 0
                while True:
                    member = stack.pop()
                    on_stack[member] = False
                    component_of[member] = len(component)
                    size += 1
                    if member == node:
                        break
                if size > 1:
                    cycles += 1
                    component.append(size)
                else:
                    component.append(1)

    return component_of, cycles


def _assign_layers(
    component: list[int],
    incoming: list[set[int]],
    count: int,
) -> list[int]:
    """Longest-path layering over the condensation.

    Each component sits one layer below its deepest predecessor, so an arrow
    always points downwards on screen: the caller is drawn above what it calls.
    Depth is memoised and the condensation is acyclic by construction, so the
    recursion terminates; the ``seen`` guard exists so a future change cannot
    turn this into a stack overflow.
    """

    # Depth is measured from the sources, not towards the sinks. Measuring
    # towards the sinks puts every leaf at the top and inverts the reading of
    # the whole diagram, which is exactly what an earlier version did.
    depth: dict[int, int] = {}

    def resolve(node: int, seen: frozenset[int]) -> int:
        if node in depth:
            return depth[node]
        if node in seen:
            return 0
        best = 0
        for parent in sorted(incoming[node]):
            best = max(best, resolve(parent, seen | {node}) + 1)
        depth[node] = best
        return best

    for node in range(count):
        resolve(node, frozenset())
    return [depth.get(component[i], 0) for i in range(count)]


def _reduce_crossings(
    adjacency: list[set[int]],
    layers: list[int],
    count: int,
) -> dict[int, list[int]]:
    """Order the nodes inside each layer by the barycenter heuristic.

    Sugiyama's crossing-reduction step, as implemented by ELK's
    ``LAYER_SWEEP`` strategy: alternate downward and upward passes, replacing
    each node's position with the mean index of its neighbours in the adjacent
    layer, then re-sort that layer only.

    Ties are broken by node id, never by set iteration order, so the result is
    identical on every run and every platform.
    """

    buckets: dict[int, list[int]] = {}
    for node in range(count):
        buckets.setdefault(layers[node], []).append(node)
    for items in buckets.values():
        items.sort()
    if not buckets:
        return buckets

    reverse = _build_reverse(adjacency, count)

    def neighbours(node: int, depth: int, downward: bool) -> list[int]:
        found = adjacency[node] if downward else reverse[node]
        return sorted(other for other in found if layers[other] == depth)

    for sweep in range(CROSSING_SWEEPS):
        downward = sweep % 2 == 0
        depths = sorted(buckets, reverse=not downward)
        for depth in depths:
            items = buckets[depth]
            neighbour_layer = depth + (1 if downward else -1)
            if neighbour_layer not in buckets:
                continue
            positions = {node: slot for slot, node in enumerate(buckets[neighbour_layer])}
            scored: list[tuple[float, int, int]] = []
            for node in items:
                adjacent = neighbours(node, neighbour_layer, downward)
                if adjacent:
                    centre = sum(positions[other] for other in adjacent) / len(adjacent)
                else:
                    centre = float(positions.get(node, len(items)))
                scored.append((centre, node, node))
            scored.sort(key=lambda entry: (entry[0], entry[1]))
            buckets[depth] = [node for _centre, _tie, node in scored]
    return buckets


def _build_reverse(adjacency: list[set[int]], count: int) -> list[set[int]]:
    reverse: list[set[int]] = [set() for _ in range(count)]
    for node in range(count):
        for other in adjacency[node]:
            reverse[other].add(node)
    return reverse


def _count_crossings(
    adjacency: list[set[int]],
    layers: list[int],
    order: dict[int, list[int]],
) -> int:
    """Adjacent-layer edge crossings, counted exactly.

    A layer pair contributes one crossing per inversion in the bottom-layer
    positions of its edges once they are sorted by top-layer position. Counting
    inversions by comparing every pair is O(m^2) and would take minutes on a
    repository-sized map; a merge-sort inversion count is exact and linearithmic.
    """

    slot: dict[int, int] = {}
    for _depth, items in order.items():
        for position, node in enumerate(items):
            slot[node] = position

    by_layer: dict[int, list[tuple[int, int]]] = {}
    for node, targets in enumerate(adjacency):
        for dst in targets:
            if layers[dst] == layers[node] + 1:
                by_layer.setdefault(layers[node], []).append((node, dst))

    total = 0
    for entries in by_layer.values():
        entries.sort(key=lambda pair: (slot.get(pair[0], 0), slot.get(pair[1], 0)))
        values = [slot.get(dst, 0) for _src, dst in entries]
        total += _inversions(values)
    return total


def _inversions(values: list[int]) -> int:
    """Merge-sort inversion count."""

    if len(values) < 2:
        return 0
    middle = len(values) // 2
    left = _inversions(values[:middle])
    right = _inversions(values[middle:])
    merged: list[int] = []
    i = j = 0
    seen = 0
    while i < middle and j < len(values) - middle:
        if values[i] <= values[middle + j]:
            merged.append(values[i])
            i += 1
        else:
            merged.append(values[middle + j])
            j += 1
            seen += middle - i
    merged.extend(values[i:middle])
    merged.extend(values[middle + j :])
    return left + right + seen


# --------------------------------------------------------------------------- #
# Legend and honesty
# --------------------------------------------------------------------------- #
#: Shape legends per view. A glyph that appears in a map with no legend entry
#: is a glyph the reader has to guess at, and the data-flow view is the one place
#: where the shape carries the meaning (diamond = the value's origin).
FLOW_SHAPE_LEGEND: dict[str, str] = {
    "source": "where an untrusted value enters",
    "sink": "where it is used",
    "caller": "the function the path arrived from",
    "via": "a step in between",
    "symbol": "an indexed symbol",
}


def _legend(spec: MapSpec) -> dict[str, Any]:
    kinds = sorted(spec.resolved_kinds())
    styles: dict[str, str] = {}
    for kind in kinds:
        styles.setdefault(kind, "dashed")
    return {
        "node_shapes": dict(NODE_SHAPES),
        "flow_shapes": dict(FLOW_SHAPE_LEGEND) if spec.view == "data_flow" else {},
        "edge_styles": EDGE_STYLES,
        "kind_default_style": styles,
        "severity_order": list(SEVERITY_ORDER),
        "note": (
            "solid = the engine proved it statically or by type; dashed = inferred "
            "by name; dotted = the target could not be bound."
        ),
    }


def _honesty(report: Any, snapshot: dict[str, Any], spec: MapSpec, model: dict[str, Any]) -> dict[str, Any]:
    stats = model.get("stats") or {}
    caveats: list[str] = []

    unresolved = int(snapshot.get("unresolved") or 0)
    if unresolved:
        caveats.append(
            f"{unresolved} call target(s) in this scan could not be resolved to a symbol; "
            "the map shows the edges that were resolved, not the ones that were guessed."
        )
    if snapshot.get("truncated"):
        caveats.append(
            "the stored graph snapshot is itself truncated: this map is a projection of the "
            f"scan, not the whole repository ({int(snapshot.get('edges_omitted') or 0)} "
            "edge(s) were dropped when the snapshot was written)."
        )
    if stats.get("omitted_nodes") or stats.get("budget_omitted"):
        parts = []
        if stats.get("omitted_nodes"):
            parts.append(f"{stats['omitted_nodes']} node(s)")
        for kind, dropped in sorted((stats.get("budget_omitted") or {}).items()):
            parts.append(f"{dropped} {kind} edge(s)")
        caveats.append(
            "the requested budget removed " + ", ".join(parts) + ". Raise --max-nodes or "
            "--max-edges, or narrow the view, to see them."
        )
    if spec.view == "module":
        caveats.append(
            f"{stats.get('collapsed', 0)} symbol(s) were collapsed onto their file: at this "
            "zoom level a module is a file, not a function."
        )
    if spec.view == "data_flow":
        drawn = int(stats.get("flows_drawn", 0))
        omitted = int(stats.get("flows_omitted", 0))
        caveats.append(
            f"this map draws only the {drawn} flow(s) the analyzer actually traced. "
            "A path that exists in the code but was not traced is not drawn, because "
            "drawing it would be a guess about where untrusted input goes."
        )
        if omitted:
            caveats.append(
                f"{omitted} recorded flow(s) were not drawn: more than "
                f"{FLOWS_PER_FINDING} per finding, or too few of their hops could be tied "
                "back to an indexed symbol. `understand finding show` has them in full."
            )
        unlinked = int(stats.get("flow_unlinked_nodes", 0))
        if unlinked:
            caveats.append(
                f"{unlinked} node(s) on this map name something the graph does not index — "
                "a value, a caller the resolver could not place, or a sink kind. They are "
                "drawn as the analyzer described them and are not connected to the code "
                "graph beyond the hop that named them."
            )
        proven = int(stats.get("proven_edges", 0))
        total = max(1, int(stats.get("edges", 0)))
        caveats.append(
            f"{proven} of {total} edge(s) were followed across modules or reproduced "
            f"({proven * 100 // total}%); the rest match a source pattern and a sink "
            "pattern without the value in between being traced. Solid edges are traced, "
            "dashed edges are matched."
        )
    if spec.view == "finding":
        placed = int(stats.get("findings_placed", 0))
        scope = int(stats.get("findings_in_scope", 0))
        if placed > scope:
            caveats.append(
                f"{placed - scope} extra placement(s) appear because one finding landed on "
                "more than one symbol; a finding can be counted on each symbol it touches."
            )
    if spec.include_findings:
        if stats.get("findings_withheld"):
            caveats.append(
                f"{stats['findings_withheld']} finding(s) were not attached to their node "
                f"(at most {stats.get('findings_cap', NODE_FINDING_CAP)} per node, "
                f"{FINDING_DETAIL_BUDGET} in total for this map). Use `understand finding "
                "show` with the finding id for the ones this map does not carry."
            )
        reason = str(stats.get("source_reason") or "")
        if reason:
            caveats.append(
                "nodes carry no source text because " + reason + "."
            )
        else:
            caveats.append(
                f"{stats.get('source_nodes', 0)} node(s) carry their own source lines, read "
                f"from {stats.get('source_root', '')} when this map was built. A repository "
                "that moves after the scan leaves the analysis intact and the text behind."
            )
    caveats.append(
        "the map records what static analysis proved. It is not evidence that anything is "
        "exploitable; check verification_status on a finding before acting on it."
    )
    return {
        "unresolved_call_targets": unresolved,
        "snapshot_truncated": bool(snapshot.get("truncated")),
        "caveats": caveats,
    }
