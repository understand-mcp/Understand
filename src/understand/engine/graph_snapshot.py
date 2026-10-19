"""Bounded call-graph serialisation.

``trace_execution`` and ``analyze_change_impact`` must answer questions about a
scan that finished minutes or hours ago, without re-reading the repository.  The
scan therefore persists a *snapshot* of the resolved call graph inside its
report.  The snapshot is deliberately bounded: it is a projection of the graph,
never the whole repository, and it records only facts the graph actually proved
(``RelationOrigin`` travels with every edge so downstream consumers can tell a
type-resolved call from a name-only guess).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from understand.models import EdgeKind

if TYPE_CHECKING:  # pragma: no cover
    from .call_graph import CallGraph
    from .symbol_index import SymbolIndex

__all__ = ["snapshot_graph", "MAX_SNAPSHOT_NODES", "MAX_SNAPSHOT_EDGES", "empty_snapshot"]

MAX_SNAPSHOT_NODES = 60_000
MAX_SNAPSHOT_EDGES = 120_000

#: Edge kinds that make an execution trace meaningful.  ``DEPENDS_ON`` is
#: included because an import-level dependency is still an evidence-backed hop.
#: The semantic relations added by :mod:`understand.engine.relations` are
#: deliberately *not* all in here: tracing ``authenticate -> check_password``
#: through ``AUTHORIZES`` would present an authorization edge as an execution
#: step, which is a different claim.
_TRACE_KINDS = frozenset(
    {
        "calls",
        "imports",
        "depends_on",
        "implements",
        "inherits",
        "sends_data_to",
        "awaits_task",
        "handles_event",
        "reads",
        "writes",
        "tests",
    }
)

#: Every kind a report may carry.  The interactive map and the architecture
#: analyzer need the full relation vocabulary; a bounded trace does not.
_ALL_KINDS = frozenset(kind.value for kind in EdgeKind)


def empty_snapshot() -> dict[str, Any]:
    return {
        "nodes": {},
        "edges": [],
        "truncated": False,
        "nodes_omitted": 0,
        "edges_omitted": 0,
        "unresolved": 0,
    }


def snapshot_graph(
    index: "SymbolIndex",
    graph: "CallGraph",
    *,
    max_nodes: int = MAX_SNAPSHOT_NODES,
    max_edges: int = MAX_SNAPSHOT_EDGES,
    kinds: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Project ``graph`` into a JSON-serialisable, bounded structure.

    ``kinds`` defaults to the trace vocabulary.  Pass ``_ALL_KINDS`` when the
    consumer needs the full relation set (a map, an architecture review) and can
    afford a larger payload.
    """

    wanted = _TRACE_KINDS if kinds is None else kinds

    nodes: dict[str, dict[str, Any]] = {}
    node_budget = max(0, max_nodes)

    def node(node_id: str) -> dict[str, Any] | None:
        if node_id in nodes:
            return nodes[node_id]
        if len(nodes) >= node_budget:
            return None
        symbol = index.get(node_id) if hasattr(index, "get") else None
        record = {
            "id": node_id,
            "name": getattr(symbol, "name", None) or node_id.rsplit(".", 1)[-1],
            "kind": getattr(symbol, "kind", None) or "unknown",
            "file": getattr(symbol, "file", None) or "",
            "start_line": int(getattr(symbol, "start_line", 0) or 0),
            "end_line": int(getattr(symbol, "end_line", 0) or 0),
            "language": getattr(symbol, "language", None) or "",
            "exported": bool(getattr(symbol, "exported", False)),
        }
        nodes[node_id] = record
        return record

    selected = _balanced(graph.edges, wanted, max_edges)
    # An edge the budget could not hold counts as omitted even though it was
    # never offered to the writer, so ``truncated`` keeps meaning "the graph you
    # are looking at is not the whole graph".
    budget_omitted = max(0, _eligible(graph.edges, wanted) - len(selected))

    edges: list[dict[str, Any]] = []
    omitted = budget_omitted
    for edge in selected:
        src = node(edge.src)
        if src is None:
            omitted += 1
            continue
        node(edge.dst)  # best effort; may be dropped by the node budget
        edges.append(
            {
                "src": edge.src,
                "dst": edge.dst,
                "kind": edge.kind.value,
                "origin": edge.origin.value,
                "file": edge.file or "",
                "line": int(edge.line or 0),
                "label": edge.label or "",
            }
        )

    unresolved = len(getattr(graph, "unresolved", ()) or ())
    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": bool(omitted),
        "nodes_omitted": max(0, node_budget and len(getattr(index, "by_id", {})) - len(nodes)),
        "edges_omitted": omitted,
        "unresolved": unresolved,
        "edges_by_kind": _counts(edges),
    }


def _eligible(edges, wanted: frozenset[str]) -> int:
    return sum(1 for edge in edges if edge.kind.value in wanted)


def _counts(edges: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for edge in edges:
        kind = edge["kind"]
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _balanced(edges, wanted: frozenset[str], budget: int) -> list:
    """Yield edges so that every relation kind survives the budget.

    Filling the budget in insertion order means whichever kind was built first
    consumes all of it. On microsoft/playwright the 120,000-edge budget was
    entirely ``calls``, and every semantic relation was dropped: the graph was
    larger and less informative than before this module existed.

    Each kind gets a share proportional to its size with a floor, and within a
    kind the original order is preserved, so a call trace is still built from the
    first calls in the repository rather than a random sample.
    """

    buckets: dict[str, list] = {}
    for edge in edges:
        if edge.kind.value not in wanted:
            continue
        buckets.setdefault(edge.kind.value, []).append(edge)
    if not buckets or budget <= 0:
        return []

    total = sum(len(v) for v in buckets.values())
    if total <= budget:
        ordered: list = []
        for kind in sorted(buckets):
            ordered.extend(buckets[kind])
        return ordered

    # Proportional share with a floor, so a kind with 30 edges still gets in.
    floor = max(1, budget // (len(buckets) * 8))
    quota = {
        kind: max(floor, int(budget * len(items) / total))
        for kind, items in buckets.items()
    }
    # Hand any unused share to the kinds that still have edges left.
    while sum(quota.values()) < budget:
        progressed = False
        for kind, items in buckets.items():
            if quota[kind] < len(items):
                quota[kind] += 1
                progressed = True
                if sum(quota.values()) >= budget:
                    break
        if not progressed:
            break

    ordered = []
    for kind in sorted(buckets):
        ordered.extend(buckets[kind][: quota[kind]])
    return ordered[:budget]