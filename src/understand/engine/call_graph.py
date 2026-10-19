"""Call-graph construction and traversal.

Resolution is deliberately conservative.  A call edge is only ``STATIC_DIRECT``
or ``TYPE_RESOLVED`` when the target is provably the callee; a name match that
could be *any* of several symbols is recorded as ``INFERRED`` and a call that
cannot be resolved at all is kept in :attr:`CallGraph.unresolved` instead of
being silently dropped.  Downstream consumers depend on this distinction --
the architecture analyzer reports inferred edges as weaker evidence and the
data-flow analyzer refuses to mark a flow "proven" when a hop is unresolved.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..logging_config import get_logger
from ..models import CallSite, Edge, EdgeKind, RelationOrigin, TraceStep
from .symbol_index import SymbolIndex

__all__ = ["CallGraph", "build_call_graph"]

logger = get_logger("engine.callgraph")

_MAX_CYCLE_LENGTH = 6
_CYCLE_BUDGET = 200_000


class CallGraph:
    """Directed graph of resolved calls plus import dependencies."""

    def __init__(self) -> None:
        self.edges: list[Edge] = []
        self.outgoing: dict[str, list[Edge]] = defaultdict(list)
        self.incoming: dict[str, list[Edge]] = defaultdict(list)
        self.unresolved: list[CallSite] = []

    # ------------------------------------------------------------- building
    def add_edge(self, edge: Edge) -> Edge:
        self.edges.append(edge)
        self.outgoing[edge.src].append(edge)
        self.incoming[edge.dst].append(edge)
        return edge

    def build(self, index: SymbolIndex) -> CallGraph:
        for call in index.calls():
            edge = self._resolve(call, index)
            if edge is not None:
                self.add_edge(edge)
            else:
                self.unresolved.append(call)
                self.add_edge(
                    Edge(
                        src=call.caller_id,
                        dst=call.callee_name,
                        kind=EdgeKind.CALLS,
                        origin=RelationOrigin.UNRESOLVED,
                        file=call.file,
                        line=call.line,
                        label=f"unresolved:{call.callee_name}",
                    )
                )
        for path, imports in index.imports.items():
            mod_id = f"{path}::<module>"
            for raw, line, _text in imports:
                target = index.resolve_import(path, raw)
                kind = EdgeKind.DEPENDS_ON if target else EdgeKind.IMPORTS
                dst = f"{target}::<module>" if target else raw
                self.add_edge(
                    Edge(
                        src=mod_id,
                        dst=dst,
                        kind=kind,
                        origin=RelationOrigin.STATIC_DIRECT if target else RelationOrigin.UNRESOLVED,
                        file=path,
                        line=line,
                        label=f"import {raw}",
                    )
                )
        logger.debug(
            "call graph: %d edges, %d unresolved call(s)", len(self.edges), len(self.unresolved)
        )
        return self

    def _resolve(self, call: CallSite, index: SymbolIndex) -> Edge | None:
        caller_file = call.caller_id.split("::", 1)[0]
        module = index.modules.get(caller_file)
        name = call.callee_name

        # 1. direct qualified match (module.symbol / class.method)
        if name in index.by_id:
            return _edge(call, name, RelationOrigin.TYPE_RESOLVED, name)

        parts = name.split(".")
        leaf = parts[-1]
        owner = parts[0] if len(parts) > 1 else None

        # 2. resolve through the imports of the calling module
        if owner and module is not None:
            for raw, _line, _text in module.imports:
                target_file = index.resolve_import(caller_file, raw)
                if not target_file:
                    continue
                candidate = f"{target_file}::{leaf}"
                if candidate in index.by_id:
                    return _edge(call, candidate, RelationOrigin.TYPE_RESOLVED, name)
                for class_id in index.by_name.get(raw.rsplit(".", 1)[-1], []):
                    sym = index.by_id[class_id]
                    if sym.kind == "class" and sym.file == target_file:
                        method = f"{sym.id}.{leaf}"
                        if method in index.by_id:
                            return _edge(call, method, RelationOrigin.TYPE_RESOLVED, name)

        # 3. unique repo-wide name match
        candidates = list(index.by_name.get(leaf, []))
        if len(candidates) == 1:
            return _edge(call, candidates[0], RelationOrigin.INFERRED, f"inferred:{name}")
        if candidates:
            same_file = [c for c in candidates if c.startswith(caller_file + "::")]
            if len(same_file) == 1:
                return _edge(call, same_file[0], RelationOrigin.INFERRED, f"inferred:same-file:{name}")
            return _edge(call, candidates[0], RelationOrigin.INFERRED, f"ambiguous({len(candidates)}):{name}")

        # 4. attribute access on self / this inside a class
        if owner in {"self", "this"}:
            parent = index.by_id.get(call.caller_id)
            if parent is not None and parent.parent:
                method = f"{parent.parent}.{leaf}"
                if method in index.by_id:
                    return _edge(call, method, RelationOrigin.TYPE_RESOLVED, name)
        return None

    # ------------------------------------------------------------- traversal
    def callers(self, sid: str) -> list[str]:
        return sorted({edge.src for edge in self.incoming.get(sid, [])})

    def callees(self, sid: str) -> list[str]:
        return sorted({edge.dst for edge in self.outgoing.get(sid, []) if edge.kind is EdgeKind.CALLS})

    def _steps(self, index: SymbolIndex, edges: list[Edge]) -> list[TraceStep]:
        steps: list[TraceStep] = []
        for edge in edges:
            steps.append(
                TraceStep(
                    node=edge.dst,
                    label=_label(index, edge.dst),
                    kind=edge.kind.value,
                    file=edge.file,
                    line=edge.line,
                    unresolved=edge.origin is RelationOrigin.UNRESOLVED,
                    note=edge.label,
                )
            )
        return steps

    def trace(self, index: SymbolIndex, start: str, *, max_depth: int = 6, limit: int = 25) -> list[list[TraceStep]]:
        """Return up to ``limit`` call paths that start at ``start``."""

        if start not in index.by_id:
            return []
        paths: list[list[TraceStep]] = []
        stack: list[tuple[str, list[TraceStep], set[str]]] = [(start, [], {start})]
        while stack and len(paths) < limit:
            node, path, seen = stack.pop()
            edges = [e for e in self.outgoing.get(node, []) if e.kind is EdgeKind.CALLS]
            if not edges or len(path) >= max_depth:
                if path:
                    paths.append(path)
                continue
            for edge in edges:
                steps = self._steps(index, [edge])
                if edge.dst in seen:
                    paths.append([*path, *steps])
                    continue
                stack.append((edge.dst, [*path, *steps], seen | {edge.dst}))
        return paths

    def reachable(self, start: str, *, max_depth: int = 12, limit: int = 2000) -> set[str]:
        seen: set[str] = set()
        frontier = [start]
        depth = 0
        while frontier and depth < max_depth and len(seen) < limit:
            nxt: list[str] = []
            for node in frontier:
                for edge in self.outgoing.get(node, []):
                    if edge.dst in seen:
                        continue
                    seen.add(edge.dst)
                    if len(seen) >= limit:
                        return seen
                    nxt.append(edge.dst)
            frontier = nxt
            depth += 1
        return seen

    def reverse_reachable(self, start: str, *, max_depth: int = 12, limit: int = 2000) -> set[str]:
        seen: set[str] = set()
        frontier = [start]
        depth = 0
        while frontier and depth < max_depth and len(seen) < limit:
            nxt: list[str] = []
            for node in frontier:
                for edge in self.incoming.get(node, []):
                    if edge.src in seen:
                        continue
                    seen.add(edge.src)
                    if len(seen) >= limit:
                        return seen
                    nxt.append(edge.src)
            frontier = nxt
            depth += 1
        return seen

    def cycles(self, *, limit: int = 25) -> list[list[str]]:
        """Detect short dependency cycles (iterative DFS, budget bounded)."""

        found: list[list[str]] = []
        seen_signatures: set[frozenset[str]] = set()
        colour: dict[str, int] = {}
        stack: list[tuple[str, list[str]]] = []
        budget = _CYCLE_BUDGET

        for root in list(self.outgoing):
            if len(found) >= limit or budget <= 0:
                break
            if colour.get(root):
                continue
            stack.append((root, [root]))
            colour[root] = 1
            while stack and len(found) < limit and budget > 0:
                node, path = stack.pop()
                for edge in self.outgoing.get(node, []):
                    budget -= 1
                    if budget <= 0:
                        break
                    target = edge.dst
                    if target == path[0]:
                        if len(path) <= _MAX_CYCLE_LENGTH:
                            signature = frozenset(path)
                            if signature not in seen_signatures:
                                seen_signatures.add(signature)
                                found.append([*path, path[0]])
                        continue
                    if target in path or len(path) >= _MAX_CYCLE_LENGTH:
                        continue
                    if colour.get(target) == 1:
                        continue
                    colour[target] = 1
                    stack.append((target, [*path, target]))
            for node, _ in stack:
                colour[node] = 2
            stack.clear()
        return found


def _edge(call: CallSite, target: str, origin: RelationOrigin, label: str) -> Edge:
    return Edge(
        src=call.caller_id,
        dst=target,
        kind=EdgeKind.CALLS,
        origin=origin,
        file=call.file,
        line=call.line,
        label=label,
    )


def _label(index: SymbolIndex, sid: str) -> str:
    symbol = index.by_id.get(sid)
    if symbol is not None:
        return f"{symbol.file}::{symbol.name}" if symbol.file else symbol.name
    return sid


def _kind(index: SymbolIndex, sid: str) -> str:
    symbol = index.by_id.get(sid)
    return symbol.kind if symbol is not None else "unknown"


def build_call_graph(index: SymbolIndex) -> CallGraph:
    """Convenience wrapper around :meth:`CallGraph.build`."""

    graph = CallGraph()
    graph.build(index)
    return graph


def _unused(value: Any) -> Any:  # pragma: no cover - keeps linters honest about Any import
    return value
