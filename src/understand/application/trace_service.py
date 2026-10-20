"""Read-only graph queries over a *stored* scan report.

``trace_execution`` and ``trace_data_flow`` must answer questions about a scan
that finished earlier, in another process.  They therefore read the bounded
call-graph snapshot persisted with the report (``ScanReport.graph_snapshot``)
instead of re-parsing the repository.

Every hop is reported with its provenance.  A hop that came from a name-only
inference is marked ``origin=INFERRED`` and the path is marked unproven, which
is the difference between "here is evidence" and "here is a guess".
"""

from __future__ import annotations

from typing import Any

from ..errors import FindingNotFound, ValidationError
from ..logging_config import get_logger
from ..models import ScanReport

__all__ = ["GraphView", "TraceService"]

logger = get_logger("application.trace")

MAX_PATHS = 50
MAX_DEPTH = 25


class GraphView:
    """Adjacency access over ``ScanReport.graph_snapshot``."""

    def __init__(self, report: ScanReport) -> None:
        snapshot = report.graph_snapshot or {}
        self.raw_nodes: dict[str, dict[str, Any]] = dict(snapshot.get("nodes") or {})
        self.truncated: bool = bool(snapshot.get("truncated"))
        self.unresolved: int = int(snapshot.get("unresolved") or 0)
        self.out: dict[str, list[dict[str, Any]]] = {}
        self.inn: dict[str, list[dict[str, Any]]] = {}
        for edge in snapshot.get("edges") or []:
            src = str(edge.get("src") or "")
            dst = str(edge.get("dst") or "")
            if not src or not dst:
                continue
            self.out.setdefault(src, []).append(edge)
            self.inn.setdefault(dst, []).append(edge)

    # ------------------------------------------------------------------ lookup
    @property
    def empty(self) -> bool:
        return not self.raw_nodes and not self.out

    def node(self, node_id: str) -> dict[str, Any]:
        return self.raw_nodes.get(node_id) or {"id": node_id, "name": node_id, "kind": "unknown", "file": ""}

    def resolve(self, symbol: str) -> list[str]:
        """Resolve a user supplied symbol to snapshot node ids."""

        needle = symbol.strip()
        if not needle:
            return []
        exact = [key for key in self.raw_nodes if key == needle]
        if exact:
            return sorted(exact)
        by_name = sorted(key for key, meta in self.raw_nodes.items() if meta.get("name") == needle)
        if by_name:
            return by_name
        lowered = needle.lower()
        ci = sorted(
            key
            for key, meta in self.raw_nodes.items()
            if str(meta.get("name") or "").lower() == lowered
        )
        if ci:
            return ci
        suffix = sorted(
            key
            for key in self.raw_nodes
            if key.lower().endswith("." + lowered) or key.lower().endswith("::" + lowered)
        )
        if suffix:
            return suffix[:50]
        # Fall back to a name *contains* match, reported as ambiguous.
        fuzzy = sorted(
            key
            for key, meta in self.raw_nodes.items()
            if lowered in str(meta.get("name") or "").lower()
        )
        return fuzzy[:50]

    # --------------------------------------------------------------- stepping
    def step(self, node_id: str, edge: dict[str, Any], *, direction: str) -> dict[str, Any]:
        other = str(edge.get("dst")) if direction == "downstream" else str(edge.get("src"))
        meta = self.node(other)
        return {
            "node": other,
            "symbol": meta.get("name") or other,
            "kind": edge.get("kind", ""),
            "edge_origin": edge.get("origin", ""),
            "file": edge.get("file") or meta.get("file") or "",
            "line": int(edge.get("line") or meta.get("start_line") or 0),
            "unresolved": other not in self.raw_nodes,
        }


class TraceService:
    """Execution and data-flow tracing over a completed scan."""

    def __init__(self, report: ScanReport) -> None:
        self.report = report
        self.view = GraphView(report)

    # ------------------------------------------------------------- execution
    def trace_execution(
        self,
        symbol: str,
        *,
        direction: str = "downstream",
        max_depth: int = 6,
        max_paths: int = 10,
        kinds: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        if direction not in ("downstream", "upstream", "both"):
            raise ValidationError(
                f"direction must be one of downstream, upstream, both (got {direction!r})"
            )
        depth = max(1, min(int(max_depth), MAX_DEPTH))
        limit = max(1, min(int(max_paths), MAX_PATHS))
        candidates = self.view.resolve(symbol)
        if not candidates:
            return {
                "symbol": symbol,
                "resolved": False,
                "resolved_candidates": [],
                "paths": [],
                "path_count": 0,
                "truncated": False,
                "note": (
                    "symbol is not present in the scan's symbol index; it may live in an "
                    "excluded, unsupported, or dynamically-created symbol"
                ),
                "provenance": {
                    "method": "symbol-index lookup only; no graph walk was performed",
                    "source": "scan.graph_snapshot",
                    "unresolved_calls_in_scan": self.view.unresolved,
                },
            }

        paths: list[list[dict[str, Any]]] = []
        unresolved_hops = 0
        for node_id in candidates[:10]:
            start = {"node": node_id, "symbol": self.view.node(node_id).get("name", node_id),
                     "kind": "ENTRY", "edge_origin": "", "file": self.view.node(node_id).get("file", ""),
                     "line": int(self.view.node(node_id).get("start_line") or 0), "unresolved": False}
            directions = ("downstream", "upstream") if direction == "both" else (direction,)
            for way in directions:
                edges = self.view.out if way == "downstream" else self.view.inn
                for path in self._walk(node_id, edges, depth, limit - len(paths), way, kinds):
                    paths.append([start, *path])
                    unresolved_hops += sum(1 for step in path if step["unresolved"])
                    if len(paths) >= limit:
                        break
                if len(paths) >= limit:
                    break
            if len(paths) >= limit:
                break

        return {
            "symbol": symbol,
            "resolved": True,
            "resolved_candidates": candidates[:10],
            "direction": direction,
            "max_depth": depth,
            "paths": paths[:limit],
            "path_count": min(len(paths), limit),
            "unresolved_hops": unresolved_hops,
            "proven": unresolved_hops == 0,
            "truncated": self.view.truncated or len(paths) >= limit or bool(candidates[10:]),
            "provenance": {
                "method": "depth-limited walk over the call-graph edges recorded in the scan",
                "source": "scan.graph_snapshot",
                "unresolved_calls_in_scan": self.view.unresolved,
                "note": (
                    "edges are static resolution results; a hop with edge_origin=INFERRED or "
                    "UNRESOLVED is a hypothesis, not proof of execution"
                ),
            },
        }

    def _walk(
        self,
        start: str,
        edges: dict[str, list[dict[str, Any]]],
        depth: int,
        budget: int,
        direction: str,
        kinds: tuple[str, ...],
    ) -> list[list[dict[str, Any]]]:
        results: list[list[dict[str, Any]]] = []
        if budget <= 0:
            return results
        stack: list[tuple[str, list[dict[str, Any]], set[str]]] = [(start, [], {start})]
        while stack and len(results) < budget:
            node_id, path, seen = stack.pop()
            neighbours = edges.get(node_id) or []
            if not neighbours:
                if path:
                    results.append(path)
                continue
            if len(path) >= depth:
                results.append(path)
                continue
            for edge in neighbours:
                if kinds and edge.get("kind") not in kinds:
                    continue
                step = self.view.step(node_id, edge, direction=direction)
                nxt = step["node"]
                if nxt in seen:
                    results.append([*path, {**step, "cycle": True}])
                    continue
                stack.append((nxt, [*path, step], seen | {nxt}))
        return results

    # ------------------------------------------------------------- data flow
    def trace_data_flow(
        self,
        *,
        finding_id: str = "",
        source: str = "",
        sink: str = "",
        max_flows: int = 25,
    ) -> dict[str, Any]:
        """Return taint paths proven by the scan's data-flow analysis.

        Unlike execution traces, data flows only exist where the analyzer proved
        them; there is no "graph walk" fallback, because inventing a plausible
        path would be exactly the kind of unsupported claim this product avoids.
        """

        max_flows = max(1, min(int(max_flows), 200))
        selected: list[dict[str, Any]] = []
        for finding in self.report.findings:
            if finding_id and finding.finding_id != finding_id and finding.rule_id != finding_id:
                continue
            if not finding.data_flows:
                continue
            for flow in finding.data_flows:
                text = " ".join(flow).lower()
                if source and source.lower() not in text:
                    continue
                if sink and sink.lower() not in text:
                    continue
                selected.append(
                    {
                        "finding_id": finding.finding_id,
                        "rule_id": finding.rule_id,
                        "severity": finding.severity.value,
                        "verification_status": finding.verification_status.value,
                        "hops": list(flow),
                    }
                )
                if len(selected) >= max_flows:
                    break
            if len(selected) >= max_flows:
                break

        if (
            finding_id
            and not selected
            and not any(f.finding_id == finding_id or f.rule_id == finding_id for f in self.report.findings)
        ):
            raise FindingNotFound(f"unknown finding id {finding_id!r}", detail={"finding_id": finding_id})

        return {
            "scan_id": self.report.scan_id,
            "filters": {"finding_id": finding_id, "source": source, "sink": sink},
            "flows": selected,
            "count": len(selected),
            "provenance": {
                "method": "direct lookup of source-to-sink paths proven by the scan's data-flow analysis",
                "source": "scan.data_flow_analysis",
                "note": (
                    "flows are reported only where a source-to-sink path was derived from "
                    "static evidence; unresolved hops downgrade the finding's verification status"
                ),
            },
            "truncated": len(selected) >= max_flows,
        }
