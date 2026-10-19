"""Change-impact analysis over a stored scan.

Given a set of changed paths, the question a professional actually asks is:
*what else moves if this changes, and what risk was already recorded there?*
The answer is built only from evidence the scan captured -- symbols, call-graph
reachability and findings -- never from guesswork about "similar" files.
"""

from __future__ import annotations

import posixpath
from typing import Any

from ..errors import ValidationError
from ..models import ScanReport
from .trace_service import GraphView

__all__ = ["ImpactService"]

MAX_CHANGED_FILES = 500
MAX_CALLERS = 200


def _normalize(path: str) -> str:
    cleaned = str(path or "").replace("\\", "/").strip()
    cleaned = cleaned.lstrip("./")
    return posixpath.normpath(cleaned) if cleaned else ""


class ImpactService:
    """Answers ``analyze_change_impact`` for one scan."""

    def __init__(self, report: ScanReport) -> None:
        self.report = report
        self.view = GraphView(report)

    def analyze(self, changed_files: list[str], *, max_depth: int = 3) -> dict[str, Any]:
        if not changed_files:
            raise ValidationError("changed_files must contain at least one path")
        if len(changed_files) > MAX_CHANGED_FILES:
            raise ValidationError(
                f"changed_files may contain at most {MAX_CHANGED_FILES} paths",
                detail={"received": len(changed_files)},
            )
        depth = max(1, min(int(max_depth), 8))
        wanted = {_normalize(path) for path in changed_files if _normalize(path)}

        # --- symbols defined in the changed files ----------------------------
        touched_symbols: dict[str, dict[str, Any]] = {}
        for node_id, meta in self.view.raw_nodes.items():
            file_path = _normalize(str(meta.get("file") or ""))
            if not file_path:
                continue
            if file_path in wanted or any(file_path.endswith("/" + w) or w.endswith("/" + file_path) for w in wanted):
                touched_symbols[node_id] = meta

        # --- reverse reachability: who calls into the changed code ----------
        callers: dict[str, dict[str, Any]] = {}
        frontier = set(touched_symbols)
        visited: set[str] = set(touched_symbols)
        for hop in range(depth):
            nxt: set[str] = set()
            for node_id in frontier:
                for edge in self.view.inn.get(node_id) or []:
                    caller = str(edge.get("src") or "")
                    if not caller or caller in visited:
                        continue
                    visited.add(caller)
                    nxt.add(caller)
                    meta = self.view.node(caller)
                    callers.setdefault(
                        caller,
                        {
                            "node": caller,
                            "symbol": meta.get("name") or caller,
                            "file": meta.get("file") or (edge.get("file") or ""),
                            "line": int(meta.get("start_line") or edge.get("line") or 0),
                            "distance": hop + 1,
                            "via": node_id,
                            "edge_kind": edge.get("kind", ""),
                            "edge_origin": edge.get("origin", ""),
                        },
                    )
                    if len(callers) >= MAX_CALLERS:
                        break
                if len(callers) >= MAX_CALLERS:
                    break
            frontier = nxt
            if not frontier or len(callers) >= MAX_CALLERS:
                break

        # --- findings that already exist in or reach the changed code --------
        affected_ids = set(touched_symbols) | set(callers)
        file_findings: list[dict[str, Any]] = []
        symbol_findings: list[dict[str, Any]] = []
        for finding in self.report.findings:
            files = {
                _normalize(str(ev.file or "")) for ev in finding.evidence if ev.file
            }
            hits_file = bool(files & wanted)
            hits_symbol = bool(set(finding.affected_symbols) & affected_ids)
            if not hits_file and not hits_symbol:
                continue
            entry = {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "verification_status": finding.verification_status.value,
                "title": finding.title,
                "match": "symbol" if hits_symbol and not hits_file else "file",
            }
            if hits_file:
                file_findings.append(entry)
            if hits_symbol:
                symbol_findings.append(entry)

        entry_points = [
            entry
            for entry in self.report.entry_points
            if _normalize(str(entry.get("file") or "")) in wanted
        ]

        return {
            "scan_id": self.report.scan_id,
            "changed_files": sorted(wanted),
            "matched_files": sorted({_normalize(str(m.get("file") or "")) for m in touched_symbols.values() if m.get("file")}),
            "changed_symbols": [
                {
                    "node": node_id,
                    "symbol": meta.get("name", node_id),
                    "kind": meta.get("kind", ""),
                    "file": meta.get("file", ""),
                    "line": int(meta.get("start_line") or 0),
                }
                for node_id, meta in sorted(touched_symbols.items())
            ],
            "impacted_callers": sorted(callers.values(), key=lambda item: (item["distance"], item["symbol"])),
            "entry_points": entry_points,
            "existing_findings": {
                "in_changed_files": _dedupe(file_findings),
                "reachable_from_changed_code": _dedupe(symbol_findings),
            },
            "counts": {
                "changed_files": len(wanted),
                "symbols": len(touched_symbols),
                "impacted_callers": len(callers),
                "findings_in_changed_files": len(_dedupe(file_findings)),
                "findings_reachable": len(_dedupe(symbol_findings)),
            },
            "provenance": {
                "method": "reverse reachability over the scan's call graph plus the scan's findings",
                "truncated": self.view.truncated or len(callers) >= MAX_CALLERS,
                "unresolved_calls_in_scan": self.view.unresolved,
                "note": (
                    "impact is derived from call-graph reachability recorded during the scan; "
                    "reflection, dynamic dispatch and runtime-only paths are not represented"
                ),
            },
        }


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        if item["finding_id"] in seen:
            continue
        seen.add(item["finding_id"])
        out.append(item)
    return out
