"""Report retrieval and rendering service.

This is what both ``understand report show`` and the MCP ``get_scan_report``
tool call.  It exists so the two interfaces cannot drift: filtering, paging,
payload shaping and format handling are defined exactly once.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import TOOL_NAME, __version__
from ..errors import UnsupportedFormatError, ValidationError
from ..logging_config import get_logger
from ..models import Page, ScanReport
from ..reporting import render_report, safe_output_path, write_report
from ..security.redaction import redact_obj
from ..storage.scan_store import ScanStore

__all__ = ["ReportService"]

logger = get_logger("application.report")

MAX_PAGE = 200


class ReportService:
    def __init__(self, store: ScanStore) -> None:
        self.store = store

    # -------------------------------------------------------------- retrieval
    def get(self, scan_id: str) -> ScanReport:
        report = self.store.load_report(scan_id)
        return report

    def summary(self, scan_id: str) -> dict[str, Any]:
        return self.store.scan_summary(scan_id)

    def list(self, *, limit: int = 20, offset: int = 0, repository: str | None = None,
             status: str | None = None) -> Page:
        return self.store.list_scans(
            limit=max(1, min(int(limit), MAX_PAGE)),
            offset=max(0, int(offset)),
            repository=repository,
            status=status,
        )

    # --------------------------------------------------------------- payload
    def payload(
        self,
        report: ScanReport,
        *,
        include_evidence: bool = True,
        include_execution_paths: bool = True,
        include_stages: bool = False,
        include_dependencies: bool = False,
        include_warnings: bool = True,
        findings: Page | None = None,
    ) -> dict[str, Any]:
        """Build the report payload shared by ``report show`` and MCP.

        The full document is always available through ``format='json'``; this
        payload is the *default* because a client that renders a report cares
        about findings, coverage and honesty metadata first.
        """

        data: dict[str, Any] = {
            "tool": TOOL_NAME,
            "tool_version": __version__,
            "schema_version": report.schema_version,
            "scan_id": report.scan_id,
            "status": report.status,
            "partial": report.partial,
            "from_cache": report.from_cache,
            "repository": {
                "source": report.repository,
                "name": report.repository_name,
                "revision": report.revision,
                "kind": report.source_kind.value,
            },
            "timing": {
                "started_at": report.started_at,
                "finished_at": report.finished_at,
                "duration_seconds": report.duration_seconds,
            },
            "request": report.request,
            "coverage": report.coverage.model_dump(mode="json"),
            "languages": [record.model_dump(mode="json") for record in report.languages],
            "components": report.components[:100],
            "entry_points": report.entry_points[:100],
            "findings_by_severity": report.findings_by_severity,
            "findings_by_category": report.findings_by_category,
            "findings_total": len(report.findings),
            "remediation_summary": report.remediation_summary,
            "limitations": report.limitations,
            "findings": findings.items if findings is not None else [],
            "pagination": {
                "total": findings.total if findings is not None else len(report.findings),
                "offset": findings.offset if findings is not None else 0,
                "limit": findings.limit if findings is not None else len(report.findings),
                "next_offset": findings.next_offset if findings is not None else None,
            },
        }
        if not include_evidence and findings is not None:
            data["findings"] = [_strip_evidence(item) for item in data["findings"]]
        if include_execution_paths and report.traces:
            data["execution_paths"] = report.traces
        if include_stages:
            data["stages"] = [record.model_dump(mode="json") for record in report.stages]
        if include_dependencies:
            data["dependencies"] = [record.model_dump(mode="json") for record in report.dependencies]
        if include_warnings:
            data["warnings"] = [record.model_dump(mode="json") for record in report.warnings]
            data["errors"] = [record.model_dump(mode="json") for record in report.errors]
        return redact_obj(data)

    # --------------------------------------------------------------- render
    def render(self, report: ScanReport, fmt: str = "text", **kwargs: Any) -> str:
        if fmt not in ("json", "text", "sarif"):
            raise UnsupportedFormatError(
                f"unsupported report format {fmt!r}",
                detail={"supported": ["json", "text", "sarif"]},
            )
        return render_report(report, fmt, **kwargs)

    def export(self, report: ScanReport, fmt: str, path: str, **kwargs: Any) -> Path:
        """Render and write to ``path`` after validating the destination."""

        if not str(path).strip():
            raise ValidationError("output path must not be empty")
        target = safe_output_path(path, fmt=fmt)
        write_report(report, fmt, target, **kwargs)
        return target


def _strip_evidence(item: Any) -> Any:
    if isinstance(item, dict):
        stripped = dict(item)
        stripped.pop("evidence", None)
        return stripped
    return item
