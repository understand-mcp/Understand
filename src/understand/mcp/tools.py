"""MCP tool implementations for UNDERSTAND.

Every tool is a thin, validated adapter over the *same* application services the
CLI uses. There is deliberately no tool that executes shell commands, reads an
arbitrary path, or evaluates code from the analysed repository.
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Callable
from typing import Any, TypeVar, overload

from understand import __version__
from understand.application import (
    FindingService,
    ImpactService,
    ReportService,
    ScanService,
    TraceService,
    finding_to_dict,
)
from understand.config import RuntimeConfig, load_config
from understand.logging_config import get_logger
from understand.mcp import schemas
from understand.models import ResourceLimits, ScanRequest

logger = get_logger("mcp.tools")

__all__ = ["ToolBox", "build_toolbox"]

_F = TypeVar("_F", bound=Callable[..., dict[str, Any]])


@overload
def envelope(name: str) -> Callable[[_F], _F]: ...


@overload
def envelope(name: str, handler: _F) -> _F: ...


def envelope(name: str, handler: _F | None = None) -> Any:
    """Guarantee every tool result is a JSON document with an ``ok`` flag.

    A tool never raises through this boundary: failures become
    ``{"ok": False, "tool": name, "error": {...}}`` so both the CLI and the MCP
    server report the same stable error code for the same failure.
    """

    def decorate(func: _F) -> _F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                logger.debug("tool %s failed", name, exc_info=True)
                return {"ok": False, "tool": name, "error": schemas.error_envelope(exc)}
            if isinstance(result, dict):
                return {"ok": True, "tool": name, **result}
            return {"ok": True, "tool": name, "result": result}

        return wrapper  # type: ignore[return-value]

    if handler is None:
        return decorate
    return decorate(handler)


class ToolBox:
    """Stateful container wiring one :class:`ScanService` to every tool."""

    def __init__(self, config: RuntimeConfig | None = None, service: ScanService | None = None) -> None:
        self._lock = threading.RLock()
        self.config = config or load_config()
        self.service = service or ScanService(self.config)
        self.service.open()

    # -- lifecycle ---------------------------------------------------------- #
    def close(self) -> None:
        with self._lock:
            try:
                self.service.close()
            except Exception:  # pragma: no cover - shutdown must not raise
                logger.debug("service close failed", exc_info=True)

    def __enter__(self) -> ToolBox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- helpers ------------------------------------------------------------ #
    @property
    def reports(self) -> ReportService:
        return ReportService(self.service.store)

    @property
    def findings(self) -> FindingService:
        return FindingService(self.service.store)

    def _request(self, args: schemas.ScanRequestInput) -> ScanRequest:
        limits = ResourceLimits()
        if args.max_files:
            limits.max_files = args.max_files
        if args.max_file_bytes:
            limits.max_file_bytes = args.max_file_bytes
        if args.max_seconds:
            limits.max_seconds = args.max_seconds
        return ScanRequest(
            repository=args.repository,
            profile=args.to_profile(),
            checks=args.to_checks(),
            cross_module=args.cross_module,
            report_format=args.report_format,
            emit_report=False,
            include_evidence=args.include_evidence,
            include_execution_paths=args.include_execution_paths,
            limits=limits,
            allow_remote=args.allow_remote,
            use_cache=args.use_cache and not args.offline,
            offline=args.offline,
        )

    # -- 1. scan_repository -------------------------------------------------- #
    @envelope("scan_repository")
    def scan_repository(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.ScanRequestInput, payload)
        request = self._request(args)
        job = self.service.start(request, use_cache=request.use_cache)
        if not args.wait:
            return {
                "scan_id": job.scan_id,
                "status": job.status,
                "repository": request.repository,
                "checks": [check.value for check in request.checks],
                "message": "scan started; poll get_scan_status with this scan id",
            }
        job.wait(args.timeout_seconds or request.limits.max_seconds + 120.0)
        if job.error is not None:
            raise job.error if isinstance(job.error, Exception) else RuntimeError(str(job.error))
        report = job.report
        assert report is not None
        page = self.findings.query_report(report, limit=200)
        payload_out = self.reports.payload(
            report,
            findings=page,
            include_evidence=args.include_evidence,
            include_execution_paths=args.include_execution_paths,
            include_stages=True,
            include_dependencies=True,
        )
        payload_out["scan_id"] = job.scan_id
        payload_out["status"] = job.status
        return payload_out

    # -- 2. get_scan_status --------------------------------------------------- #
    @envelope("get_scan_status")
    def get_scan_status(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.ScanStatusInput, payload)
        return self.service.status(args.scan_id)

    # -- 3. cancel_scan ------------------------------------------------------- #
    @envelope("cancel_scan")
    def cancel_scan(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.CancelScanInput, payload)
        self.service.get(args.scan_id)
        cancelled = self.service.cancel(args.scan_id)
        return {
            "scan_id": args.scan_id,
            "cancelled": cancelled,
            "message": "cancellation requested" if cancelled else "scan is unknown or already finished",
        }

    # -- 4. get_scan_report ---------------------------------------------------- #
    @envelope("get_scan_report")
    def get_scan_report(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.ReportQueryInput, payload)
        report = self.reports.get(args.scan_id)
        page = self.findings.query(
            args.scan_id,
            severity=args.severity,
            category=args.category,
            rule_id=args.rule_id,
            file=args.file,
            language=args.language,
            verification_status=args.verification_status,
            query=args.query,
            include_suppressed=args.include_suppressed,
            limit=args.limit,
            offset=args.offset,
        )
        return self.reports.payload(
            report,
            findings=page,
            include_evidence=args.include_evidence,
            include_execution_paths=args.include_execution_paths,
            include_stages=args.include_stages,
            include_dependencies=args.include_dependencies,
        )

    # -- 5. inspect_finding ---------------------------------------------------- #
    @envelope("inspect_finding")
    def inspect_finding(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.FindingInput, payload)
        finding = self.findings.get(args.finding_id, scan_id=args.scan_id)
        document = finding_to_dict(finding, include_evidence=args.include_evidence)
        interpretation = {
            "what_this_means": finding.summary,
            "how_confident": finding.confidence_rationale,
            "what_was_not_proven": finding.assumptions,
            "how_to_verify": finding.preconditions,
            "confidence_is_not_certainty": (
                "confidence describes the strength of the static evidence in this report, "
                "not the severity of the underlying issue and not a runtime exploit result."
            ),
        }
        return {"finding": document, "interpretation": interpretation}

    # -- 6. trace_execution ------------------------------------------------------ #
    @envelope("trace_execution")
    def trace_execution(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.ExecutionTraceInput, payload)
        report = self.reports.get(args.scan_id)
        return TraceService(report).trace_execution(
            args.symbol,
            direction=args.direction,
            max_depth=args.max_depth,
            max_paths=args.max_paths,
        )

    # -- 7. trace_data_flow ------------------------------------------------------ #
    @envelope("trace_data_flow")
    def trace_data_flow(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.DataFlowInput, payload)
        report = self.reports.get(args.scan_id)
        return TraceService(report).trace_data_flow(
            finding_id=args.finding_id or "",
            max_flows=args.max_flows,
        )

    # -- 8. analyze_change_impact --------------------------------------------------- #
    @envelope("analyze_change_impact")
    def analyze_change_impact(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.ChangeImpactInput, payload)
        report = self.reports.get(args.scan_id)
        return ImpactService(report).analyze(args.changed_files, max_depth=args.max_depth)

    # -- 9. query_codebase ------------------------------------------------------------ #
    @envelope("query_codebase")
    def query_codebase(self, **payload: Any) -> dict[str, Any]:
        args = schemas.validate(schemas.CodebaseQueryInput, payload)
        if not any(
            [
                args.query,
                args.severity,
                args.category,
                args.rule_id,
                args.file,
                args.language,
            ]
        ):
            raise ValueError(
                "query_codebase needs at least one filter: query, severity, category, rule_id, "
                "file or language"
            )
        report = self.reports.get(args.scan_id)
        page = self.findings.query_report(
            report,
            severity=args.severity,
            category=args.category,
            rule_id=args.rule_id,
            file=args.file,
            language=args.language,
            query=args.query,
            include_suppressed=args.include_suppressed,
            limit=args.limit,
            offset=args.offset,
        )
        result = page.model_dump(mode="json")
        result["scan_id"] = args.scan_id
        result["findings_by_severity"] = report.findings_by_severity
        result["provenance"] = {
            "tool": "understand",
            "tool_version": __version__,
            "note": (
                "every finding below carries file/line evidence from a static scan; "
                "no CVE, CVSS score, or runtime exploit result is fabricated."
            ),
        }
        return result

    @envelope("get_code_map")
    def get_code_map(
        self,
        **payload: Any,
    ) -> dict[str, Any]:
        """Return a bounded, renderable projection of a stored scan."""

        from ..engine import code_map as engine

        args = schemas.validate(schemas.MapQueryInput, payload)
        report = self.reports.get(args.scan_id)
        spec = engine.MapSpec(
            scan_id=args.scan_id,
            view=args.view,
            root=args.root.strip(),
            depth=args.depth,
            direction=args.direction,
            kinds=frozenset(k for k in (args.kinds or ()) if k),
            include_findings=args.include_findings,
            budget=engine.MapBudget(max_nodes=args.max_nodes, max_edges=args.max_edges),
        )
        engine.validate_spec(spec)
        model = engine.build_map(report, spec)
        # The HTML is opt-in. A client that wants to reason about this map
        # needs the nodes and edges as data; 40MB of markup helps nobody and
        # would blow the context window of every model it was handed to.
        result: dict[str, Any] = {
            "map": model,
            "view": args.view,
            "question": engine.VIEW_QUESTIONS.get(args.view, ""),
            "provenance": {
                "tool": "understand",
                "tool_version": __version__,
                "note": (
                    "This is what static analysis proved about the stored scan. "
                    "Node and edge counts, the budget removals and every caveat in "
                    "map.honesty are reported as they are: a truncated map that "
                    "looks complete is a false claim."
                ),
            },
        }
        if args.html:
            from ..reporting import render_map_html

            result["html"] = render_map_html(model)
        return result


def build_toolbox(config: RuntimeConfig | None = None) -> ToolBox:
    return ToolBox(config)
