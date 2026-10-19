"""Scan orchestrator: explicit stages, budgets, cancellation, partial results."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from understand.config import RuntimeConfig
from understand.engine import coverage as coverage_mod
from understand.engine import language_detection as lang
from understand.engine.analyzers.base import AnalysisContext
from understand.engine.analyzers.registry import registry
from understand.engine.call_graph import CallGraph
from understand.engine.control_flow import extract_control_flow
from understand.engine.data_flow import analyze_data_flow
from understand.engine.dependency_analysis import analyze_dependencies
from understand.engine.graph_snapshot import empty_snapshot, snapshot_graph
from understand.engine.relations import build_relations
from understand.engine.repository_inventory import build_inventory, detect_frameworks_from_manifests
from understand.engine.repository_loader import AcquiredRepository, acquire
from understand.engine.symbol_index import SymbolIndex
from understand.engine.verification import normalize as normalize_findings
from understand.errors import ResourceLimitExceeded, ScanCancelled, UnderstandError
from understand.logging_config import get_logger
from understand.models import (
    Check,
    CoverageRecord,
    DependencyRecord,
    Finding,
    Profile,
    ScanReport,
    ScanRequest,
    ScanWarning,
    SourceKind,
    StageRecord,
    StageStatus,
    utcnow,
)
from understand.security.repository_policy import RepositoryPolicy
from understand.security.sandbox import Workspace

log = get_logger("engine.orchestrator")

STAGES = (
    "validate_request",
    "acquire_source",
    "inventory",
    "language_detection",
    "parse_and_index",
    "graph_construction",
    "dependency_analysis",
    "security_analysis",
    "bug_analysis",
    "reliability_analysis",
    "architecture_analysis",
    "cross_module_analysis",
    "dependency_status",
    "normalize_findings",
    "coverage",
    "cleanup",
)

PROFILE_NOTES: dict[str, list[str]] = {
    "standard": [
        "Standard profile: intra-procedural pattern rules, single-module call resolution, "
        "flow analysis limited to the calling module.",
    ],
    "deep": [
        "Deep profile adds cross-module call resolution, multi-hop taint propagation, "
        "control-flow resource pairing, architecture analysis and expanded data-flow budget.",
        "Deep profile costs materially more time and memory than the standard profile.",
    ],
}


@dataclass
class ScanResult:
    report: ScanReport
    index: SymbolIndex = field(default_factory=SymbolIndex)
    graph: CallGraph = field(default_factory=CallGraph)
    repository: AcquiredRepository | None = None
    inventory: object | None = None
    flows: list = field(default_factory=list)

    def symbols(self) -> SymbolIndex:
        return self.index

    def cleanup(self) -> None:
        if self.repository is not None:
            self.repository.cleanup()


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise ScanCancelled("scan cancelled by request")


class ScanOrchestrator:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        cancel: CancellationToken | None = None,
        on_stage: Callable[[str], None] | None = None,
    ) -> None:
        self.config = config
        self.cancel = cancel or CancellationToken()
        #: Optional progress hook invoked with the stage name as it starts.
        #: Used by the application layer to answer "what is this scan doing?".
        self.on_stage = on_stage

    # ------------------------------------------------------------------ main
    def run(self, request: ScanRequest) -> ScanResult:
        started = time.monotonic()
        # Captured separately from the monotonic clock: monotonic time cannot be
        # turned back into a wall-clock timestamp, and the report needs both.
        started_at = utcnow()
        # The request carries its own wall-clock budget; every stage checkpoint
        # checks it so an over-long analysis stops instead of running forever.
        deadline = started + float(request.limits.max_seconds)
        stages: dict[str, StageRecord] = {name: StageRecord(name=name) for name in STAGES}
        warnings: list[ScanWarning] = []
        errors: list[ScanWarning] = []
        index = SymbolIndex()
        graph = CallGraph()
        flows: list = []
        repository: AcquiredRepository | None = None
        workspace: Workspace | None = None
        inventory = None
        coverage: CoverageRecord | None = None
        findings: list[Finding] = []
        dependencies: list[DependencyRecord] = []
        entry_points: list[dict] = []

        def stage(name: str) -> "_StageCtx":
            return _StageCtx(self, stages, name)

        def checkpoint() -> None:
            """Raise on cancellation or once the request's time budget is spent."""

            self.cancel.check()
            if time.monotonic() > deadline:
                raise ResourceLimitExceeded(
                    f"scan exceeded its time budget of {request.limits.max_seconds:g}s",
                    detail={"limit": "max_seconds", "value": request.limits.max_seconds},
                )

        try:
            # 1. validate ---------------------------------------------------
            with stage("validate_request") as s:
                s.start()
                s.mark(StageStatus.COMPLETED, "request validated")

            # 2. acquire ----------------------------------------------------
            with stage("acquire_source") as s:
                s.start()
                checkpoint()
                if not request.allow_remote and _looks_remote(request.repository):
                    from understand.errors import InvalidSourceError

                    raise InvalidSourceError("remote scanning disabled for this request")
                repository = acquire(request, self.config)
                s.mark(StageStatus.COMPLETED,
                       f"acquired {repository.kind.value} repository {repository.name}",
                       repository.display)
                root = repository.root

            # 3. inventory --------------------------------------------------
            with stage("inventory") as s:
                s.start()
                checkpoint()
                policy = RepositoryPolicy.for_config(self.config, allowed_roots=request.allowed_roots)
                limits = request.limits
                inventory = build_inventory(
                    root, policy,
                    max_files=min(limits.max_files, self.config.analysis.max_files),
                    max_file_bytes=min(limits.max_file_bytes, self.config.analysis.max_file_bytes),
                    max_total_bytes=min(limits.max_total_bytes, self.config.analysis.max_total_bytes),
                )
                s.mark(StageStatus.COMPLETED,
                       f"{len(inventory.files)} files, {inventory.total_bytes} bytes")

            # 4. language detection ----------------------------------------
            with stage("language_detection") as s:
                s.start()
                checkpoint()
                detected = {lang.detect(p).language for p in inventory.contents}
                s.mark(StageStatus.COMPLETED,
                       f"{len(detected)} language(s): " + ", ".join(sorted(detected)[:12]))

            # 5. parse + index ---------------------------------------------
            with stage("parse_and_index") as s:
                s.start()
                checkpoint()
                failed_parses, _symbols, generated_skipped = coverage_mod.parse_all(
                    inventory, index, max_symbols=request.limits.max_symbols)
                if failed_parses:
                    warnings.append(ScanWarning(
                        stage="parse_and_index",
                        message=f"{len(failed_parses)} file(s) could not be parsed and are "
                                "indexed structurally only: " + ", ".join(failed_parses[:8]),
                    ))
                s.mark(StageStatus.COMPLETED,
                       f"{len(index.by_id)} symbols across {len(index.modules)} files")

            # 6. graph ------------------------------------------------------
            with stage("graph_construction") as s:
                s.start()
                checkpoint()
                graph = CallGraph().build(index)
                for edge in build_relations(index, graph):
                    graph.add_edge(edge)
                s.mark(StageStatus.COMPLETED,
                       f"{len(graph.edges)} edges, {len(graph.unresolved)} unresolved call(s)")

            # 7. dependencies ----------------------------------------------
            with stage("dependency_analysis") as s:
                s.start()
                checkpoint()
                dep = analyze_dependencies(root, inventory.files,
                                           max_bytes=self.config.analysis.max_file_bytes)
                dependencies = dep.to_records()
                s.mark(StageStatus.COMPLETED,
                       f"{len(dependencies)} manifest(s); ecosystems: "
                       + (", ".join(sorted(dep.ecosystems)) or "none"))

            # 8-11. analyzers ------------------------------------------------
            control = extract_control_flow(index)
            checks = request.checks or registry.checks_for_profile(request.profile.value)
            ctx = AnalysisContext(
                index=index, graph=graph, profile=request.profile,
                cross_module=request.cross_module,
                checks=frozenset(checks), deep=request.profile is Profile.DEEP,
                data_flows=[], control_flow=control, limits=request.limits,
            )
            stage_by_check = {
                Check.SECURITY: "security_analysis",
                Check.BUGS: "bug_analysis",
                Check.RELIABILITY: "reliability_analysis",
                Check.ARCHITECTURE: "architecture_analysis",
                Check.DEPENDENCIES: "dependency_analysis",
            }

            # cross-module / flow analysis feeds the security analyzer
            if request.cross_module or request.profile is Profile.DEEP:
                with stage("cross_module_analysis") as s:
                    s.start()
                    checkpoint()
                    flows = analyze_data_flow(
                        index, graph,
                        cross_module=request.cross_module,
                        deep=request.profile is Profile.DEEP,
                        limit=request.limits.max_findings,
                    )
                    ctx.data_flows = flows
                    s.mark(StageStatus.COMPLETED,
                           f"{len(flows)} source-to-sink path(s)")
            else:
                with stage("cross_module_analysis") as s:
                    s.start()
                    s.mark(StageStatus.SKIPPED,
                           "cross-module analysis not requested; use --cross-module or --deep")

            for check in (Check.SECURITY, Check.BUGS, Check.RELIABILITY, Check.ARCHITECTURE):
                name = stage_by_check[check]
                with stage(name) as s:
                    s.start()
                    checkpoint()
                    if check not in checks:
                        s.mark(StageStatus.SKIPPED, f"{check.value} analysis not requested")
                        continue
                    sub = AnalysisContext(
                        index=index, graph=graph, profile=request.profile,
                        cross_module=request.cross_module,
                        checks=frozenset({check}),
                        deep=request.profile is Profile.DEEP,
                        data_flows=flows if check is Check.SECURITY else [],
                        control_flow=control, limits=request.limits,
                    )
                    produced, warns = registry.run(sub)
                    findings.extend(produced)
                    warnings.extend(warns)
                    entry_points = _entry_points(ctx)
                    s.mark(StageStatus.COMPLETED, f"{len(produced)} finding(s)")

            # 12. dependency vulnerability status --------------------------
            with stage("dependency_status") as s:
                s.start()
                checkpoint()
                s.mark(StageStatus.SKIPPED,
                       "No trusted advisory source configured; CVE/CVSS values are never invented")

            # 13. normalize -------------------------------------------------
            with stage("normalize_findings") as s:
                s.start()
                checkpoint()
                findings = normalize_findings(findings, limit=request.limits.max_findings)
                s.mark(StageStatus.COMPLETED, f"{len(findings)} unique finding(s)")

            # 14. coverage --------------------------------------------------
            with stage("coverage") as s:
                s.start()
                checkpoint()
                unsupported = [
                    f"{language}: {limitation}"
                    for language, limitation in _unsupported_features(inventory)
                ]
                coverage = coverage_mod.build_coverage(
                    inventory, index,
                    failed_parses=failed_parses,
                    unresolved_calls=len(graph.unresolved),
                    graph_edge_count=len(graph.edges),
                    truncated=inventory.truncated,
                    exclusions=policy.exclusion_reasons,
                    unsupported=unsupported,
                    notes=PROFILE_NOTES.get(request.profile.value, []),
                    generated_skipped=generated_skipped,
                )
                s.mark(StageStatus.COMPLETED, coverage_mod.summarize(coverage))

            status = "cancelled" if self.cancel.cancelled else "completed"
        except ScanCancelled as exc:
            status = "cancelled"
            errors.append(ScanWarning(stage="scan", message=str(exc), code="scan_cancelled"))
            coverage = coverage or _empty_coverage()
        except ResourceLimitExceeded as exc:
            status = "partial"
            errors.append(ScanWarning(stage="scan", message=str(exc), code="resource_limit_exceeded"))
            coverage = coverage or _empty_coverage()
        except Exception as exc:  # noqa: BLE001
            status = "failed"
            # UnderstandError carries its own code; anything else is an internal
            # failure and must not be reported as a user-input problem.
            code = exc.code if isinstance(exc, UnderstandError) else "analysis_error"
            errors.append(
                ScanWarning(stage="scan", message=f"{type(exc).__name__}: {exc}", code=code)
            )
            log.exception("scan failed")
            coverage = coverage or _empty_coverage()
            for rec in stages.values():
                if rec.status is StageStatus.RUNNING:
                    rec.status = StageStatus.FAILED
                    rec.error = f"{type(exc).__name__}: {exc}"
        finally:
            with stage("cleanup") as s:
                s.start()
                if repository is not None:
                    repository.cleanup()
                if workspace is not None:
                    workspace.__exit__(None, None, None)
                s.mark(StageStatus.COMPLETED, "temporary resources released")

        finished = time.monotonic()
        report = ScanReport(
            scan_id=_scan_id(started),
            status=status,
            source_kind=repository.kind if repository else SourceKind.LOCAL,
            repository=repository.display if repository else request.repository,
            repository_name=repository.name if repository else "",
            revision=repository.revision if repository else "",
            duration_seconds=round(finished - started, 3),
            request=request.model_dump(mode="json"),
            limits=request.limits.model_dump(mode="json"),
            languages=list(coverage.languages) if coverage else [],
            components=_components(inventory),
            entry_points=entry_points[:200],
            stages=list(stages.values()),
            coverage=coverage or _empty_coverage(),
            dependencies=dependencies,
            findings=findings,
            warnings=warnings,
            errors=errors,
            limitations=_limitations(coverage, graph, request),
            remediation_summary=_remediation_summary(findings),
            traces=_traces(flows),
            graph_snapshot=snapshot_graph(index, graph) if (index and graph) else empty_snapshot(),
            partial=status != "completed",
            started_at=started_at,
            finished_at=utcnow(),
        )
        report.finalize()
        return ScanResult(report=report, index=index, graph=graph,
                          repository=repository, inventory=inventory, flows=flows)


class _StageCtx:
    def __init__(self, orch: "ScanOrchestrator", stages: dict[str, StageRecord], name: str) -> None:
        self.orch = orch
        self.stages = stages
        self.rec = stages[name]
        self.t0 = 0.0

    def __enter__(self) -> "_StageCtx":
        self.t0 = time.monotonic()
        self.rec.status = StageStatus.RUNNING
        if self.orch.on_stage is not None:
            try:
                self.orch.on_stage(self.rec.name)
            except Exception:  # pragma: no cover - progress hook must never break a scan
                pass
        return self

    def start(self) -> None:
        """Explicitly begin the stage (idempotent with ``__enter__``)."""

        if self.rec.status is not StageStatus.RUNNING:
            self.__enter__()

    def mark(self, status: StageStatus, detail: str = "", context: str = "") -> None:
        self.rec.status = status
        self.rec.detail = f"{detail} | {context}" if context else detail
        self.rec.seconds = round(time.monotonic() - self.t0, 3)

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is not None and self.rec.status is StageStatus.RUNNING:
            self.rec.status = StageStatus.FAILED
            self.rec.error = f"{exc_type.__name__}: {exc}"
        if self.rec.status is StageStatus.RUNNING:
            self.rec.status = StageStatus.COMPLETED
        self.rec.seconds = round(time.monotonic() - self.t0, 3)


def _looks_remote(source: str) -> bool:
    s = source.lower()
    return s.startswith(("http://", "https://", "ssh://", "git+ssh://", "git@"))


def _scan_id(started: float) -> str:
    import hashlib
    import os

    return "scan_" + hashlib.sha256(
        f"{started:.6f}:{os.getpid()}:{time.time_ns()}".encode("utf-8")
    ).hexdigest()[:16]


def _entry_points(ctx: AnalysisContext) -> list[dict]:
    from understand.engine.analyzers.architecture_analysis import ArchitectureAnalyzer

    return ArchitectureAnalyzer.entry_points(ctx)


def _components(inventory) -> list[dict]:
    if inventory is None:
        return []
    frameworks = detect_frameworks_from_manifests(inventory)
    return [
        {"name": "build_systems", "values": sorted(set(inventory.build_systems))},
        {"name": "frameworks", "values": frameworks},
        {"name": "manifests", "values": sorted(inventory.manifests)[:50]},
        {"name": "ci", "values": sorted(inventory.ci_files)[:50]},
        {"name": "api_specs", "values": sorted(inventory.schemas)[:50]},
        {"name": "database_migrations", "values": sorted(inventory.migrations)[:50]},
        {"name": "infrastructure", "values": sorted(inventory.infra)[:50]},
        {"name": "scripts", "values": sorted(inventory.scripts)[:50]},
        {"name": "tests", "values": sorted(inventory.test_dirs)[:50]},
        {"name": "packages", "values": inventory.packages[:200]},
    ]


def _unsupported_features(inventory) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if inventory is None:
        return out
    for path in sorted(inventory.contents):
        detection = lang.detect(path)
        if detection.language == "unknown":
            out.append((path, "unknown"))
    return out


def _empty_coverage() -> CoverageRecord:
    return CoverageRecord()


def _traces(flows: list) -> dict[str, list[list[str]]]:
    traces: dict[str, list[list[str]]] = {}
    for i, flow in enumerate(flows[:100]):
        traces[f"flow_{i}"] = [flow.path()]
    return traces


def _limitations(coverage: CoverageRecord | None, graph: CallGraph, request: ScanRequest) -> list[str]:
    out = [
        "UNDERSTAND performs static analysis. It does not execute repository code and cannot "
        "confirm runtime-only behaviours.",
        "Findings are evidence-backed candidates. A finding is NOT a confirmed vulnerability "
        "unless its verification_status says so.",
        "Structural (non-Python) languages are parsed lexically: no type, scope or dynamic "
        "dispatch resolution is performed for them.",
        "Dependency vulnerability lookup is not performed unless a trusted advisory source is "
        "configured; no CVE or CVSS value is ever fabricated.",
        "Path sensitivity is not implemented; loops are summarised rather than unrolled.",
        "Template injection, deserialization gadgets and authorization bypass require manual "
        "confirmation beyond what static rules can establish.",
    ]
    if coverage:
        if coverage.unresolved_calls:
            out.append(f"{coverage.unresolved_calls} call target(s) were not statically resolvable.")
        if coverage.files_failed:
            out.append(f"{coverage.files_failed} file(s) failed to parse.")
        if coverage.truncated:
            out.append("The repository exceeded a configured budget; results are partial.")
        for language in coverage.languages:
            out.extend(f"{language.language}: {lim}" for lim in language.limitations[:3])
    if not request.cross_module:
        out.append("Cross-module reasoning was not enabled for this scan (use --cross-module).")
    if request.profile.value != "deep":
        out.append("Deep profile was not enabled; interprocedural analysis was limited.")
    return list(dict.fromkeys(out))


def _remediation_summary(findings: list[Finding]) -> list[str]:
    counts: dict[str, int] = {}
    for f in findings:
        if f.remediation:
            counts[f.remediation] = counts.get(f.remediation, 0) + 1
    return [f"{text} ({n} finding(s))" for text, n in
            sorted(counts.items(), key=lambda kv: -kv[1])[:10]]