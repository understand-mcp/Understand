"""Typed domain models shared by every interface and engine component.

All models are Pydantic v2 models so the exact same validated objects flow
from the CLI parser, from MCP tool arguments, through the orchestrator and
into the report serializers.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from understand import REPORT_SCHEMA_VERSION, TOOL_NAME, __version__


def utcnow() -> str:
    """Return an ISO-8601 UTC timestamp (second precision, always suffixed Z)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False, populate_by_name=True)


# --------------------------------------------------------------------------- enums


class SourceKind(str, Enum):
    LOCAL = "local"
    LOCAL_GIT = "local_git"
    REMOTE_GIT = "remote_git"


class Profile(str, Enum):
    STANDARD = "standard"
    DEEP = "deep"


class Check(str, Enum):
    SECURITY = "security"
    BUGS = "bugs"
    ARCHITECTURE = "architecture"
    DEPENDENCIES = "dependencies"
    RELIABILITY = "reliability"

    @classmethod
    def _missing_(cls, value: object) -> "Check | None":
        """Accept user-supplied spellings such as "BUGS" or " Security "."""
        if isinstance(value, str):
            text = value.strip().lower()
            for member in cls:
                if member.value == text:
                    return member
        return None


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(
                f"unknown severity {value!r}; expected one of "
                + ", ".join(s.value for s in cls)
            ) from exc


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 2, "medium": 1, "low": 0}[self.value]


class VerificationStatus(str, Enum):
    """How strongly a finding was established. Never inferred from plausibility."""

    STATIC_EVIDENCE = "static_evidence"
    CROSS_MODULE_TRACE = "cross_module_trace"
    TEST_BACKED = "test_backed"
    REPRODUCED = "reproduced"
    INCONCLUSIVE = "inconclusive"
    NOT_VERIFIED = "not_verified"


class EvidenceKind(str, Enum):
    SOURCE_RANGE = "source_range"
    CALL_TRACE = "call_trace"
    DATA_FLOW = "data_flow"
    CONFIG_VALUE = "config_value"
    MANIFEST = "manifest"
    EXTERNAL = "external"
    HEURISTIC = "heuristic"


class EdgeKind(str, Enum):
    IMPORTS = "imports"
    CALLS = "calls"
    IMPLEMENTS = "implements"
    INHERITS = "inherits"
    READS = "reads"
    WRITES = "writes"
    TRANSFORMS = "transforms"
    VALIDATES = "validates"
    AUTHORIZES = "authorizes"
    SENDS_DATA_TO = "sends_data_to"
    DEPENDS_ON = "depends_on"
    CONFIGURES = "configures"
    REGISTERS = "registers"
    HANDLES_EVENT = "handles_event"
    STARTS_TASK = "starts_task"
    AWAITS_TASK = "awaits_task"
    OPENS_RESOURCE = "opens_resource"
    CLOSES_RESOURCE = "closes_resource"
    TESTS = "tests"
    INFLUENCES = "influences"


class RelationOrigin(str, Enum):
    """How confident we are that an edge is real."""

    STATIC_DIRECT = "static_direct"
    TYPE_RESOLVED = "type_resolved"
    INFERRED = "inferred"
    RUNTIME = "runtime"
    UNRESOLVED = "unresolved"


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SupportLevel(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    TEXT_ONLY = "text_only"
    UNSUPPORTED = "unsupported"


# --------------------------------------------------------------------------- scan config


class ResourceLimits(Base):
    max_files: int = Field(default=20_000, ge=1, le=1_000_000)
    max_file_bytes: int = Field(default=2_000_000, ge=1)
    max_total_bytes: int = Field(default=512_000_000, ge=1)
    max_symbols: int = Field(default=400_000, ge=1)
    max_findings: int = Field(default=5_000, ge=1)
    max_seconds: float = Field(default=600.0, gt=0)
    max_call_graph_depth: int = Field(default=12, ge=1, le=64)
    max_visit_steps: int = Field(default=200_000, ge=1_000)
    max_workers: int = Field(default=8, ge=1, le=64)
    max_trace_steps: int = Field(default=6_000, ge=10)


class ScanRequest(Base):
    """The single normalized scan request used by CLI *and* MCP."""

    repository: str = Field(min_length=1, max_length=2_048)
    profile: Profile = Profile.STANDARD
    checks: tuple[Check, ...] = ()
    cross_module: bool = False
    report_format: str = Field(default="json", max_length=32)
    emit_report: bool = True
    include_evidence: bool = True
    include_execution_paths: bool = True
    limits: ResourceLimits = Field(default_factory=ResourceLimits)
    allowed_roots: tuple[str, ...] = ()
    allow_remote: bool = True
    allow_private_repositories: bool = False
    use_cache: bool = True
    offline: bool = False
    scanner_version: str = Field(default=__version__, max_length=64)

    @field_validator("repository")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("repository must not be blank")
        return v

    @field_validator("checks", mode="before")
    @classmethod
    def _coerce_checks(cls, v: Any) -> Any:
        if v is None:
            return ()
        if isinstance(v, str):
            return (v,)
        return tuple(v)

    @field_validator("report_format")
    @classmethod
    def _norm_format(cls, v: str) -> str:
        return v.strip().lower()

    def cache_key_material(self) -> str:
        payload = "|".join(
            [
                self.repository,
                self.profile.value,
                ",".join(sorted(c.value for c in self.checks)),
                str(self.cross_module),
                str(self.include_evidence),
                str(self.include_execution_paths),
                self.scanner_version,
                ",".join(str(getattr(self.limits, f)) for f in ResourceLimits.model_fields),
            ]
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- graph


class Symbol(Base):
    id: str
    name: str
    kind: str
    file: str
    language: str = "unknown"
    parent: str | None = None
    start_line: int = 0
    end_line: int = 0
    signature: str = ""
    docstring: str = ""
    decorators: tuple[str, ...] = ()
    bases: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()
    exported: bool = True


class Edge(Base):
    src: str
    dst: str
    kind: EdgeKind
    origin: RelationOrigin = RelationOrigin.STATIC_DIRECT
    file: str = ""
    line: int = 0
    label: str = ""


class CallSite(Base):
    caller_id: str
    callee_name: str
    file: str
    line: int
    resolved_id: str | None = None
    reason: str = ""


class FileRecord(Base):
    path: str
    language: str = "unknown"
    support: SupportLevel = SupportLevel.TEXT_ONLY
    size: int = 0
    lines: int = 0
    is_generated: bool = False
    is_test: bool = False
    is_vendored: bool = False
    is_binary: bool = False
    read_error: str = ""


# --------------------------------------------------------------------------- evidence


class Evidence(Base):
    kind: EvidenceKind
    file: str
    start_line: int = 0
    end_line: int = 0
    symbol: str = ""
    snippet: str = ""
    note: str = ""
    # Proven/inferred provenance for graph-ish evidence
    origin: RelationOrigin | None = None


class TraceStep(Base):
    node: str
    label: str
    kind: str
    file: str = ""
    line: int = 0
    unresolved: bool = False
    note: str = ""


# --------------------------------------------------------------------------- findings


class Finding(Base):
    finding_id: str = ""
    title: str
    category: str
    rule_id: str = ""
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.LOW
    verification_status: VerificationStatus = VerificationStatus.STATIC_EVIDENCE
    summary: str = ""
    technical_explanation: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    affected_symbols: list[str] = Field(default_factory=list)
    call_chains: list[list[str]] = Field(default_factory=list)
    data_flows: list[list[str]] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    analysis_method: str = ""
    analyzer_version: str = __version__
    language: str = "unknown"
    suppressed: bool = False
    suppression_reason: str = ""
    confidence_rationale: str = ""
    fingerprint: str = ""

    def ensure_id(self) -> str:
        """Derive a stable fingerprint and id from the finding's own content.

        The fingerprint pins *where* the finding lives (rule + title + first
        evidence location) so the same rule reported on a different line is a
        different finding; the id pins the fingerprint so repeated scans of an
        unchanged file produce the same id.
        """
        if not self.fingerprint:
            anchor = self.evidence[0] if self.evidence else None
            # The end line and the symbol name belong here because the same
            # rule fires on the same start line in many similar helpers, and
            # file:start_line alone is not enough to tell those findings apart.
            location = (
                f"{anchor.file}:{anchor.start_line}-{anchor.end_line}:{anchor.symbol}"
                if anchor is not None
                else ""
            )
            base = "|".join([self.rule_id or self.category, self.title, location])
            self.fingerprint = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
        if not self.finding_id:
            key = "|".join([self.rule_id or self.category, self.fingerprint, self.title])
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
            self.finding_id = f"{self.rule_id or 'FND'}-{digest}"
        return self.finding_id


# --------------------------------------------------------------------------- coverage/report


class StageRecord(Base):
    name: str
    status: StageStatus = StageStatus.PENDING
    seconds: float = 0.0
    detail: str = ""
    error: str = ""


class LanguageRecord(Base):
    language: str
    support: SupportLevel
    files: int = 0
    lines: int = 0
    analyzers: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class CoverageRecord(Base):
    files_total: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    bytes_read: int = 0
    symbols: int = 0
    edges: int = 0
    unresolved_calls: int = 0
    languages: list[LanguageRecord] = Field(default_factory=list)
    exclusions: dict[str, str] = Field(default_factory=dict)
    unsupported_features: list[str] = Field(default_factory=list)
    truncated: bool = False
    notes: list[str] = Field(default_factory=list)


class DependencyRecord(Base):
    ecosystem: str
    manifest: str
    packages: list[str] = Field(default_factory=list)
    vulnerability_check: str = Field(default="not_performed")
    note: str = ""


class ScanWarning(Base):
    stage: str
    message: str
    # Machine-readable failure code when the warning records an error, so callers
    # (CLI exit status, MCP envelopes) do not have to parse the message text.
    code: str = ""


class ScanReport(Base):
    schema_version: str = REPORT_SCHEMA_VERSION
    tool: str = TOOL_NAME
    tool_version: str = __version__
    scan_id: str
    status: str = "completed"
    source_kind: SourceKind = SourceKind.LOCAL
    repository: str = ""
    repository_name: str = ""
    revision: str = ""
    workspace_root: str = ""
    started_at: str = Field(default_factory=utcnow)
    finished_at: str = ""
    duration_seconds: float = 0.0
    request: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] = Field(default_factory=dict)
    languages: list[LanguageRecord] = Field(default_factory=list)
    components: list[dict[str, Any]] = Field(default_factory=list)
    entry_points: list[dict[str, Any]] = Field(default_factory=list)
    stages: list[StageRecord] = Field(default_factory=list)
    coverage: CoverageRecord = Field(default_factory=CoverageRecord)
    dependencies: list[DependencyRecord] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    traces: dict[str, list[list[str]]] = Field(default_factory=dict)
    graph_snapshot: dict[str, Any] = Field(default_factory=dict)
    warnings: list[ScanWarning] = Field(default_factory=list)
    errors: list[ScanWarning] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    remediation_summary: list[str] = Field(default_factory=list)
    from_cache: bool = False
    partial: bool = False

    def finalize(self) -> "ScanReport":
        sev: dict[str, int] = {}
        cat: dict[str, int] = {}
        for f in self.findings:
            # Every category seen is reported, even when every finding in it was
            # suppressed, so a reader can tell "checked, nothing found" apart
            # from "not checked".
            cat.setdefault(f.category, 0)
            if f.suppressed:
                continue
            sev[f.severity.value] = sev.get(f.severity.value, 0) + 1
            cat[f.category] += 1
        self.findings_by_severity = {k: sev[k] for k in sorted(sev, key=lambda s: -Severity.parse(s).rank)}
        self.findings_by_category = dict(sorted(cat.items()))
        # Suppressed findings are listed last: they were seen and judged, not
        # silently dropped, so a reader should still be able to find them.
        self.findings.sort(key=lambda f: (f.suppressed, -f.severity.rank, -f.confidence.rank, f.title))
        return self


class Page(Base):
    """Paginated slice of a collection (used by MCP + CLI report show)."""

    items: list[Any]
    total: int
    offset: int
    limit: int
    next_offset: int | None = None

    @model_validator(mode="after")
    def _derive_next_offset(self) -> "Page":
        if self.next_offset is None:
            consumed = self.offset + len(self.items)
            if consumed < self.total:
                self.next_offset = consumed
        return self
