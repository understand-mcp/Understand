"""Validated input schemas and machine-readable error envelopes for MCP tools.

Every MCP tool takes plain, strictly validated inputs. Nothing here reaches the
filesystem, the network, or a shell on behalf of the model: the tools only
forward typed arguments to the shared application services.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic import ValidationError as PydanticValidationError

from understand.errors import UnderstandError, ValidationError
from understand.models import Check, Profile

# Response-size ceilings for the query tools (``get_scan_report`` and
# ``query_codebase``). They are *guardrails for the caller*, not performance
# tuning: the model, not a human, decides how big a page should be, and an LLM
# that asks for 100000 findings in one call would otherwise pull a whole report
# into its context window and stall the session.
#
#   * MAX_LIMIT (500) caps ``limit``. A default of 50 is normal use; 500 is the
#     most a single response may carry. Anything larger must be paged through
#     with ``offset`` -- each page returns ``pagination.next_offset``, so no
#     result is unreachable, just not returned all at once.
#   * MAX_TEXT_QUERY (200) caps the free-text ``query`` string. A real search
#     term is a symbol name, a rule id or a phrase; 200 characters is already
#     generous, and a longer one is nearly always a pasted file, which belongs
#     in a scan rather than in a filter.
#
# Both raise the model's own error envelope (``validation_error``) when
# exceeded, so the client learns the limit instead of silently getting a
# truncated answer.
MAX_LIMIT = 500
MAX_TEXT_QUERY = 200

_LIST_FILTER_KEYS = frozenset({"severity", "verification_status", "checks"})


class Strict(BaseModel):
    """Base model: unknown keys are rejected, whitespace is stripped."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @model_validator(mode="before")
    @classmethod
    def _accept_single_string_filter(cls, data: Any) -> Any:
        """Let clients pass ``severity="high"`` instead of ``["high"]``."""

        if not isinstance(data, dict):
            return data
        widened = {
            key: ([data[key]] if isinstance(data[key], str) else data[key])
            if key in _LIST_FILTER_KEYS
            else data[key]
            for key in data
        }
        return widened

    def reject_unknown(self) -> dict[str, Any]:  # pragma: no cover - helper
        return self.model_dump(mode="json", exclude_none=True)


def _check_names() -> list[str]:
    return [check.value for check in Check]


class ScanRequestInput(Strict):
    """Input for ``scan_repository``."""

    repository: Annotated[str, Field(min_length=1, max_length=2048, description="Local directory or remote git URL.")]
    checks: Annotated[
        list[Literal["security", "bugs", "architecture", "dependencies", "reliability"]],
        Field(max_length=5, description="Checks to run. Empty means the default set."),
    ] = []
    profile: Literal["standard", "deep"] = "standard"
    cross_module: bool = False
    report_format: Literal["json", "text", "sarif"] = "json"
    include_evidence: bool = True
    include_execution_paths: bool = True
    allow_remote: bool = False
    offline: bool = False
    use_cache: bool = True
    max_files: Annotated[int, Field(ge=1, le=200_000)] | None = None
    max_file_bytes: Annotated[int, Field(ge=1, le=50_000_000)] | None = None
    max_seconds: Annotated[int, Field(ge=1, le=3_600)] | None = None
    wait: bool = Field(default=True, description="Wait for completion and return the full report.")
    timeout_seconds: Annotated[int, Field(ge=1, le=7_200)] | None = None

    @field_validator("checks")
    @classmethod
    def _dedupe(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))

    def to_checks(self) -> tuple[Check, ...]:
        return tuple(Check(name) for name in self.checks)

    def to_profile(self) -> Profile:
        return Profile.DEEP if self.profile == "deep" else Profile.STANDARD


class ReportQueryInput(Strict):
    """Input for ``get_scan_report``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]
    severity: list[Literal["critical", "high", "medium", "low", "info"]] | None = None
    category: str | None = Field(default=None, max_length=64)
    rule_id: str | None = Field(default=None, max_length=64)
    file: str | None = Field(default=None, max_length=512)
    language: str | None = Field(default=None, max_length=64)
    verification_status: (
        list[
            Literal[
                "static_evidence",
                "cross_module_trace",
                "test_backed",
                "reproduced",
                "inconclusive",
                "not_verified",
            ]
        ]
        | None
    ) = None
    query: str | None = Field(default=None, max_length=MAX_TEXT_QUERY)
    include_suppressed: bool = False
    include_stages: bool = False
    include_dependencies: bool = False
    include_evidence: bool = True
    include_execution_paths: bool = True
    limit: Annotated[int, Field(ge=1, le=MAX_LIMIT)] = 50
    offset: Annotated[int, Field(ge=0)] = 0


class FindingInput(Strict):
    """Input for ``inspect_finding``."""

    finding_id: Annotated[str, Field(min_length=1, max_length=160)]
    scan_id: str | None = Field(default=None, max_length=128)
    include_evidence: bool = True


class ExecutionTraceInput(Strict):
    """Input for ``trace_execution``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]
    symbol: Annotated[str, Field(min_length=1, max_length=400)]
    direction: Literal["downstream", "upstream", "both"] = "downstream"
    max_depth: Annotated[int, Field(ge=1, le=25)] = 6
    max_paths: Annotated[int, Field(ge=1, le=50)] = 10


class DataFlowInput(Strict):
    """Input for ``trace_data_flow``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]
    finding_id: Annotated[str, Field(min_length=1, max_length=160)] | None = None
    max_flows: Annotated[int, Field(ge=1, le=100)] = 25


class ChangeImpactInput(Strict):
    """Input for ``analyze_change_impact``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]
    changed_files: Annotated[list[str], Field(min_length=1, max_length=500)]
    max_depth: Annotated[int, Field(ge=1, le=10)] = 3

    @field_validator("changed_files")
    @classmethod
    def _clean(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip().replace("\\", "/") for item in value if item and item.strip()]
        if not cleaned:
            raise ValueError("changed_files must contain at least one non-empty path")
        return list(dict.fromkeys(cleaned))


class CodebaseQueryInput(Strict):
    """Input for ``query_codebase``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]
    query: str | None = Field(default=None, max_length=MAX_TEXT_QUERY, description="Free text over finding fields.")
    severity: list[Literal["critical", "high", "medium", "low", "info"]] | None = None
    category: str | None = Field(default=None, max_length=64)
    file: str | None = Field(default=None, max_length=512)
    language: str | None = Field(default=None, max_length=64)
    rule_id: str | None = Field(default=None, max_length=64)
    include_suppressed: bool = False
    limit: Annotated[int, Field(ge=1, le=MAX_LIMIT)] = 50
    offset: Annotated[int, Field(ge=0)] = 0


class ScanStatusInput(Strict):
    """Input for ``get_scan_status``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]


class CancelScanInput(Strict):
    """Input for ``cancel_scan``."""

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]


# --------------------------------------------------------------------------- #
# Error envelope
# --------------------------------------------------------------------------- #
def error_envelope(exc: Exception) -> dict[str, Any]:
    """Turn any exception into a stable, machine-readable error document."""

    if isinstance(exc, UnderstandError):
        payload: dict[str, Any] = exc.to_dict()
        payload["recoverable"] = exc.exit_code not in (1,)
        payload["retryable"] = exc.exit_code in (70, 74)
        return payload
    if isinstance(exc, (ValueError, TypeError)):
        return {
            "code": "invalid_input",
            "message": str(exc),
            "recoverable": True,
            "retryable": False,
            "hint": "check the tool arguments against its schema",
        }
    return {
        "code": "internal_error",
        "message": f"{type(exc).__name__}: {exc}",
        "recoverable": False,
        "retryable": False,
        "hint": "retry once; if it persists, report this scan id and the message",
    }


#: Every view the map engine can draw. Kept here rather than imported from the
#: engine so the schema module stays free of engine dependencies and the value
#: is a literal contract the client can validate against.
MAP_VIEWS: tuple[str, ...] = (
    "module",
    "call",
    "inheritance",
    "dependency",
    "test",
    "event",
    "obligation",
    "influence",
    "data_flow",
    "finding",
)


class MapQueryInput(Strict):
    """Arguments for ``get_code_map``.

    A map is a bounded projection of one stored scan. Every bound here is a
    refusal to build something a reader cannot use: a map of forty thousand
    nodes is not a map, it is a wall, and the reader learns nothing from it.
    """

    scan_id: Annotated[str, Field(min_length=1, max_length=128)]
    view: Annotated[
        Literal[
            "module",
            "call",
            "inheritance",
            "dependency",
            "test",
            "event",
            "obligation",
            "influence",
            "data_flow",
            "finding",
        ],
        Field(description="Which question the map answers."),
    ] = "module"
    root: Annotated[
        str,
        Field(
            default="",
            max_length=512,
            description=(
                "Symbol id, file, directory or `file::symbol` to centre the map on. "
                "Empty means the whole repository."
            ),
        ),
    ] = ""
    depth: Annotated[int, Field(ge=0, le=6, description="Hops from the root.")] = 3
    direction: Annotated[
        Literal["out", "in", "both"],
        Field(description="Follow callers, callees, or both."),
    ] = "both"
    kinds: list[str] | None = Field(
        default=None,
        max_length=20,
        description="Relation kinds to draw. Empty means the view's own set.",
    )
    include_findings: Annotated[
        bool,
        Field(description="Attach findings and source text to every node."),
    ] = True
    max_nodes: Annotated[int, Field(ge=10, le=20000, description="Node budget.")] = 2000
    max_edges: Annotated[int, Field(ge=10, le=60000, description="Edge budget.")] = 8000

    # The single-file HTML is opt-in for a reason: a client that wants to
    # reason about this map needs the nodes and edges as data, and 40MB of
    # markup would blow the context window of every model it was handed to.
    # Declared here rather than smuggled past the schema so a client can see
    # the cost of asking for it.
    html: Annotated[bool, Field(description="Also return the single-file HTML. Off by default.")] = False


def validate(model: type[Strict], payload: dict[str, Any]) -> Strict:
    """Validate ``payload`` against ``model``.

    Pydantic failures are re-raised as
    :class:`~understand.errors.ValidationError` so the CLI and the MCP server
    report the same stable error code for bad input.
    """

    try:
        return model.model_validate(payload)
    except PydanticValidationError as exc:
        problems = [
            {"field": ".".join(str(part) for part in err["loc"]), "problem": err["msg"], "type": err["type"]}
            for err in exc.errors()
        ]
        raise ValidationError(
            f"invalid arguments for {model.__name__}",
            detail={"problems": problems[:20]},
        ) from exc