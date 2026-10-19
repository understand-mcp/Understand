"""SARIF 2.1.0 rendering for UNDERSTAND findings.

SARIF is the interchange format understood by GitHub code scanning, Azure
DevOps, and most SAST dashboards.  The renderer maps UNDERSTAND's evidence
model onto SARIF locations and keeps the richer UNDERSTAND fields inside
``properties`` so nothing is lost.

Deliberate constraint: SARIF carries *no* invented information.  A finding whose
evidence has no file/line is still emitted, but as a SARIF result without a
location rather than as a fabricated one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import TOOL_NAME, __version__
from ..models import Evidence, Finding, ScanReport, Severity
from ..security.redaction import redact_snippet

__all__ = [
    "SARIF_SCHEMA",
    "SARIF_SCHEMA_REPOSITORY",
    "SARIF_SPEC_URL",
    "SARIF_VERSION",
    "render_sarif",
    "sarif_dict",
    "write_sarif",
]

SARIF_VERSION = "2.1.0"

# The ``$schema`` value must be a URI that actually resolves, because editors and
# CI validators fetch it to check the document.  The OASIS-published copy is the
# normative one: it is immutable, version-pinned and served from the standards
# body's own domain.  The OASIS GitHub repository is *not* usable for this: the
# project restructured its tree, so the historical
# ``oasis-tcs/sarif-spec/master/Schemata/...`` path now answers 404.
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json"
)

# Same schema, mirrored in the OASIS repository under its current path.  Kept for
# provenance only -- it tracks a moving branch, so it must never be the value
# written into ``$schema``.  Verified reachable; both URLs were checked with an
# HTTP GET on 2026-01-18.
SARIF_SCHEMA_REPOSITORY = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# Human-readable entry point for the format itself, used in the driver
# ``properties`` so a reader of the file can find the specification without
# trusting a schema fetch.
SARIF_SPEC_URL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html"

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _severity(finding: Finding) -> Severity:
    raw = finding.severity
    if isinstance(raw, Severity):
        return raw
    try:
        return Severity.parse(raw.value if hasattr(raw, "value") else str(raw))
    except ValueError:
        return Severity.INFO

# UNDERSTAND has no published home page yet.  SARIF leaves ``informationUri``
# optional, and emitting a URL that answers 404 would be a lie in every report
# we write, so it is only emitted once a real project page exists.
_TOOL_INFORMATION_URI: str | None = None


def _uri(path: str | None) -> str:
    if not path:
        return "unknown"
    return str(path).replace("\\", "/").lstrip("/")


def _rule_id(finding: Finding) -> str:
    return finding.rule_id or "UNDERSTAND-GENERIC"


def _rule_name(rule_id: str) -> str:
    parts = [p for p in rule_id.replace("_", "-").split("-") if p]
    return " ".join(parts).title() if parts else rule_id


def _location(ev: Evidence) -> dict[str, Any] | None:
    if not ev.file:
        return None
    region: dict[str, Any] = {}
    if ev.start_line and ev.start_line > 0:
        region["startLine"] = int(ev.start_line)
        if ev.end_line and int(ev.end_line) >= int(ev.start_line):
            region["endLine"] = int(ev.end_line)
    if ev.snippet:
        region["snippet"] = {"text": redact_snippet(ev.snippet)}
    physical: dict[str, Any] = {
        "artifactLocation": {"uri": _uri(ev.file), "uriBaseId": "%SRCROOT%"},
    }
    if region:
        physical["region"] = region
    return {"physicalLocation": physical}


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        rid = _rule_id(finding)
        if rid in seen:
            tags = seen[rid]["properties"].setdefault("tags", [])
            for tag in (str(finding.category), finding.language):
                if tag and tag not in tags:
                    tags.append(tag)
            continue
        seen[rid] = {
            "id": rid,
            "name": _rule_name(rid),
            "shortDescription": {"text": finding.title or rid},
            "fullDescription": {"text": finding.technical_explanation or finding.summary or finding.title or rid},
            "defaultConfiguration": {"level": _LEVELS.get(_severity(finding), "note")},
            "help": {"text": finding.remediation or "No automated remediation is available."},
            "properties": {
                "category": str(finding.category),
                "tags": [t for t in (str(finding.category), finding.language) if t],
            },
        }
    return [seen[key] for key in sorted(seen)]


def _result(finding: Finding) -> dict[str, Any]:
    locations = [loc for loc in (_location(ev) for ev in finding.evidence) if loc]
    message = finding.technical_explanation or finding.summary or finding.title or finding.finding_id
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "level": _LEVELS.get(_severity(finding), "note"),
        "message": {"text": redact_snippet(message, limit=2000) or finding.finding_id},
        "properties": {
            "findingId": finding.finding_id,
            "category": str(finding.category),
            "severity": str(finding.severity.value),
            "confidence": str(finding.confidence.value),
            "verificationStatus": str(finding.verification_status.value),
            "analysisMethod": finding.analysis_method,
            "analyzerVersion": finding.analyzer_version,
            "suppressed": bool(finding.suppressed),
        },
    }
    if locations:
        result["locations"] = locations
    fingerprint = finding.fingerprint or finding.finding_id or _rule_id(finding)
    if fingerprint:
        result["partialFingerprints"] = {"understandFingerprint/v1": fingerprint}
    if finding.impact:
        result["properties"]["impact"] = redact_snippet(finding.impact, limit=1000)
    if finding.assumptions:
        result["properties"]["assumptions"] = [
            redact_snippet(str(item), limit=400) for item in finding.assumptions
        ]
    if finding.affected_symbols:
        result["properties"]["affectedSymbols"] = list(finding.affected_symbols)
    if finding.call_chains:
        result["properties"]["callChains"] = [list(chain) for chain in finding.call_chains]
    if finding.data_flows:
        result["properties"]["dataFlows"] = [list(chain) for chain in finding.data_flows]
    return result


def sarif_dict(report: ScanReport, *, redact: bool = True) -> dict[str, Any]:
    """Build the SARIF document for ``report``."""

    findings = list(report.findings)
    notifications = [
        {
            "level": "warning",
            "message": {"text": redact_snippet(warning.message, limit=800)},
            "descriptor": {"id": f"warning/{warning.stage}"},
        }
        for warning in report.warnings
    ]
    notifications.extend(
        {
            "level": "error",
            "message": {"text": redact_snippet(str(error), limit=800)},
            "descriptor": {"id": "error/scan"},
        }
        for error in report.errors
    )
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "UNDERSTAND",
                "version": __version__,
                "semanticVersion": __version__,
                "rules": _rules(findings),
                "properties": {
                    "sarifSpecification": SARIF_SPEC_URL,
                    "sarifSchemaRepositoryCopy": SARIF_SCHEMA_REPOSITORY,
                },
            }
        },
        "automationDetails": {"id": f"{TOOL_NAME}/{report.scan_id}"},
        "invocations": [
            {
                "executionSuccessful": report.status == "completed" and not report.errors,
                "endTimeUtc": report.finished_at,
                "properties": {
                    "profile": report.request.get("profile"),
                    "crossModule": report.request.get("cross_module"),
                    "sourceKind": report.source_kind.value,
                    "revision": report.revision,
                    "partial": bool(report.partial),
                    "fromCache": bool(report.from_cache),
                },
            }
        ],
        "results": [_result(finding) for finding in findings],
    }
    if notifications:
        # SARIF 2.1.0 defines toolExecutionNotifications on an *invocation*, not
        # on the run; verified against the OASIS schema (tools/validate_sarif.py).
        run["invocations"][0]["toolExecutionNotifications"] = notifications
    if _TOOL_INFORMATION_URI:
        run["tool"]["driver"]["informationUri"] = _TOOL_INFORMATION_URI
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def render_sarif(report: ScanReport, *, pretty: bool = True, redact: bool = True) -> str:
    data = sarif_dict(report, redact=redact)
    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False, default=str)
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=False, default=str)


def write_sarif(report: ScanReport, path: Path, *, pretty: bool = True, redact: bool = True) -> Path:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_sarif(report, pretty=pretty, redact=redact) + "\n", encoding="utf-8")
    return target
