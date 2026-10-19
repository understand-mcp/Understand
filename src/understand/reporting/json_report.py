"""Deterministic, redacted JSON rendering for :class:`ScanReport` objects.

The JSON document is the machine-readable contract of UNDERSTAND.  Stability
rules applied here:

* keys are emitted in a fixed order (model declaration order), not sorted
  arbitrarily, so diffs between two runs of the same scanner are meaningful;
* evidence snippets are redacted and truncated before serialisation;
* timestamps and durations come from the report itself, never from ``now()``,
  so rendering the same report twice yields byte-identical output.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import ScanReport
from ..security.redaction import redact_obj, redact_snippet

__all__ = [
    "render_json",
    "report_to_dict",
    "write_json",
]

# Keys that hold free-form source text and therefore must be redacted and
# truncated before they leave the process.
_SNIPPET_KEYS = ("snippet", "note", "summary", "technical_explanation")


def _redact_finding(finding: Any, *, redact: bool = True) -> dict[str, Any]:
    data = finding.model_dump(mode="json") if hasattr(finding, "model_dump") else dict(finding)
    if not redact:
        return data
    evidence = []
    for item in data.get("evidence") or []:
        item = dict(item)
        snippet = item.get("snippet")
        if snippet:
            item["snippet"] = redact_snippet(str(snippet))
        evidence.append(item)
    if evidence:
        data["evidence"] = evidence
    for key in _SNIPPET_KEYS:
        value = data.get(key)
        if isinstance(value, str) and value:
            data[key] = redact_snippet(value, limit=4000)
    return data


def report_to_dict(report: ScanReport, *, redact: bool = True) -> dict[str, Any]:
    """Convert a report into plain JSON-compatible structures."""

    data = report.model_dump(mode="json")
    data["findings"] = [_redact_finding(f, redact=redact) for f in report.findings]
    if redact:
        data = redact_obj(data)
    return data


def render_json(report: ScanReport, *, pretty: bool = True, redact: bool = True) -> str:
    """Serialise ``report`` to JSON text.

    ``pretty=False`` produces a single compact line, suitable for piping into
    ``jq`` or for embedding in an MCP tool result.
    """

    data = report_to_dict(report, redact=redact)
    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False, default=str)
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=False, default=str)


def write_json(report: ScanReport, path: Path, *, pretty: bool = True, redact: bool = True) -> Path:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        render_json(report, pretty=pretty, redact=redact) + "\n",
        encoding="utf-8",
    )
    return target
