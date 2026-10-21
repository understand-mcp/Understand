"""Paste-ready report blocks and the one-time thank-you note.

Nothing here opens a socket, sends telemetry or records anything about the
machine it runs on. The only state is a single flag in
``~/.understand/state.json`` that records that the thank-you line has already
been shown, so it is shown once and then never again.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from understand.models import Finding, ScanReport, Severity

PROJECT_URL = "https://github.com/understand-mcp/Understand"
INSTALL_HINT = "pip install understand-mcp"

THANKS_TEXT = (
    "If UNDERSTAND saved you time, a star helps other people find it:\n"
    f"  {PROJECT_URL}"
)

#: Severities in the order a reader cares about them.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: How many findings the share block quotes. Three is enough to be useful and
#: few enough that the block stays readable in a chat window.
TOP_FINDINGS = 3


# --------------------------------------------------------------------------- #
# Local state
# --------------------------------------------------------------------------- #
def state_dir() -> Path:
    """The directory the tool already owns for local state."""
    return Path.home() / ".understand"


def state_path() -> Path:
    return state_dir() / "state.json"


def _load_state(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_state(path: Path, data: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        # The note is a courtesy. If the flag cannot be written the note may
        # appear again later, which is not worth failing a scan over.
        return


def thanks_enabled() -> bool:
    """Honour the opt-out switch."""
    raw = os.environ.get("UNDERSTAND_NO_THANKS", "").strip().lower()
    return raw not in {"1", "true", "yes", "on"}


def thanks_already_shown(path: Path | None = None) -> bool:
    target = path or state_path()
    return bool(_load_state(target).get("thanks_shown"))


def maybe_thanks(path: Path | None = None) -> str | None:
    """Return the thank-you note the first time only, then nothing."""
    if not thanks_enabled():
        return None
    target = path or state_path()
    if thanks_already_shown(target):
        return None
    state = _load_state(target)
    state["thanks_shown"] = True
    _save_state(target, state)
    return THANKS_TEXT


# --------------------------------------------------------------------------- #
# Share blocks
# --------------------------------------------------------------------------- #
def _severity_counts(report: ScanReport) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in report.findings:
        if finding.suppressed:
            continue
        name = str(finding.severity.value)
        counts[name] = counts.get(name, 0) + 1
    return counts


def _location(finding: Finding) -> str:
    if not finding.evidence:
        return ""
    anchor = finding.evidence[0]
    if anchor.start_line:
        return f"{anchor.file}:{anchor.start_line}"
    return anchor.file


def _top_findings(report: ScanReport) -> list[Finding]:
    live = [finding for finding in report.findings if not finding.suppressed]
    criticals = [finding for finding in live if finding.severity == Severity.CRITICAL]
    if criticals:
        return criticals[:TOP_FINDINGS]
    highs = [finding for finding in live if finding.severity == Severity.HIGH]
    return highs[:TOP_FINDINGS]


def share_payload(report: ScanReport) -> dict[str, Any]:
    """The share block as data, for the JSON form and for tests."""
    counts = _severity_counts(report)
    return {
        "tool": "UNDERSTAND",
        "scan_id": report.scan_id,
        "repository": report.repository_name or report.repository,
        "files_analyzed": report.coverage.files_analyzed,
        "files_total": report.coverage.files_total,
        "findings_total": sum(counts.values()),
        "findings_by_severity": {name: counts[name] for name in SEVERITY_ORDER if counts.get(name)},
        "top_findings": [
            {
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "severity": str(finding.severity.value),
                "title": finding.title,
                "location": _location(finding),
            }
            for finding in _top_findings(report)
        ],
        "install": INSTALL_HINT,
        "project": PROJECT_URL,
    }


def share_text(report: ScanReport) -> str:
    """A paste-ready plain-text block."""
    counts = _severity_counts(report)
    total = sum(counts.values())
    breakdown = ", ".join(f"{name} {counts[name]}" for name in SEVERITY_ORDER if counts.get(name))
    lines = [
        f"UNDERSTAND scan {report.scan_id}",
        f"Repository : {report.repository_name or report.repository}",
        f"Files      : {report.coverage.files_analyzed} analysed",
        f"Findings   : {total}" + (f"  ({breakdown})" if breakdown else ""),
    ]
    top = _top_findings(report)
    if top:
        lines.append("")
        lines.append("Top findings")
        for finding in top:
            rule = finding.rule_id or finding.category
            location = _location(finding)
            lines.append(f"  {rule}  {location}  {finding.title}")
    lines.append("")
    lines.append(f"Scanned with: {INSTALL_HINT}")
    lines.append(f"Report      : {PROJECT_URL}")
    return "\n".join(lines)


def share_markdown(report: ScanReport) -> str:
    """A paste-ready Markdown block."""
    payload = share_payload(report)
    lines = [
        f"**UNDERSTAND** scanned `{payload['repository']}`"
        f" — {payload['files_analyzed']} files, {payload['findings_total']} findings.",
        "",
    ]
    severity = payload["findings_by_severity"]
    if severity:
        lines.append("| severity | count |")
        lines.append("| --- | ---: |")
        for name in SEVERITY_ORDER:
            if severity.get(name):
                lines.append(f"| {name} | {severity[name]} |")
        lines.append("")
    top = payload["top_findings"]
    if top:
        lines.append("Top findings:")
        lines.append("")
        for finding in top:
            location = finding["location"] or ""
            suffix = f" — `{location}`" if location else ""
            lines.append(f"- **{finding['rule_id']}** {finding['title']}{suffix}")
        lines.append("")
    lines.append(f"Scanned with `{INSTALL_HINT}` · {PROJECT_URL}")
    return "\n".join(lines)


def build_share(report: ScanReport, fmt: str = "text") -> str:
    """Return the share block in ``text``, ``markdown`` or ``json``."""
    key = (fmt or "text").strip().lower()
    if key in {"markdown", "md"}:
        return share_markdown(report)
    if key == "json":
        return json.dumps(share_payload(report), indent=2)
    return share_text(report)
