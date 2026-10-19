"""Human readable console / file rendering of a :class:`ScanReport`.

The text renderer is intentionally terse: it is what a professional reads in a
terminal while triaging.  It never invents information -- every line is derived
from the report model.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ..models import ScanReport, Severity
from ..security.redaction import redact_snippet

__all__ = ["render_text", "supports_color", "write_text"]

_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_COLOR = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("UNDERSTAND_FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "\u2026"


def _location(finding) -> str:
    if not finding.evidence:
        return "(no evidence recorded)"
    ev = finding.evidence[0]
    if ev.start_line and ev.end_line and ev.start_line != ev.end_line:
        return f"{ev.file}:{ev.start_line}-{ev.end_line}"
    if ev.start_line:
        return f"{ev.file}:{ev.start_line}"
    return str(ev.file or "(unknown file)")


def _header(report: ScanReport) -> list[str]:
    counts = report.findings_by_severity
    total = sum(counts.values())
    lines = [
        f"{_BOLD}UNDERSTAND{_RESET} scan report",
        f"  scan id      : {report.scan_id}",
        f"  repository   : {report.repository_name or report.repository}",
        f"  revision     : {report.revision or '(not a git repository)'}",
        f"  source       : {report.source_kind.value}",
        f"  status       : {report.status}",
        f"  duration     : {report.duration_seconds:.2f}s"
        + ("  (from cache)" if report.from_cache else "")
        + ("  (PARTIAL - some stages failed)" if report.partial else ""),
        f"  findings     : {total}",
    ]
    for severity in _SEVERITY_ORDER:
        key = severity.value
        if counts.get(key):
            lines.append(f"      {key:<8} {counts[key]}")
    return lines


def _findings_block(report: ScanReport, *, max_findings: int | None, color: bool) -> list[str]:
    lines: list[str] = []
    findings = list(report.findings)
    shown = findings if max_findings is None else findings[:max_findings]
    if not shown:
        lines.append("")
        lines.append("No findings were reported. This is not a proof of correctness; see coverage and")
        lines.append("limitations below before drawing conclusions.")
        return lines

    for severity in _SEVERITY_ORDER:
        bucket = [f for f in shown if f.severity == severity]
        total = sum(1 for f in findings if f.severity == severity)
        if not bucket:
            continue
        # When the listing is truncated the per-severity count must stay the true
        # total, otherwise the header says "critical 68" and the body says
        # "critical (50)" with no explanation and the output looks wrong.
        head = f"{severity.value} ({total})" if total == len(bucket) else f"{severity.value} ({len(bucket)} of {total})"
        label = _paint(head, _COLOR[severity], color)
        lines.append("")
        lines.append(label)
        lines.append("-" * len(head))
        for finding in bucket:
            lines.append(f"  {finding.finding_id}  {finding.title}")
            lines.append(f"      rule        : {finding.rule_id or '(none)'}  [{finding.category}]")
            lines.append(f"      location    : {_location(finding)}")
            lines.append(
                f"      confidence  : {finding.confidence.value}   "
                f"verification: {finding.verification_status.value}"
            )
            if finding.summary:
                lines.append(f"      summary     : {_clip(redact_snippet(finding.summary, limit=300), 300)}")
            if finding.remediation:
                lines.append(f"      remediation : {_clip(redact_snippet(finding.remediation, limit=300), 300)}")
    if max_findings is not None and len(findings) > len(shown):
        lines.append("")
        lines.append(
            f"  ... {len(findings) - len(shown)} further findings omitted by the "
            f"--limit cap (showing {len(shown)} of {len(findings)}). "
            f"Raise --limit, or export --format json, to see every finding. "
            f"This truncation is not a clean bill of health."
        )
    return lines


def _coverage_block(report: ScanReport) -> list[str]:
    coverage = report.coverage
    if coverage is None:
        return []
    lines = [
        "",
        "Coverage",
        "-------",
        f"  files        : {coverage.files_analyzed}/{coverage.files_total} analyzed"
        f", {coverage.files_skipped} skipped, {coverage.files_failed} failed",
        f"  symbols      : {coverage.symbols}    edges: {coverage.edges}"
        f"    unresolved calls: {coverage.unresolved_calls}",
    ]
    for record in sorted(coverage.languages, key=lambda r: (-r.files, r.language)):
        lines.append(
            f"      {record.language:<16} {record.support.value:<12} "
            f"files={record.files} lines={record.lines}"
        )
    if coverage.truncated:
        lines.append("  NOTE: analysis was truncated by resource limits.")
    if coverage.exclusions:
        lines.append(f"  excluded      : {coverage.exclusions} file(s)")
    if coverage.unsupported_features:
        lines.append(f"  unsupported   : {_clip('; '.join(coverage.unsupported_features), 300)}")
    if coverage.notes:
        lines.append(f"  notes         : {_clip('; '.join(coverage.notes), 300)}")
    return lines


def _tail_block(report: ScanReport, *, max_findings: int | None) -> list[str]:
    lines: list[str] = []
    lines.append("")
    lines.append("Limitations")
    lines.append("-----------")
    for item in report.limitations:
        lines.append(f"  - {_clip(item, 400)}")
    if not report.limitations:
        lines.append("  - findings are heuristic: static evidence is not proof of exploitability")
        lines.append("  - absence of findings is not evidence of absence of defects")
        lines.append("  - only the stages that reported a status were executed")
    if report.warnings:
        lines.append("")
        lines.append(f"Warnings ({len(report.warnings)})")
        lines.append("-" * 12)
        for warning in report.warnings[:20]:
            lines.append(f"  - [{warning.stage}] {_clip(warning.message, 300)}")
        if len(report.warnings) > 20:
            lines.append(f"  ... {len(report.warnings) - 20} more warnings")
    if report.errors:
        lines.append("")
        lines.append(f"Errors ({len(report.errors)})")
        lines.append("-" * 10)
        for error in report.errors[:20]:
            lines.append(f"  - {_clip(str(error), 300)}")
    if report.dependencies:
        lines.append("")
        lines.append("Dependencies")
        lines.append("-----------")
        for dep in report.dependencies:
            lines.append(
                f"  {dep.ecosystem:<12} {len(dep.packages):>4} package(s) via {dep.manifest}"
                f"   vulnerability_check={dep.vulnerability_check}"
            )
    return lines


def render_text(
    report: ScanReport,
    *,
    max_findings: int | None = 50,
    color: bool | None = None,
) -> str:
    """Render ``report`` as plain text."""

    use_color = supports_color() if color is None else color
    if use_color:
        # Rebuild the header without embedded raw bold markers leaking through.
        lines: list[str] = []
        counts = report.findings_by_severity
        total = sum(counts.values())
        title = _paint("UNDERSTAND scan report", _BOLD, True)
        lines.append(title)
        lines.append(f"  scan id      : {report.scan_id}")
        lines.append(f"  repository   : {report.repository_name or report.repository}")
        lines.append(f"  revision     : {report.revision or '(not a git repository)'}")
        lines.append(f"  source       : {report.source_kind.value}")
        lines.append(f"  status       : {report.status}")
        lines.append(
            f"  duration     : {report.duration_seconds:.2f}s"
            + ("  (from cache)" if report.from_cache else "")
            + ("  (PARTIAL - some stages failed)" if report.partial else "")
        )
        lines.append(f"  findings     : {total}")
        for severity in _SEVERITY_ORDER:
            key = severity.value
            if counts.get(key):
                lines.append(f"      {_paint(key, _COLOR[severity], True)} {counts[key]}")
    else:
        lines = [line.replace("\033[1m", "").replace("\033[0m", "") for line in _header(report)]

    lines.extend(_findings_block(report, max_findings=max_findings, color=use_color))
    lines.extend(_coverage_block(report))
    lines.extend(_tail_block(report, max_findings=max_findings))
    return "\n".join(lines)


def write_text(report: ScanReport, path: Path, *, max_findings: int | None = 50) -> Path:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_text(report, max_findings=max_findings, color=False) + "\n", encoding="utf-8")
    return target
