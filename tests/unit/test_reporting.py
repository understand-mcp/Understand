"""Unit tests for report rendering (json / text / sarif) and output-path safety."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from understand.errors import UnsupportedFormatError
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    ScanReport,
    ScanWarning,
    Severity,
    VerificationStatus,
)
from understand.reporting import (
    normalize_format,
    render_report,
    safe_output_path,
    write_report,
)
from understand.reporting.json_report import render_json
from understand.reporting.sarif_report import render_sarif
from understand.reporting.text_report import render_text

SECRET = "AKIAIOSFODNN7EXAMPLE"


def _report() -> ScanReport:
    report = ScanReport(
        scan_id="scan-report-1",
        repository="/tmp/repo",
        repository_name="repo",
        revision="deadbeef",
        source_kind="local",
        status="completed",
        duration_seconds=1.25,
        warnings=[ScanWarning(stage="inventory", message="skipped binary file")],
        errors=[],
    )
    report.findings = [
        Finding(
            title="Shell injection in handle_ping",
            category="security",
            rule_id="SEC-PY-SHELL-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.STATIC_EVIDENCE,
            language="python",
            summary="Untrusted host reaches subprocess.call with shell=True.",
            remediation="Use a fixed argument list and avoid shell=True.",
            evidence=[
                Evidence(
                    kind=EvidenceKind.SOURCE_RANGE,
                    file="app/api.py",
                    start_line=7,
                    end_line=11,
                    symbol="app.api.handle_ping",
                    snippet=f'os.system("ping " + host)  # key="{SECRET}"',
                )
            ],
        ),
        Finding(
            title="Assignment in condition",
            category="bugs",
            rule_id="BUG-CMP-001",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.INCONCLUSIVE,
            language="python",
        ),
    ]
    report.finalize()
    return report


def test_normalize_format_accepts_aliases() -> None:
    assert normalize_format("JSON") == "json"
    assert normalize_format(" sarif ") == "sarif"
    assert normalize_format("text") == "text"


def test_normalize_format_rejects_unknown() -> None:
    with pytest.raises(UnsupportedFormatError):
        normalize_format("pdf")
    with pytest.raises(UnsupportedFormatError):
        normalize_format("")


def test_render_json_is_deterministic() -> None:
    first = render_json(_report())
    second = render_json(_report())
    assert first == second
    payload = json.loads(first)
    assert payload["schema_version"]
    assert payload["scan_id"] == "scan-report-1"
    assert len(payload["findings"]) == 2


def test_render_json_redacts_secrets() -> None:
    payload = json.loads(render_json(_report(), redact=True))
    assert SECRET not in payload["findings"][0]["evidence"][0]["snippet"]
    assert "[REDACTED]" in payload["findings"][0]["evidence"][0]["snippet"]


def test_render_json_without_redaction_keeps_content() -> None:
    payload = json.loads(render_json(_report(), redact=False))
    assert SECRET in payload["findings"][0]["evidence"][0]["snippet"]


def test_render_text_contains_findings_and_limits() -> None:
    text = render_text(_report(), color=False)
    assert "scan-report-1" in text
    assert "SEC-PY-SHELL-001" in text
    assert "app/api.py" in text
    assert "Limitations" in text


def test_render_text_respects_max_findings() -> None:
    text = render_text(_report(), max_findings=1, color=False)
    assert "BUG-CMP-001" not in text
    assert "SEC-PY-SHELL-001" in text


def test_render_text_honours_no_color() -> None:
    assert "\x1b[" not in render_text(_report(), color=False)


def test_render_sarif_shape() -> None:
    doc = json.loads(render_sarif(_report()))
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert doc["runs"][0]["tool"]["driver"]["name"] == "UNDERSTAND"
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    critical = next(r for r in results if r["ruleId"] == "SEC-PY-SHELL-001")
    assert critical["level"] == "error"
    assert critical["partialFingerprints"]["understandFingerprint/v1"]
    location = critical["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "app/api.py"
    assert location["region"]["startLine"] == 7


def test_render_sarif_severity_levels() -> None:
    doc = json.loads(render_sarif(_report()))
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["SEC-PY-SHELL-001"] == "error"
    assert levels["BUG-CMP-001"] == "note"


def test_render_sarif_carries_warnings() -> None:
    doc = json.loads(render_sarif(_report()))
    # SARIF 2.1.0 puts toolExecutionNotifications on the invocation; the run
    # object has no such property and adding one fails schema validation.
    invocation = doc["runs"][0]["invocations"][0]
    notifications = invocation.get("toolExecutionNotifications", [])
    assert notifications
    assert "toolExecutionNotifications" not in doc["runs"][0]


def test_render_report_dispatch() -> None:
    assert json.loads(render_report(_report(), "json"))["scan_id"] == "scan-report-1"
    assert "UNDERSTAND" in render_report(_report(), "text", color=False) or "scan-report-1" in render_report(_report(), "text", color=False)
    assert json.loads(render_report(_report(), "sarif"))["version"] == "2.1.0"


def test_render_report_rejects_unknown_format() -> None:
    with pytest.raises(UnsupportedFormatError):
        render_report(_report(), "xml")


def test_write_report_to_file(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    write_report(_report(), "json", target)
    assert json.loads(target.read_text(encoding="utf-8"))["scan_id"] == "scan-report-1"


def test_write_report_returns_stdout_when_no_path() -> None:
    assert json.loads(write_report(_report(), "json"))["scan_id"] == "scan-report-1"


def test_safe_output_path_accepts_plain_name(tmp_path: Path) -> None:
    resolved = safe_output_path(tmp_path / "report.json", fmt="json")
    assert resolved.name == "report.json"


def test_safe_output_path_rejects_traversal() -> None:
    with pytest.raises(Exception):
        safe_output_path("../escape.json", fmt="json")
    with pytest.raises(Exception):
        safe_output_path("/tmp/../etc/passwd", fmt="json")


def test_safe_output_path_rejects_protected_dirs() -> None:
    with pytest.raises(Exception):
        safe_output_path("/etc/understand.json", fmt="json")


def test_safe_output_path_rejects_extension_mismatch(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        safe_output_path(tmp_path / "report.txt", fmt="sarif")


def test_safe_output_path_rejects_hostile_names(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        safe_output_path(tmp_path / "CON.json", fmt="json")
    with pytest.raises(Exception):
        safe_output_path(tmp_path / "report.json.", fmt="json")


def test_safe_output_path_rejects_directory(tmp_path: Path) -> None:
    target = tmp_path / "adir.json"
    target.mkdir()
    with pytest.raises(Exception):
        safe_output_path(target, fmt="json")


def test_safe_output_path_rejects_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        link.symlink_to(real)
    except OSError:  # pragma: no cover - Windows without developer mode
        pytest.skip("symlinks unavailable")
    with pytest.raises(Exception):
        safe_output_path(link, fmt="json")


def test_report_payload_from_service_includes_findings(session_config, risky_scan_id) -> None:
    from understand.application import FindingService, ReportService, ScanService

    with ScanService(session_config) as service:
        report = service.report(risky_scan_id)
        page = FindingService(service.store).query_report(report, limit=5)
        payload = ReportService(service.store).payload(report, findings=page)
    assert payload["scan_id"] == risky_scan_id
    assert payload["findings"]
    assert payload["coverage"]
    assert payload["request"]


def test_report_payload_strips_evidence(session_config, risky_scan_id) -> None:
    from understand.application import ReportService, ScanService

    with ScanService(session_config) as service:
        report = service.report(risky_scan_id)
        payload = ReportService(service.store).payload(
            report, include_evidence=False, findings=None
        )
    assert "evidence" not in (payload["findings"][0] if payload["findings"] else {})


def test_checks_are_documented_in_capabilities() -> None:
    from understand.cli import capabilities_document

    document = capabilities_document()
    assert Check.SECURITY.value in document["checks"]
    assert document["llm_required"] is False
    assert document["telemetry"] is False