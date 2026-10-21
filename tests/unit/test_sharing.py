"""Tests for the shareable report block and the one-time thank-you note."""

from __future__ import annotations

import json
from pathlib import Path

from understand.models import (
    CoverageRecord,
    Evidence,
    EvidenceKind,
    Finding,
    ScanReport,
    Severity,
)
from understand.sharing import (
    PROJECT_URL,
    build_share,
    maybe_thanks,
    share_markdown,
    share_payload,
    share_text,
    thanks_already_shown,
    thanks_enabled,
)


def _report() -> ScanReport:
    return ScanReport(
        scan_id="scan-test-0001",
        repository="example/project",
        repository_name="example/project",
        coverage=CoverageRecord(files_analyzed=12, files_total=14),
        findings=[
            Finding(
                finding_id="SEC-SQL-001-abc123",
                title="SQL built from a request parameter",
                category="security",
                rule_id="SEC-SQL-001",
                severity=Severity.CRITICAL,
                evidence=[
                    Evidence(
                        kind=EvidenceKind.SOURCE_RANGE,
                        file="app/db.py",
                        start_line=9,
                        end_line=9,
                        symbol="query",
                    )
                ],
            ),
            Finding(
                finding_id="BUG-PY-PASS-001-def456",
                title="A function body is only a pass",
                category="bugs",
                rule_id="BUG-PY-PASS-001",
                severity=Severity.LOW,
            ),
        ],
    )


def test_share_text_names_the_scan_the_counts_and_the_top_finding() -> None:
    block = share_text(_report())

    assert "scan-test-0001" in block
    assert "example/project" in block
    assert "12 analysed" in block
    assert "critical 1" in block
    assert "low 1" in block
    assert "SEC-SQL-001" in block
    assert "app/db.py:9" in block
    assert PROJECT_URL in block


def test_share_text_ignores_suppressed_findings() -> None:
    report = _report()
    report.findings[0].suppressed = True

    block = share_text(report)

    assert "critical 0" not in block
    assert "critical" not in block


def test_share_markdown_has_a_severity_table_and_the_finding() -> None:
    block = share_markdown(_report())

    assert "| severity | count |" in block
    assert "| critical | 1 |" in block
    assert "**SEC-SQL-001**" in block
    assert "`app/db.py:9`" in block


def test_share_payload_is_the_machine_readable_form() -> None:
    payload = share_payload(_report())

    assert payload["scan_id"] == "scan-test-0001"
    assert payload["files_analyzed"] == 12
    assert payload["findings_total"] == 2
    assert payload["findings_by_severity"] == {"critical": 1, "low": 1}
    assert payload["top_findings"][0]["location"] == "app/db.py:9"
    assert payload["project"] == PROJECT_URL


def test_build_share_dispatches_on_the_format() -> None:
    report = _report()

    assert build_share(report, "text") == share_text(report)
    assert build_share(report, "markdown") == share_markdown(report)
    assert json.loads(build_share(report, "json"))["scan_id"] == "scan-test-0001"


def test_the_thank_you_note_is_shown_once(tmp_path: Path) -> None:
    state = tmp_path / "state.json"

    first = maybe_thanks(state)
    second = maybe_thanks(state)

    assert first is not None
    assert PROJECT_URL in first
    assert second is None
    assert thanks_already_shown(state) is True


def test_the_thank_you_note_can_be_switched_off(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("UNDERSTAND_NO_THANKS", "1")

    assert thanks_enabled() is False
    assert maybe_thanks(tmp_path / "state.json") is None
    assert thanks_already_shown(tmp_path / "state.json") is False
