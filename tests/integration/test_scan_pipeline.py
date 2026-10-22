"""Integration tests: one engine behind the CLI and the MCP tool box."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from understand.application import (
    FindingService,
    ImpactService,
    ReportService,
    ScanService,
    TraceService,
)
from understand.errors import ResourceLimitExceeded, ScanNotFound, ValidationError
from understand.models import Check, Profile, ResourceLimits, ScanRequest

REQUESTS = (Check.SECURITY, Check.BUGS, Check.ARCHITECTURE, Check.RELIABILITY)


def _request(repo: str, **kwargs) -> ScanRequest:
    payload = {
        "repository": repo,
        "profile": Profile.DEEP,
        "checks": REQUESTS,
        "cross_module": True,
    }
    payload.update(kwargs)
    return ScanRequest(**payload)


# --------------------------------------------------------------------------- service


def test_scan_produces_findings_with_evidence(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        job = service.run_sync(_request(risky_repo))
    assert job.succeeded, job.error
    report = job.report
    assert report is not None
    assert report.status == "completed"
    assert report.findings
    for finding in report.findings:
        assert finding.finding_id
        assert finding.severity is not None
        assert finding.remediation or finding.impact or finding.summary
        for item in finding.evidence:
            assert item.file
            assert item.start_line >= 1


def test_findings_are_not_fabricated_on_clean_repo(minimal_repo: str, config) -> None:
    with ScanService(config) as service:
        job = service.run_sync(_request(minimal_repo))
    assert job.succeeded, job.error
    assert job.report is not None
    severities = set(job.report.findings_by_severity)
    assert not (severities - {"info"})


def test_shell_injection_is_found(risky_report) -> None:
    rule_ids = {f.rule_id for f in risky_report.findings}
    assert "SEC-PY-SHELL-001" in rule_ids
    shell = next(f for f in risky_report.findings if f.rule_id == "SEC-PY-SHELL-001")
    assert shell.severity.value in {"critical", "high"}
    assert any(e.file.endswith(".py") for e in shell.evidence)


def test_safe_invocation_forms_are_not_reported(config) -> None:
    """An argv array, an explicit shell=False and a bound clause are not injections."""
    repo = str(Path(__file__).resolve().parents[1] / "fixtures" / "repo_safe_calls")
    with ScanService(config) as service:
        job = service.run_sync(_request(repo))
    assert job.succeeded, job.error
    report = job.report
    assert report is not None
    shell_files = {
        evidence.file
        for finding in report.findings
        if finding.rule_id == "SEC-PY-SHELL-001"
        for evidence in finding.evidence
    }
    assert "app/shell_true.py" in shell_files
    assert "app/safe_calls.py" not in shell_files
    shell = next(
        finding
        for finding in report.findings
        if finding.rule_id == "SEC-PY-SHELL-001"
        and any(evidence.file.endswith("shell_true.py") for evidence in finding.evidence)
    )
    assert shell.severity.value == "critical"
    sql_files = {
        evidence.file
        for finding in report.findings
        if finding.rule_id == "SEC-SQL-001"
        for evidence in finding.evidence
    }
    assert "app/raw_query.py" in sql_files
    assert "app/bound_query.py" not in sql_files


def test_dependencies_never_invent_cves(risky_report) -> None:
    for dependency in risky_report.dependencies:
        assert dependency.vulnerability_check == "not_performed"


def test_generated_and_vendored_files_are_skipped(config) -> None:
    repo = str(Path(__file__).resolve().parents[1] / "fixtures" / "repo_mixed_content")
    with ScanService(config) as service:
        job = service.run_sync(_request(repo))
    assert job.succeeded, job.error
    coverage = job.report.coverage
    assert coverage is not None
    # files_analyzed is a count, not a list of records: what matters here is that
    # files were analysed at all while the vendored/generated trees stayed out.
    assert coverage.files_analyzed >= 1
    assert coverage.files_skipped >= 1


def test_coverage_reports_honest_numbers(risky_report) -> None:
    coverage = risky_report.coverage
    assert coverage is not None
    assert coverage.files_analyzed >= 1
    assert coverage.symbols >= 1
    assert coverage.languages


def test_language_support_is_declared(risky_report) -> None:
    by_name = {record.language: record for record in risky_report.languages}
    assert "python" in by_name
    assert by_name["python"].support in {"full", "partial", "text_only", "unsupported"}


def test_report_has_honesty_metadata(risky_report) -> None:
    assert risky_report.limitations
    assert risky_report.limits
    assert risky_report.tool_version
    assert risky_report.revision is not None


def test_scan_status_round_trip(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        job = service.run_sync(_request(risky_repo))
        status = service.status(job.scan_id)
        assert status["status"] == "completed"
        assert status["scan_id"] == job.scan_id
        assert status["terminal"] is True
        assert "finding_count" in status


def test_unknown_scan_raises(risky_repo: str, config) -> None:
    with ScanService(config) as service, pytest.raises(ScanNotFound):
        service.report("scan-does-not-exist")


def test_list_scans_is_paginated(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        service.run_sync(_request(risky_repo))
        page = service.list_scans(limit=1)
        assert page.total >= 1
        assert len(page.items) <= 1


def test_cache_second_run_is_reused(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        first = service.run_sync(_request(risky_repo), use_cache=True)
        second = service.run_sync(_request(risky_repo), use_cache=True)
    assert first.succeeded and second.succeeded
    assert second.from_cache is True
    assert second.report is not None and second.report.from_cache is True


def test_cache_disabled_always_recomputes(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        first = service.run_sync(_request(risky_repo), use_cache=False)
        second = service.run_sync(_request(risky_repo), use_cache=False)
    assert first.succeeded and second.succeeded
    assert second.from_cache is False


def test_offline_mode_skips_cache(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        service.run_sync(_request(risky_repo), use_cache=True)
        offline = service.run_sync(_request(risky_repo, offline=True), use_cache=True)
    assert offline.from_cache is False


def test_cancellation_marks_job_cancelled(risky_repo: str, config) -> None:
    with ScanService(config) as service:
        job = service.start(_request(risky_repo))
        service.cancel(job.scan_id)
        assert job.wait(60) is True
    assert job.status in {"cancelled", "completed"}


def test_cancel_unknown_scan_returns_false(config) -> None:
    with ScanService(config) as service:
        assert service.cancel("scan-unknown") is False


def test_timeout_raises_resource_limit(risky_repo: str, config) -> None:
    # A budget this small cannot be met even by a trivial scan, so the first
    # stage checkpoint always trips the limit on a fast machine too.
    limits = ResourceLimits(max_seconds=1e-6)
    with ScanService(config) as service, pytest.raises(ResourceLimitExceeded):
        service.run_sync(_request(risky_repo, limits=limits), timeout=0.2)


def test_validate_rejects_remote_when_disabled(config) -> None:
    with ScanService(config) as service, pytest.raises(ValidationError):
        service.validate(_request("https://github.com/owner/repo"))


def test_validate_rejects_empty_repository(config) -> None:
    # model_construct bypasses pydantic so the service-level guard, not the
    # model validator, is what rejects the request.
    with (
        ScanService(config) as service,
        pytest.raises(ValidationError),
    ):
        service.validate(ScanRequest.model_construct(repository=""))


def test_missing_source_fails_cleanly(config, tmp_path: Path) -> None:
    from understand.errors import InvalidSourceError

    with ScanService(config) as service:
        job = service.run_sync(_request(str(tmp_path / "nope")))
    assert not job.succeeded
    assert job.error is not None
    assert job.error["code"] in {InvalidSourceError.code, "invalid_source"}


# --------------------------------------------------------------------------- findings


def test_finding_query_filters(session_config, risky_scan_id) -> None:
    with ScanService(session_config) as service:
        findings = FindingService(service.store)
        page = findings.query(risky_scan_id, severity="critical")
        assert page.total >= 1
        for item in page.items:
            assert item["severity"] == "critical"
        by_category = findings.query(risky_scan_id, category="security", limit=100)
        assert all(i["category"] == "security" for i in by_category.items)


def test_finding_query_rejects_bad_enums(session_config, risky_scan_id) -> None:
    with ScanService(session_config) as service:
        findings = FindingService(service.store)
        with pytest.raises(ValidationError):
            findings.query(risky_scan_id, severity="catastrophic")
        with pytest.raises(ValidationError):
            findings.query(risky_scan_id, category="not-a-category")


def test_inspect_finding_returns_evidence(session_config, risky_scan_id) -> None:
    with ScanService(session_config) as service:
        findings = FindingService(service.store)
        page = findings.query(risky_scan_id, limit=1)
        finding_id = page.items[0]["finding_id"]
        detail = findings.get(finding_id)
    assert detail.finding_id == finding_id
    assert detail.evidence
    assert detail.verification_status is not None


def test_finding_stats(session_config, risky_report) -> None:
    with ScanService(session_config) as service:
        stats = FindingService(service.store).stats(risky_report)
    assert stats["total"] == len(risky_report.findings)


# --------------------------------------------------------------------------- traces


def test_trace_execution_finds_paths(risky_report) -> None:
    traces = TraceService(risky_report)
    result = traces.trace_execution("handle_ping")
    assert result["paths"]
    assert result["provenance"]["method"]


def test_trace_execution_marks_unresolved(risky_report) -> None:
    result = TraceService(risky_report).trace_execution("handle_ping")
    assert "unresolved_hops" in result
    assert isinstance(result["proven"], bool)


def test_trace_execution_unknown_symbol(risky_report) -> None:
    result = TraceService(risky_report).trace_execution("definitely_not_here")
    assert result["resolved"] is False
    assert result["paths"] == []


def test_trace_data_flow_uses_real_flows(risky_report) -> None:
    traces = TraceService(risky_report)
    flow_findings = [f for f in risky_report.findings if f.rule_id == "SEC-FLOW-001"]
    if not flow_findings:
        pytest.skip("fixture produced no flow findings")
    result = traces.trace_data_flow(finding_id=flow_findings[0].finding_id)
    assert result["flows"]
    for flow in result["flows"]:
        assert flow["hops"]


def test_trace_data_flow_unknown_finding(risky_report) -> None:
    from understand.errors import FindingNotFound

    with pytest.raises(FindingNotFound):
        TraceService(risky_report).trace_data_flow(finding_id="nope")


def test_trace_data_flow_never_invents(risky_report) -> None:
    """A source/sink query with no evidence must return nothing, not a guess."""
    result = TraceService(risky_report).trace_data_flow(
        source="never_seen_source", sink="never_seen_sink"
    )
    assert result["flows"] == []


# --------------------------------------------------------------------------- impact


def test_change_impact_finds_callers(risky_report) -> None:
    impact = ImpactService(risky_report).analyze(["app/api.py"])
    assert impact["changed_symbols"]
    assert "impacted_callers" in impact
    assert impact["provenance"]["method"]


def test_change_impact_rejects_empty_input(risky_report) -> None:
    with pytest.raises(ValidationError):
        ImpactService(risky_report).analyze([])


def test_change_impact_unknown_file(risky_report) -> None:
    result = ImpactService(risky_report).analyze(["does/not/exist.py"])
    assert result["changed_symbols"] == []
    assert result["impacted_callers"] == []


# --------------------------------------------------------------------------- reports


def test_report_service_payload_and_render(session_config, risky_scan_id) -> None:
    with ScanService(session_config) as service:
        reports = ReportService(service.store)
        report = service.report(risky_scan_id)
        page = FindingService(service.store).query_report(report, limit=5)
        payload = reports.payload(report, findings=page)
        assert payload["scan_id"] == risky_scan_id
        assert json.loads(reports.render(report, "json"))["scan_id"] == risky_scan_id
        assert reports.summary(risky_scan_id)["scan_id"] == risky_scan_id


def test_report_service_export(session_config, risky_scan_id, tmp_path: Path) -> None:
    with ScanService(session_config) as service:
        reports = ReportService(service.store)
        report = service.report(risky_scan_id)
        target = reports.export(report, "sarif", str(tmp_path / "r.sarif"))
    assert target.exists()
    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"

def test_a_write_inside_a_transaction_is_not_reported(config) -> None:
    """A write that is already atomic is not an untransacted write."""
    repo = str(Path(__file__).resolve().parents[1] / "fixtures" / "repo_safe_calls")
    with ScanService(config) as service:
        job = service.run_sync(_request(repo))
    assert job.succeeded, job.error
    report = job.report
    assert report is not None
    write_files = {
        evidence.file
        for finding in report.findings
        if finding.rule_id == "BUG-SQL-NOTX-001"
        for evidence in finding.evidence
    }
    assert "app/untransacted_write.py" in write_files
    assert "app/transacted_write.py" not in write_files

def test_a_god_module_is_reported_but_a_test_file_is_not(tmp_path, config) -> None:
    """A wide, long module is a god module; a test file is not."""
    body = "\n".join(f"def helper_{index}() -> int:\n    return {index}\n" for index in range(60))
    padding = "\n".join(f"# padding line {index}" for index in range(1200))
    module = body + "\n" + padding
    (tmp_path / "big_module.py").write_text(module, encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "big_test_file.py").write_text(module, encoding="utf-8")
    with ScanService(config) as service:
        job = service.run_sync(_request(str(tmp_path)))
    assert job.succeeded, job.error
    report = job.report
    assert report is not None
    god_modules = {
        evidence.file
        for finding in report.findings
        if finding.rule_id == "ARCH-COUPLING-001"
        for evidence in finding.evidence
    }
    assert "big_module.py" in god_modules
    assert "tests/big_test_file.py" not in god_modules
