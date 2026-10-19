"""Unit tests for the core data model and error taxonomy."""

from __future__ import annotations

import pytest

from understand import errors, models
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Page,
    Profile,
    ResourceLimits,
    ScanRequest,
    ScanReport,
    Severity,
    VerificationStatus,
    utcnow,
)


def test_enums_use_lowercase_values() -> None:
    assert Severity.CRITICAL.value == "critical"
    assert Confidence.HIGH.value == "high"
    assert VerificationStatus.STATIC_EVIDENCE.value == "static_evidence"
    assert EvidenceKind.SOURCE_RANGE.value == "source_range"
    assert Check.SECURITY.value == "security"
    assert Profile.DEEP.value == "deep"


def test_severity_rank_is_ordered() -> None:
    ranks = [s.rank for s in Severity]
    assert ranks == sorted(ranks, reverse=True)
    assert Severity.parse("HIGH") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("not-a-severity")


def test_finding_ensure_id_is_stable() -> None:
    evidence = [Evidence(kind=EvidenceKind.SOURCE_RANGE, file="a.py", start_line=1, end_line=2)]
    first = Finding(
        title="Shell injection",
        category="security",
        rule_id="SEC-PY-SHELL-001",
        severity=Severity.CRITICAL,
        evidence=evidence,
    )
    first.ensure_id()
    second = Finding(
        title="Shell injection",
        category="security",
        rule_id="SEC-PY-SHELL-001",
        severity=Severity.CRITICAL,
        evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file="a.py", start_line=1, end_line=2)],
    )
    second.ensure_id()
    assert first.finding_id == second.finding_id
    assert first.finding_id.startswith("SEC-PY-SHELL-001-")
    assert first.fingerprint


def test_finding_ensure_id_changes_with_location() -> None:
    a = Finding(title="t", category="security", rule_id="R", severity=Severity.LOW,
                evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file="a.py", start_line=1)])
    b = Finding(title="t", category="security", rule_id="R", severity=Severity.LOW,
                evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file="a.py", start_line=9)])
    a.ensure_id()
    b.ensure_id()
    assert a.finding_id != b.finding_id


def test_scan_request_rejects_unknown_fields() -> None:
    with pytest.raises(Exception):
        ScanRequest(repository=".", nonsense=True)  # type: ignore[call-arg]


def test_scan_request_normalises_checks() -> None:
    request = ScanRequest(repository=".", checks=("security", "BUGS"), report_format="JSON")
    assert Check.SECURITY in request.checks and Check.BUGS in request.checks
    assert request.report_format == "json"


def test_cache_key_material_is_deterministic_and_sensitive() -> None:
    a = ScanRequest(repository=".", checks=(Check.SECURITY, Check.BUGS))
    b = ScanRequest(repository=".", checks=(Check.BUGS, Check.SECURITY))
    c = ScanRequest(repository=".", checks=(Check.SECURITY,), cross_module=True)
    assert a.cache_key_material() == b.cache_key_material()
    assert a.cache_key_material() != c.cache_key_material()


def test_scan_report_finalize_sorts_and_counts() -> None:
    report = ScanReport(
        scan_id="scan-1",
        repository=".",
        started_at=utcnow(),
        findings=[
            Finding(title="low", category="security", rule_id="A", severity=Severity.LOW,
                    confidence=Confidence.LOW),
            Finding(title="crit", category="security", rule_id="B", severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH),
            Finding(title="suppressed", category="bugs", rule_id="C", severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH, suppressed=True),
        ],
    )
    report.finalize()
    assert [f.title for f in report.findings] == ["crit", "low", "suppressed"]
    assert report.findings_by_severity["critical"] == 1
    assert report.findings_by_category["bugs"] == 0  # suppressed is excluded


def test_page_next_offset() -> None:
    page = Page(items=[1, 2], total=5, offset=0, limit=2)
    assert page.next_offset == 2
    last = Page(items=[5], total=5, offset=4, limit=2)
    assert last.next_offset is None


def test_resource_limits_defaults_are_positive() -> None:
    limits = ResourceLimits()
    for name, value in limits.model_dump().items():
        assert value > 0, name


@pytest.mark.parametrize(
    "cls,code",
    [
        (errors.ConfigurationError, "configuration_error"),
        (errors.InvalidSourceError, "invalid_source"),
        (errors.AccessDeniedError, "access_denied"),
        (errors.NetworkPolicyError, "network_policy"),
        (errors.AcquisitionError, "acquisition_failed"),
        (errors.ResourceLimitExceeded, "resource_limit_exceeded"),
        (errors.ScanCancelled, "scan_cancelled"),
        (errors.ScanNotFound, "scan_not_found"),
        (errors.FindingNotFound, "finding_not_found"),
        (errors.UnsupportedFormatError, "unsupported_format"),
        (errors.StorageError, "storage_error"),
        (errors.AnalysisError, "analysis_error"),
        (errors.ValidationError, "validation_error"),
    ],
)
def test_error_taxonomy(cls: type, code: str) -> None:
    error = cls("boom", detail={"k": "v"})
    payload = error.to_dict()
    assert payload["code"] == code
    assert payload["message"] == "boom"
    assert payload["detail"] == {"k": "v"}
    assert isinstance(payload["exit_code"], int)
    assert payload["exit_code"] == cls.exit_code


def test_error_taxonomy_exit_codes_are_unique() -> None:
    codes = [
        cls.exit_code
        for cls in (
            errors.ConfigurationError,
            errors.InvalidSourceError,
            errors.AccessDeniedError,
            errors.NetworkPolicyError,
            errors.AcquisitionError,
            errors.ResourceLimitExceeded,
            errors.ScanCancelled,
            errors.ScanNotFound,
            errors.FindingNotFound,
            errors.UnsupportedFormatError,
            errors.StorageError,
            errors.AnalysisError,
            errors.ValidationError,
        )
    ]
    assert len(codes) == len(set(codes))


def test_every_error_subclasses_base() -> None:
    subclasses = [
        obj
        for name in dir(errors)
        if isinstance(obj := getattr(errors, name), type)
        and issubclass(obj, errors.UnderstandError)
    ]
    # The base itself is part of the taxonomy and is used directly for generic
    # internal failures, so only the *derived* errors are asserted here.
    assert errors.UnderstandError in subclasses
    derived = [cls for cls in subclasses if cls is not errors.UnderstandError]
    assert len(derived) >= 13
    assert all(cls.__mro__[1] is errors.UnderstandError for cls in derived)


def test_models_module_exports_expected_names() -> None:
    for name in ("ScanRequest", "ScanReport", "Finding", "Evidence", "Symbol", "Edge", "Page"):
        assert hasattr(models, name)