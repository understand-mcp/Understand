"""Unit tests for the storage layer: schema, persistence, cache and queries."""

from __future__ import annotations

from pathlib import Path

import pytest

from understand.errors import ScanNotFound, StorageError
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Profile,
    ScanReport,
    ScanRequest,
    Severity,
    VerificationStatus,
)
from understand.storage import (
    SCHEMA_VERSION,
    ScanCache,
    ScanStore,
    digest_repository,
    digest_request,
    report_to_dict,
    restore_report,
)
from understand.storage.migrations import apply, current_version, expected_tables, table_names, verify
from understand.storage.scan_store import Where


def test_store_initialises_schema(store: ScanStore) -> None:
    conn = store._connect()
    assert current_version(conn) == SCHEMA_VERSION
    verify(conn)
    assert set(expected_tables()).issubset(set(table_names(conn)))


def test_schema_is_idempotent(store: ScanStore) -> None:
    conn = store._connect()
    apply(conn)
    apply(conn)
    assert current_version(conn) == SCHEMA_VERSION


def _report(scan_id: str = "scan-test-0001", **kwargs) -> ScanReport:
    report = ScanReport(
        scan_id=scan_id,
        repository="/tmp/repo",
        repository_name="repo",
        revision="abc123",
        source_kind="local",
        status="completed",
        **kwargs,
    )
    report.findings = [
        Finding(
            title="Shell injection in handler",
            category="security",
            rule_id="SEC-PY-SHELL-001",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.STATIC_EVIDENCE,
            language="python",
            summary="os.system with tainted input",
            evidence=[
                Evidence(
                    kind=EvidenceKind.SOURCE_RANGE,
                    file="app/api.py",
                    start_line=3,
                    end_line=5,
                    snippet="os.system(request.args['q'])",
                )
            ],
        ),
        Finding(
            title="Bare except",
            category="bugs",
            rule_id="BUG-PY-BARE-EXC-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.STATIC_EVIDENCE,
            language="python",
        ),
    ]
    report.finalize()
    return report


def test_scan_lifecycle(store: ScanStore) -> None:
    store.create_scan(
        "scan-lifecycle",
        request=ScanRequest(repository="/tmp/repo", checks=(Check.SECURITY,)),
        repository="/tmp/repo",
        repository_name="repo",
        source_kind="local",
        status="running",
    )
    assert "scan-lifecycle" in [s["scan_id"] for s in store.list_scans(limit=10).items]
    store.save_report(_report("scan-lifecycle"))
    store.update_status("scan-lifecycle", "completed")

    loaded = store.load_report("scan-lifecycle")
    assert loaded.scan_id == "scan-lifecycle"
    assert len(loaded.findings) == 2
    assert store.report_exists("scan-lifecycle")

    summary = store.scan_summary("scan-lifecycle")
    assert summary["status"] == "completed"
    assert summary["finding_count"] == 2

    assert store.delete_scan("scan-lifecycle") is True
    assert store.report_exists("scan-lifecycle") is False


def test_load_missing_scan_raises(store: ScanStore) -> None:
    with pytest.raises(ScanNotFound):
        store.load_report("does-not-exist")


def test_load_report_without_payload_raises(store: ScanStore) -> None:
    store.create_scan(
        "scan-empty",
        request=ScanRequest(repository="."),
        repository=".",
        status="running",
    )
    with pytest.raises(ScanNotFound):
        store.load_report("scan-empty")


def test_findings_round_trip_with_lowercase_enums(store: ScanStore) -> None:
    store.save_report(_report("scan-findings"))
    shell = store.query_findings("scan-findings", rule_id="SEC-PY-SHELL-001").items[0]
    finding = store.get_finding(shell.finding_id, scan_id="scan-findings")
    assert finding.finding_id == shell.finding_id
    stored = store.query_findings("scan-findings", severity="critical")
    assert stored.total == 1
    assert stored.items[0].severity == Severity.CRITICAL

    by_rule = store.query_findings("scan-findings", rule_id="BUG-PY-BARE-EXC-001")
    assert by_rule.total == 1

    by_category = store.query_findings("scan-findings", category=["security", "bugs"])
    assert by_category.total == 2

    by_file = store.query_findings("scan-findings", file="app/api.py")
    assert by_file.total == 1

    by_text = store.query_findings("scan-findings", query="shell")
    assert by_text.total == 1


def test_query_findings_paginates(store: ScanStore) -> None:
    store.save_report(_report("scan-page"))
    page = store.query_findings("scan-page", limit=1, offset=0)
    assert len(page.items) == 1
    assert page.total == 2
    assert page.next_offset == 1
    rest = store.query_findings("scan-page", limit=1, offset=1)
    assert rest.items[0].rule_id != page.items[0].rule_id


def test_report_round_trip_is_lossless(store: ScanStore) -> None:
    original = _report("scan-roundtrip", warnings=[], errors=[])
    store.save_report(original)
    restored = store.load_report("scan-roundtrip")
    assert restored.model_dump(mode="json") == original.model_dump(mode="json")


def test_report_to_dict_and_restore_without_store() -> None:
    original = _report("scan-nostore")
    restored = restore_report(report_to_dict(original))
    assert restored.scan_id == original.scan_id
    assert len(restored.findings) == len(original.findings)


def test_cache_round_trip(store: ScanStore) -> None:
    store.save_report(_report("scan-cache"))
    store.cache_store(
        root_digest="deadbeef", request_digest="cafe", scan_id="scan-cache",
        scanner_version="0.1.0",
    )
    assert store.cache_lookup("deadbeef", "cafe") == "scan-cache"
    assert store.cache_lookup("deadbeef", "other") is None
    assert store.cache_invalidate_digest("deadbeef") == 1
    assert store.cache_lookup("deadbeef", "cafe") is None


def test_meta_helpers(store: ScanStore) -> None:
    store.set_meta("k", "v")
    assert store.get_meta("k") == "v"
    assert store.get_meta("missing", "fallback") == "fallback"


def test_prune_keeps_newest(store: ScanStore) -> None:
    for index in range(5):
        store.create_scan(f"scan-p{index}", request=ScanRequest(repository="."), repository=".")
    removed = store.prune(keep=2)
    assert removed >= 3
    assert store.list_scans(limit=10).total <= 2


def test_oversized_report_is_refused(store: ScanStore, monkeypatch) -> None:
    import understand.storage.scan_store as module

    monkeypatch.setattr(module, "_MAX_REPORT_BYTES", 128)
    with pytest.raises(StorageError):
        store.save_report(_report("scan-big"))


def test_digest_repository_is_stable_and_content_sensitive(
    tmp_path: Path, risky_repo: str
) -> None:
    first, count = digest_repository(risky_repo, None)
    assert count > 0
    assert first == digest_repository(risky_repo, None)[0]

    (tmp_path / "a.txt").write_text("alpha\n", encoding="utf-8")
    before = digest_repository(tmp_path, None)[0]
    (tmp_path / "a.txt").write_text("beta\n", encoding="utf-8")
    assert digest_repository(tmp_path, None)[0] != before


def test_digest_repository_ignores_hidden_by_default(tmp_path: Path) -> None:
    (tmp_path / "keep.txt").write_text("k", encoding="utf-8")
    baseline = digest_repository(tmp_path, None)[0]
    (tmp_path / ".hidden").write_text("h", encoding="utf-8")
    assert digest_repository(tmp_path, None)[0] == baseline


def test_digest_request_is_stable() -> None:
    request = ScanRequest(repository=".", profile=Profile.DEEP, checks=(Check.SECURITY,))
    assert digest_request(request) == digest_request(request)
    other = ScanRequest(repository=".", profile=Profile.STANDARD, checks=(Check.SECURITY,))
    assert digest_request(request) != digest_request(other)


def test_scan_cache_wraps_store(store: ScanStore, risky_repo: str) -> None:
    cache = ScanCache(store, enabled=True)
    request = ScanRequest(repository=risky_repo, checks=(Check.SECURITY,))
    root_digest, request_digest = cache.compute_digests(risky_repo, request)
    lookup = cache.lookup(root_digest, request_digest)
    assert lookup.hit is False

    store.save_report(_report("scan-wrapped"))
    cache.store(
        root_digest=root_digest, request_digest=request_digest, scan_id="scan-wrapped"
    )
    assert cache.lookup(root_digest, request_digest).hit is True
    assert cache.lookup(root_digest, request_digest).scan_id == "scan-wrapped"

    assert cache.invalidate(root_digest) == 1
    assert cache.lookup(root_digest, request_digest).hit is False


def test_disabled_cache_never_hits(store: ScanStore) -> None:
    cache = ScanCache(store, enabled=False)
    root_digest, request_digest = cache.compute_digests(".", ScanRequest(repository="."))
    store.save_report(_report("scan-disabled"))
    store.cache_store(
        root_digest=root_digest, request_digest=request_digest, scan_id="scan-disabled"
    )
    assert cache.lookup(root_digest, request_digest).hit is False


def test_store_rejects_newer_schema(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "future.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE schema_info(version INTEGER)")
    conn.execute("INSERT INTO schema_info VALUES (9999)")
    conn.commit()
    conn.close()
    # __enter__ initializes, so the rejection surfaces on entry, not on the body.
    with pytest.raises(StorageError), ScanStore(path):
        pass
# --------------------------------------------------------------------------- filters
# The tool's own security rule flags ``f"SELECT ... FROM scans{clause}"`` as a
# SQL injection site. That is the right thing to point a reviewer at, and these
# tests are the answer: the clause can only ever be one of a fixed set of
# reviewed fragments, and a column nobody declared cannot be expressed at all.


def test_a_declared_column_binds_a_parameter() -> None:
    where = Where().eq("status", "completed")
    assert where.clause() == " WHERE status = ?"
    assert where.params == ["completed"]


def test_a_value_never_reaches_the_sql_text() -> None:
    hostile = "' OR 1=1 --"
    where = Where().eq("status", hostile).eq("file", hostile)
    assert hostile not in where.clause()
    assert where.params == [hostile, hostile]


def test_an_undeclared_column_is_refused() -> None:
    with pytest.raises(StorageError):
        Where().eq("report_json", "x")
    with pytest.raises(StorageError):
        Where().eq("scan_id; DROP TABLE scans", "x")


def test_a_set_filter_uses_one_placeholder_per_value() -> None:
    where = Where().one_of("severity", ["high", "critical"])
    assert where.clause() == " WHERE severity IN (?,?)"
    assert where.params == ["high", "critical"]


def test_an_empty_set_filter_adds_nothing() -> None:
    where = Where().one_of("severity", [])
    assert where.clause() == ""
    assert where.params == []


def test_a_set_filter_on_an_undeclared_column_is_refused() -> None:
    with pytest.raises(StorageError):
        Where().one_of("file", ["a.py"])


def test_a_flag_binds_nothing() -> None:
    where = Where().flag("not_suppressed")
    assert where.clause() == " WHERE suppressed = 0"
    assert where.params == []


def test_an_unknown_flag_is_refused() -> None:
    with pytest.raises(StorageError):
        Where().flag("everything")


def test_the_text_search_binds_one_pattern_per_column() -> None:
    where = Where().text_contains("%needle%")
    assert where.clause().count("LIKE ?") == 4
    assert where.params == ["%needle%"] * 4


def test_clauses_combine_in_the_order_they_were_added() -> None:
    where = Where().eq("scan_id", "s1").flag("not_suppressed").eq("rule_id", "R1")
    assert where.clause() == " WHERE scan_id = ? AND suppressed = 0 AND rule_id = ?"
    assert where.params == ["s1", "R1"]


def test_an_empty_builder_produces_no_clause() -> None:
    assert Where().clause() == ""


def test_a_hostile_filter_value_cannot_change_the_query(store: ScanStore) -> None:
    """The end-to-end proof: the hostile string is a value, not a statement."""
    page = store.query_findings("' OR 1=1 --", severity="critical")
    assert page.items == []
    assert page.total == 0
