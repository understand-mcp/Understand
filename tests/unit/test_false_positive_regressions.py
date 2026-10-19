"""Fabricated findings found by auditing a real scan against the real source.

Every test here was written after reading the actual Playwright source lines the
tool pointed at, and finding the tool was wrong. The fixtures in
``tests/fixtures`` cannot reach these paths, which is why 276 tests passed while
the tool was reporting critical SQL injection on a Chrome browser API.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from understand.engine.data_flow import SINK_RULES, SRC_RULES
from understand.models import (
    Confidence,
    Finding,
    ScanReport,
    Severity,
    VerificationStatus,
)
from understand.reporting.text_report import render_text

DATA_FLOW = Path(__file__).resolve().parents[2] / "src" / "understand" / "engine" / "data_flow.py"


def _is_sql_sink(source: str) -> bool:
    return any(name == "sql-exec" for name, pattern, _ in SINK_RULES if pattern.search(source))


def _is_db_source(source: str) -> bool:
    return any(name == "db-read" for name, pattern, _ in SRC_RULES if pattern.search(source))


class TestHostApisAreNotDatabaseApis:
    """A browser API named ``query`` is not a database.

    Regression: scanning microsoft/playwright produced 68 critical findings, and
    ``SEC-FLOW-001`` at
    ``packages/extension/src/connectedTabGroup.ts:55`` claimed a Chrome extension's
    ``chrome.tabs.query({ groupId: g.id })`` was a critical SQL injection. That file
    is a browser tab-group manager: no database, no SQL, no string literal.
    """

    @pytest.mark.parametrize(
        "source",
        [
            "const tabsPerGroup = await Promise.all(stale.map(g => chrome.tabs.query({ groupId: g.id })));",
            "const groups = await chrome.tabGroups.query({});",
            "el.querySelector('.panel')",
            "router.query.url",
            "map.raw(new Uint8Array(4))",
            "queue.execute();",
        ],
    )
    def test_host_api_calls_are_not_sql(self, source: str) -> None:
        assert not _is_sql_sink(source)
        assert not _is_db_source(source)

    @pytest.mark.parametrize(
        "source",
        [
            "cursor.execute(sql, params)",
            "db.query('SELECT * FROM users WHERE id = ?', [id])",
            "conn.raw(`DELETE FROM t WHERE id = ${x}`)",
            "client.query('INSERT INTO t VALUES (?)', v)",
            "this._conn.run(`DELETE FROM ${TABLE} WHERE run_id NOT IN (SELECT 1)`)",
        ],
    )
    def test_real_sql_is_still_detected(self, source: str) -> None:
        assert _is_sql_sink(source)

    def test_a_flow_needs_at_least_one_hop(self) -> None:
        """A source and a sink on one expression is one regex matching twice.

        The flow builder emitted those, which is how a single line produced a
        "data from X reaches X" critical finding with no propagation at all.
        """
        body = DATA_FLOW.read_text(encoding="utf-8")
        assert "if not chain:" in body, "empty-chain flows must be dropped"


class TestBareSqlKeywordsAreNotSql:
    """``Map.delete()`` is not a database write.

    Regression: ``BUG-SQL-NOTX-001`` matched ``\\b(?:INSERT|UPDATE|DELETE)\\b``
    case-insensitively, so ``this._groupTabIds.delete(tabId);`` in a Chrome
    extension was reported as an untransacted database write. Four such findings
    were attributed to one browser file, and the ``transaction`` category was the
    single largest in the whole Playwright scan.
    """

    @staticmethod
    def _pattern() -> re.Pattern[str]:
        from understand.engine.analyzers.bug_analysis import BUG_RULES

        rule = next(r for r in BUG_RULES if r.rule_id == "BUG-SQL-NOTX-001")
        return rule.pattern

    @pytest.mark.parametrize(
        "source",
        [
            "this._groupTabIds.delete(tabId);",
            "await chrome.tabGroups.update(id, style);",
            "map.delete(key)",
            "array.insert(0, item)",
            "set.add(value)",
        ],
    )
    def test_non_sql_calls_are_not_sql_writes(self, source: str) -> None:
        assert not self._pattern().search(source)

    @pytest.mark.parametrize(
        "source",
        [
            "await conn.run(`DELETE FROM runs WHERE id = ${x}`)",
            "conn.query('UPDATE users SET name = $1 WHERE id = $2')",
            "db.execute('INSERT INTO runs (id) VALUES (?)')",
        ],
    )
    def test_real_sql_statements_still_match(self, source: str) -> None:
        assert self._pattern().search(source)


class TestTruncatedTextReportIsNotACleanBillOfHealth:
    """A truncated listing that looks complete is worse than no listing."""

    @staticmethod
    def _report(count: int) -> ScanReport:
        report = ScanReport(scan_id="scan-trunc", repository="/tmp/repo")
        report.findings = [
            Finding(
                title=f"finding {index}",
                category="bugs",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                verification_status=VerificationStatus.STATIC_EVIDENCE,
            )
            for index in range(count)
        ]
        report.finalize()
        return report

    def test_severity_header_shows_the_true_total(self) -> None:
        # "critical (5)" would read as if only five critical findings existed.
        assert "critical (5 of 68)" in render_text(self._report(68), max_findings=5)

    def test_untruncated_severity_header_is_unqualified(self) -> None:
        text = render_text(self._report(3), max_findings=50)
        assert "critical (3)" in text
        assert "of 3)" not in text

    def test_omission_count_is_explicit(self) -> None:
        text = render_text(self._report(68), max_findings=5)
        assert "63 further findings omitted" in text
        assert "not a clean bill of health" in text