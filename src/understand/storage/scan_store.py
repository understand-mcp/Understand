"""SQLite-backed persistence for scan reports, findings, stages and caches.

Design notes
------------
* One connection guarded by a re-entrant lock; SQLite is opened with
  ``check_same_thread=False`` so a background scan worker and the CLI/MCP
  request thread can share one :class:`ScanStore`.
* Reports are stored as canonical JSON (the full report) *and* denormalised into
  ``scans`` / ``findings`` / ``stages`` rows so listing and filtering stay cheap
  without a separate search index.
* Secrets are *not* redacted at rest -- redaction is a rendering concern and is
  applied by :mod:`understand.reporting`.  Storing the raw report keeps evidence
  intact for the tool that needs it.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..errors import FindingNotFound, ScanNotFound, StorageError
from ..models import (
    CoverageRecord,
    DependencyRecord,
    Evidence,
    Finding,
    LanguageRecord,
    Page,
    ResourceLimits,
    ScanReport,
    ScanRequest,
    ScanWarning,
    Severity,
    StageRecord,
    utcnow,
)
from . import migrations
from .migrations import SCHEMA_VERSION

_MAX_REPORT_BYTES = 64 * 1024 * 1024


def _enum_value(value: object) -> str:
    """Store enums by their wire value (e.g. critical), never Severity.CRITICAL."""

    return str(getattr(value, "value", value))


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


#: The only column names a caller may filter on, and the SQL fragment each one
#: is allowed to produce.  A filter that is not in this table cannot be
#: expressed at all, which is what makes the generated statements safe by
#: construction rather than safe by convention: a caller's text never reaches
#: the query, only a key it must already own.
_FILTER_SQL: dict[str, str] = {
    "scan_id": "scan_id = ?",
    "status": "status = ?",
    "repository_name": "repository_name = ?",
    "rule_id": "rule_id = ?",
    "file": "file = ?",
    "language": "language = ?",
}

#: Columns a filter may list several values for.
_SET_COLUMNS = frozenset({"severity", "category", "verification"})

#: Predicates that bind no parameter, so they cannot carry user input at all.
_FLAG_SQL: dict[str, str] = {
    "not_suppressed": "suppressed = 0",
}

#: The free-text search, kept whole rather than assembled per column so the
#: shape of the predicate is one reviewed constant rather than a loop's output.
_TEXT_SEARCH = "(title LIKE ? OR payload_json LIKE ? OR rule_id LIKE ? OR file LIKE ?)"


class Where:
    """Accumulates a ``WHERE`` clause out of reviewed fragments.

    Every fragment this builder can emit is a constant declared above. Values
    never enter the SQL text; they are bound as parameters in order. This is
    the only way the store builds a filtered query, so there is no code path
    where a filter name or a value is interpolated.
    """

    def __init__(self) -> None:
        self._parts: list[str] = []
        self._params: list[Any] = []

    def eq(self, column: str, value: object) -> Where:
        """Bind one value against one whitelisted column."""
        fragment = _FILTER_SQL.get(column)
        if fragment is None:
            raise StorageError(f"{column!r} is not a filterable column")
        self._parts.append(fragment)
        self._params.append(value)
        return self

    def one_of(self, column: str, values: Sequence[object]) -> Where:
        """Bind a set of values against one whitelisted column."""
        if column not in _SET_COLUMNS:
            raise StorageError(f"{column!r} is not a filterable column")
        chosen = list(values)
        if not chosen:
            return self
        placeholders = ",".join("?" * len(chosen))
        self._parts.append(f"{column} IN ({placeholders})")
        self._params.extend(chosen)
        return self

    def flag(self, name: str) -> Where:
        """Apply a predicate that takes no value."""
        fragment = _FLAG_SQL.get(name)
        if fragment is None:
            raise StorageError(f"{name!r} is not a known predicate")
        self._parts.append(fragment)
        return self

    def text_contains(self, needle: str) -> Where:
        """Apply the free-text search, binding the same pattern four times."""
        self._parts.append(_TEXT_SEARCH)
        self._params.extend([needle] * 4)
        return self

    def clause(self) -> str:
        """The ``WHERE`` clause, or an empty string when nothing was filtered."""
        return " WHERE " + " AND ".join(self._parts) if self._parts else ""

    @property
    def params(self) -> list[Any]:
        return list(self._params)


class ScanStore:
    """Persistent store for scan history and cached results."""

    def __init__(self, path: str | os.PathLike[str] | None = None, *, timeout: float = 30.0) -> None:
        self.path = Path(path).expanduser() if path is not None else Path(":memory:")
        self.timeout = timeout
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        #: Pragmas that the database refused.  They are optimisations, not
        #: requirements, so the failure is recorded instead of raised.
        self._pragma_failures: list[str] = []

    # ------------------------------------------------------------------ lifecycle

    def _connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        if str(self.path) != ":memory:":
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise StorageError(f"cannot create storage directory {self.path.parent}: {exc}") from exc
        try:
            conn = sqlite3.connect(
                str(self.path),
                timeout=self.timeout,
                isolation_level=None,
                check_same_thread=False,
            )
        except sqlite3.Error as exc:
            raise StorageError(f"cannot open scan store at {self.path}: {exc}") from exc
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error as exc:  # pragma: no cover - in-memory builds may refuse WAL
            # A PRAGMA is an optimisation, not a requirement: an in-memory or
            # read-only build may refuse it.  The store still works, so the
            # failure is recorded rather than raised.
            self._pragma_failures.append(f"PRAGMA failed: {exc}")
        self._conn = conn
        return conn

    def initialize(self) -> ScanStore:
        with self._lock:
            conn = self._connect()
            migrations.apply(conn)
            migrations.verify(conn)
        return self

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> ScanStore:
        return self.initialize()

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ helpers

    def _execute(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        conn = self._connect()
        try:
            return conn.execute(sql, tuple(params))
        except sqlite3.Error as exc:
            raise StorageError(f"scan store query failed: {exc}") from exc

    def _transaction(self):
        conn = self._connect()
        return _Transaction(conn)

    # ------------------------------------------------------------------ scans

    def create_scan(
        self,
        scan_id: str,
        *,
        request: ScanRequest | dict[str, Any],
        repository: str,
        repository_name: str = "",
        revision: str = "",
        source_kind: str = "local",
        root_digest: str = "",
        tool_version: str = "",
        status: str = "running",
    ) -> None:
        payload = request.model_dump() if isinstance(request, ScanRequest) else dict(request)
        with self._lock, self._transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO scans
                    (scan_id, created_at, finished_at, status, source_kind, repository,
                     repository_name, revision, root_digest, tool_version, finding_count, report_json)
                VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    scan_id,
                    utcnow(),
                    status,
                    str(source_kind),
                    repository,
                    repository_name,
                    revision,
                    root_digest,
                    tool_version,
                    # No report yet: keep the column non-empty but not decodable,
                    # so load_report() reports ScanNotFound instead of StorageError.
                    "",
                ),
            )
            cur.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                (f"request:{scan_id}", _json(payload)),
            )

    def update_status(self, scan_id: str, status: str) -> None:
        with self._lock:
            self._execute("UPDATE scans SET status = ? WHERE scan_id = ?", (status, scan_id))

    def _disambiguate_ids(self, report: ScanReport) -> None:
        """Make every finding id unique within one report.

        ``finding_id`` is derived from rule, title and the first evidence
        location, so two findings that share all of those (easy on a large
        codebase, where the same rule fires on many similar helpers) produce
        the same id. ``findings`` is keyed by ``(scan_id, finding_id)``, so a
        collision would fail the whole insert and lose the entire report.

        The suffix is a stable ordinal, not a random one: the report's finding
        order is fixed by ``finalize()``, so re-running the same scan produces
        the same ids. The fingerprint is left alone because it describes *what*
        was found; only the per-scan id is made unique.
        """
        seen: dict[str, int] = {}
        for finding in report.findings:
            base = finding.finding_id
            count = seen.get(base, 0)
            seen[base] = count + 1
            if count:
                finding.finding_id = f"{base}-{count + 1}"

    def save_report(self, report: ScanReport, *, root_digest: str = "") -> None:
        """Persist a finished report plus its findings and stage records."""
        for finding in report.findings:
            finding.ensure_id()
        self._disambiguate_ids(report)
        raw = report.model_dump_json()
        if len(raw.encode("utf-8")) > _MAX_REPORT_BYTES:
            raise StorageError(
                f"report for scan {report.scan_id} is larger than the storage limit "
                f"({_MAX_REPORT_BYTES} bytes); narrow the scan or raise ResourceLimits"
            )
        with self._lock, self._transaction() as cur:
            cur.execute(
                """
                INSERT OR REPLACE INTO scans
                    (scan_id, created_at, finished_at, status, source_kind, repository,
                     repository_name, revision, root_digest, tool_version, finding_count, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.scan_id,
                    report.started_at or utcnow(),
                    report.finished_at or utcnow(),
                    report.status,
                    str(report.source_kind),
                    report.repository,
                    report.repository_name,
                    report.revision,
                    root_digest,
                    report.tool_version,
                    len(report.findings),
                    raw,
                ),
            )
            cur.execute("DELETE FROM findings WHERE scan_id = ?", (report.scan_id,))
            cur.execute("DELETE FROM stages WHERE scan_id = ?", (report.scan_id,))
            cur.executemany(
                """
                INSERT INTO findings
                    (finding_id, scan_id, rule_id, category, severity, confidence, verification,
                     language, title, file, start_line, end_line, symbol, fingerprint,
                     suppressed, evidence_json, payload_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [self._finding_row(report.scan_id, f) for f in report.findings],
            )
            cur.executemany(
                "INSERT OR REPLACE INTO stages (scan_id, name, status, seconds, detail, error) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (report.scan_id, s.name, str(s.status), s.seconds, s.detail, s.error)
                    for s in report.stages
                ],
            )

    @staticmethod
    def _finding_row(scan_id: str, finding: Finding) -> tuple[Any, ...]:
        finding.ensure_id()
        first = finding.evidence[0] if finding.evidence else None
        return (
            finding.finding_id,
            scan_id,
            finding.rule_id,
            finding.category,
            _enum_value(finding.severity),
            _enum_value(finding.confidence),
            _enum_value(finding.verification_status),
            finding.language,
            finding.title,
            first.file if first else "",
            first.start_line if first else 0,
            first.end_line if first else 0,
            first.symbol if first else "",
            finding.fingerprint,
            1 if finding.suppressed else 0,
            _json([e.model_dump() for e in finding.evidence]),
            _json(finding.model_dump()),
        )

    def load_report(self, scan_id: str) -> ScanReport:
        row = self._execute(
            "SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise ScanNotFound(f"no scan with id {scan_id!r}")
        raw = row["report_json"]
        if not raw:
            raise ScanNotFound(
                f"scan {scan_id!r} has no stored report yet (it may still be running or have failed)",
                detail={"scan_id": scan_id},
            )
        try:
            return ScanReport.model_validate_json(raw)
        except Exception as exc:  # pragma: no cover - corrupted row
            raise StorageError(f"stored report for {scan_id} could not be decoded: {exc}") from exc

    def report_exists(self, scan_id: str) -> bool:
        row = self._execute("SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return row is not None

    def scan_summary(self, scan_id: str) -> dict[str, Any]:
        row = self._execute(
            """
            SELECT scan_id, created_at, finished_at, status, source_kind, repository,
                   repository_name, revision, finding_count
              FROM scans WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()
        if row is None:
            raise ScanNotFound(f"no scan with id {scan_id!r}")
        return dict(row)

    def list_scans(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        repository: str | None = None,
        status: str | None = None,
    ) -> Page:
        limit = max(1, min(int(limit), 500))
        offset = max(0, int(offset))
        where = Where()
        if repository:
            where.eq("repository_name", repository)
        if status:
            where.eq("status", status)
        where_clause = where.clause()
        params = where.params
        total = int(self._execute(f"SELECT COUNT(*) AS c FROM scans{where_clause}", params).fetchone()["c"])
        rows = self._execute(
            f"""
            SELECT scan_id, created_at, finished_at, status, source_kind, repository,
                   repository_name, revision, finding_count
              FROM scans{where_clause}
             ORDER BY created_at DESC, scan_id DESC
             LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        items = [dict(r) for r in rows]
        return Page(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
            next_offset=offset + limit if offset + limit < total else None,
        )

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock, self._transaction() as cur:
            cur.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            cur.execute("DELETE FROM stages WHERE scan_id = ?", (scan_id,))
            cur.execute("DELETE FROM scan_cache WHERE scan_id = ?", (scan_id,))
            cur.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cur.rowcount > 0

    def prune(self, keep: int = 50) -> int:
        """Drop the oldest scans beyond ``keep``.  Returns the number removed."""
        keep = max(1, int(keep))
        stale = (
            "SELECT scan_id FROM scans ORDER BY created_at DESC, scan_id DESC LIMIT -1 OFFSET ?"
        )
        with self._lock, self._transaction() as cur:
            for table in ("findings", "stages", "scan_cache", "scans"):
                cur.execute(
                    f"DELETE FROM {table} WHERE scan_id IN ({stale})",
                    (keep,),
                )
            return int(cur.rowcount)

    # ------------------------------------------------------------------ findings

    def get_finding(self, finding_id: str, *, scan_id: str | None = None) -> Finding:
        if scan_id:
            row = self._execute(
                "SELECT payload_json FROM findings WHERE scan_id = ? AND finding_id = ?",
                (scan_id, finding_id),
            ).fetchone()
        else:
            row = self._execute(
                """
                SELECT payload_json FROM findings
                 WHERE finding_id = ?
                 ORDER BY scan_id DESC LIMIT 1
                """,
                (finding_id,),
            ).fetchone()
        if row is None:
            raise FindingNotFound(f"no finding with id {finding_id!r}")
        return Finding.model_validate_json(row["payload_json"])

    def query_findings(
        self,
        scan_id: str,
        *,
        severity: str | Sequence[str] | None = None,
        category: str | Sequence[str] | None = None,
        rule_id: str | None = None,
        file: str | None = None,
        language: str | None = None,
        verification_status: str | Sequence[str] | None = None,
        query: str | None = None,
        include_suppressed: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Page:
        """Filtered, paginated findings for one scan."""
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        where = Where().eq("scan_id", scan_id)
        if not include_suppressed:
            where.flag("not_suppressed")

        def _in(column: str, value: str | Sequence[str] | None) -> None:
            if value is None:
                return
            values = [value] if isinstance(value, str) else list(value)
            where.one_of(column, [str(v).strip().lower() for v in values if str(v).strip()])

        _in("severity", severity)
        _in("category", category)
        _in("verification", verification_status)
        if rule_id:
            where.eq("rule_id", rule_id)
        if file:
            where.eq("file", file)
        if language:
            where.eq("language", language.lower())
        if query:
            where.text_contains(f"%{query}%")
        where_clause = where.clause()
        params = where.params
        total = int(self._execute(f"SELECT COUNT(*) AS c FROM findings{where_clause}", params).fetchone()["c"])
        rows = self._execute(
            f"""
            SELECT payload_json FROM findings{where_clause}
             ORDER BY
                 CASE severity
                     WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                     WHEN 'low' THEN 3 ELSE 4 END,
                 finding_id
             LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        items = [Finding.model_validate_json(r["payload_json"]) for r in rows]
        return Page(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
            next_offset=offset + limit if offset + limit < total else None,
        )

    # ------------------------------------------------------------------ cache

    def cache_lookup(self, root_digest: str, request_digest: str) -> str | None:
        """Return the cached ``scan_id`` when the digest pair still matches."""
        row = self._execute(
            """
            SELECT c.scan_id AS scan_id
              FROM scan_cache c
              JOIN scans s ON s.scan_id = c.scan_id
             WHERE c.root_digest = ? AND c.request_digest = ?
               AND s.report_json <> '{}'
             ORDER BY c.created_at DESC
             LIMIT 1
            """,
            (root_digest, request_digest),
        ).fetchone()
        return str(row["scan_id"]) if row else None

    def cache_store(
        self,
        *,
        root_digest: str,
        request_digest: str,
        scan_id: str,
        scanner_version: str = "",
    ) -> None:
        with self._lock:
            self._execute(
                """
                INSERT OR REPLACE INTO scan_cache
                    (cache_key, scan_id, created_at, root_digest, scanner_version, request_digest)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"{root_digest}:{request_digest}",
                    scan_id,
                    utcnow(),
                    root_digest,
                    scanner_version,
                    request_digest,
                ),
            )

    def cache_invalidate_digest(self, root_digest: str) -> int:
        with self._lock, self._transaction() as cur:
            cur.execute("DELETE FROM scan_cache WHERE root_digest = ?", (root_digest,))
            return int(cur.rowcount)

    def cache_clear(self) -> int:
        with self._lock, self._transaction() as cur:
            cur.execute("DELETE FROM scan_cache")
            return int(cur.rowcount)

    def cache_stats(self) -> dict[str, int]:
        scans = int(self._execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"])
        entries = int(self._execute("SELECT COUNT(*) AS c FROM scan_cache").fetchone()["c"])
        findings = int(self._execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"])
        return {"scans": scans, "cache_entries": entries, "findings": findings}

    # ------------------------------------------------------------------ meta

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value)
            )

    def get_meta(self, key: str, default: str = "") -> str:
        row = self._execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else default


class _Transaction:
    """Tiny ``with`` helper that brackets a BEGIN/COMMIT with rollback."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._cur: sqlite3.Cursor | None = None

    def __enter__(self) -> sqlite3.Cursor:
        self._conn.execute("BEGIN IMMEDIATE")
        self._cur = self._conn.cursor()
        return self._cur

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._cur is None:  # pragma: no cover - __enter__ always sets the cursor
            raise StorageError("scan store transaction ended without a cursor")
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    """Stable, JSON-safe dict for a report (used by MCP and CLI output)."""
    return json.loads(report.model_dump_json())


def restore_report(payload: dict[str, Any]) -> ScanReport:
    """Inverse of :func:`report_to_dict`; tolerant of extra keys from older builds."""
    return ScanReport.model_validate(payload)


__all__ = [
    "SCHEMA_VERSION",
    "CoverageRecord",
    "DependencyRecord",
    "Evidence",
    "LanguageRecord",
    "ResourceLimits",
    "ScanReport",
    "ScanRequest",
    "ScanStore",
    "ScanWarning",
    "Severity",
    "StageRecord",
    "migrations",
    "report_to_dict",
    "restore_report",
]
