"""Schema definition and forward-only migrations for the UNDERSTAND scan store.

The schema is intentionally small and boring: scan records, findings, stage
records and a content-addressed cache table.  Migrations are ordered and
applied inside a transaction; unknown future versions are rejected rather than
silently downgraded.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from ..errors import StorageError

#: Current schema version understood by this build.
SCHEMA_VERSION = 4


# Each migration is (version, tuple_of_statements).  Never edit a shipped
# migration -- append a new one instead.
MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        1,
        (
            """
            CREATE TABLE IF NOT EXISTS schema_info (
                version INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id      TEXT PRIMARY KEY,
                created_at   TEXT NOT NULL,
                finished_at  TEXT NOT NULL DEFAULT '',
                status       TEXT NOT NULL,
                source_kind  TEXT NOT NULL DEFAULT 'local',
                repository   TEXT NOT NULL,
                repository_name TEXT NOT NULL DEFAULT '',
                revision     TEXT NOT NULL DEFAULT '',
                root_digest  TEXT NOT NULL DEFAULT '',
                tool_version TEXT NOT NULL DEFAULT '',
                finding_count INTEGER NOT NULL DEFAULT 0,
                report_json  TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_scans_repo ON scans(repository_name)",
        ),
    ),
    (
        2,
        (
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id    TEXT NOT NULL,
                scan_id       TEXT NOT NULL,
                rule_id       TEXT NOT NULL DEFAULT '',
                category      TEXT NOT NULL DEFAULT '',
                severity      TEXT NOT NULL DEFAULT 'info',
                confidence    TEXT NOT NULL DEFAULT 'low',
                verification  TEXT NOT NULL DEFAULT 'static_evidence',
                language      TEXT NOT NULL DEFAULT 'unknown',
                title         TEXT NOT NULL DEFAULT '',
                file          TEXT NOT NULL DEFAULT '',
                start_line    INTEGER NOT NULL DEFAULT 0,
                end_line      INTEGER NOT NULL DEFAULT 0,
                symbol        TEXT NOT NULL DEFAULT '',
                fingerprint   TEXT NOT NULL DEFAULT '',
                suppressed    INTEGER NOT NULL DEFAULT 0,
                evidence_json TEXT NOT NULL DEFAULT '{}',
                payload_json  TEXT NOT NULL,
                PRIMARY KEY (scan_id, finding_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(scan_id, severity)",
            "CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(scan_id, rule_id)",
        ),
    ),
    (
        3,
        (
            """
            CREATE TABLE IF NOT EXISTS stages (
                scan_id TEXT NOT NULL,
                name    TEXT NOT NULL,
                status  TEXT NOT NULL,
                seconds REAL NOT NULL DEFAULT 0.0,
                detail  TEXT NOT NULL DEFAULT '',
                error   TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (scan_id, name)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scan_cache (
                cache_key     TEXT PRIMARY KEY,
                scan_id       TEXT NOT NULL,
                created_at    TEXT NOT NULL,
                root_digest   TEXT NOT NULL,
                scanner_version TEXT NOT NULL,
                request_digest TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_cache_digest ON scan_cache(root_digest)",
        ),
    ),
    (
        4,
        (
            "CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(scan_id, file)",
            """
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """,
        ),
    ),
)


def current_version(conn: sqlite3.Connection) -> int:
    """Return the schema version of an already-open connection (0 when empty)."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_info'"
    ).fetchone()
    if row is None:
        return 0
    row = conn.execute("SELECT MAX(version) FROM schema_info").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def apply(conn: sqlite3.Connection, target: int = SCHEMA_VERSION) -> int:
    """Apply pending migrations in order.  Returns the resulting version."""
    version = current_version(conn)
    if version > target:
        raise StorageError(
            f"scan store schema version {version} is newer than this build supports ({target}); "
            "upgrade understand or point storage_path at a fresh database"
        )
    for step, statements in MIGRATIONS:
        if step <= version:
            continue
        try:
            conn.execute("BEGIN")
            for statement in statements:
                conn.execute(statement)
            conn.execute("DELETE FROM schema_info")
            conn.execute("INSERT INTO schema_info(version) VALUES (?)", (step,))
            conn.commit()
        except sqlite3.Error as exc:  # pragma: no cover - defensive
            conn.rollback()
            raise StorageError(f"failed to apply schema migration {step}: {exc}") from exc
        version = step
    return version


def table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {str(r[0]) for r in rows}


def expected_tables() -> set[str]:
    return {"schema_info", "scans", "findings", "stages", "scan_cache", "meta"}


def verify(conn: sqlite3.Connection) -> None:
    """Raise if the schema is not the one this build expects."""
    missing = expected_tables() - table_names(conn)
    if missing:
        raise StorageError(f"scan store is missing tables: {', '.join(sorted(missing))}")


def statements() -> Sequence[str]:
    """All statements across all migrations -- used by tests and docs."""
    return [s for _, group in MIGRATIONS for s in group]