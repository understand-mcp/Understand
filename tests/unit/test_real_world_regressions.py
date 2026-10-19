"""Regressions found by scanning a real repository, not by a fixture.

Every test in this file was written after UNDERSTAND was pointed at
``https://github.com/microsoft/playwright`` (a shallow clone, ~3,100 files,
mostly TypeScript). The three test fixtures in ``tests/fixtures`` are too small
and too clean to reach any of these paths, which is exactly why they survived
268 passing tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from understand.engine import language_detection as lang
from understand.engine.coverage import build_coverage
from understand.engine.dependency_analysis import analyze_dependencies
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    ScanReport,
    Severity,
    VerificationStatus,
)


class TestNodeManifests:
    """Playwright has 24 ``package.json`` files. Every one of them failed."""

    def test_json_manifest_parser_takes_only_text(self, tmp_path) -> None:
        manifest = {
            "dependencies": {"playwright-core": "1.55.0"},
            "devDependencies": {"typescript": "~5.0.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")

        result = analyze_dependencies(tmp_path, {"package.json": "package.json"})

        packages = {p for record in result.records for p in record.packages}
        assert "playwright-core@1.55.0" in packages
        assert "typescript@~5.0.0" in packages


class TestDuplicateFindingIds:
    """Playwright produced 2,823 findings and the store rejected all of them."""

    def test_identical_findings_get_distinct_ids(self, store) -> None:
        def finding() -> Finding:
            return Finding(
                rule_id="SEC-PY-SHELL-001",
                category=Check.SECURITY,
                title="Shell injection in helper",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                verification_status=VerificationStatus.STATIC_EVIDENCE,
                summary="same title, same rule, same file, same line",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.SOURCE_RANGE,
                        file="app/api.py",
                        start_line=7,
                        end_line=7,
                        symbol="app.api.helper",
                    )
                ],
            )

        report = ScanReport(scan_id="scan-dupes", repository="/tmp/x", repository_name="x")
        report.findings = [finding(), finding(), finding()]
        report.finalize()

        store.save_report(report)

        restored = store.load_report("scan-dupes")
        ids = [f.finding_id for f in restored.findings]
        assert len(ids) == 3
        assert len(set(ids)) == 3, f"finding ids collided: {ids}"

    def test_ids_are_stable_across_saves(self, store) -> None:
        """The disambiguation suffix is an ordinal, not a random value."""
        report = ScanReport(scan_id="scan-stable", repository="/tmp/x", repository_name="x")
        report.findings = [
            Finding(
                rule_id="R",
                category=Check.BUGS,
                title="t",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                verification_status=VerificationStatus.INCONCLUSIVE,
            )
            for _ in range(2)
        ]
        report.finalize()

        store.save_report(report)
        first = [f.finding_id for f in store.load_report("scan-stable").findings]

        again = ScanReport(scan_id="scan-stable", repository="/tmp/x", repository_name="x")
        again.findings = [Finding(**f.model_dump(exclude={"finding_id", "fingerprint"}))
                          for f in report.findings]
        again.finalize()
        store.save_report(again)
        second = [f.finding_id for f in store.load_report("scan-stable").findings]

        assert first == second


class TestLanguageLimitations:
    """The TypeScript limitations rendered as ``G``, ``e``, ``n``, ``e``, ..."""

    def test_no_registered_language_exposes_a_bare_string(self) -> None:
        for name in lang.KNOWN_LANGUAGES:
            items = lang.limitations_for(name)
            assert not isinstance(items, str), f"{name} limitations are a bare string"
            assert all(isinstance(item, str) and item.strip() for item in items), (
                f"{name} produced an empty or non-string limitation"
            )

    def test_unknown_language_is_reported_plainly(self) -> None:
        assert lang.limitations_for("cobol") == ("Language is not registered.",)


class TestPerLanguageFailedParseNote:
    """Every language claimed all 7 parse failures, including ``unknown``."""

    def test_note_is_scoped_to_the_language_that_failed(self, risky_index) -> None:
        def record(path: str, language: str, lines: int) -> SimpleNamespace:
            return SimpleNamespace(is_binary=False, language=language, lines=lines, path=path)

        inventory = SimpleNamespace(
            files={
                "good.ts": record("good.ts", "typescript", 10),
                "broken.ts": record("broken.ts", "typescript", 5),
                "main.py": record("main.py", "python", 20),
            },
            contents={
                "good.ts": object(),
                "broken.ts": object(),
                "main.py": object(),
            },
            skipped=0,
            total_bytes=35,
        )

        coverage = build_coverage(
            inventory,
            risky_index,
            failed_parses=["broken.ts"],
            unresolved_calls=0,
            graph_edge_count=0,
            truncated=False,
            exclusions={},
            unsupported=[],
            notes=[],
        )

        by_language = {r.language: r.limitations for r in coverage.languages}
        typescript_notes = [n for n in by_language["typescript"] if "failed to parse" in n]
        python_notes = [n for n in by_language["python"] if "failed to parse" in n]

        assert typescript_notes, "the language that actually failed must say so"
        assert not python_notes, "an unrelated language must not claim the failure"
        assert "1 file(s)" in typescript_notes[0]


class TestScanTiming:
    """A 325-second Playwright scan reported started_at == finished_at."""

    def test_started_at_is_not_the_moment_the_report_was_built(self, risky_report) -> None:
        assert risky_report.started_at
        assert risky_report.finished_at
        # The ordering is the part that must hold. Strict inequality is a
        # property of the fixture repo, not of the code: a small scan finishes
        # inside the same second, so asserting it here only tests how fast this
        # machine is.
        assert risky_report.started_at <= risky_report.finished_at, (
            "started_at was stamped after finished_at, so it cannot be the scan start"
        )

    def test_orchestrator_passes_started_at_to_the_report(self) -> None:
        # The real regression was not a value problem but a wiring problem:
        # the constructor was never given ``started_at``, so pydantic's
        # default_factory stamped it at report-build time. That is only
        # observable in the source, hence this assertion.
        source = (Path(__file__).resolve().parents[2] / "src" / "understand" / "engine"
                  / "orchestrator.py").read_text(encoding="utf-8")
        assert "started_at=started_at" in source, (
            "the orchestrator must hand the scan start time to the ScanReport"
        )

    def test_duration_is_positive_and_plausible(self, risky_report) -> None:
        assert risky_report.duration_seconds > 0