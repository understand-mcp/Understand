"""Pluggable analyzer registry.

Adding an analyzer must never require changing the orchestrator: register a
class with a ``name``, a ``check`` and a ``run(AnalysisContext)`` method.
"""

from __future__ import annotations

from dataclasses import dataclass

from understand.engine.analyzers.architecture_analysis import ArchitectureAnalyzer
from understand.engine.analyzers.base import AnalysisContext
from understand.engine.analyzers.bug_analysis import BugAnalyzer
from understand.engine.analyzers.reliability_analysis import ReliabilityAnalyzer
from understand.engine.analyzers.security_analysis import SecurityAnalyzer
from understand.logging_config import get_logger
from understand.models import Check, Finding, ScanWarning

log = get_logger("engine.registry")

DEFAULT_CHECKS: tuple[Check, ...] = (
    Check.SECURITY,
    Check.BUGS,
    Check.ARCHITECTURE,
    Check.DEPENDENCIES,
    Check.RELIABILITY,
)

_PROFILES: dict[str, tuple[Check, ...]] = {
    "standard": DEFAULT_CHECKS,
    "security": (Check.SECURITY,),
    "bugs": (Check.BUGS, Check.RELIABILITY),
    "deep": DEFAULT_CHECKS,
}

_ANALYZER_CLASSES = (
    SecurityAnalyzer,
    BugAnalyzer,
    ArchitectureAnalyzer,
    ReliabilityAnalyzer,
)


@dataclass(frozen=True)
class AnalyzerEntry:
    name: str
    check: Check
    instance: object


class AnalyzerRegistry:
    def __init__(self) -> None:
        self._entries: list[AnalyzerEntry] = []
        for cls in _ANALYZER_CLASSES:
            inst = cls()
            self.register(inst)

    def register(self, analyzer: object) -> None:
        name = getattr(analyzer, "name", analyzer.__class__.__name__)
        check = getattr(analyzer, "check", Check.BUGS)
        self._entries = [e for e in self._entries if e.name != name]
        self._entries.append(AnalyzerEntry(name=name, check=check, instance=analyzer))

    @property
    def entries(self) -> list[AnalyzerEntry]:
        return list(self._entries)

    def names(self) -> list[str]:
        return [e.name for e in self._entries]

    def checks_for_profile(self, profile: str) -> tuple[Check, ...]:
        return _PROFILES.get(profile, DEFAULT_CHECKS)

    def run(self, ctx: AnalysisContext) -> tuple[list[Finding], list[ScanWarning]]:
        findings: list[Finding] = []
        warnings: list[ScanWarning] = []
        for entry in self._entries:
            if not ctx.wants(entry.check):
                continue
            try:
                produced = entry.instance.run(ctx)  # type: ignore[attr-defined]
            except Exception as exc:
                warnings.append(ScanWarning(stage=f"analyzer:{entry.name}",
                                           message=f"analyzer failed: {type(exc).__name__}: {exc}"))
                log.exception("analyzer %s failed", entry.name)
                continue
            for f in produced or []:
                f.analysis_method = f.analysis_method or entry.name
                f.ensure_id()
                findings.append(f)
        return findings, warnings


registry = AnalyzerRegistry()


def profile_checks(profile: str, requested: tuple[Check, ...] = ()) -> tuple[Check, ...]:
    base = registry.checks_for_profile(profile)
    if not requested:
        return base
    merged = list(dict.fromkeys([*base, *requested]))
    return tuple(merged)


__all__ = ["DEFAULT_CHECKS", "AnalysisContext", "AnalyzerRegistry", "profile_checks", "registry"]
