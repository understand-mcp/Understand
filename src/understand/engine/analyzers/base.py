"""Analyzer contract shared by every analysis pass."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from understand.engine.call_graph import CallGraph
from understand.engine.symbol_index import SymbolIndex
from understand.models import Check, Finding, Profile


@dataclass
class AnalysisContext:
    """Everything an analyzer may read. No hidden global state."""

    index: SymbolIndex
    graph: CallGraph
    profile: Profile
    cross_module: bool
    checks: frozenset[Check]
    deep: bool
    data_flows: list = field(default_factory=list)
    control_flow: dict = field(default_factory=dict)
    limits: object | None = None

    def wants(self, check: Check) -> bool:
        return check in self.checks


@runtime_checkable
class Analyzer(Protocol):
    name: str
    check: Check
    applies_to: tuple[str, ...]

    def run(self, ctx: AnalysisContext) -> list[Finding]:  # pragma: no cover - protocol
        ...


class BaseAnalyzer:
    name = "base"
    check = Check.BUGS
    applies_to: tuple[str, ...] = ()

    def run(self, ctx: AnalysisContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- helpers used by concrete analyzers ---------------------------------
    @staticmethod
    def symbol_name(sid: str) -> str:
        return sid.split("::", 1)[-1] if "::" in sid else sid

    @staticmethod
    def short_file(path: str) -> str:
        return path