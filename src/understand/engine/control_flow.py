"""Control-flow extraction: branches, loops, early returns, async constructs.

This is *not* a path-explosion engine. It extracts the structural facts a
security review needs and explicitly records when full path coverage is not
claimed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from understand.engine.symbol_index import SymbolIndex
from understand.models import Edge, EdgeKind, RelationOrigin

BRANCH_RE = re.compile(r"\b(?:if|elif|else\s+if|switch|case|match|when|unless)\b")
LOOP_RE = re.compile(r"\b(?:for|while|forEach|foreach|loop|do)\b")
RETURN_RE = re.compile(r"\breturn\b")
THROW_RE = re.compile(r"\b(?:throw|raise|panic|fatal|abort)\b")
TRY_RE = re.compile(r"\b(?:try|catch|except|finally|recover|rescue|ensure|defer)\b")
EARLY_RETURN_RE = re.compile(r"\breturn\b")

TASK_START_RE = re.compile(
    r"\b(?:asyncio\.create_task|asyncio\.gather|ensure_future|threading\.Thread|"
    r"new\s+Thread|Process\.start|go\s+func|spawn\(|Promise\.|asyncio\.run|"
    r"gevent|celery\.task|@app\.task|BackgroundTasks?\.add|setTimeout|setInterval)\b")
TASK_AWAIT_RE = re.compile(r"\b(?:await|asyncio\.await|\.then\(|join\(|WaitGroup|\.get\(\)|\.result\(\))\b")
LOCK_RE = re.compile(r"\b(?:Lock\(|RLock\(|Mutex|synchronized|semaphore|Semaphore|atomic|with\s+\w*lock|acquire\s*\(|transaction|begin\(\)|BEGIN\b)")
TRANSACTION_RE = re.compile(r"\b(?:transaction|BEGIN|COMMIT|ROLLBACK|atomic\(\)|withTransaction|savepoint)\b", re.I)
# The trailing ``\b`` belongs to the word alternatives only.  Applying it to the
# whole group meant ``open(`` had to be followed by a word character, so
# ``open("settings.json")`` -- the ordinary spelling -- never matched and only
# ``open(someIdentifier`` did.  Resource-lifetime edges were therefore missing
# every resource opened by a literal, which is most of them.
RESOURCE_OPEN_RE = re.compile(
    r"(?<![\w.])(?:io\.Open\b|os\.Open\b|createReadStream\b|fs\.open\b|getConnection\b|"
    r"requests\.Session\b|new\s+(?:FileInputStream|FileReader|Pool|Client)\b|"
    r"Popen\s*\(|open\s*\(|connect\s*\(|acquire\s*\()")
# A definition line names a function; it does not open a resource. Without this
# guard ``def open(self)`` and ``def acquire(self)`` were counted as resource
# acquisitions, and every class with such a method looked like a leak.
_DEFINITION_RE = re.compile(r"^\s*(?:async\s+def|def|class|function)\b")
RESOURCE_CLOSE_RE = re.compile(
    r"\b(?:defer\s+\w*\.Close|with\s+open|using\s)"
    r"|\.?\b(?:close|end|release|shutdown|Dispose)\s*\(\)")


@dataclass
class ControlFlowFacts:
    symbol_id: str
    file: str
    start_line: int
    end_line: int
    branches: int = 0
    loops: int = 0
    returns: int = 0
    throws: int = 0
    has_try: bool = False
    early_returns: list[int] = field(default_factory=list)
    starts_tasks: list[tuple[int, str]] = field(default_factory=list)
    awaits_tasks: list[tuple[int, str]] = field(default_factory=list)
    shared_state: list[tuple[int, str]] = field(default_factory=list)
    transactions: list[tuple[int, str]] = field(default_factory=list)
    resources_opened: list[tuple[int, str]] = field(default_factory=list)
    resources_closed: list[tuple[int, str]] = field(default_factory=list)
    path_coverage_claimed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "symbol": self.symbol_id, "file": self.file,
            "start_line": self.start_line, "end_line": self.end_line,
            "branches": self.branches, "loops": self.loops, "returns": self.returns,
            "throws": self.throws, "has_try": self.has_try,
            "early_returns": self.early_returns,
            "starts_tasks": self.starts_tasks, "awaits_tasks": self.awaits_tasks,
            "shared_state": self.shared_state, "transactions": self.transactions,
            "resources_opened": self.resources_opened, "resources_closed": self.resources_closed,
            "path_coverage_claimed": self.path_coverage_claimed,
        }


def extract_control_flow(index: SymbolIndex) -> dict[str, ControlFlowFacts]:
    facts: dict[str, ControlFlowFacts] = {}
    for sid, sym in index.by_id.items():
        if sym.kind not in {"function", "method", "module"}:
            continue
        module = index.modules.get(sym.file)
        if module is None:
            continue
        entry = ControlFlowFacts(sid, sym.file, sym.start_line, sym.end_line)
        for lineno in range(sym.start_line, min(sym.end_line, sym.start_line + 600) + 1):
            text = module.dirty_lines.get(lineno, module.line(lineno))
            if not text.strip():
                continue
            if BRANCH_RE.search(text):
                entry.branches += 1
            if LOOP_RE.search(text):
                entry.loops += 1
            if RETURN_RE.search(text):
                entry.returns += 1
                entry.early_returns.append(lineno)
            if THROW_RE.search(text):
                entry.throws += 1
            if TRY_RE.search(text):
                entry.has_try = True
            m = TASK_START_RE.search(text)
            if m:
                entry.starts_tasks.append((lineno, m.group(0)))
            m = TASK_AWAIT_RE.search(text)
            if m:
                entry.awaits_tasks.append((lineno, m.group(0)))
            if LOCK_RE.search(text):
                entry.shared_state.append((lineno, text.strip()[:120]))
            if TRANSACTION_RE.search(text):
                entry.transactions.append((lineno, text.strip()[:120]))
            m = RESOURCE_OPEN_RE.search(text)
            if m and not _DEFINITION_RE.match(text):
                entry.resources_opened.append((lineno, m.group(0)))
            m = RESOURCE_CLOSE_RE.search(text)
            if m:
                entry.resources_closed.append((lineno, m.group(0)))
        facts[sid] = entry
    return facts


def concurrency_edges(index: SymbolIndex, graph) -> list[Edge]:
    """Edges describing task creation and awaiting relationships."""
    edges: list[Edge] = []
    facts = extract_control_flow(index)
    for sid, entry in facts.items():
        for lineno, token in entry.starts_tasks:
            edges.append(Edge(src=sid, dst=f"{entry.file}:{lineno}", kind=EdgeKind.STARTS_TASK,
                              origin=RelationOrigin.INFERRED, file=entry.file, line=lineno,
                              label=f"starts async work: {token}"))
        for lineno, token in entry.awaits_tasks:
            edges.append(Edge(src=sid, dst=f"{entry.file}:{lineno}", kind=EdgeKind.AWAITS_TASK,
                              origin=RelationOrigin.INFERRED, file=entry.file, line=lineno,
                              label=f"awaits: {token}"))
        for lineno, token in entry.transactions:
            edges.append(Edge(src=sid, dst=f"{entry.file}:{lineno}", kind=EdgeKind.CONFIGURES,
                              origin=RelationOrigin.INFERRED, file=entry.file, line=lineno,
                              label=f"transaction boundary: {token[:60]}"))
    return edges


def build_control_flow(index: SymbolIndex, graph) -> dict[str, ControlFlowFacts]:
    return extract_control_flow(index)
