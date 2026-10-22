"""Functional defect, logical-error and reliability analysis.

Every rule states what it proves syntactically and what still needs review. No
rule infers a defect from a name alone, and no rule claims a test is inadequate
merely because it does not match an expected template.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from understand.engine.analyzers.base import AnalysisContext
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    RelationOrigin,
    Severity,
    VerificationStatus,
)
from understand.security.redaction import redact_snippet
from understand.security.repository_policy import is_test_path


@dataclass(frozen=True)
class BugRule:
    rule_id: str
    title: str
    category: str
    pattern: re.Pattern[str]
    languages: tuple[str, ...]
    severity: Severity
    confidence: Confidence
    explanation: str
    impact: str
    remediation: str
    references: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    refine: Callable[[str, int, object], bool] | None = None
    raw_pattern: re.Pattern[str] | None = None
    skip_in_tests: bool = False


def _handler_body(module: object, lineno: int) -> list[str]:
    """Return the source lines of the block that belongs to an ``except`` header.

    The header line itself is not part of the body. A body that is empty, or
    that holds nothing but ``pass`` and comments, is the case the rules below
    are about.
    """
    lines = getattr(module, "lines", [])
    header = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
    indent = len(header) - len(header.lstrip())
    body: list[str] = []
    for raw_line in lines[lineno:]:
        if not raw_line.strip():
            body.append(raw_line)
            continue
        if len(raw_line) - len(raw_line.lstrip()) <= indent:
            break
        body.append(raw_line)
    return body


def _keep_empty_handler(raw: str, lineno: int, module: object) -> bool:
    """Keep only handlers whose body really does nothing."""
    body = [line.strip() for line in _handler_body(module, lineno) if line.strip()]
    if not body:
        return True
    return all(line == "pass" or line.startswith("#") for line in body)


def _keep_unused_binding(raw: str, lineno: int, module: object) -> bool:
    """Keep only handlers whose bound name is never referenced."""
    match = re.search(r"^\s*except\s+[A-Za-z_.]+\s+as\s+(\w+)\s*:", raw)
    if match is None:
        return True
    name = match.group(1)
    body = "\n".join(_handler_body(module, lineno))
    return not re.search(rf"\b{re.escape(name)}\b", body)


def _keep_mutated_global(raw: str, lineno: int, module: object) -> bool:
    """Keep only module level containers that are mutated somewhere else."""
    match = re.match(r"^\s*(?:const\s+)?([A-Za-z_]\w*)\s*=\s*", raw)
    if match is None:
        return True
    name = match.group(1)
    lines = getattr(module, "lines", [])
    mutator = re.compile(
        rf"\b{re.escape(name)}\s*(?:\.(?:append|update|extend|add|insert|pop|clear"
        rf"|setdefault|remove|discard|sort|reverse)\(|\+=|-=|=(?!=))"
    )
    for index, line in enumerate(lines):
        if index + 1 == lineno:
            continue
        if mutator.search(line):
            return True
    return False


def _has_decorator(ctx: AnalysisContext, sym) -> bool:
    """True when the definition carries a decorator.

    A decorated member is normally called by a framework rather than by name:
    a pydantic validator, a property, an abstract override. Calling it dead
    would be wrong, so such names are left alone.
    """
    module = ctx.index.modules.get(sym.file)
    if module is None:
        return False
    lines = getattr(module, "lines", [])
    for lineno in range(max(1, sym.start_line - 5), sym.start_line):
        if lineno <= len(lines) and lines[lineno - 1].strip().startswith("@"):
            return True
    return False


#: A ``with`` that opens a transaction.  The write statements of a scan store
#: are bracketed by one, so they are already atomic.
_TRANSACTION_CONTEXT_RE = re.compile(
    r"^\s*with\b.*(?:transaction|atomic|tx)\w*\s*\(|\bwith\b.*\.\s*begin\s*\(",
    re.I,
)

#: A transaction opened by hand: ``conn.execute("BEGIN")``.  The keyword lives
#: inside a string, so the source line is searched.
_TRANSACTION_BEGIN_RE = re.compile(r"^\s*(?:\w+\.)*execute\s*\(\s*[\"']BEGIN\b", re.I)


def _inside_transaction(module: object, lineno: int) -> bool:
    """True when the statement is bracketed by a transaction context manager.

    A write inside ``with self._transaction() as cur:`` is committed as one
    unit, so reporting it as an untransacted write is wrong.  The transaction
    can only be seen by looking upwards for the ``with`` that opens the block.
    """

    lines = getattr(module, "lines", None) or []
    index = lineno - 1
    if index < 0 or index >= len(lines):
        return False
    current_indent = len(lines[index]) - len(lines[index].lstrip())
    for back in range(index - 1, max(-1, index - 60), -1):
        line = lines[back]
        if not line.strip():
            continue
        if not (_TRANSACTION_CONTEXT_RE.match(line) or _TRANSACTION_BEGIN_RE.match(line)):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= current_indent:
            return True
    return False


def _keep_untransactioned_write(raw: str, lineno: int, module: object) -> bool:
    """False when the write already sits inside a transaction."""

    return not _inside_transaction(module, lineno)


BUG_RULES: tuple[BugRule, ...] = (
    BugRule(
        rule_id="BUG-CMP-001",
        title="Assignment used inside a conditional expression",
        category="logic-error",
        pattern=re.compile(r"\b(if|while)\s*\(\s*(?:not\s+)?[\w.$\[\]]+\s*=\s*(?![=])"),
        languages=("c", "cpp", "java", "csharp", "javascript", "typescript", "go", "php", "ruby"),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        explanation=(
            "In C-family languages and most languages with truthiness, `x = y` inside a "
            "condition is an assignment rather than a comparison. This is almost never "
            "what the author intended."
        ),
        impact="Conditions behave as stated; branches are entered unexpectedly.",
        remediation="Use `==` for comparison (or an explicit boolean expression).",
        references=("https://cwe.mitre.org/data/definitions/481.html",),
    ),
    BugRule(
        rule_id="BUG-PY-BARE-EXC-001",
        title="Bare except swallows all exceptions",
        category="error-handling",
        pattern=re.compile(r"^\s*except\s*:"),
        languages=("python",),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        explanation=(
            "A bare except catches BaseException, including KeyboardInterrupt and "
            "SystemExit, and hides genuine programming errors."
        ),
        impact="Failures are invisible; the system continues in an undefined state.",
        remediation="Catch `Exception` (or the specific exception) and log it.",
        references=("https://cwe.mitre.org/data/definitions/396.html",),
    ),
    BugRule(
        rule_id="BUG-PY-PASS-001",
        title="Exception handler does nothing",
        category="error-handling",
        pattern=re.compile(r"^\s*except[^\n:]*:\s*(?:#.*)?$"),
        languages=("python",),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        explanation="The handler body is empty (or only a comment), discarding the error context.",
        impact="Silent failure; operators lose the signal needed to diagnose incidents.",
        remediation="Log the exception or re-raise it.",
        refine=_keep_empty_handler,
    ),
    BugRule(
        rule_id="BUG-PY-EXC-VAR-001",
        title="Exception handler bound to a name but never used",
        category="error-handling",
        pattern=re.compile(r"^\s*except\s+[A-Za-z_.]+\s+as\s+(\w+)\s*:"),
        languages=("python",),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        explanation=(
            "The exception is captured into a name that is not referenced, so the failure "
            "detail is discarded."
        ),
        impact="Diagnostics are lost; bugs become harder to triage.",
        remediation="Log the variable, or drop the `as` clause.",
        refine=_keep_unused_binding,
    ),
    BugRule(
        rule_id="BUG-SHELL-UNQUOTED-001",
        title="Unquoted shell variable expansion",
        category="word-splitting",
        pattern=re.compile(r"(?<![$\w])\$[A-Za-z_][\w]*"),
        languages=("shell",),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        explanation=(
            "Unquoted expansions undergo globbing and word splitting in POSIX shells, "
            "which silently changes the argument list."
        ),
        impact="Wrong arguments, or unintended path expansion.",
        remediation="Quote expansions: \"$var\".",
        assumptions=("The variable value is not a controlled single word.",),
    ),
    BugRule(
        rule_id="BUG-JS-EQ-001",
        title="Loose equality comparison",
        category="logic-error",
        pattern=re.compile(r"[^=!<>]==[^=]|[^!]!=[^=]"),
        languages=("javascript", "typescript"),
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        explanation=(
            "== performs type coercion, so values such as '' == 0 are equal. This is "
            "rarely the intended comparison."
        ),
        impact="Unexpected branch behaviour; subtle validation bypasses.",
        remediation="Use === / !==.",
        references=("https://cwe.mitre.org/data/definitions/697.html",),
    ),
    BugRule(
        rule_id="BUG-RACE-001",
        title="Shared mutable state without an evident lock or transaction",
        category="concurrency",
        pattern=re.compile(r"^\s*(?:self|this)\.[\w.]+\s*(\+=|-=|\*=)\s*"),
        languages=("python", "javascript", "typescript", "java", "csharp", "go"),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        explanation=(
            "An instance attribute is mutated in place. If the object is shared across "
            "threads or async tasks this is a potential data race. It is only a finding "
            "when the object really is shared; most objects are not."
        ),
        impact="Non-deterministic state under concurrency.",
        remediation="Guard with a lock, use an atomic primitive, or avoid shared mutation.",
        assumptions=("The owning object is reachable from more than one execution context.",
                     "No higher-level synchronisation covers this mutation."),
        references=("https://cwe.mitre.org/data/definitions/362.html",),
    ),
    BugRule(
        rule_id="BUG-CMP-CHAIN-001",
        title="Chained comparison across typed languages",
        category="type-error",
        pattern=re.compile(r"\bif\s*\(\s*\d+\s*<=\s*[a-z_$][\w$]*\s*<=\s*\d+\s*\)"),
        languages=("c", "cpp", "java", "csharp", "go", "php", "javascript", "typescript"),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        explanation=(
            "C-family languages do not support Python-style chained comparisons; the "
            "expression is evaluated left-to-right and compared with a boolean."
        ),
        impact="The comparison does not mean what it reads like.",
        remediation="Write two explicit comparisons combined with &&.",
    ),
    BugRule(
        rule_id="BUG-PY-DEFAULT-001",
        title="Mutable default argument",
        category="state-corruption",
        pattern=re.compile(r"def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\))"),
        languages=("python",),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        explanation=(
            "A mutable default is evaluated once at definition time and shared across every "
            "call, so state leaks between invocations."
        ),
        impact="Subtle, hard-to-reproduce state corruption and memory growth.",
        remediation="Use None as the default and construct the value inside the function.",
        references=("https://docs.python.org/3/reference/datamodel.html#mutable-default-arguments",),
    ),
    BugRule(
        rule_id="BUG-GO-ERR-001",
        title="Ignored error return value",
        category="error-handling",
        pattern=re.compile(r"^\s*(?:defer\s+)?\w+(?:\.\w+)*\.(?:Write|Close|Sync|Flush|Commit|Remove|MkdirAll)\s*\("),
        languages=("go",),
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        explanation=(
            "Go requires the returned error to be handled explicitly; discarding it hides "
            "failures such as a short write or a failed commit."
        ),
        impact="Silent partial writes and inconsistent state.",
        remediation="Check the error and handle or wrap it.",
        assumptions=("The call can fail at runtime.",),
    ),
    BugRule(
        rule_id="BUG-SQL-NOTX-001",
        title="Multi-statement write without an explicit transaction",
        category="transaction",
        # The bare words INSERT/UPDATE/DELETE are not SQL on their own:
        # ``this._groupTabIds.delete(tabId)`` is a Map removal, and a case-insensitive
        # keyword match reported it as an untransacted database write. Each keyword
        # is therefore required alongside the companion word that makes it a
        # statement.
        pattern=re.compile(r"\b(?:INSERT\s+INTO|UPDATE\s+[\w.\"'`\[\]]+\s+SET|DELETE\s+FROM)\b", re.I),
        languages=("python", "javascript", "typescript", "java", "go", "csharp", "php"),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        explanation=(
            "A write statement appears without a visible transaction boundary in the same "
            "symbol. Interleaved concurrent writes can then produce partial state."
        ),
        impact="Partially applied multi-step updates under concurrency.",
        remediation="Wrap related writes in a single transaction.",
        assumptions=("The caller opens a transaction outside this symbol.",),
        refine=_keep_untransactioned_write,
        # The SQL text lives inside a string literal, and the sanitiser blanks
        # string bodies so that a keyword in a comment cannot raise a finding.
        # The write keyword is therefore looked for in the source line, while
        # the call itself is looked for in the sanitised one.
        raw_pattern=re.compile(
            r"\w+\s*\([^\n]*\b(?:INSERT\s+INTO|UPDATE\s+[\w.\"'`\[\]]+\s+SET|DELETE\s+FROM)\b",
            re.I,
        ),
        skip_in_tests=True,
    ),
    BugRule(
        rule_id="BUG-MUTABLE-GLOBAL-001",
        title="Mutable module-level state",
        category="state-corruption",
        pattern=re.compile(r"^(?!\s)(?:const\s+)?[\w.\[\]]+\s*=\s*(?:\[\]|\{|dict\(|list\(|new\s+Map|new\s+Set)"),
        languages=("javascript", "typescript", "python"),
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        explanation="Module-level mutable containers are shared process-wide.",
        impact="Cross-request or cross-test interference when mutated in place.",
        remediation="Keep mutable state per-instance or per-request.",
        refine=_keep_mutated_global,
    ),
)


class BugAnalyzer:
    name = "bugs"
    check = Check.BUGS
    applies_to = ("*",)

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, module in sorted(ctx.index.modules.items()):
            for lineno in range(1, len(module.lines) + 1):
                raw = module.line(lineno)
                text = module.dirty_lines.get(lineno, raw)
                if not raw.strip():
                    continue
                for rule in BUG_RULES:
                    if rule.languages and module.language not in rule.languages:
                        continue
                    if rule.skip_in_tests and is_test_path(path):
                        continue
                    if not rule.pattern.search(text) and not (
                        rule.raw_pattern is not None and rule.raw_pattern.search(raw)
                    ):
                        continue
                    if rule.refine is not None and not rule.refine(raw, lineno, module):
                        continue
                    symbol = _scope(ctx, path, lineno)
                    findings.append(_finding(rule, path, lineno, raw.strip(), symbol))
        findings.extend(self._resource_findings(ctx))
        findings.extend(self._dead_code_findings(ctx))
        return findings

    # ------------------------------------------------------------- resources
    def _resource_findings(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for sid, entry in (ctx.control_flow or {}).items():
            if not entry.resources_opened:
                continue
            opened_n = len(entry.resources_opened)
            closed_n = len(entry.resources_closed)
            has_try = entry.has_try
            if closed_n < opened_n and not has_try:
                sym = ctx.index.by_id.get(sid)
                if sym is None or sym.kind not in {"function", "method"}:
                    continue
                line_no = entry.resources_opened[0][0]
                snippet = ctx.index.modules[sym.file].line(line_no) if sym.file in ctx.index.modules else ""
                out.append(Finding(
                    title=f"Resource acquired in {sid.split('::')[-1]} is not released on every path",
                    category="resource-leak",
                    rule_id="BUG-RESOURCE-001",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    verification_status=VerificationStatus.STATIC_EVIDENCE,
                    summary=(
                        f"{opened_n} resource acquisition(s) and {closed_n} release(s) were "
                        "observed with no exception handling in the same function."
                    ),
                    technical_explanation=(
                        "Acquisitions and releases were counted from the function body. "
                        "Because the body contains no try/except/finally/defer construct, an "
                        "exception or early return between the two leaves the resource open. "
                        "This is a potential leak; it becomes a confirmed leak only if the "
                        "function can actually raise or return in between."
                    ),
                    evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=sym.file,
                                       start_line=line_no, end_line=entry.resources_opened[-1][0],
                                       symbol=sid.split("::")[-1],
                                       snippet=redact_snippet(snippet),
                                       note="acquisition without an exception boundary")],
                    affected_symbols=[sid],
                    assumptions=["An exception or early return can occur between acquisition and release.",
                                 "The resource is not released by a caller or context manager."],
                    preconditions=["The function raises or returns early after the acquisition."],
                    impact="File descriptor, socket or connection exhaustion over time.",
                    remediation="Use a context manager / try-with-resources / defer so release is structural.",
                    references=["https://cwe.mitre.org/data/definitions/404.html"],
                    analysis_method="control-flow resource pairing",
                    fingerprint=f"resource:{sid}",
                    confidence_rationale=f"opened={opened_n} closed={closed_n} has_try={has_try}",
                ))
        return out

    # ------------------------------------------------------------- dead code
    def _dead_code_findings(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for sym in sorted(ctx.index.by_id.values(), key=lambda s: (s.file, s.start_line)):
            if (sym.kind not in {"function", "method", "class"} or sym.exported
                    or sym.name.startswith("__") or _has_decorator(ctx, sym)):
                continue
            if ctx.index.modules[sym.file].is_usable is False:
                continue
            incoming = ctx.graph.callers(sym.id)
            if incoming:
                continue
            # referenced anywhere in an import statement, e.g. "from x import add"
            referenced = any(
                any(
                    _name_pattern(sym.name).search(statement_text or "")
                    for _raw, _line, statement_text in imports
                )
                for imports in ctx.index.imports.values()
            )
            if referenced:
                continue
            base_name = sym.file.rsplit("/", 1)[-1]
            if base_name in _ENTRY_FILE_NAMES or sym.file.startswith("tests/"):
                continue
            is_entry = any(
                e.src == f"{sym.file}::<module>" and e.kind.value == "calls"
                for e in ctx.graph.outgoing.get(f"{sym.file}::<module>", [])
            )
            if referenced or is_entry or _looks_like_entrypoint(sym):
                continue
            out.append(Finding(
                title=f"No caller found for {sym.id.split('::')[-1]}",
                category="dead-code",
                rule_id="BUG-DEAD-001",
                severity=Severity.INFO,
                confidence=Confidence.LOW,
                verification_status=VerificationStatus.INCONCLUSIVE,
                summary=f"{sym.id} is a private name with no resolved caller.",
                technical_explanation=(
                    "The call graph contains no edge into this symbol and no import references "
                    "its name. It may still be reachable through reflection, a framework "
                    "convention, a plugin registry or dynamic dispatch, which this engine "
                    "cannot see, so this is recorded as inconclusive rather than dead code."
                ),
                evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=sym.file,
                                   start_line=sym.start_line, end_line=sym.start_line,
                                   symbol=sym.id.split("::")[-1],
                                   snippet=redact_snippet(sym.signature),
                                   note="definition with no resolved caller")],
                affected_symbols=[sym.id],
                assumptions=["No dynamic dispatch, decorator registration or framework convention reaches it."],
                impact="Maintenance cost; possibly dead code.",
                remediation="Confirm reachability, then remove or annotate it.",
                analysis_method="call-graph reverse reachability",
                fingerprint=f"dead:{sym.id}",
                confidence_rationale="no resolved caller; dynamic dispatch is not modelled",
            ))
        return out[:200]


_ENTRY_HINTS = ("main", "handler", "test", "setup", "teardown", "fixture", "conftest",
                "run", "serve", "start", "app", "cli", "__init__", "index", "migrate")


#: Files whose contents are conventionally reachable from a framework.
_ENTRY_FILE_NAMES = frozenset(
    {"main.py", "__main__.py", "app.py", "manage.py", "wsgi.py", "asgi.py", "cli.py",
     "index.js", "index.ts", "main.js", "main.ts", "server.py", "handler.py", "run.py"}
)


def _name_pattern(name: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w.]){re.escape(name)}\b")


def _looks_like_entrypoint(sym) -> bool:
    name = sym.name.lower()
    return any(h in name for h in _ENTRY_HINTS)


def _scope(ctx: AnalysisContext, path: str, lineno: int) -> str:
    module = ctx.index.modules.get(path)
    if module is None:
        return ""
    best, best_span = "", 10**9
    for sym in module.symbols:
        if sym.start_line <= lineno <= sym.end_line:
            span = sym.end_line - sym.start_line
            if span < best_span:
                best, best_span = sym.id, span
    return best


def _finding(rule: BugRule, path: str, line_no: int, text: str, symbol: str) -> Finding:
    return Finding(
        title=rule.title,
        category=rule.category,
        rule_id=rule.rule_id,
        severity=rule.severity,
        confidence=rule.confidence,
        verification_status=VerificationStatus.STATIC_EVIDENCE,
        summary=rule.title,
        technical_explanation=rule.explanation,
        evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=path, start_line=line_no,
                           end_line=line_no, symbol=symbol.split("::")[-1] if symbol else "",
                           snippet=redact_snippet(text), note=f"rule {rule.rule_id}")],
        affected_symbols=[symbol] if symbol else [],
        assumptions=list(rule.assumptions),
        preconditions=list(rule.assumptions),
        impact=rule.impact,
        remediation=rule.remediation,
        references=list(rule.references),
        analysis_method="pattern rule over sanitized source lines",
        fingerprint=f"{path}:{line_no}:{rule.rule_id}",
        confidence_rationale=f"rule {rule.rule_id} matched at {path}:{line_no}",
    )


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share a rule, file and nearby line."""
    from collections import defaultdict

    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        first = f.evidence[0].file if f.evidence else ""
        buckets[(f.rule_id, first)].append(f)
    out: list[Finding] = []
    for (_rule, _file), group in buckets.items():
        group.sort(key=lambda f: f.evidence[0].start_line if f.evidence else 0)
        current: Finding | None = None
        last_line = -10_000
        for f in group:
            line = f.evidence[0].start_line if f.evidence else 0
            if current is not None and line - last_line <= 3:
                last_line = max(last_line, line)
                current.evidence.extend(f.evidence)
                if f.affected_symbols:
                    current.affected_symbols = list(dict.fromkeys(
                        current.affected_symbols + f.affected_symbols))
                continue
            current = f
            out.append(f)
    return out


__all__ = ["BUG_RULES", "BugAnalyzer", "RelationOrigin", "deduplicate"]
