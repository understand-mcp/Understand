"""Reliability analysis: timeouts, retries, cleanup ordering, unbounded growth."""

from __future__ import annotations

import re

from understand.engine.analyzers.base import AnalysisContext
from understand.models import (
    Check,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Severity,
    VerificationStatus,
)
from understand.security.redaction import redact_snippet

RETRY_RE = re.compile(r"\b(?:retry|retries|backoff|attempts|maxRetries|for\s+attempt\s+in)\b", re.I)
TIMEOUT_RE = re.compile(r"\b(?:timeout|timed_out|connectTimeout|readTimeout|Timeout|context\.WithTimeout)\b")
UNBOUNDED_GROWTH_RE = re.compile(r"^\s*(?:self|this)\.[\w.]+\s*\.\s*append\s*\(|^\s*\w+\.push\s*\(|^\s*list\.append\s*\(")
CLEANUP_RE = re.compile(r"\b(?:cleanup|teardown|dispose|release|close|shutdown|__del__|finalize|onClose)\b", re.I)
SLEEP_RE = re.compile(r"\b(?:time\.sleep|sleep\s*\(|Thread\.sleep|setTimeout)\s*\(")
UNHANDLED_PROMISE_RE = re.compile(r"^\s*(?:this\.)?\w+(?:\.\w+)*\s*\([^)]*\)\s*;\s*$")


class ReliabilityAnalyzer:
    name = "reliability"
    check = Check.RELIABILITY
    applies_to = ("*",)

    def run(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, module in sorted(ctx.index.modules.items()):
            for lineno in range(1, len(module.lines) + 1):
                raw = module.line(lineno)
                text = module.dirty_lines.get(lineno, raw)
                if not raw.strip():
                    continue
                symbol = self._scope(ctx, path, lineno)
                f = self._retry_without_timeout(ctx, path, lineno, raw.strip(), symbol, module)
                if f:
                    findings.append(f)
                f = self._blocking_sleep(ctx, path, lineno, raw.strip(), symbol, module)
                if f:
                    findings.append(f)
        findings.extend(self._resource_lifecycle(ctx))
        return findings

    # ------------------------------------------------------------------ rules
    def _retry_without_timeout(self, ctx, path, lineno, text, symbol, module) -> Finding | None:
        if not RETRY_RE.search(text):
            return None
        window = "\n".join(module.line(i) for i in
                           range(max(1, lineno - 25), min(len(module.lines), lineno + 25) + 1))
        if TIMEOUT_RE.search(window):
            return None
        return Finding(
            title="Retry loop without a timeout budget",
            category="retry-timeout",
            rule_id="REL-RETRY-001",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            verification_status=VerificationStatus.STATIC_EVIDENCE,
            summary="A retry construct appears with no timeout or deadline within the surrounding scope.",
            technical_explanation=(
                "Retries without a bounded overall deadline can keep a request pending "
                "indefinitely and exhaust connection pools or worker capacity. Confidence is "
                "low because the timeout may be supplied by an outer layer."
            ),
            evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=path, start_line=lineno,
                               end_line=lineno, symbol=symbol.split("::")[-1] if symbol else "",
                               snippet=redact_snippet(text), note="retry without deadline")],
            affected_symbols=[symbol] if symbol else [],
            assumptions=["No outer layer imposes a deadline on this call."],
            preconditions=["The retried operation can hang."],
            impact="Resource exhaustion and unbounded request latency.",
            remediation="Bound the total attempt count and an overall deadline with backoff.",
            references=["https://cwe.mitre.org/data/definitions/400.html"],
            analysis_method="pattern rule with scope-window context",
            fingerprint=f"{path}:{lineno}:REL-RETRY-001",
            confidence_rationale="retry token present, no timeout token within +/-25 lines",
        )

    def _blocking_sleep(self, ctx, path, lineno, text, symbol, module) -> Finding | None:
        if not SLEEP_RE.search(text):
            return None
        if "await" in text or "asyncio" in text:
            return None
        if any("async" in module.line(i) for i in range(max(1, lineno - 6), lineno + 1)):
            return None
        return Finding(
            title="Blocking sleep in synchronous code",
            category="blocking-call",
            rule_id="REL-SLEEP-001",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.STATIC_EVIDENCE,
            summary="A synchronous sleep blocks the executing thread.",
            technical_explanation=(
                "Blocking sleeps reduce throughput and, inside an event-loop process, stall "
                "every concurrent request."
            ),
            evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=path, start_line=lineno,
                               end_line=lineno, symbol=symbol.split("::")[-1] if symbol else "",
                               snippet=redact_snippet(text), note="blocking sleep")],
            affected_symbols=[symbol] if symbol else [],
            assumptions=["The process serves more than one request or task."],
            impact="Throughput loss; latency amplification under load.",
            remediation="Use an awaitable sleep (asyncio.sleep, time.Timer) instead.",
            analysis_method="pattern rule over sanitized source lines",
            fingerprint=f"{path}:{lineno}:REL-SLEEP-001",
            confidence_rationale="sleep call without await in a non-async window",
        )

    def _resource_lifecycle(self, ctx: AnalysisContext) -> list[Finding]:
        out: list[Finding] = []
        for sid, entry in (ctx.control_flow or {}).items():
            if not entry.resources_opened or entry.has_try:
                continue
            if not entry.early_returns:
                continue
            sym = ctx.index.by_id.get(sid)
            if sym is None or sym.kind not in {"function", "method"}:
                continue
            if len(entry.resources_opened) > len(entry.resources_closed):
                line_no = entry.resources_opened[0][0]
                module = ctx.index.modules.get(sym.file)
                out.append(Finding(
                    title=f"Cleanup ordering risk in {sid.split('::')[-1]}",
                    category="cleanup-ordering",
                    rule_id="REL-CLEANUP-001",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    verification_status=VerificationStatus.INCONCLUSIVE,
                    summary=(
                        f"{len(entry.early_returns)} early return(s) exist in a function that "
                        "acquires a resource, without an exception-safe release construct."
                    ),
                    technical_explanation=(
                        "Early returns between acquisition and release are a common source of "
                        "cleanup gaps. Whether a specific resource is leaked cannot be "
                        "determined without path-sensitive analysis, so this is reported as "
                        "inconclusive rather than a confirmed leak."
                    ),
                    evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=sym.file,
                                       start_line=line_no, end_line=line_no,
                                       symbol=sid.split("::")[-1],
                                       snippet=redact_snippet(module.line(line_no) if module else ""),
                                       note="acquisition followed by early returns")],
                    affected_symbols=[sid],
                    assumptions=["A resource is released after the acquisition on the main path."],
                    impact="Possible leaked file handles, sockets or locks.",
                    remediation="Use RAII / context managers / defer so cleanup is structural.",
                    analysis_method="control-flow early-return analysis",
                    fingerprint=f"cleanup:{sid}",
                    confidence_rationale="early returns present; path-sensitive proof not performed",
                ))
        return out

    @staticmethod
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