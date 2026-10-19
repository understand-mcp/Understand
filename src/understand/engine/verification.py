"""Verification status assignment and finding normalization.

UNDERSTAND distinguishes what was *established* from what was *suggested*. A
finding is never promoted to a stronger status without evidence for the
promotion. Nothing here fabricates a reproduction.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict

from understand.logging_config import get_logger
from understand.models import (
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)

log = get_logger("engine.verification")

# Order used when merging duplicates: keep the strongest evidence status.
_STATUS_ORDER = [
    VerificationStatus.STATIC_EVIDENCE,
    VerificationStatus.CROSS_MODULE_TRACE,
    VerificationStatus.TEST_BACKED,
    VerificationStatus.REPRODUCED,
    VerificationStatus.INCONCLUSIVE,
    VerificationStatus.NOT_VERIFIED,
]


def status_rank(status: VerificationStatus) -> int:
    return _STATUS_ORDER.index(status)


def normalize(findings: list[Finding], *, limit: int = 5000) -> list[Finding]:
    """Deduplicate, cap, and assign stable identifiers."""
    seen: dict[str, Finding] = {}
    for f in findings:
        f.ensure_id()
        if f.suppressed:
            continue
        key = f.fingerprint or f.rule_id
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
            continue
        _merge(existing, f)
    out = list(seen.values())
    out.sort(key=lambda f: (-f.severity.rank, -f.confidence.rank, f.rule_id, f.finding_id))
    if len(out) > limit:
        log.info("finding cap reached: %d findings kept out of %d", limit, len(out))
        out = out[:limit]
    return out


def _merge(target: Finding, other: Finding) -> None:
    if other.evidence:
        target.evidence.extend(other.evidence)
    if other.affected_symbols:
        target.affected_symbols = list(dict.fromkeys(target.affected_symbols + other.affected_symbols))
    if other.assumptions:
        target.assumptions = list(dict.fromkeys(target.assumptions + other.assumptions))
    if other.call_chains:
        target.call_chains.extend(other.call_chains[:3])
    if other.data_flows:
        target.data_flows.extend(other.data_flows[:3])
    if status_rank(other.verification_status) < status_rank(target.verification_status):
        target.verification_status = other.verification_status
    if other.confidence.rank > target.confidence.rank:
        target.confidence = other.confidence
        target.confidence_rationale = other.confidence_rationale
    target.evidence = target.evidence[:20]


def group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {s.value: [] for s in Severity}
    for f in findings:
        out[f.severity.value].append(f)
    return out


def group_by_category(findings: list[Finding]) -> dict[str, list[Finding]]:
    buckets: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[f.category].append(f)
    return dict(sorted(buckets.items()))


def suppression_key(f: Finding) -> str:
    return hashlib.sha256(
        f"{f.rule_id}|{f.fingerprint}".encode("utf-8")
    ).hexdigest()[:16]


def confidence_from_evidence(f: Finding) -> Confidence:
    """Derive confidence from the evidence actually attached to a finding."""
    if not f.evidence:
        return Confidence.LOW
    if f.verification_status is VerificationStatus.REPRODUCED:
        return Confidence.HIGH
    has_trace = any(e.kind.value in {"call_trace", "data_flow"} for e in f.evidence)
    if has_trace and f.verification_status is VerificationStatus.CROSS_MODULE_TRACE:
        return Confidence.HIGH if all(
            e.origin is None or e.origin.value in {"static_direct", "type_resolved"}
            for e in f.evidence
        ) else Confidence.MEDIUM
    if f.verification_status is VerificationStatus.STATIC_EVIDENCE:
        return Confidence.MEDIUM if len(f.evidence) > 1 else Confidence.LOW
    return Confidence.LOW


def verification_summary(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.verification_status.value] = counts.get(f.verification_status.value, 0) + 1
    return counts