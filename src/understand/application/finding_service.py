"""Finding query service.

Findings are addressed by a stable fingerprint id (``RULE-<hash>``), so the
same defect in the same code always has the same id across scans.  That makes
``finding show`` and MCP ``inspect_finding`` usable as a workflow: scan, fix,
re-scan, diff.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..errors import FindingNotFound, ScanNotFound, ValidationError
from ..models import Confidence, Finding, Page, ScanReport, Severity, VerificationStatus
from ..storage.scan_store import ScanStore

__all__ = ["FindingService", "finding_to_dict"]

MAX_LIMIT = 500


def finding_to_dict(finding: Finding, *, include_evidence: bool = True) -> dict[str, Any]:
    data = finding.model_dump(mode="json")
    if not include_evidence:
        data.pop("evidence", None)
    return data


class FindingService:
    def __init__(self, store: ScanStore) -> None:
        self.store = store

    # -------------------------------------------------------------- retrieval
    def get(self, finding_id: str, *, scan_id: str | None = None) -> Finding:
        finding_id = (finding_id or "").strip()
        if not finding_id:
            raise ValidationError("finding_id must not be empty")
        return self.store.get_finding(finding_id, scan_id=scan_id)

    def exists(self, finding_id: str) -> bool:
        """Whether ``finding_id`` resolves.

        Only "not found" answers False. A storage failure must not masquerade as
        a missing finding, so anything else is allowed to propagate.
        """
        try:
            self.store.get_finding(finding_id)
        except (FindingNotFound, ScanNotFound, ValidationError):
            return False
        return True

    def query(
        self,
        scan_id: str,
        *,
        severity: Sequence[str] | str | None = None,
        category: Sequence[str] | str | None = None,
        rule_id: str | None = None,
        file: str | None = None,
        language: str | None = None,
        verification_status: Sequence[str] | str | None = None,
        query: str | None = None,
        include_suppressed: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> Page:
        severities = _enum_filter(severity, Severity)
        categories = _category_filter(category)
        verifications = _enum_filter(verification_status, VerificationStatus)
        page = self.store.query_findings(
            scan_id,
            severity=severities,
            category=categories,
            rule_id=rule_id,
            file=file,
            language=language,
            verification_status=verifications,
            query=query,
            include_suppressed=include_suppressed,
            limit=max(1, min(int(limit), MAX_LIMIT)),
            offset=max(0, int(offset)),
        )
        return Page(
            items=[finding_to_dict(item, include_evidence=True) for item in page.items],
            total=page.total,
            offset=page.offset,
            limit=page.limit,
            next_offset=page.next_offset,
        )

    def query_report(
        self,
        report: ScanReport,
        **kwargs: Any,
    ) -> Page:
        """In-memory equivalent of :meth:`query`, for a report already loaded."""

        limit = max(1, min(int(kwargs.pop("limit", 50)), MAX_LIMIT))
        offset = max(0, int(kwargs.pop("offset", 0)))
        severities = set(_enum_filter(kwargs.pop("severity", None), Severity) or ())
        verifications = set(_enum_filter(kwargs.pop("verification_status", None), VerificationStatus) or ())
        categories = set(_category_filter(kwargs.pop("category", None)) or ())
        rule_id = kwargs.pop("rule_id", None)
        file_filter = kwargs.pop("file", None)
        language = kwargs.pop("language", None)
        text = (kwargs.pop("query", None) or "").strip().lower()
        include_suppressed = bool(kwargs.pop("include_suppressed", False))

        selected: list[Finding] = []
        for finding in report.findings:
            if finding.suppressed and not include_suppressed:
                continue
            if severities and finding.severity.value not in severities:
                continue
            if verifications and finding.verification_status.value not in verifications:
                continue
            if categories and finding.category not in categories:
                continue
            if rule_id and finding.rule_id != rule_id:
                continue
            if language and finding.language != language:
                continue
            if file_filter and not _touches_file(finding, file_filter):
                continue
            if text and not _matches_text(finding, text):
                continue
            selected.append(finding)

        total = len(selected)
        window = selected[offset : offset + limit]
        return Page(
            items=[finding_to_dict(f) for f in window],
            total=total,
            offset=offset,
            limit=limit,
            next_offset=offset + limit if offset + limit < total else None,
        )

    # ------------------------------------------------------------------ stats
    def stats(self, report: ScanReport) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        by_verification: dict[str, int] = {}
        by_confidence: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for finding in report.findings:
            if finding.suppressed:
                continue
            by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
            key = finding.verification_status.value
            by_verification[key] = by_verification.get(key, 0) + 1
            ckey = finding.confidence.value
            by_confidence[ckey] = by_confidence.get(ckey, 0) + 1
            rkey = finding.rule_id or "UNCLASSIFIED"
            by_rule[rkey] = by_rule.get(rkey, 0) + 1
        return {
            "total": sum(by_severity.values()),
            "by_severity": by_severity,
            "by_verification_status": by_verification,
            "by_confidence": by_confidence,
            "top_rules": sorted(by_rule.items(), key=lambda item: (-item[1], item[0]))[:20],
            "highest_severity": next(
                (level.value for level in sorted(Severity, key=lambda s: -s.rank) if by_severity.get(level.value)),
                "",
            ),
        }


def _enum_filter(values: Sequence[str] | str | None, enum_cls: Any) -> list[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        values = list(values.replace(";", ",").split(","))
    out: list[str] = []
    for raw in values:
        token = str(raw).strip().lower()
        if not token:
            continue
        try:
            out.append(enum_cls(token).value)
        except ValueError:
            allowed = [member.value for member in enum_cls]
            raise ValidationError(
                f"invalid {enum_cls.__name__.lower()} filter {raw!r}",
                detail={"allowed": allowed},
            ) from None
    return out or None


def _category_filter(values: Sequence[str] | str | None) -> list[str] | None:
    if values is None:
        return None
    if isinstance(values, str):
        values = list(values.replace(";", ",").split(","))
    out = [str(value).strip().lower() for value in values if str(value).strip()]
    allowed = {"security", "bugs", "architecture", "dependencies", "reliability"}
    for value in out:
        if value not in allowed:
            raise ValidationError(
                f"invalid category filter {value!r}", detail={"allowed": sorted(allowed)}
            )
    return out or None


def _touches_file(finding: Finding, needle: str) -> bool:
    target = needle.replace("\\", "/").strip()
    for evidence in finding.evidence:
        path = str(evidence.file or "").replace("\\", "/")
        if path == target or path.endswith("/" + target):
            return True
    return False


def _matches_text(finding: Finding, needle: str) -> bool:
    haystack = " ".join(
        part
        for part in (
            finding.title,
            finding.rule_id or "",
            finding.summary or "",
            finding.technical_explanation or "",
            finding.remediation or "",
            " ".join(finding.affected_symbols),
        )
        if part
    ).lower()
    return needle in haystack


_ = Confidence  # re-exported for callers that filter on confidence
