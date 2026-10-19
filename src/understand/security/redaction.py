"""Secret redaction for logs, reports and error messages.

Redaction is applied to every string that leaves the analysis engine when it is
serialized. The engine itself keeps raw source in memory only for the duration
of a scan and never writes source bodies to storage by default.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    # A PEM header on its own (a truncated dump, a log line) still leaks the fact
    # that a private key was present, so the marker is masked even without a body.
    ("private_key_marker", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[^\n]*\n?)")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("url_credentials", re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")),
    ("assignment_secret", re.compile(
        r"(?i)\b((?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|"
        r"private[_-]?key|password|passwd|secret)\s*[:=]\s*)(['\"])([^'\"\n]{6,120})\2"
    )),
)

_MIN_SNIPPET = 400


def redact_text(text: str) -> str:
    """Mask well-known credential shapes in a free-form string."""
    if not text:
        return text
    out = text
    for _name, pat in _PATTERNS:
        if pat.groups >= 3 and _name == "assignment_secret":
            out = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}{m.group(2)}", out)
        else:
            out = pat.sub(REDACTED, out)
    return out


def redact_obj(obj: Any, *, max_depth: int = 12) -> Any:
    """Recursively redact strings inside JSON-like structures.

    Pydantic models are converted to their JSON form first so a report object
    can be passed in directly without leaking secrets through a field the
    caller forgot to unpack.
    """

    if max_depth <= 0:
        return "[TRUNCATED]"
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {str(k): redact_obj(v, max_depth=max_depth - 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v, max_depth=max_depth - 1) for v in obj]
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return redact_obj(dump(mode="json"), max_depth=max_depth - 1)
        except Exception:  # pragma: no cover - non-pydantic model_dump
            return redact_text(str(obj))
    return obj


def redact_snippet(snippet: str, *, limit: int = 240) -> str:
    """Redact and length-bound a source snippet before it enters a report."""
    if not snippet:
        return ""
    snippet = snippet.strip()
    if len(snippet) > limit:
        snippet = snippet[:limit] + "…"
    return redact_text(snippet)


def looks_like_secret(value: str) -> bool:
    """Heuristic used by the hardcoded-credential analyzer."""
    if not value or len(value) < 8:
        return False
    v = value.strip().strip("\"'")
    for _n, pat in _PATTERNS:
        if pat.fullmatch(v) or pat.search(v):
            return True
    return False