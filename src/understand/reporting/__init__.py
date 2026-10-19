"""Report rendering facade.

Every renderer takes a :class:`~understand.models.ScanReport` and returns text.
The registry here is the single place that knows which formats exist, so both
the CLI and the MCP server fail the same way for an unknown format.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable

from ..errors import UnsupportedFormatError
from ..models import ScanReport
from ..security.path_validation import is_hostile_filename
from .html_map import render_map_html, write_map_html
from .json_report import render_json, report_to_dict, write_json
from .sarif_report import render_sarif, sarif_dict, write_sarif
from .text_report import render_text, supports_color, write_text

__all__ = [
    "SUPPORTED_FORMATS",
    "render_report",
    "write_report",
    "safe_output_path",
    "safe_map_output_path",
    "render_json",
    "render_text",
    "render_sarif",
    "render_map_html",
    "write_map_html",
    "report_to_dict",
    "sarif_dict",
    "supports_color",
]

SUPPORTED_FORMATS: tuple[str, ...] = ("json", "text", "sarif")

_RENDERERS: dict[str, Callable[..., str]] = {
    "json": render_json,
    "text": render_text,
    "sarif": render_sarif,
}

_WRITERS: dict[str, Callable[..., Path]] = {
    "json": write_json,
    "text": write_text,
    "sarif": write_sarif,
}

_ALIASES = {
    "sarif-v2-1-0": "sarif",
    "sarif2": "sarif",
    "txt": "text",
    "plain": "text",
    "markdown": "text",
    "md": "text",
}

#: Directories a scan should never be able to clobber, even when the user
#: passes an absolute ``--output`` path.
_PROTECTED = (
    os.environ.get("SystemRoot", r"C:\Windows"),
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/boot",
)


def normalize_format(fmt: str) -> str:
    key = (fmt or "").strip().lower()
    key = _ALIASES.get(key, key)
    if key not in _RENDERERS:
        raise UnsupportedFormatError(
            f"unsupported report format {fmt!r}",
            detail={"supported": list(SUPPORTED_FORMATS)},
        )
    return key


def render_report(report: ScanReport, fmt: str = "text", **kwargs: Any) -> str:
    """Render ``report`` in ``fmt``."""

    renderer = _RENDERERS[normalize_format(fmt)]
    if renderer is render_text:
        kwargs.setdefault("color", None)
        kwargs.setdefault("max_findings", 50)
    return renderer(report, **kwargs)


def safe_output_path(path: str | os.PathLike[str], *, fmt: str | None = None) -> Path:
    """Validate a user supplied ``--output`` path and return an absolute one.

    Rules (documented in ``docs/security-model.md``):

    * relative paths resolve against the current working directory;
    * the path may not traverse above the working directory via ``..`` when it
      is relative;
    * the path may not be a symlink, so ``--output`` cannot be used to write
      through a link into a protected location;
    * writing into well-known operating system directories is refused;
    * a filename that is hostile on Windows (reserved device name, trailing dot
      or space, illegal characters) is refused.
    """

    raw = os.fspath(path)
    if not raw.strip():
        raise UnsupportedFormatError("empty output path")
    if "\x00" in raw:
        raise UnsupportedFormatError("output path contains a NUL byte")

    candidate = Path(raw)
    absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
    normalized = Path(os.path.normpath(str(absolute)))

    if not candidate.is_absolute() and ".." in candidate.parts:
        raise UnsupportedFormatError("output path may not traverse above the working directory")

    if normalized.name and is_hostile_filename(normalized.name):
        raise UnsupportedFormatError(f"output filename {normalized.name!r} is not a safe filename")

    if normalized.exists() and normalized.is_dir():
        raise UnsupportedFormatError(f"output path {normalized} is a directory")
    if normalized.is_symlink():
        raise UnsupportedFormatError("refusing to write through a symbolic link")

    text = os.path.normcase(str(normalized))
    for protected in _PROTECTED:
        if not protected:
            continue
        # Compare fully-resolved forms so that a POSIX-style protected entry such
        # as "/etc" still matches on Windows, where the candidate may have been
        # re-anchored onto the current drive.
        root = os.path.normcase(os.path.abspath(protected))
        try:
            if os.path.commonpath([text, root]) == root and text != root:
                raise UnsupportedFormatError(f"refusing to write into protected location {root}")
        except ValueError:  # pragma: no cover - different drives
            continue

    if fmt is not None:
        expected = ".sarif" if normalize_format(fmt) == "sarif" else f".{normalize_format(fmt)}"
        if normalized.suffix and normalized.suffix.lower() not in {expected, ".json"}:
            raise UnsupportedFormatError(
                f"output extension {normalized.suffix!r} does not match format {fmt!r}"
            )
    return normalized


def safe_map_output_path(path: str | os.PathLike[str]) -> Path:
    """Validate a ``--output`` path for a code map.

    A map is its own format, not a ``--format`` value: the view, root, depth and
    kind filters are arguments, so ``--format html`` would be the wrong door.
    The path still goes through :func:`safe_output_path` unchanged, so every
    rule there (no ``..`` escape, no symlink, no protected directory, no hostile
    filename) applies to a map exactly as it does to a SARIF file.
    """

    normalized = safe_output_path(path)
    if normalized.suffix and normalized.suffix.lower() not in {".html", ".htm"}:
        raise UnsupportedFormatError(
            f"output extension {normalized.suffix!r} does not match a map (.html)"
        )
    return normalized


def write_report(report: ScanReport, fmt: str, path: str | os.PathLike[str] | None = None, **kwargs: Any) -> str:
    """Render ``report`` and optionally write it to ``path``.

    Returns the rendered text; the file (if any) is written as a side effect.
    """

    normalized = normalize_format(fmt)
    text = render_report(report, normalized, **kwargs)
    if path is None:
        return text
    target = safe_output_path(path, fmt=normalized)
    writer = _WRITERS[normalized]
    if normalized == "text":
        writer(report, target, **{k: v for k, v in kwargs.items() if k == "max_findings"})
    else:
        writer(report, target, **{k: v for k, v in kwargs.items() if k in ("pretty", "redact")})
    return text


def _self_check() -> None:  # pragma: no cover - developer helper
    sys.stderr.write(", ".join(SUPPORTED_FORMATS) + "\n")