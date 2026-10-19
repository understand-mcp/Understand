"""Filesystem path validation and traversal prevention."""

from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath

from understand.errors import AccessDeniedError, InvalidSourceError

_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10)),
}
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def normalize_relpath(path: str) -> str:
    """Normalize a repository-relative path to a safe POSIX-style form.

    Raises on absolute paths, drive letters, traversal segments and NUL bytes.
    """
    if "\x00" in path:
        raise InvalidSourceError("path contains a NUL byte")
    text = unicodedata.normalize("NFC", path).replace("\\", "/")
    if _CONTROL_CHARS.search(text):
        raise InvalidSourceError("path contains control characters")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        raise InvalidSourceError(f"absolute paths are not allowed in repository-relative paths: {path!r}")
    if text.startswith("//"):
        raise InvalidSourceError("UNC-style paths are not allowed")
    parts: list[str] = []
    for raw in PurePosixPath(text).parts:
        if raw in {".", ""}:
            continue
        if raw == "..":
            raise InvalidSourceError(f"path traversal segment is not allowed: {path!r}")
        parts.append(raw)
    if not parts:
        raise InvalidSourceError(f"empty path: {path!r}")
    return "/".join(parts)


def is_hostile_filename(name: str) -> bool:
    """Detect Windows-reserved names, trailing dots/spaces and control chars."""
    if not name or name in {".", ".."}:
        return True
    if _CONTROL_CHARS.search(name) or "\x00" in name:
        return True
    if len(name) > 255:
        return True
    stem = name.split(".")[0].lower()
    if stem in _WINDOWS_RESERVED:
        return True
    if name != name.rstrip(" ."):
        return True
    # Alternate data streams and path separators smuggled into a single component
    if any(c in name for c in ("/", "\\", "|", "?", "*", "<", ">", '"')):
        return True
    if unicodedata.normalize("NFC", name) != name:
        return False
    return False


def resolve_within(root: Path, candidate: Path, *, allow_symlinks: bool = False) -> Path:
    """Resolve `candidate` and prove it stays inside `root`.

    Symlinks are resolved before the containment test, which defeats the
    classic "symlink escapes the workspace" trick.
    """
    try:
        real_root = Path(os.path.realpath(root))
        real_candidate = Path(os.path.realpath(candidate))
    except OSError as exc:  # pragma: no cover - platform dependent
        raise AccessDeniedError(f"cannot resolve path {candidate}: {exc}") from exc
    if not allow_symlinks:
        # Even without following symlinks for reading, reject anything that
        # resolves outside the root.
        pass
    try:
        real_candidate.relative_to(real_root)
    except ValueError as exc:
        raise AccessDeniedError(
            f"path {candidate} resolves outside the authorized root {real_root}"
        ) from exc
    return real_candidate


def assert_local_source(path: str | Path, *, allowed_roots: tuple[str, ...] = ()) -> Path:
    """Validate a local SOURCE argument and return its resolved absolute path."""
    text = os.fspath(path)
    if not text or "\x00" in text:
        raise InvalidSourceError("local path must be a non-empty string without NUL bytes")
    expanded = Path(os.path.expanduser(text))
    if not expanded.exists():
        raise InvalidSourceError(f"local path does not exist: {path}")
    if expanded.is_file():
        raise InvalidSourceError(f"expected a directory, got a file: {path}")
    try:
        resolved = Path(os.path.realpath(expanded))
    except OSError as exc:
        raise InvalidSourceError(f"cannot resolve local path {path}: {exc}") from exc
    if not resolved.is_dir():
        raise InvalidSourceError(f"expected a directory: {path}")
    if os.name == "nt":  # drive-root guard
        drive, _ = os.path.splitdrive(str(resolved))
        anchor = resolved.parent if drive else resolved
        if str(anchor) == str(resolved):
            raise AccessDeniedError(f"refusing to scan a filesystem root: {resolved}")
    if allowed_roots:
        roots = [Path(os.path.realpath(os.path.expanduser(r))) for r in allowed_roots]
        for r in roots:
            try:
                resolved.relative_to(r)
                break
            except ValueError:
                continue
        else:
            raise AccessDeniedError(
                f"{resolved} is outside the authorized roots: " + ", ".join(str(r) for r in roots)
            )
    return resolved


def relative_to_root(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = Path(os.path.relpath(path, root))
    return PureWindowsPath(*rel.parts).as_posix() if os.name == "nt" else rel.as_posix()