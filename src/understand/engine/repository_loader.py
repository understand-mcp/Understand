"""Repository acquisition: local path or validated remote git clone."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from understand.config import RuntimeConfig
from understand.errors import InvalidSourceError, ResourceLimitExceeded
from understand.logging_config import get_logger
from understand.models import ScanRequest, SourceKind
from understand.security.path_validation import assert_local_source
from understand.security.safe_git import (
    clone_remote,
    is_git_repo,
    local_git_metadata,
    looks_like_remote,
    parse_git_url,
)

log = get_logger("engine.loader")


@dataclass
class AcquiredRepository:
    root: Path
    kind: SourceKind
    display: str
    name: str
    revision: str = ""
    remote_url: str = ""
    temporary: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    def cleanup(self) -> None:
        if self.temporary and self.root and self.root.exists():
            parent = tempfile.gettempdir()
            try:
                resolved = Path(self.root).resolve()
                if str(resolved).startswith(str(Path(parent).resolve())):
                    shutil.rmtree(resolved, ignore_errors=True)
            except OSError:  # pragma: no cover
                log.warning("failed to clean up temporary workspace %s", self.root)


def _dir_size(path: Path, limit: int) -> int:
    total = 0
    for root, _dirs, files in _walk_bounded(path):
        for f in files:
            try:
                total += (Path(root) / f).stat().st_size
            except OSError:
                continue
            if total > limit:
                return total
    return total


def _walk_bounded(path: Path, max_dirs: int = 400_000):
    seen = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except (OSError, PermissionError):
            continue
        dirs, files = [], []
        for e in entries:
            try:
                if e.is_dir() and not e.is_symlink():
                    dirs.append(e)
                elif e.is_file():
                    files.append(e.name)
            except OSError:
                continue
        yield current, dirs, files
        seen += 1
        if seen > max_dirs:
            return
        stack.extend(dirs)


def acquire(request: ScanRequest, config: RuntimeConfig) -> AcquiredRepository:
    """Obtain a readable repository root honouring all security policy."""
    source = request.repository.strip()

    if looks_like_remote(source) or source.startswith("git@"):
        if not request.allow_remote:
            raise InvalidSourceError("remote scanning disabled for this request")
        return _acquire_remote(source, request, config)
    return _acquire_local(source, request, config)


def _acquire_local(source: str, request: ScanRequest, config: RuntimeConfig) -> AcquiredRepository:
    allowed = tuple(dict.fromkeys(tuple(request.allowed_roots) + tuple(config.local_roots)))
    root = assert_local_source(source, allowed_roots=allowed)
    size = _dir_size(root, config.security.max_clone_bytes)
    if size > config.security.max_clone_bytes:
        raise ResourceLimitExceeded(
            f"repository size {size} bytes exceeds the configured limit "
            f"{config.security.max_clone_bytes} bytes"
        )
    meta = local_git_metadata(root)
    kind = SourceKind.LOCAL_GIT if is_git_repo(root) else SourceKind.LOCAL
    name = root.name or str(root)
    return AcquiredRepository(
        root=root, kind=kind, display=str(root), name=name,
        revision=meta.get("revision", ""), remote_url=meta.get("remote", ""), metadata=meta,
    )


def _acquire_remote(source: str, request: ScanRequest, config: RuntimeConfig) -> AcquiredRepository:
    if source.startswith("git@"):
        source = "ssh://" + source[4:].replace(":", "/", 1)
    remote = parse_git_url(source, config.security)
    tmp = Path(tempfile.mkdtemp(prefix="understand-clone-"))
    dest = tmp / "repo"
    try:
        meta = clone_remote(remote, config.security, dest)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    size = _dir_size(dest, config.security.max_clone_bytes)
    if size > config.security.max_clone_bytes:
        shutil.rmtree(tmp, ignore_errors=True)
        raise ResourceLimitExceeded(
            f"cloned repository exceeds the configured size limit "
            f"({config.security.max_clone_bytes} bytes)"
        )
    name = remote.path.rstrip("/").rsplit("/", 1)[-1]
    if name.endswith(".git"):
        name = name[:-4]
    return AcquiredRepository(
        root=dest, kind=SourceKind.REMOTE_GIT, display=remote.url, name=name or "repository",
        revision=meta.get("revision", ""), remote_url=remote.url, temporary=True, metadata=meta,
    )
