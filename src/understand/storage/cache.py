"""Content-addressed cache for scan results.

A cached scan is only reused when *both* halves still match:

``root_digest``
    a content digest of the repository tree (path, size and, for reasonably
    sized files, the bytes themselves), and

``request_digest``
    a digest of everything in the :class:`~understand.models.ScanRequest` that
    can change the answer (profile, checks, cross-module flag, limits, scanner
    version).

Changing a file, adding one, deleting one, upgrading the scanner or asking for
a different analysis all produce a different digest, so stale results are never
served.  Excluded paths never enter the digest, so reformatting a vendored
directory cannot invalidate a scan.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from ..logging_config import get_logger
from ..models import ScanRequest
from ..security.repository_policy import RepositoryPolicy

log = get_logger(__name__)

#: Files larger than this contribute size + mtime instead of a full content hash.
_CONTENT_HASH_LIMIT = 1_048_576

#: Upper bound on files folded into a single tree digest.
_MAX_DIGEST_FILES = 50_000


def _file_digest(path: Path, size: int) -> str:
    if size <= _CONTENT_HASH_LIMIT:
        h = hashlib.sha256()
        try:
            with path.open("rb") as fh:
                for chunk in iter(lambda: fh.read(262_144), b""):
                    h.update(chunk)
        except OSError as exc:  # pragma: no cover - unreadable file
            return f"unreadable:{exc.errno}"
        return h.hexdigest()
    return f"large:{size}"


#: Lazily built default policy used when the caller does not supply one, so the
#: digest never depends on hidden/generated/vendor files that analysis ignores.
_DEFAULT_POLICY: RepositoryPolicy | None = None


def _default_policy() -> RepositoryPolicy:
    global _DEFAULT_POLICY
    if _DEFAULT_POLICY is None:
        from ..config import AnalysisPolicy

        _DEFAULT_POLICY = RepositoryPolicy(AnalysisPolicy())
    return _DEFAULT_POLICY


def digest_repository(
    root: str | os.PathLike[str],
    policy: RepositoryPolicy | None = None,
    *,
    max_files: int = _MAX_DIGEST_FILES,
) -> tuple[str, int]:
    """Return ``(digest, files_counted)`` for the analysable content of ``root``.

    The digest is stable across machines: it depends only on relative paths and
    file bytes, never on absolute location, mtime or iteration order.  When no
    ``policy`` is supplied the default analysis policy applies, so hidden,
    vendored and generated files never invalidate a cached scan.
    """
    policy = policy if policy is not None else _default_policy()
    base = Path(root).resolve()
    hasher = hashlib.sha256()
    hasher.update(b"understand-tree-v1\n")
    entries: list[tuple[str, str]] = []
    counted = 0

    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        current = Path(dirpath)
        rel_dir = current.relative_to(base)
        dirnames[:] = [
            d
            for d in sorted(dirnames)
            if not policy.decide(str(rel_dir / d).replace("\\", "/")).excluded
        ]
        for filename in sorted(filenames):
            full = current / filename
            rel = f"{rel_dir.as_posix()}/{filename}" if str(rel_dir) != "." else filename
            decision = policy.decide(rel)
            if decision.excluded:
                continue
            try:
                stat = full.stat()
            except OSError:
                entries.append((rel, "stat-error"))
                continue
            if full.is_symlink():
                # Symlinks are not followed; record them as opaque entries so
                # adding/removing a link still invalidates the cache.
                entries.append((rel, "symlink"))
                continue
            entries.append((rel, f"{stat.st_size}:{_file_digest(full, stat.st_size)}"))
            counted += 1
            if counted >= max_files:
                log.warning("tree digest truncated at %d files", max_files)
                break
        if counted >= max_files:
            break

    for rel, token in sorted(entries):
        hasher.update(rel.encode("utf-8", "surrogateescape"))
        hasher.update(b"\x00")
        hasher.update(token.encode("utf-8", "surrogateescape"))
        hasher.update(b"\n")
    return hasher.hexdigest(), counted


def digest_request(request: ScanRequest) -> str:
    """Digest of the parts of a scan request that affect the result."""
    return request.cache_key_material()


@dataclass(frozen=True, slots=True)
class CacheLookup:
    """Outcome of a cache probe."""

    hit: bool
    scan_id: str = ""
    root_digest: str = ""
    request_digest: str = ""
    reason: str = ""


class ScanCache:
    """Cache facade over :class:`~understand.storage.scan_store.ScanStore`."""

    def __init__(self, store, *, enabled: bool = True) -> None:
        self._store = store
        self.enabled = enabled

    def compute_digests(
        self, root: str | os.PathLike[str], request: ScanRequest, policy: RepositoryPolicy | None = None
    ) -> tuple[str, str]:
        root_digest, _files_counted = digest_repository(root, policy)
        return root_digest, digest_request(request)

    def lookup(self, root_digest: str, request_digest: str) -> CacheLookup:
        if not self.enabled:
            return CacheLookup(False, reason="cache disabled")
        try:
            scan_id = self._store.cache_lookup(root_digest, request_digest)
        except Exception as exc:  # pragma: no cover - storage problems are not fatal
            log.warning("cache lookup failed: %s", exc)
            return CacheLookup(False, root_digest=root_digest, request_digest=request_digest, reason=str(exc))
        if scan_id:
            return CacheLookup(True, scan_id=scan_id, root_digest=root_digest, request_digest=request_digest)
        return CacheLookup(
            False, root_digest=root_digest, request_digest=request_digest, reason="no matching entry"
        )

    def store(
        self,
        *,
        root_digest: str,
        request_digest: str,
        scan_id: str,
        scanner_version: str = "",
    ) -> None:
        if not self.enabled:
            return
        try:
            self._store.cache_store(
                root_digest=root_digest,
                request_digest=request_digest,
                scan_id=scan_id,
                scanner_version=scanner_version,
            )
        except Exception as exc:  # pragma: no cover
            log.warning("cache store failed: %s", exc)

    def invalidate(self, root_digest: str) -> int:
        try:
            return self._store.cache_invalidate_digest(root_digest)
        except Exception as exc:  # pragma: no cover
            log.warning("cache invalidation failed: %s", exc)
            return 0

    def clear(self) -> int:
        try:
            return self._store.cache_clear()
        except Exception as exc:  # pragma: no cover
            log.warning("cache clear failed: %s", exc)
            return 0


__all__ = [
    "CacheLookup",
    "ScanCache",
    "digest_repository",
    "digest_request",
    "_CONTENT_HASH_LIMIT",
    "_MAX_DIGEST_FILES",
]