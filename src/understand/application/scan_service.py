"""The single scan service used by *both* the CLI and the MCP server.

Design contract
---------------
There is exactly one implementation of "run an analysis".  The CLI is a thin
argument parser over :class:`ScanService`; the MCP server exposes the same
object as tools.  Anything that differs between the two interfaces (waiting
synchronously, writing a file, formatting for a terminal) lives in the
interface layer, never here.

Jobs
----
``start()`` returns immediately with a job whose ``scan_id`` can be polled
through :meth:`ScanService.status`.  Long scans therefore never block an MCP
client, while the CLI can call :meth:`run_sync` and wait.
"""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from ..config import RuntimeConfig, load_config
from ..engine.orchestrator import CancellationToken, ScanOrchestrator, ScanResult
from ..errors import (
    ResourceLimitExceeded,
    ScanCancelled,
    ScanNotFound,
    UnderstandError,
    ValidationError,
)
from ..logging_config import get_logger
from ..models import Page, Profile, ScanReport, ScanRequest, SourceKind, utcnow
from ..security.repository_policy import RepositoryPolicy
from ..storage.cache import ScanCache
from ..storage.scan_store import ScanStore

__all__ = ["JobStatus", "ScanJob", "ScanService", "looks_remote"]

logger = get_logger("application.scan")


def looks_remote(repository: str) -> bool:
    return "://" in repository or repository.startswith("git@")


class JobStatus:
    """Job lifecycle states (plain strings so they serialize verbatim)."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    TERMINAL = frozenset({COMPLETED, FAILED, CANCELLED})
    ALL = (QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED)


@dataclass
class ScanJob:
    """In-memory handle for one scan."""

    scan_id: str
    request: ScanRequest
    status: str = JobStatus.QUEUED
    created_at: str = field(default_factory=utcnow)
    started_at: str = ""
    finished_at: str = ""
    current_stage: str = ""
    report: ScanReport | None = None
    error: dict[str, Any] | None = None
    from_cache: bool = False
    cancel: CancellationToken = field(default_factory=CancellationToken, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, repr=False)

    @property
    def terminal(self) -> bool:
        return self.status in JobStatus.TERMINAL

    @property
    def succeeded(self) -> bool:
        return self.status == JobStatus.COMPLETED and self.report is not None

    def wait(self, timeout: float | None = None) -> bool:
        return self._done.wait(timeout)

    def _finish(self, status: str) -> None:
        self.status = status
        self.finished_at = utcnow()
        self._done.set()

    def public(self) -> dict[str, Any]:
        """Machine-readable status, safe for MCP output and for logs."""

        data: dict[str, Any] = {
            "scan_id": self.scan_id,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "current_stage": self.current_stage,
            "repository": self.request.repository,
            "profile": self.request.profile.value,
            "checks": [check.value for check in self.request.checks],
            "cross_module": self.request.cross_module,
            "from_cache": self.from_cache,
            "terminal": self.terminal,
        }
        if self.report is not None:
            data["finding_count"] = len(self.report.findings)
            data["findings_by_severity"] = self.report.findings_by_severity
            data["partial"] = self.report.partial
            data["duration_seconds"] = self.report.duration_seconds
        if self.error is not None:
            data["error"] = self.error
        return data


class ScanService:
    """Owns the store, the cache and the worker pool."""

    def __init__(
        self,
        config: RuntimeConfig | None = None,
        *,
        store: ScanStore | None = None,
        cache: ScanCache | None = None,
        max_workers: int | None = None,
        keep_jobs: int = 128,
    ) -> None:
        self.config = config or load_config()
        self._store = store
        self._owns_store = store is None
        self._cache = cache
        self._workers = max_workers or max(1, min(4, self.config.max_workers or 2))
        self._executor: ThreadPoolExecutor | None = None
        self._jobs: dict[str, ScanJob] = {}
        self._futures: dict[str, Future[None]] = {}
        self._lock = threading.RLock()
        self._keep_jobs = max(8, keep_jobs)
        self._policy: RepositoryPolicy | None = None

    # ------------------------------------------------------------- lifecycle
    @property
    def store(self) -> ScanStore:
        if self._store is None:
            self._store = ScanStore(self.config.storage_path)
            self._owns_store = True
        return self._store

    @property
    def cache(self) -> ScanCache:
        if self._cache is None:
            self._cache = ScanCache(self.store, enabled=True)
        return self._cache

    @property
    def policy(self) -> RepositoryPolicy:
        if self._policy is None:
            self._policy = RepositoryPolicy.for_config(self.config)
        return self._policy

    def open(self) -> ScanService:
        """Initialize storage and recover jobs abandoned by a previous run."""

        if self._store is None:
            self._store = ScanStore(self.config.storage_path)
            self._owns_store = True
        self._store.initialize()
        self.recover_abandoned()
        return self

    def close(self) -> None:
        pool, self._executor = self._executor, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        if self._store is not None and self._owns_store:
            try:
                self._store.close()
            except Exception:  # pragma: no cover - best effort
                logger.debug("store close failed", exc_info=True)
            self._store = None

    def __enter__(self) -> ScanService:
        return self.open()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def recover_abandoned(self) -> int:
        """Mark scans left ``running`` by a crashed process as ``failed``.

        Without this, a client polling a scan id from a previous run would wait
        forever for a job that can never make progress.
        """

        try:
            store = self.store
            stale: list[str] = []
            for status in (JobStatus.RUNNING, JobStatus.QUEUED):
                page = store.list_scans(limit=200, status=status)
                stale.extend(str(item["scan_id"]) for item in page.items)
            for scan_id in stale:
                store.update_status(scan_id, JobStatus.FAILED)
            if stale:
                logger.warning("marked %d abandoned scan(s) as failed", len(stale))
            return len(stale)
        except Exception:  # pragma: no cover - recovery must never be fatal
            logger.debug("abandoned job recovery failed", exc_info=True)
            return 0

    # ------------------------------------------------------------ validation
    def validate(self, request: ScanRequest) -> ScanRequest:
        """Apply configuration policy to a request before any work starts."""

        if not request.repository or not request.repository.strip():
            raise ValidationError("repository must not be empty")
        if request.limits.max_seconds <= 0:
            raise ValidationError("limits.max_seconds must be positive")
        if request.limits.max_files <= 0:
            raise ValidationError("limits.max_files must be positive")
        if looks_remote(request.repository) and not self.config.security.allow_remote:
            raise ValidationError(
                "remote repositories are disabled by configuration "
                "(enable security.allow_remote to permit them)"
            )
        if not request.allowed_roots:
            request.allowed_roots = tuple(self.config.local_roots)
        return request

    # ------------------------------------------------------------------- API
    def start(self, request: ScanRequest, *, use_cache: bool | None = None) -> ScanJob:
        """Begin a scan and return immediately with a pollable job."""

        self.open()
        request = self.validate(request)
        cache_enabled = request.use_cache if use_cache is None else use_cache
        scan_id = self._new_scan_id()
        job = ScanJob(scan_id=scan_id, request=request)

        if cache_enabled and not request.offline and not looks_remote(request.repository):
            cached = self._try_cache(job, scan_id, request)
            if cached is not None:
                return cached

        self._register(job)
        self._record_scan(job)
        future = self._executor_pool().submit(self._execute, job)
        with self._lock:
            self._futures[scan_id] = future
        return job

    def run_sync(
        self,
        request: ScanRequest,
        *,
        timeout: float | None = None,
        use_cache: bool | None = None,
    ) -> ScanJob:
        """Start a scan and block until it reaches a terminal state."""

        job = self.start(request, use_cache=use_cache)
        limit = timeout if timeout is not None else float(request.limits.max_seconds) + 120.0
        if not job.wait(timeout=limit):
            self.cancel(job.scan_id)
            raise ResourceLimitExceeded(
                f"scan {job.scan_id} did not finish within {limit:.0f}s",
                detail={"scan_id": job.scan_id, "stage": job.current_stage},
            )
        # A caller that set a resource budget expects to be told when it is
        # spent; a partial report is still available for inspection.
        if job.error is not None and job.error.get("code") == "resource_limit_exceeded":
            raise ResourceLimitExceeded(str(job.error.get("message", "resource limit exceeded")), detail=job.error)
        return job

    def cancel(self, scan_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is None or job.terminal:
            return False
        job.cancel.cancel()
        logger.info("cancellation requested for scan %s", scan_id)
        return True

    def get(self, scan_id: str) -> ScanJob:
        with self._lock:
            job = self._jobs.get(scan_id)
        if job is not None:
            return job
        if self.store.report_exists(scan_id):
            report = self.store.load_report(scan_id)
            return ScanJob(
                scan_id=scan_id,
                request=_request_from_report(report),
                status=report.status or JobStatus.COMPLETED,
                created_at=report.started_at,
                started_at=report.started_at,
                finished_at=report.finished_at,
                report=report,
            )
        raise ScanNotFound(f"unknown scan id {scan_id!r}", detail={"scan_id": scan_id})

    def status(self, scan_id: str) -> dict[str, Any]:
        return self.get(scan_id).public()

    def report(self, scan_id: str) -> ScanReport:
        job = self.get(scan_id)
        if job.report is not None:
            return job.report
        return self.store.load_report(scan_id)

    def list_scans(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        repository: str = "",
        status: str = "",
    ) -> Page:
        return self.store.list_scans(limit=limit, offset=offset, repository=repository, status=status)

    # --------------------------------------------------------------- internals
    def _executor_pool(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=self._workers, thread_name_prefix="understand-scan"
            )
        return self._executor

    @staticmethod
    def _new_scan_id() -> str:
        return f"scan-{time.strftime('%Y%m%d', time.gmtime())}-{uuid.uuid4().hex[:8]}"

    def _register(self, job: ScanJob) -> None:
        with self._lock:
            self._jobs[job.scan_id] = job
            finished = sorted(
                (key for key, value in self._jobs.items() if value.terminal and key != job.scan_id),
                key=lambda key: self._jobs[key].finished_at,
            )
            excess = len(self._jobs) - self._keep_jobs
            for key in finished[:excess] if excess > 0 else ():
                self._jobs.pop(key, None)
                self._futures.pop(key, None)

    def _record_scan(self, job: ScanJob) -> None:
        remote = looks_remote(job.request.repository)
        try:
            self.store.create_scan(
                job.scan_id,
                request=job.request,
                repository=job.request.repository,
                source_kind=SourceKind.REMOTE_GIT.value if remote else SourceKind.LOCAL.value,
                status=JobStatus.RUNNING,
            )
        except Exception:  # pragma: no cover - storage problems must not block a scan
            logger.warning("could not record scan %s", job.scan_id, exc_info=True)

    def _try_cache(self, job: ScanJob, scan_id: str, request: ScanRequest) -> ScanJob | None:
        root_digest = ""
        request_digest = ""
        try:
            root_digest, request_digest = self.cache.compute_digests(
                request.repository, request, self.policy
            )
            lookup = self.cache.lookup(root_digest, request_digest)
        except Exception:  # pragma: no cover - cache problems never block scanning
            logger.debug("cache probe failed", exc_info=True)
            return None
        if not lookup.hit or not lookup.scan_id:
            return None
        try:
            if not self.store.report_exists(lookup.scan_id):
                return None
            source = self.store.load_report(lookup.scan_id)
        except Exception:  # pragma: no cover
            logger.debug("cache load failed", exc_info=True)
            return None

        report = source.model_copy(deep=True)
        report.scan_id = scan_id
        report.from_cache = True
        report.request = request.model_dump(mode="json")
        report.finished_at = utcnow()
        report.finalize()
        self._register(job)
        job.report = report
        job.from_cache = True
        job.status = JobStatus.COMPLETED
        job.started_at = job.finished_at
        job._done.set()
        self._store_report(report, scan_id, root_digest, request_digest)
        logger.info("scan %s served from cache (source scan %s)", scan_id, lookup.scan_id)
        return job

    def _execute(self, job: ScanJob) -> None:
        job.started_at = utcnow()
        job.status = JobStatus.RUNNING
        result: ScanResult | None = None
        try:
            orchestrator = ScanOrchestrator(
                self.config,
                cancel=job.cancel,
                on_stage=lambda name: setattr(job, "current_stage", name),
            )
            result = orchestrator.run(job.request)
        except ScanCancelled:
            logger.info("scan %s cancelled", job.scan_id)
            job.error = {"code": "scan_cancelled", "message": "scan cancelled before completion"}
            job._finish(JobStatus.CANCELLED)
            self._set_stored_status(job)
            return
        except UnderstandError as exc:
            logger.warning("scan %s failed: %s", job.scan_id, exc)
            payload = exc.to_dict() if hasattr(exc, "to_dict") else {"message": str(exc)}
            job.error = dict(payload)
            job._finish(JobStatus.FAILED)
            self._set_stored_status(job)
            return
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan %s crashed", job.scan_id)
            job.error = {
                "code": "internal_error",
                "message": f"{type(exc).__name__}: {exc}",
                "hint": "this is an UNDERSTAND defect; re-run with --verbose for a traceback",
            }
            job._finish(JobStatus.FAILED)
            self._set_stored_status(job)
            return
        finally:
            if result is not None:
                try:
                    result.cleanup()
                except Exception:  # pragma: no cover
                    logger.debug("workspace cleanup failed", exc_info=True)

        report = result.report
        self._store_report(report, job.scan_id, *self._digests(job))
        job.report = report
        job.current_stage = ""
        # The orchestrator records failures on the report rather than raising, so
        # the job status has to be derived from the report: a failed scan must not
        # be reported to a caller as a success.
        if report.status in ("failed", "cancelled", "partial"):
            first = report.errors[0] if report.errors else None
            job.error = {
                "code": (first.code if first and first.code else "analysis_error"),
                "message": (first.message if first else f"scan {report.status}"),
                "scan_id": job.scan_id,
            }
        job._finish(
            {
                "failed": JobStatus.FAILED,
                "cancelled": JobStatus.CANCELLED,
            }.get(report.status, JobStatus.COMPLETED)
        )
        self._set_stored_status(job)

    def _digests(self, job: ScanJob) -> tuple[str, str]:
        """Cache keys for a finished scan, or blanks when caching does not apply."""

        request = job.request
        if not request.use_cache or request.offline or looks_remote(request.repository):
            return "", ""
        try:
            return self.cache.compute_digests(request.repository, request, self.policy)
        except Exception:  # pragma: no cover - a cache key is never worth failing over
            logger.debug("cache digest failed for %s", job.scan_id, exc_info=True)
            return "", ""

    def _store_report(self, report: ScanReport, scan_id: str, root_digest: str, request_digest: str) -> None:
        try:
            report.scan_id = scan_id or report.scan_id
            report.finalize()
            self.store.save_report(report, root_digest=root_digest)
        except Exception:  # pragma: no cover
            logger.warning("could not persist scan %s", report.scan_id, exc_info=True)
            return
        if root_digest and request_digest:
            try:
                self.cache.store(
                    root_digest=root_digest,
                    request_digest=request_digest,
                    scan_id=report.scan_id,
                )
            except Exception:  # pragma: no cover
                logger.debug("cache store failed", exc_info=True)

    def _set_stored_status(self, job: ScanJob) -> None:
        try:
            self.store.update_status(job.scan_id, job.status)
        except Exception:  # pragma: no cover
            logger.debug("status update failed for %s", job.scan_id, exc_info=True)


def _request_from_report(report: ScanReport) -> ScanRequest:
    """Best-effort reconstruction of the request that produced a report."""

    data = report.request if isinstance(report.request, dict) else {}
    try:
        profile = Profile(data.get("profile", "standard"))
    except ValueError:
        profile = Profile.STANDARD
    try:
        return ScanRequest(
            repository=data.get("repository") or report.repository,
            profile=profile,
            checks=tuple(data.get("checks", ())),
            cross_module=bool(data.get("cross_module", False)),
            report_format=data.get("report_format", "text"),
        )
    except Exception:  # pragma: no cover - a report is always at least usable as a locator
        return ScanRequest(repository=report.repository or ".")
