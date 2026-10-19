"""Repository inventory: enumeration, language detection, project components."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from understand.config import AnalysisPolicy
from understand.engine import language_detection as lang
from understand.errors import ResourceLimitExceeded
from understand.logging_config import get_logger
from understand.models import FileRecord, SupportLevel
from understand.security.path_validation import relative_to_root, resolve_within
from understand.security.repository_policy import RepositoryPolicy
from understand.security.sandbox import Workspace

log = get_logger("engine.inventory")

BUILD_SYSTEM_MARKERS: dict[str, str] = {
    "package.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "requirements.txt": "pip",
    "pyproject.toml": "python-project",
    "poetry.lock": "poetry",
    "Pipfile": "pipenv",
    "setup.py": "setuptools",
    "go.mod": "go-modules",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "Makefile": "make",
    "CMakeLists.txt": "cmake",
    "Dockerfile": "docker",
    "docker-compose.yml": "compose",
    "Vagrantfile": "vagrant",
}

FRAMEWORK_MARKERS: dict[str, tuple[str, ...]] = {
    "django": ("manage.py", "settings.py", "urls.py"),
    "flask": ("app.py", "wsgi.py", "flask"),
    "fastapi": ("main.py", "fastapi"),
    "express": ("express",),
    "nestjs": ("@nestjs/core", "nest-cli.json"),
    "nextjs": ("next.config.js", "next.config.ts"),
    "react": ("react-dom", "react"),
    "vue": ("vue",),
    "svelte": ("svelte.config.js",),
    "spring": ("pom.xml",),
    "rails": ("config.ru", "Gemfile"),
    "laravel": ("artisan",),
    "gin": ("gin-gonic",),
    "actix": ("actix-web",),
    "axum": ("axum",),
    "fastify": ("fastify",),
    "angular": ("angular.json",),
}

CI_MARKERS = (".github/workflows", ".gitlab-ci.yml", ".circleci", "Jenkinsfile",
              "azure-pipelines.yml", ".travis.yml")

ENTRY_FILES = ("main.py", "__main__.py", "app.py", "server.py", "wsgi.py", "asgi.py",
               "cli.py", "index.js", "index.ts", "main.go", "main.rs", "Program.cs",
               "manage.py", "application.js", "server.ts", "start.sh", "entrypoint.sh")

SCHEMA_EXTENSIONS = (".sql", ".prisma", ".graphql", ".gql")
MIGRATION_HINTS = ("migrations", "migrate", "schema", "db")
SPEC_HINTS = ("openapi", "swagger", ".proto", "asyncapi", "graphql")
INFRA_SUFFIXES = (".tf", ".tfvars", "dockerfile", ".dockerfile")
SCRIPT_SUFFIXES = (".sh", ".bash", ".ps1", ".bat", ".cmd", ".mk")


@dataclass
class Inventory:
    root: Path
    files: dict[str, FileRecord] = field(default_factory=dict)
    contents: dict[str, str] = field(default_factory=dict)
    build_systems: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    manifests: list[str] = field(default_factory=list)
    test_dirs: list[str] = field(default_factory=list)
    ci_files: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    schemas: list[str] = field(default_factory=list)
    migrations: list[str] = field(default_factory=list)
    infra: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    total_bytes: int = 0
    truncated: bool = False
    skipped: int = 0
    failed: int = 0
    policy: RepositoryPolicy | None = None
    seen_dirs: set[str] = field(default_factory=set)


def _is_binary_sample(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(4096)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b < 127)
    return (printable / len(chunk)) < 0.75


def build_inventory(root: Path, policy: RepositoryPolicy, *, max_files: int,
                    max_file_bytes: int, max_total_bytes: int) -> Inventory:
    """Enumerate, filter and read repository files under the configured budgets."""
    inv = Inventory(root=root, policy=policy)
    stack: list[Path] = [root]
    root_resolved = Path(root).resolve()

    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except (OSError, PermissionError):
            inv.failed += 1
            continue
        try:
            rel_dir = relative_to_root(root_resolved, current)
        except ValueError:
            continue
        if rel_dir != ".":
            inv.seen_dirs.add(rel_dir)

        for entry in entries:
            try:
                is_dir = entry.is_dir()
                is_file = entry.is_file()
            except OSError:
                inv.failed += 1
                continue
            if entry.is_symlink() and not policy.analysis.follow_symlinks:
                inv.skipped += 1
                policy.note_exclusion("symlink skipped")
                continue
            rel = relative_to_root(root_resolved, entry)
            if is_dir:
                decision = policy.decide(rel)
                if decision.excluded:
                    policy.note_exclusion(decision.reason, decision.pattern)
                    continue
                stack.append(entry)
                continue
            if not is_file:
                inv.skipped += 1
                continue
            decision = policy.decide(rel)
            if decision.excluded:
                inv.skipped += 1
                policy.note_exclusion(decision.reason, decision.pattern)
                continue
            if len(inv.contents) >= max_files:
                inv.truncated = True
                policy.note_exclusion("file-count budget reached", f"max_files={max_files}")
                break
            try:
                resolved = resolve_within(root_resolved, entry,
                                          allow_symlinks=policy.analysis.follow_symlinks)
                size = resolved.stat().st_size
            except (OSError, Exception) as exc:  # noqa: B014 - AccessDeniedError included
                inv.failed += 1
                log.debug("cannot stat %s: %s", rel, exc)
                continue
            if size > max_file_bytes:
                inv.skipped += 1
                policy.note_exclusion("file too large", f"> {max_file_bytes} bytes")
                continue
            if inv.total_bytes + size > max_total_bytes:
                inv.truncated = True
                policy.note_exclusion("byte budget reached", f"max_total_bytes={max_total_bytes}")
                break
            binary = _is_binary_sample(entry)
            detection = lang.detect(rel)
            record = FileRecord(
                path=rel,
                language=detection.language if not binary else "binary",
                support=SupportLevel.UNSUPPORTED if binary else detection.support,
                size=size,
                is_generated=policy.is_generated_path(rel),
                is_test=policy.is_test_path(rel),
                is_vendored="vendor" in rel.lower() or "node_modules" in rel.lower(),
                is_binary=binary,
            )
            inv.files[rel] = record
            inv.total_bytes += size
            if binary:
                continue
            try:
                text = resolved.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeDecodeError) as exc:
                record.read_error = f"{type(exc).__name__}: {exc}"
                inv.failed += 1
                continue
            inv.contents[rel] = text
            record.lines = text.count("\n") + 1
            _classify(inv, rel)

    inv.packages = sorted(inv.seen_dirs)
    return inv


def _classify(inv: Inventory, rel: str) -> None:
    base = rel.rsplit("/", 1)[-1]
    low = rel.lower()
    if base in BUILD_SYSTEM_MARKERS:
        inv.build_systems.append(BUILD_SYSTEM_MARKERS[base])
        inv.manifests.append(rel)
    for marker in CI_MARKERS:
        if marker in low or base == marker.rsplit("/", 1)[-1]:
            if rel not in inv.ci_files:
                inv.ci_files.append(rel)
    if base in ENTRY_FILES or low.endswith(("/main", "/main.py")):
        inv.entry_points.append(rel)
    if rel.endswith(SCHEMA_EXTENSIONS) or any(h in low for h in SPEC_HINTS):
        inv.schemas.append(rel)
    if any(h in low for h in MIGRATION_HINTS) and rel.endswith((".sql", ".py", ".js", ".ts", ".go", ".rb")):
        inv.migrations.append(rel)
    if rel.endswith(INFRA_SUFFIXES) or base.lower().startswith("dockerfile"):
        inv.infra.append(rel)
    if rel.endswith(SCRIPT_SUFFIXES):
        inv.scripts.append(rel)
    if "/test" in low or low.startswith("test") or "/spec" in low or "/__tests__/" in low:
        if rel not in inv.test_dirs:
            inv.test_dirs.append(rel)
    for framework, markers in FRAMEWORK_MARKERS.items():
        if any(m in low or base == m for m in markers):
            if framework not in inv.frameworks:
                inv.frameworks.append(framework)


def detect_frameworks_from_manifests(inv: Inventory) -> list[str]:
    """Second pass: recognise frameworks from manifest content."""
    found = set(inv.frameworks)
    for rel, text in inv.contents.items():
        base = rel.rsplit("/", 1)[-1]
        if base in {"package.json", "requirements.txt", "pyproject.toml", "go.mod", "Gemfile"}:
            for framework, markers in FRAMEWORK_MARKERS.items():
                if any(m in text for m in markers):
                    found.add(framework)
    return sorted(found)


def assert_within_budget(count: int, max_files: int) -> None:
    if count > max_files:
        raise ResourceLimitExceeded(f"file count {count} exceeds max_files={max_files}")


__all__ = ["Inventory", "build_inventory", "detect_frameworks_from_manifests", "AnalysisPolicy"]