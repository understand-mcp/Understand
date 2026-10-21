"""Runtime configuration for UNDERSTAND.

Precedence (highest first): explicit file/env > environment variables >
built-in defaults. Nothing here reads the analysed repository.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from understand.errors import ConfigurationError

ENV_PREFIX = "UNDERSTAND_"


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{ENV_PREFIX}{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class SecurityPolicy:
    """Defence-in-depth policy for repository acquisition."""

    # Remote acquisition is opt-in: a scan must never reach the network unless
    # the operator explicitly allows it (--allow-remote / ALLOW_REMOTE).
    allow_remote: bool = False
    allowed_hosts: tuple[str, ...] = ()           # empty => any public host
    block_private_networks: bool = True
    allow_http: bool = False                        # require https for remote git
    allow_ssh: bool = False
    clone_depth: int = 25
    clone_timeout_seconds: float = 120.0
    max_clone_bytes: int = 512 * 1024 * 1024
    recurse_submodules: bool = False
    allow_private_repo_credentials: bool = False
    execute_repo_code: bool = False                 # never; documented as unsupported


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise ConfigurationError(f"{ENV_PREFIX}{name} must be a number, got {raw!r}") from None


@dataclass(frozen=True)
class AnalysisPolicy:
    exclude_dirs: frozenset[str] = frozenset(
        {
            ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv", "env",
            "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
            "dist", "build", "out", "target", ".next", ".nuxt", ".gradle",
            ".idea", ".vscode", ".terraform", "site-packages", ".cache",
            "coverage", "htmlcov", "bower_components", "Pods", ".dart_tool",
            # Vendored bundles that ship *inside* a source tree. A checked-in
            # copy of a library under a test fixture is still a copy of the
            # library: analysing it reports the library's internals as this
            # repository's code. On microsoft/playwright, tests/assets holds
            # Browserify builds of React 15, whose module-loader parameter
            # ``_dereq_`` appeared 597 times in the unresolved-call count and
            # is not a call anyone in that repository makes. The directory
            # name ``assets`` is handled separately in RepositoryPolicy: it is
            # only ever a source directory when it sits under ``src``, so a
            # blanket entry here would throw away real code.
            "vendored", "third_party", "thirdparty", "fixtures",
            "testdata", "test-data", "__snapshots__",
        }
    )
    exclude_globs: tuple[str, ...] = (
        "*.min.js", "*.min.css", "*.map", "*.lock", "*.svg", "*.ico", "*.png",
        "*.jpg", "*.jpeg", "*.gif", "*.woff", "*.woff2", "*.ttf", "*.eot",
        "*.pdf", "*.zip", "*.tar", "*.gz", "*.xz", "*.7z", "*.rar",
        "*.pyc", "*.pyo", "*.class", "*.o", "*.a", "*.so", "*.dylib", "*.dll",
        "*.exe", "*.wasm", "*.jar", "*.bin", "*.db", "*.sqlite", "*.pdb",
    )
    sensitive_globs: tuple[str, ...] = (
        "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks",
        ".env", ".env.*", "id_rsa", "id_ed25519", "*.keystore", ".htpasswd",
        "credentials", "*.netrc", ".aws/credentials", "*.kdbx",
    )
    max_file_bytes: int = 2_000_000
    max_files: int = 20_000
    max_total_bytes: int = 512 * 1024 * 1024
    follow_symlinks: bool = False
    allow_generated: bool = False


@dataclass(frozen=True)
class RuntimeConfig:
    storage_path: str = "~/.understand/scans.db"
    mode: str = "local"                 # "local" or "hosted"
    local_roots: tuple[str, ...] = ()    # additional authorized roots in local mode
    security: SecurityPolicy = field(default_factory=SecurityPolicy)
    analysis: AnalysisPolicy = field(default_factory=AnalysisPolicy)
    telemetry: bool = False
    log_level: str = "INFO"
    max_workers: int = 8

    @property
    def storage_file(self) -> Path:
        p = Path(os.path.expanduser(self.storage_path))
        return p

    def with_overrides(self, **kw: object) -> RuntimeConfig:
        return replace(self, **kw)  # type: ignore[arg-type]


def _load_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(os.path.expanduser(path))
    if not p.is_file():
        raise ConfigurationError(f"config file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigurationError(f"config file {p} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"config file {p} must contain a JSON object")
    return data


def load_config(config_file: str | None = None) -> RuntimeConfig:
    """Build the effective configuration from file + environment + defaults."""
    raw = _load_file(config_file or _env("CONFIG"))

    sec_raw = {**(raw.get("security") or {})}  # type: ignore[arg-type]
    ana_raw = {**(raw.get("analysis") or {})}  # type: ignore[arg-type]

    allowed_hosts = sec_raw.get("allowed_hosts") or _env("ALLOWED_HOSTS") or ()
    if isinstance(allowed_hosts, str):
        allowed_hosts = tuple(h.strip() for h in allowed_hosts.split(",") if h.strip())
    allowed_hosts = tuple(allowed_hosts)

    roots = raw.get("local_roots") or _env("LOCAL_ROOTS") or ()
    if isinstance(roots, str):
        roots = tuple(r.strip() for r in roots.split(os.pathsep) if r.strip())
    roots = tuple(str(Path(os.path.expanduser(r)).resolve()) for r in roots)  # type: ignore[union-attr]

    sec = SecurityPolicy(
        allow_remote=bool(sec_raw.get("allow_remote", _env_bool("ALLOW_REMOTE", False))),
        allowed_hosts=allowed_hosts,
        block_private_networks=bool(sec_raw.get("block_private_networks", _env_bool("BLOCK_PRIVATE_NETWORKS", True))),
        allow_http=bool(sec_raw.get("allow_http", _env_bool("ALLOW_HTTP", False))),
        allow_ssh=bool(sec_raw.get("allow_ssh", _env_bool("ALLOW_SSH", False))),
        clone_depth=int(sec_raw.get("clone_depth", _env_int("CLONE_DEPTH", 25))),
        clone_timeout_seconds=float(sec_raw.get("clone_timeout_seconds", _env_float("CLONE_TIMEOUT", 120.0))),
        max_clone_bytes=int(sec_raw.get("max_clone_bytes", _env_int("MAX_CLONE_BYTES", 512 * 1024 * 1024))),
        recurse_submodules=bool(sec_raw.get("recurse_submodules", _env_bool("SUBMODULES", False))),
        allow_private_repo_credentials=bool(
            sec_raw.get("allow_private_repo_credentials", _env_bool("ALLOW_PRIVATE_CREDS", False))
        ),
        execute_repo_code=bool(sec_raw.get("execute_repo_code", False)),
    )

    ana = AnalysisPolicy(
        max_file_bytes=int(ana_raw.get("max_file_bytes", _env_int("MAX_FILE_BYTES", 2_000_000))),
        max_files=int(ana_raw.get("max_files", _env_int("MAX_FILES", 20_000))),
        max_total_bytes=int(ana_raw.get("max_total_bytes", _env_int("MAX_TOTAL_BYTES", 512 * 1024 * 1024))),
        follow_symlinks=bool(ana_raw.get("follow_symlinks", _env_bool("FOLLOW_SYMLINKS", False))),
    )

    mode = str(raw.get("mode") or _env("MODE") or "local").lower()
    if mode not in {"local", "hosted"}:
        raise ConfigurationError(f"mode must be 'local' or 'hosted', got {mode!r}")
    if mode == "hosted":
        # Hosted deployments must never implicitly trust private destinations.
        sec = replace(sec, allow_http=False, allow_ssh=False, block_private_networks=True,
                      allow_private_repo_credentials=False)

    return RuntimeConfig(
        storage_path=str(raw.get("storage_path") or _env("STORAGE") or "~/.understand/scans.db"),
        mode=mode,
        local_roots=roots,
        security=sec,
        analysis=ana,
        telemetry=_env_bool("TELEMETRY", False),
        log_level=str(raw.get("log_level") or _env("LOG_LEVEL") or "INFO").upper(),
        max_workers=int(raw.get("max_workers") or _env_int("WORKERS", 8)),
    )
