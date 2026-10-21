"""Sandbox helpers: temporary workspaces and resource-limited execution.

UNDERSTAND never executes analysed repository code. The only subprocess it ever
runs is `git` (with an explicit argv, hooks disabled), and optionally
user-configured external static-analysis tools via :func:`run_tool`.

`run_tool` exists so external analyzers can be added without granting arbitrary
command execution: the executable must be in the configured allowlist, arguments
are passed as an array, and a timeout is mandatory.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from understand.errors import ConfigurationError, ResourceLimitExceeded

DEFAULT_TIMEOUT = 60.0


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass
class ExecutionPolicy:
    """Explicit allowlist for external analysis tools."""

    allowed_executables: frozenset[str] = field(default_factory=frozenset)
    default_timeout: float = DEFAULT_TIMEOUT
    max_output_bytes: int = 8 * 1024 * 1024
    env_allowlist: tuple[str, ...] = ("PATH", "HOME", "TEMP", "TMP", "SYSTEMROOT", "SystemRoot")

    def permits(self, executable: str) -> bool:
        name = Path(executable).name.lower()
        if name.endswith(".exe"):
            name = name[:-4]
        if name in self.allowed_executables:
            return True
        resolved = shutil.which(executable)
        if not resolved:
            return False
        return bool(resolved) and Path(resolved).name.lower() in {
            e.lower() for e in self.allowed_executables
        }


class Workspace:
    """A temporary directory that is always cleaned up."""

    def __init__(self, prefix: str = "understand-") -> None:
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._prefix = prefix

    def __enter__(self) -> Path:
        self._tmp = tempfile.TemporaryDirectory(prefix=self._prefix)
        return Path(self._tmp.name)

    @property
    def path(self) -> Path:
        """The temporary directory, while the workspace is open."""

        if self._tmp is None:
            raise ConfigurationError("workspace is not open")
        return Path(self._tmp.name)

    def __exit__(self, *exc: object) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None


def run_tool(
    argv: list[str],
    policy: ExecutionPolicy,
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    extra_env: dict[str, str] | None = None,
) -> ToolResult:
    """Run an allowlisted external analyzer with a hard timeout."""
    if not argv:
        raise ConfigurationError("empty command")
    if not policy.permits(argv[0]):
        raise ConfigurationError(
            f"external tool {argv[0]!r} is not in the analyzer allowlist"
        )
    env = {k: os.environ[k] for k in policy.env_allowlist if k in os.environ}
    if extra_env:
        env.update(extra_env)
    env.setdefault("LC_ALL", "C")
    limit = timeout or policy.default_timeout
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            timeout=limit,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ResourceLimitExceeded(f"{argv[0]} timed out after {limit:.0f}s") from exc
    except OSError as exc:
        return ToolResult(list(argv), -1, "", str(exc))

    def cap(data: str) -> str:
        if len(data) > policy.max_output_bytes:
            return data[: policy.max_output_bytes] + "\n[output truncated]"
        return data

    return ToolResult(list(argv), proc.returncode, cap(proc.stdout or ""), cap(proc.stderr or ""))


def sandbox_notes() -> list[str]:
    """Residual-risk statements surfaced in documentation and reports."""
    return [
        "UNDERSTAND does not execute analysed repository code during a scan.",
        "Untrusted repository files are read as data only; instructions inside them are never followed.",
        "git is invoked with hooks disabled, no shell, credential helpers disabled and prompts disabled.",
        "Only `git` and explicitly allowlisted external analyzers may be executed.",
        "A container runtime alone is not a security guarantee; see docs/security-model.md.",
    ]
