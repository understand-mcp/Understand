"""Security-control tests: path traversal, SSRF, safe subprocess, redaction, policy."""

from __future__ import annotations

import os
from dataclasses import fields
from pathlib import Path

import pytest

from understand.config import AnalysisPolicy, RuntimeConfig, SecurityPolicy
from understand.errors import (
    AccessDeniedError,
    ConfigurationError,
    InvalidSourceError,
    NetworkPolicyError,
    ResourceLimitExceeded,
    ValidationError,
)
from understand.security.path_validation import (
    assert_local_source,
    is_hostile_filename,
    normalize_relpath,
    resolve_within,
)
from understand.security.redaction import (
    REDACTED,
    looks_like_secret,
    redact_obj,
    redact_snippet,
    redact_text,
)
from understand.security.repository_policy import RepositoryPolicy
from understand.security.safe_git import GitRemote, parse_git_url
from understand.security.sandbox import ExecutionPolicy, run_tool


# --------------------------------------------------------------------------- paths


@pytest.mark.parametrize(
    "candidate",
    [
        "../escape.py",
        "/etc/passwd",
        "C:\\Windows\\system32",
        "..\\..\\windows",
        "a/../../b",
        "with\x00nul.py",
        "with\nnewline.py",
        "",
    ],
)
def test_normalize_relpath_rejects_dangerous_paths(candidate: str) -> None:
    # The helper raises InvalidSourceError: a rejected path is an unusable source.
    with pytest.raises((InvalidSourceError, ValidationError)):
        normalize_relpath(candidate)


def test_normalize_relpath_accepts_safe_paths() -> None:
    assert normalize_relpath("app/api.py") == "app/api.py"
    assert normalize_relpath("./app//api.py") == "app/api.py"


@pytest.mark.parametrize(
    "name",
    ["CON", "con.txt", "PRN", "NUL", "COM1", "LPT9", "name.", "name ", "a*b", "a?b", 'a"b', "a|b"],
)
def test_is_hostile_filename(name: str) -> None:
    assert is_hostile_filename(name) is True


def test_is_hostile_filename_accepts_normal_names() -> None:
    assert is_hostile_filename("api.py") is False
    assert is_hostile_filename("Dockerfile") is False
    assert is_hostile_filename("a" * 200 + ".py") is False


def test_resolve_within_blocks_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "inside.txt").write_text("ok", encoding="utf-8")
    assert resolve_within(root, root / "inside.txt", allow_symlinks=False)
    # Escaping the root is reported as an access denial, which is what it is.
    with pytest.raises((AccessDeniedError, ValidationError)):
        resolve_within(root, root / ".." / "outside.txt", allow_symlinks=False)


def test_resolve_within_blocks_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:  # pragma: no cover - Windows without developer mode
        pytest.skip("symlinks unavailable")
    with pytest.raises((AccessDeniedError, ValidationError)):
        resolve_within(root, link, allow_symlinks=False)


def test_assert_local_source_requires_allowed_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    assert assert_local_source(repo, allowed_roots=(tmp_path,))
    # An empty allow-list means "no additional roots configured", not "deny all":
    # the loader resolves it from config.local_roots before calling in.
    assert assert_local_source(repo, allowed_roots=())
    outside = tmp_path.parent / "elsewhere"
    outside.mkdir(exist_ok=True)
    with pytest.raises(AccessDeniedError):
        assert_local_source(repo, allowed_roots=(str(outside),))


def test_assert_local_source_rejects_files_and_roots(tmp_path: Path) -> None:
    a_file = tmp_path / "f.txt"
    a_file.write_text("x", encoding="utf-8")
    with pytest.raises(InvalidSourceError):
        assert_local_source(a_file, allowed_roots=(tmp_path,))
    # A filesystem root is refused outright: scanning it would be unbounded.
    with pytest.raises((InvalidSourceError, AccessDeniedError)):
        assert_local_source(Path(a_file.anchor), allowed_roots=(str(Path(a_file.anchor)),))


def test_assert_local_source_rejects_missing(tmp_path: Path) -> None:
    with pytest.raises(InvalidSourceError):
        assert_local_source(tmp_path / "nope", allowed_roots=(tmp_path,))


# --------------------------------------------------------------------------- SSRF


def test_parse_git_url_accepts_public_https() -> None:
    remote = parse_git_url("https://github.com/owner/repo.git", SecurityPolicy())
    assert isinstance(remote, GitRemote)
    assert remote.host == "github.com"
    assert remote.path.endswith("owner/repo.git")


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo.git",  # http disabled by default
        "https://127.0.0.1/repo.git",
        "https://localhost/repo.git",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/repo.git",
        "https://10.0.0.5/repo.git",
        "https://192.168.1.1/repo.git",
        "https://0.0.0.0/repo.git",
        "https://metadata.google.internal/repo.git",
        "ssh://git@github.com/owner/repo.git",
        "file:///etc/passwd",
    ],
)
def test_parse_git_url_blocks_dangerous_remotes(url: str) -> None:
    with pytest.raises(NetworkPolicyError):
        parse_git_url(url, SecurityPolicy())


def test_parse_git_url_rejects_embedded_credentials() -> None:
    with pytest.raises(NetworkPolicyError):
        parse_git_url("https://user:token@github.com/owner/repo.git", SecurityPolicy())


def test_parse_git_url_rejects_argument_injection() -> None:
    with pytest.raises(NetworkPolicyError):
        parse_git_url("--upload-pack=evil", SecurityPolicy())
    with pytest.raises(NetworkPolicyError):
        parse_git_url("https://github.com/owner/repo.git --config=x", SecurityPolicy())


def test_parse_git_url_enforces_host_allowlist() -> None:
    policy = SecurityPolicy(allowed_hosts=("github.com",))
    assert parse_git_url("https://github.com/o/r.git", policy).host == "github.com"
    with pytest.raises(NetworkPolicyError):
        parse_git_url("https://gitlab.com/o/r.git", policy)


def test_parse_git_url_allows_hostless_domain_rejected() -> None:
    with pytest.raises(NetworkPolicyError):
        parse_git_url("https://-bad-.com/repo.git", SecurityPolicy())


def test_parse_git_url_returned_url_has_no_credentials() -> None:
    remote = parse_git_url("https://github.com/owner/repo.git", SecurityPolicy())
    assert "@" not in remote.url or remote.url.count("@") == 0


def test_ssh_requires_explicit_opt_in() -> None:
    policy = SecurityPolicy(allow_ssh=True)
    remote = parse_git_url("git@github.com:owner/repo.git", policy)
    assert remote.host == "github.com"
    assert remote.scheme == "ssh"


# --------------------------------------------------------------------------- redaction


@pytest.mark.parametrize(
    "text,secret",
    [
        ("key = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("token ghp_012345678901234567890123456789012345", "ghp_012345678901234567890123456789012345"),
        ("xoxb-1111-2222-abcdefghijklmnop", "xoxb-1111-2222-abcdefghijklmnop"),
        ("AIzaSyA1234567890abcdefghijklmnopqrstuv", "AIzaSyA1234567890abcdefghijklmnopqrstuv"),
        ("-----BEGIN RSA PRIVATE KEY-----", "BEGIN RSA PRIVATE KEY"),
        ("postgres://user:hunter2@db.example/app", "hunter2"),
        ('password = "s3cr3t-passphrase"', "s3cr3t-passphrase"),
    ],
)
def test_redact_text_removes_secrets(text: str, secret: str) -> None:
    redacted = redact_text(text)
    assert secret not in redacted
    assert REDACTED in redacted


def test_redact_text_keeps_benign_content() -> None:
    text = "def handler():\n    return 42\n"
    assert redact_text(text) == text


def test_redact_obj_walks_nested_structures() -> None:
    payload = {
        "a": [{"b": "AKIAIOSFODNN7EXAMPLE"}],
        "c": ("AKIAIOSFODNN7EXAMPLE",),
        "d": {"nested": "https://user:pw@example.com"},
    }
    redacted = redact_obj(payload)
    assert REDACTED in redacted["a"][0]["b"]
    # Tuples are walked too, and come back as JSON-friendly lists.
    assert redacted["c"] == [REDACTED]
    assert "pw" not in redacted["d"]["nested"]


def test_redact_obj_handles_pydantic() -> None:
    from pydantic import BaseModel

    class Model(BaseModel):
        token: str

    redacted = redact_obj(Model(token="ghp_012345678901234567890123456789012345"))
    assert redacted["token"] == REDACTED


def test_redact_snippet_truncates() -> None:
    snippet = "x" * 5000
    assert len(redact_snippet(snippet, limit=50)) <= 80


def test_looks_like_secret() -> None:
    assert looks_like_secret("AKIAIOSFODNN7EXAMPLE") is True
    assert looks_like_secret("hello world") is False


# --------------------------------------------------------------------------- sandbox


def test_run_tool_rejects_unlisted_executables() -> None:
    policy = ExecutionPolicy(allowed_executables=("git",))
    with pytest.raises((ValidationError, ConfigurationError)):
        run_tool(["python", "-c", "print(1)"], policy)


def test_run_tool_never_uses_a_shell(tmp_path: Path) -> None:
    policy = ExecutionPolicy(allowed_executables=("git",), default_timeout=10)
    result = run_tool(["git", "--version"], policy, cwd=tmp_path)
    assert result.ok is True
    assert "git" in result.stdout


def test_run_tool_enforces_timeout() -> None:
    policy = ExecutionPolicy(allowed_executables=("git",), default_timeout=0.05)
    # The budget is mandatory: an over-budget run is refused rather than awaited.
    try:
        result = run_tool(["git", "--version"], policy)
    except ResourceLimitExceeded:
        return
    assert result.ok is True and result.timed_out is False


def test_run_tool_does_not_inherit_shell_metacharacters(tmp_path: Path) -> None:
    policy = ExecutionPolicy(allowed_executables=("git",), default_timeout=10)
    result = run_tool(["git", "rev-parse", "--git-dir; rm -rf /"], policy, cwd=tmp_path)
    assert result.ok is False or "rm -rf" in (result.stderr or "")


def test_workspace_cleans_up() -> None:
    from understand.security.sandbox import Workspace

    workspace = Workspace()
    with workspace:
        path = workspace.path
        (path / "scratch.txt").write_text("x", encoding="utf-8")
        assert path.exists()
    assert not path.exists()


# --------------------------------------------------------------------------- policy


def test_vendored_bundles_inside_the_tree_are_excluded() -> None:
    """A checked-in library under a fixture is still a library.

    The exclusion list already covered ``vendor/`` and ``node_modules/``, but
    a repository that vendors a browserified copy of a library into
    ``tests/assets/`` has neither directory. Analysing that copy reports the
    library's internals as this repository's code: on microsoft/playwright the
    Browserify module-loader parameter ``_dereq_`` alone accounted for 597
    unresolved call targets, none of which is a call anyone in that
    repository makes.
    """

    from understand.config import AnalysisPolicy
    from understand.security.repository_policy import RepositoryPolicy

    policy = RepositoryPolicy(AnalysisPolicy())
    for path in (
        "tests/assets/reading-list/react-dom_15.7.0.js",
        "assets/bundle.min.js",
        "vendor/bundle.js",
        "third_party/zod/index.js",
        "testdata/golden.json",
    ):
        assert policy.decide(path).excluded, path

    # The exclusions must not reach ordinary source or ordinary tests.
    for path in (
        "packages/playwright/src/reporters/html.ts",
        "tests/library/client-certificates.spec.ts",
        "src/assets/icons.ts",
    ):
        assert not policy.decide(path).excluded, path


def test_repository_policy_excludes_vendor_generated_and_hidden(
    tmp_path: Path, risky_repo: str
) -> None:
    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(risky_repo,))
    assert policy.decide("node_modules/pkg/index.js").excluded
    assert policy.decide(".git/config").excluded
    assert policy.decide("vendor/thirdparty.py").excluded
    assert policy.decide("generated/schema_pb2.py").excluded
    assert not policy.decide("app/api.py").excluded


def test_repository_policy_marks_tests(risky_repo: str) -> None:
    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(risky_repo,))
    assert policy.is_test_path("tests/test_api.py") is True
    assert policy.is_test_path("app/api.py") is False


def test_repository_policy_records_reasons(risky_repo: str) -> None:
    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(risky_repo,))
    decision = policy.decide("node_modules/x.js")
    assert decision.excluded and decision.reason


def test_forbidden_names_are_blocked(tmp_path: Path) -> None:
    from understand.security.repository_policy import FORBIDDEN_NAMES

    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(str(tmp_path),))
    for name in list(FORBIDDEN_NAMES)[:5]:
        candidate = tmp_path / name
        assert policy.decide(name).excluded


def test_policy_honours_exclude_globs(tmp_path: Path) -> None:
    policy = RepositoryPolicy(
        AnalysisPolicy(exclude_globs=("*.secret",)), allowed_roots=(str(tmp_path),)
    )
    assert policy.decide("a/b.secret").excluded
    assert not policy.decide("a/b.py").excluded


def test_policy_guard_rejects_paths_outside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(str(root),))
    with pytest.raises((AccessDeniedError, ValidationError)):
        policy.guard(root, root / ".." / "escape.py")


def test_policy_guard_allows_files_inside_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(str(root),))
    assert policy.guard(root, root / "ok.py")


def test_max_file_bytes_is_enforced() -> None:
    policy = AnalysisPolicy(max_file_bytes=100)
    assert policy.max_file_bytes == 100


# --------------------------------------------------------------------------- config


def test_hosted_mode_hardens_network_policy() -> None:
    config = RuntimeConfig(mode="hosted", telemetry=False)
    assert config.security.allow_http is False
    assert config.security.allow_ssh is False
    assert config.security.block_private_networks is True
    assert config.security.execute_repo_code is False


def test_telemetry_defaults_off() -> None:
    assert RuntimeConfig().telemetry is False


def test_config_env_overrides(monkeypatch) -> None:
    monkeypatch.setenv("ALLOW_REMOTE", "0")
    monkeypatch.setenv("BLOCK_PRIVATE_NETWORKS", "true")
    config = RuntimeConfig()
    assert config.security.allow_remote is False


def test_config_file_is_loaded(tmp_path: Path) -> None:
    import json as _json

    from understand.config import load_config

    path = tmp_path / "cfg.json"
    path.write_text(_json.dumps({"security": {"allow_remote": False}, "max_workers": 3}), "utf-8")
    config = load_config(path)
    assert config.security.allow_remote is False
    assert config.max_workers == 3


def test_config_file_errors_are_configuration_errors(tmp_path: Path) -> None:
    from understand.config import load_config
    from understand.errors import ConfigurationError

    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_config(path)


def test_max_clone_bytes_is_settable(tmp_path: Path, monkeypatch) -> None:
    """The clone-size limit is enforced by the loader, so it must be settable."""
    import json as _json

    from understand.config import load_config

    path = tmp_path / "cfg.json"
    path.write_text(_json.dumps({"security": {"max_clone_bytes": 1234}}), "utf-8")
    assert load_config(path).security.max_clone_bytes == 1234

    monkeypatch.setenv("UNDERSTAND_MAX_CLONE_BYTES", "4321")
    assert load_config().security.max_clone_bytes == 4321


def test_clone_timeout_has_one_default_everywhere(monkeypatch) -> None:
    """A dataclass default that differs from load_config's is a silent trap."""
    from understand.config import SecurityPolicy, load_config

    monkeypatch.delenv("UNDERSTAND_CLONE_TIMEOUT", raising=False)
    assert load_config().security.clone_timeout_seconds == SecurityPolicy().clone_timeout_seconds

    monkeypatch.setenv("UNDERSTAND_CLONE_TIMEOUT", "45")
    assert load_config().security.clone_timeout_seconds == 45.0


def test_git_hook_switch_does_not_exist() -> None:
    """Hooks are always disabled; there is deliberately no switch to re-enable."""
    from understand.config import SecurityPolicy

    assert "respect_git_hooks" not in {f.name for f in fields(SecurityPolicy)}


def test_no_hardcoded_credentials_in_source() -> None:
    import re
    import subprocess

    root = Path(__file__).resolve().parents[2] / "src"
    pattern = re.compile(r"(password|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']{8,}[\"']", re.I)
    offenders: list[str] = []
    for file in root.rglob("*.py"):
        text = file.read_text(encoding="utf-8", errors="replace")
        if "getenv" in text or "environ" in text or "secret" in file.name:
            continue
        for line in text.splitlines():
            if "REDACTED" in line or "EXAMPLE" in line or "placeholder" in line.lower():
                continue
            if pattern.search(line):
                offenders.append(f"{file.name}: {line.strip()[:80]}")
    assert not offenders, offenders[:5]


def test_dockerfile_uses_non_root_user() -> None:
    dockerfile = Path(__file__).resolve().parents[2] / "Dockerfile"
    if not dockerfile.exists():
        pytest.skip("Dockerfile not present")
    text = dockerfile.read_text(encoding="utf-8")
    assert "USER " in text.upper()


def test_no_shell_true_in_source() -> None:
    root = Path(__file__).resolve().parents[2] / "src"
    offenders = []
    for file in root.rglob("*.py"):
        for number, line in enumerate(file.read_text(encoding="utf-8").splitlines(), 1):
            if "shell=True" in line:
                offenders.append(f"{file}:{number}")
    assert not offenders, offenders


def test_git_env_is_hardened() -> None:
    from understand.security.safe_git import _safe_git_env

    env = _safe_git_env()
    assert env.get("GIT_TERMINAL_PROMPT") == "0"
    assert env.get("GIT_CONFIG_NOSYSTEM") == "1"
    assert env.get("GIT_CONFIG_GLOBAL") == os.devnull


def test_git_disabled_when_missing(monkeypatch) -> None:
    from understand.security import safe_git

    monkeypatch.setattr(safe_git, "_git_executable", lambda: None)
    remote = parse_git_url("https://github.com/o/r.git", SecurityPolicy())
    with pytest.raises(ValidationError):
        safe_git.clone_remote(remote, SecurityPolicy(), None)