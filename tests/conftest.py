"""Shared pytest fixtures for the UNDERSTAND test-suite."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, str(SRC))

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def pytest_configure(config: pytest.Config) -> None:
    os.environ.setdefault("UNDERSTAND_TELEMETRY", "0")


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture(scope="session")
def risky_repo() -> str:
    return str(FIXTURES / "repo_shell_risk")


@pytest.fixture(scope="session")
def minimal_repo() -> str:
    return str(FIXTURES / "repo_minimal")


@pytest.fixture(scope="session")
def mixed_repo() -> str:
    return str(FIXTURES / "repo_mixed_content")


@pytest.fixture()
def config(tmp_path: Path):
    """A RuntimeConfig isolated to a per-test temporary database."""
    from understand.config import AnalysisPolicy, RuntimeConfig, SecurityPolicy

    return RuntimeConfig(
        storage_path=str(tmp_path / "understand.db"),
        security=SecurityPolicy(allow_remote=False),
        analysis=AnalysisPolicy(),
        telemetry=False,
    )


@pytest.fixture()
def store(config):
    from understand.storage import ScanStore

    with ScanStore(config.storage_path) as st:
        st.initialize()
        yield st


@pytest.fixture(scope="session")
def risky_index(risky_repo: str):
    """Parsed symbol index for the risky fixture (built once per session)."""
    from understand.config import AnalysisPolicy
    from understand.engine.symbol_index import SymbolIndex, parse_module
    from understand.security.repository_policy import RepositoryPolicy

    policy = RepositoryPolicy(AnalysisPolicy(), allowed_roots=(risky_repo,))
    index = SymbolIndex()
    for path in sorted((__import__("pathlib").Path(risky_repo)).rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(risky_repo).as_posix()
        if policy.decide(rel).excluded:
            continue
        if path.suffix not in {".py", ".js", ".ts"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lang = "python" if path.suffix == ".py" else "javascript"
        index.add(parse_module(rel, text, lang))
    return index


@pytest.fixture(scope="session")
def risky_graph(risky_index):
    from understand.engine.call_graph import build_call_graph

    return build_call_graph(risky_index)


@pytest.fixture(scope="session")
def session_db(tmp_path_factory) -> Path:
    return tmp_path_factory.mktemp("understand-session") / "understand.db"


@pytest.fixture(scope="session")
def session_config(session_db: Path):
    from understand.config import AnalysisPolicy, RuntimeConfig, SecurityPolicy

    return RuntimeConfig(
        storage_path=str(session_db),
        security=SecurityPolicy(allow_remote=False),
        analysis=AnalysisPolicy(),
        telemetry=False,
    )


@pytest.fixture(scope="session")
def risky_scan_id(risky_repo: str, session_config) -> Iterator[str]:
    """Run the risky fixture once and yield its scan id."""
    from understand.application import ScanService
    from understand.models import Check, Profile, ScanRequest

    request = ScanRequest(
        repository=risky_repo,
        profile=Profile.DEEP,
        checks=(Check.SECURITY, Check.BUGS, Check.ARCHITECTURE, Check.RELIABILITY),
        cross_module=True,
    )
    with ScanService(session_config) as service:
        job = service.run_sync(request, timeout=180)
        assert job.succeeded, job.error
        yield job.scan_id


@pytest.fixture(scope="session")
def risky_report(risky_scan_id: str, session_config):
    from understand.application import ScanService

    with ScanService(session_config) as service:
        yield service.report(risky_scan_id)


@pytest.fixture(scope="session")
def minimal_scan_id(minimal_repo: str, session_config) -> str:
    from understand.application import ScanService
    from understand.models import Check, Profile, ScanRequest

    request = ScanRequest(
        repository=minimal_repo,
        profile=Profile.DEEP,
        checks=(Check.SECURITY, Check.BUGS, Check.ARCHITECTURE, Check.RELIABILITY),
        cross_module=True,
    )
    with ScanService(session_config) as service:
        job = service.run_sync(request, timeout=180)
        assert job.succeeded, job.error
        return job.scan_id
