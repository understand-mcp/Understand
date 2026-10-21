"""The version the tool reports must be the version of the package.

A tool that reports the wrong version is worse than a tool that reports none:
the number ends up in every report, in the SARIF ``analyzerVersion`` and in the
MCP server handshake. The literal lives in ``src/understand/__init__.py`` and the
package metadata lives in ``pyproject.toml``; this test is what keeps them one
number.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from understand import __version__

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def test_reported_version_matches_the_package() -> None:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert __version__ == data["project"]["version"]


def test_reported_version_is_not_a_placeholder() -> None:
    assert __version__.count(".") == 2
    assert all(part.isdigit() for part in __version__.split("."))
