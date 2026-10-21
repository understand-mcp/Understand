"""Build the distributable MCPB bundle for UNDERSTAND.

A host can distribute a server as an ``.mcpb`` archive that clients run
locally over stdio. The archive needs three things: a manifest, the package
source, and a small entry point that makes the runtime dependencies available
on a machine that does not have them yet.

This script produces all three from the working tree, so the bundle is
reproducible from source instead of being uploaded by hand.

Usage::

    python tools/build_mcpb.py --out-dir dist

It requires the MCPB CLI::

    npm install -g @anthropic-ai/mcpb
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_VERSION = "0.4"
REPOSITORY_URL = "https://github.com/understand-mcp/Understand"

ENTRY_POINT = '''"""Entry point for the MCPB bundle.

The bundle ships the package source, but the runtime dependencies (the MCP SDK
and pydantic) are not bundled: pydantic ships a compiled extension that cannot
be copied between platforms. So the entry point tries the bundled source first
and, when the dependencies are missing, builds a local virtual environment
from the published wheel and re-executes itself with that interpreter.
"""

import os
import subprocess
import sys
import venv

BUNDLE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(BUNDLE_ROOT, "src")
VERSION = "{version}"


def _venv_python(root: str) -> str:
    if os.name == "nt":
        return os.path.join(root, "Scripts", "python.exe")
    return os.path.join(root, "bin", "python")


def _bootstrap() -> None:
    root = os.path.join(BUNDLE_ROOT, ".venv")
    python = _venv_python(root)
    if not os.path.isdir(root):
        venv.EnvBuilder(with_pip=True).create(root)
    subprocess.check_call([python, "-m", "pip", "install", "--quiet", f"understand-mcp=={{VERSION}}"])
    os.execv(python, [python, os.path.abspath(__file__)])


def main() -> None:
    if SOURCE not in sys.path:
        sys.path.insert(0, SOURCE)
    try:
        from understand.mcp.server import main as server_main
    except ImportError:
        _bootstrap()
        return
    server_main()


if __name__ == "__main__":
    main()
'''


def project_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def build_manifest(version: str) -> dict:
    return {
        "manifest_version": MANIFEST_VERSION,
        "name": "understand-mcp",
        "display_name": "UNDERSTAND",
        "version": version,
        "description": (
            "Repository-wide code intelligence, security and defect analysis "
            "with a CLI and an MCP server."
        ),
        "long_description": (
            "UNDERSTAND reads a repository, builds a symbol graph with twenty kinds of "
            "relation, and reports findings with an explicit statement of how strong "
            "the evidence is for each one."
        ),
        "author": {
            "name": "understand-mcp contributors",
            "url": REPOSITORY_URL,
        },
        "repository": {"type": "git", "url": REPOSITORY_URL},
        "homepage": REPOSITORY_URL,
        "documentation": f"{REPOSITORY_URL}/tree/main/docs",
        "support": f"{REPOSITORY_URL}/issues",
        "keywords": ["static-analysis", "security", "mcp", "code-intelligence", "sarif"],
        "license": "MIT",
        "server": {
            "type": "python",
            "entry_point": "server/main.py",
            "mcp_config": {
                "command": "python",
                "args": ["${__dirname}/server/main.py"],
                "env": {"UNDERSTAND_MCP_TRANSPORT": "stdio"},
            },
        },
        "tools_generated": True,
        "compatibility": {
            "platforms": ["darwin", "win32", "linux"],
            "runtimes": {"python": ">=3.11"},
        },
    }


def stage(staging: Path, version: str) -> None:
    (staging / "server").mkdir(parents=True, exist_ok=True)
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(REPO_ROOT / name, staging / name)
    shutil.copytree(
        REPO_ROOT / "src",
        staging / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (staging / "manifest.json").write_text(
        json.dumps(build_manifest(version), indent=2) + "\n",
        encoding="utf-8",
    )
    (staging / "server" / "main.py").write_text(
        ENTRY_POINT.format(version=version),
        encoding="utf-8",
    )


def pack(staging: Path, out_dir: Path, version: str) -> Path:
    executable = shutil.which("mcpb")
    if executable is None:
        raise SystemExit(
            "The MCPB CLI is not installed. Run: npm install -g @anthropic-ai/mcpb"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [executable, "pack", str(staging), str(out_dir / f"understand-mcp-{version}.mcpb")],
        check=True,
    )
    return out_dir / f"understand-mcp-{version}.mcpb"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the MCPB bundle for UNDERSTAND.")
    parser.add_argument(
        "--out-dir",
        default="dist",
        help="Where to write the .mcpb archive (default: dist).",
    )
    args = parser.parse_args()

    version = project_version()
    out_dir = (REPO_ROOT / args.out_dir).resolve()
    with tempfile.TemporaryDirectory(prefix="understand-mcpb-") as temporary:
        staging = Path(temporary)
        stage(staging, version)
        archive = pack(staging, out_dir, version)

    print(f"{archive} ({archive.stat().st_size} bytes, version {version})")


if __name__ == "__main__":
    main()
