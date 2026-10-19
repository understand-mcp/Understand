"""Dependency manifest parsing and dependency-vulnerability status reporting.

Vulnerability data is NEVER invented. If no trusted advisory source is
explicitly configured, the report says `not_performed` and explains why.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from understand.logging_config import get_logger
from understand.models import DependencyRecord, SupportLevel

log = get_logger("engine.dependencies")

ADVISORY_SOURCES = ("osv", "github-advisory-database")

_MANIFESTS: dict[str, tuple[str, str]] = {
    "package.json": ("npm", "node"),
    "package-lock.json": ("npm", "node-lock"),
    "yarn.lock": ("npm", "yarn"),
    "requirements.txt": ("pypi", "txt"),
    "requirements-dev.txt": ("pypi", "txt-dev"),
    "Pipfile": ("pypi", "pipenv"),
    "pyproject.toml": ("pypi", "pyproject"),
    "poetry.lock": ("pypi", "poetry"),
    "go.mod": ("go", "gomod"),
    "go.sum": ("go", "gosum"),
    "Cargo.toml": ("crates-io", "cargo"),
    "Cargo.lock": ("crates-io", "cargolock"),
    "pom.xml": ("maven", "pom"),
    "build.gradle": ("maven", "gradle"),
    "build.gradle.kts": ("maven", "gradle-kts"),
    "Gemfile": ("rubygems", "gemfile"),
    "composer.json": ("packagist", "composer"),
    "composer.lock": ("packagist", "composerlock"),
}

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(?:([<>=!~]=?[^;#\s]*)|@([^;#\s]+))?")
_GRADLE_RE = re.compile(r"""["']([\w.\-]+):([\w.\-]+):([\w.\-]+)["']""")


@dataclass
class DependencyAnalysis:
    records: list[DependencyRecord] = field(default_factory=list)
    ecosystems: set[str] = field(default_factory=set)
    vulnerability_status: str = "not_performed"
    vulnerability_reason: str = (
        "No trusted vulnerability advisory source is configured. "
        "UNDERSTAND never fabricates CVE identifiers or CVSS scores."
    )

    def to_records(self) -> list[DependencyRecord]:
        return self.records


def _read(path, relpath: str, max_bytes: int) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return ""


def _parse_json_manifest(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    pkgs: list[str] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(section)
        if isinstance(block, dict):
            pkgs.extend(f"{k}@{v}" for k, v in block.items() if isinstance(k, str))
    return pkgs


def _parse_requirements(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            out.append(line)
    return out


def _parse_pyproject(text: str) -> list[str]:
    out: list[str] = []
    try:
        import tomllib

        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return out
    project = data.get("project") or {}
    for dep in project.get("dependencies", []) or []:
        if isinstance(dep, str):
            out.append(dep)
    optional = project.get("optional-dependencies") or {}
    if isinstance(optional, dict):
        for group in optional.values():
            if isinstance(group, list):
                out.extend(str(d) for d in group)
    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for dep in (poetry.get("dependencies") or {}):
        if dep.lower() != "python":
            out.append(dep)
    return out


def _parse_gomod(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require (") or line in {"require ("}:
            continue
        m = re.match(r"^require\s+([\w./\-]+)\s+v[\w.\-+]+", line)
        if m:
            out.append(m.group(1))
    return out


def _parse_cargo(text: str) -> list[str]:
    out: list[str] = []
    try:
        import tomllib

        data = tomllib.loads(text)
    except Exception:  # noqa: BLE001
        return out
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section) or {}
        if isinstance(block, dict):
            out.extend(str(k) for k in block)
    return out


def _parse_gemfile(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if re.match(r"^\s*gem\s+['\"]", ln)]


def _parse_gradle(text: str) -> list[str]:
    return [f"{g}:{a}:{v}" for g, a, v in _GRADLE_RE.findall(text)]


def _parse_composer(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[str] = []
    for section in ("require", "require-dev"):
        block = data.get(section)
        if isinstance(block, dict):
            out.extend(f"{k}@{v}" for k, v in block.items() if k != "php")
    return out


_PARSERS = {
    "node": _parse_json_manifest,
    "node-lock": lambda t: [],
    "yarn": lambda t: [],
    "txt": _parse_requirements,
    "txt-dev": _parse_requirements,
    "pipenv": _parse_requirements,
    "pyproject": _parse_pyproject,
    "poetry": lambda t: [],
    "gomod": _parse_gomod,
    "gosum": lambda t: [],
    "cargo": _parse_cargo,
    "cargolock": lambda t: [],
    "pom": lambda t: [],
    "gradle": _parse_gradle,
    "gradle-kts": _parse_gradle,
    "gemfile": _parse_gemfile,
    "composer": _parse_composer,
    "composerlock": lambda t: [],
}


def analyze_dependencies(root, files: dict[str, str], *, max_bytes: int = 2_000_000) -> DependencyAnalysis:
    """Parse recognised manifests found in the inventory."""
    result = DependencyAnalysis()
    for relpath in sorted(files):
        name = PurePosixPath(relpath).name
        entry = _MANIFESTS.get(name)
        if entry is None:
            continue
        ecosystem, kind = entry
        if relpath.endswith((".lock", "-lock.json", ".sum")) and kind in {"node-lock", "yarn",
                                                                            "poetry", "cargolock",
                                                                            "gosum", "composerlock"}:
            result.records.append(DependencyRecord(
                ecosystem=ecosystem, manifest=relpath, packages=[],
                vulnerability_check="not_performed",
                note="lockfile present; parsed dependency set comes from the manifest",
            ))
            result.ecosystems.add(ecosystem)
            continue
        text = _read(root / relpath, relpath, max_bytes)
        parser = _PARSERS.get(kind)
        packages: list[str] = []
        if parser and text:
            try:
                packages = sorted({p.strip() for p in parser(text) if p.strip()})
            except Exception as exc:  # noqa: BLE001
                log.warning("dependency manifest %s could not be parsed: %s", relpath, exc)
                packages = []
        result.records.append(DependencyRecord(
            ecosystem=ecosystem, manifest=relpath, packages=packages[:500],
            vulnerability_check="not_performed", note=result.vulnerability_reason,
        ))
        result.ecosystems.add(ecosystem)
    return result


def dependency_status() -> tuple[str, str]:
    return "not_performed", DependencyAnalysis().vulnerability_reason


__all__ = ["analyze_dependencies", "dependency_status", "DependencyAnalysis", "SupportLevel"]