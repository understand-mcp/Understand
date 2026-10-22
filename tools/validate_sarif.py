"""Validate a rendered SARIF document against the official OASIS schema.

Usage:
    python tools/validate_sarif.py [path-to-sarif.json]

With no argument it renders the SARIF for tests/fixtures/repo_shell_risk and
validates that, so the check runs without producing a file first.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from understand.reporting.sarif_report import SARIF_SCHEMA, SARIF_SCHEMA_REPOSITORY  # noqa: E402

_CACHE = ROOT / "tools" / ".sarif-schema.json"


def load_schema(url: str) -> dict:
    if url == SARIF_SCHEMA and _CACHE.exists():
        return json.loads(_CACHE.read_text(encoding="utf-8"))
    with urllib.request.urlopen(url, timeout=60) as response:
        data = json.loads(response.read().decode("utf-8"))
    if url == SARIF_SCHEMA:
        _CACHE.write_text(json.dumps(data), encoding="utf-8")
    return data


def build() -> dict:
    import tempfile

    from understand.application.scan_service import ScanService
    from understand.config import AnalysisPolicy, RuntimeConfig, SecurityPolicy
    from understand.models import Check, Profile, ScanRequest
    from understand.reporting.sarif_report import sarif_dict

    with tempfile.TemporaryDirectory() as tmp:
        config = RuntimeConfig(
            storage_path=Path(tmp) / "validate.db",
            security=SecurityPolicy(allow_remote=False),
            analysis=AnalysisPolicy(),
            telemetry=False,
        )
        request = ScanRequest(
            repository=str(ROOT / "tests" / "fixtures" / "repo_shell_risk"),
            profile=Profile.DEEP,
            checks=(Check.SECURITY, Check.BUGS, Check.ARCHITECTURE, Check.RELIABILITY),
            cross_module=True,
        )
        with ScanService(config) as service:
            job = service.run_sync(request, timeout=180)
    if not job.succeeded:
        raise RuntimeError(f"the fixture scan failed: {job.error}")
    return sarif_dict(job.report)


def main(argv: list[str]) -> int:
    import jsonschema

    document = json.loads(Path(argv[0]).read_text(encoding="utf-8")) if argv else build()
    schema = load_schema(SARIF_SCHEMA)
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    print(f"document : {argv[0] if argv else '(rendered from tests/fixtures/repo_shell_risk)'}")
    print(f"$schema  : {document['$schema']}")
    print(f"version  : {document['version']}  runs={len(document['runs'])}")
    print(f"results  : {len(document['runs'][0]['results'])}")
    print(f"mirror   : {SARIF_SCHEMA_REPOSITORY}")
    if not errors:
        print("result   : VALID against the OASIS SARIF 2.1.0 schema")
        return 0
    print(f"result   : {len(errors)} schema violation(s)")
    for error in errors[:20]:
        location = "/".join(str(p) for p in error.absolute_path) or "<root>"
        print(f"  - {location}: {error.message}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
