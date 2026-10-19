"""Group a stored scan's findings by rule so a human can audit rule by rule.

Usage:
    python tools/audit_rules.py <scan_id> [severity] [db_path]

Example:
    python tools/audit_rules.py scan-20261018-24e9bea4 high

Why this exists
---------------
Severity counts are useless on their own: 316 "high" findings could be one
genuine bug reported 316 times, or 316 different real problems, or 300
false positives and 16 real ones. Nothing in the count distinguishes those.

So this prints, per rule, how many findings it produced, how many distinct
files those landed in, how many of those files are test or asset trees, and
one representative snippet to audit against the real source.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from understand.models import Severity
from understand.storage.scan_store import ScanStore

_TEST_MARKERS = (
    "/tests/",
    "/test/",
    "/assets/",
    "/vendor/",
    "/node_modules/",
    "/third_party/",
    "/examples/",
    "/fixtures/",
)


def _is_test_or_asset(file: str) -> bool:
    lowered = file.replace("\\", "/").lower()
    return any(marker in lowered for marker in _TEST_MARKERS)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 64
    scan_id = argv[1]
    wanted = Severity.parse(argv[2]) if len(argv) > 2 else None
    db = Path(argv[3]) if len(argv) > 3 else Path.home() / ".understand" / "scans.db"

    with ScanStore(db) as store:
        report = store.load_report(scan_id)

    grouped: dict[tuple[str, str], list] = defaultdict(list)
    for finding in report.findings:
        if wanted is not None and finding.severity != wanted:
            continue
        grouped[(finding.rule_id, finding.category)].append(finding)

    print(f"{scan_id}: {sum(len(v) for v in grouped.values())} findings, "
          f"{len(grouped)} distinct rules\n")

    rows = sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0][0]))
    for (rule_id, category), findings in rows:
        files = {f.evidence[0].file for f in findings if f.evidence}
        testish = sum(1 for f in findings if f.evidence and _is_test_or_asset(f.evidence[0].file))
        sample = findings[0]
        location = f"{sample.evidence[0].file}:{sample.evidence[0].start_line}" if sample.evidence else "(no location)"
        print(f"{rule_id}  [{category}]  x{len(findings)}  "
              f"files={len(files)}  test/asset={testish}")
        print(f"    title   : {sample.title}")
        print(f"    location: {location}")
        print(f"    snippet : {(sample.evidence[0].snippet if sample.evidence else '')[:120]!r}")
        print(f"    fix     : {sample.remediation[:150]}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
