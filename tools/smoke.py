from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from understand.application import FindingService, ImpactService, ReportService, ScanService, TraceService
from understand.config import RuntimeConfig
from understand.models import Check, Profile, ScanRequest

config = RuntimeConfig(storage_path=":memory:")
service = ScanService(config).open()
report_service = ReportService(service.store)
finding_service = FindingService(service.store)

for fixture in ("repo_shell_risk", "repo_minimal", "repo_mixed_content"):
    request = ScanRequest(
        repository=str(Path("tests/fixtures") / fixture),
        profile=Profile.DEEP,
        checks=(Check.SECURITY, Check.BUGS, Check.ARCHITECTURE, Check.RELIABILITY, Check.DEPENDENCIES),
        cross_module=True,
    )
    job = service.run_sync(request, timeout=120)
    print("=" * 70)
    print(fixture, "->", job.status, "err:", job.error)
    if job.report is None:
        continue
    report = job.report
    print("findings:", len(report.findings), report.findings_by_severity)
    for finding in report.findings[:6]:
        loc = finding.evidence[0].file if finding.evidence else "-"
        line = finding.evidence[0].start_line if finding.evidence else 0
        print(f"  {finding.finding_id:<26} {finding.severity.value:<8} {finding.rule_id:<22} {loc}:{line}")
    print("coverage:", report.coverage.files_analyzed, "files,", report.coverage.symbols, "symbols,",
          report.coverage.edges, "edges,", report.coverage.unresolved_calls, "unresolved")
    print("languages:", [(r.language, r.support.value, r.files) for r in report.languages])
    print("deps:", [(d.ecosystem, len(d.packages), d.vulnerability_check) for d in report.dependencies])
    print("limitations:", len(report.limitations))
    snapshot = report.graph_snapshot
    print("snapshot nodes/edges:", len(snapshot.get("nodes", {})), len(snapshot.get("edges", [])))

    tracer = TraceService(report)
    traced = tracer.trace_execution("handle_ping", direction="downstream", max_depth=3)
    print("trace handle_ping paths:", traced.get("path_count"))
    flows = tracer.trace_data_flow()
    print("data flows:", flows["count"])

    impact = ImpactService(report).analyze(["app/api.py"])
    print("impact counts:", impact["counts"])

    page = finding_service.query_report(report, severity="high", limit=3)
    print("query high:", page.total, [f["finding_id"] for f in page.items])
    payload = report_service.payload(report, findings=page)
    print("payload keys:", sorted(payload)[:8], "...")

    from understand.reporting import render_report
    sarif = render_report(report, "sarif")
    print("sarif bytes:", len(sarif))
    import json
    doc = json.loads(sarif)
    print("sarif version:", doc["version"], "results:", len(doc["runs"][0]["results"]))

service.close()
print("SMOKE OK")
