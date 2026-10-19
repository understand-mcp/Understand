"""List every critical finding of a scan with its evidence, for auditing."""
import sys
from pathlib import Path

from understand.models import Severity
from understand.storage.scan_store import ScanStore

scan_id = sys.argv[1]
severity = sys.argv[2] if len(sys.argv) > 2 else "critical"
db = Path(sys.argv[3]).expanduser() if len(sys.argv) > 3 else Path.home() / ".understand" / "scans.db"

with ScanStore(db) as store:
    report = store.load_report(scan_id)

wanted = getattr(Severity, severity.upper())
rows = [f for f in report.findings if f.severity == wanted]
print(f"{scan_id}: {len(rows)} {severity} findings\n")
for f in rows:
    ev = f.evidence[0] if f.evidence else None
    loc = f"{ev.file}:{ev.start_line}" if ev else "(no location)"
    snippet = (ev.snippet or "").replace("\n", " ")[:110] if ev else ""
    print(f"{f.rule_id:<18} {f.category:<22} {f.verification_status:<20} {loc}")
    print(f"    title : {f.title}")
    print(f"    source: {snippet}")
    print()