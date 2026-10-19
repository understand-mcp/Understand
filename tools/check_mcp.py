import asyncio

from understand.mcp.server import build_server
from understand.mcp.tools import ToolBox

tb = ToolBox()
s = build_server(tb)
tools = asyncio.run(s.list_tools())
for t in sorted(tools, key=lambda x: x.name):
    schema = t.input_schema or {}
    props = list(schema.get("properties") or {})
    print(t.name, "| required:", schema.get("required"), "| props:", len(props))

print("--- unknown scan id (application error -> envelope) ---")
r = asyncio.run(s.call_tool("get_scan_status", {"scan_id": "nope"}))
for c in r:
    print(getattr(c, "text", "")[:260])

print("--- unknown finding id ---")
r = asyncio.run(s.call_tool("inspect_finding", {"finding_id": "SEC-SQL-001-deadbeef"}))
for c in r:
    print(getattr(c, "text", "")[:260])

print("--- resource read ---")
res = asyncio.run(s.read_resource("understand://security-model"))
print(str(res)[:120])
tb.close()