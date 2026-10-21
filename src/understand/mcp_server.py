"""Console entry point: ``python -m understand.mcp_server``.

Kept as a thin module so the package can be launched by a hosted platform, Docker and
plain ``python -m`` without importing anything else first.
"""

from __future__ import annotations

from understand.mcp.server import main

if __name__ == "__main__":
    raise SystemExit(main())
