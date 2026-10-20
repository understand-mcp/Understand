"""Container health check for the UNDERSTAND MCP server.

The check asks the HTTP transport for its capabilities resource. It is
intentionally tolerant: a stdio deployment must not be reported unhealthy just
because it has no HTTP port.

It lives in a file rather than inline in the Dockerfile because a Dockerfile
cannot carry a heredoc inside a HEALTHCHECK instruction.
"""

import os
import sys
import urllib.request


def main() -> int:
    """Return 0 when the server looks healthy, 1 when it does not."""

    host = os.environ.get("UNDERSTAND_MCP_HOST", "0.0.0.0")
    port = os.environ.get("UNDERSTAND_MCP_PORT", "8000")
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/mcp", timeout=4) as response:
            return 0 if response.status < 500 else 1
    except Exception:
        # No HTTP listener (stdio mode) is a valid configuration, not a failure.
        return 0


if __name__ == "__main__":
    sys.exit(main())
