"""Model Context Protocol surface for UNDERSTAND.

The MCP server is an *interface* over the same application services the CLI
uses. It adds validation and machine-readable envelopes; it never adds analysis
behaviour, and it exposes no shell, filesystem or code-execution tool.
"""

from __future__ import annotations

__all__ = ["ToolBox", "build_server", "build_toolbox", "run"]


def __getattr__(name: str):
    """Lazy re-exports so importing ``understand.mcp`` stays cheap."""

    if name in ("ToolBox", "build_toolbox"):
        from understand.mcp.tools import ToolBox, build_toolbox

        return {"ToolBox": ToolBox, "build_toolbox": build_toolbox}[name]
    if name in ("build_server", "run"):
        from understand.mcp import server as _server

        return getattr(_server, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")