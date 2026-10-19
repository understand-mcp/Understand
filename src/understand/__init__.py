"""UNDERSTAND - repository-wide code intelligence and analysis engine.

One engine, two interfaces: a professional CLI and an MCP server that both
call the same application services, analysis pipeline and reporting code.
"""

from __future__ import annotations

__all__ = ["__version__", "TOOL_NAME", "REPORT_SCHEMA_VERSION"]

__version__ = "0.1.0"
TOOL_NAME = "understand"
REPORT_SCHEMA_VERSION = "1.0"