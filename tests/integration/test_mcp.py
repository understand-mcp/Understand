"""Integration tests for the MCP tool box and server wiring."""

from __future__ import annotations

import json

import pytest

from understand.mcp.tools import ToolBox
from understand.mcp.schemas import (
    ChangeImpactInput,
    CodebaseQueryInput,
    ExecutionTraceInput,
    MAP_VIEWS,
    MapQueryInput,
    ScanRequestInput,
    validate,
)
from understand.errors import ValidationError


@pytest.fixture()
def box(session_config):
    with ToolBox(session_config) as toolbox:
        yield toolbox


@pytest.fixture()
def scan_id(box: ToolBox, risky_repo: str) -> str:
    result = box.scan_repository(
        repository=risky_repo,
        profile="deep",
        checks=["security", "bugs", "architecture", "reliability"],
        cross_module=True,
    )
    assert result["ok"] is True, result
    return result["scan_id"]


# --------------------------------------------------------------------------- schemas


def test_scan_request_input_defaults() -> None:
    payload = validate(ScanRequestInput, {"repository": "."})
    assert payload.repository == "."
    assert payload.checks in ((), None) or isinstance(payload.checks, list)


def test_scan_request_input_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        validate(ScanRequestInput, {"repository": ".", "shell": "rm -rf /"})


def test_scan_request_input_rejects_bad_profile() -> None:
    with pytest.raises(ValidationError):
        validate(ScanRequestInput, {"repository": ".", "profile": "turbo"})


def test_change_impact_requires_files() -> None:
    with pytest.raises(ValidationError):
        validate(ChangeImpactInput, {"scan_id": "s", "changed_files": []})


def test_execution_trace_requires_symbol() -> None:
    with pytest.raises(ValidationError):
        validate(ExecutionTraceInput, {"scan_id": "s"})


def test_codebase_query_validates_types() -> None:
    with pytest.raises(ValidationError):
        validate(CodebaseQueryInput, {"scan_id": "s", "query": 5})


# --------------------------------------------------------------------------- tools


def test_scan_repository_returns_scan_id(box: ToolBox, risky_repo: str) -> None:
    result = box.scan_repository(repository=risky_repo, profile="deep", checks=["security"])
    assert result["ok"] is True
    assert result["scan_id"].startswith("scan-")
    assert "status" in result


def test_get_scan_status(box: ToolBox, scan_id: str) -> None:
    status = box.get_scan_status(scan_id=scan_id)
    assert status["ok"] is True
    assert status["status"] == "completed"


def test_get_scan_status_unknown_is_soft_failure(box: ToolBox) -> None:
    status = box.get_scan_status(scan_id="scan-nope")
    assert status["ok"] is False
    assert status["error"]["code"] == "scan_not_found"


def test_get_scan_report_with_filters(box: ToolBox, scan_id: str) -> None:
    report = box.get_scan_report(scan_id=scan_id, severity="critical", limit=10)
    assert report["ok"] is True
    for finding in report["findings"]:
        assert finding["severity"] == "critical"


def test_get_scan_report_paginates(box: ToolBox, scan_id: str) -> None:
    first = box.get_scan_report(scan_id=scan_id, limit=1, offset=0)
    assert len(first["findings"]) <= 1
    if first["pagination"]["total"] > 1:
        second = box.get_scan_report(scan_id=scan_id, limit=1, offset=1)
        assert second["findings"][0]["finding_id"] != first["findings"][0]["finding_id"]


def test_inspect_finding(box: ToolBox, scan_id: str) -> None:
    report = box.get_scan_report(scan_id=scan_id, limit=1)
    finding_id = report["findings"][0]["finding_id"]
    detail = box.inspect_finding(scan_id=scan_id, finding_id=finding_id)
    assert detail["ok"] is True
    assert detail["finding"]["evidence"]
    assert "interpretation" in detail


def test_inspect_finding_unknown(box: ToolBox, scan_id: str) -> None:
    detail = box.inspect_finding(scan_id=scan_id, finding_id="NOPE-0000000000")
    assert detail["ok"] is False


def test_trace_execution(box: ToolBox, scan_id: str) -> None:
    result = box.trace_execution(scan_id=scan_id, symbol="handle_ping")
    assert result["ok"] is True
    assert "paths" in result


def test_trace_data_flow(box: ToolBox, scan_id: str) -> None:
    report = box.get_scan_report(scan_id=scan_id, rule_id="SEC-FLOW-001", limit=5)
    if not report["findings"]:
        pytest.skip("no flow findings in fixture")
    result = box.trace_data_flow(scan_id=scan_id, finding_id=report["findings"][0]["finding_id"])
    assert result["ok"] is True
    assert result["flows"]


def test_analyze_change_impact(box: ToolBox, scan_id: str) -> None:
    result = box.analyze_change_impact(scan_id=scan_id, changed_files=["app/api.py"])
    assert result["ok"] is True
    assert "impacted_callers" in result


def test_analyze_change_impact_requires_files(box: ToolBox, scan_id: str) -> None:
    result = box.analyze_change_impact(scan_id=scan_id, changed_files=[])
    assert result["ok"] is False


def test_query_codebase(box: ToolBox, scan_id: str) -> None:
    result = box.query_codebase(scan_id=scan_id, query="handle_ping")
    assert result["ok"] is True
    assert "provenance" in result


def test_query_codebase_requires_query(box: ToolBox, scan_id: str) -> None:
    result = box.query_codebase(scan_id=scan_id, query="")
    assert result["ok"] is False


def test_cancel_scan_unknown_is_soft(box: ToolBox) -> None:
    result = box.cancel_scan(scan_id="scan-nope")
    assert result["ok"] is False


def test_every_tool_returns_json_serialisable_output(box: ToolBox, scan_id: str) -> None:
    for result in (
        box.get_scan_status(scan_id=scan_id),
        box.get_scan_report(scan_id=scan_id, limit=3),
        box.trace_execution(scan_id=scan_id, symbol="handle_ping"),
        box.analyze_change_impact(scan_id=scan_id, changed_files=["app/api.py"]),
        box.query_codebase(scan_id=scan_id, query="api"),
    ):
        json.dumps(result)


def test_tool_outputs_are_redacted(box: ToolBox, risky_repo: str) -> None:
    result = box.scan_repository(
        repository=risky_repo, profile="deep", checks=["security"], include_evidence=True
    )
    report = box.get_scan_report(scan_id=result["scan_id"], limit=50)
    blob = json.dumps(report)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob


# --------------------------------------------------------------------------- server


def test_server_registers_every_tool(session_config) -> None:
    from understand.mcp.server import build_server

    server = build_server(session_config)
    import asyncio

    tools = asyncio.run(server.list_tools())
    names = {tool.name for tool in tools}
    assert {
        "scan_repository",
        "get_scan_report",
        "inspect_finding",
        "trace_execution",
        "trace_data_flow",
        "analyze_change_impact",
        "query_codebase",
        "get_scan_status",
    } <= names


def test_tool_schemas_have_real_properties(session_config) -> None:
    import asyncio

    from understand.mcp.server import build_server

    server = build_server(session_config)
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    schema = tools["scan_repository"].input_schema
    assert "properties" in schema
    assert "repository" in schema["properties"]
    assert schema.get("required") == ["repository"]


def test_no_filesystem_or_shell_tools_are_exposed(session_config) -> None:
    import asyncio

    from understand.mcp.server import build_server

    server = build_server(session_config)
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    for forbidden in ("read_file", "write_file", "list_directory", "run_command", "execute_python"):
        assert forbidden not in names


def test_server_exposes_capabilities_resource(session_config) -> None:
    import asyncio

    from understand.mcp.server import build_server

    server = build_server(session_config)
    uris = {str(resource.uri) for resource in asyncio.run(server.list_resources())}
    assert "understand://capabilities" in uris


def test_server_handles_unknown_scan_without_raising(session_config) -> None:
    import asyncio

    from understand.mcp.server import build_server

    server = build_server(session_config)
    result = asyncio.run(server.call_tool("get_scan_status", {"scan_id": "scan-nope"}))
    payload = json.loads(result.content[0].text)
    assert payload["ok"] is False
# --------------------------------------------------------------------------- code map


def test_map_query_input_defaults() -> None:
    payload = validate(MapQueryInput, {"scan_id": "scan-x"})
    assert payload.view == "module"
    assert payload.root == ""
    assert payload.depth == 3
    assert payload.direction == "both"
    assert payload.include_findings is True


def test_map_query_input_every_view_is_accepted() -> None:
    for view in MAP_VIEWS:
        assert validate(MapQueryInput, {"scan_id": "scan-x", "view": view}).view == view


def test_map_query_input_rejects_an_unknown_view() -> None:
    with pytest.raises(ValidationError):
        validate(MapQueryInput, {"scan_id": "scan-x", "view": "vibes"})


@pytest.mark.parametrize(
    "overrides",
    [
        {"depth": 7},
        {"depth": -1},
        {"max_nodes": 9},
        {"max_nodes": 20001},
        {"max_edges": 0},
        {"direction": "sideways"},
        {"root": "x" * 600},
        {"kinds": ["calls"] * 21},
    ],
)
def test_map_query_input_refuses_what_a_reader_cannot_use(overrides: dict) -> None:
    payload = {"scan_id": "scan-x", **overrides}
    with pytest.raises(ValidationError):
        validate(MapQueryInput, payload)


def test_map_query_input_forbids_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        validate(MapQueryInput, {"scan_id": "scan-x", "html": "yes please"})


def test_get_code_map_returns_a_bounded_model(box: ToolBox, scan_id: str) -> None:
    result = box.get_code_map(scan_id=scan_id, max_nodes=120, max_edges=300)
    assert result["ok"] is True, result
    model = result["map"]
    assert len(model["nodes"]) <= 120
    assert len(model["edges"]) <= 300
    assert model["stats"]["nodes"] == len(model["nodes"])


def test_get_code_map_carries_the_question_and_the_caveats(box: ToolBox, scan_id: str) -> None:
    result = box.get_code_map(scan_id=scan_id)
    assert result["question"]
    # A map without its caveats is a map that will be read as more certain
    # than the analysis behind it.
    assert result["map"]["honesty"]["caveats"]
    assert "false claim" in result["provenance"]["note"]


def test_get_code_map_html_is_opt_in(box: ToolBox, scan_id: str) -> None:
    plain = box.get_code_map(scan_id=scan_id, max_nodes=20, max_edges=40)
    assert "html" not in plain
    with_html = box.get_code_map(scan_id=scan_id, max_nodes=20, max_edges=40, html=True)
    assert "<canvas" in with_html["html"]


def test_get_code_map_rejects_an_unknown_scan(box: ToolBox) -> None:
    result = box.get_code_map(scan_id="scan-does-not-exist")
    assert result["ok"] is False
    assert result["error"]["code"] == "scan_not_found"


def test_get_code_map_rejects_an_unknown_view(box: ToolBox, scan_id: str) -> None:
    result = box.get_code_map(scan_id=scan_id, view="vibes")
    assert result["ok"] is False
    # A schema rejection is reported as validation_error, not invalid_input:
    # "invalid_input" means the argument was well formed but the wrong shape
    # for the tool, while a value outside the declared set never got that far.
    assert result["error"]["code"] == "validation_error"
