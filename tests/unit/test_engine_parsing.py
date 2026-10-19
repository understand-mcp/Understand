"""Unit tests for parsing, symbol indexing, call-graph construction and data flow."""

from __future__ import annotations

import pytest

from understand.engine.call_graph import build_call_graph
from understand.engine.data_flow import analyze_data_flow
from understand.engine.graph_snapshot import empty_snapshot, snapshot_graph
from understand.engine.parsing import make_symbol_id, strip_comments_and_strings
from understand.engine.symbol_index import SymbolIndex, parse_module
from understand.models import SupportLevel

PY_SOURCE = '''
"""Module docstring."""

import os
from app.service import run_command


def handler(request):
    value = request.args.get("host")
    return run_command(value)


class Service:
    """A service."""

    def run(self, value):
        return run_command(value)
'''

JS_SOURCE = """
// leading comment
import { helper } from "./helper.js";

export function outer(input) {
  return helper(input);
}

const arrow = (x) => {
  return inner(x);
};
"""


def test_strip_comments_and_strings_removes_noise() -> None:
    lines = [
        "# a comment",
        'value = "a # not a comment"',
        "other = 1  # trailing",
    ]
    sanitized, comments, _literals = strip_comments_and_strings(lines, ("#",), keep_literals=True)
    assert "a # not a comment" not in sanitized[1]
    assert comments[1] == "a comment"
    assert sanitized[2].strip().startswith("other = 1")


def test_strip_handles_block_comments() -> None:
    lines = ["/* start", "still inside", "end */ x = 1"]
    sanitized, _comments, _literals = strip_comments_and_strings(lines, ("//",), keep_literals=True)
    assert "still inside" not in "".join(sanitized)
    assert "x = 1" in sanitized[-1]


def test_parse_python_extracts_symbols_and_calls() -> None:
    module = parse_module("app/api.py", PY_SOURCE, "python")
    names = {s.name for s in module.symbols}
    assert {"handler", "Service", "run"} <= names
    service = next(s for s in module.symbols if s.name == "Service")
    assert service.kind == "class"
    run = next(s for s in module.symbols if s.name == "run")
    assert run.parent == service.id
    assert "run_command" in {c.callee_name for c in module.calls}
    # Cross-reference resolution is a later stage (build_call_graph), not the parser's job.
    assert all(not c.resolved_id for c in module.calls)
    assert module.is_usable


def test_parse_python_handles_syntax_errors_gracefully() -> None:
    module = parse_module("broken.py", "def oops(:\n    pass\n", "python")
    assert not module.is_usable
    assert module.parse_error


def test_parse_structural_js_symbols() -> None:
    module = parse_module("src/app.js", JS_SOURCE, "javascript")
    names = {s.name for s in module.symbols}
    assert "outer" in names
    assert "helper" in {c.callee_name for c in module.calls}
    assert any("helper" in spec for spec, _line, _raw in module.imports)


def test_parse_text_module_has_no_symbols() -> None:
    module = parse_module("notes.md", "# Title\n\ntext\n", "markdown")
    assert module.symbols == []
    # Prose is readable (so it counts as covered) but yields no symbols.
    assert module.is_usable
    assert module.support is not SupportLevel.FULL


def test_symbol_index_lookup_and_resolve() -> None:
    index = SymbolIndex()
    index.add(parse_module("app/api.py", PY_SOURCE, "python"))
    index.add(parse_module("app/service.py", "def run_command(v):\n    return v\n", "python"))
    assert index.get(make_symbol_id("app/api.py", "handler")) is not None
    assert index.lookup("handler")
    # Import resolution maps a module specifier to a repository file, not to a symbol.
    resolved = index.resolve_import("app/api.py", "app.service")
    assert resolved == "app/service.py"


def test_call_graph_resolves_and_traces(risky_index, risky_graph) -> None:
    graph = build_call_graph(risky_index)
    assert graph.edges
    handler_ids = [
        s.id
        for module in risky_index.modules.values()
        for s in module.symbols
        if s.name == "handle_ping"
    ]
    if handler_ids:
        paths = graph.trace(risky_index, handler_ids[0], max_depth=4, limit=10)
        assert paths
        # Paths are the edges walked out of the start symbol, so the first step
        # is a callee of handler_ping rather than handler_ping itself.
        outgoing = {e.dst for e in graph.outgoing.get(handler_ids[0], [])}
        assert outgoing
        assert all(path and path[0].node in outgoing for path in paths)
        # A step is either a resolved symbol or an honestly-recorded unresolved callee.
        assert all(
            step.node in risky_index.by_id or step.unresolved
            for path in paths
            for step in path
        )


def test_call_graph_records_unresolved_calls(risky_index) -> None:
    graph = build_call_graph(risky_index)
    index = SymbolIndex()
    index.add(
        parse_module(
            "dyn.py",
            "def go(obj):\n    return getattr(obj, 'maybe_missing')\n",
            "python",
        )
    )
    small = build_call_graph(index)
    assert small.edges
    assert any(edge.label for edge in small.edges)


def test_data_flow_reports_only_evidenced_flows(risky_index, risky_graph) -> None:
    flows = analyze_data_flow(risky_index, risky_graph, cross_module=True, deep=True)
    assert flows, "the risky fixture must produce at least one tainted flow"
    for flow in flows:
        assert flow.hops
        assert flow.hops[0].file
        assert flow.hops[0].line > 0
        assert isinstance(flow.proven, bool)
        payload = flow.to_dict()
        assert payload["source"] and payload["sink"]


def test_data_flow_without_cross_module_is_narrower(risky_index, risky_graph) -> None:
    narrow = analyze_data_flow(risky_index, risky_graph, cross_module=False, deep=False)
    wide = analyze_data_flow(risky_index, risky_graph, cross_module=True, deep=True)
    assert len(narrow) <= len(wide)


def test_graph_snapshot_shape(risky_index, risky_graph) -> None:
    snapshot = snapshot_graph(risky_index, risky_graph)
    assert "nodes" in snapshot and "edges" in snapshot
    assert snapshot["truncated"] is False
    node = next(iter(snapshot["nodes"].values()))
    assert {"id", "name", "kind", "file", "start_line", "end_line"} <= set(node)


def test_graph_snapshot_is_bounded(risky_index, risky_graph) -> None:
    snapshot = snapshot_graph(risky_index, risky_graph, max_nodes=1, max_edges=1)
    assert snapshot["truncated"] is True
    assert snapshot["nodes_omitted"] >= 0
    assert snapshot["edges_omitted"] >= 0


def test_empty_snapshot_is_usable() -> None:
    snapshot = empty_snapshot()
    assert snapshot["nodes"] == {}
    assert snapshot["edges"] == []
    assert snapshot["truncated"] is False


@pytest.mark.parametrize(
    "language,source",
    [
        ("python", "def f():\n    return 1\n"),
        ("javascript", "function f() { return 1; }\n"),
        ("go", "func f() int { return 1 }\n"),
        ("rust", "fn f() -> i32 { 1 }\n"),
        ("java", "class A { void f() {} }\n"),
        ("ruby", "def f\n  1\nend\n"),
        ("shell", "f() { echo hi; }\n"),
    ],
)
def test_language_parsers_do_not_crash(language: str, source: str) -> None:
    module = parse_module(f"sample.{language}", source, language)
    assert module.language == language
    assert isinstance(module.symbols, list)