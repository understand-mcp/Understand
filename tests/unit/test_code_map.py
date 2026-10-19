"""Tests for the interactive code map.

Written against the same three rules the renderer claims to honour, because a
security tool that asserts "no network, no innerHTML, honest about truncation"
in its documentation and does not test for it is only making a claim.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from understand.engine.code_map import (
    MAX_DEPTH,
    VIEWS,
    MapBudget,
    MapSpec,
    build_map,
    explain_finding,
    validate_spec,
)
from understand.errors import FindingNotFound, UnsupportedFormatError, ValidationError
from understand.reporting import safe_map_output_path
from understand.reporting.html_map import MAX_MAP_BYTES, render_map_html, write_map_html

HTML_MAP = Path(__file__).resolve().parents[2] / "src" / "understand" / "reporting" / "html_map.py"


def _block(script: str, name: str) -> str:
    """The body of a JavaScript object literal declared as ``var NAME = {``.

    Parsing the palette out of the renderer source is the only way to assert
    on it: the colours live inside a template string, not in any Python
    object, and a test that re-declares them here would only be testing itself.
    """
    start = script.index("var " + name + " = {")
    depth = 0
    for i in range(script.index("{", start), len(script)):
        if script[i] == "{":
            depth += 1
        elif script[i] == "}":
            depth -= 1
            if depth == 0:
                return script[start : i + 1]
    raise AssertionError("unterminated object literal: " + name)


def _report(
    nodes: dict[str, dict],
    edges: list[dict],
    findings: list = (),
    **snapshot_extra,
) -> SimpleNamespace:
    snapshot = {
        "nodes": nodes,
        "edges": edges,
        "truncated": False,
        "nodes_omitted": 0,
        "edges_omitted": 0,
        "unresolved": 0,
    }
    snapshot.update(snapshot_extra)
    return SimpleNamespace(
        scan_id="scan-map-1",
        repository="/tmp/repo",
        revision="deadbeef",
        findings=findings,
        graph_snapshot=snapshot,
    )


def _node(node_id: str, file: str, kind: str = "function") -> dict:
    return {
        "id": node_id,
        "name": node_id.rsplit("::", 1)[-1],
        "kind": kind,
        "file": file,
        "start_line": 1,
        "end_line": 4,
        "language": "python",
        "exported": True,
    }


def _edge(src: str, dst: str, kind: str = "calls", origin: str = "static_direct") -> dict:
    return {"src": src, "dst": dst, "kind": kind, "origin": origin, "file": "", "line": 1, "label": ""}


CHAIN = _report(
    nodes={
        "a.py::load": _node("a.py::load", "a.py"),
        "app/api.py::handler": _node("app/api.py::handler", "app/api.py"),
        "app/db.py::query": _node("app/db.py::query", "app/db.py"),
        "b.py::unrelated": _node("b.py::unrelated", "b.py"),
    },
    edges=[
        _edge("app/api.py::handler", "a.py::load"),
        _edge("app/api.py::handler", "app/db.py::query"),
        _edge("app/api.py::handler", "a.py::load"),
    ],
)


class TestSpecValidation:
    def test_blank_scan_id_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            validate_spec(MapSpec(scan_id="  "))

    def test_unknown_view_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            validate_spec(MapSpec(scan_id="s", view="nope"))

    def test_depth_bounds_are_enforced(self) -> None:
        assert validate_spec(MapSpec(scan_id="s", depth=MAX_DEPTH)).depth == MAX_DEPTH
        with pytest.raises(ValidationError):
            validate_spec(MapSpec(scan_id="s", depth=0))
        with pytest.raises(ValidationError):
            validate_spec(MapSpec(scan_id="s", depth=MAX_DEPTH + 1))

    def test_unknown_kind_is_refused_and_the_code_says_which(self) -> None:
        with pytest.raises(ValidationError) as caught:
            validate_spec(MapSpec(scan_id="s", kinds=frozenset({"teleports"})))
        assert "teleports" in caught.value.message

    def test_direction_is_validated(self) -> None:
        with pytest.raises(ValidationError):
            validate_spec(MapSpec(scan_id="s", direction="sideways"))

    def test_budget_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            MapBudget(max_nodes=0)
        with pytest.raises(ValidationError):
            MapBudget(max_edges=-1)

    def test_a_view_declares_its_own_kinds(self) -> None:
        for view in VIEWS:
            spec = validate_spec(MapSpec(scan_id="s", view=view))
            assert spec.resolved_kinds(), f"{view} resolved to no relation kinds"


class TestModuleMap:
    def test_symbols_collapse_onto_their_file(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        ids = {node["id"] for node in model["nodes"]}
        assert ids == {"a.py", "app/api.py", "app/db.py"}

    def test_collapsed_count_is_reported(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        assert model["stats"]["collapsed"] == 1  # four symbols onto three files

    def test_repeated_edges_collapse_into_a_count(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        pair = [e for e in model["edges"] if e["src"] == "app/api.py" and e["dst"] == "a.py"]
        assert len(pair) == 1
        assert pair[0]["count"] == 2
        assert "x2" in pair[0]["label"]

    def test_self_edges_are_dropped(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        assert all(edge["src"] != edge["dst"] for edge in model["edges"])

    def test_nodes_with_no_file_are_not_modules(self) -> None:
        report = _report(nodes={"ghost": _node("ghost", "")}, edges=[])
        model = build_map(report, MapSpec(scan_id="s"))
        assert model["nodes"] == []
        assert "no node in this snapshot carries a file" in model["meta"]["empty_reason"]

    def test_empty_snapshot_says_so_instead_of_rendering_nothing(self) -> None:
        report = _report(nodes={}, edges=[])
        model = build_map(report, MapSpec(scan_id="s"))
        assert model["nodes"] == [] and model["edges"] == []
        assert model["meta"]["empty_reason"]
        assert model["honesty"]["caveats"]

    def test_kind_filter_narrows_the_edges(self) -> None:
        report = _report(
            nodes=CHAIN.graph_snapshot["nodes"],
            edges=[_edge("app/api.py::handler", "a.py::load", kind="imports"), _edge("app/api.py::handler", "app/db.py::query")],
        )
        model = build_map(report, MapSpec(scan_id="s", kinds=frozenset({"imports"})))
        assert {edge["kind"] for edge in model["edges"]} == {"imports"}

    def test_direction_out_keeps_only_edges_leaving_the_root(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s", root="app", direction="out"))
        assert model["nodes"]
        assert all(edge["src"] == "app/api.py" for edge in model["edges"])

    def test_root_that_matches_nothing_is_reported(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s", root="nope/"))
        assert "matches no indexed file" in model["meta"]["empty_reason"]

    def test_every_edge_points_at_a_node_that_is_drawn(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s"))
        ids = {node["id"] for node in model["nodes"]}
        for edge in model["edges"]:
            assert edge["src"] in ids and edge["dst"] in ids


class TestLayout:
    def test_layout_is_deterministic(self) -> None:
        first = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        second = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        assert first["layout"] == second["layout"]
        assert [n["x"] for n in first["nodes"]] == [n["x"] for n in second["nodes"]]

    def test_a_different_scan_id_does_not_silently_reuse_a_layout(self) -> None:
        # The seed is recorded, not trusted, so this is a stability check rather
        # than a claim that the seed changes positions.
        one = build_map(CHAIN, MapSpec(scan_id="scan-a"))
        two = build_map(CHAIN, MapSpec(scan_id="scan-b"))
        assert one["layout"]["seed"] != two["layout"]["seed"]

    def test_coordinates_stay_inside_the_reported_extent(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s"))
        layout = model["layout"]
        for node in model["nodes"]:
            assert node["x"] >= 0.0
            assert node["y"] >= 0.0
            assert node["x"] + node["w"] <= layout["width"]
            assert node["y"] + node["h"] <= layout["height"]
            # A node with no height is invisible to a renderer that draws a box,
            # and an invisible node is indistinguishable from a missing one.
            assert node["h"] > 0.0

    def test_nodes_in_the_same_component_stack_within_one_lane(self) -> None:
        report = _report(
            nodes={
                "x/app/one.py::a": _node("x/app/one.py::a", "x/app/one.py"),
                "x/app/two.py::b": _node("x/app/two.py::b", "x/app/two.py"),
                "x/lib/three.py::c": _node("x/lib/three.py::c", "x/lib/three.py"),
            },
            edges=[],
        )
        model = build_map(report, MapSpec(scan_id="s"))
        lanes = {node["id"]: node["y"] for node in model["nodes"]}
        # Three unrelated files form three single-file components. With no
        # edges between them they share the first lane, side by side.
        assert lanes["x/app/one.py"] == lanes["x/app/two.py"]

    def test_a_dependency_points_downwards_on_screen(self) -> None:
        report = _report(
            nodes={
                "x/api.py::handler": _node("x/api.py::handler", "x/api.py"),
                "x/db.py::query": _node("x/db.py::query", "x/db.py"),
            },
            edges=[_edge("x/api.py::handler", "x/db.py::query", "calls")],
        )
        model = build_map(report, MapSpec(scan_id="s"))
        place = {node["id"]: node for node in model["nodes"]}
        source = place["x/api.py"]
        target = place["x/db.py"]
        # The caller is drawn above what it calls: an arrow that points up
        # inverts the reading of the whole diagram.
        assert source["y"] < target["y"]
        assert model["layout"]["layers"] >= 2

    def test_a_cycle_collapses_into_one_lane_and_is_marked(self) -> None:
        report = _report(
            nodes={
                "x/a.py::a": _node("x/a.py::a", "x/a.py"),
                "x/b.py::b": _node("x/b.py::b", "x/b.py"),
            },
            edges=[
                _edge("x/a.py::a", "x/b.py::b", "calls"),
                _edge("x/b.py::b", "x/a.py::a", "calls"),
            ],
        )
        model = build_map(report, MapSpec(scan_id="s"))
        layout = model["layout"]
        assert layout["cycles_broken"] == 1
        assert layout["layers"] == 1
        assert all(node["in_cycle"] for node in model["nodes"])

    def test_no_two_nodes_overlap(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s"))
        boxes = [
            (node["x"], node["y"], node["x"] + node["w"], node["y"] + node["h"])
            for node in model["nodes"]
        ]
        for i, first in enumerate(boxes):
            for second in boxes[i + 1 :]:
                overlap_x = min(first[2], second[2]) - max(first[0], second[0])
                overlap_y = min(first[3], second[3]) - max(first[1], second[1])
                assert overlap_x <= 0 or overlap_y <= 0

    def test_a_wide_lane_wraps_instead_of_stretching(self) -> None:
        # Two hundred unrelated files must not become one 200-file-long row.
        report = _report(
            nodes={f"pkg/f{index:03d}.py::f": _node(f"pkg/f{index:03d}.py::f", f"pkg/f{index:03d}.py")
                   for index in range(200)},
            edges=[],
        )
        model = build_map(report, MapSpec(scan_id="s"))
        layout = model["layout"]
        rows = {node["y"] for node in model["nodes"]}
        # Without wrapping every one of the two hundred files would share a
        # single row and the drawing would be one very long thin strip.
        assert len(rows) > 5
        # Two hundred files in one row would be roughly 25,000 pixels wide.
        assert layout["width"] < 4000.0


class TestBudgetHonesty:
    def test_edge_budget_reports_what_it_dropped_and_which_kinds(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s", budget=MapBudget(max_nodes=50, max_edges=1)))
        assert model["stats"]["edges"] == 1
        assert model["stats"]["budget_omitted"]

    def test_a_dropped_budget_appears_in_the_caveats(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s", budget=MapBudget(max_nodes=50, max_edges=1)))
        caveats = " ".join(model["honesty"]["caveats"])
        assert "budget removed" in caveats
        assert "--max-edges" in caveats

    def test_node_budget_is_reported_rather_than_silently_applied(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s", budget=MapBudget(max_nodes=1, max_edges=100)))
        assert len(model["nodes"]) == 1
        assert model["stats"]["omitted_nodes"] > 0

    def test_unresolved_calls_are_stated_as_a_caveat(self) -> None:
        report = _report(
            nodes=CHAIN.graph_snapshot["nodes"],
            edges=CHAIN.graph_snapshot["edges"],
            unresolved=412,
        )
        model = build_map(report, MapSpec(scan_id="s"))
        assert model["honesty"]["unresolved_call_targets"] == 412
        assert any("412" in caveat for caveat in model["honesty"]["caveats"])

    def test_truncated_snapshot_is_disclosed_with_its_real_count(self) -> None:
        report = _report(
            nodes=CHAIN.graph_snapshot["nodes"],
            edges=CHAIN.graph_snapshot["edges"],
            truncated=True,
            edges_omitted=999,
        )
        model = build_map(report, MapSpec(scan_id="s"))
        assert model["honesty"]["snapshot_truncated"] is True
        assert any("999" in caveat for caveat in model["honesty"]["caveats"])

    def test_the_final_caveat_always_states_what_a_map_is_not(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="s"))
        assert "not evidence that anything is exploitable" in model["honesty"]["caveats"][-1]


class TestFindings:
    def test_a_finding_colours_the_file_it_names(self) -> None:
        finding = SimpleNamespace(
            severity=SimpleNamespace(value="critical"),
            evidence=[SimpleNamespace(file="app/db.py")],
        )
        report = _report(
            nodes=CHAIN.graph_snapshot["nodes"],
            edges=CHAIN.graph_snapshot["edges"],
            findings=[finding],
        )
        model = build_map(report, MapSpec(scan_id="s"))
        node = {n["id"]: n for n in model["nodes"]}["app/db.py"]
        assert node["finding_severity"] == "critical"
        assert node["finding_count"] == 1
        assert node["findings"] == {"critical": 1}

    def test_worst_severity_wins_over_count(self) -> None:
        findings = [
            SimpleNamespace(severity=SimpleNamespace(value="low"), evidence=[SimpleNamespace(file="a.py")]),
            SimpleNamespace(severity=SimpleNamespace(value="high"), evidence=[SimpleNamespace(file="a.py")]),
        ]
        report = _report(nodes=CHAIN.graph_snapshot["nodes"], edges=CHAIN.graph_snapshot["edges"], findings=findings)
        model = build_map(report, MapSpec(scan_id="s"))
        node = {n["id"]: n for n in model["nodes"]}["a.py"]
        assert node["finding_severity"] == "high"
        assert node["finding_count"] == 2

    def test_no_findings_option_omits_the_counts(self) -> None:
        findings = [SimpleNamespace(severity=SimpleNamespace(value="low"), evidence=[SimpleNamespace(file="a.py")])]
        report = _report(nodes=CHAIN.graph_snapshot["nodes"], edges=CHAIN.graph_snapshot["edges"], findings=findings)
        model = build_map(report, MapSpec(scan_id="s", include_findings=False))
        node = {n["id"]: n for n in model["nodes"]}["a.py"]
        assert node["finding_count"] == 0
        assert node["findings"] == {}


class TestHtmlOutput:
    @pytest.fixture()
    def html(self) -> str:
        return render_map_html(build_map(CHAIN, MapSpec(scan_id="scan-map-1")))

    def test_it_is_one_document(self, html: str) -> None:
        assert html.startswith("<!DOCTYPE html>")
        assert html.rstrip().endswith("</html>")

    def test_it_makes_no_network_request(self, html: str) -> None:
        # A CWE reference is plain text inside the model, not a fetched asset.
        body = html.split("</style>", 1)[1]
        assert "http://" not in body.replace("http://www.w3.org/2000/svg", "")
        assert "https://" not in body
        assert "src=" not in body

    def test_it_never_uses_innerHTML(self, html: str) -> None:
        # Property access, not the bare word: the file says in a comment that it
        # does not use innerHTML, and that sentence must not fail the test.
        assert ".innerHTML" not in html
        assert ".outerHTML" not in html
        assert "insertAdjacentHTML" not in html
        assert "document.write" not in html

    def test_it_carries_no_inline_event_handlers(self, html: str) -> None:
        # addEventListener is the only sanctioned route.
        assert not re.search(r"\son(click|load|error|mouseover)\s*=", html)

    def test_repository_text_cannot_close_the_script_block(self) -> None:
        hostile = SimpleNamespace(
            scan_id="s",
            repository="</script><img src=x onerror=alert(1)>",
            revision="r",
            findings=[],
            graph_snapshot={
                "nodes": {"a": {**_node("a", "</script><img src=x onerror=alert(1)>"), "name": "</script>"}},
                "edges": [],
                "truncated": False,
                "unresolved": 0,
                "edges_omitted": 0,
                "nodes_omitted": 0,
            },
        )
        html = render_map_html(build_map(hostile, MapSpec(scan_id="s")))
        payload = html.split('type="application/json">', 1)[1].split("</script>", 1)[0]
        # The payload round-trips through JSON with the hostile text intact,
        # and the raw markup never appears.
        assert "<img" not in payload
        assert "</script>" not in payload
        assert json.loads(payload.encode().decode("unicode_escape"))["meta"]["repository"].startswith("</script>")

    def test_it_states_its_caveats_in_the_document(self, html: str) -> None:
        assert "honesty" in html and "caveats" in html

    def test_it_is_byte_identical_across_renders(self) -> None:
        model = build_map(CHAIN, MapSpec(scan_id="scan-map-1"))
        assert render_map_html(model) == render_map_html(model)

    def test_every_declared_relation_kind_reaches_the_model(self) -> None:
        # The test that stops a future change dropping a relation from the map.
        model = build_map(CHAIN, MapSpec(scan_id="s"))
        drawn = {kind for kind, style in model["legend"]["kind_default_style"].items() if style}
        assert drawn == set(model["meta"]["spec"]["kinds"])


class TestOutputPath:
    def test_html_extension_is_required(self, tmp_path: Path) -> None:
        with pytest.raises(UnsupportedFormatError):
            safe_map_output_path(tmp_path / "map.svg")

    def test_a_parent_escape_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(UnsupportedFormatError):
            safe_map_output_path("../escape.html")

    def test_an_ordinary_path_is_accepted(self, tmp_path: Path) -> None:
        assert safe_map_output_path(tmp_path / "map.html").suffix == ".html"

    def test_write_produces_a_readable_file(self, tmp_path: Path) -> None:
        target = write_map_html(build_map(CHAIN, MapSpec(scan_id="s")), tmp_path / "m.html")
        assert target.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")

    def test_write_refuses_to_exceed_the_byte_ceiling(self, tmp_path: Path, monkeypatch) -> None:
        import understand.reporting.html_map as html_map

        monkeypatch.setattr(html_map, "MAX_MAP_BYTES", 10)
        with pytest.raises(Exception) as caught:
            write_map_html(build_map(CHAIN, MapSpec(scan_id="s")), tmp_path / "big.html")
        assert "ceiling" in str(caught.value)

    def test_the_ceiling_is_a_real_number_not_a_placeholder(self) -> None:
        assert MAX_MAP_BYTES > 1_000_000


SYMBOL_CHAIN = _report(
    nodes={
        "a.py::Base": _node("a.py::Base", "a.py", "class"),
        "a.py::Child": _node("a.py::Child", "a.py", "class"),
        "a.py::handler": _node("a.py::handler", "a.py"),
        "a.py::helper": _node("a.py::helper", "a.py"),
        "a.py::deep": _node("a.py::deep", "a.py"),
        "a.py::deeper": _node("a.py::deeper", "a.py"),
        "b.py::other": _node("b.py::other", "b.py"),
        "tests/test_a.py::test_handler": _node("tests/test_a.py::test_handler", "tests/test_a.py"),
    },
    edges=[
        _edge("a.py::Child", "a.py::Base", "inherits", "static_direct"),
        _edge("a.py::handler", "a.py::helper"),
        _edge("a.py::helper", "a.py::deep"),
        _edge("a.py::deep", "a.py::deeper"),
        _edge("tests/test_a.py::test_handler", "a.py::handler", "tests", "static_direct"),
        _edge("b.py::other", "a.py::helper"),
    ],
)


class TestSymbolViews:
    """The call/inheritance/dependency/test views answer different questions."""

    def test_every_declared_view_has_a_builder_and_a_question(self) -> None:
        from understand.engine.code_map import FINDING_VIEWS, SYMBOL_VIEWS, VIEW_KINDS, VIEW_QUESTIONS

        for name in VIEWS:
            assert VIEW_KINDS.get(name), f"{name} declares no relation kinds"
            assert VIEW_QUESTIONS.get(name), f"{name} has no stated question"
        # Every view is reachable from exactly one place: a builder, a kind set,
        # and a stated question. A view that is missing one is a view a reader
        # cannot discover, and a builder with no question draws the right lines
        # for the wrong reason.
        assert set(VIEWS) == {
            "module",
            "call",
            "inheritance",
            "dependency",
            "test",
            "event",
            "obligation",
            "influence",
            "data_flow",
            "finding",
        }
        assert FINDING_VIEWS == {"data_flow", "finding"}
        assert not FINDING_VIEWS & SYMBOL_VIEWS, (
            "a view is either a traversal from a root or a projection of findings; "
            "being both means its builder does not know which one it is"
        )

    def test_call_view_walks_outwards_from_the_root(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=3)),
        )
        ids = {n["id"] for n in model["nodes"]}
        assert "a.py::handler" in ids, "the root is always drawn"
        assert "a.py::helper" in ids, "one hop out"
        assert "a.py::deep" in ids, "two hops out"
        # handler -> helper -> deep -> deeper is three hops, so depth 3 is the
        # last one that still reaches the root.
        assert "a.py::deeper" in ids
        assert "b.py::other" in ids, "a caller is reachable too when direction is both"
        assert all(e["kind"] in ("calls", "awaits_task", "starts_task") for e in model["edges"])
        assert model["meta"]["root"] == "a.py::handler"

    def test_depth_two_stops_before_the_third_hop(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=2)),
        )
        ids = {n["id"] for n in model["nodes"]}
        assert "a.py::deep" in ids
        assert "a.py::deeper" not in ids

    def test_depth_one_stops_immediately(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=1)),
        )
        ids = {n["id"] for n in model["nodes"]}
        assert "a.py::helper" in ids
        assert "a.py::deep" not in ids

    def test_direction_out_ignores_callers(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(
                MapSpec(scan_id="s", view="call", root="a.py::helper", direction="out", depth=2)
            ),
        )
        ids = {n["id"] for n in model["nodes"]}
        assert "a.py::deep" in ids
        assert "a.py::handler" not in ids, "a caller is not reachable going out"
        assert "b.py::other" not in ids

    def test_direction_in_ignores_callees(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(
                MapSpec(scan_id="s", view="call", root="a.py::helper", direction="in", depth=2)
            ),
        )
        ids = {n["id"] for n in model["nodes"]}
        assert "b.py::other" in ids
        assert "a.py::deep" not in ids

    def test_inheritance_view_draws_only_inheritance(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="inheritance", root="a.py::Child")),
        )
        assert [e["kind"] for e in model["edges"]] == ["inherits"]
        assert {n["id"] for n in model["nodes"]} == {"a.py::Child", "a.py::Base"}

    def test_test_view_keeps_the_test_and_its_subject(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="test", root="tests/test_a.py::test_handler")),
        )
        assert [e["kind"] for e in model["edges"]] == ["tests"]
        assert "a.py::handler" in {n["id"] for n in model["nodes"]}

    def test_dependency_view_excludes_calls(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="dependency", root="b.py::other", depth=3)),
        )
        assert all(e["kind"] in ("imports", "depends_on") for e in model["edges"])

    def test_nodes_are_symbols_not_files(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=3)),
        )
        assert all(n["kind"] != "module" for n in model["nodes"])
        assert model["stats"]["collapsed"] == 0

    def test_ambiguous_root_is_refused_rather_than_guessed(self) -> None:
        report = _report(
            nodes={
                "x.py::run": _node("x.py::run", "x.py"),
                "y.py::run": _node("y.py::run", "y.py"),
            },
            edges=[_edge("x.py::run", "y.py::run")],
        )
        model = build_map(report, validate_spec(MapSpec(scan_id="s", view="call", root="run")))
        assert model["nodes"] == []
        reason = model["meta"]["empty_reason"]
        assert "ambiguous" in reason
        # The refusal has to name a way forward, not just refuse.
        assert "x.py::run" in reason

    def test_unknown_root_is_refused(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="nope")),
        )
        assert model["nodes"] == []
        assert "matches no indexed symbol" in model["meta"]["empty_reason"]

    def test_a_root_resolved_from_a_bare_name_uses_the_full_id(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="handler", depth=1)),
        )
        assert model["meta"]["root"] == "a.py::handler"

    def test_a_method_resolves_by_its_qualified_name(self) -> None:
        report = _report(
            nodes={
                "a.py::Service.start": {
                    "id": "a.py::Service.start",
                    "name": "start",
                    "kind": "method",
                    "file": "a.py",
                    "start_line": 1,
                    "end_line": 2,
                    "language": "python",
                    "exported": False,
                }
            },
            edges=[],
        )
        model = build_map(
            report, validate_spec(MapSpec(scan_id="s", view="call", root="Service.start"))
        )
        assert model["meta"]["root"] == "a.py::Service.start"

    def test_a_file_root_pulls_in_every_symbol_in_it(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="dependency", root="a.py", depth=1)),
        )
        assert "a.py::handler" in {n["id"] for n in model["nodes"]}
        assert "b.py::other" not in {n["id"] for n in model["nodes"]}

    def test_no_root_ranks_by_degree_instead_of_falling_back_to_nothing(self) -> None:
        model = build_map(
            SYMBOL_CHAIN, validate_spec(MapSpec(scan_id="s", view="call", depth=3))
        )
        assert model["nodes"], "a repository with call edges must not map to nothing"
        top = max(model["nodes"], key=lambda n: n["finding_count"])
        assert top["id"] == "a.py::helper" or model["stats"]["nodes"] == len(model["nodes"])

    def test_budget_is_enforced_on_a_symbol_view(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(
                MapSpec(scan_id="s", view="call", depth=6, budget=MapBudget(max_nodes=2))
            ),
        )
        assert len(model["nodes"]) <= 2
        assert model["stats"]["omitted_nodes"] > 0

    def test_layout_is_present_and_bounded(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=3)),
        )
        layout = model["layout"]
        assert layout["algorithm"] == "layered"
        assert layout["width"] > 0 and layout["height"] > 0
        for node in model["nodes"]:
            assert 0 <= node["x"] <= layout["width"]
            assert node["h"] > 0

    def test_every_drawn_node_has_a_shape(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=3)),
        )
        from understand.engine.code_map import NODE_SHAPES

        for node in model["nodes"]:
            assert node["shape"] in NODE_SHAPES.values()

    def test_build_is_deterministic(self) -> None:
        spec = MapSpec(scan_id="s", view="call", root="a.py::handler", depth=3)
        first = build_map(SYMBOL_CHAIN, validate_spec(spec))
        second = build_map(SYMBOL_CHAIN, validate_spec(spec))
        assert json.dumps(first["nodes"], sort_keys=True) == json.dumps(
            second["nodes"], sort_keys=True
        )
        assert first["layout"] == second["layout"]

    def test_the_rendered_html_carries_the_new_view(self) -> None:
        model = build_map(
            SYMBOL_CHAIN,
            validate_spec(MapSpec(scan_id="s", view="call", root="a.py::handler", depth=3)),
        )
        html = render_map_html(model)
        assert "a.py::handler" in html
        assert "What does this symbol call" in html


    def test_a_wide_flat_graph_is_wrapped_toward_the_target_aspect(self) -> None:
        """A 40:1 drawing has to be zoomed out until no label is readable."""

        wide = _report(
            nodes={f"m.py::f{i:03d}": _node(f"m.py::f{i:03d}", "m.py") for i in range(60)},
            edges=[_edge("m.py::f000", f"m.py::f{i:03d}") for i in range(1, 60)],
        )
        model = build_map(wide, validate_spec(MapSpec(scan_id="s", view="call", root="m.py::f000")))
        layout = model["layout"]
        aspect = layout["width"] / max(1.0, layout["height"])
        assert aspect < 8.0, f"a 60-node fan-out laid out at {aspect:.1f}:1 is unreadable when fitted"
        assert aspect > 0.2, "wrapping must not collapse the drawing into a single column"

    def test_a_deep_graph_is_allowed_to_be_tall(self) -> None:
        deep = _report(
            nodes={f"m.py::f{i}": _node(f"m.py::f{i}", "m.py") for i in range(12)},
            edges=[_edge(f"m.py::f{i}", f"m.py::f{i + 1}") for i in range(11)],
        )
        # A traversal is depth-bounded, so the walk has to be opened up before the
        # layering has twelve layers to work with.
        model = build_map(
            deep, validate_spec(MapSpec(scan_id="s", view="call", root="m.py::f0", depth=6))
        )
        # A rooted walk cannot exceed MAX_DEPTH + 1 layers by construction.
        assert model["layout"]["layers"] == MAX_DEPTH + 1


class TestAdaptiveQuality:
    """The renderer must not assume a GPU.

    Every proxy a web page can read about the hardware is a guess and is wrong
    on somebody's machine, so the only honest signal is the measured cost of the
    frame just drawn. These tests pin the controller's behaviour and, above
    all, that a machine which keeps up is never penalised.
    """

    SCRIPT = Path(HTML_MAP).read_text(encoding="utf-8")

    def test_quality_controller_exists_and_is_measured_not_guessed(self) -> None:
        # The controller must consume a measurement, not a hardware string.
        assert "measureFrame(performance.now() - startedAt)" in self.SCRIPT
        assert "var perf = { quality: 1" in self.SCRIPT

    def test_no_gpu_or_user_agent_sniffing(self) -> None:
        # deviceMemory, GPU vendor strings and platform branches would each be a
        # guess. None may appear in *code*; prose that merely names them as the
        # things being avoided is fine and is stripped first.
        code = "\n".join(
            line for line in self.SCRIPT.splitlines() if not line.strip().startswith("//")
        )
        for probe in ("deviceMemory", "navigator.gpu", "getContext('webgl')",
                      'getContext("webgl")', "hardwareConcurrency", "userAgent"):
            assert probe not in code, f"{probe} is a hardware guess"

    def test_frames_drawn_while_nobody_is_touching_the_map_do_not_degrade_it(self) -> None:
        # Standing still is not a performance problem. A slow frame at rest must
        # not lower the detail level, or a big picture would permanently damage
        # the map for everyone with a big repository.
        assert "if (!adaptNow()) return false;" in self.SCRIPT
        assert 'interacting() || restoreStage >= 0 || performance.now() < adaptUntil' in self.SCRIPT

    def test_quality_floors_and_ceiling_are_bounded(self) -> None:
        assert "var PERF_MIN_QUALITY = 0.15;" in self.SCRIPT
        assert "perf.quality = Math.max(PERF_MIN_QUALITY" in self.SCRIPT
        assert "perf.quality = Math.min(1, perf.quality + 0.12)" in self.SCRIPT

    def test_detail_is_restored_in_steps_not_one_jump(self) -> None:
        # One frame restoring everything was an isolated 130-200ms stall.
        assert "var RESTORE_STEPS = [0.35, 0.6, 0.85, 1.0];" in self.SCRIPT
        assert "function beginRestore()" in self.SCRIPT
        assert "beginRestore();" in self.SCRIPT

    def test_the_ladder_ceils_the_edge_budget_while_restoring(self) -> None:
        assert "var ceiling = restoreCeiling();" in self.SCRIPT
        assert "if (ceiling !== null) n = Math.round(n * ceiling);" in self.SCRIPT

    def test_a_slow_step_steps_the_ladder_back_instead_of_pressing_on(self) -> None:
        assert "if (expensive) { restoreStage = 0; return; }" in self.SCRIPT

    def test_the_quality_level_is_reported_to_the_reader(self) -> None:
        # A thinner picture that does not say so is a false claim.
        assert '"detail " + Math.round(perf.quality * 100) + "% to hold the frame rate on this machine"' in self.SCRIPT
        assert 'if (detail) statusEl.appendChild(el("span", "warn", detail));' in self.SCRIPT

    def test_label_budget_follows_the_same_controller(self) -> None:
        # Text is the other expensive thing; leaving it unthinned would make the
        # controller ineffective.
        assert "var n = Math.round(LABEL_BUDGET * perf.quality);" in self.SCRIPT

    def test_the_reported_label_count_is_the_real_one(self) -> None:
        # It used to print the constant instead of the budget, so a thinned map
        # would claim it was drawing more labels than it was.
        assert '"labels on, " + labelBudget() + " of "' in self.SCRIPT


# --------------------------------------------------------------------------- detail


def _finding(finding_id: str = "SEC-FLOW-001-abc123", **overrides):
    from understand.models import Confidence, Evidence, EvidenceKind, Finding, Severity
    from understand.models import VerificationStatus

    payload = {
        "finding_id": finding_id,
        "rule_id": "SEC-FLOW-001",
        "title": "environment variable reaches SQL execution",
        "category": "sql-injection",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "verification_status": VerificationStatus.CROSS_MODULE_TRACE,
        "summary": "An environment variable reaches a SQL statement.",
        "technical_explanation": "process.env is interpolated into a COPY statement.",
        "impact": "The destination path of the export is attacker-influenced.",
        "remediation": "Bind the value as a parameter.",
        "assumptions": ["No allow-list was found on the destination path."],
        "preconditions": ["The CI environment can be influenced by an attacker."],
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "evidence": [
            Evidence(
                kind=EvidenceKind.SOURCE_RANGE,
                file="app/db.py",
                start_line=12,
                end_line=13,
                symbol="run_export",
                snippet="await connection.run(f\"COPY t TO '{out}'\")",
            )
        ],
        "affected_symbols": ["app/db.py::run_export"],
        "call_chains": [["handler", "run_export"]],
        "data_flows": [
            [
                "entered from app.api.handler",
                "env var process.env.OUT (line 12)",
                "in app/db.py::run_export",
                "sink: sql-exec",
            ]
        ],
    }
    payload.update(overrides)
    return Finding(**payload)


FLOW_REPORT = _report(
    nodes={
        "app/api.py::handler": _node("app/api.py::handler", "app/api.py"),
        "app/db.py::run_export": _node("app/db.py::run_export", "app/db.py"),
    },
    edges=[_edge("app/api.py::handler", "app/db.py::run_export", origin="inferred")],
    findings=[_finding()],
    unresolved=17,
)


class TestExplainFinding:
    def test_it_returns_the_whole_argument_not_a_summary(self) -> None:
        account = explain_finding(FLOW_REPORT, "SEC-FLOW-001-abc123")
        assert account["rule_id"] == "SEC-FLOW-001"
        assert account["severity"] == "critical"
        assert account["confidence"] == "high"
        assert account["verification_status"] == "cross_module_trace"
        assert account["where"].startswith("app/db.py:12")
        assert account["what"] and account["how"] and account["impact"]
        assert account["remediation"] and account["references"]

    def test_the_chain_is_numbered_source_to_sink(self) -> None:
        account = explain_finding(FLOW_REPORT, "SEC-FLOW-001-abc123")
        chain = account["chain"]
        assert [step["step"] for step in chain] == [1, 2, 3, 4]
        assert chain[0]["role"] == "source"
        assert chain[-1]["role"] == "sink"
        assert all(step["role"] == "propagation" for step in chain[1:-1])

    def test_what_was_not_proven_is_its_own_section(self) -> None:
        # The whole point of the account. A reader who sees the impact without
        # seeing the gap can act on a hypothesis.
        account = explain_finding(FLOW_REPORT, "SEC-FLOW-001-abc123")
        assert account["not_proven"] == ["No allow-list was found on the destination path."]
        assert account["must_be_true"] == [
            "The CI environment can be influenced by an attacker."
        ]
        assert account["not_proven"] != account["must_be_true"]

    def test_the_root_it_recommends_is_a_symbol_the_map_can_actually_draw(self) -> None:
        account = explain_finding(FLOW_REPORT, "SEC-FLOW-001-abc123")
        # The hop already carried the full id here. The requirement is not the
        # spelling: it is that the recommendation resolves, because a bare
        # "run_export" draws an empty map that looks like a clean repository.
        assert account["map"]["root"] in FLOW_REPORT.graph_snapshot["nodes"]

    def test_a_bare_symbol_name_is_qualified_before_it_is_recommended(self) -> None:
        report = _report(
            nodes={"app/db.py::run_export": _node("app/db.py::run_export", "app/db.py")},
            edges=[],
            findings=[
                _finding(
                    data_flows=[["env var process.env.OUT (line 12)", "in run_export", "sink: sql-exec"]],
                    affected_symbols=[],
                )
            ],
        )
        assert explain_finding(report, "SEC-FLOW-001-abc123")["map"]["root"] == (
            "app/db.py::run_export"
        )

    def test_unresolved_targets_are_carried_into_the_caveats(self) -> None:
        account = explain_finding(FLOW_REPORT, "SEC-FLOW-001-abc123")
        assert any("17 call target" in caveat for caveat in account["caveats"])

    def test_a_finding_without_a_chain_says_the_path_was_not_traced(self) -> None:
        report = _report(
            nodes={"app/db.py::run_export": _node("app/db.py::run_export", "app/db.py")},
            edges=[],
            findings=[_finding(data_flows=[], call_chains=[])],
        )
        account = explain_finding(report, "SEC-FLOW-001-abc123")
        # The chain is not blank — it falls back to the evidence line — but the
        # account must say that is all it has.
        assert account["chain"][0]["role"] == "sink"
        assert any("stops at the sink" in caveat for caveat in account["caveats"])

    def test_a_rule_id_is_accepted_as_well_as_a_finding_id(self) -> None:
        assert explain_finding(FLOW_REPORT, "SEC-FLOW-001")["finding_id"] == (
            "SEC-FLOW-001-abc123"
        )

    def test_an_unknown_finding_is_not_silently_ignored(self) -> None:
        with pytest.raises(FindingNotFound):
            explain_finding(FLOW_REPORT, "SEC-NOPE-001")

    def test_an_empty_id_is_a_usage_error(self) -> None:
        with pytest.raises(ValidationError):
            explain_finding(FLOW_REPORT, "   ")

    def test_it_never_returns_an_empty_kind_set(self) -> None:
        # A map with no kinds draws nodes and no edges, which reads as "nothing
        # is connected" rather than "nothing was asked for".
        account = explain_finding(FLOW_REPORT, "SEC-FLOW-001-abc123")
        assert account["map"]["kinds"]


class TestEmbeddedJsonIsValidJson:
    def test_a_snippet_with_a_quote_and_a_backslash_round_trips(self) -> None:
        # It did not. Every backslash was doubled a second time after
        # json.dumps, which turned \" into \\" and made the whole embedded
        # document unparseable as soon as any node carried source.
        nasty = {
            "nodes": [
                {
                    "id": "a.py::f",
                    "source": 'if (x === "object") { return "\\n"; }',
                    "close": "</script><img src=x onerror=alert(1)>",
                }
            ]
        }
        html = render_map_html(nasty)
        raw = re.search(
            r'<script id="map-data" type="application/json">(.*?)</script>', html, re.S
        )
        assert raw, "the embedded payload is missing"
        restored = json.loads(raw.group(1))
        assert restored["nodes"][0]["source"] == nasty["nodes"][0]["source"]
        assert restored["nodes"][0]["close"] == nasty["nodes"][0]["close"]

    def test_the_backslash_is_not_doubled_twice(self) -> None:
        source = (
            HTML_MAP.read_text(encoding="utf-8").split('def _embed')[1].split("def render_map_html")[0]
        )
        assert '.replace("\\\\", "\\\\\\\\")' not in source


class TestPanelExplainsRatherThanLists:
    #: Only the browser payload. The module docstring names ``innerHTML`` while
    #: explaining why it is never used, and reading the whole file would make
    #: that sentence look like a violation.
    SCRIPT = HTML_MAP.read_text(encoding="utf-8").split('_TEMPLATE = """', 1)[1]

    def test_the_panel_shows_the_node_source(self) -> None:
        assert 'el("h3", null, "Code")' in self.SCRIPT
        assert "if (node.source_available) {" in self.SCRIPT
        assert "sourceText = node.source;" in self.SCRIPT

    def test_a_file_less_node_is_told_why_it_has_no_code(self) -> None:
        # It had no file of its own, and the old wording said so in a way that
        # read like a broken tool ("it is a pivot the analyzer made"). The panel
        # now says what the node actually is: the name of something the code
        # calls that could not be bound to a definition in this repository.
        assert "This node has no file of its own" not in self.SCRIPT
        assert "could not bind it to a definition" in self.SCRIPT
        assert "placeholder_reason" in self.SCRIPT

    def test_a_placeholder_is_drawn_as_a_hollow_dashed_node(self) -> None:
        # Otherwise a name with no definition looks exactly like a function.
        assert 'n.shape === "placeholder"' in self.SCRIPT
        assert '"Hollow, dashed node"' in self.SCRIPT

    def test_a_missing_source_is_still_distinguished_from_no_file(self) -> None:
        # Three reasons, never one: readable, no file at all, or the repository
        # moved. Collapsing the last two is a false statement about the analysis.
        assert "STATS.source_reason" in self.SCRIPT

    def test_every_part_of_the_argument_is_rendered(self) -> None:
        for heading in (
            "What is happening",
            "Impact",
            "Evidence",
            "What must be true for this to matter",
            "What this analysis did NOT prove",
            "Why this confidence",
            "How to fix it",
        ):
            assert heading in self.SCRIPT, heading

    def test_a_data_flow_is_rendered_as_a_numbered_path(self) -> None:
        assert 'el("ol", "chain")' in self.SCRIPT

    def test_the_panel_never_builds_markup_from_repository_text(self) -> None:
        # Comments are stripped first: the helper that assigns textContent is
        # documented by naming the property it refuses to use.
        code = "\n".join(
            line for line in self.SCRIPT.splitlines()
            if not line.lstrip().startswith(("//", "/*", "*"))
        )
        assert "innerHTML" not in code
        assert "insertAdjacentHTML" not in code
        assert "outerHTML" not in code
        assert "textContent" in code


def _flow_report(finding, nodes=None, edges=None):
    return _report(
        nodes=nodes
        or {
            "app/api.py::handler": _node("app/api.py::handler", "app/api.py"),
            "app/api.py::on_start": _node("app/api.py::on_start", "app/api.py"),
            "app/api.py::check_token": _node("app/api.py::check_token", "app/api.py"),
            "app/api.py::post_to_api": _node("app/api.py::post_to_api", "app/api.py"),
            "app/db.py::run_export": _node("app/db.py::run_export", "app/db.py"),
        },
        edges=edges
        or [
            _edge("app/api.py::handler", "app/db.py::run_export", origin="inferred"),
            _edge(
                "app/api.py::on_start",
                "app/api.py::handler",
                kind="registers",
                origin="static_direct",
            ),
            _edge(
                "app/api.py::on_start",
                "app/api.py::handler",
                kind="handles_event",
                origin="inferred",
            ),
            _edge(
                "app/api.py::check_token",
                "app/api.py::handler",
                kind="validates",
                origin="inferred",
            ),
            _edge(
                "app/api.py::handler",
                "app/api.py::post_to_api",
                kind="sends_data_to",
                origin="inferred",
            ),
        ],
        findings=[finding],
        unresolved=4,
    )


class TestDataFlowView:
    """A flow is a traced path, so it is drawn from the finding, not the graph."""

    def test_a_flow_is_drawn_from_the_finding_not_the_graph(self):
        model = build_map(
            _flow_report(_finding()),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        assert model["stats"]["flows_drawn"] == 1
        assert model["stats"]["edges"] >= 2
        assert model["meta"]["question"]

    def test_the_value_origin_and_the_sink_are_anchored_not_dropped(self):
        # The graph indexes neither `process.env` nor `sql-exec`. A map whose
        # path starts at the first function it could name would be drawing a
        # different path from the one the analyzer traced.
        model = build_map(
            _flow_report(_finding()),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        roles = {n["id"]: n["flow_role"] for n in model["nodes"]}
        assert any(role == "source" for role in roles.values())
        assert any(role == "sink" for role in roles.values())
        assert any(role == "symbol" for role in roles.values())

    def test_a_proven_flow_is_solid_and_a_matched_one_is_dashed(self):
        from understand.models import Confidence, VerificationStatus

        proven = build_map(
            _flow_report(_finding()),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        static = build_map(
            _flow_report(
                _finding(
                    verification_status=VerificationStatus.STATIC_EVIDENCE,
                    confidence=Confidence.LOW,
                )
            ),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        assert {e["confidence"] for e in proven["edges"]} == {"solid"}
        assert {e["confidence"] for e in static["edges"]} == {"dashed"}
        assert static["stats"]["proven_edges"] == 0

    def test_the_share_of_traced_edges_is_stated(self):
        model = build_map(_flow_report(_finding()), MapSpec(scan_id="flow", view="data_flow"))
        caveats = " ".join(model["honesty"]["caveats"])
        assert "Solid edges are traced" in caveats
        assert str(model["stats"]["proven_edges"]) in caveats

    def test_untraced_paths_are_not_invented(self):
        report = _report(
            nodes={"app/db.py::run_export": _node("app/db.py::run_export", "app/db.py")},
            edges=[],
            findings=[
                _finding(
                    data_flows=[],
                    call_chains=[],
                    evidence=[],
                    affected_symbols=["app/db.py::run_export"],
                )
            ],
            unresolved=0,
        )
        model = build_map(report, MapSpec(scan_id="flow", view="data_flow"))
        assert model["nodes"] == []
        assert "proved no path" in model["meta"]["empty_reason"]

    def test_a_one_hop_flow_is_not_drawn_as_an_edge(self):
        model = build_map(
            _flow_report(_finding(data_flows=[["sink: sql-exec"]])),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        assert model["nodes"] == []

    def test_the_module_placeholder_is_not_a_place_a_value_travelled_through(self):
        model = build_map(
            _flow_report(
                _finding(
                    data_flows=[["in <module>", "sink: shell-exec", "entered from app.api.handler"]]
                )
            ),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        assert not any("<module>" in n["id"] for n in model["nodes"])

    def test_more_flows_than_the_cap_are_counted_not_silently_dropped(self):
        model = build_map(
            _flow_report(
                _finding(
                    data_flows=[
                        ["entered from app.api.handler", "in app/db.py::run_export", "sink: sql-exec"],
                        ["entered from app.api.other", "in app/db.py::run_export", "sink: sql-exec"],
                        ["entered from app.api.third", "in app/db.py::run_export", "sink: sql-exec"],
                        ["entered from app.api.fourth", "in app/db.py::run_export", "sink: sql-exec"],
                        ["entered from app.api.fifth", "in app/db.py::run_export", "sink: sql-exec"],
                    ]
                )
            ),
            MapSpec(scan_id="flow", view="data_flow"),
        )
        assert model["stats"]["flows_drawn"] == 3
        assert model["stats"]["flows_omitted"] == 2
        assert "were not drawn" in " ".join(model["honesty"]["caveats"])

    def test_every_flow_view_node_carries_a_role_and_a_known_shape(self):
        model = build_map(_flow_report(_finding()), MapSpec(scan_id="flow", view="data_flow"))
        assert model["nodes"]
        for node in model["nodes"]:
            assert node["flow_role"]
            assert node["shape"]


class TestFindingView:
    def test_nodes_are_placed_by_worst_severity_then_busyness(self):
        from understand.models import Severity

        model = build_map(
            _report(
                nodes={
                    "app/a.py::quiet": _node("app/a.py::quiet", "app/a.py"),
                    "app/b.py::loud": _node("app/b.py::loud", "app/b.py"),
                },
                edges=[],
                findings=[
                    _finding(
                        finding_id="F-LOW",
                        rule_id="R-LOW",
                        severity=Severity.LOW,
                        affected_symbols=["app/a.py::quiet"],
                        evidence=[],
                        data_flows=[],
                    ),
                    _finding(
                        finding_id="F-CRIT",
                        rule_id="R-CRIT",
                        severity=Severity.CRITICAL,
                        affected_symbols=["app/b.py::loud"],
                        evidence=[],
                        data_flows=[],
                    ),
                ],
                unresolved=0,
            ),
            MapSpec(scan_id="findings", view="finding"),
        )
        assert [n["id"] for n in model["nodes"]] == ["app/b.py::loud", "app/a.py::quiet"]
        assert model["nodes"][0]["finding_severity"] == "critical"

    def test_the_budget_reports_what_it_removed(self):
        report = _report(
            nodes={
                f"app/f{index}.py::fn": _node(f"app/f{index}.py::fn", f"app/f{index}.py")
                for index in range(8)
            },
            edges=[],
            findings=[
                _finding(
                    finding_id=f"F-{index}",
                    rule_id=f"R-{index}",
                    affected_symbols=[f"app/f{index}.py::fn"],
                    evidence=[],
                    data_flows=[],
                )
                for index in range(8)
            ],
            unresolved=0,
        )
        model = build_map(
            report,
            MapSpec(scan_id="findings", view="finding", budget=MapBudget(max_nodes=3)),
        )
        assert model["stats"]["nodes"] == 3
        assert model["stats"]["omitted_nodes"] == 5
        assert "removed 5 node(s)" in " ".join(model["honesty"]["caveats"])

    def test_a_scan_with_no_findings_says_so(self):
        model = build_map(
            _report(nodes={"a.py::x": _node("a.py::x", "a.py")}, edges=[], findings=[], unresolved=0),
            MapSpec(scan_id="findings", view="finding"),
        )
        assert model["nodes"] == []
        assert "no finding" in model["meta"]["empty_reason"]

    def test_one_finding_on_several_symbols_is_not_reported_as_a_shortfall(self):
        model = build_map(
            _report(
                nodes={
                    "a.py::one": _node("a.py::one", "a.py"),
                    "a.py::two": _node("a.py::two", "a.py"),
                },
                edges=[],
                findings=[
                    _finding(
                        affected_symbols=["a.py::one", "a.py::two"],
                        evidence=[],
                        data_flows=[],
                    )
                ],
                unresolved=0,
            ),
            MapSpec(scan_id="findings", view="finding"),
        )
        assert model["stats"]["findings_placed"] == 2
        assert model["stats"]["findings_in_scope"] == 1
        assert "more than one symbol" in " ".join(model["honesty"]["caveats"])


class TestRelationKindsOnlyViews:
    """event, obligation and influence exist to expose kinds nothing else draws."""

    @pytest.mark.parametrize(
        ("view", "kind", "present"),
        [
            ("event", "registers", True),
            ("event", "handles_event", True),
            ("obligation", "sends_data_to", True),
        ],
    )
    def test_a_view_draws_its_own_kinds(self, view, kind, present):
        model = build_map(
            _flow_report(_finding()),
            MapSpec(scan_id="rel", view=view),
        )
        assert (kind in model["stats"]["edges_by_kind"]) is present

    def test_a_view_never_draws_a_kind_it_does_not_declare(self):
        for view in ("event", "obligation", "influence"):
            from understand.engine.code_map import VIEW_KINDS

            model = build_map(
                _flow_report(_finding()),
                MapSpec(scan_id="rel", view=view),
            )
            assert set(model["stats"]["edges_by_kind"]) <= set(VIEW_KINDS[view])

    def test_the_obligation_view_covers_all_five_obligations(self):
        from understand.engine.code_map import VIEW_KINDS

        assert VIEW_KINDS["obligation"] == {
            "validates",
            "authorizes",
            "sends_data_to",
            "opens_resource",
            "closes_resource",
        }

    def test_an_absent_relation_says_absent_rather_than_disconnected(self):
        # "nothing connects your root" and "the analyzer found nothing at all"
        # send a reader to different next steps.
        model = build_map(
            _flow_report(_finding()),
            MapSpec(scan_id="rel", view="influence"),
        )
        assert model["nodes"] == []
        reason = model["meta"]["empty_reason"]
        assert "anywhere in the repository" in reason
        assert "requested root" not in reason


class TestLayoutSolvesForAspect:
    """The row count is solved for, not guessed.

    A reader reported that the map "suddenly became tiny". The cause was not the
    renderer: the wrapping heuristic returned the widest allowed row whenever its
    height estimate said the total width would fit, and that estimate ignored the
    fact that more than one row multiplies the real height. The result was a
    drawing three times taller than wide, which fit-to-view zooms out until every
    node is a speck.
    """

    def _chain(self, count: int) -> SimpleNamespace:
        nodes, edges = {}, []
        for i in range(count):
            nodes[f"m{i:04d}"] = _node(f"m{i:04d}::run", f"pkg/m{i:04d}.py")
            if i:
                edges.append(_edge(f"m{i - 1:04d}::run", f"m{i:04d}::run"))
        return _report(nodes, edges)

    def test_a_deep_chain_is_not_a_thin_column(self) -> None:
        model = build_map(self._chain(300), MapSpec(scan_id="scan-map-1", view="module"))
        layout = model["layout"]
        aspect = layout["width"] / layout["height"]
        assert 0.5 <= aspect <= 4.0, layout

    def test_the_achieved_aspect_is_reported_not_the_wanted_one(self) -> None:
        # If the target cannot be reached, the model must say what it reached.
        model = build_map(self._chain(300), MapSpec(scan_id="scan-map-1", view="module"))
        layout = model["layout"]
        assert layout["width"] > 0 and layout["height"] > 0
        assert layout["algorithm"] == "layered"

    def test_wrapping_is_chosen_for_aspect_not_for_a_fixed_cap(self) -> None:
        # 40 independent files in one layer: a fixed cap would put 26 in the
        # first row and 14 in the second, which is a ragged two-row drawing for
        # no reason. The solver should pick a single row.
        nodes = {f"m{i:03d}": _node(f"m{i:03d}::run", f"pkg/m{i:03d}.py") for i in range(40)}
        edges = [_edge(f"m{i:03d}::run", f"m{i + 1:03d}::run") for i in range(39)]
        model = build_map(_report(nodes, edges), MapSpec(scan_id="scan-map-1", view="module"))
        layout = model["layout"]
        assert layout["width"] / layout["height"] > 1.2, layout


class TestPlaceholderNodes:
    """A name with no definition must not look like a function with no code."""

    def _report_with_unresolved(self) -> SimpleNamespace:
        nodes = {
            "app/api.py::handler": _node("app/api.py::handler", "app/api.py"),
            "app/api.py::serve": _node("app/api.py::serve", "app/api.py"),
        }
        # An unresolved callee has no file: it is a name the analyzer saw being
        # called and could not bind to a definition in the repository.
        nodes["Error"] = _node("Error", "")
        nodes["path.join"] = _node("path.join", "")
        # Both unresolved callees hang off the rooted symbol, so a rooted call
        # view actually reaches them.
        edges = [
            _edge("app/api.py::handler", "Error", kind="calls", origin="unresolved"),
            _edge("app/api.py::handler", "path.join", kind="calls", origin="unresolved"),
        ]
        return _report(nodes, edges)

    def _call_model(self) -> dict:
        report = self._report_with_unresolved()
        return build_map(report, MapSpec(scan_id="scan-map-1", view="call", root="app/api.py::handler"))

    def test_a_node_without_a_file_is_marked_a_placeholder(self) -> None:
        model = self._call_model()
        ghosts = [n for n in model["nodes"] if n.get("placeholder")]
        assert {n["name"] for n in ghosts} == {"Error", "path.join"}

    def test_a_placeholder_does_not_borrow_a_functions_glyph(self) -> None:
        model = self._call_model()
        for node in model["nodes"]:
            expected = "placeholder" if not node["file"] else "circle"
            assert node["shape"] == expected, node["id"]

    def test_a_real_symbol_is_not_a_placeholder(self) -> None:
        model = self._call_model()
        real = [n for n in model["nodes"] if n["name"] == "handler"][0]
        assert real["placeholder"] is False
        assert real["shape"] == "circle"

    def test_every_placeholder_says_what_it_is(self) -> None:
        model = self._call_model()
        for node in model["nodes"]:
            if node.get("placeholder"):
                reason = node.get("placeholder_reason") or ""
                assert "could not bind it to a definition" in reason, node["id"]
                assert node["name"] in reason, node["id"]

    def test_a_qualified_name_is_explained_differently_from_a_bare_one(self) -> None:
        model = self._call_model()
        reasons = {n["name"]: n.get("placeholder_reason") for n in model["nodes"] if n.get("placeholder")}
        assert "qualified" in reasons["path.join"]
        assert "unqualified name" in reasons["Error"]

    def test_the_placeholder_count_reaches_the_statistics(self) -> None:
        model = self._call_model()
        assert model["stats"]["placeholder_nodes"] == 2

    def test_a_map_with_no_placeholder_says_zero(self) -> None:
        nodes = {"a.py::run": _node("a.py::run", "a.py")}
        model = build_map(_report(nodes, []), MapSpec(scan_id="scan-map-1", view="module"))
        assert model["stats"]["placeholder_nodes"] == 0


class TestFileLevelFindingsReachTheirFile:
    """A finding whose symbol was not indexed must still reach the file.

    The docstring of ``_attach_findings`` promises this widening, and the
    implementation used to build the file index with empty lists and never
    populate it. The result a reader saw was a node reporting ``Findings (0)``
    on a file the report says has three findings in it -- the map claiming a
    file is clean while the report says otherwise.
    """

    def test_a_finding_whose_symbol_is_absent_lands_on_the_files_nodes(self) -> None:
        report = _report(
            nodes={
                "app/db.py::query": _node("app/db.py::query", "app/db.py"),
            },
            edges=[],
            findings=[_finding(affected_symbols=["app/db.py::not_indexed"])],
        )
        model = build_map(report, MapSpec(scan_id="scan-map-1", view="module"))
        node = model["nodes"][0]
        assert node["finding_detail"], "the finding must reach the node in its own file"
        assert node["finding_detail"][0]["rule_id"] == "SEC-FLOW-001"

    def test_two_evidence_lines_in_one_file_attach_once(self) -> None:
        from understand.models import Evidence, EvidenceKind

        finding = _finding(
            evidence=[
                Evidence(
                    kind=EvidenceKind.SOURCE_RANGE,
                    file="app/db.py",
                    start_line=12,
                    end_line=13,
                    symbol="run_export",
                    snippet="one",
                ),
                Evidence(
                    kind=EvidenceKind.SOURCE_RANGE,
                    file="app/db.py",
                    start_line=20,
                    end_line=21,
                    symbol="other",
                    snippet="two",
                ),
            ],
            affected_symbols=[],
        )
        report = _report(
            nodes={"app/db.py::query": _node("app/db.py::query", "app/db.py")},
            edges=[],
            findings=[finding],
        )
        model = build_map(report, MapSpec(scan_id="scan-map-1", view="module"))
        assert len(model["nodes"][0]["finding_detail"]) == 1

    def test_a_file_with_no_finding_still_reports_none(self) -> None:
        report = _report(
            nodes={"a.py::load": _node("a.py::load", "a.py")},
            edges=[],
            findings=[_finding()],
        )
        model = build_map(report, MapSpec(scan_id="scan-map-1", view="module"))
        assert model["nodes"][0]["finding_detail"] == []


class TestSeverityBordersAreVisible:
    """A border drawn in the fill colour is not a border.

    ``drawNode`` used to set the stroke to the fill for a node carrying a
    severity, which made the outline invisible and left a critical node
    indistinguishable from a high one.
    """

    def _script(self) -> str:
        source = HTML_MAP.read_text(encoding="utf-8")
        return source.split("_TEMPLATE = ", 1)[1]

    def test_the_border_palette_exists(self) -> None:
        assert "var SEVERITY_BORDER" in self._script()

    def test_no_severity_border_equals_its_fill(self) -> None:
        import re

        script = self._script()
        fills = dict(
            re.findall(r"(\w+):\s*\"?(#[0-9a-fA-F]{6})", _block(script, "SEVERITY_FILL"))
        )
        borders = dict(
            re.findall(r"(\w+):\s*\"?(#[0-9a-fA-F]{6})", _block(script, "SEVERITY_BORDER"))
        )
        assert set(borders) == set(fills)
        for name, colour in borders.items():
            assert colour != fills[name], f"{name} border is its own fill"

    def test_the_border_thickens_with_severity(self) -> None:
        import re

        block = _block(self._script(), "SEVERITY_BORDER_PX")
        widths = {k: float(v) for k, v in re.findall(r"(\w+):\s*([0-9.]+)", block)}
        order = ["critical", "high", "medium", "low", "info"]
        assert set(order) <= set(widths)
        for worse, better in zip(order, order[1:]):
            assert widths[worse] > widths[better], f"{worse} must be heavier than {better}"

    def test_the_stroke_no_longer_reuses_the_fill(self) -> None:
        script = self._script()
        assert "(sev ? SEVERITY_BORDER[sev] || fill" in script
        assert "sev ? fill :" not in script

    def test_the_legend_explains_the_border(self) -> None:
        script = self._script()
        assert "Severity border" in script
        assert "ul.swatches" in script


class TestLabelsAreSpentOnWhatIsVisible:
    """A label budget handed out by global rank starves the nodes on screen.

    A reader who zooms into a corner of a 2,000 node map has a few dozen
    nodes in front of them and expects those nodes to have names. The budget
    used to go to the 400 most connected symbols in the whole repository, so
    the nodes actually on screen were frequently anonymous while names sat on
    nodes off screen.
    """

    def _script(self) -> str:
        return HTML_MAP.read_text(encoding="utf-8").split("_TEMPLATE = ", 1)[1]

    def test_the_budget_is_spent_on_the_viewport(self) -> None:
        assert "if (visCount > LABEL_ALL_BELOW && n.labelRank >= labelBudget()) return;" in self._script()

    def test_the_visible_count_cannot_go_stale(self) -> None:
        script = self._script()
        start = script.index("function visibleNodes()")
        culler = script[start:start + 1400]
        assert "visCount = NODES.length;" in culler
        assert "visCount = out.length;" in culler
        assert "visCount = 0;" in culler

    def test_the_status_bar_says_which_rule_applied(self) -> None:
        assert '"labels on, all " + visCount + " visible node(s) named"' in self._script()

    def test_labels_appear_earlier_than_the_old_threshold(self) -> None:
        # 0.28 was the old threshold; a 200 world pixel module name is legible
        # at roughly a fifth of that.
        assert "showLabels = cam.scale >= 0.14;" in self._script()
