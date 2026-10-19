"""Regression tests for the semantic relation engine.

``EdgeKind`` declared twenty kinds for most of this project's life while six
were ever produced. The remaining fourteen were declarations: a report could
contain an ``INHERITS`` edge only by accident. These tests exist so the relations
stay *honest* as well as present.

The honesty half matters more than the presence half. An earlier draft of the
obligation rules classified ``subprocess.check_output`` as a validator and
``socket.getaddrinfo`` as egress; pointing the tool at microsoft/playwright is
what surfaced both. Nothing here trusts a name without a check that can fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from understand.engine import language_detection as lang
from understand.engine.call_graph import build_call_graph
from understand.engine.graph_snapshot import snapshot_graph
from understand.engine.relations import (
    _AUTHORIZE_RE,
    _EGRESS_METHOD,
    _EGRESS_RECEIVER,
    _VALIDATE_RE,
    attribute_edges,
    build_relations,
    inheritance_edges,
    obligation_edges,
    transform_edges,
)
from understand.engine.relations import (
    test_edges as build_test_edges,
)
from understand.engine.symbol_index import SymbolIndex, parse_module
from understand.models import Edge, EdgeKind, RelationOrigin

DATA_FLOW = Path(__file__).resolve().parents[2] / "src" / "understand" / "engine" / "data_flow.py"


def _index(files: dict[str, str]) -> SymbolIndex:
    index = SymbolIndex()
    for path, text in files.items():
        # Route through the real detector so a .json fixture reaches the
        # structured-data parser and produces config_key symbols, exactly as a
        # real scan would.
        index.add(parse_module(path, text, lang.detect(path).language))
    return index


PY_CHAIN = {
    "app/models.py": '''
class Reader:
    def read(self, handle):
        return handle.read()


class Writer(Reader):
    def write(self, handle, data):
        return handle.write(data)
''',
    "app/service.py": '''
import os
from app.models import Reader, Writer


def normalize_name(raw):
    return raw.strip()


def has_access(user, resource):
    return bool(user)


class Service(Writer):
    def __init__(self):
        self.reader = Reader()
        self.cache = {}

    def load(self, raw):
        self.cache["raw"] = raw
        value = normalize_name(raw)
        if has_access(value, "db"):
            return self.reader.read(value)
        return None

    def handle_request(self, event):
        self.cache["event"] = event
        return event

    def build_url(self, host, path):
        return f"https://{host}{path}"

    def read_settings(self):
        handle = open("settings.json")
        try:
            return handle.read()
        finally:
            handle.close()
''',
    "app/config.json": '{"log_level": "info", "timeout": 30, "retries": 3}',
    "app/api.py": (
        "import json\n"
        "import os\n"
        "import requests\n"
        "\n"
        "from app.service import Service\n"
        "\n"
        "app = Service()\n"
        "\n"
        "\n"
        "def publish_event(payload):\n"
        "    requests.post('https://example.invalid/hook', json=payload)\n"
        "\n"
        "\n"
        "def read_settings():\n"
        "    with open(os.environ['CONFIG_PATH']) as handle:\n"
        "        return json.load(handle)\n"
        "\n"
        "\n"
        "def handle_webhook(event):\n"
        "    return publish_event(event)\n"
        "\n"
        "\n"
        "def register_routes(router):\n"
        "    router.add_handler(handle_webhook)\n"
    ),
    "app/tasks.py": (
        "import json\n"
        "import os\n"
        "\n"
        "\n"
        "registry = {}\n"
        "\n"
        "\n"
        "@registry.task\n"
        "def refresh():\n"
        "    return os.environ['LOG_LEVEL']\n"
    ),
    "tests/test_service.py": (
        "from app.service import Service\n"
        "\n"
        "\n"
        "def test_load():\n"
        "    assert Service().load('x') is not None\n"
    ),
}

TS_CHAIN = {
    "src/store.ts": '''
export interface Reader {
  read(handle: string): string;
}

export class Store implements Reader {
  cache: Map<string, string>;

  constructor() {
    this.cache = new Map();
  }

  read(handle: string): string {
    this.cache.set(handle, handle);
    return handle;
  }
}
''',
}


class TestInheritance:
    def test_python_base_is_provable(self) -> None:
        edges = inheritance_edges(_index(PY_CHAIN))
        inherits = {(e.src.rsplit("::", 1)[-1], e.dst.rsplit("::", 1)[-1]) for e in edges}
        # Service extends Writer, which extends Reader. Transitive ancestry is
        # not claimed here -- only the declared bases are.
        assert ("Service", "Writer") in inherits
        assert ("Writer", "Reader") in inherits
        assert ("Service", "Reader") not in inherits

        service = next(e for e in edges if e.src.endswith("::Service"))
        assert service.origin.value == "static_direct"

    def test_structural_bases_are_never_claimed_as_provable(self) -> None:
        edges = inheritance_edges(_index(TS_CHAIN))
        assert edges, "the TypeScript fixture declares an interface"
        # The interface name resolves, but the base list itself came from a
        # regex over sanitised text, so the edge may not claim to be a fact.
        assert all(e.origin.value in {"inferred", "unresolved"} for e in edges)

    def test_interface_base_is_implements_not_inherits(self) -> None:
        kinds = {e.dst.rsplit("::", 1)[-1]: e.kind.value for e in inheritance_edges(_index(TS_CHAIN))}
        assert kinds["Reader"] == "implements"

    def test_builtin_bases_are_not_relations(self) -> None:
        index = _index({"m.py": "class Boom(Exception):\n    pass\n"})
        assert inheritance_edges(index) == []

    def test_decorator_marker_is_not_a_base_name(self) -> None:
        index = _index({"m.ts": "@Component()\nexport class Widget extends Base {}\n"})
        for edge in inheritance_edges(index):
            assert not edge.dst.startswith("@")


class TestAttributeAccess:
    def test_assignment_is_a_write_and_use_is_a_read(self) -> None:
        edges = attribute_edges(_index(PY_CHAIN))
        writes = {(e.src.rsplit("::", 1)[-1], e.label) for e in edges if e.kind.value == "writes"}
        reads = {(e.src.rsplit("::", 1)[-1], e.label) for e in edges if e.kind.value == "reads"}
        # Symbol ids are qualified: a method is "Service.load", not "load".
        assert ("Service.load", "cache") in writes
        assert ("Service.__init__", "reader") in writes
        assert ("Service.load", "reader") in reads

    def test_mutation_counts_as_a_write(self) -> None:
        index = _index({
            "m.ts": "export class C {\n  run() {\n    this.items.push(1);\n  }\n}\n"
        })
        writes = [e for e in attribute_edges(index) if e.kind.value == "writes"]
        assert any(e.label == "items" for e in writes)

    def test_subscript_assignment_counts_as_a_write(self) -> None:
        index = _index(PY_CHAIN)
        writes = {(e.src.rsplit("::", 1)[-1], e.label) for e in attribute_edges(index)
                  if e.kind.value == "writes"}
        # self.cache["raw"] = raw changes the attribute just as much as a plain
        # assignment does; reporting it as a read only was wrong.
        assert ("Service.load", "cache") in writes

    def test_unresolvable_attribute_is_marked_unresolved(self) -> None:
        edges = attribute_edges(_index(PY_CHAIN))
        assert any(e.origin.value == "unresolved" for e in edges)

    def test_self_is_never_a_relation(self) -> None:
        index = _index({"m.py": "class C:\n  def run(self):\n    return self\n"})
        assert not [e for e in attribute_edges(index) if e.label == "self"]


class TestTransform:
    def test_returning_a_parameter_is_a_transform(self) -> None:
        edges = transform_edges(_index(PY_CHAIN))
        assert any(e.src.endswith("::normalize_name") for e in edges)

    def test_self_loop_is_intentional(self) -> None:
        for edge in transform_edges(_index(PY_CHAIN)):
            # A transform relates a symbol to its own output shape, so src == dst
            # is the point rather than a mistake.
            assert edge.src == edge.dst


class TestObligationVocabularies:
    @pytest.mark.parametrize(
        "name",
        ["validate", "validate_input", "sanitize", "assert_valid", "isValid", "check_schema", "escape"],
    )
    def test_validation_names_match(self, name: str) -> None:
        assert _VALIDATE_RE.match(name)

    @pytest.mark.parametrize(
        "name",
        ["check_output", "checkout", "checker", "checksum", "background", "compile", "get"],
    )
    def test_non_validation_names_do_not_match(self, name: str) -> None:
        # ``check_output`` is a subprocess call, not a validator. An earlier
        # draft put a VALIDATES edge on every subprocess invocation.
        assert not _VALIDATE_RE.match(name)

    @pytest.mark.parametrize("name", ["authorize", "is_admin", "can_edit", "require_auth", "verify_token"])
    def test_authorization_names_match(self, name: str) -> None:
        assert _AUTHORIZE_RE.match(name)

    @pytest.mark.parametrize("name", ["allowsNameFromContent", "handler", "callback", "allowAll"])
    def test_non_authorization_names_do_not_match(self, name: str) -> None:
        # ``allowsNameFromContent`` reads like authorization and is not: it
        # derives an accessible name. Matching it would put an AUTHORIZES edge
        # on accessibility code.
        assert not _AUTHORIZE_RE.match(name)

    @pytest.mark.parametrize("name", ["allow", "allowed", "allowlist", "allows"])
    def test_permission_verbs_match(self, name: str) -> None:
        # ``allow``/``allows``/``allowlist`` all carry the access-control sense
        # closely enough to be worth a reviewer looking.
        assert _AUTHORIZE_RE.match(name)

    def test_egress_needs_verb_or_transport_plus_method(self) -> None:
        assert _EGRESS_RECEIVER.match("axios") and _EGRESS_METHOD.match("post")
        assert not _EGRESS_RECEIVER.match("socket")
        # socket.getaddrinfo is DNS resolution, not egress.
        assert not _EGRESS_METHOD.match("getaddrinfo")

    def test_obligation_edges_need_a_strong_call_origin(self) -> None:
        """An ambiguous name match must not become an obligation claim."""

        files = {
            "a.py": "def parse(text):\n    return text\n\n\ndef use(raw):\n    return parse(raw)\n",
            "tests/assets/bundle.js": "function parse(input) { return input; }\n",
        }
        index = _index(files)
        graph = build_call_graph(index)
        edges = obligation_edges(index, graph)
        # Either no obligation edge, or one that does not point into the bundle.
        assert all("bundle.js" not in e.dst for e in edges)


class TestTestEdges:
    def test_test_symbol_points_at_what_it_exercises(self) -> None:
        files = {
            "app/core.py": "def handle(value):\n    return value\n",
            "tests/test_core.py": (
                "from app.core import handle\n\n\ndef test_handle():\n    assert handle(1) == 1\n"
            ),
        }
        index = _index(files)
        edges = build_test_edges(index, build_call_graph(index))
        assert edges
        assert all(e.src.startswith("tests/") for e in edges)
        assert all(e.dst.startswith("app/") for e in edges)

    def test_a_test_calling_another_test_is_not_a_test_relation(self) -> None:
        files = {
            "app/core.py": "def handle(value):\n    return value\n",
            "tests/test_a.py": "def helper():\n    return 1\n",
            "tests/test_b.py": "from tests.test_a import helper\n\n\ndef test_x():\n    helper()\n",
        }
        index = _index(files)
        assert build_test_edges(index, build_call_graph(index)) == []


class TestBuildRelations:
    def test_every_declared_kind_is_reachable(self) -> None:
        """The whole point: no EdgeKind may be a declaration only.

        ``CALLS``/``IMPORTS``/``DEPENDS_ON`` come from the call graph itself and
        are not the subject here, so this asserts the other fourteen.
        """

        produced: set[str] = set()
        for tree in (PY_CHAIN, TS_CHAIN):
            index = _index(tree)
            graph = build_call_graph(index)
            for edge in build_relations(index, graph):
                produced.add(edge.kind.value)

        expected = {
            "implements", "inherits", "reads", "writes", "transforms",
            "validates", "authorizes", "sends_data_to", "registers",
            "handles_event", "opens_resource", "closes_resource", "tests",
            "influences",
        }
        assert expected - produced == set()

    def test_no_relation_claims_to_be_a_runtime_observation(self) -> None:
        index = _index(PY_CHAIN)
        graph = build_call_graph(index)
        for edge in build_relations(index, graph):
            assert edge.origin.value != "runtime", (
                "a static analyser has no runtime evidence; claiming otherwise "
                "would be a fabricated proof"
            )

    def test_the_source_still_contains_no_print(self) -> None:
        """stdout is the MCP stdio protocol stream."""

        source = DATA_FLOW.read_text(encoding="utf-8")
        assert "print(" not in source


class TestSnapshotFairness:
    """The projection must not let one edge kind eat the whole budget.

    Filling the budget in insertion order meant 120,000 ``calls`` edges consumed
    all of it on a large repository and every semantic relation was dropped: the
    graph was bigger and less informative than before relations existed.
    """

    def _graph(self, calls: int, extra: dict[str, int]) -> object:
        index = SymbolIndex()
        index.add(parse_module("a.py", "def run():\n    return 1\n", "python"))
        graph = build_call_graph(index)
        graph.edges.clear()
        graph.outgoing.clear()
        graph.incoming.clear()
        for i in range(calls):
            graph.add_edge(
                Edge(src="a.py::run", dst=f"n{i}", kind=EdgeKind.CALLS,
                     origin=RelationOrigin.INFERRED, file="a.py", line=1)
            )
        for kind, count in extra.items():
            for i in range(count):
                graph.add_edge(
                    Edge(src="a.py::run", dst=f"{kind}{i}", kind=EdgeKind(kind),
                         origin=RelationOrigin.INFERRED, file="a.py", line=1)
                )
        return index, graph

    def test_a_small_relation_kind_survives_a_huge_call_graph(self) -> None:
        index, graph = self._graph(5_000, {"inherits": 12})
        snapshot = snapshot_graph(index, graph, max_nodes=100, max_edges=500)
        kinds = {e["kind"] for e in snapshot["edges"]}
        assert "calls" in kinds
        assert "inherits" in kinds, "the 12-edge kind was starved by 5,000 calls"

    def test_counts_are_reported_per_kind(self) -> None:
        index, graph = self._graph(200, {"inherits": 5, "reads": 9})
        snapshot = snapshot_graph(index, graph, max_nodes=100, max_edges=10_000)
        assert snapshot["edges_by_kind"]["inherits"] == 5
        assert snapshot["edges_by_kind"]["reads"] == 9
        assert snapshot["edges_by_kind"]["calls"] == 200

    def test_truncation_is_reported_when_the_budget_bites(self) -> None:
        index, graph = self._graph(5_000, {})
        snapshot = snapshot_graph(index, graph, max_nodes=100, max_edges=100)
        assert snapshot["truncated"] is True
        assert snapshot["edges_omitted"] > 0
