"""Code-map model construction.

A stored scan carries a bounded graph snapshot.  Reading 285,307 edges as JSON
is not something a person does, so this module turns that snapshot into a small,
honest, deterministic *map model*: the nodes, the edges between them, the
legend that explains every style, and the block that states what the analysis
did not prove.

Three rules govern everything here.

1. **A map never invents.**  Every node comes from a snapshot node, every edge
   from a snapshot edge.  The map may drop edges under a budget, but it never
   adds one the scan did not record.
2. **A truncated map says so.**  When a budget binds, ``stats`` carries the
   omitted counts and the renderer prints them in the status bar.  A map that
   looks complete but is not is worse than no map.
3. **The same scan yields the same map.**  Layout is computed here, in Python,
   from a seed derived from the scan id, so the output is byte-identical across
   runs and can be diffed in a review.

The renderer (``understand.reporting.html_map``) receives a
:class:`MapModel` and nothing else.  It never reads the repository, so it has
no way to fabricate a fact the model does not already carry.
"""

from __future__ import annotations

import itertools
import os
from dataclasses import dataclass, field, replace
from typing import Any

from ..errors import ValidationError
from ..models import EdgeKind
from .code_map_common import (
    EDGE_STYLES,
    FINDING_DETAIL_BUDGET,
    FLOWS_PER_FINDING,
    NODE_FINDING_CAP,
    NODE_SHAPES,
    SEVERITY_ORDER,
)
from .code_map_layout import (
    _collapsed_symbols,
    _depth_floor,
    _edge_counts,
    _files_within,
    _honesty,
    _layout_module,
    _legend,
    _rank_to_severity,
    _relative_depth,
    _seed,
    _severity_name,
    _worst_severity,
)

__all__ = [
    "EDGE_STYLES",
    "EXPLAIN_KINDS",
    "FINDING_VIEWS",
    "MAX_DEPTH",
    "NODE_SHAPES",
    "SEVERITY_ORDER",
    "SYMBOL_VIEWS",
    "VIEWS",
    "VIEW_KINDS",
    "VIEW_QUESTIONS",
    "MapBudget",
    "MapSpec",
    "build_map",
    "explain_finding",
    "validate_spec",
]

#: Hard ceiling on traversal depth.  Past this a call tree stops being a map and
#: becomes the graph again.
MAX_DEPTH = 6

_ALL_KINDS: frozenset[str] = frozenset(kind.value for kind in EdgeKind)


#: Every view is a different *question*, not a different arrangement of the same
#: nodes.  ``module`` collapses the symbol graph onto files; the rest keep symbols
#: and traverse outward from a root.
VIEWS: tuple[str, ...] = (
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
)

#: Which relation kinds each view draws.  A view that never draws a kind is a
#: view that should not accept a filter for it.
VIEW_KINDS: dict[str, frozenset[str]] = {
    "module": _ALL_KINDS,
    # "what does this call" and "what calls this" are the two halves of the call
    # graph.  Reads and writes are deliberately excluded: they relate a method to
    # its own fields, not to another function, so on a call map they would be
    # self-loops drawn between neighbours.
    "call": frozenset({"calls", "awaits_task", "starts_task"}),
    "inheritance": frozenset({"inherits", "implements"}),
    # "what does this module import" is the same question as the module map but at
    # the symbol level for a single subtree, so it keeps only structural edges.
    "dependency": frozenset({"imports", "depends_on"}),
    # The subject of a test edge is the thing under test; drawing the test's own
    # calls would answer a different question.
    "test": frozenset({"tests"}),
    # "who raises it and who listens". Both halves are kept because half an
    # event map is not an event map: the emitter with no listener and the
    # listener with no emitter are both questions people actually ask.
    "event": frozenset({"registers", "handles_event"}),
    # "what this code promises". A validation, an authorisation check and a
    # network egress are all obligations the caller should know about before
    # relying on the function, so they belong in one view rather than three.
    "obligation": frozenset(
        {"validates", "authorizes", "sends_data_to", "opens_resource", "closes_resource"}
    ),
    # "what changes this". Config keys and environment reads are the two ways a
    # repository's behaviour is decided from outside its code.
    "influence": frozenset({"configures", "influences"}),
    # The data-flow view is built from findings rather than from the graph: a
    # flow the analyzer never proved has no edges to draw, so drawing the
    # graph here would show the call graph under a misleading name.
    "data_flow": frozenset({"calls"}),
    # The finding view is built from findings too, for the same reason.
    "finding": _ALL_KINDS,
}

#: Views that keep symbols instead of collapsing them onto files.
SYMBOL_VIEWS: frozenset[str] = frozenset(
    {
        "call",
        "inheritance",
        "dependency",
        "test",
        "event",
        "obligation",
        "influence",
    }
)

#: Views built from findings rather than from the graph.  They are excluded from
#: ``SYMBOL_VIEWS`` because a traversal from a root is the wrong model for them:
#: their nodes come from a finding's own recorded evidence.
FINDING_VIEWS: frozenset[str] = frozenset({"data_flow", "finding"})

#: One-line question per view, surfaced by ``understand map views`` and by the
#: renderer's own header.  A view whose purpose has to be inferred from its name
#: is a view nobody will open twice.
VIEW_QUESTIONS: dict[str, str] = {
    "module": "Which files depend on which files?",
    "call": "What does this symbol call, and what calls it?",
    "inheritance": "What does this class extend or implement, and what extends it?",
    "dependency": "What does this module import, directly or transitively?",
    "test": "What does this test actually exercise?",
    "event": "Who raises this event, and who listens for it?",
    "obligation": "What does this code validate, authorise, or send?",
    "influence": "What configuration decides how this behaves?",
    "data_flow": "How does untrusted input reach this sink?",
    "finding": "Where are the findings, and how bad are they?",
}


#: Glyph for a node that has no file of its own.  Such a node is not a symbol
#: the analyzer read: it is the *name* of something the code calls that the
#: analyzer could not bind to a definition -- ``Error``, ``async``,
#: ``path.join``.  Drawing it with the same glyph as a real function invited
#: the reader to click it expecting source and find none, which reads as a
#: broken tool rather than as an honest limit of static analysis.
PLACEHOLDER_SHAPE = "placeholder"


def _shape_for(kind: str, path: str) -> str:
    """Glyph for a node: a placeholder when it has no file, its kind otherwise."""

    if not path:
        return PLACEHOLDER_SHAPE
    return NODE_SHAPES.get(kind, NODE_SHAPES["unknown"])


@dataclass(frozen=True)
class MapBudget:
    """Ceilings the caller may tighten but never remove."""

    max_nodes: int = 2_000
    max_edges: int = 8_000

    def __post_init__(self) -> None:
        for name in ("max_nodes", "max_edges"):
            value = getattr(self, name)
            if value <= 0:
                raise ValidationError(f"map budget {name} must be positive, got {value}")


@dataclass(frozen=True)
class MapSpec:
    """What to draw.  Carries no coordinates and no styling."""

    scan_id: str
    view: str = "module"
    root: str = ""
    depth: int = 3
    direction: str = "both"
    kinds: frozenset[str] = frozenset()
    include_findings: bool = True
    budget: MapBudget = field(default_factory=MapBudget)

    def resolved_kinds(self) -> frozenset[str]:
        if self.kinds:
            return self.kinds
        return VIEW_KINDS.get(self.view, _ALL_KINDS)

    def describe(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "view": self.view,
            "root": self.root,
            "depth": self.depth,
            "direction": self.direction,
            "kinds": sorted(self.resolved_kinds()),
            "include_findings": self.include_findings,
            "budget": {
                "max_nodes": self.budget.max_nodes,
                "max_edges": self.budget.max_edges,
            },
        }


def validate_spec(spec: MapSpec) -> MapSpec:
    """Return a normalised copy of ``spec`` or raise :class:`ValidationError`.

    The CLI and the MCP server both call this, so an invalid map request fails
    the same way on both surfaces.
    """

    if not spec.scan_id or not spec.scan_id.strip():
        raise ValidationError("a scan id is required to build a map")
    if spec.view not in VIEWS:
        raise ValidationError(
            f"unknown map view {spec.view!r}",
            detail={"supported": list(VIEWS)},
        )
    if spec.direction not in ("out", "in", "both"):
        raise ValidationError(
            f"unknown map direction {spec.direction!r}",
            detail={"supported": ["out", "in", "both"]},
        )
    if spec.depth < 1 or spec.depth > MAX_DEPTH:
        raise ValidationError(f"map depth must be between 1 and {MAX_DEPTH}, got {spec.depth}")
    unknown = sorted(set(spec.kinds) - _ALL_KINDS)
    if unknown:
        raise ValidationError(
            f"unknown relation kind(s): {', '.join(unknown)}",
            detail={"supported": sorted(_ALL_KINDS)},
        )
    return replace(spec, kinds=frozenset(spec.resolved_kinds()))


# --------------------------------------------------------------------------- #
# Construction
# --------------------------------------------------------------------------- #
def build_map(report: Any, spec: MapSpec) -> dict[str, Any]:
    """Build the map model for ``report`` according to ``spec``."""

    spec = validate_spec(spec)
    snapshot = getattr(report, "graph_snapshot", None) or {}
    raw_nodes: dict[str, Any] = snapshot.get("nodes") or {}
    raw_edges: list[dict[str, Any]] = snapshot.get("edges") or []

    if not raw_nodes:
        return _empty_model(spec, "this scan stored no graph snapshot")

    builder = _BUILDERS[spec.view]
    model = builder(report, spec, raw_nodes, raw_edges)

    model["meta"].update(
        {
            "tool": "understand",
            "scan_id": spec.scan_id,
            "repository": str(getattr(report, "repository", "") or ""),
            "revision": str(getattr(report, "revision", "") or ""),
            "spec": spec.describe(),
        }
    )
    if spec.include_findings:
        # A severity histogram answers "how bad is this file". It does not answer
        # "why", which is the question a reader has after clicking a node. The
        # detail pass is shared by every view so a new view cannot forget it.
        _attach_findings(model, report)
        _attach_source(model)
    _annotate_placeholders(model)
    model["honesty"] = _honesty(report, snapshot, spec, model)
    return model


def _empty_model(spec: MapSpec, reason: str) -> dict[str, Any]:
    return {
        "meta": {"view": spec.view, "empty_reason": reason},
        "nodes": [],
        "edges": [],
        "legend": _legend(spec),
        "stats": {
            "nodes": 0,
            "edges": 0,
            "edges_by_kind": {},
            "collapsed": 0,
            "omitted_nodes": 0,
            "omitted_edges": 0,
            "budget_omitted": {},
        },
        "layout": {"algorithm": "none", "seed": _seed(spec), "converged": True},
        "honesty": {
            "unresolved_call_targets": 0,
            "confidence": {},
            "caveats": [reason],
        },
    }


# --------------------------------------------------------------------------- detail


#: Lines of a symbol's body attached to its node, and the character ceiling on
#: each. Enough to recognise the function; not enough to paste the file.
BODY_LINES = 24
SNIPPET_CHARS = 1200
EVIDENCE_CHARS = 400


def _clip(text: Any, limit: int) -> str:
    value = str(text or "").rstrip()
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _enum_text(value: Any) -> str:
    """The wire form of an enum member, not its ``repr``.

    ``Severity`` mixes ``str``, so on Python 3.11 ``str(Severity.MEDIUM)`` is
    ``"Severity.MEDIUM"`` and not ``"medium"``. A map that printed that would
    tell a reader nothing they could match against a finding id or a filter, and
    the value is already the string the rest of the system uses.
    """
    raw = getattr(value, "value", value)
    return str(raw or "")


def _finding_detail(finding: Any, node_ids: list[str]) -> dict[str, Any]:
    """One finding, shaped for a reader rather than for the store.

    Everything here already exists on the model. The work is choosing what a
    person needs in order to judge it, and dropping what they do not: the
    analyzer version, the fingerprint, the id of the scan it came from.
    """
    evidence = []
    for item in getattr(finding, "evidence", ()) or ():
        evidence.append(
            {
                "kind": str(getattr(item, "kind", "") or ""),
                "file": str(getattr(item, "file", "") or ""),
                "start_line": int(getattr(item, "start_line", 0) or 0),
                "end_line": int(getattr(item, "end_line", 0) or 0),
                "symbol": str(getattr(item, "symbol", "") or ""),
                "snippet": _clip(getattr(item, "snippet", ""), EVIDENCE_CHARS),
                "origin": str(getattr(item, "origin", "") or ""),
            }
        )
    return {
        "finding_id": str(getattr(finding, "finding_id", "") or ""),
        "rule_id": str(getattr(finding, "rule_id", "") or ""),
        "title": str(getattr(finding, "title", "") or ""),
        "category": str(getattr(finding, "category", "") or ""),
        "severity": _enum_text(getattr(finding, "severity", "")),
        "confidence": _enum_text(getattr(finding, "confidence", "")),
        "verification_status": _enum_text(getattr(finding, "verification_status", "")),
        "language": str(getattr(finding, "language", "") or ""),
        "summary": _clip(getattr(finding, "summary", ""), 600),
        "technical_explanation": _clip(getattr(finding, "technical_explanation", ""), 1400),
        "impact": _clip(getattr(finding, "impact", ""), 800),
        "remediation": _clip(getattr(finding, "remediation", ""), 1000),
        "assumptions": [str(x) for x in (getattr(finding, "assumptions", ()) or ())],
        "preconditions": [str(x) for x in (getattr(finding, "preconditions", ()) or ())],
        "references": [str(x) for x in (getattr(finding, "references", ()) or ())],
        "confidence_rationale": _clip(getattr(finding, "confidence_rationale", ""), 400),
        "analysis_method": str(getattr(finding, "analysis_method", "") or ""),
        "evidence": evidence,
        "data_flows": [[str(x) for x in flow] for flow in (getattr(finding, "data_flows", ()) or ())][:6],
        "call_chains": [[str(x) for x in chain] for chain in (getattr(finding, "call_chains", ()) or ())][:6],
        "affected_symbols": [str(x) for x in (getattr(finding, "affected_symbols", ()) or ())][:12],
        "nodes": node_ids,
    }


def _annotate_placeholders(model: dict[str, Any]) -> None:
    """Say, per placeholder node, what kind of unresolvable name it is.

    "This node has no file of its own" is true of three quite different things,
    and a reader who cannot tell them apart concludes the tool is broken. The
    distinctions are all visible in the name itself, so they are stated here
    rather than left for the reader to guess from a hollow rectangle.
    """

    stats = model.setdefault("stats", {})
    stats.setdefault("placeholder_nodes", 0)
    for node in model.get("nodes", []):
        if not node.get("placeholder"):
            continue
        stats["placeholder_nodes"] = int(stats["placeholder_nodes"]) + 1
        name = str(node.get("name") or node.get("id") or "")
        head = (
            "No code is attached to this node because there is none. This is the "
            "name of something the analysed code calls that the analyzer could not "
            "bind it to a definition in this repository. "
        )
        if node.get("flow_role") in ("source", "sink", "caller", "via", "step"):
            node["placeholder_reason"] = (
                head + "It is an end of a traced data-flow path: the analyzer named "
                "the role it plays (a source, a sink, the caller it entered from) but "
                "found no definition for it here."
            )
        elif "." in name and "(" not in name:
            node["placeholder_reason"] = (
                head + "`" + name + "` is qualified, which usually means it is a "
                "method on a value the analyzer did not resolve -- most often part "
                "of the standard library or of a third-party dependency. The call is "
                "real; only the receiver's definition is outside this repository."
            )
        else:
            node["placeholder_reason"] = (
                head + "`" + name + "` is an unqualified name with no definition "
                "here, which usually means it comes from the standard library or a "
                "third-party dependency, or is chosen dynamically at run time. The "
                "call is real; only its target is outside this repository."
            )


def _attach_findings(model: dict[str, Any], report: Any) -> None:
    """Give every node the findings that actually land on it.

    A finding is attributed to a node two ways, and the second one is a
    deliberate widening: a finding whose evidence is in this file but whose
    ``affected_symbols`` does not name this node still belongs on the node a
    reader will click. Hiding it would mean the map says a file is clean when
    the report disagrees.
    """
    nodes = model.get("nodes") or []
    by_id = {str(node.get("id")): node for node in nodes}
    findings = list(getattr(report, "findings", ()) or ())

    attributed: dict[str, list[dict[str, Any]]] = {}
    files_touched: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        target_ids = [str(s) for s in (getattr(finding, "affected_symbols", ()) or ()) if str(s) in by_id]
        # One detail per finding, shared by both indexes. Building it twice
        # would defeat the de-duplication below, because two equal dicts are
        # still two objects.
        detail = _finding_detail(finding, target_ids)
        # Every finding is indexed by file, not only the ones whose symbol
        # survived the node budget. A finding whose ``affected_symbols`` names a
        # symbol the snapshot does not contain still happened in a file, and
        # skipping it here is what left a reader staring at a node that said
        # "Findings (0)" while the report disagreed.
        for item in getattr(finding, "evidence", ()) or ():
            path = str(getattr(item, "file", "") or "")
            if path and detail not in files_touched.setdefault(path, []):
                files_touched[path].append(detail)
        for node_id in target_ids:
            attributed.setdefault(node_id, []).append(detail)

    # Only the files that actually back a node can widen anything.
    by_file: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        path = str(node.get("file") or "")
        if path and path not in by_file:
            by_file[path] = files_touched.get(path, [])

    budget = FINDING_DETAIL_BUDGET
    attached = 0
    withheld = 0
    for node in nodes:
        node_id = str(node.get("id"))
        path = str(node.get("file") or "")
        chosen = attributed.get(node_id) or by_file.get(path) or []
        if budget <= 0:
            withheld += len(chosen)
            continue
        keep = chosen[:NODE_FINDING_CAP]
        budget -= len(keep)
        attached += len(keep)
        withheld += len(chosen) - len(keep)
        node["finding_detail"] = keep
        node["finding_detail_total"] = len(chosen)

    stats = model.setdefault("stats", {})
    stats["findings_attached"] = attached
    stats["findings_withheld"] = withheld
    stats["findings_cap"] = NODE_FINDING_CAP


def _repository_root(display: str) -> str:
    """The local directory a stored scan still points at, or ``""``.

    A scan of a local repository records the path it was given, so the source is
    usually still there and a node can carry its own body. A scan of a remote
    repository records a URL and a temporary clone that is long gone, and a
    repository that has since moved or been deleted is equally common. Both
    cases are normal; neither is an error, and the model says which happened
    rather than pretending the code exists.
    """
    text = str(display or "").strip()
    if not text or "://" in text or "@" in text.split("/")[0]:
        return ""
    if not os.path.isdir(text):
        return ""
    return os.path.abspath(text)


def _attach_source(model: dict[str, Any]) -> None:
    """Attach each node's own source lines when the repository is still readable.

    The stored snapshot deliberately carries no source text: it is written for
    traces that must work without the repository. A map is read by a person
    looking at code, and "what does this function do" cannot be answered by an
    id, a line range and a list of edges. So the body is read here, from disk,
    at map-build time, and only when the path in the scan still exists.
    """
    meta = model.get("meta") or {}
    root = _repository_root(str(meta.get("repository") or ""))
    nodes = model.get("nodes") or []

    if not root:
        for node in nodes:
            node["source"] = ""
            node["source_available"] = False
        stats = model.setdefault("stats", {})
        stats["source_root"] = ""
        stats["source_nodes"] = 0
        stats["source_reason"] = (
            "the repository this scan came from is not a readable local directory "
            "(a remote clone is temporary and is gone), so nodes carry no source text"
        )
        return

    wanted: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        path = str(node.get("file") or "")
        if path:
            wanted.setdefault(path, []).append(node)

    filled = 0
    unreadable: list[str] = []
    for path, owners in wanted.items():
        lines: list[str] = []
        try:
            with open(os.path.join(root, path), encoding="utf-8", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError:
            unreadable.append(path)
            continue
        for node in owners:
            start = max(1, int(node.get("start_line") or 1))
            end = int(node.get("end_line") or 0) or start
            body = lines[start - 1 : max(start, end)]
            if not body:
                body = lines[start - 1 : start]
            text = "\n".join(body[:BODY_LINES])
            if len(body) > BODY_LINES:
                text += f"\n… {len(body) - BODY_LINES} more line(s)"
            node["source"] = _clip(text, SNIPPET_CHARS)
            node["source_available"] = bool(node["source"])
            node["body_lines"] = len(body)
            if node["source"]:
                filled += 1

    stats = model.setdefault("stats", {})
    stats["source_root"] = root
    stats["source_nodes"] = filled
    stats["source_reason"] = ""
    if unreadable:
        stats["source_reason"] = (
            f"{len(unreadable)} file(s) could not be read from the recorded "
            "repository path, so those nodes carry no source text"
        )


# --------------------------------------------------------------------------- explain
# ``explain_finding`` answers the question a map click cannot: not "what is
# this node" but "how did untrusted input get here, and what stops it". It is
# deliberately a separate entry point from the map, because the map is a
# picture and this is an argument. A picture that stops at the sink and never
# says what was not proven is how a heuristic becomes a false alarm.
EXPLAIN_KINDS = {
    "security": frozenset({"calls", "inherits", "implements", "reads", "writes",
                           "transforms", "validates", "authorizes", "sends_data_to",
                           "handles_event", "registers", "influences", "imports"}),
    "bugs": frozenset({"calls", "reads", "writes", "transforms", "awaits_task",
                       "starts_task", "imports"}),
    "architecture": frozenset({"calls", "depends_on", "imports", "inherits", "implements"}),
    "dependencies": frozenset({"imports", "depends_on"}),
    "reliability": frozenset({"calls", "opens_resource", "closes_resource", "awaits_task"}),
}


def explain_finding(
    report: Any,
    finding_id: str,
    *,
    depth: int = 4,
    budget: MapBudget | None = None,
) -> dict[str, Any]:
    """Build the causal account of one finding, with its map request.

    The output is ordered the way a reader has to follow an argument: what was
    found, where, why it matters, the chain that carries the value, the
    evidence that supports each link, what must be true for it to be
    exploitable, and — separately and explicitly — what this analysis did not
    establish. Returning the map request alongside the prose means the two can
    never disagree about which symbol the account is about.
    """

    from ..errors import FindingNotFound, ValidationError

    if not finding_id or not finding_id.strip():
        raise ValidationError("a finding id is required")

    finding = None
    for candidate in report.findings:
        if candidate.finding_id == finding_id or candidate.rule_id == finding_id:
            finding = candidate
            break
    if finding is None:
        raise FindingNotFound(
            f"no finding with id {finding_id!r} in this scan",
            detail={"scan_id": report.scan_id, "findings": len(report.findings)},
        )
    finding.ensure_id()

    detail = _finding_detail(finding, [])
    traced = bool(getattr(finding, "data_flows", None) or getattr(finding, "call_chains", None))
    chain = _explain_chain(finding)

    snapshot = report.graph_snapshot or {}
    node_ids = set(snapshot.get("nodes") or {})
    file_hint = finding.evidence[0].file if finding.evidence else ""
    root = _explain_root(finding, node_ids, file_hint)
    view = "call"
    if finding.category in ("architecture", "dependencies"):
        view = "dependency"
    elif finding.category == "bugs":
        view = "call"

    categories = {str(f.category) for f in report.findings}
    kind_fallback = EXPLAIN_KINDS.get(str(finding.category))
    if kind_fallback is None:
        # A category with no hand-written set falls back to the union of what
        # the scan actually contains, so the map is never empty because of a
        # missing table entry.
        kind_fallback = frozenset(
            str(e.get("kind")) for e in (report.graph_snapshot or {}).get("edges", [])
            if e.get("kind")
        )
    unused_categories = sorted(categories - {str(finding.category)})

    where = ""
    if finding.evidence:
        anchor = finding.evidence[0]
        where = f"{anchor.file}:{anchor.start_line}"
        if anchor.symbol:
            where += f" in {anchor.symbol}"

    caveats: list[str] = []
    if str(finding.verification_status) in ("inconclusive", "not_verified"):
        caveats.append(
            "This finding is marked " + _enum_text(finding.verification_status) +
            ". That means the analysis did not reach a conclusion about "
            "exploitability, not that it found one."
        )
    if str(finding.confidence) == "low":
        caveats.append(
            "Confidence is low. Treat this as a place worth reading, not as a "
            "demonstrated defect."
        )
    if not traced:
        # The chain below falls back to the evidence line so the account is
        # never blank, but a fallback is not a trace and must not be read as
        # one.
        caveats.append(
            "No data-flow or call chain was recorded for this finding, so the "
            "account stops at the sink. The path from untrusted input to this "
            "line was not traced."
        )
    unresolved = int((report.graph_snapshot or {}).get("unresolved") or 0)
    if unresolved:
        caveats.append(
            f"{unresolved} call target(s) in this scan could not be resolved to a "
            "symbol, so a step in the chain may be missing."
        )
    if (report.graph_snapshot or {}).get("truncated"):
        caveats.append(
            "The stored graph snapshot is truncated. A caller of this function "
            "may exist in the repository and not in this analysis."
        )

    return {
        "scan_id": report.scan_id,
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "category": _enum_text(finding.category),
        "severity": _enum_text(finding.severity),
        "confidence": _enum_text(finding.confidence),
        "verification_status": _enum_text(finding.verification_status),
        "where": where,
        "what": detail["summary"],
        "how": detail["technical_explanation"],
        "impact": detail["impact"],
        "chain": chain,
        "evidence": detail["evidence"],
        "call_chains": detail["call_chains"],
        "must_be_true": detail["preconditions"],
        "not_proven": detail["assumptions"],
        "confidence_rationale": detail["confidence_rationale"],
        "remediation": detail["remediation"],
        "references": detail["references"],
        "analysis_method": detail["analysis_method"],
        "map": {
            "view": view,
            "root": root,
            "depth": max(1, min(int(depth), MAX_DEPTH)),
            "kinds": sorted(kind_fallback),
        },
        "other_categories_in_this_scan": unused_categories,
        "caveats": caveats,
        "budget": {
            "max_nodes": budget.max_nodes if budget else MapBudget().max_nodes,
            "max_edges": budget.max_edges if budget else MapBudget().max_edges,
        },
    }


def _resolve_node_id(candidate: str, node_ids: set[str], file_hint: str) -> str:
    """Turn a symbol name into a node id the map can actually root on.

    A hop says ``ParquetReporter.onEnd``; the snapshot calls the same symbol
    ``tests/config/parquetReporter.ts::ParquetReporter.onEnd``. Recommending
    the bare name produces a command that silently draws an empty map, which is
    worse than recommending nothing.
    """

    if not candidate:
        return ""
    if candidate in node_ids:
        return candidate
    if file_hint:
        qualified = f"{file_hint}::{candidate}"
        if qualified in node_ids:
            return qualified
    for node_id in node_ids:
        if node_id.endswith("::" + candidate):
            return node_id
    return ""


def _explain_root(finding: Any, node_ids: set[str], file_hint: str) -> str:
    """Pick the symbol a map should be centred on for this finding.

    The symbol the analyzer blamed is the obvious answer and the wrong one
    about half the time: for a taint finding the interesting graph is the path
    that *reaches* it, which starts upstream. When the finding carries an
    explicit chain, its first hop is that entry point; otherwise the blamed
    symbol is the honest centre.
    """

    flows = [
        [str(h).strip() for h in (flow if isinstance(flow, (list, tuple)) else [flow])]
        for flow in (getattr(finding, "data_flows", None) or [])
    ]
    # "in <symbol>" names the scope a hop happened in. Scan every flow before
    # settling: the first flow's scopes are its callers, and the scope holding
    # the sink is the one a map must be centred on.
    scopes = [
        h[3:].strip()
        for hops in flows
        for h in hops
        if h.startswith("in ") and h[3:].strip() not in ("", "<module>")
    ]
    if scopes:
        return _resolve_node_id(scopes[-1], node_ids, file_hint) or scopes[-1]
    for hops in flows:
        # "entered from <symbol>" names the caller on the way in.
        for hop in hops:
            if hop.startswith("entered from "):
                caller = hop[len("entered from "):].strip()
                if caller and " " not in caller and caller != "<module>":
                    return _resolve_node_id(caller, node_ids, file_hint) or caller
        first = hops[0] if hops else ""
        token = first[3:].strip() if first.startswith("in ") else first
        if token and all(ch.isalnum() or ch in "_$:." for ch in token) and " " not in token:
            return _resolve_node_id(token, node_ids, file_hint) or token
    symbols = list(getattr(finding, "affected_symbols", None) or [])
    symbols = [str(s) for s in symbols if str(s) and not str(s).endswith("::<module>")]
    for symbol in symbols:
        resolved = _resolve_node_id(symbol, node_ids, file_hint)
        if resolved:
            return resolved
    return symbols[0] if symbols else ""


def _explain_chain(finding: Any) -> list[dict[str, Any]]:
    """The ordered argument from source to sink, as steps a reader can follow."""

    steps: list[dict[str, Any]] = []
    for flow in getattr(finding, "data_flows", None) or []:
        hops = list(flow) if isinstance(flow, (list, tuple)) else [flow]
        for position, hop in enumerate(hops):
            steps.append(
                {
                    "step": len(steps) + 1,
                    "hop": str(hop),
                    "role": "source" if position == 0 else
                            ("sink" if position == len(hops) - 1 else "propagation"),
                }
            )
    if not steps:
        for chain_hops in getattr(finding, "call_chains", None) or []:
            hops = list(chain_hops) if isinstance(chain_hops, (list, tuple)) else [chain_hops]
            for hop in hops:
                steps.append({"step": len(steps) + 1, "hop": str(hop), "role": "call"})
    if not steps:
        for position, evidence in enumerate(getattr(finding, "evidence", None) or []):
            steps.append(
                {
                    "step": position + 1,
                    "hop": f"{evidence.file}:{evidence.start_line}",
                    "role": "sink",
                }
            )
    return steps


def _module_map(
    report: Any,
    spec: MapSpec,
    raw_nodes: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Collapse the symbol graph onto files.

    A module map answers "which files talk to which files".  Symbol-level detail
    is noise at that zoom level and would push a 40-file project past any
    readable node count.
    """

    wanted = spec.resolved_kinds()
    file_of: dict[str, str] = {}
    for node_id, node in raw_nodes.items():
        path = str(node.get("file") or "")
        if path:
            file_of[node_id] = path

    if not file_of:
        return _empty_model(spec, "no node in this snapshot carries a file path")

    if spec.root:
        wanted_files = _files_within(file_of.values(), spec.root)
        if not wanted_files:
            return _empty_model(spec, f"root {spec.root!r} matches no indexed file")
    else:
        wanted_files = set(file_of.values())

    # Findings are counted per file so a node can be coloured by its worst
    # severity.  Evidence is the only place a finding names a file.
    severity_by_file: dict[str, dict[str, int]] = {}
    if spec.include_findings:
        for finding in getattr(report, "findings", ()) or ():
            for item in getattr(finding, "evidence", ()) or ():
                path = str(getattr(item, "file", "") or "")
                if not path:
                    continue
                bucket = severity_by_file.setdefault(path, {})
                name = _severity_name(getattr(finding, "severity", None))
                bucket[name] = bucket.get(name, 0) + 1

    # Collapse edges.  A pair of files can be joined by several kinds; each kind
    # is kept separately so the legend stays meaningful, and the counts say how
    # often.
    collapsed: dict[tuple[str, str, str], dict[str, Any]] = {}
    direction = spec.direction
    for edge in raw_edges:
        kind = str(edge.get("kind") or "")
        if kind not in wanted:
            continue
        src = file_of.get(str(edge.get("src") or ""))
        dst = file_of.get(str(edge.get("dst") or ""))
        if not src or not dst or src == dst:
            continue
        if src not in wanted_files and dst not in wanted_files:
            continue
        if direction == "out" and src not in wanted_files:
            continue
        if direction == "in" and dst not in wanted_files:
            continue
        key = (src, dst, kind)
        record = collapsed.get(key)
        if record is None:
            collapsed[key] = {
                "src": src,
                "dst": dst,
                "kind": kind,
                "origin": str(edge.get("origin") or "inferred"),
                "count": 1,
                "lines": {int(edge.get("line") or 0)} - {0},
            }
        else:
            record["count"] += 1
            record["lines"].add(int(edge.get("line") or 0))

    node_files = {src for src, _dst, _kind in collapsed} | {dst for _src, dst, _kind in collapsed}
    if not node_files:
        # No relation survived, but the files are still real and the caller
        # asked for a map of them. Rendering nothing would read as "this
        # repository has no files", which is a different and wrong claim.
        node_files = set(wanted_files)
    if spec.root:
        node_files |= {path for path in wanted_files if path == spec.root}
    node_files = {path for path in node_files if path in wanted_files or not spec.root}

    omitted_nodes = max(0, len(node_files) - spec.budget.max_nodes)
    node_list = sorted(node_files)[: spec.budget.max_nodes]
    kept = set(node_list)

    edge_list: list[dict[str, Any]] = []
    budget_omitted: dict[str, int] = {}
    for (src, dst, kind) in sorted(collapsed):
        record = collapsed[(src, dst, kind)]
        if src not in kept or dst not in kept:
            omitted_nodes += 1
            continue
        if len(edge_list) >= spec.budget.max_edges:
            budget_omitted[kind] = budget_omitted.get(kind, 0) + 1
            continue
        origins = record["origin"]
        edge_list.append(
            {
                "src": src,
                "dst": dst,
                "kind": kind,
                "origin": origins,
                "confidence": EDGE_STYLES.get(origins, "dashed"),
                "count": record["count"],
                "file": src,
                "line": 0,
                "label": f"{kind} x{record['count']}",
            }
        )

    nodes = []
    floor = _depth_floor(node_list)
    for path in node_list:
        severities = severity_by_file.get(path, {})
        depth = _relative_depth(path, spec.root)
        if not spec.root:
            depth = max(0, depth - floor)
        nodes.append(
            {
                "id": path,
                "name": path.rsplit("/", 1)[-1],
                "kind": "module",
                "file": path,
                "start_line": 0,
                "end_line": 0,
                "language": "",
                "exported": True,
                "depth_from_root": depth,
                "finding_severity": _worst_severity(severities),
                "finding_count": sum(severities.values()),
                "unresolved_calls": 0,
                "shape": NODE_SHAPES["module"],
                "findings": (
                    {name: severities.get(name, 0) for name in SEVERITY_ORDER if severities.get(name)}
                    if spec.include_findings
                    else {}
                ),
            }
        )

    stats = {
        "nodes": len(nodes),
        "edges": len(edge_list),
        "edges_by_kind": _edge_counts(edge_list),
        "collapsed": _collapsed_symbols(len(raw_nodes), len(nodes)),
        "omitted_nodes": omitted_nodes,
        "omitted_edges": 0,
        "budget_omitted": budget_omitted,
    }
    layout = _layout_module(nodes, edge_list, spec)
    model = {
        "meta": {"view": "module", "root": spec.root},
        "nodes": nodes,
        "edges": edge_list,
        "legend": _legend(spec),
        "stats": stats,
        "layout": layout,
        "honesty": {},
    }
    return model


# --------------------------------------------------------------------------- #
# Symbol views
# --------------------------------------------------------------------------- #
def _resolve_root(
    raw: str,
    raw_nodes: dict[str, Any],
) -> tuple[str, list[str], list[str]]:
    """Resolve ``--root`` to one or more node ids.

    Accepts a full ``file::symbol`` id, a bare symbol name, or a file path (in
    which case every symbol in that file becomes a root).

    Returns ``(primary, extra_roots, candidates)``.  When a bare name is
    genuinely ambiguous the function refuses to pick one and returns the
    candidates instead, because silently choosing the alphabetically first
    match produced a map rooted at the wrong symbol and nothing in the output
    said so.
    """

    text = (raw or "").strip()
    if not text:
        return "", [], []
    if text in raw_nodes:
        return text, [], []

    by_id: list[str] = []
    by_name = sorted(
        node_id
        for node_id, node in raw_nodes.items()
        if str(node.get("name") or "") == text
    )
    by_file = sorted(
        node_id
        for node_id, node in raw_nodes.items()
        if str(node.get("file") or "") == text
    )
    # A file path is not ambiguous when it matches six symbols: that is the
    # ordinary meaning of "start from this file". Treating it as ambiguity made
    # `--root some/file.py` unusable on any file with more than one symbol.
    if by_file:
        return by_file[0], by_file[1:], []
    # A qualified name such as ``Class.method`` is stored as the bare method
    # name, so the last dot segment has to be tried as a fallback.
    tail = text.rsplit(".", 1)[-1]
    by_tail = sorted(
        node_id
        for node_id, node in raw_nodes.items()
        if str(node.get("name") or "") == tail
    )

    for candidates in (by_id, by_name, by_tail):
        if not candidates:
            continue
        if len(candidates) == 1:
            return candidates[0], [], []
        # Ambiguous. Narrowing by preferring the longest id would be a guess.
        return "", [], candidates[:12]
    return "", [], []


def _traverse(
    spec: MapSpec,
    raw_nodes: dict[str, Any],
    raw_edges: list[dict[str, Any]],
    root_id: str,
    extra_roots: list[str],
) -> tuple[dict[str, int], dict[tuple[str, str, str], dict[str, Any]]]:
    """Depth-limited breadth-first walk outward from the roots.

    Returns node distances keyed by id, and the edges that survived with their
    collapsed counters.  The walk is breadth-first and bounded by ``spec.depth``
    so the answer to "what does this call" is a readable neighbourhood rather
    than the whole repository.
    """

    wanted = spec.resolved_kinds()
    out: dict[str, list[dict[str, Any]]] = {}
    inc: dict[str, list[dict[str, Any]]] = {}
    for edge in raw_edges:
        kind = str(edge.get("kind") or "")
        if kind not in wanted:
            continue
        src = str(edge.get("src") or "")
        dst = str(edge.get("dst") or "")
        if not src or not dst or src == dst:
            continue
        if src not in raw_nodes or dst not in raw_nodes:
            continue
        out.setdefault(src, []).append(edge)
        inc.setdefault(dst, []).append(edge)


    distances: dict[str, int] = {}
    frontier = [node for node in [root_id, *extra_roots] if node]
    for node in frontier:
        distances[node] = 0
    for level in range(1, spec.depth + 1):
        nxt: list[str] = []
        for node in frontier:
            buckets = []
            if spec.direction in ("out", "both"):
                buckets.append(out)
            if spec.direction in ("in", "both"):
                buckets.append(inc)
            for bucket in buckets:
                for edge in bucket.get(node, ()):
                    other = str(edge["dst"]) if bucket is out else str(edge["src"])
                    if other not in distances:
                        distances[other] = level
                        nxt.append(other)
        if not nxt:
            break
        frontier = nxt

    collapsed: dict[tuple[str, str, str], dict[str, Any]] = {}
    for src, edges in out.items():
        for edge in edges:
            dst = str(edge["dst"])
            if src not in distances or dst not in distances:
                continue
            kind = str(edge["kind"])
            key = (src, dst, kind)
            record = collapsed.get(key)
            if record is None:
                collapsed[key] = {
                    "src": src,
                    "dst": dst,
                    "kind": kind,
                    "origin": str(edge.get("origin") or "inferred"),
                    "count": 1,
                    "lines": {int(edge.get("line") or 0)} - {0},
                }
            else:
                record["count"] += 1
                record["lines"].add(int(edge.get("line") or 0))
    return distances, collapsed


def _collapse_all(
    spec: MapSpec,
    raw_nodes: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Collapse every edge of a wanted kind, for the no-root case.

    Direction is applied here rather than in :func:`_traverse` because with no
    root "out" and "in" have no anchor: the caller asked for a graph, not for one
    side of it.
    """

    wanted = spec.resolved_kinds()
    collapsed: dict[tuple[str, str, str], dict[str, Any]] = {}
    for edge in raw_edges:
        kind = str(edge.get("kind") or "")
        if kind not in wanted:
            continue
        src = str(edge.get("src") or "")
        dst = str(edge.get("dst") or "")
        if not src or not dst or src == dst:
            continue
        if src not in raw_nodes or dst not in raw_nodes:
            continue
        key = (src, dst, kind)
        record = collapsed.get(key)
        if record is None:
            collapsed[key] = {
                "src": src,
                "dst": dst,
                "kind": kind,
                "origin": str(edge.get("origin") or "inferred"),
                "count": 1,
                "lines": {int(edge.get("line") or 0)} - {0},
            }
        else:
            record["count"] += 1
            record["lines"].add(int(edge.get("line") or 0))
    return collapsed


def _degree(node_ids: set[str], collapsed: dict[tuple[str, str, str], dict[str, Any]]) -> dict[str, int]:
    """How many relations touch each node, used to rank the no-root selection."""

    degree: dict[str, int] = {}
    for src, dst, _kind in collapsed:
        degree[src] = degree.get(src, 0) + 1
        degree[dst] = degree.get(dst, 0) + 1
    for node in node_ids:
        degree.setdefault(node, 0)
    return degree


def _symbol_findings(report: Any, include: bool) -> dict[str, dict[str, int]]:
    """Severity histogram keyed by the file a finding's evidence names."""

    buckets: dict[str, dict[str, int]] = {}
    if not include:
        return buckets
    for finding in getattr(report, "findings", ()) or ():
        name = _severity_name(getattr(finding, "severity", None))
        for item in getattr(finding, "evidence", ()) or ():
            path = str(getattr(item, "file", "") or "")
            if not path:
                continue
            bucket = buckets.setdefault(path, {})
            bucket[name] = bucket.get(name, 0) + 1
    return buckets


def _symbol_map(
    report: Any,
    spec: MapSpec,
    raw_nodes: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Shared builder for the symbol-level views.

    Every symbol view differs only in which relation kinds it draws, so the
    traversal, budget, node shape and layout are identical.  Duplicating them
    per view would guarantee that one view fixes a bug and three keep it.
    """

    if not raw_nodes:
        return _empty_model(spec, "this scan stored no graph snapshot")

    root_id, extra_roots, candidates = _resolve_root(spec.root, raw_nodes)
    if spec.root and not root_id:
        if candidates:
            return _empty_model(
                spec,
                f"root {spec.root!r} is ambiguous: it matches {len(candidates)} symbol(s). "
                "Pass a full id such as " + candidates[0],
            )
        return _empty_model(spec, f"root {spec.root!r} matches no indexed symbol or file")

    if root_id:
        distances, collapsed = _traverse(spec, raw_nodes, raw_edges, root_id, extra_roots)
        # Every node in the neighbourhood is drawn, including ones that are only
        # reachable through an edge kind this view does not draw. Without them a
        # `tests` view would show the tests and nothing they exercise.
        node_ids = set(distances)
        for src, dst, _kind in collapsed:
            node_ids.add(src)
            node_ids.add(dst)
    else:
        # No root: the whole snapshot is the neighbourhood. A traversal from
        # nothing reaches nothing, and an empty map for a repository with 35,000
        # symbols would claim there is nothing to see. The budget below is what
        # keeps this readable, and the degree ranking is what keeps it relevant:
        # the busiest symbols come first rather than whatever the ids sort to.
        collapsed = _collapse_all(spec, raw_nodes, raw_edges)
        node_ids = {src for src, _dst, _kind in collapsed} | {
            dst for _src, dst, _kind in collapsed
        }
        distances = dict.fromkeys(node_ids, 0)

    if not node_ids:
        # Two very different situations produce an empty neighbourhood, and the
        # reason has to name which one it is. "Nothing connects your root" and
        # "this scan recorded no such relation anywhere" send a reader to
        # different next steps.
        if root_id:
            return _empty_model(
                spec,
                "no relation of the kinds this view draws connects the requested root",
            )
        return _empty_model(
            spec,
            f"this scan recorded no relation of the kinds this view draws "
            f"({', '.join(sorted(spec.resolved_kinds()))}); the analyzer found none "
            "anywhere in the repository, which is not the same as there being none",
        )

    omitted_nodes = max(0, len(node_ids) - spec.budget.max_nodes)
    if root_id:
        # Nearest to the root first, then by id so the choice is deterministic.
        node_list = sorted(node_ids, key=lambda nid: (distances.get(nid, 99), nid))
    else:
        # No root means the budget, not the traversal, decides what survives.
        # Ranking by degree keeps the map about the code that actually talks to
        # other code instead of the alphabetically first 2,000 symbols.
        degree = _degree(node_ids, collapsed)
        node_list = sorted(node_ids, key=lambda nid: (-degree.get(nid, 0), nid))
    node_list = node_list[: spec.budget.max_nodes]
    kept = set(node_list)

    edge_list: list[dict[str, Any]] = []
    budget_omitted: dict[str, int] = {}
    for src, dst, kind in sorted(collapsed):
        record = collapsed[(src, dst, kind)]
        if src not in kept or dst not in kept:
            omitted_nodes += 1
            continue
        if len(edge_list) >= spec.budget.max_edges:
            budget_omitted[kind] = budget_omitted.get(kind, 0) + 1
            continue
        origin = record["origin"]
        edge_list.append(
            {
                "src": src,
                "dst": dst,
                "kind": kind,
                "origin": origin,
                "confidence": EDGE_STYLES.get(origin, "dashed"),
                "count": record["count"],
                "file": str(raw_nodes[src].get("file") or ""),
                "line": min(record["lines"]) if record["lines"] else 0,
                "label": f"{kind} x{record['count']}",
            }
        )

    severity_by_file = _symbol_findings(report, spec.include_findings)
    nodes: list[dict[str, Any]] = []
    for node_id in node_list:
        node = raw_nodes[node_id]
        path = str(node.get("file") or "")
        severities = severity_by_file.get(path, {})
        name = str(node.get("name") or node_id.rsplit("::", 1)[-1])
        kind = str(node.get("kind") or "unknown")
        nodes.append(
            {
                "id": node_id,
                "name": name,
                "kind": kind,
                "file": path,
                "start_line": int(node.get("start_line") or 0),
                "end_line": int(node.get("end_line") or 0),
                "language": str(node.get("language") or ""),
                "exported": bool(node.get("exported", False)),
                "depth_from_root": distances.get(node_id, 0),
                "is_root": distances.get(node_id) == 0,
                "finding_severity": _worst_severity(severities),
                "finding_count": sum(severities.values()),
                "unresolved_calls": 0,
                "shape": _shape_for(kind, path),
                "placeholder": not path,
                "findings": (
                    {name_: severities.get(name_, 0) for name_ in SEVERITY_ORDER if severities.get(name_)}
                    if spec.include_findings
                    else {}
                ),
            }
        )

    stats = {
        "nodes": len(nodes),
        "edges": len(edge_list),
        "edges_by_kind": _edge_counts(edge_list),
        "collapsed": 0,
        "omitted_nodes": omitted_nodes,
        "omitted_edges": 0,
        "budget_omitted": budget_omitted,
        "root": root_id,
        "depth_limit": spec.depth,
        "reached": len(node_ids),
    }
    layout = _layout_module(nodes, edge_list, spec)
    model = {
        "meta": {"view": spec.view, "root": root_id, "question": VIEW_QUESTIONS[spec.view]},
        "nodes": nodes,
        "edges": edge_list,
        "legend": _legend(spec),
        "stats": stats,
        "layout": layout,
        "honesty": {},
    }
    return model


#: Verification states in which a flow was actually *proven* rather than
#: pattern-matched.  The data-flow view encodes this difference in the edge
#: ``origin`` so the existing solid/dashed/dotted vocabulary already draws it,
#: and so a reader who ignores the legend still sees two different edge
#: populations on screen.
PROVEN_VERIFICATIONS: frozenset[str] = frozenset(
    {"cross_module_trace", "test_backed", "reproduced"}
)


#: Findings a no-root data-flow map draws.  Worst first: a map of a repository
#: with three hundred flows has to choose, and choosing by severity is the only
#: choice a reader would have made themselves.
DATA_FLOW_FINDING_CAP = 60


def _flow_edge_origin(finding: Any) -> str:
    """How strongly the analyzer claims *this* flow.

    ``cross_module_trace`` means the value was followed from one module into
    another. ``static_evidence`` means a source pattern and a sink pattern were
    found in the same function and nothing in between was checked. Drawing both
    as solid lines would tell a reader the second one was proven.
    """

    status = getattr(finding.verification_status, "value", finding.verification_status)
    return "type_resolved" if str(status) in PROVEN_VERIFICATIONS else "inferred"


def _flow_file_hint(finding: Any) -> str:
    """The file a finding's evidence points at, used to qualify bare hop names."""

    for item in finding.evidence:
        if item.file:
            return item.file
    if finding.affected_symbols:
        return finding.affected_symbols[0].split("::", 1)[0]
    return ""


#: Hop prefixes that name where a value came from rather than a symbol. A flow is
#: a story with a beginning, and the beginning is usually not a function: it is
#: ``process.env.X`` or a request parameter. Dropping those hops would draw a
#: path that starts in mid-air.
_SOURCE_PREFIXES: tuple[str, ...] = (
    "source:",
    "env",
    "param",
    "argument",
    "request",
    "input",
    "unknown",
    "taint",
)


def _hop_node(hop: str, raw_nodes: dict[str, Any], file_hint: str) -> tuple[str, str]:
    """Resolve one recorded hop to a node id and the role it plays in the flow.

    Hops are written as prose, because the report reads better that way:
    ``entered from ParquetReporter.onBegin``, ``in ParquetReporter.onEnd``,
    ``sink: sql-exec``. Two of those name symbols the graph indexes; the others
    name the origin and the destination *of the value*, which the graph has no
    node for. Those get a synthetic node instead of being dropped — a data-flow
    map whose path starts at the first function it could name would be a
    different, and wrong, claim.
    """

    text = hop.strip()
    if not text:
        return "", ""
    lowered = text.lower()

    if text.startswith("in ") and text[3:].strip() not in ("", "<module>"):
        name = text[3:].strip()
        return _resolve_node_id(name, set(raw_nodes), file_hint) or f"flow-origin::{name}", "scope"
    if text.startswith("entered from "):
        name = text[len("entered from "):].strip()
        if name and " " not in name and name != "<module>":
            return (
                _resolve_node_id(name, set(raw_nodes), file_hint) or f"flow-caller::{name}",
                "caller",
            )
    if lowered.startswith("sink"):
        label = text.split(":", 1)[1].strip() if ":" in text else text
        return f"flow-sink::{label}", "sink"
    if lowered.startswith(_SOURCE_PREFIXES):
        return f"flow-source::{text}", "source"
    if " " not in text and all(ch.isalnum() or ch in "_$:." for ch in text):
        return _resolve_node_id(text, set(raw_nodes), file_hint) or f"flow-hop::{text}", "via"
    return f"flow-step::{text}", "step"


#: How a node on a data-flow map is drawn. The origin and the sink are the two
#: ends of the argument, so they are given their own glyphs rather than being
#: left to look like ordinary functions.
FLOW_NODE_SHAPES: dict[str, str] = {
    "source": "diamond",
    "sink": "square",
    "caller": "pill",
    "scope": "rounded",
    "via": "circle",
    "step": "circle",
    "symbol": "circle",
}


#: Role implied by each synthetic id prefix. Deriving the role from the id is
#: what keeps a pseudo node honest: the caller decides the prefix, and the
#: renderer reads the role back rather than guessing from the shape.
_PSEUDO_ROLES: dict[str, str] = {
    "flow-source": "source",
    "flow-sink": "sink",
    "flow-caller": "caller",
    "flow-origin": "scope",
    "flow-hop": "via",
    "flow-step": "step",
}


def _pseudo_node(node_id: str) -> dict[str, Any]:
    """A node for something the graph does not index: a value, or a sink kind."""

    prefix, _, label = node_id.partition("::")
    role = _PSEUDO_ROLES.get(prefix, "step")
    if prefix == "flow-source":
        name = label
    elif prefix == "flow-sink":
        name = f"{label} sink"
    elif prefix == "flow-caller":
        name = f"{label} (caller)"
    else:
        name = label
    return {
        "id": node_id,
        "name": name,
        "kind": role,
        "file": "",
        "start_line": 0,
        "end_line": 0,
        "language": "",
        "exported": False,
        "depth_from_root": 0,
        "is_root": False,
        "finding_severity": "",
        "finding_count": 0,
        "unresolved_calls": 0,
        "shape": FLOW_NODE_SHAPES.get(role, "circle"),
        "findings": {},
        "flow_role": role,
        "flow_label": label,
    }


def _data_flow_map(
    report: Any,
    spec: MapSpec,
    raw_nodes: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Draw the flows the analyzer recorded, and only those.

    This view is deliberately *not* a traversal. The graph contains every call in
    the repository; a data-flow map that drew the graph would show a call graph
    wearing a data-flow label. What makes a path a flow is that the analyzer
    traced untrusted input through it, and that evidence only exists on the
    finding. So the nodes come from ``finding.data_flows`` and the edges from
    the hops between them.
    """

    findings = [f for f in getattr(report, "findings", []) if not f.suppressed]
    if not findings:
        return _empty_model(spec, "this scan recorded no finding, so it recorded no data flow")

    with_flows = [f for f in findings if f.data_flows]
    if not with_flows:
        return _empty_model(
            spec,
            "no finding in this scan carries a traced data flow; the analyzer matched "
            "patterns but proved no path from untrusted input to a sink",
        )

    ranked = sorted(
        with_flows,
        key=lambda f: (
            -f.severity.rank,
            0 if str(getattr(f.verification_status, "value", f.verification_status))
            in PROVEN_VERIFICATIONS
            else 1,
            f.finding_id,
        ),
    )

    # A root narrows to the findings whose evidence names it. Without one the
    # map takes the worst findings, which is what a reader opening this view is
    # asking about.
    if spec.root:
        wanted = _resolve_root(spec.root, raw_nodes)[0]
        file_hint = str(raw_nodes.get(wanted, {}).get("file") or "") if wanted else ""
        scope = [
            f
            for f in with_flows
            if wanted
            and (
                f.finding_id == spec.root
                or f.rule_id == spec.root
                or wanted in f.affected_symbols
                or f.rule_id == wanted
                or (file_hint and any(e.file == file_hint for e in f.evidence))
            )
        ]
        if not scope:
            return _empty_model(
                spec,
                f"no traced data flow is recorded against {spec.root!r}",
            )
    else:
        file_hint = ""
        scope = ranked[:DATA_FLOW_FINDING_CAP]

    node_ids: set[str] = set()
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    flows_drawn = 0
    flows_omitted = 0

    for finding in scope:
        origin = _flow_edge_origin(finding)
        hint = _flow_file_hint(finding)
        drawn_here = 0
        for flow in finding.data_flows:
            if drawn_here >= FLOWS_PER_FINDING:
                flows_omitted += 1
                continue
            hops = [str(step).strip() for step in flow]
            # `<module>` is the analyzer's stand-in for "the file as a whole".
            # It is not a place a value travelled through, so a hop naming it
            # is dropped; the chain still connects across it because the hops
            # on either side are joined regardless.
            hops = [
                hop
                for hop in hops
                if hop and hop != "<module>" and not hop.startswith("in <module>")
            ]
            chain = [_hop_node(hop, raw_nodes, hint) for hop in hops]
            chain = [(nid, role) for nid, role in chain if nid]
            if len({nid for nid, _role in chain}) < 2:
                # A flow that resolves to a single node is a source or a sink on
                # its own. Drawing it as an edge to a phantom would invent the
                # connection that the whole view exists to show.
                flows_omitted += 1
                continue
            drawn_here += 1
            flows_drawn += 1
            for (src, src_role), (dst, _dst_role) in itertools.pairwise(chain):
                if src == dst:
                    continue
                key = (src, dst, finding.rule_id)
                if key in seen:
                    continue
                seen.add(key)
                node_ids.add(src)
                node_ids.add(dst)
                if len(edges) >= spec.budget.max_edges:
                    continue
                src_node = raw_nodes.get(src, {})
                edges.append(
                    {
                        "src": src,
                        "dst": dst,
                        "kind": "calls",
                        "origin": origin,
                        "confidence": EDGE_STYLES.get(origin, "dashed"),
                        "count": 1,
                        "file": str(src_node.get("file") or ""),
                        "line": int(src_node.get("end_line") or 0),
                        "label": f"{finding.rule_id} · {origin} · from {src_role}",
                    }
                )

    if not node_ids:
        return _empty_model(
            spec,
            "the traced flows name symbols the scan did not index, so there is "
            "nothing to draw; run `understand finding show` to read them instead",
        )

    kept = sorted(node_ids)[: spec.budget.max_nodes]
    kept_set = set(kept)
    edges = [e for e in edges if e["src"] in kept_set and e["dst"] in kept_set]
    omitted_nodes = max(0, len(node_ids) - len(kept))

    severities = _symbol_findings(report, spec.include_findings)
    nodes: list[dict[str, Any]] = []
    for node_id in kept:
        raw = raw_nodes.get(node_id)
        if raw is None:
            nodes.append(_pseudo_node(node_id))
            continue
        path = str(raw.get("file") or "")
        counts = severities.get(path, {})
        kind = str(raw.get("kind") or "unknown")
        nodes.append(
            {
                "id": node_id,
                "name": str(raw.get("name") or node_id.rsplit("::", 1)[-1]),
                "kind": kind,
                "file": path,
                "start_line": int(raw.get("start_line") or 0),
                "end_line": int(raw.get("end_line") or 0),
                "language": str(raw.get("language") or ""),
                "exported": bool(raw.get("exported", False)),
                "depth_from_root": 0,
                "is_root": False,
                "finding_severity": _worst_severity(counts),
                "finding_count": sum(counts.values()),
                "unresolved_calls": 0,
                "placeholder": not path,
                "shape": _shape_for(kind, path),
                "flow_role": "symbol",
                "findings": {
                    name_: counts.get(name_, 0) for name_ in SEVERITY_ORDER if counts.get(name_)
                }
                if spec.include_findings
                else {},
            }
        )

    stats = {
        "nodes": len(nodes),
        "edges": len(edges),
        "edges_by_kind": _edge_counts(edges),
        "collapsed": 0,
        "omitted_nodes": omitted_nodes,
        "omitted_edges": 0,
        "budget_omitted": {},
        "root": spec.root,
        "depth_limit": spec.depth,
        "reached": len(node_ids),
        "findings_in_scope": len(scope),
        "flows_drawn": flows_drawn,
        "flows_omitted": flows_omitted,
        "proven_edges": sum(1 for e in edges if e["origin"] == "type_resolved"),
        # Named `flow_*` on purpose: ``stats["source_nodes"]`` already means
        # "nodes whose source text could be read" and is written by the detail
        # pass for every view. Two different meanings under one key is worse
        # than either.
        "flow_source_nodes": sum(1 for n in nodes if n.get("flow_role") == "source"),
        "flow_sink_nodes": sum(1 for n in nodes if n.get("flow_role") == "sink"),
        "flow_symbol_nodes": sum(1 for n in nodes if n.get("flow_role") == "symbol"),
        "flow_unlinked_nodes": sum(1 for n in nodes if not n.get("file")),
    }
    model = {
        "meta": {"view": spec.view, "root": spec.root, "question": VIEW_QUESTIONS[spec.view]},
        "nodes": nodes,
        "edges": edges,
        "legend": _legend(spec),
        "stats": stats,
        "layout": _layout_module(nodes, edges, spec),
        "honesty": {},
    }
    return model


def _finding_file_hint(finding: Any) -> str:
    """The file a finding's evidence points at, used to qualify bare hop names."""

    for item in finding.evidence:
        if item.file:
            return item.file
    if finding.affected_symbols:
        return finding.affected_symbols[0].split("::", 1)[0]
    return ""


def _finding_map(
    report: Any,
    spec: MapSpec,
    raw_nodes: dict[str, Any],
    raw_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    """Draw where the findings are, and how bad they are.

    Node colour already carries severity in every other view; here it is the
    whole point, so a node that carries a critical finding is also the largest
    one on screen. A repository's findings cluster, and the shape of that
    cluster is a question no severity count answers.
    """

    findings = [f for f in getattr(report, "findings", []) if not f.suppressed]
    if not findings:
        return _empty_model(spec, "this scan recorded no finding")

    wanted = _resolve_root(spec.root, raw_nodes)[0] if spec.root else ""
    scope = findings
    if spec.root and wanted:
        scope = [
            f
            for f in findings
            if wanted in f.affected_symbols
            or f.rule_id == spec.root
            or f.finding_id == spec.root
            or any(str(raw_nodes.get(wanted, {}).get("file") or "") == e.file for e in f.evidence)
        ]
        if not scope:
            return _empty_model(spec, f"no finding in this scan lands on {spec.root!r}")

    # Per node: the worst severity, how many findings, and which rules fired.
    per_node: dict[str, dict[str, Any]] = {}
    for finding in scope:
        targets = {
            s for s in finding.affected_symbols if s in raw_nodes
        }
        if not targets:
            evidence_files = {e.file for e in finding.evidence if e.file}
            for node_id, node in raw_nodes.items():
                if str(node.get("file") or "") in evidence_files and str(
                    node.get("kind") or ""
                ) in ("function", "method", "class"):
                    targets.add(node_id)
        if not targets:
            continue
        for node_id in targets:
            bucket = per_node.setdefault(
                node_id,
                {"worst": 0, "count": 0, "rules": set(), "severities": {}},
            )
            rank = int(finding.severity.rank)
            if rank > bucket["worst"]:
                bucket["worst"] = rank
            bucket["count"] += 1
            bucket["rules"].add(finding.rule_id)
            name = str(getattr(finding.severity, "value", finding.severity))
            bucket["severities"][name] = bucket["severities"].get(name, 0) + 1

    if not per_node:
        return _empty_model(
            spec,
            "every finding in this scan names a location the graph does not index, "
            "so there is nothing to place on a map; `understand finding show` still "
            "has the evidence",
        )

    # Worst first, then busiest: the map is about the part of the repository a
    # reader should look at first.
    ordered = sorted(per_node, key=lambda nid: (-per_node[nid]["worst"], -per_node[nid]["count"], nid))
    kept = ordered[: spec.budget.max_nodes]
    kept_set = set(kept)
    omitted_nodes = max(0, len(ordered) - len(kept))

    edge_keys: dict[tuple[str, str], dict[str, Any]] = {}
    budget_omitted: dict[str, int] = {}
    for edge in raw_edges:
        src, dst = edge.get("src"), edge.get("dst")
        if src not in kept_set or dst not in kept_set:
            continue
        key = (src, dst)
        record = edge_keys.get(key)
        if record is None:
            if len(edge_keys) >= spec.budget.max_edges:
                kind = str(edge.get("kind") or "")
                budget_omitted[kind] = budget_omitted.get(kind, 0) + 1
                continue
            edge_keys[key] = {
                "src": src,
                "dst": dst,
                "kind": str(edge.get("kind") or "calls"),
                "origin": str(edge.get("origin") or "inferred"),
                "count": 0,
                "file": str(edge.get("file") or ""),
                "line": int(edge.get("line") or 0),
            }
            record = edge_keys[key]
        record["count"] += 1

    edges: list[dict[str, Any]] = []
    for key in sorted(edge_keys):
        record = edge_keys[key]
        origin = record["origin"]
        edges.append(
            {
                **record,
                "confidence": EDGE_STYLES.get(origin, "dashed"),
                "label": f"{record['kind']} x{record['count']}"
                + (" · both carry findings" if per_node[key[0]]["count"] and per_node[key[1]]["count"] else ""),
            }
        )

    nodes: list[dict[str, Any]] = []
    for node_id in kept:
        node = raw_nodes[node_id]
        path = str(node.get("file") or "")
        bucket = per_node[node_id]
        kind = str(node.get("kind") or "unknown")
        nodes.append(
            {
                "id": node_id,
                "name": str(node.get("name") or node_id.rsplit("::", 1)[-1]),
                "kind": kind,
                "file": path,
                "start_line": int(node.get("start_line") or 0),
                "end_line": int(node.get("end_line") or 0),
                "language": str(node.get("language") or ""),
                "exported": bool(node.get("exported", False)),
                "depth_from_root": 0,
                "is_root": node_id == wanted,
                "finding_severity": _rank_to_severity(bucket["worst"]),
                "finding_count": bucket["count"],
                "unresolved_calls": 0,
                "shape": _shape_for(kind, path),
                "placeholder": not path,
                "findings": {
                    name_: bucket["severities"].get(name_, 0)
                    for name_ in SEVERITY_ORDER
                    if bucket["severities"].get(name_)
                },
                "finding_rules": sorted(bucket["rules"])[:12],
            }
        )

    stats = {
        "nodes": len(nodes),
        "edges": len(edges),
        "edges_by_kind": _edge_counts(edges),
        "collapsed": 0,
        "omitted_nodes": omitted_nodes,
        "omitted_edges": 0,
        "budget_omitted": budget_omitted,
        "root": wanted,
        "depth_limit": spec.depth,
        "reached": len(ordered),
        "findings_in_scope": len(scope),
        "findings_placed": sum(per_node[nid]["count"] for nid in kept),
    }
    return {
        "meta": {"view": spec.view, "root": wanted, "question": VIEW_QUESTIONS[spec.view]},
        "nodes": nodes,
        "edges": edges,
        "legend": _legend(spec),
        "stats": stats,
        "layout": _layout_module(nodes, edges, spec),
        "honesty": {},
    }

_BUILDERS = {
    "module": _module_map,
    "call": _symbol_map,
    "inheritance": _symbol_map,
    "dependency": _symbol_map,
    "test": _symbol_map,
    "event": _symbol_map,
    "obligation": _symbol_map,
    "influence": _symbol_map,
    "data_flow": _data_flow_map,
    "finding": _finding_map,
}
