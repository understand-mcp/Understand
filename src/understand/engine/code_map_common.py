"""The vocabulary the code map is built from.

These names are the shared language of the map model: the shapes a node may
take, the styles an edge may take, the order severities are read in, and the
ceilings that keep a map small enough to read.  The view builders and the
layout engine both need them, so they live here instead of in either half.
"""

from __future__ import annotations

#: Node glyphs.  Shape carries the symbol kind so colour is free to carry
#: severity.
NODE_SHAPES: dict[str, str] = {
    "module": "square",
    "class": "rounded",
    "function": "circle",
    "method": "pill",
    "unknown": "circle",
    "directory": "frame",
}

#: Edge style per evidence strength.  ``origin`` is the engine's own claim about
#: how sure it is, and the map must not upgrade that claim.
EDGE_STYLES: dict[str, str] = {
    "static_direct": "solid",
    "type_resolved": "solid",
    "inferred": "dashed",
    "unresolved": "dotted",
    "runtime": "dotted",
}

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

#: ``Severity.rank`` back to its name.  The finding view buckets a node by the
#: worst rank it saw rather than by name, because comparing names is a string
#: comparison and "critical" < "high" is true in ASCII.
SEVERITY_RANKS: dict[str, int] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

#: Findings attached per node. A file with two hundred findings would otherwise
#: carry a megabyte of prose into a three-megabyte document, and the reader
#: cannot hold two hundred explanations in their head either. The rest are
#: counted, never silently dropped.
NODE_FINDING_CAP = 6

#: Global ceiling on attached finding payloads. Every node gets its own cap and
#: this bounds the total, so one pathological file cannot blow the document up.
FINDING_DETAIL_BUDGET = 400

#: Flows drawn per finding.  A finding with more chains than this is a finding
#: worth reading in prose (``understand finding show``), not in a picture.
FLOWS_PER_FINDING = 3
