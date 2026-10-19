"""Semantic relations between symbols.

:class:`~understand.engine.call_graph.CallGraph` answers "who calls whom", which
is only one of the relationships that exist in real code.  A repository also
expresses inheritance, attribute access, validation, authorization, egress,
registration, resource lifetimes, test coverage and configuration influence.
``EdgeKind`` declares all of them, but until this module existed only six were
ever produced, so nine of the declared kinds could not appear in a report and
six more existed only as declarations.

Every relation produced here carries a :class:`RelationOrigin` that says how
strongly it is known, and the rule is deliberately blunt:

* ``STATIC_DIRECT`` is only used when the fact came from the Python ``ast``
  module, where the base class list is a fact rather than a guess.
* ``TYPE_RESOLVED`` is used when a name was matched against a symbol that is
  provably the target (same class, same file, unique repository-wide).
* ``INFERRED`` is used for every lexical heuristic.  These edges are useful for
  triage and worthless as proof, and the origin label is what tells the two
  apart downstream.
* ``UNRESOLVED`` is used when the target could not be bound to a symbol at all.
  The edge still records the intent (this handler listens to that event) but it
  is not treated as a link to an existing node.

Nothing here executes analysed code, and nothing is inferred from a name alone
when the name can be checked.  The budgets at the top exist because a large
monorepo can produce millions of candidate relations and a report that carries
all of them is not a report anybody reads.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import TYPE_CHECKING

from understand.engine.control_flow import extract_control_flow
from understand.engine.parsing import is_test_path
from understand.models import Edge, EdgeKind, RelationOrigin

if TYPE_CHECKING:  # pragma: no cover
    from understand.engine.call_graph import CallGraph
    from understand.engine.symbol_index import SymbolIndex

__all__ = ["RELATION_BUDGETS", "build_relations"]

#: Per-kind caps.  A single pathological repository (a 30k-line generated
#: framework file, a giant ``__init__.py``) must not be able to consume the
#: whole edge budget on one relation type.
RELATION_BUDGETS: dict[EdgeKind, int] = {
    EdgeKind.INHERITS: 40_000,
    EdgeKind.IMPLEMENTS: 20_000,
    EdgeKind.READS: 120_000,
    EdgeKind.WRITES: 120_000,
    EdgeKind.TRANSFORMS: 40_000,
    EdgeKind.VALIDATES: 40_000,
    EdgeKind.AUTHORIZES: 20_000,
    EdgeKind.SENDS_DATA_TO: 60_000,
    EdgeKind.REGISTERS: 40_000,
    EdgeKind.HANDLES_EVENT: 40_000,
    EdgeKind.OPENS_RESOURCE: 60_000,
    EdgeKind.CLOSES_RESOURCE: 60_000,
    EdgeKind.TESTS: 40_000,
    EdgeKind.INFLUENCES: 20_000,
}

#: Lines of a symbol body scanned for attribute access.  Matches the data-flow
#: engine's cap so the two never disagree about how much of a function was read.
MAX_BODY_LINES = 500

# ---------------------------------------------------------------- vocabularies

# A base class is treated as an interface rather than a superclass when its name
# says so.  This is a naming heuristic and is therefore always INFERRED, but the
# distinction is worth making: "implements Reader" and "inherits BaseException"
# mean very different things to a reviewer.
#
# TypeScript spells the difference in the keyword (``implements``) rather than in
# the name, so the sanitised source line is consulted for that language: a bare
# ``implements X`` is authoritative in a way a name ending in ``Interface`` is
# not.
_INTERFACE_RE = re.compile(
    r"(?:Interface|Protocol|ABC|Contract)$"
    r"|^I[A-Z][A-Za-z0-9_]*$"
    r"|(?:^|\b)(?:ABC|Protocol|Generic|Iterable|Mapping|Sequence)(?:$|\b)"
)

# A callee name that suggests the caller checks its input.  ``check_`` is only
# honoured with a validation-shaped suffix: ``subprocess.check_output`` is a
# process call, and treating it as a validator would put a VALIDATES edge on
# every subprocess invocation in the repository.
_VALIDATE_NAMES = frozenset(
    {
        "validate", "valid", "check", "verify", "assert", "sanitize", "sanitise",
        "clean", "escape", "escapeHtml", "quote", "parse", "coerce",
        "normalize", "normalise", "is_valid", "isValid", "assert_valid",
        "assertValid",
    }
)
_VALIDATE_RE = re.compile(
    r"^(?:validate|verify|sanitiz|sanitis|assert)[\w_]*$"
    # camelCase is the JavaScript spelling of the same idea; without this arm
    # ``isValid`` matched nothing and every JS validation call went unrecorded.
    r"|^is_?[Vv]alid[\w_]*$"
    r"|^(?:normalize|normalise|escape|coerce|parse)[\w_]*$"
    r"|^check_(?:valid|invalid|schema|format|bounds|range|length|size|args|"
    r"argspec|input|value|values|required|presence|non_empty|not_null|"
    r"not_none|type|types|path|paths|params|param_types|owner|permissions?)"
)

# A callee name that suggests the caller decides who may proceed.
_AUTHORIZE_RE = re.compile(
    r"^(?:authorize|authorise|authn|authz|authenticate|permit|deny|"
    r"is_admin|is_superuser|is_authenticated|is_authorized|is_authorised|"
    r"require_auth|require_permission|require_role|check_permission|"
    r"check_access|verify_token|verify_jwt|check_token)[\w_]*$"
    r"|^(?:can|has)_(?:access|admin|edit|manage|permission|read|role|write)"
    r"|^allow(?:ed|list|s)?$"
    r"|^login$|^logout$|^policy$|^guard$"
)

# A callee that leaves the process.  The receiver has to look like a transport
# or the method name has to be a transport verb: a bare ``write`` or ``append``
# is a file or list operation, and calling it egress would put a
# SENDS_DATA_TO edge on most of a codebase.
_EGRESS_VERB = frozenset(
    {
        "fetch", "send", "publish", "emit", "dispatch", "notify", "webhook",
        "upload", "postMessage", "request", "deliver",
    }
)
_EGRESS_VERB_RE = re.compile(r"^(?:publish|emit|dispatch|notify|send|post)[\w_]*$")
_EGRESS_RECEIVER = re.compile(
    r"^(?:requests|httpx|aiohttp|axios|fetch|urllib|http|https|url|boto3|"
    r"requests\.\w+|axios\.\w+|urllib\.\w+)$",
    re.I,
)
#: Methods that are genuinely "put this on the wire" when the receiver is a
#: transport.  A bare transport receiver is not enough: ``socket.getaddrinfo``
#: is DNS resolution and ``redis.get`` is a read, so naming the receiver alone
#: would label both as egress.
_EGRESS_METHOD = re.compile(
    r"^(?:get|post|put|patch|delete|head|options|request|send|sendall|"
    r"sendmail|send_message|publish|put_message|set|write_url)$"
)

# Names that indicate a function is an event handler rather than a caller.
_HANDLER_NAME_RE = re.compile(
    r"^(?:handle|on|dispatch|process|receive)[_A-Z]|^_?on\w*"
    r"|_handler$|^handler$|Handler$|^listener$|^on_"
)
_EVENT_DECORATOR_RE = re.compile(
    r"(?:route|\.get|\.post|\.put|\.delete|\.patch|task|command|register|"
    r"subscriber|consumer|listener|handler|event|hook|signal|subscribe|"
    r"on_message|on_event|fixture|provides|use)",
    re.I,
)

#: TypeScript/JavaScript heritage keyword.  ``extends`` means inheritance,
#: ``implements`` means the class satisfies a contract, and conflating them
#: hides the most interesting case: a class that implements three interfaces and
#: extends nothing still looks like a base class in a name-only model.
_IMPL_KEYWORD_RE = re.compile(r"\bimplements\b")

_SELF_ATTR_RE = re.compile(r"\b(?:self|this)\.([A-Za-z_$][\w$]*)")
_SELF_ASSIGN_RE = re.compile(
    r"\b(?:self|this)\.([A-Za-z_$][\w$]*)\s*(?:=[^=~]|[+\-*/%&|^]=)"
    # ``self.cache[key] = value`` mutates the attribute just as much as
    # ``self.cache = value`` does; without this arm every dict-valued
    # attribute was reported as read-only.
    r"|\b(?:self|this)\.([A-Za-z_$][\w$]*)\s*\[[^\]]*\]\s*(?:=[^=~]|[+\-*/%&|^]=)"
    r"|\b(?:self|this)\.([A-Za-z_$][\w$]*)\.(?:push|append|add|set|update|clear|delete)\s*\("
)
_ENV_READ_RE = re.compile(
    r"\b(?:os\s*\.\s*environ|process\s*\.\s*env|ENV\s*\[|System\s*\.\s*getenv|getenv\s*\()"
)

#: A configuration lookup: a subscript, ``getenv`` or an ``environ`` access. The
#: key must be *used*, not merely named in a comment. An earlier version of this
#: pattern contained a literal ``{}`` placeholder that was never substituted, so
#: it matched nothing at all.
_KEY_LOOKUP_RE = re.compile(r"\[\s*[\"']?[A-Za-z_$][\w$]*[\"']?\s*\]|getenv|environ\s*[.\[]")


def _leaf(target: str) -> str:
    """The bare identifier of a resolved id or a dotted callee name."""

    text = target.rsplit("::", 1)[-1]
    return text.rsplit(".", 1)[-1]


def _members(index: SymbolIndex) -> dict[str, list[str]]:
    """Map ``owner name`` -> member symbol ids, for attribute resolution.

    ``self.x`` inside class ``C`` means ``C.x``; a module-level ``x`` means
    ``<module>.x``.  Building the index once keeps the per-symbol loop cheap on
    repositories with tens of thousands of symbols.
    """

    members: dict[str, list[str]] = {}
    for sid, sym in index.by_id.items():
        if sym.parent:
            members.setdefault(sym.parent, []).append(sid)
            members.setdefault(sym.parent.rsplit(".", 1)[-1], []).append(sid)
        else:
            members.setdefault(f"{sym.file}::<module>", []).append(sid)
            members.setdefault(sym.name, []).append(sid)
    return members


def _unique(index: SymbolIndex, name: str, *, file: str | None = None) -> str | None:
    """Resolve a bare name to one symbol id, or give up rather than guess."""

    ids = index.by_name.get(name) or []
    if file:
        same = [i for i in ids if index.by_id[i].file == file]
        if len(same) == 1:
            return same[0]
    if len(ids) == 1:
        return ids[0]
    return None


# ------------------------------------------------------------------ inheritance


def inheritance_edges(index: SymbolIndex) -> list[Edge]:
    """``INHERITS`` and ``IMPLEMENTS`` from every class base list.

    Python bases come straight from ``ast`` and are therefore provable.  Every
    other language's bases were recovered by matching ``class X(...):`` in
    sanitised text, so they are recorded as inferred even when the base name
    resolves perfectly -- the name resolves, the parent list does not.
    """

    edges: list[Edge] = []
    budget = {EdgeKind.INHERITS: RELATION_BUDGETS[EdgeKind.INHERITS],
              EdgeKind.IMPLEMENTS: RELATION_BUDGETS[EdgeKind.IMPLEMENTS]}
    for sid, sym in index.by_id.items():
        if not sym.bases:
            continue
        provable = sym.language == "python"
        module = index.modules.get(sym.file)
        # The declaration line carries the ``implements`` keyword that the base
        # list itself does not, so it is read once per symbol rather than per base.
        base_line = (
            module.dirty_lines.get(sym.start_line, module.line(sym.start_line))
            if module is not None
            else ""
        )
        for raw in sym.bases:
            base = raw.split("(", 1)[0].strip().strip(",")
            if not base or base in {"object", "Exception", "BaseException"}:
                continue
            # ``@dec class`` and ``implements A, B`` both reach here with a
            # leading marker left over from a decorator or a TS heritage clause.
            base = base.lstrip("@").strip()
            if not base or not re.fullmatch(r"[A-Za-z_$][\w$.\[\]\s]*", base):
                continue
            interface = bool(_INTERFACE_RE.search(base)) or (
                sym.language not in {"python"} and _IMPL_KEYWORD_RE.search(base_line)
            )
            kind = EdgeKind.IMPLEMENTS if interface else EdgeKind.INHERITS
            if budget[kind] <= 0:
                continue
            name = base.rsplit(".", 1)[-1]
            target = _unique(index, name, file=sym.file)
            if target is not None and target == sid:
                target = None
            if target is None:
                # The base is not in this repository (or is ambiguous). Record
                # the intent, but do not pretend the node exists.
                edges.append(
                    Edge(
                        src=sid,
                        dst=name,
                        kind=kind,
                        origin=RelationOrigin.UNRESOLVED,
                        file=sym.file,
                        line=sym.start_line,
                        label=f"{'implements' if interface else 'extends'} {raw}",
                    )
                )
            else:
                edges.append(
                    Edge(
                        src=sid,
                        dst=target,
                        kind=kind,
                        origin=RelationOrigin.STATIC_DIRECT if provable else RelationOrigin.INFERRED,
                        file=sym.file,
                        line=sym.start_line,
                        label=raw,
                    )
                )
            budget[kind] -= 1
    return edges


# ------------------------------------------------------------- attribute access


def attribute_edges(index: SymbolIndex) -> list[Edge]:
    """``READS`` and ``WRITES`` for ``self.x`` / ``this.x`` inside a body.

    An assignment is a write; every other mention is a read.  Mutating calls
    (``self.items.append(...)``) count as writes because they change the
    attribute's value.  Reads are capped separately from writes so a
    read-heavy repository cannot starve the write edges, which are the ones a
    reviewer actually acts on.
    """

    edges: list[Edge] = []
    reads_left = RELATION_BUDGETS[EdgeKind.READS]
    writes_left = RELATION_BUDGETS[EdgeKind.WRITES]
    members = _members(index)

    for sid, sym in index.by_id.items():
        if sym.kind not in {"function", "method"} or not sym.parent:
            continue
        module = index.modules.get(sym.file)
        if module is None:
            continue
        owner_ids = members.get(sym.parent) or members.get(sym.parent.rsplit(".", 1)[-1]) or []
        owner_file = index.by_id[owner_ids[0]].file if owner_ids else sym.file
        last = min(sym.end_line, sym.start_line + MAX_BODY_LINES)
        for lineno in range(sym.start_line, last + 1):
            text = module.dirty_lines.get(lineno, "")
            if not text.strip():
                continue
            writes = {
                m.group(1) or m.group(2) or m.group(3) for m in _SELF_ASSIGN_RE.finditer(text)
            }
            for match in _SELF_ATTR_RE.finditer(text):
                attr = match.group(1)
                is_write = attr in writes
                if is_write:
                    if writes_left <= 0:
                        continue
                    writes_left -= 1
                elif reads_left <= 0:
                    continue
                else:
                    reads_left -= 1
                target = _member_target(index, members, owner_ids, owner_file, attr)
                edges.append(
                    Edge(
                        src=sid,
                        dst=target or attr,
                        kind=EdgeKind.WRITES if is_write else EdgeKind.READS,
                        origin=(
                            RelationOrigin.TYPE_RESOLVED
                            if target
                            else RelationOrigin.UNRESOLVED
                        ),
                        file=sym.file,
                        line=lineno,
                        label=attr,
                    )
                )
    return edges


def _member_target(
    index: SymbolIndex,
    members: dict[str, list[str]],
    owner_ids: list[str],
    owner_file: str,
    attr: str,
) -> str | None:
    """Bind ``self.<attr>`` to a symbol declared on the owning class."""

    if owner_ids:
        by_attr = [i for i in owner_ids if index.by_id[i].name == attr]
        if len(by_attr) == 1:
            return by_attr[0]
    module_members = members.get(f"{owner_file}::<module>", [])
    same = [i for i in module_members if index.by_id[i].name == attr]
    return same[0] if len(same) == 1 else None


# ---------------------------------------------------------- transformation shape


def transform_edges(index: SymbolIndex) -> list[Edge]:
    """``TRANSFORMS`` for functions that accept an input and return one of them.

    A function whose declared parameters appear in its ``return`` statement is
    shaping a value rather than producing one from nothing -- parsing, coercion,
    formatting.  That is a useful thing to see in a map, and it is checkable
    from the signature plus the body, so the edges are inferred but not guessed.
    """

    edges: list[Edge] = []
    budget = RELATION_BUDGETS[EdgeKind.TRANSFORMS]
    param_re_cache: dict[str, re.Pattern[str]] = {}
    for sid, sym in index.by_id.items():
        if sym.kind not in {"function", "method"} or budget <= 0:
            continue
        module = index.modules.get(sym.file)
        if module is None or not sym.signature:
            continue
        params = _signature_params(sym.signature)
        if not params:
            continue
        pattern = param_re_cache.get(sym.signature)
        if pattern is None:
            pattern = re.compile(
                r"return\b[^;{}]*\b(" + "|".join(re.escape(p) for p in params) + r")\b"
            )
            param_re_cache[sym.signature] = pattern
        last = min(sym.end_line, sym.start_line + MAX_BODY_LINES)
        for lineno in range(sym.start_line, last + 1):
            if pattern.search(module.dirty_lines.get(lineno, "")):
                edges.append(
                    Edge(
                        src=sid,
                        dst=sid,
                        kind=EdgeKind.TRANSFORMS,
                        origin=RelationOrigin.INFERRED,
                        file=sym.file,
                        line=lineno,
                        label=f"returns one of {', '.join(params[:4])}",
                    )
                )
                budget -= 1
                break
    return edges


def _signature_params(signature: str) -> list[str]:
    """Parameter names from a signature line, tolerant of ``self`` and types."""

    inner = signature[signature.find("(") + 1 : signature.rfind(")")] if "(" in signature else ""
    params: list[str] = []
    for chunk in inner.split(","):
        name = chunk.split("=", 1)[0].split(":", 1)[0].strip().lstrip("*")
        if name and name.isidentifier() and name not in {"self", "cls", "this"}:
            params.append(name)
    return params


# ------------------------------------------------------------- caller obligation


_STRONG_ORIGINS = frozenset({RelationOrigin.STATIC_DIRECT, RelationOrigin.TYPE_RESOLVED})


def _obligation_target(index: SymbolIndex, edge: Edge) -> bool:
    """Whether this call's target is specific enough to carry an obligation.

    A cross-file name match is not enough. On microsoft/playwright a bare
    ``parse(`` in a Playwright file resolved to the single ``parse`` inside a
    vendored Vue bundle, and the file was then reported as validating through
    Vue. Two conditions keep that out:

    * a strong origin (direct id, or resolved through an import or ``self``), or
    * the target lives in the *same file* as the caller, where a unique name
      match is about as good as it gets without types.
    """

    if edge.origin in _STRONG_ORIGINS:
        return True
    src = index.by_id.get(edge.src)
    dst = index.by_id.get(edge.dst)
    if src is None or dst is None:
        return False
    return src.file == dst.file


def obligation_edges(index: SymbolIndex, graph: CallGraph) -> list[Edge]:
    """``VALIDATES``, ``AUTHORIZES`` and ``SENDS_DATA_TO`` derived from calls.

    These re-read the call edges the graph already resolved, so the target is the
    same symbol the call edge points at -- no second, weaker resolution pass.  A
    callee whose *name* says it validates or authorises is not proof that it
    does, so every edge here is ``INFERRED`` unless the call edge itself was
    unresolved, in which case it stays ``UNRESOLVED``.
    """

    edges: list[Edge] = []
    budgets = {
        EdgeKind.VALIDATES: RELATION_BUDGETS[EdgeKind.VALIDATES],
        EdgeKind.AUTHORIZES: RELATION_BUDGETS[EdgeKind.AUTHORIZES],
        EdgeKind.SENDS_DATA_TO: RELATION_BUDGETS[EdgeKind.SENDS_DATA_TO],
    }
    for edge in graph.edges:
        if edge.kind is not EdgeKind.CALLS or edge.src == edge.dst:
            # A self-edge is never a call. The structural parser matches the
            # declaration line ``function parse(input) {`` as a call to parse,
            # so every function was calling itself and reporting that it
            # validates itself.
            continue
        if not _obligation_target(index, edge):
            continue
        full = edge.dst.rsplit("::", 1)[-1]
        name = full.rsplit(".", 1)[-1]
        receiver = full.rsplit(".", 1)[0] if "." in full else ""
        kind: EdgeKind | None = None
        if name in _VALIDATE_NAMES or _VALIDATE_RE.match(name):
            kind = EdgeKind.VALIDATES
        elif _AUTHORIZE_RE.match(name):
            kind = EdgeKind.AUTHORIZES
        elif name in _EGRESS_VERB or _EGRESS_VERB_RE.match(name) or (
            _EGRESS_RECEIVER.match(receiver) and _EGRESS_METHOD.match(name)
        ):
            kind = EdgeKind.SENDS_DATA_TO
        if kind is None or budgets[kind] <= 0:
            continue
        budgets[kind] -= 1
        edges.append(
            Edge(
                src=edge.src,
                dst=edge.dst,
                kind=kind,
                origin=edge.origin,
                file=edge.file,
                line=edge.line,
                label=full,
            )
        )
    return edges


# ----------------------------------------------------------------- registration


def registration_edges(index: SymbolIndex) -> list[Edge]:
    """``REGISTERS`` and ``HANDLES_EVENT`` from decorators and handler names.

    A decorated function is registered with whatever the decorator belongs to,
    so the edge points at the decorator's root when that root is a symbol in the
    repository.  A function whose *name* is a handler gets an edge from its
    module, because the dispatcher is usually a framework the repository does not
    contain and claiming an edge to it would be fiction.
    """

    edges: list[Edge] = []
    registers_left = RELATION_BUDGETS[EdgeKind.REGISTERS]
    handlers_left = RELATION_BUDGETS[EdgeKind.HANDLES_EVENT]

    for sid, sym in index.by_id.items():
        if sym.decorators and registers_left > 0:
            for raw in sym.decorators:
                root = raw.strip().split("(", 1)[0].lstrip("@")
                if not _EVENT_DECORATOR_RE.search(raw):
                    continue
                name = root.rsplit(".", 1)[-1]
                target = _unique(index, name, file=sym.file)
                edges.append(
                    Edge(
                        src=sid,
                        dst=target or root,
                        kind=EdgeKind.REGISTERS,
                        origin=(
                            RelationOrigin.STATIC_DIRECT
                            if target and sym.language == "python"
                            else (RelationOrigin.TYPE_RESOLVED if target else RelationOrigin.UNRESOLVED)
                        ),
                        file=sym.file,
                        line=sym.start_line,
                        label=f"@{raw}",
                    )
                )
                registers_left -= 1

        if handlers_left <= 0 or not _HANDLER_NAME_RE.search(sym.name):
            continue
        if not (sym.kind in {"function", "method"} or sym.decorators):
            continue
        emitters = [
            other
            for other in index.by_name.get("", [])
            if other != sid and _is_emitter(index.by_id[other], sym.file)
        ]
        target = emitters[0] if len(emitters) == 1 else f"{sym.file}::<module>"
        edges.append(
            Edge(
                src=sid,
                dst=target,
                kind=EdgeKind.HANDLES_EVENT,
                origin=(
                    RelationOrigin.TYPE_RESOLVED if len(emitters) == 1 else RelationOrigin.INFERRED
                ),
                file=sym.file,
                line=sym.start_line,
                label=f"handler: {sym.name}",
            )
        )
        handlers_left -= 1
    return edges


def _is_emitter(symbol, file: str) -> bool:
    return (
        symbol.file == file
        and symbol.kind in {"function", "method", "class"}
        and re.match(r"^(?:emit|publish|dispatch|trigger|fire|notify|send|on)_?[A-Za-z]*$", symbol.name)
        is not None
    )


# -------------------------------------------------------------- resource lifetime


def resource_edges(index: SymbolIndex) -> list[Edge]:
    """``OPENS_RESOURCE``, ``CLOSES_RESOURCE``, plus task and transaction edges.

    The control-flow extractor already records these facts; nothing was turning
    them into graph edges, which is why ``OPENS_RESOURCE`` and
    ``CLOSES_RESOURCE`` were declared but never appeared.  They are lexical, so
    they are inferred.
    """

    edges: list[Edge] = []
    opens = RELATION_BUDGETS[EdgeKind.OPENS_RESOURCE]
    closes = RELATION_BUDGETS[EdgeKind.CLOSES_RESOURCE]
    for sid, entry in extract_control_flow(index).items():
        for lineno, token in entry.resources_opened:
            if opens <= 0:
                break
            opens -= 1
            edges.append(
                Edge(
                    src=sid,
                    dst=f"{entry.file}:{lineno}",
                    kind=EdgeKind.OPENS_RESOURCE,
                    origin=RelationOrigin.INFERRED,
                    file=entry.file,
                    line=lineno,
                    label=f"opens: {token}",
                )
            )
        for lineno, token in entry.resources_closed:
            if closes <= 0:
                break
            closes -= 1
            edges.append(
                Edge(
                    src=sid,
                    dst=f"{entry.file}:{lineno}",
                    kind=EdgeKind.CLOSES_RESOURCE,
                    origin=RelationOrigin.INFERRED,
                    file=entry.file,
                    line=lineno,
                    label=f"closes: {token}",
                )
            )
        for lineno, token in entry.starts_tasks:
            edges.append(
                Edge(
                    src=sid,
                    dst=f"{entry.file}:{lineno}",
                    kind=EdgeKind.STARTS_TASK,
                    origin=RelationOrigin.INFERRED,
                    file=entry.file,
                    line=lineno,
                    label=f"starts async work: {token}",
                )
            )
        for lineno, token in entry.awaits_tasks:
            edges.append(
                Edge(
                    src=sid,
                    dst=f"{entry.file}:{lineno}",
                    kind=EdgeKind.AWAITS_TASK,
                    origin=RelationOrigin.INFERRED,
                    file=entry.file,
                    line=lineno,
                    label=f"awaits: {token}",
                )
            )
        for lineno, token in entry.transactions:
            edges.append(
                Edge(
                    src=sid,
                    dst=f"{entry.file}:{lineno}",
                    kind=EdgeKind.CONFIGURES,
                    origin=RelationOrigin.INFERRED,
                    file=entry.file,
                    line=lineno,
                    label=f"transaction boundary: {token[:60]}",
                )
            )
    return edges


# ------------------------------------------------------------------- test links


#: Trees that live under a test directory but contain no tests. A vendored React
#: bundle in ``tests/assets/`` is a test *fixture*, and a JS engine's ``if``
#: blocks are not test assertions; counting them produced 15,000 "exercised by a
#: test" relations on microsoft/playwright, none of which a reviewer could act on.
_FIXTURE_TREES = (
    "/assets/", "/fixtures/", "/node_modules/", "/vendor/", "/vendored/",
    "/third_party/", "/thirdparty/", "/dist/", "/build/", "/generated/",
)


def _is_test_source(relpath: str) -> bool:
    low = "/" + relpath.lower()
    if any(tree in low for tree in _FIXTURE_TREES):
        return False
    return is_test_path(relpath)


def test_edges(index: SymbolIndex, graph: CallGraph) -> list[Edge]:
    """``TESTS`` from a symbol in a test tree to the symbol it exercises.

    The source must be a *function* that runs, not the module that contains it.
    A structural parse attributes a top-level call to the module, and "the file
    exercises ``mkdir``" is not a test relationship -- only ``test_it_does_x``
    calling ``mkdir`` is.
    """

    edges: list[Edge] = []
    budget = RELATION_BUDGETS[EdgeKind.TESTS]
    for edge in graph.edges:
        if budget <= 0 or edge.kind is not EdgeKind.CALLS or edge.src == edge.dst:
            continue
        src = index.by_id.get(edge.src)
        dst = index.by_id.get(edge.dst)
        if src is None or dst is None:
            continue
        if src.kind not in {"function", "method"} or dst.kind not in {"function", "method"}:
            continue
        if not _is_test_source(src.file) or _is_test_source(dst.file):
            continue
        budget -= 1
        edges.append(
            Edge(
                src=edge.src,
                dst=edge.dst,
                kind=EdgeKind.TESTS,
                origin=edge.origin,
                file=edge.file,
                line=edge.line,
                label=f"{dst.name} is exercised by a test",
            )
        )
    return edges


# --------------------------------------------------------------- configuration


def influence_edges(index: SymbolIndex) -> list[Edge]:
    """``INFLUENCES`` from a function to the configuration it reads at runtime.

    Only real configuration nodes are linked: an ``environment variable`` edge
    points at the manifest key symbol when one exists, and otherwise at nothing
    at all.  "Reads an env var" with no node to point at is already recorded by
    the security analyzer; an edge to an invented node would only look tidier.
    """

    edges: list[Edge] = []
    budget = RELATION_BUDGETS[EdgeKind.INFLUENCES]
    keys: dict[str, str] = {}
    for sid, sym in index.by_id.items():
        if sym.kind == "config_key" and sym.signature:
            keys.setdefault(sym.name, sid)
    if not keys:
        return edges

    for sid, sym in index.by_id.items():
        if budget <= 0 or sym.kind not in {"function", "method", "module"}:
            continue
        module = index.modules.get(sym.file)
        if module is None:
            continue
        last = min(sym.end_line, sym.start_line + MAX_BODY_LINES)
        seen: set[str] = set()
        for lineno in range(sym.start_line, last + 1):
            sanitized = module.dirty_lines.get(lineno, "")
            if not _ENV_READ_RE.search(sanitized):
                continue
            # The *name* of the key lives inside a string literal, which
            # sanitisation blanks. Detection stays on the sanitised line so a
            # keyword inside an unrelated string cannot match, and the name
            # itself is read from the original.
            raw = module.line(lineno)
            if not _KEY_LOOKUP_RE.search(sanitized):
                continue
            for name, key_id in keys.items():
                if name in seen:
                    continue
                if not _mentions_key(raw, name):
                    continue
                seen.add(name)
                budget -= 1
                edges.append(
                    Edge(
                        src=sid,
                        dst=key_id,
                        kind=EdgeKind.INFLUENCES,
                        origin=RelationOrigin.INFERRED,
                        file=sym.file,
                        line=lineno,
                        label=f"runtime configuration key {name}",
                    )
                )
    return edges


def _mentions_key(text: str, key: str) -> bool:
    """Whether ``key``'s identifier appears in the line, case-insensitively.

    The environment variable and the config-file key are usually the same word
    in different casings: ``os.environ['LOG_LEVEL']`` reads the ``log_level``
    key of ``config.json``. Comparing case-sensitively meant the link between a
    setting and the code that reads it was never recorded.
    """

    return re.search(rf"\b{re.escape(key)}\b", text, re.I) is not None


# ---------------------------------------------------------------------- driver


def build_relations(index: SymbolIndex, graph: CallGraph) -> list[Edge]:
    """Every semantic relation this repository can prove or honestly infer.

    The result is deliberately not deduplicated: two callers of the same
    validator are two different facts about the code, and collapsing them would
    lose the caller side of the relation.
    """

    edges: list[Edge] = []
    edges.extend(inheritance_edges(index))
    edges.extend(attribute_edges(index))
    edges.extend(transform_edges(index))
    edges.extend(obligation_edges(index, graph))
    edges.extend(registration_edges(index))
    edges.extend(resource_edges(index))
    edges.extend(test_edges(index, graph))
    edges.extend(influence_edges(index))
    return edges


def _iter_kinds(edges: Iterable[Edge]) -> dict[EdgeKind, int]:  # pragma: no cover - diagnostics
    counts: dict[EdgeKind, int] = {}
    for edge in edges:
        counts[edge.kind] = counts.get(edge.kind, 0) + 1
    return counts
