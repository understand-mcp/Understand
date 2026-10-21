"""Intra- and inter-procedural data-flow analysis (conservative, explicitly labelled).

Model
-----
For every symbol we compute, per line, a small set of *tainted variable names*.
Facts come from four rule families defined in this module:

  SOURCES     externally controlled values (request data, argv, env, file/db reads)
  SINKS       dangerous operations (SQL, shell, eval, path join, render, ...)
  VALIDATORS  checks that can legitimately clear taint (type/schema checks,
              allow-lists, escaping, parameterised queries, auth checks)
  SANITIZERS  callables that are only trusted when they exist in the repository
              AND their body contains a recognizable transformation. A function
              *name* alone never clears taint.

Propagation is a forward data-flow fixed point over the call graph:
  seeds = parameters tainted at a call site, plus source expressions in a body.
  Intra-procedural propagation follows simple assignments.
  Inter-procedural propagation passes taint into the callee's matching
  parameters (positional) and, when unambiguous, into the callee's return value.

Provenance is explicit. Every hop records whether it was PROVEN (the value's
textually visible at both ends) or INFERRED (positional/name heuristic, or the
calling module was only structurally parsed). A flow containing any inferred hop
is reported with ``proven=False``.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from understand.engine.call_graph import CallGraph
from understand.engine.symbol_index import SymbolIndex
from understand.logging_config import get_logger
from understand.models import EdgeKind, RelationOrigin, SupportLevel

log = get_logger("engine.dataflow")

MAX_PROPAGATION_ROUNDS = 12
MAX_FLOWS = 200
MAX_BODY_LINES = 500

# --------------------------------------------------------------------------- rule tables

# A receiver whose name implies a database handle, used to qualify SQL-ish method
# calls. Without it, ``.query(`` and ``.execute(`` match host APIs too and the
# taint engine invents flows between two halves of the same expression.
_DB_STRONG = (
    # The trailing \b matters: without it "repo" matches the start of
    # "report", so ``events.report.find(...)`` looked like a database call.
    r"\b(?:db|database|conn|connection|sql|repository|repo|dao|knex"
    r"|sequelize|prisma|orm|tx|transaction)\b\s*\.\s*"
)
_DB_WEAK = r"\b(?:session|sess|client|pool|store)\b\s*\.\s*"
_DB_METHOD_STRONG = r"(?:query|execute|exec|raw|unsafe|any|one|first|many|all|findOne)\s*\("
# ``run(`` and ``exec(`` are ordinary names (``session.run(program)`` is a
# Playwright CLI dispatch, not SQL), so those two need a receiver that is
# unambiguous, not merely suggestive. The pairing is deliberate: a strong
# receiver plus a weak method, never a weak receiver plus a weak method.
_DB_METHOD_WEAK = r"(?:query|execute|exec|raw|run)\s*\("
_DB_RECEIVER = rf"(?:{_DB_STRONG}(?:{_DB_METHOD_STRONG}|{_DB_METHOD_WEAK})|{_DB_WEAK}{_DB_METHOD_STRONG})"

# Source kinds whose line number is a POSITION rather than a match.
# ``_find_source`` hands back the enclosing function's first line when the
# value came from a parameter or could not be tied to a source line at all,
# so comparing that line with a sink line proves nothing either way.
_NO_MATCHED_SOURCE_LINE = frozenset({"parameter", "unknown", "unknown-origin"})

SOURCE_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("request", r"\b(?:req|request)\s*\.\s*(?:args|form|json|values|body|data|query_params|GET|POST|params|query)\b", "HTTP request data"),
    ("cli", r"\b(?:process\s*\.\s*argv|sys\s*\.\s*argv|os\s*\.\s*Args|flag\s*\.\s*\w+|cli\s*\.\s*\w+)", "command-line argument"),
    ("env", r"\b(?:os\s*\.\s*environ|process\s*\.\s*env|ENV\s*\[|System\s*\.\s*getenv|\bgetenv\s*\()", "environment variable"),
    ("http-response", r"\b(?:requests\s*\.\s*(?:get|post|put)|httpx\s*\.|fetch\s*\(|axios\s*\.|http\s*\.\s*Get)", "outbound HTTP response"),
    ("file-read", r"\b(?:open\s*\(|readFile|read_text\s*\(|os\s*\.\s*ReadFile|ioutil\s*\.\s*ReadFile|fopen\s*\()", "file read"),
    # The receiver has to look like a database handle. A bare ``.query(`` matches
    # browser and platform APIs too (``chrome.tabs.query(...)`` in a Chrome
    # extension was classified as a database read), and a source that is really a
    # sink turns every SQL finding into a fabricated flow.
    # ``.find(`` is deliberately absent: it is ``Array.prototype.find`` in
    # almost every codebase (``this.state.sessions.find(...)`` in Playwright's
    # dashboard model was classified as a database read), and ``.findOne(``
    # needs a database receiver like every other method here.
    ("db-read", rf"\b(?:SELECT\b|cursor\s*\.\s*execute|{_DB_RECEIVER})", "database read"),
    ("body-stream", r"\b(?:r\s*\.\s*Body|req\s*\.\s*Stream|request\s*\.\s*get_data\s*\(\))", "raw request body"),
    ("event-payload", r"\b(?:on\s*\(\s*['\"]message['\"]|\.\s*recv\s*\(\s*\)|event\s*\.\s*data)", "event/message payload"),
    ("arg-param", r"^\s*(?:const|let|var|final)?\s*[A-Za-z_$][\w$]*\s*(?:=|:)\s*(?:process|os)\s*\.\s*(?:argv|environ|env)\b", "process argument"),
)

SINK_PATTERNS: tuple[tuple[str, str, str], ...] = (
    # A bare ``query(`` / ``raw(`` / ``.execute(`` is not SQL: ``chrome.tabs.query(``,
    # ``Map.prototype.raw(`` and similar host APIs matched here and were reported as
    # critical SQL execution. Either an explicit DB receiver, a driver type, or a
    # raw SQL string has to be present.
    (
        "sql-exec",
        # No bare ``QueryContext``: that is the name Playwright gives its DOM
        # query context type, and matching the identifier classified every
        # ``context: QueryContext`` parameter as SQL execution.
        r"cursor\s*\.\s*execute"
        r"|ExecContext\s*\.\s*execute"
        r"|sql\s*\.\s*(?:query|exec)"
        rf"|(?:{_DB_RECEIVER})"
        # A SQL-ish method whose first argument is a string literal or a template
        # is almost always a hand-written statement, whatever the receiver is
        # called. An empty or identifier argument proves nothing, so those are
        # not matched here.
        r"|(?:query|execute|raw|run)\s*\(\s*[fbr]*[\"'`]",
        "SQL execution",
    ),
    # A shell sink is a call whose arguments a shell can reinterpret. An argv
    # array, or an explicit shell=False, means no shell is involved, so those
    # calls are not shell sinks. ``child_process.spawn`` takes an argv array
    # too; only exec and execSync go through a shell.
    ("shell-exec", r"(?:os\s*\.\s*system|os\s*\.\s*popen"
                   r"|subprocess\s*\.\s*(?:run|call|Popen|check_output|check_call)\s*\("
                   r"(?!\s*\[)(?![^\n]*shell\s*=\s*False)"
                   r"|child_process\s*\.\s*(?:exec|execSync)"
                   r"|Runtime\s*\.\s*getRuntime)", "shell command execution"),
    # ``compile(`` is excluded: it is a template compiler in every frontend
    # framework (``compile(template, options)`` in Vue is not code execution).
    # ``$eval``-style names are excluded because ``$`` is a non-word character,
    # so ``\beval(`` matches Playwright's ``page.$eval(selector, fn)`` DOM
    # helper; the negative lookbehind requires a real boundary.
    # ``exec(`` requires a template literal, a concatenated string, or a quoted
    # argument followed by another argument. Node's
    # ``child_process.exec('tar', '-xzf', file)`` passes argv straight to the
    # OS with no shell, so matching it as "dynamic evaluation" is wrong; the
    # dangerous shapes are the interpolated ones.
    ("eval", r"(?:(?<![$\w.])eval\s*\(|new\s+Function\s*\(|(?<![$\w.])exec\s*\(\s*(?:[fbr]*[\"'`][^\"'`]*[\"'`]\s*[\"']|[fbr]*`|[fbr]*[\"'`][^\"'`]*[\"'`]\s*\+|[^\s,)]+\s*\+))", "dynamic evaluation"),
    ("path-join", r"(?:os\s*\.\s*path\s*\.\s*join|path\s*\.\s*join|filepath\s*\.\s*Join)", "filesystem path construction"),
    ("file-write", r"(?:open\s*\([^)]*['\"][wa]|\.\s*write_text\s*\(|\.\s*writeFile|os\s*\.\s*write\s*\(|WriteFile\s*\()", "file write"),
    ("http-send", r"(?:requests\s*\.\s*(?:post|put|patch)|httpx\s*\.\s*post|axios\s*\.\s*post|fetch\s*\([^)]{0,120}method\s*:\s*['\"]POST)", "outbound HTTP request"),
    ("render-html", r"(?:innerHTML|dangerouslySetInnerHTML|render_template_string|document\s*\.\s*write|\|safe\b|\bautoescape\s+false\b)", "HTML rendering"),
    ("redirect", r"(?:sendRedirect|redirect\s*\(|window\s*\.\s*location\s*=|Response\s*\.\s*redirect)", "HTTP redirect"),
    ("deserialize", r"(?:pickle\s*\.\s*loads|yaml\s*\.\s*load\s*\(|marshal\s*\.\s*loads|jsonpickle|unserialize\s*\(|ObjectInputStream)", "unsafe deserialization"),
    ("crypto-weak", r"(?:hashlib\s*\.\s*md5|hashlib\s*\.\s*sha1|\bMD5\s*\.\s*new|\bSHA1\s*\(|\bDES\b|\bRC4\b|Math\s*\.\s*random\b|\brandom\s*\.\s*(?:random|randint|choice)\b)", "weak cryptography / non-cryptographic randomness"),
    ("tls-off", r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false))", "TLS verification disabled"),
    ("tempfile-insecure", r"(?:tempfile\s*\.\s*mktemp|mktemp\s*\()", "insecure temporary file"),
)

VALIDATION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("type-check", r"(?:isinstance\s*\(|\btypeof\s+\w+\s*===|instanceof\b|\binstance\s+\w+\b|\bis_numeric\b|\bstrconv\.\w*Parse)"),
    ("schema-validation", r"(?:BaseModel|z\s*\.\s*object|zod|joi\s*\.|schema\s*\.\s*validate|Validate\s*\(|pydantic|\bparse_obj\b)"),
    ("allowlist", r"(?:allow_?list|white_?list|safe_?list|allowed_\w+|\bin\s+ALLOWED|SetOf\s*\(|valid_\w+\s*=)"),
    ("escaping", r"(?:escape\w*\s*\(|htmlspecialchars|shell_?quote|shlex\s*\.\s*quote|quote_?\w*\s*\(|sanitiz\w*\s*\()"),
    ("range-check", r"(?:<\s*0\s*>|<=\s*len\s*\(|\blen\s*\([^)]*\)\s*[<>]|\bisdigit\s*\(|maxlength|maxLength|\bclamp\b)"),
    ("parameterized-query", r"(?:execute\s*\(\s*[^,()]+\s*,\s*[\(\[]|\?\s*,\s*%s|parameteriz|prepare\s*\(\s*[^\"']|PreparedStatement|sql\s*\.\s*Named)"),
    ("auth-check", r"(?:require_auth|is_authenticated|current_user|verify_token|check_permission|login_required|jwt\s*\.\s*verify|hasPermission|authorize\s*\(|@PreAuthorize|IsAuthenticated)"),
    ("path-containment", r"(?:realpath|resolve\(\)\s*\.\s*startswith|\.startswith\s*\(\s*(?:BASE|ROOT|ALLOWED)|abspath\s*\()"),
)

SANITIZER_NAMES = frozenset({
    "escape", "escape_html", "escapejs", "htmlspecialchars", "sanitize", "sanitise",
    "sanitize_input", "shellquote", "shlex_quote", "quote", "quote_identifier",
    "escape_like", "clean", "validate_input", "validate", "safe_join", "is_safe_path",
    "safe_path_join", "prepare_statement", "parameterize", "realpath_check",
})

_SANITIZER_BODY_HINTS = (
    r"\.replace\s*\(", r"re\s*\.\s*sub\s*\(", r"\.escape\s*\(", r"\.quote\s*\(",
    r"realpath", r"abspath", r"basename", r"int\s*\(", r"float\s*\(",
    r"\.strip\s*\(", r"isinstance\s*\(", r"\.lower\s*\(", r"urlencode",
    r"startswith\s*\(", r"shlex",
)

_ASSIGN_RE = re.compile(r"^\s*(?:const|let|var|final|my|private|public|static)?\s*"
                        r"(?P<lhs>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*"
                        r"(?::[^=]*?)?=\s*(?!=)(?P<rhs>.+?)\s*$")

_FUNC_SIG_RES = (
    re.compile(r"^\s*(?:export\s+)?(?:public\s+|private\s+|protected\s+|internal\s+|static\s+|"
               r"open\s+|override\s+|suspend\s+|async\s+)*(?:async\s+)?(?:function\s+)?"
               r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^)]*)\)\s*(?:[:{]|->|where|\{)"),
    re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^)]*)\)"),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^)]*)\)"),
    re.compile(r"^\s*(?:public|private|protected|static|final)?\s*[\w<>\[\],.?]*\s+"
               r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<args>[^)]*)\)\s*(?:throws\s[\w,\s.]*)?\{"),
)

_ARGV_INNER = re.compile(r"^\s*(?:process|os)\s*\.\s*(?:argv|Args|environ|env)\s*(?:\[|\.get)?")


def _compile(patterns: tuple[tuple[str, str, str], ...]) -> list[tuple[str, re.Pattern[str], str]]:
    return [(n, re.compile(p), d) for n, p, d in patterns]


SRC_RULES = _compile(SOURCE_PATTERNS)
SINK_RULES = _compile(SINK_PATTERNS)
VAL_RULES = [(n, re.compile(p)) for n, p in VALIDATION_PATTERNS]


def _rules_by_kind(patterns: tuple[tuple[str, str, str], ...]) -> dict[str, list[re.Pattern[str]]]:
    """Group compiled patterns by source kind.

    Needed to ask a precise question — "does *this* assignment pull from an
    environment variable?" — rather than "does *some* source appear on this
    line?".
    """
    grouped: dict[str, list[re.Pattern[str]]] = {}
    for kind, pattern, _doc in patterns:
        grouped.setdefault(kind, []).append(re.compile(pattern))
    return grouped

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


# --------------------------------------------------------------------------- facts


@dataclass
class LineFacts:
    """Everything the rules can say about one physical line."""

    sources: list[tuple[int, str, str]] = field(default_factory=list)   # (col, kind, doc)
    sinks: list[tuple[int, str, str]] = field(default_factory=list)
    validators: list[str] = field(default_factory=list)
    lhs: str = ""
    rhs: str = ""


def line_facts(line: str) -> LineFacts:
    facts = LineFacts()
    for name, pat, doc in SRC_RULES:
        for m in pat.finditer(line):
            facts.sources.append((m.start(), name, doc))
    for name, pat, doc in SINK_RULES:
        for m in pat.finditer(line):
            facts.sinks.append((m.start(), name, doc))
    for name, pat in VAL_RULES:
        if pat.search(line):
            facts.validators.append(name)
    assign = _ASSIGN_RE.match(line)
    if assign:
        facts.lhs = assign.group("lhs")
        facts.rhs = assign.group("rhs")
    return facts


@dataclass
class Hop:
    label: str
    file: str
    line: int
    symbol: str
    origin: str
    text: str = ""

    def to_dict(self) -> dict[str, object]:
        return {"label": self.label, "file": self.file, "line": self.line,
                "symbol": self.symbol, "origin": self.origin, "text": self.text}


@dataclass
class TaintFlow:
    source_kind: str = ""
    source_description: str = ""
    source_file: str = ""
    source_line: int = 0
    sink_kind: str = ""
    sink_description: str = ""
    sink_file: str = ""
    sink_line: int = 0
    hops: list[Hop] = field(default_factory=list)
    cross_module: bool = False
    unresolved_hops: list[str] = field(default_factory=list)

    @property
    def proven(self) -> bool:
        return not self.unresolved_hops and all(h.origin != RelationOrigin.INFERRED.value for h in self.hops)

    def path(self) -> list[str]:
        return [h.label for h in self.hops]

    def to_dict(self) -> dict[str, object]:
        return {
            "source": {"kind": self.source_kind, "description": self.source_description,
                       "file": self.source_file, "line": self.source_line},
            "sink": {"kind": self.sink_kind, "description": self.sink_description,
                     "file": self.sink_file, "line": self.sink_line},
            "cross_module": self.cross_module,
            "proven": self.proven,
            "hops": [h.to_dict() for h in self.hops],
            "unresolved_hops": self.unresolved_hops,
        }


# --------------------------------------------------------------------------- analyzer


class DataFlowAnalyzer:
    def __init__(self, index: SymbolIndex, graph: CallGraph, *,
                 cross_module: bool = False, deep: bool = False) -> None:
        self.index = index
        self.graph = graph
        self.cross_module = cross_module
        self.deep = deep
        self.facts: dict[str, dict[int, LineFacts]] = {}
        self.params: dict[str, list[str]] = {}
        self._trusted_sanitizers: set[str] = set()
        self._raw_cache: dict[str, dict[int, str]] = {}
        self._source_rules_by_kind = _rules_by_kind(SOURCE_PATTERNS)
        self._resolve_sanitizers()

    # ----------------------------------------------------------- preparation
    def prepare(self) -> None:
        for path, module in self.index.modules.items():
            table: dict[int, LineFacts] = {}
            for i in range(1, len(module.lines) + 1):
                text = module.dirty_lines.get(i, module.line(i))
                if not text.strip():
                    continue
                table[i] = line_facts(text)
            self.facts[path] = table
        for sid, sym in self.index.by_id.items():
            if sym.kind not in {"function", "method"}:
                continue
            self.params[sid] = self._signature_params(sid, sym)

    def _resolve_sanitizers(self) -> None:
        for name in SANITIZER_NAMES:
            ids = self.index.by_name.get(name)
            if not ids:
                # Not present in the repo: trust the name only for well-known stdlib helpers.
                if name in {"escape", "escapejs", "quote", "htmlspecialchars", "shlex_quote"}:
                    self._trusted_sanitizers.add(name)
                continue
            for sid in ids:
                sym = self.index.by_id[sid]
                mod = self.index.modules.get(sym.file)
                if mod is None:
                    continue
                body = "\n".join(mod.dirty_lines.get(i, mod.line(i))
                                 for i in range(sym.start_line, min(sym.end_line, sym.start_line + 120) + 1))
                if any(re.search(hint, body) for hint in _SANITIZER_BODY_HINTS):
                    self._trusted_sanitizers.add(name)

    def _signature_params(self, sid: str, sym) -> list[str]:
        target_module = self.index.modules.get(sym.file)
        if target_module is None:
            return []
        for i in range(sym.start_line, max(sym.start_line - 2, 0), -1):
            for pattern in _FUNC_SIG_RES:
                m = pattern.search(target_module.dirty_lines.get(i, target_module.line(i)) or target_module.line(i))
                if m and m.group("name").lstrip("*") in {sym.name, sym.name.split(".")[-1]}:
                    raw = m.group("args") or ""
                    out = []
                    for part in raw.split(","):
                        p = part.strip()
                        if not p:
                            continue
                        p = p.split(":")[0].split("=")[0].strip()
                        p = p.replace("*", "").replace("&", "").strip()
                        if p and _IDENT_RE.fullmatch(p):
                            out.append(p)
                    return out
        return []

    # ------------------------------------------------------------ propagation
    def _body(self, sid: str) -> tuple[str, list[tuple[int, str]], dict[int, LineFacts]]:
        sym = self.index.by_id[sid]
        module = self.index.modules[sym.file]
        if module is None:
            return "", [], {}
        start, end = sym.start_line, min(sym.end_line, sym.start_line + MAX_BODY_LINES)
        lines = [(i, module.dirty_lines.get(i, module.line(i))) for i in range(start, end + 1)]
        return sym.id, lines, self.facts.get(sym.file, {})

    def _local_taint(self, sid: str, seeded: set[str]) -> tuple[set[str], set[str], dict[str, int]]:
        """Forward pass inside one symbol. Returns (tainted, validated_at, sinks_touched)."""
        _sym, lines, fact_table = self._body(sid)
        tainted: set[str] = set()
        validated: dict[str, int] = {}
        seed_lower = {s.lower() for s in seeded}
        for name in seeded:
            tainted.add(name)
        sinks_hit: dict[str, int] = {}
        for lineno, text in lines:
            facts = fact_table.get(lineno) or line_facts(text)
            # sources seed taint for anything assigned from them
            if facts.sources and facts.lhs:
                tainted.add(facts.lhs.split(".")[-1])
                validated.pop(facts.lhs.split(".")[-1], None)
            if facts.lhs and facts.rhs:
                lhs = facts.lhs.split(".")[-1]
                rhs = facts.rhs
                rhs_idents = set(_IDENT_RE.findall(rhs))
                if lhs in seed_lower or (rhs_idents & {t.lower() for t in tainted}):
                    tainted.add(lhs)
                    validated.pop(lhs, None)
                elif rhs_idents & {t.lower() for t in validated}:
                    tainted.discard(lhs)
                    validated.setdefault(lhs, lineno)
                elif self._rhs_is_sanitized(rhs):
                    tainted.discard(lhs)
                elif facts.validators:
                    # a validator on a tainted expression clears the bound name
                    if any(t.lower() in rhs_idents for t in tainted):
                        for t in list(tainted):
                            if t.lower() in rhs_idents and lhs in rhs_idents:
                                tainted.discard(t)
                        tainted.discard(lhs)
                        validated.setdefault(lhs, lineno)
            # sinks
            for _col, kind, _doc in facts.sinks:
                for var in tainted:
                    if re.search(rf"\b{re.escape(var)}\b", text, re.IGNORECASE):
                        sinks_hit[f"{kind}@{lineno}"] = lineno
        return tainted, set(validated), sinks_hit

    def _rhs_is_sanitized(self, rhs: str) -> bool:
        for m in re.finditer(r"([A-Za-z_$][\w$]*)\s*\(", rhs):
            leaf = m.group(1)
            if leaf in self._trusted_sanitizers or leaf.lower() in self._trusted_sanitizers:
                return True
        return any(leaf in self._trusted_sanitizers for leaf in _IDENT_RE.findall(rhs))

    # ------------------------------------------------------------------- main
    def analyze(self, *, limit: int = MAX_FLOWS) -> list[TaintFlow]:
        self.prepare()
        in_taint: dict[str, set[str]] = defaultdict(set)
        out_taint: dict[str, set[str]] = {}
        flow_seeds: dict[str, list[Hop]] = {}


        for _round in range(MAX_PROPAGATION_ROUNDS):
            changed = False
            for sid, sym in self.index.by_id.items():
                if sym.kind not in {"function", "method", "module"}:
                    continue
                tainted, _validated, _hits = self._local_taint(sid, in_taint[sid])
                prev = out_taint.get(sid, set())
                if tainted != prev:
                    out_taint[sid] = tainted
                    changed = True
                for callee_id in self.graph.callees(sid):
                    if not self.cross_module:
                        callee = self.index.by_id.get(callee_id)
                        if callee is None or callee.file != sym.file:
                            continue
                    module = self.index.modules[sym.file]
                    if module is None:
                        continue
                    edge_line = self._edge_line(sid, callee_id)
                    text = module.dirty_lines.get(edge_line, "")
                    if not text.strip():
                        text = next((module.dirty_lines.get(i, "") for i in range(edge_line - 1, 0, -1)
                                     if module.dirty_lines.get(i, "").strip()), "")
                    passed = self._args_matching(text, tainted)
                    params = self.params.get(callee_id, [])
                    newly = set()
                    if params and passed:
                        for idx, _arg in enumerate(passed):
                            name = params[idx] if idx < len(params) else (params[-1] if len(params) == 1 else None)
                            if name:
                                newly.add(name)
                    elif params and text.strip():
                        newly.update(params[: min(len(params), max(1, len(tainted) + 1))])
                    if newly - in_taint[callee_id]:
                        in_taint[callee_id] |= newly
                        changed = True
                    if newly:
                        hop = Hop(label=f"call {callee_id.split('::')[-1]}", file=sym.file,
                                  line=edge_line, symbol=sid.split("::")[-1],
                                  origin=self._edge_origin(sid, callee_id))
                        flow_seeds.setdefault(callee_id, []).append(hop)
            if not changed:
                break

        # ------------------------------------------------------------- reporting
        flows: list[TaintFlow] = []
        seen: set[tuple[str, str, int, str]] = set()
        for sid, tainted in sorted(out_taint.items()):
            if not tainted:
                continue
            sym = self.index.by_id[sid]
            if sym.file not in self.index.modules:
                continue
            module = self.index.modules[sym.file]
            if self.index.modules[sym.file].support is SupportLevel.TEXT_ONLY:
                continue
            raw_lines = self._raw_lines(sym.file)
            for lineno in range(sym.start_line, min(sym.end_line, sym.start_line + MAX_BODY_LINES) + 1):
                # Facts are detected on sanitized text (so a keyword inside a
                # string literal cannot match), but the snippet handed to a
                # human must be the original line: a reviewer checking
                # ``path.join(appFolder, 'index.html')`` cannot verify anything
                # when every string body has been blanked out.
                text = raw_lines.get(lineno, module.dirty_lines.get(lineno, module.line(lineno)))
                facts = self.facts.get(sym.file, {}).get(lineno)
                if facts is None or not facts.sinks:
                    continue
                # A tainted name sitting on the LEFT of an assignment did not
                # travel into the sink -- it is being produced by it. In
                # ``row = conn.execute("SELECT MAX(version) FROM schema_info")``
                # the word ``row`` is present and the call is a SQL sink, so
                # the previous row was reported as reaching SQL execution. It
                # does not: the value passed to the call is the literal, and
                # the old row is being overwritten. Stripping the assignment
                # target first is what tells the two apart.
                haystack = re.sub(r"^\s*[\w.\[\]]+\s*(?::=|=)\s*", "", text)
                hit = [
                    var
                    for var in tainted
                    if re.search(rf"\b{re.escape(var)}\b", haystack, re.IGNORECASE)
                ]
                if not hit:
                    continue
                for _col, kind, doc in facts.sinks:
                    key = (sym.file, kind, lineno, sid)
                    if key in seen:
                        continue
                    seen.add(key)
                    src_kind, src_doc, src_line = self._find_source(sid, tainted)
                    chain = self._build_chain(sid)
                    # No propagation means no flow. A source and a sink reported on
                    # the same expression are one regex matching twice, not a path;
                    # emitting it produced "data from X reaches X" findings with zero
                    # hops, which is how one browser API call became a critical
                    # SQL-injection flow.
                    if not chain:
                        continue
                    # A sink line that already carries a SOURCE pattern, where
                    # the source could not be tied to any tainted name, is one
                    # expression rather than a path. ``conn.execute("SELECT
                    # name FROM sqlite_master")`` holds the db-read source (the
                    # word SELECT) and the sql-exec sink (the method call) on
                    # the same line, and no assignment ever carried a value
                    # between them, so there is nothing to propagate. It was
                    # reported as "a database read reaches SQL execution" at
                    # critical severity with zero real flow.
                    #
                    # Both halves of the test are needed. The source-on-this-
                    # line check alone would also drop a real injection written
                    # as ``conn.execute("SELECT " + tainted)``. The
                    # unattributed check alone does nothing, because the line
                    # number a fallback kind carries is the function's first
                    # line, which is not where the pattern matched. And a
                    # parameter used as the argument on its own declaration
                    # line is a real flow that must survive: that line has no
                    # source pattern on it, so it is kept.
                    if src_line == lineno:
                        continue
                    flows.append(TaintFlow(
                        source_kind=src_kind, source_description=src_doc,
                        source_file=sym.file, source_line=src_line,
                        sink_kind=kind, sink_description=doc,
                        sink_file=sym.file, sink_line=lineno,
                        hops=[*chain, Hop(label=f"sink: {kind}", file=sym.file, line=lineno,
                                          symbol=sid.split("::")[-1],
                                          origin=RelationOrigin.STATIC_DIRECT.value,
                                          text=text.strip()[:160])],
                        cross_module=any(h.file != sym.file for h in chain),
                        unresolved_hops=self._unresolved_chain(sid),
                    ))
                    if len(flows) >= limit:
                        return flows
        return flows

    # ------------------------------------------------------------- utilities
    def _edge_line(self, src: str, dst: str) -> int:
        for e in self.graph.outgoing.get(src, []):
            if e.dst == dst and e.kind is EdgeKind.CALLS:
                return e.line or 0
        sym = self.index.by_id.get(src)
        return sym.start_line if sym else 0

    def _edge_origin(self, src: str, dst: str) -> str:
        for e in self.graph.outgoing.get(src, []):
            if e.dst == dst and e.kind is EdgeKind.CALLS:
                return e.origin.value
        return RelationOrigin.INFERRED.value

    @staticmethod
    def _args_matching(text: str, tainted: set[str]) -> list[str]:
        lowered = text.lower()
        found: list[str] = []
        for m in re.finditer(r"\(([^()]*)\)", text):
            for arg in m.group(1).split(","):
                arg = arg.strip().rstrip(")")
                if not arg:
                    continue
                for var in tainted:
                    if re.search(rf"\b{re.escape(var)}\b", arg, re.IGNORECASE) or var.lower() in lowered:
                        found.append(arg.split("=")[0].split(":")[0].strip())
                        break
        return found

    def _find_source(self, sid: str, tainted: set[str]) -> tuple[str, str, int]:
        """Attribute the taint to the line that actually produced the value.

        The previous version returned the *first* source-looking line anywhere
        in the function body. In a 700-line file that pairs one unrelated
        ``process.env.SOMETHING`` with all forty ``path.join`` calls in the
        same file and calls every one of them "environment variable reaches
        filesystem path construction". A source is only reported when it is on
        a line that assigns or declares the tainted name; otherwise the origin
        is reported honestly as a parameter or as unknown.
        """
        sym = self.index.by_id[sid]
        module = self.index.modules.get(sym.file)
        if module is None:
            return "unknown-origin", "value of unknown origin", 0
        last = min(sym.end_line, sym.start_line + MAX_BODY_LINES)
        lines = self._raw_lines(sym.file)
        for name in sorted(tainted):
            assignment = re.compile(
                rf"(?:^|[^\w$]){re.escape(name)}\s*(?:=|:=|:=)\s*([^;]{{0,200}})"
            )
            for lineno in range(sym.start_line, last + 1):
                facts = self.facts.get(sym.file, {}).get(lineno)
                if not facts or not facts.sources:
                    continue
                text = lines.get(lineno, "")
                match = assignment.search(text)
                if not match:
                    continue
                tail = match.group(1)
                for _col, kind, doc in facts.sources:
                    if any(r.search(tail) for r in self._source_rules_by_kind.get(kind, ())):
                        return kind, doc, lineno
        for name in sorted(tainted):
            if self.params.get(sid) and name in self.params[sid]:
                return "parameter", f"parameter {name!r} of {sym.id.split('::')[-1]}", sym.start_line
        return "unknown-origin", "tainted value of unknown origin (propagated)", sym.start_line

    def _raw_lines(self, relpath: str) -> dict[int, str]:
        """Original file text by line number.

        Evidence snippets come from ``dirty_lines``, which is the *sanitized*
        copy: string bodies are blanked there. Showing that as evidence makes
        a finding impossible to check by hand, because the line that matters
        (``path.join(appFolder, 'index.html')``) arrives with its literals
        replaced by spaces.
        """
        cached = self._raw_cache.get(relpath)
        if cached is None:
            module = self.index.modules.get(relpath)
            if module is None:
                cached = {}
            else:
                cached = {n: module.line(n) for n in range(1, len(module.lines) + 1)}
            self._raw_cache[relpath] = cached
        return cached

    def _build_chain(self, sid: str) -> list[Hop]:
        seeds = self._ancestor_seeds(sid)
        chain = list(seeds)
        chain.append(Hop(label=f"in {sid.split('::')[-1]}", file=self.index.by_id[sid].file,
                         line=self.index.by_id[sid].start_line, symbol=sid.split("::")[-1],
                         origin=RelationOrigin.STATIC_DIRECT.value))
        return chain

    def _ancestor_seeds(self, sid: str) -> list[Hop]:
        seen: set[str] = set()
        out: list[Hop] = []
        stack = self.graph.callers(sid)
        depth = 0
        while stack and depth < 8 and len(out) < 6:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            sym = self.index.by_id.get(node)
            if sym is None:
                continue
            out.append(Hop(label=f"entered from {sym.id.split('::')[-1]}", file=sym.file,
                           line=sym.start_line, symbol=sym.id.split("::")[-1],
                           origin=self._edge_origin(node, sid)))
            stack.extend(self.graph.callers(node))
            depth += 1
        out.reverse()
        return out

    def _unresolved_chain(self, sid: str) -> list[str]:
        unresolved = [c.callee_name for c in self.graph.unresolved if c.caller_id == sid]
        return sorted(set(unresolved))[:10]


def analyze_data_flow(index: SymbolIndex, graph: CallGraph, *, cross_module: bool = False,
                      deep: bool = False, limit: int = MAX_FLOWS) -> list[TaintFlow]:
    return DataFlowAnalyzer(index, graph, cross_module=cross_module, deep=deep).analyze(limit=limit)
