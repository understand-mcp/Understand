"""Symbol extraction and indexing.

Python goes through the real `ast` module (FULL support). Every other
registered language uses structural scanning: comment/string-aware brace and
keyword matching. Structural extraction is explicitly marked PARTIAL - it finds
symbols and call sites but performs no scope or type resolution, and unresolved
call targets are recorded rather than guessed.
"""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from understand.engine import language_detection as lang
from understand.engine.parsing import (
    CALL_RE,
    CLASS_PATTERNS,
    CONTROL_WORDS,
    IMPORT_PATTERNS,
    KEYWORD_FUNCTION_PATTERNS,
    ParsedModule,
    extract_calls,
    extract_string_assignments,
    is_test_path,
    make_symbol_id,
    module_qualifier,
    strip_comments_and_strings,
)
from understand.logging_config import get_logger
from understand.models import CallSite, SupportLevel, Symbol

log = get_logger("engine.symbols")

MAX_LINE_CHARS = 4000
_PY_AST_KEYWORDS = frozenset({
    "def", "class", "async", "lambda", "return", "yield", "await", "import",
    "from", "if", "else", "elif", "for", "while", "try", "except", "finally",
    "with", "as", "raise", "assert", "pass", "break", "continue", "global",
    "nonlocal", "del", "print", "not", "and", "or", "in", "is", "match", "case",
    "type",
})


def truncate_lines(text: str) -> list[str]:
    lines = text.splitlines()
    if any(len(ln) > MAX_LINE_CHARS for ln in lines):
        return [ln[:MAX_LINE_CHARS] for ln in lines]
    return lines


# --------------------------------------------------------------------------- Python


def _py_signature(node: ast.AST) -> str:
    try:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            parts: list[str] = []
            pos_only = list(getattr(args, "posonlyargs", []) or [])
            defaults = list(args.defaults)
            positional = pos_only + list(args.args)
            pad = len(positional) - len(defaults)
            for i, a in enumerate(positional):
                piece = a.arg
                if i >= pad:
                    piece += "=" + ast.unparse(defaults[i - pad])
                parts.append(piece)
            if args.vararg:
                parts.append("*" + args.vararg.arg)
            elif args.kwonlyargs:
                parts.append("*")
            for a, d in zip(args.kwonlyargs, args.kw_defaults):
                piece = a.arg
                if d is not None:
                    piece += "=" + ast.unparse(d)
                parts.append(piece)
            if args.kwarg:
                parts.append("**" + args.kwarg.arg)
            ret = f" -> {ast.unparse(node.returns)}" if node.returns else ""
            prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
            return f"{prefix} {node.name}({', '.join(parts)}){ret}"
        if isinstance(node, ast.ClassDef):
            bases = ", ".join(ast.unparse(b) for b in node.bases)
            kw = ", ".join(f"{k.arg}={ast.unparse(k.value)}" for k in node.keywords if k.arg)
            inner = ", ".join(x for x in (bases, kw) if x)
            return f"class {node.name}({inner})" if inner else f"class {node.name}"
    except Exception:  # noqa: BLE001 - signature is best-effort only
        return ""
    return ""


def _py_doc(node: ast.AST) -> str:
    try:
        return (ast.get_docstring(node) or "").strip().split("\n")[0][:300]
    except Exception:  # noqa: BLE001
        return ""


def _py_expr_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Call):
        f = node.func
        if isinstance(f, ast.Name):
            names.append(f.id)
        elif isinstance(f, ast.Attribute):
            base = f.value
            parts = [f.attr]
            while isinstance(base, ast.Attribute):
                parts.append(base.attr)
                base = base.value
            if isinstance(base, ast.Name):
                parts.append(base.id)
            names.append(".".join(reversed(parts)))
    return names


def parse_python(path: str, text: str) -> ParsedModule:
    lines = truncate_lines(text)
    module = ParsedModule(path=path, language="python", support=SupportLevel.FULL, lines=lines)
    module.literals = extract_string_assignments(lines)
    # Every consumer that scans a body line (``control_flow``, ``data_flow``,
    # ``relations``) reads ``dirty_lines``. Populating it only in the structural
    # parser meant Python -- the one language parsed exactly -- had an empty
    # mapping, so every line-scanning analyzer silently saw nothing. Same
    # sanitiser, same contract, both parsers.
    py_prefixes = lang.comment_prefixes_for("python")
    sanitized, comments, _ = strip_comments_and_strings(lines, py_prefixes)
    module.comments = comments
    module.dirty_lines = {i: v for i, v in enumerate(sanitized, start=1)}
    try:
        tree = ast.parse(text, filename=path)
    except SyntaxError as exc:
        module.parse_error = f"SyntaxError: {exc.msg} (line {exc.lineno})"
        return module
    except (ValueError, RecursionError, MemoryError) as exc:
        module.parse_error = f"{type(exc).__name__}: {exc}"
        return module

    # ---- imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module.imports.append((alias.name, node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.ImportFrom):
            mod = ("." * (node.level or 0)) + (node.module or "")
            module.imports.append((mod, node.lineno, ast.unparse(node)))

    # ---- symbols
    class_defs: dict[int, str] = {}

    def walk(node: ast.AST, parent: str | None, prefix: str, container: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                kind = (
                    "class"
                    if isinstance(child, ast.ClassDef)
                    else ("method" if container in {"class", "module"} else "function")
                )
                if container == "class" and kind == "class":
                    kind = "class"
                qualified = f"{prefix}{child.name}"
                sid = make_symbol_id(path, qualified)
                sym = Symbol(
                    id=sid,
                    name=child.name,
                    kind=kind,
                    file=path,
                    language="python",
                    parent=parent,
                    start_line=child.lineno,
                    end_line=getattr(child, "end_lineno", child.lineno) or child.lineno,
                    signature=_py_signature(child),
                    docstring=_py_doc(child),
                    exported=not child.name.startswith("_"),
                )
                if isinstance(child, ast.ClassDef):
                    sym.decorators = tuple(ast.unparse(d) for d in child.decorator_list)
                    sym.bases = tuple(ast.unparse(b) for b in child.bases)
                    class_defs[id(child)] = sid
                    sym.modifiers = ("class",)
                else:
                    sym.decorators = tuple(ast.unparse(d) for d in child.decorator_list)
                    sym.modifiers = ("async",) if isinstance(child, ast.AsyncFunctionDef) else ()
                module.symbols.append(sym)
                walk(child, sid, f"{qualified}.", "class" if isinstance(child, ast.ClassDef) else "module")
            elif isinstance(child, (ast.If, ast.Try)):
                walk(child, parent, prefix, container)

    walk(tree, None, "", "module")

    # module-level symbol for file-level container
    module.symbols.append(
        Symbol(
            id=make_symbol_id(path, "<module>"),
            name=PurePosixPath(path).name,
            kind="module",
            file=path,
            language="python",
            start_line=1,
            end_line=max(1, len(lines)),
            exported=True,
        )
    )

    # ---- call sites, scope-resolved
    scopes: list[tuple[int, int, str]] = [(s.start_line, s.end_line or s.start_line, s.id)
                                           for s in module.symbols]
    scopes.sort(key=lambda t: (t[0] - t[1], t[0]))

    def scope_for(lineno: int) -> str:
        best = make_symbol_id(path, "<module>")
        best_len = 10**9
        for start, end, sid in scopes:
            if start <= lineno <= end:
                span = end - start
                if span < best_len:
                    best, best_len = sid, span
        return best

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            caller = scope_for(node.lineno)
            for name in _py_expr_names(node):
                if name.split(".")[-1] in CONTROL_WORDS:
                    continue
                module.calls.append(
                    CallSite(caller_id=caller, callee_name=name, file=path, line=node.lineno)
                )
        elif isinstance(node, ast.Await):
            module.calls.append(
                CallSite(caller_id=scope_for(node.lineno), callee_name="await",
                         file=path, line=node.lineno, reason="async boundary")
            )
    return module


# --------------------------------------------------------------------------- structural

_STRUCT_COMPILED: dict[str, list[tuple[re.Pattern[str], str]]] = {
    "function": [(re.compile(pat, re.M), lang_name) for lang_name, pat in KEYWORD_FUNCTION_PATTERNS],
    "class": [(re.compile(pat, re.M), lang_name) for lang_name, pat in CLASS_PATTERNS],
    "import": [(re.compile(pat, re.M), lang_name) for lang_name, pat in IMPORT_PATTERNS],
}

#: Words that are keywords in some registered language but not in CONTROL_WORDS,
#: which is call-oriented. They must never become symbol names either.
_STRUCT_RESERVED = frozenset({"catch", "finally", "for", "foreach", "using", "unless", "until"})


def _brace_end(lines: list[str], start_idx: int) -> int:
    """Return the 1-based last line of a brace block starting at start_idx (0-based)."""
    depth = 0
    seen = False
    for i in range(start_idx, len(lines)):
        line = lines[i]
        for ch in line:
            if ch == "{":
                depth += 1
                seen = True
            elif ch == "}":
                depth -= 1
                if seen and depth <= 0:
                    return i + 1
        if seen and depth <= 0:
            return i + 1
    return len(lines)


def _indent_end(lines: list[str], start_idx: int) -> int:
    base = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= base:
            return i
    return len(lines)


def parse_structural(path: str, text: str, language: str) -> ParsedModule:
    lines = truncate_lines(text)
    prefixes = lang.comment_prefixes_for(language)
    module = ParsedModule(path=path, language=language, support=SupportLevel.PARTIAL, lines=lines)
    sanitized, comments, _ = strip_comments_and_strings(lines, prefixes)
    module.comments = comments
    module.dirty_lines = {i: v for i, v in enumerate(sanitized, start=1)}
    module.literals = extract_string_assignments(lines)

    joined = "\n".join(sanitized)
    # Imports are read from the original text: sanitization blanks string bodies,
    # which is exactly where relative module specifiers live.
    raw_joined = "\n".join(lines)

    # imports
    for pattern, lang_name in _STRUCT_COMPILED["import"]:
        if lang_name != language:
            continue
        for m in pattern.finditer(raw_joined):
            mod = (m.group(1) or "").strip().rstrip(",")
            if mod:
                module.imports.append((mod, raw_joined.count("\n", 0, m.start()) + 1, m.group(0).strip()))

    # symbols
    brace = lang.is_brace_language(language) or language in {"rust", "java"}
    scopes: list[tuple[int, int, str, str]] = []  # start, end, id, qualified
    for group, kind in (("class", "class"), ("function", "function")):
        for pattern, lang_name in _STRUCT_COMPILED[group]:
            if lang_name != language:
                continue
            for m in pattern.finditer(joined):
                name = m.groupdict().get("name")
                if not name:
                    continue
                # A control keyword is never a definition. The method patterns
                # must match ``run() {`` but not ``if (...) {`` or
                # ``switch (...) {``, which otherwise became symbols named "if"
                # and "switch" with a bogus heritage clause from the next line.
                if name in CONTROL_WORDS or name in _STRUCT_RESERVED:
                    continue
                start = joined.count("\n", 0, m.start()) + 1
                line_no = start
                # prefer the physical line the match starts on
                prefix_lines = joined[: m.start()].count("\n")
                line_no = prefix_lines + 1
                end = (_brace_end(sanitized, line_no - 1) if brace
                       else _indent_end(sanitized, min(line_no - 1, len(sanitized) - 1)))
                parent, qual = _enclosing(scopes, line_no)
                qualified = f"{qual}{name}"
                scopes.append((line_no, end, make_symbol_id(path, qualified), qualified))
                module.symbols.append(
                    Symbol(
                        id=make_symbol_id(path, qualified),
                        name=name,
                        kind=kind,
                        file=path,
                        language=language,
                        parent=parent,
                        start_line=line_no,
                        end_line=max(line_no, end),
                        signature=sanitized[line_no - 1].strip()[:200] if 0 < line_no <= len(sanitized) else "",
                        docstring=_doc_above(sanitized, comments, line_no),
                        bases=_bases_from_line(sanitized[line_no - 1] if 0 < line_no <= len(sanitized) else ""),
                        exported=not name.startswith("_"),
                    )
                )

    module.symbols.append(
        Symbol(
            id=make_symbol_id(path, "<module>"),
            name=PurePosixPath(path).name,
            kind="module",
            file=path,
            language=language,
            start_line=1,
            end_line=max(1, len(lines)),
            exported=True,
        )
    )

    def scope_for(lineno: int) -> str:
        best = make_symbol_id(path, "<module>")
        best_span = 10**9
        for start, end, sid, _qual in scopes:
            if start <= lineno <= end:
                span = end - start
                if span < best_span:
                    best, best_span = sid, span
        return best

    module.calls = extract_calls(sanitized, path, scope_for)
    return module


def _enclosing(scopes: list[tuple[int, int, str, str]], lineno: int) -> tuple[str | None, str]:
    best: tuple[int, str, str] | None = None
    for start, end, sid, qual in scopes:
        if start < lineno <= end:
            span = end - start
            if best is None or span < best[0]:
                best = (span, sid, qual + ".")
    if best:
        return best[1], best[2]
    return None, ""


def _doc_above(sanitized: list[str], comments: dict[int, str], lineno: int) -> str:
    for i in range(lineno - 1, max(0, lineno - 6), -1):
        c = comments.get(i + 1, "")
        if c and (c.startswith("///") or c.startswith("/**") or c.startswith("*/") or "///" in c):
            return c.strip("/!*> ")[:300]
        if c.startswith("#") and not sanitized[i].strip().startswith("#"):
            continue
    return ""


_BASES_RE = re.compile(r"\(([^)]*)\)\s*(?::|where|\{|extends|implements)")
_TS_HERITAGE_RE = re.compile(r"\b(?:extends|implements)\s+([\w\s,.<>]+?)\s*(?:\{|$)")
#: A line only declares a class if it says so. Without this guard a method's
#: parameter list looked like a heritage clause: ``read(handle: string): string {``
#: produced a class whose base was ``handle: string``.
_TYPE_DECL_RE = re.compile(r"\b(?:class|interface|enum|record|struct|trait|object)\b")


def _bases_from_line(line: str) -> tuple[str, ...]:
    if not _TYPE_DECL_RE.search(line):
        return ()
    m = _BASES_RE.search(line)
    if not m:
        # TypeScript spells heritage without parentheses: ``implements A, B``.
        ts = _TS_HERITAGE_RE.search(line)
        if not ts:
            return ()
        return tuple(x.strip().split("<")[0] for x in ts.group(1).split(",") if x.strip())
    inner = m.group(1)
    return tuple(x.strip().split("<")[0] for x in inner.split(",") if x.strip())


def parse_module(path: str, text: str, language: str) -> ParsedModule:
    if language == "python":
        return parse_python(path, text)
    if language in {"json", "toml"}:
        return _parse_structured_data(path, text, language)
    if language in {"yaml", "sql", "markdown", "text", "hcl"}:
        return _text_module(path, text, language)
    return parse_structural(path, text, language)


def _text_module(path: str, text: str, language: str) -> ParsedModule:
    lines = truncate_lines(text)
    return ParsedModule(
        path=path,
        language=language,
        support=lang.support_for(language),
        lines=lines,
        comments={i: ln.strip() for i, ln in enumerate(lines, 1) if ln.strip().startswith("#")},
        literals=extract_string_assignments(lines),
    )


def _parse_structured_data(path: str, text: str, language: str) -> ParsedModule:
    lines = truncate_lines(text)
    module = ParsedModule(path=path, language=language, support=SupportLevel.FULL, lines=lines)
    try:
        if language == "json":
            import json

            data = json.loads(text)
        else:
            import tomllib

            data = tomllib.loads(text)
    except Exception as exc:  # noqa: BLE001
        module.parse_error = f"{type(exc).__name__}: {exc}"
        return module
    keys: list[tuple[str, int]] = []

    def walk(obj: object, prefix: str) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                keys.append((f"{prefix}.{k}" if prefix else str(k), 1))
                walk(v, f"{prefix}.{k}" if prefix else str(k))
        elif isinstance(obj, list):
            for item in obj[:200]:
                walk(item, prefix)

    walk(data, "")
    module.symbols.append(
        Symbol(id=make_symbol_id(path, "<root>"), name=PurePosixPath(path).name, kind="module",
               file=path, language=language, start_line=1, end_line=max(1, len(lines)), exported=True)
    )
    for key, line in keys:
        module.symbols.append(
            Symbol(id=make_symbol_id(path, key), name=key.rsplit(".", 1)[-1], kind="config_key",
                   file=path, language=language, start_line=line, end_line=line,
                   signature=key, exported=True)
        )
    return module


# --------------------------------------------------------------------------- index


@dataclass
class SymbolIndex:
    """In-memory index of symbols and import relations for one scan."""

    by_id: dict[str, Symbol] = field(default_factory=dict)
    by_name: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    by_file: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    modules: dict[str, ParsedModule] = field(default_factory=dict)
    imports: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)
    module_to_path: dict[str, str] = field(default_factory=dict)

    def add(self, module: ParsedModule) -> None:
        self.modules[module.path] = module
        self.imports[module.path] = module.imports
        qual = module_qualifier(module.path)
        self.module_to_path.setdefault(qual, module.path)
        self.module_to_path.setdefault(qual.replace("/", "."), module.path)
        for sym in module.symbols:
            self.by_id[sym.id] = sym
            self.by_name[sym.name].append(sym.id)
            self.by_file[sym.file].append(sym.id)

    def lookup(self, name: str) -> list[str]:
        short = name.rsplit(".", 1)[-1]
        return list(self.by_name.get(name, [])) + list(self.by_name.get(short, []))

    def get(self, sid: str) -> Symbol | None:
        return self.by_id.get(sid)

    def resolve_import(self, module_path: str, raw_module: str) -> str | None:
        """Best-effort resolution of an import to a repository file."""
        if not raw_module:
            return None
        raw = raw_module.strip().strip("'\"")
        if raw.startswith("."):
            base = module_qualifier(module_path).split("/")
            up = len(raw) - len(raw.lstrip("."))
            base = base[: len(base) - up] if up else base
            tail = raw.lstrip(".").replace(".", "/")
            cand = "/".join([*base, tail]) if tail else "/".join(base)
        else:
            cand = raw.replace(".", "/")
        if cand in self.module_to_path:
            return self.module_to_path[cand]
        for key, path in self.module_to_path.items():
            if key == cand or key.endswith("/" + cand) or key.endswith("." + raw):
                return path
        stem = cand.rsplit("/", 1)[-1]
        for ext in (".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".cs", ".kt"):
            probe = f"{cand}{ext}"
            if probe in self.module_to_path:
                return self.module_to_path[probe]
        for key, path in self.module_to_path.items():
            if key.rsplit("/", 1)[-1].rsplit(".", 1)[-1] == stem:
                return path
        return None

    def calls(self) -> list[CallSite]:
        """Every call site recorded while parsing, in file order."""

        sites: list[CallSite] = []
        for module in self.modules.values():
            sites.extend(module.calls)
        sites.sort(key=lambda call: (call.file, call.line))
        return sites

    def summary(self) -> list[str]:
        return [f"{k}={len(v)}" for k, v in sorted(self.by_file.items())]


__all__ = [
    "SymbolIndex",
    "parse_module",
    "parse_python",
    "parse_structural",
    "truncate_lines",
    "CALL_RE",
    "is_test_path",
]