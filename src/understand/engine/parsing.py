"""Shared parsing infrastructure: sanitization, structural scanning, models.

`ParsedModule` is the single representation every analyzer consumes, whether the
module was understood by a real parser (Python `ast`) or by structural scanning.
The `parse_error` / `support` fields keep the two honestly distinguishable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from understand.models import CallSite, SupportLevel, Symbol

# --------------------------------------------------------------------------- regexes

IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"

KEYWORD_FUNCTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("c", rf"(?P<kw>static\s+|inline\s+|extern\s+|const\s+|virtual\s+|unsigned\s+|signed\s+)*"
            rf"(?:[A-Za-z_][\w:<>,\*&\[\]\s]*?)\s+\**(?P<name>{IDENT})\s*\([^;{{]*\)\s*(?:const\s*)?\{{"),
    ("go", rf"func\s+(?:\(\s*\w+\s+\*?{IDENT}\s*\)\s*)?(?P<name>{IDENT})\s*(?:\[[^\]]*\])?\s*\([^{{]*\)\s*(?:\([^{{]*\))?\s*\{{"),
    ("rust", rf"(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>{IDENT})\s*(?:<[^>{{]*>)?\s*\("),
    ("javascript", rf"(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>{IDENT})"),
    ("javascript", rf"(?:export\s+)?(?:const|let|var)\s+(?P<name>{IDENT})\s*(?::[^=;\n]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>)"),
    # ``class`` is deliberately absent for javascript/typescript: it lives in
    # CLASS_PATTERNS. Listing it here as well produced two symbols with the same
    # id for every TypeScript class, and because the function pass runs second
    # the ``function``-kinded one won in the index -- so every TS class was
    # mistyped as a function by everything downstream.
    ("typescript", rf"(?:export\s+)?(?:declare\s+)?(?:async\s+)?function\s*\*?\s*(?P<name>{IDENT})"),
    # Arrow-function and function-expression constants, for the same reason as
    # the javascript entry above. TypeScript codebases declare helpers this way
    # constantly (``export const tString = (arg: any, path: string) => {``), and
    # when they are not indexed the symbol does not exist, so every call to
    # them stays unresolved even though the definition is in the repository.
    ("typescript", rf"(?:export\s+)?(?:default\s+)?(?:const|let|var)\s+(?P<name>{IDENT})\s*(?::[^=;\n]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>)"),
    # Class methods. A TypeScript or JavaScript class whose methods are not
    # indexed is a class with no body as far as every analyzer is concerned:
    # no call sites, no attribute reads or writes, no data-flow. The leading
    # ``(?:private|public|protected|readonly|static|async|get|set|override)``
    # run is what distinguishes a method from an ``if`` or a call, and the
    # indent requirement is what keeps a nested call from looking like one.
    ("typescript", rf"^[ \t]{{2,}}(?:(?:public|private|protected|readonly|static|"
                  rf"abstract|override|async|get|set)\s+)*\*?\s*(?P<name>{IDENT})\s*"
                  rf"\([^;{{}}]*\)\s*(?::[^{{;]+)?\{{"),
    ("javascript", rf"^[ \t]{{2,}}(?:(?:static|async|get|set|\*)\s+)*"
                   rf"(?P<name>{IDENT})\s*\([^;{{}}]*\)\s*\{{"),
    ("typescript", rf"(?:export\s+)?interface\s+(?P<name>{IDENT})"),
    ("typescript", rf"(?:export\s+)?type\s+(?P<name>{IDENT})\s*(?:<[^=]*>)?\s*="),
    ("typescript", rf"(?:export\s+)?enum\s+(?P<name>{IDENT})"),
    ("java", rf"(?:public|private|protected|static|final|abstract|synchronized|native|\s)*"
             rf"(?P<name>{IDENT})\s*\([^;{{]*\)\s*(?:throws\s[\w,\s.]+)?\{{"),
    ("kotlin", rf"(?:private\s+|public\s+|internal\s+|open\s+|override\s+|suspend\s+)*fun\s+(?:<[^>]*>\s*)?(?P<name>{IDENT})\s*\("),
    ("csharp", rf"(?:public|private|protected|internal|static|virtual|override|async|sealed|partial|\s)*"
              rf"(?P<name>{IDENT})\s*\([^;{{]*\)\s*(?:where\s[^{{]+)?\{{"),
    ("php", rf"(?:public\s+|private\s+|protected\s+|static\s+|abstract\s+|final\s+)*function\s*&?\s*(?P<name>{IDENT})\s*\("),
    ("swift", rf"(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+|static\s+|class\s+|final\s+|override\s+|mutating\s+)*func\s+(?P<name>{IDENT})\s*(?:<[^>]*>)?\s*\("),
    ("ruby", rf"def\s+(?:self\.)?(?P<name>{IDENT}[?!]?)"),
    ("scala", rf"(?:private\s+|protected\s+|override\s+|final\s+|case\s+)*class\s+(?P<name>{IDENT})"),
    ("scala", rf"def\s+(?P<name>{IDENT})\s*(?:\[[^\]]*\])?\s*(?:\([^)]*\))?\s*(?::[^=]+)?="),
    ("dart", rf"(?P<kw>class|mixin|extension|enum)\s+(?P<name>{IDENT})"),
    ("dart", rf"(?:[\w<>,\s]*?\s+)?(?P<name>{IDENT})\s*\([^;{{]*\)\s*(?:async\s*\*?\s*)?\{{"),
    ("groovy", rf"(?:def|void|[\w<>\[\]]+)\s+(?P<name>{IDENT})\s*\("),
)

CLASS_PATTERNS: tuple[tuple[str, str], ...] = (
    # ``^\s*`` is wrong here even though it looks harmless: ``\s`` matches a
    # newline, so a class preceded by a blank line matched starting on the blank
    # line and every computed line number -- and therefore the class's whole body
    # range, its bases and its evidence -- shifted by one. ``[ \t]*`` cannot
    # cross a line boundary.
    ("python", rf"^[ \t]*class\s+(?P<name>{IDENT})"),
    ("ruby", rf"^[ \t]*class\s+(?P<name>{IDENT})"),
    ("php", rf"^[ \t]*(?:abstract\s+|final\s+)?class\s+(?P<name>{IDENT})"),
    ("typescript", rf"^[ \t]*(?:export\s+)?(?:declare\s+)?(?:abstract\s+)?class\s+(?P<name>{IDENT})"),
    ("javascript", rf"^[ \t]*(?:export\s+)?class\s+(?P<name>{IDENT})"),
    ("java", rf"(?:class|interface|enum|record)\s+(?P<name>{IDENT})"),
    ("csharp", rf"(?:class|interface|struct|record|enum)\s+(?P<name>{IDENT})"),
    ("cpp", rf"class\s+(?P<name>{IDENT})"),
    ("go", rf"type\s+(?P<name>{IDENT})\s+(?:struct|interface)\b"),
    ("rust", rf"(?:pub\s+)?(?:struct|enum|trait)\s+(?P<name>{IDENT})"),
    ("kotlin", rf"(?:class|object|interface)\s+(?P<name>{IDENT})"),
    ("swift", rf"(?:class|struct|protocol|enum|extension)\s+(?P<name>{IDENT})"),
    ("scala", rf"(?:class|trait|object)\s+(?P<name>{IDENT})"),
    ("dart", rf"(?:class|mixin|extension|enum)\s+(?P<name>{IDENT})"),
)

IMPORT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("python", r"^\s*import\s+([A-Za-z_][\w.,\s]*)"),
    ("python", r"^\s*from\s+([A-Za-z_][\w.]*)\s+import"),
    ("javascript", r"^\s*import\s+(?:[\w*{}\s,]+\s+from\s+)?['\"]([^'\"]+)['\"]"),
    ("javascript", r"^\s*export\s+.*?\s+from\s+['\"]([^'\"]+)['\"]"),
    ("javascript", r"require\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    ("javascript", r"import\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    # TypeScript keeps the JavaScript module syntax verbatim, but the lookup is
    # an exact language-name match, so without these entries every ``import``
    # in a ``.ts`` file was invisible: file-level dependencies, the relations
    # graph and architecture analysis all saw a repository of isolated files.
    ("typescript", r"^\s*import\s+(?:[\w*{}\s,]+\s+from\s+)?['\"]([^'\"]+)['\"]"),
    ("typescript", r"^\s*export\s+.*?\s+from\s+['\"]([^'\"]+)['\"]"),
    ("typescript", r"require\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    ("typescript", r"import\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    ("go", r"^\s*import\s+(?:\w+\s+)?\"([^\"]+)\""),
    ("go", r"^\s*(?:\"([^\"]+)\")"),
    ("rust", r"^\s*use\s+([A-Za-z_][\w:{}, *]*)"),
    ("rust", r"^\s*mod\s+(\w+)"),
    ("java", r"^\s*import\s+(?:static\s+)?([\w.*]+)\s*;"),
    ("csharp", r"^\s*using\s+(?:static\s+)?([\w.]+)\s*;"),
    ("php", r"^\s*(?:require|include)(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]"),
    ("ruby", r"^\s*require(?:_relative)?\s+['\"]([^'\"]+)['\"]"),
    ("shell", r"^\s*(?:source|\.)\s+['\"]?([^\s'\"]+)"),
)

CALL_RE = re.compile(rf"(?P<recv>{IDENT}(?:\.{IDENT})*)?\s*\.\s*(?P<name>{IDENT})\s*\(")
BARE_CALL_RE = re.compile(rf"(?<![\w.$])(?P<name>{IDENT})\s*\(")
CONTROL_WORDS = frozenset({
    # Words that open or close a block. None of these can be a call: the
    # parser sees ``if (x)`` and must not record a call to ``if``.
    "if", "elif", "else", "for", "while", "switch", "case", "catch", "return",
    "do", "then", "end", "match", "when",
    # Declarations and modifiers.
    "def", "fun", "fn", "class", "struct", "enum", "interface", "trait",
    "var", "let", "const", "public", "private", "protected", "static",
    # Operators that never take a call syntax.
    "new", "function", "typeof", "instanceof", "sizeof", "delete",
    "await", "yield", "throw", "raise", "assert", "lambda", "defer", "select",
    # Operators and connectors.
    "in", "is", "as", "with", "and", "or", "not", "andalso", "orelse",
    # Reserved for the language-word list below.
    "import", "from",
})

#: Words that are keywords in some registered language and can never be the
#: name of a call. They are a separate set from ``CONTROL_WORDS`` on purpose:
#: that one is call-oriented and deliberately omits language words, and this
#: one is a language word list. Without it ``async(async () => {})``,
#: ``super(...)`` and ``void(...)`` in TypeScript and JavaScript each become a
#: CallSite, fail resolution, and sit in the unresolved count forever as if
#: they were a library the analyzer could not find. On microsoft/playwright
#: that was 1,341 entries of 52,793 -- noise in a number a reader is meant to
#: trust. Nothing here is callable in any registered language.
LANGUAGE_KEYWORDS = frozenset({
    # The three this list exists for: ``async(async () => {})``,
    # ``super(...)`` and ``void(...)`` are not calls in any language.
    "async", "super", "void",
    # Words that are keywords somewhere and are essentially never a callable
    # name. Deliberately short. A first attempt copied the whole of
    # CONTROL_WORDS in here and dropped every call named ``go(``, ``set(``,
    # ``map(`` or ``filter(`` -- on microsoft/playwright ``super.go(...)`` is a
    # real call and this killed it. A word only belongs here if you cannot
    # imagine a method with that name.
    "this", "self", "cls", "null", "nil", "true", "false",
    "typeof", "instanceof", "in", "of", "new",
    "class", "struct", "enum", "interface", "trait", "impl", "mod",
    "extends", "implements",
    "import", "export", "from", "as", "is", "with", "and", "or", "not", "end",
    "package", "namespace", "internal", "abstract", "final", "sealed",
    "override", "virtual", "readonly", "static",
    "public", "private", "protected", "synchronized", "transient", "native",
})


def is_not_a_call(name: str) -> bool:
    """Whether ``name`` is a keyword rather than something the code called."""

    return name in CONTROL_WORDS or name in LANGUAGE_KEYWORDS


_ASSIGN_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<key>[A-Za-z_][\w.\-]{2,40})
    \s*[:=]\s*
    (?P<quote>["'])(?P<value>[^"'\n]{6,200})(?P=quote)
    """)


@dataclass
class ParsedModule:
    """Normalized parse output consumed by every analyzer."""

    path: str
    language: str
    support: SupportLevel
    lines: list[str] = field(default_factory=list)
    symbols: list[Symbol] = field(default_factory=list)
    imports: list[tuple[str, int, str]] = field(default_factory=list)  # (module, line, raw)
    calls: list[CallSite] = field(default_factory=list)
    comments: dict[int, str] = field(default_factory=dict)
    parse_error: str = ""
    dirty_lines: dict[int, str] = field(default_factory=dict)   # line -> sanitized line
    literals: dict[int, dict[str, str]] = field(default_factory=dict)  # line -> {name: value}

    @property
    def is_usable(self) -> bool:
        return bool(self.lines) and not self.parse_error

    def symbol_by_id(self) -> dict[str, Symbol]:
        return {s.id: s for s in self.symbols}

    def line(self, n: int) -> str:
        if 1 <= n <= len(self.lines):
            return self.lines[n - 1]
        return ""


def make_symbol_id(path: str, qualified_name: str) -> str:
    return f"{path}::{qualified_name}"


def strip_comments_and_strings(
    lines: list[str], comment_prefixes: tuple[str, ...], *, keep_literals: bool = False
) -> tuple[list[str], dict[int, str], dict[int, str]]:
    """Blank out comments and string bodies so structural scanning is not confused.

    Returns (sanitized_lines, comments_by_line, literal_by_line).
    """
    out: list[str] = []
    comments: dict[int, str] = {}
    literals: dict[int, str] = {}
    in_block = False
    for idx, raw in enumerate(lines, start=1):
        line = raw
        i = 0
        n = len(line)
        buf: list[str] = []
        while i < n:
            if in_block:
                if line.startswith("*/", i):
                    in_block = False
                    i += 2
                else:
                    i += 1
                continue
            if line.startswith("/*", i):
                in_block = True
                i += 2
                continue
            ch = line[i]
            if ch == "#" and "#" in comment_prefixes:
                rest = line[i:]
                if rest.startswith("#!") and idx == 1:
                    buf.append(ch)
                    i += 1
                    continue
                comments[idx] = rest.strip().strip("#").strip()
                break
            if ch == "/" and i + 1 < n and line[i + 1] == "/" and "//" in comment_prefixes:
                comments[idx] = line[i + 2 :].strip()
                break
            if ch in "\"'`":
                quote = ch
                j = i + 1
                while j < n:
                    if line[j] == "\\" and quote != "`":
                        j += 2
                        continue
                    if line[j] == quote:
                        j += 1
                        break
                    j += 1
                if keep_literals:
                    literals[idx] = line[i + 1 : max(i + 1, j - 1)]
                buf.append(quote + " " * max(0, j - i - 2) + (quote if j <= n and j - 1 < n else ""))
                i = j
                continue
            buf.append(ch)
            i += 1
        out.append("".join(buf))
    return out, comments, literals


def extract_calls(
    sanitized: list[str], path: str, scope_of_line
) -> list[CallSite]:
    """Extract call sites with the enclosing symbol resolved per line."""
    calls: list[CallSite] = []
    for idx, line in enumerate(sanitized, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        caller = scope_of_line(idx)
        seen: set[str] = set()
        for m in CALL_RE.finditer(line):
            name = m.group("name")
            recv = m.group("recv")
            if is_not_a_call(name):
                continue
            key = f"{recv}.{name}"
            if key in seen:
                continue
            seen.add(key)
            calls.append(CallSite(caller_id=caller, callee_name=key, file=path, line=idx))
        for m in BARE_CALL_RE.finditer(line):
            name = m.group("name")
            if is_not_a_call(name) or name in seen:
                continue
            seen.add(name)
            calls.append(CallSite(caller_id=caller, callee_name=name, file=path, line=idx))
    return calls


def module_qualifier(path: str) -> str:
    """Best-effort module qualifier for import resolution (strip extension)."""
    p = PurePosixPath(path)
    parts = list(p.parts)
    if parts and "." in parts[-1]:
        parts[-1] = parts[-1].rsplit(".", 1)[0]
    if parts and parts[-1] in {"__init__", "index", "mod"}:
        parts = parts[:-1]
    return "/".join(parts)


def is_test_path(relpath: str) -> bool:
    low = "/" + relpath.lower()
    base = relpath.rsplit("/", 1)[-1].lower()
    return any(
        seg in low
        for seg in ("/test/", "/tests/", "/spec/", "/specs/", "/__tests__/", "/testdata/", "/fixtures/")
    ) or base.startswith(("test_", "spec_")) or base.endswith(
        ("_test.go", "_test.py", ".test.ts", ".test.tsx", ".spec.ts", "_spec.rb")
    )


def extract_string_assignments(lines: list[str]) -> dict[int, dict[str, str]]:
    """Extract `NAME = "literal"` pairs per line (used by config/secret analyzers)."""
    out: dict[int, dict[str, str]] = {}
    for idx, line in enumerate(lines, start=1):
        for m in _ASSIGN_SECRET_RE.finditer(line):
            out.setdefault(idx, {})[m.group("key")] = m.group("value")
    return out
