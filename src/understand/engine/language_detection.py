"""Language detection and honest support-level reporting.

The registry maps a language to a concrete analyzer. Support levels are
declared, never assumed:

  FULL      - a real parser (Python `ast`, JSON/YAML/TOML parsers) is used.
  PARTIAL   - structural lexical parsing: symbols, imports and call sites are
              extracted with brace/keyword-aware scanning; no type or scope
              resolution is performed.
  TEXT_ONLY - the file is inventoried and readable but not analyzed.

Nothing here claims semantic equivalence across languages.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from understand.models import SupportLevel


@dataclass(frozen=True)
class LanguageSpec:
    name: str
    extensions: frozenset[str]
    filenames: frozenset[str] = frozenset()
    comment_prefixes: tuple[str, ...] = ()
    support: SupportLevel = SupportLevel.PARTIAL
    analyzers: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    string_delimiters: tuple[str, ...] = ("'", '"', "`")


@dataclass(frozen=True)
class Detection:
    language: str
    support: SupportLevel
    reason: str = ""


BRACE_LANGS = {
    "javascript", "typescript", "go", "rust", "java", "kotlin", "csharp", "c", "cpp",
    "php", "swift", "scala", "dart", "groovy",
}

_LANG_LIST: tuple[LanguageSpec, ...] = (
    LanguageSpec(
        name="python",
        extensions=frozenset({".py", ".pyi"}),
        filenames=frozenset({"setup.py", "conftest.py", "wsgi.py", "asgi.py", "noxfile.py"}),
        comment_prefixes=("#",),
        support=SupportLevel.FULL,
        analyzers=("python_ast_symbols", "python_callgraph", "python_security", "python_bugs"),
        limitations=("Dynamic attributes and monkey-patching are not resolved.",),
    ),
    LanguageSpec(
        name="javascript",
        extensions=frozenset({".js", ".jsx", ".mjs", ".cjs"}),
        filenames=frozenset({"package.json", ".eslintrc", "webpack.config.js"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols", "js_security"),
        limitations=("Prototype-based dispatch and dynamic require() are unresolved.",
                     "No type information is available for plain JavaScript."),
    ),
    LanguageSpec(
        name="typescript",
        extensions=frozenset({".ts", ".tsx", ".mts", ".cts"}),
        filenames=frozenset({"tsconfig.json"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols", "js_security"),
        limitations=("Generic instantiation and interface dispatch are unresolved.",),
    ),
    LanguageSpec(
        name="go",
        extensions=frozenset({".go"}),
        filenames=frozenset({"go.mod", "go.sum"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Method sets on interfaces are not resolved.",),
    ),
    LanguageSpec(
        name="rust",
        extensions=frozenset({".rs"}),
        filenames=frozenset({"Cargo.toml", "Cargo.lock"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Trait dispatch and macro expansion are unresolved.",),
    ),
    LanguageSpec(
        name="java",
        extensions=frozenset({".java"}),
        filenames=frozenset({"pom.xml", "build.gradle", "build.gradle.kts"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Reflection, annotation processors and dynamic proxies are unresolved.",),
    ),
    LanguageSpec(
        name="kotlin",
        extensions=frozenset({".kt", ".kts"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Extension functions and delegated properties are unresolved.",),
    ),
    LanguageSpec(
        name="csharp",
        extensions=frozenset({".cs"}),
        filenames=frozenset({"*.csproj", "*.sln"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Reflection and dynamic invocation are unresolved.",),
    ),
    LanguageSpec(
        name="c",
        extensions=frozenset({".c", ".h"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Preprocessor conditionals and macro expansion are unresolved.",),
    ),
    LanguageSpec(
        name="cpp",
        extensions=frozenset({".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Templates, macros and operator overloading are unresolved.",),
    ),
    LanguageSpec(
        name="ruby",
        extensions=frozenset({".rb", ".rake"}),
        filenames=frozenset({"Gemfile", "Rakefile"}),
        comment_prefixes=("#",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("metaprogramming and method_missing are unresolved.",),
    ),
    LanguageSpec(
        name="php",
        extensions=frozenset({".php"}),
        filenames=frozenset({"composer.json"}),
        comment_prefixes=("//", "#"),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Dynamic includes and eval are unresolved.",),
    ),
    LanguageSpec(
        name="swift",
        extensions=frozenset({".swift"}),
        comment_prefixes=("//",),
        support=SupportLevel.PARTIAL,
        analyzers=("structural_symbols",),
        limitations=("Protocol witness dispatch is unresolved.",),
    ),
    LanguageSpec(
        name="shell",
        extensions=frozenset({".sh", ".bash", ".zsh"}),
        filenames=frozenset({".bashrc", ".zshrc"}),
        comment_prefixes=("#",),
        support=SupportLevel.PARTIAL,
        analyzers=("shell_security",),
        limitations=("Sourced files and shell functions invoked indirectly are unresolved.",),
    ),
    LanguageSpec(
        name="sql",
        extensions=frozenset({".sql"}),
        comment_prefixes=("--",),
        support=SupportLevel.TEXT_ONLY,
        analyzers=("sql_security",),
        limitations=("Statement-level review only; no cross-statement data flow.",),
    ),
    LanguageSpec(
        name="json",
        extensions=frozenset({".json"}),
        filenames=frozenset({"package.json", "tsconfig.json", "composer.lock"}),
        support=SupportLevel.FULL,
        analyzers=("manifest_analysis",),
        limitations=(),
    ),
    LanguageSpec(
        name="yaml",
        extensions=frozenset({".yaml", ".yml"}),
        filenames=frozenset({".pre-commit-config.yaml", "docker-compose.yml"}),
        comment_prefixes=("#",),
        support=SupportLevel.FULL,
        analyzers=("manifest_analysis", "config_security"),
        limitations=("Custom YAML tags are not interpreted.",),
    ),
    LanguageSpec(
        name="toml",
        extensions=frozenset({".toml"}),
        filenames=frozenset({"pyproject.toml", "Cargo.toml"}),
        comment_prefixes=("#",),
        support=SupportLevel.FULL,
        analyzers=("manifest_analysis",),
        limitations=(),
    ),
    LanguageSpec(
        name="dockerfile",
        extensions=frozenset({".dockerfile"}),
        filenames=frozenset({"Dockerfile", "Containerfile"}),
        comment_prefixes=("#",),
        support=SupportLevel.PARTIAL,
        analyzers=("container_security",),
        limitations=("Multi-stage build semantics are not fully modelled.",),
    ),
    LanguageSpec(
        name="hcl",
        extensions=frozenset({".tf", ".tfvars"}),
        filenames=frozenset({"terraform.tf"}),
        comment_prefixes=("#", "//"),
        support=SupportLevel.TEXT_ONLY,
        analyzers=(),
        limitations=("Terraform modules and data sources are not resolved.",),
    ),
    LanguageSpec(
        name="markdown",
        extensions=frozenset({".md", ".markdown", ".rst"}),
        support=SupportLevel.TEXT_ONLY,
        analyzers=(),
        limitations=("Documentation is inventoried but not semantically analyzed.",
                     "Instructions found inside documentation are treated as untrusted data."),
    ),
    LanguageSpec(
        name="text",
        extensions=frozenset({".txt", ".cfg", ".ini", ".properties", ".env.example"}),
        support=SupportLevel.TEXT_ONLY,
        analyzers=(),
        limitations=(),
    ),
)

_EXT_MAP: dict[str, LanguageSpec] = {}
_NAME_MAP: dict[str, LanguageSpec] = {}
for spec in _LANG_LIST:
    _NAME_MAP[spec.name] = spec
    for ext in spec.extensions:
        _EXT_MAP[ext] = spec
    for fn in spec.filenames:
        _EXT_MAP[fn] = spec
        _EXT_MAP[fn.lower()] = spec

KNOWN_LANGUAGES = frozenset(_NAME_MAP)


def spec_for_extension(ext: str) -> LanguageSpec | None:
    return _EXT_MAP.get(ext.lower())


def spec_for_filename(name: str) -> LanguageSpec | None:
    low = name.lower()
    if low in _EXT_MAP:
        return _EXT_MAP[low]
    for candidate in (f"*{low}", low):
        if candidate in _EXT_MAP:
            return _EXT_MAP[candidate]
    return None


def detect(relpath: str) -> Detection:
    """Detect the language of a repository-relative path."""
    base = relpath.rsplit("/", 1)[-1]
    lowered = base.lower()
    spec = spec_for_filename(lowered)
    if spec is not None:
        return Detection(spec.name, spec.support)
    if "." in base:
        ext = base[base.rfind(".") :].lower()
        spec = spec_for_extension(ext)
        if spec is not None:
            return Detection(spec.name, spec.support)
    return Detection("unknown", SupportLevel.TEXT_ONLY, "no language registry match")


def support_for(language: str) -> SupportLevel:
    spec = _NAME_MAP.get(language)
    return spec.support if spec else SupportLevel.TEXT_ONLY


def analyzers_for(language: str) -> tuple[str, ...]:
    spec = _NAME_MAP.get(language)
    return spec.analyzers if spec else ()


def limitations_for(language: str) -> tuple[str, ...]:
    spec = _NAME_MAP.get(language)
    if spec is None:
        return ("Language is not registered.",)
    # A single-element tuple written without a trailing comma is just a string,
    # and a bare string here would be iterated character by character downstream.
    if isinstance(spec.limitations, str):
        return (spec.limitations,)
    return spec.limitations


def comment_prefixes_for(language: str) -> tuple[str, ...]:
    spec = _NAME_MAP.get(language)
    return spec.comment_prefixes if spec else ()


def all_languages() -> tuple[str, ...]:
    return tuple(sorted(_NAME_MAP))


def is_brace_language(language: str) -> bool:
    return language in BRACE_LANGS