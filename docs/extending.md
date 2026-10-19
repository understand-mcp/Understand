# Extending UNDERSTAND

Where to put new code, what a new analyzer must do, and which invariants you break if you ignore them.

Read [architecture.md](architecture.md) first. This document assumes you know where the layers are.

---

## The layering rule

```
cli.py  /  mcp/          interface      — parse arguments, format output, talk to models
        application/     use cases      — scan, findings, reports, traces, impact
        engine/          analysis       — parsing, graph, data flow, verification
        models/          shared types   — enums, records, validation
        security/        policy         — paths, network, redaction, sandbox
        storage/         persistence    — sqlite, migrations, cache
```

**Dependencies point downward only.** `engine/` must not import `application/`. `models/` imports nothing from the project. A new analyzer in `engine/analyzers/` may use `models/`, `security/` and other `engine/` modules — and nothing above.

If your change makes `engine/` import `application/`, the design is wrong; usually the logic belongs somewhere lower, or the boundary needs a small value type passed down instead.

---

## Adding a check

Checks live in `engine/analyzers/`. Each one is a class with a fixed shape.

```python
# engine/analyzers/my_new_analysis.py
from ..base import Analyzer, AnalysisContext
from ...models import Check, Finding, Severity

class MyNewAnalyzer(Analyzer):
    check = Check.MY_NEW          # add the enum member in models/ first
    rule_prefix = "MYNEW"

    def applies_to(self, ctx: AnalysisContext, symbol: Symbol) -> bool:
        # Cheap gate. Do the expensive work inside analyze().
        return symbol.language == "python"

    def analyze(self, ctx: AnalysisContext, symbol: Symbol) -> Iterable[Finding]:
        yield Finding(
            category=Check.MY_NEW.value,
            rule_id=f"{self.rule_prefix}-{symbol.name}",
            title="…",
            severity=Severity.LOW,
            confidence=Confidence.LOW,          # be honest; see below
            verification_status=VerificationStatus.INCONCLUSIVE,
            summary="…",
            technical_explanation="…",
            remediation="…",
            evidence=[Evidence(kind=EvidenceKind.SOURCE_RANGE, file=…, start_line=…,
                               snippet=…)],
            assumptions=["static analysis only"],
        )
```

Then register it in `engine/analyzers/registry.py`.

### The rules that matter

**1. A finding is a claim, so carry its evidence strength.**
`confidence` and `verification_status` are not decoration. They are the only thing that stops a downstream model from telling a human that a `low`/`inconclusive` static hint is a proven vulnerability. If you cannot honestly claim more than `STATIC_EVIDENCE`, do not claim it. The honesty clause in `README.md` makes misrepresenting your own output a documented violation of the project's terms of use.

**2. Never invent a location.**
If you have no file and line, omit the evidence entry entirely. A locationless finding is valid and is emitted without a SARIF location. A fabricated line number is not.

**3. Do not run code.**
No `exec`, no `subprocess`, no importing the analysed repository. There is an allowlisted `run_tool()` in `security/sandbox.py` for external analyzers, and it is the only sanctioned path to running anything.

**4. Stay inside the resource budget.**
Call `ctx.cancel.check()` in any loop that can be long. The orchestrator checks it at stage boundaries only; a single long stage must check internally or cancellation will not be observed until it ends.

**5. Redact every string that leaves.**
Evidence snippets go through `redact_snippet()`. The report renderers redact again on the way out, but a secret in memory is still a secret in a crash dump.

**6. Add the check to the CLI and MCP surfaces.**
`Check` members flow into `ScanRequest.checks`, the CLI feature tokens, and the MCP schema. A check that cannot be requested from both interfaces is a check nobody will run.

---

## Adding a language

Language support is a spec plus, where possible, a parser.

1. **`engine/language_detection.py`** — add a `LanguageSpec` with the extensions, comment syntax, line-comment and block-comment markers, and string delimiters. Add it to the ordered detection list; earlier entries win on ties.
2. **`engine/parsing.py`** — if a real parser is available, write one that builds a `Module` with `symbols`, `calls` and `imports`. If not, extend `parse_structural()`'s keyword patterns.
3. **`engine/analyzers/registry.py`** — map the language to the analyzers that support it, and record its limitations via `limitations_for()`.

**The structural parser is deliberately approximate.** It finds shapes, not semantics. Any check built on it must lower its `confidence` accordingly and say so in `limitations_for()`. A heuristic parser presented as an exact one is the single most damaging thing you can add to this project.

Two traps already paid for, worth knowing before you hit them again:

- **Read imports from the original text, never from sanitised text.** Sanitisation blanks string bodies, which is exactly where relative module specifiers live. `parse_structural()` keeps `raw_joined` alongside the sanitised text for this reason; keep doing the same. `relations.py` reads the *name* of a configuration key from `module.line(n)` for the same reason, while detecting the lookup itself on the sanitised line.
- **Unresolved calls stay unresolved.** `build_call_graph` records them as `UNRESOLVED` edges labelled by callee name. Do not drop them (invisible problems) and do not bind them to a same-named symbol (invented call graphs).
- **Never anchor a definition pattern with `^\s*`.** `\s` matches a newline, so a class preceded by a blank line matched starting *on the blank line* and every line number derived from it — the body range, the bases, the evidence — shifted by one. Use `^[ \t]*`.
- **Never list one definition in two pattern tables.** TypeScript `class` appeared in both `CLASS_PATTERNS` and `KEYWORD_FUNCTION_PATTERNS`; every TS class produced two symbols with the same id and the `function`-kinded one won, so all TS classes were mistyped as functions engine-wide.
- **Index the methods.** A TypeScript class whose methods were never extracted is a class with no body: no call sites, no attribute reads or writes, no data-flow. Method patterns must reject control keywords — `if (...) {` and `switch (...) {` match a naive method regex and become symbols named "if".

---

## Adding a relation

`engine/relations.py` is where a new relationship between symbols belongs, not
in the call graph. Each kind gets its own function returning `list[Edge]`, added
to `build_relations()`, with an entry in `RELATION_BUDGETS`.

The rule that matters is the one the module already exists to enforce: **the
`origin` you set is a claim about evidence, and it is checked.** `STATIC_DIRECT`
for facts from a real parser, `TYPE_RESOLVED` when the target is provably right,
`INFERRED` for every lexical heuristic, `UNRESOLVED` when nothing could be
bound. A relation that names its target from a pattern match alone is not
evidence, and the test suite will say so.

Add to `_TRACE_KINDS` in `graph_snapshot.py` only if a relation is genuinely an
execution step. Tracing `authenticate → check_password` through `AUTHORIZES`
presents an authorization claim as a call, which is a different and stronger
statement than the code supports.

---

## Adding a tool

Tools are MCP-facing; they must be worth a model's attention.

1. **`mcp/schemas.py`** — add a `Strict` input model. It rejects unknown fields, so a typo in a tool name is a client error rather than a silently ignored argument.
2. **`mcp/tools.py`** — add a `ToolBox` method. It takes keyword arguments, calls `schemas.validate(...)`, and is decorated `@envelope("<name>")`. That decorator is what turns any exception into the machine-readable error envelope; do not hand-roll try/except around the body.
3. **`mcp/server.py`** — add a nested, explicitly-typed function and register it with `add_tool`. **Write the type signature out.** The MCP SDK derives the tool's JSON schema from the signature; a `**payload` signature produces one useless `payload` argument.

   Pick annotations deliberately: read-only and idempotent tools get `_READ_ONLY`, anything that creates or mutates scan state gets `_MUTATING`. Clients use these to decide whether to ask the user.
4. **`docs/mcp-protocol.md` and the README tool table** — a tool nobody can find does not exist.

**Budget the response.** Every tool that returns a list should page it. `MAX_LIMIT` (500) caps a page; `MAX_TEXT_QUERY` (200) caps a search string. Nine tools already cost a client context window; a tenth that returns unbounded output costs more than it earns.

---

## Adding an output format

1. **`reporting/<format>.py`** — implement `render_*(report, ...) -> str` plus a `*_dict()` for structured callers.
2. **`reporting/__init__.py`** — register the format in the format table used by `safe_output_path()`, and extend the extension→format mapping.
3. **`cli.py`** — add it to the `--format` choices and the `UnsupportedFormatError` path.
4. **Validate against the real specification, not against yourself.** `tools/validate_sarif.py` exists because reading a SARIF document and checking it looks right is not validation; it caught a real spec violation that every structural check had passed. Do the same for any new format: get the official schema, validate a real report, and keep the validator.

Redaction is not optional in a new format. It is applied by the renderers, not by the callers, and a new renderer that forgets will ship secrets into CI artefacts.

---

## Changing storage

Bump `SCHEMA_VERSION` in `storage/migrations.py` and add a migration entry. Do not edit an existing migration: a database already in the field has applied it.

`apply()` refuses to open a database whose stored version is **newer** than the code expects, which is the correct behaviour — it means a downgraded binary fails loudly instead of corrupting data.

Storage invariants worth preserving:

- `save_report()` calls `ensure_id()` on every finding **before** serialising. Without it, generated finding ids are lost on round-trip and SARIF fingerprints change between runs.
- "Row exists but has no report" (`ScanNotFound`) is distinct from "row does not exist" — a scan that has started but has not finished must read differently from one that never existed.

---

## Changing configuration

Add the field to the frozen dataclass, then read it in `load_config()` **from both** the config file and an `UNDERSTAND_`-prefixed env var.

That last part is not optional. Three defects in this codebase existed because a field was declared and enforced but never read by `load_config`: `max_clone_bytes` was enforced with a hard-coded value that no configuration could change, and `clone_timeout_seconds` had two different defaults depending on which constructor ran. A field that nothing reads is worse than no field, because it documents a capability that does not exist.

If a setting must not be changeable — git hooks, executing repository code — **do not add a field for it**. An inert switch that reads as configurable is a lie in the configuration surface.

---

## Tests

Layout mirrors the package:

```
tests/unit/          one file per module
tests/security/      the security controls
tests/integration/   the pipeline, the CLI, the MCP server
tests/fixtures/      tiny repositories with known properties
```

Rules that keep the suite trustworthy:

- **A fixture repository must have a property you can assert.** `repo_shell_risk` exists so "there is a shell-injection finding at `app/api.py`" is a testable claim, not a hope.
- **Never write a test that asserts what the code happens to do.** Several tests in this repository were written before the code existed and encoded assumptions; most failures since have been tests asserting an API shape that did not exist. When a test fails, decide explicitly which side is wrong, and say why in the commit.
- **Do not weaken a test to make it pass.** Accepting a broader exception type is legitimate when two classes are both honest answers (`pytest.raises((AccessDeniedError, ValidationError))` for a path escape). Deleting an assertion is not.
- **Coverage claims need a run.** `python -m pytest -q` is the gate.

---

## Style

- `ruff check src tests` — line length 110, `E,F,W,I,UP,B,C4,SIM,RUF`.
- Type annotations on public functions.
- Docstrings that say *why*, not *what*. `# increment i` is noise; `# keep i stable so the sort key does not change` is the reason the sort key exists.
- No comments restating the next line of code.
- No `print()` anywhere in `src/`. stdout is the MCP stdio protocol stream. Use the logger, which writes to stderr.

---

## Related

- [architecture.md](architecture.md) — layers, pipeline, invariants
- [security-model.md](security-model.md) — what you may not break
- [mcp-protocol.md](mcp-protocol.md) — tool contract and envelopes
- [roadmap.md](roadmap.md) — what is planned next