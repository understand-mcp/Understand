# Roadmap

What is done, what is missing, and what is deliberately not planned. Nothing here is a promise.

This document is a snapshot of the project's real state. Where it disagrees with the code, **the code is the defect** — see [README.md](README.md) in `docs/` for that convention.

---

## Shipped (0.1.0)

| Area | State |
|---|---|
| Analysis pipeline | 11 stages, `validate_request` → `finalize` |
| Checks | `security`, `bugs`, `architecture`, `dependencies`, `reliability` |
| Language coverage | Python (exact `ast`), JS/TS and others (structural, honestly labelled) |
| Graph | Symbols, call edges, imports, data flow, unresolved-call tracking |
| Findings | Severity, confidence, verification status, fingerprints, stable ids |
| Reporting | `text`, `json`, `sarif` (SARIF validated against the OASIS schema) |
| Storage | SQLite, migrations v1–v4, content-addressed scan cache |
| Security controls | Path containment, exclusion policy, SSRF defence, sandbox, redaction |
| Interfaces | CLI (7 commands, sysexits exit codes) and MCP server (9 tools, 2 resources) |
| Transport | stdio, streamable-http, SSE |
| Packaging | PyPI-installable, two console scripts, multi-stage Dockerfile |
| Tests | 268 passing |
| Docs | 11 documents in `docs/` |

---

## Blocking before publication

These are the gaps between "works on my machine" and "someone else can install it".

### 1. Fill in the donation addresses

`LICENSE` is MIT and needs no contact block. `README.md` does contain placeholder addresses
in the **Support this project** section (`bc1qREPLACE…`, `0xREPLACE…`, `REPLACE_WITH_YOUR_SOLANA_ADDRESS`).
Crypto transfers are irreversible, so a placeholder must never survive publication — either
replace them with real addresses or delete the section.

### 2. CHANGELOG

No changelog exists. For 0.1.0 it is a single entry, but the file should exist before the first tag so the convention is established.

### 3. CI

No GitHub Actions workflow. The minimum:

```yaml
# .github/workflows/ci.yml
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix: { os: [ubuntu-latest, macos-latest, windows-latest], python: ["3.10", "3.11", "3.12", "3.13"] }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "${{ matrix.python }}" }
      - run: pip install -e . pytest
      - run: python -m pytest -q
      - run: pip install jsonschema && python tools/validate_sarif.py
```

The matrix is the point. The project claims Linux, macOS and Windows support and this is what would prove it; today that claim rests on reasoning, not on a test run. Windows is the platform most likely to break — path handling, `os.devnull`, case folding and drive letters are exactly where a POSIX-developed tool goes wrong.

### 4. Verify the published artefact

Build the wheel, install it into a clean virtualenv, and confirm `understand --version` and `understand-mcp-server` both work from `PATH`. Everything so far has been run from the source tree with `src` on `sys.path`.

---

## High value

### An exact parser for TypeScript and JavaScript — delivered

Delivered. `parse_module()` already dispatched on language, so the change stayed inside the parser: TypeScript and JavaScript go to the `tree-sitter` grammars from the `ts` extra, and fall back to the lexical parser when those wheels are absent.

What remains is symbol resolution: call targets are still matched by name, so the call graph — not the parse — is now where low-confidence JS/TS findings come from.

### Precise data flow

Data flow is currently derived from call structure plus statically matched source/sink patterns. A proper taint analysis (source → propagation through assignments, calls, containers → sink) would make `trace_data_flow` answer the question developers actually ask: *can untrusted input reach this sink, and through which chain?*

### Better architecture analysis

Layering, coupling and cycles are detected heuristically from imports. Cycle detection in particular is exact and cheap; dependency-direction violations would benefit from explicit module metadata.

### Incremental rescans

The cache is keyed on a whole-repository digest, so any change invalidates the whole scan. Per-file digests with symbol-level reuse would make "scan after my edit" near-instant on large repositories. `scan_cache` already has the schema for it (`stages` table).

### Interactive code maps

The relation vocabulary is complete — all twenty kinds are produced — but today it can only be read as JSON. A rendered map is the missing surface between the graph and a person, and it is the only realistic way to look at 285,000 edges. Designed in detail, including the four open decisions that have to be made before Phase 1 starts: [interactive-map.md](interactive-map.md).

---

## Medium value

| Item | Why |
|---|---|
| SARIF `automationDetails` + baseline support | Lets a scan be compared against the previous run instead of re-reported |
| Cyclomatic complexity / metrics per symbol | Cheap, and reviewers ask for it constantly |
| Test coverage reporting | Only worthwhile once CI exists to enforce it |
| GitHub Action wrapper | One-line `uses:` for adopters who do not want a Python dependency |
| More language specs | Go, Java, Rust, C# — each is a `LanguageSpec` plus a parser decision |

---

## Deliberately not planned

These are refusals, not omissions.

**Executing analysed repository code.** There is an `execute_repo_code` configuration switch so a hosted deployment can *assert* it is off. It is never read by anything, because there is no code path that honours it. A tool that reads untrusted repositories must not run them.

**Enabling git hooks.** Git is always invoked with `core.hooksPath` pointed at the null device and `protocol.*.allow=never`. A `respect_git_hooks` field existed and was deleted: an inert switch in a security surface is worse than no switch.

**A `--allowed-host` flag.** Remote hosts come from configuration only, so a scan cannot widen its own network permissions at the call site. Adding the flag would remove that property.

**A GUI.** The interfaces are a CLI and MCP, and both are reachable from any editor, terminal or agent. A GUI would be a fourth way to reach the same services, and it would not be the one people use.

**Silently dropping low-confidence findings.** A `low`/`inconclusive` finding is reported as exactly that. Filtering it out would make the tool feel cleaner and lie more.

---

## Honest limitations

What the tool cannot do, stated plainly because a user who knows the edges uses it better:

- **It does not prove exploitability.** A finding is a static observation plus evidence. `verification_status: reproduced` means the analysis cross-checked it, not that it was executed.
- **Structural parsing is approximate** for every language without an exact parser.
- **Dynamic dispatch is not invented.** Unresolved calls stay unresolved and are counted.
- **Dependency analysis is inventory, not vulnerability scanning.** It reads manifests and reports what is declared. It does not consult an advisory database and says so in the report (`not_performed`) rather than implying a clean bill of health.
- **Absence of findings is not absence of defects.** Every report carries this in its Limitations section.
- **Cross-module reasoning is import-graph reasoning.** It follows imports and named calls. It does not follow reflection, dependency injection, dynamic `getattr`, or runtime plugin registration.

---

## Related

- [architecture.md](architecture.md) — how the system is built
- [extending.md](extending.md) — how to add to it
- [security-model.md](security-model.md) — what must not be broken