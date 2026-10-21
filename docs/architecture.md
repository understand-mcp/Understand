# Architecture

This document explains what actually happens when you run a scan, and why the
pipeline is shaped the way it is. For the tool and CLI surfaces, see
[mcp-protocol.md](mcp-protocol.md) and [cli.md](cli.md).

## The central design constraint

Two interfaces exist: a CLI and an MCP server. They are **thin**. Every
capability lives in `application/` and every decision about *how to analyse* lives
in `engine/`. The interfaces differ only in how they present results and whether
they wait.

```
understand scan ...          understand.mcp_server
  understand.cli                    │
        │                           │
        └──────────────┬────────────┘
                       ▼
         application/scan_service.py     ← jobs, cache, storage, validation
                       │
                       ▼
          engine/orchestrator.py         ← the pipeline itself
                       │
    ┌──────────┬───────┼────────┬──────────────┬─────────────┐
    ▼          ▼       ▼        ▼              ▼             ▼
 acquire   inventory  parse   call graph   data flow   checks (analyzers)
    │          │       │        │              │             │
    └──────────┴───────┴────────┴──────────────┴─────────────┘
                       │
                       ▼
         models/ + reporting/ + storage/
```

The consequence: a bug in the engine is a bug for both interfaces, and a new
transport never needs engine work. The consequence the other way: **the CLI can
never be more capable than MCP**, because it is the same services. That is the
point.

## The stages

`ScanOrchestrator.run()` executes these in order. Each is wrapped in a stage
context that records start/end time, status and detail, so a report always
states which stages actually ran.

| # | Stage | What it does | On failure |
|---|---|---|---|
| 1 | `validate_request` | Request shape and policy preconditions. | Fails the scan. |
| 2 | `acquire_source` | Resolve the source to a real directory. Remote sources are shallow-cloned into a temp dir. | Fails the scan. |
| 3 | `inventory` | Walk the tree under the exclusion policy, read the files that pass, classify binary/text and language. | Fails the scan. |
| 4 | `language_detection` | Resolve an analysis language per file. | Fails the scan. |
| 5 | `parse_and_index` | Parse to a symbol index: functions, classes, methods, calls, imports. Files that cannot be parsed fall back to structural (regex) parsing and are reported as a warning. | A file that cannot be parsed is a warning; an unexpected error fails the scan. |
| 6 | `graph_construction` | Resolve call targets and imports into a directed graph. Unresolved targets are kept as explicitly-labelled edges, never dropped. | Fails the scan. |
| 7 | `dependency_analysis` | Read the dependency manifests the repository ships. | Fails the scan. |
| 8 | `security_analysis` | Run the security rule family: the pattern rules and the source-to-sink rules. Skipped when the check was not requested. | A failing analyzer is a warning; the other analyzers still run. |
| 9 | `bug_analysis` | Run the defect rule family. Skipped when the check was not requested. | A failing analyzer is a warning; the other analyzers still run. |
| 10 | `reliability_analysis` | Run the reliability rule family. Skipped when the check was not requested. | A failing analyzer is a warning; the other analyzers still run. |
| 11 | `architecture_analysis` | Run the architecture rule family: coupling, layering, cycles. Skipped when the check was not requested. | A failing analyzer is a warning; the other analyzers still run. |
| 12 | `cross_module_analysis` | Derive source-to-sink paths where the analyzers can prove them. Skipped unless `--cross-module` or the deep profile is used. | Fails the scan. |
| 13 | `dependency_status` | Attach vulnerability status to the dependencies. Always skipped: no trusted advisory source is configured, so CVE and CVSS values are never invented. | Never runs. |
| 14 | `normalize_findings` | Deduplicate, sort and cap the findings. | Fails the scan. |
| 15 | `coverage` | Compute what was analysed, what was skipped and what the limitations are. | Fails the scan. |
| 16 | `cleanup` | Release the workspace and the temporary clone. | Always runs, even after a failure. |

Stage 12 executes before stages 8 to 11: the flow analysis feeds the security
analyzer. The stage list keeps the declared order above so a report always reads
the same way.

### How a failure is reported

Three outcomes, and they are not the same thing.

- **`failed`** — the scan raised an unexpected exception. Any stage can do this:
  if `graph_construction` or `coverage` throws, the whole scan fails, because a
  report that claims to describe a repository it could not fully describe would
  be a lie. The reason lands in `report.errors` with a machine-readable `code`
  (`analysis_error`, or the code of the `UnderstandError` that was raised).
- **`partial`** — the wall-clock budget ran out. `ResourceLimitExceeded` at a
  stage checkpoint ends the scan early, `report.status` is `partial` and
  `report.partial` is true. The findings produced up to that point are kept.
- **`completed` with warnings** — an individual analyzer raised, or a file could
  not be parsed. The analyzer registry catches the exception per analyzer and
  records it as a `ScanWarning` in `report.warnings`. The scan continues, every
  other analyzer still contributes, and the status stays `completed`.

So an analyzer edge case never costs you the other findings, and a budget
overrun is labelled partial, in the CLI output, in the JSON payload, in the
SARIF `invocation.executionSuccessful`, and in the limitations list. It is never
presented as complete.

## Cancellation and budgets

Two independent mechanisms stop a scan:

- **Cancellation** — a `CancellationToken` is checked at every stage boundary.
  SIGINT in the CLI, or `cancel_scan` over MCP, sets the token; the scan stops at
  the next checkpoint and finishes as `cancelled`.
- **Resource budgets** — `request.limits` bounds the work: file count, per-file
  bytes, total bytes, symbol count, and **wall-clock seconds**. The deadline is
  checked at the same checkpoints, so an over-budget scan stops instead of
  running forever. When the budget is spent the report is `partial` and
  `run_sync` raises `ResourceLimitExceeded` to a blocking caller.

Both surface in the report, because "we stopped early" is information the reader
needs.

## The symbol index

`engine/symbol_index.py` is the backbone. For each file it produces a module
record:

- `symbols` — functions, classes, methods, with kind, signature and line span.
- `calls` — call sites with the callee *name* and the scope they appear in.
- `imports` — module specifiers with the line they appear on.
- `comments` — retained deliberately, keyed by line, so reports can explain *why*
  a line matters.

Parsing is two-tier:

- `parse_python` uses the `ast` module. It is exact.
- `parse_structural` uses per-language patterns. It is approximate.

When `ast` fails, the file is re-parsed structurally and the report says so
(`files_failed` in coverage, plus a limitations line). The alternative — silently
dropping unparseable files — would make coverage a lie.

Note one subtlety that is easy to get wrong: **imports are read from the original
text, not from the sanitized text**. Sanitization blanks string bodies, and
string bodies are exactly where relative module specifiers live. Reading imports
from sanitized text silently loses every JavaScript import.

## The call graph

`build_call_graph(index)` resolves each call site to a symbol id using scope
rules (same file, same module, imported symbol, project-wide unique name).

Resolution fails often — dynamic dispatch, decorators, metaprogramming, factory
patterns. The graph therefore keeps unresolved calls as **first-class edges**
with `origin=UNRESOLVED`, labelling them by callee name rather than inventing an
id. They are counted in `coverage.unresolved_calls` and named in the limitations.

A dropped unresolved call would silently understate the blast radius of a change.
A fabricated id would make the graph wrong in a way nobody could detect. Both are
worse than an honest label.

## Relations

`engine/relations.py` answers the question the call graph cannot: not *who calls
whom* but *how everything else connects*. It produces the fourteen semantic
kinds `EdgeKind` declares — inheritance, attribute reads and writes,
validation, authorization, egress, registration, event handling, resource
lifetime, transformation, test coverage and configuration influence.

Two rules govern it.

**Origin is a claim, not a label.** `STATIC_DIRECT` is used only where Python's
`ast` made the fact (a class's base list). `TYPE_RESOLVED` means a name matched a
symbol that is provably the target. Everything lexical is `INFERRED`. When a
target cannot be bound at all the edge records the intent against the bare name
with `origin=UNRESOLVED` — the same honesty rule the call graph follows. A static
analyser has no `RUNTIME` evidence, and `tests/unit/test_relations.py` asserts
that no relation ever claims otherwise.

**Obligations need a trustworthy target.** A `VALIDATES` edge asserts more than
"these two names are related", so it is only emitted when the underlying call was
resolved directly, through an import, or to a symbol in the caller's own file.
On microsoft/playwright a bare `parse(` in a Playwright file resolved to the
single `parse` inside a vendored Vue bundle; without that restriction the file
was reported as validating through Vue.

Every kind is capped. `RELATION_BUDGETS` bounds each one, and the projection in
`graph_snapshot.py` allocates the edge budget proportionally per kind with a
floor. Filling the budget in insertion order let 120,000 `calls` edges consume
all of it on a large repository and dropped every relation — the graph would have
been larger *and* less informative than before this module existed.

## Storage

`storage/scan_store.py` is a SQLite store with a versioned migration chain
(`storage/migrations.py`, currently at `SCHEMA_VERSION = 4`):

| Version | Adds |
|---|---|
| 1 | `schema_info`, `scans` and their indexes |
| 2 | `findings` and three indexes (rule, severity, scan) |
| 3 | `stages`, `scan_cache` |
| 4 | `idx_findings_file`, `meta` |

Design points that matter:

- `apply()` refuses to open a database written by a *newer* version rather than
  guessing. A downgrade must not corrupt data.
- Reports are stored as JSON alongside denormalized finding rows. The rows make
  filtering and pagination fast; the JSON makes the round-trip lossless.
- `save_report()` calls `ensure_id()` on every finding **before** serialization,
  so a finding's generated id survives a round-trip.
- A scan that exists but has no report yet is distinguishable from a scan that
  does not exist: the former raises `ScanNotFound` on `load_report`, the latter
  on `create_scan`-time lookup. Conflating them produces misleading errors.

## The cache

Cache keys are two digests: the repository content (`root_digest`) and the
request shape (`request_digest`). Both must match for a hit.

`digest_repository()` hashes file contents **under the same exclusion policy the
scan uses**. This is not a detail: if the digest included files the analysis
ignores, then adding a `.gitignore`d file would invalidate every cache entry for
no reason, and the cache would appear broken for reasons unrelated to the code.

The digest is bounded in two ways — a per-file content-hash limit and a total
file-count limit — so hashing a very large repository cannot itself become the
resource exhaustion.

## Concurrency

`ScanService` runs jobs on a `ThreadPoolExecutor` and keeps an in-memory job
registry.

- Jobs are pruned when they exceed a keep-alive bound, oldest first.
- A scan left `running` by a crashed process is marked `failed` on the next
  startup. Without this, a client polling a scan id from a previous run would
  wait forever for a job that can never progress.
- A job's status is derived from the **report**, not from whether the engine
  raised. The orchestrator records failures on the report rather than raising, so
  `_execute` reads `report.status` to decide whether to report success. Failing
  to do this is how a missing source directory ends up reported as a successful
  scan.

## Where to look when something looks wrong

| Symptom | Look first |
|---|---|
| A file was not analysed | `engine/repository_inventory.py`, then `security/repository_policy.py` |
| A finding is missing | `engine/analyzers/registry.py` — was the check even requested? |
| The call graph is wrong | `engine/call_graph.py`, then `engine/symbol_index.py` |
| A relation is wrong or missing | `engine/relations.py`; check the edge's `origin` before trusting it |
| Coverage numbers look odd | `engine/coverage.py` |
| Results differ between CLI and MCP | they should not — both call `application/scan_service.py` |
| A report will not render | `reporting/`, then the report model in `models/` |