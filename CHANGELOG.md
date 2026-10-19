# Changelog

All notable changes to UNDERSTAND are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — first release

UNDERSTAND is a repository-intelligence engine with two interfaces over one
analysis core: a CLI and an MCP server. It reads a repository, builds a symbol
graph with twenty kinds of relation, and reports findings with an explicit
statement of how strong the evidence is for each one.

### Added

**Interfaces**
- `understand` CLI: `scan`, `report show`, `report list`, `finding show`,
  `map show`, `map views`, `map explain`, `config show`, `capabilities`,
  `version`.
- `understand-mcp-server` and `python -m understand.mcp_server [stdio|streamable-http|sse]`.
- Ten MCP tools over one shared service, and three resources
  (`understand://capabilities`, `understand://security-model`,
  `understand://map-schema`).

**Analysis**
- Eleven pipeline stages; only the first three can fail a scan outright, so a
  later failure produces a `partial` report with a coded warning instead of
  silently reporting less work as complete.
- Five checks: security, bugs, architecture, dependencies, reliability.
- Six `verification_status` values, and a findings model that states what the
  evidence does *not* prove.

**Code maps**
- Ten map views: `module`, `call`, `inheritance`, `dependency`, `test`,
  `event`, `obligation`, `influence`, `data_flow`, `finding`.
- Single-file interactive HTML: anchored zoom, pointer-event pan, a minimap,
  viewport culling, level-of-detail rendering, and a renderer that measures its
  own frames and thins detail to hold the frame rate — so it needs no particular
  GPU and runs on a machine with no graphics card.
- Clicking any node shows its real source, every finding that landed on it in
  full, and a dedicated "what this analysis did not prove" block.
- `understand map explain <finding_id>` prints the causal chain as prose — what
  the source is, what the sink is, what must be true for it to matter, and what
  was not proven — and ends with the command that draws the path it described.

**Output**
- `text`, `json` and `sarif` (validated against the OASIS SARIF 2.1.0 schema by
  `tools/validate_sarif.py`).

**Security**
- The analysed repository is treated as untrusted data. No tool executes
  repository code, runs shell commands, or reads paths outside the configured
  roots; remote acquisition carries an SSRF denylist, DNS re-resolved before
  cloning, credential stripping, and git invoked with hooks disabled.

**Operational**
- SQLite store with migrations v1–v4, content-digest caching, sysexits-aligned
  exit codes, a two-stage unprivileged Docker image, and a container HEALTHCHECK
  that does not report a stdio deployment unhealthy.

### Known limitations

These are stated here rather than discovered later. All of them are visible in
the report a scan produces.

- **Unresolved call targets.** On microsoft/playwright, 52,793 call targets
  could not be bound to a definition. Most are the standard library, third-party
  packages and runtime-chosen names; static analysis cannot resolve them
  without full module and type resolution, so this number cannot reach zero.
- **TypeScript and JavaScript parsing is lexical**, not syntactic. Python is
  parsed with `ast` and is exact. Expect a higher false-positive rate on
  TypeScript and verify any finding before acting on it.
- **Dependency analysis is inventory, not vulnerability scanning.** It reports
  `not_performed` rather than implying a clean bill of health.
- **Findings are heuristic.** A finding is a static result. `confidence` and
  `verification_status` describe evidence strength, not exploitability.
- **Cross-module reasoning is import-graph reasoning.** It does not follow
  reflection, dependency injection, `getattr` or plugin loading.
- **Maps are a bounded projection.** A snapshot holds at most 60,000 nodes and
  120,000 edges, and the node/edge budgets remove what does not fit. Every
  removal is counted and reported.

[0.1.0]: https://github.com/understand-mcp/understand/releases/tag/v0.1.0
