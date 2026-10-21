# Changelog

All notable changes to UNDERSTAND are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - provider-neutral distribution

### Removed

- Publishing to Smithery. `smithery.yaml` and `docs/smithery.md` are gone, and
  the docs no longer name a directory.

### Added

- `deploy/`: a self-hosting recipe - the server container behind Caddy, with TLS
  and HTTP basic authentication, a persistent scan database, and the budgets the
  server enforces. Copy `deploy/.env.example` to `deploy/.env`, fill it in, and
  run `docker compose up -d`.

### Changed

- The bundle builder and the release workflow describe the `.mcpb` bundle in
  provider-neutral terms. The bundle itself is unchanged.

## [0.1.2] — signed provenance on PyPI

### Changed
- The PyPI upload now carries a PEP 740 attestation. `uv publish` only uploads
  attestations that already exist, so the publish workflow now generates them
  first from the workflow's OIDC identity. Every release on PyPI can now be
  traced back to the commit and the workflow that built it.

## [0.1.1] — the distributable bundle

### Added
- `tools/build_mcpb.py`: one command that builds the Smithery `.mcpb` bundle
  from the working tree — manifest, source, bootstrap shim, packed archive.
- `smithery.yaml`: the publishing configuration for the stdio bundle.
- `.github/workflows/bundle.yml`: builds the bundle and attaches it to a
  published release, so a released `.mcpb` always matches a released tag.
- `.github/workflows/publish.yml`: publishes to PyPI from CI through Trusted
  Publishing, so the uploaded files carry provenance metadata.

### Changed
- The PyPI upload moved from a local machine to CI. A release is now
  published by a signed tag, and the same build that produces the bundle
  produces the distribution.

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
- TypeScript and JavaScript are parsed with the `tree-sitter` grammars from the
  `ts` extra, so their syntax is exact rather than lexical. The lexical
  parser remains as a fallback when those wheels are not installed.
- Six `verification_status` values, and a findings model that states what the
  evidence does *not* prove.

**Code maps**
- Ten map views: `module`, `call`, `inheritance`, `dependency`, `test`,
  `event`, `obligation`, `influence`, `data_flow`, `finding`.
- Single-file interactive HTML: anchored zoom, pointer-event pan, a minimap,
  viewport culling, level-of-detail rendering, and a renderer that measures its
  own frames and thins detail to hold the frame rate — so it needs no particular
  GPU and runs on a machine with no graphics card.
- The map is drawn on an `OffscreenCanvas` worker, so panning and zooming do
  not block the page thread; browsers without `Worker` fall back to the
  in-page renderer.
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
- **TypeScript and JavaScript call targets are resolved by name only.** The
  syntax itself is exact — Python is parsed with `ast`, TypeScript and
  JavaScript with the `tree-sitter` grammars from the `ts` extra
  (`pip install -e ".[ts]"`), and fall back to the lexical parser when those
  wheels are absent. But a call is bound to a definition by name, so the
  call graph stays approximate on those two languages. Verify any finding
  before acting on it.
- **Dependency analysis is inventory, not vulnerability scanning.** It reports
  `not_performed` rather than implying a clean bill of health.
- **Findings are heuristic.** A finding is a static result. `confidence` and
  `verification_status` describe evidence strength, not exploitability.
- **Cross-module reasoning is import-graph reasoning.** It does not follow
  reflection, dependency injection, `getattr` or plugin loading.
- **Maps are a bounded projection.** A snapshot holds at most 60,000 nodes and
  120,000 edges, and the node/edge budgets remove what does not fit. Every
  removal is counted and reported.

[0.1.2]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.2
[0.1.1]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.1
[0.1.0]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.0
