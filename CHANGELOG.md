# Changelog

All notable changes to UNDERSTAND are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.7] - the last findings, and a publish that cannot fail twice

### Fixed
- The publish workflow uploaded a version that PyPI already had, and PyPI
  rejects that because a file never changes. The job now asks PyPI whether the
  version is there and stops with a green result, so a release that is
  published twice can never fail the workflow again.
- Three `assert` statements in production code became explicit errors. An
  assertion disappears under `python -O`, so it must not be the thing that
  keeps the store and the MCP server honest.
- Three empty `except` handlers now do something. The store records the
  pragma it could not set, the optional tree-sitter grammars are cleared
  explicitly, and the remote host check asks a question instead of catching
  an exception to do nothing.
- A write that already sits inside a transaction is no longer reported as an
  untransacted write. The rule sees the transaction whether it was opened by
  a context manager or by an explicit `BEGIN`, and it reads the SQL text from
  the source line because the sanitiser hides string bodies.
- A god module has to be wide and long before it is reported, and a test file
  never is. The map model was split into three modules because it genuinely
  was one: the vocabulary, the layout engine and the view builders.
- Two layout helpers that nothing called were removed.

### Changed
- The self-scan of this repository now reports nothing at all: 0 findings, 0
  critical, 0 high.

## [0.1.6] - the version stops lying

### Fixed
- `understand capabilities` and `understand version` printed the help text
  instead of their JSON when the command was given without a single option. The
  dispatcher read "no argument left after the command" as "no command at all".
- The version the tool reports was frozen at 0.1.0 while the package moved on,
  so every report, the SARIF `analyzerVersion` and the MCP server announced a
  version that was not the one installed. The literal now matches
  `pyproject.toml`, and a test fails the build when the two drift apart.

### Changed
- `.gitignore` covers the local launch folder and a packed copy of the git
  directory, so neither can be committed by accident.

## [0.1.5] - quieter findings, typed and documented

The audit kept going after 0.1.4 and found that the tool was noisier about
itself than it needed to be, that one flag was doing the opposite of what
its name says, and that half the options were undocumented.

### Fixed

- The severity filter behind `--fail-on` compared the ranks the wrong way
  round, so `--fail-on high` never failed on a critical or a high finding.
  It now fails on what it says it fails on.
- `assert` in a test file is the assertion mechanism, not a validation
  guard. It is no longer reported as a security finding.
- An `except` block that does something is no longer reported as an empty
  handler, and an exception bound to a name that is used is no longer
  reported as an unused binding.
- A module-level lookup table that is never mutated is no longer reported
  as a mutable global, and a private helper with no caller is now reported
  as dead code (public names were being reported before, which is backwards:
  a public name is the one you cannot judge).
- The resource heuristic matched our own method names, so `self.open()` and
  `acquire()` read as resource acquisitions. It now matches the call, not
  the name.
- Prose was analysed as code: a README that mentioned a retry was reported
  as a retry without a timeout, and a `setTimeout` inside a template string
  was reported as a blocking sleep.
- The scan `--help` lists every option the CLI accepts, and `docs/cli.md`
  now carries a complete generated reference for all of them, so the docs
  cannot drift from the code.

### Changed

- `mypy` reports no errors across the source, and CI runs it as a third
  check next to the tests and the linter.
- The README opens with a picture of what the tool does: your repository,
  the engine, and the finding you get back.

## [0.1.4] - the audited release

### Added

- `understand report show SCAN_ID --share` prints a paste-ready block: the
  repository, the number of files, the findings by severity and the top
  findings with their file and line. `--share --format markdown` and
  `--share --format json` give the same content in the other two shapes.
- After the first successful scan the CLI prints one line asking for a star.
  It is shown once per machine, it is written to stderr so a piped report
  stays valid, and `--no-thanks` or `UNDERSTAND_NO_THANKS=1` switches it off.
  No telemetry is sent, no network call is made, and the only thing recorded
  is a single flag in `~/.understand/state.json`.
- `CONTRIBUTING.md`, `SECURITY.md` and `CODE_OF_CONDUCT.md`, plus issue and
  pull request templates, so a first-time contributor knows what is expected.
- The source distribution now ships the documentation, the tests, the tooling
  and the deployment recipe, so an sdist is a complete checkout and not just
  the importable package.
- `src/understand/py.typed` marks the package as typed (PEP 561), which the
  packaging metadata already claimed.

### Changed

- The README now opens with a sixty-second quickstart instead of the badge
  block.
- The shell-injection rule no longer reports a call that passes an argument
  array or that sets `shell=False`: no shell is involved there, so the
  arguments cannot be reinterpreted as shell syntax. A call that reaches a
  shell is still reported, and so is a call whose arguments are interpolated.
- The SQL-injection rule no longer reports a statement that interpolates only
  a reviewed query-builder clause and binds its values as parameters.
- The taint engine no longer treats a process started with an argument array
  as a shell sink.
- The architecture documentation now describes the sixteen stages the pipeline
  actually runs, and how a failure is reported: an analyzer that raises is a
  warning, a spent time budget is a partial report, and an unexpected error
  fails the scan and says so.

## [0.1.3] - provider-neutral distribution

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

[0.1.7]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.7
[0.1.6]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.6
[0.1.5]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.5
[0.1.4]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.4
[0.1.3]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.3
[0.1.2]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.2
[0.1.1]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.1
[0.1.0]: https://github.com/understand-mcp/Understand/releases/tag/v0.1.0
