<div align="center">

# UNDERSTAND

Repository-wide code intelligence, security and defect analysis.

A CLI and an MCP server over one engine.

[![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-2.0-blue)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-MIT-8a5cf5)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-533%20passed-brightgreen)](tests)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](docs/cli.md)

[Report a bug](https://github.com/understand-mcp/Understand/issues) ·
[Request a feature](https://github.com/understand-mcp/Understand/issues)

</div>

## Real run: microsoft/playwright

This is the real output, not a demo fixture. Playwright is 3,024 files and
480,000 lines of mostly TypeScript, which is close to the worst case for the
call graph this tool builds.

```bash
git clone --depth 1 https://github.com/microsoft/playwright.git
understand scan ./playwright security bugs dependencies --deep --cross-module \
    --max-files 2500 --max-seconds 900
```

```text
UNDERSTAND scan report
  scan id      : scan-20261018-1ae0b2ae
  repository   : pw
  revision     : b335271cdc2b57cac2be8ad37c5dd283ac6b8938
  source       : local_git
  status       : completed
  duration     : 318s
  findings     : 1524
      critical 2
      high     216
      medium   307
      low      632
      info     367

critical (2)
-----------
  SEC-SQL-001-67dde74fcdd1  SQL query built by string interpolation
      rule        : SEC-SQL-001  [sql-injection]
      location    : utils/test-results-db/db.ts:117
      confidence  : medium   verification: cross_module_trace
      summary     : SQL query built by string interpolation
      remediation : Use parameterised queries / prepared statements and bind values.

  SEC-FLOW-001-5f9747b50c62  environment variable reaches SQL execution
      rule        : SEC-FLOW-001  [sql-injection]
      location    : tests/config/parquetReporter.ts:128
      confidence  : high     verification: static_evidence
      summary     : environment variable reaches SQL execution
      remediation : Validate and bound the value before it reaches the sink.
```

Both were read against the real source before being called real.

`utils/test-results-db/db.ts:117` is a DuckDB wrapper that builds a
`DELETE FROM ${TABLE_NAME} ... ORDER BY ... LIMIT $n` statement by template
interpolation. `${TABLE_NAME}` is a compile-time constant rather than user
input, so it is a style finding rather than an injection, and `medium` is the
honest level.

`tests/config/parquetReporter.ts:128` is exact. Line 126 reads
`process.env.PWTEST_PARQUET_OUTPUT_FILE` into `outputFile`, and line 128 sends
it into `COPY test_results TO '<path>'` escaped only by doubling single quotes.
An environment variable really does reach a SQL destination. Exploitability is
narrow — it is a CI test-harness script, so an attacker would need control of
the CI environment — but the claim itself is correct.

Coverage for the same scan:

```text
files_total      3024      files_analyzed  2500      files_skipped   524
files_failed        7      symbols        33100      edges        222630
unresolved_calls 132153    bytes_read  33177562      duration      318s

typescript  partial      1389 files   480554 lines
javascript  partial       170 files   162288 lines
unknown     text_only     519 files    60088 lines
markdown    text_only     248 files    94160 lines
json        full           72 files    16825 lines
shell       partial        33 files     1320 lines
yaml        full           23 files     5417 lines
```

33 dependency manifests were read, including 109 packages from the root
`package.json`. Every one is reported as `vulnerability_check=not_performed`.

### What that output actually tells you

**An earlier version of this tool got this badly wrong on the same repository,
and the numbers below are the corrected ones.** The first scan of this checkout
reported 2,823 findings including 68 criticals. Reading the source behind them,
one of those criticals was fabricated outright: `SEC-FLOW-001` called a critical
SQL injection at `packages/extension/src/connectedTabGroup.ts:55`, and line 55 of
that file is `chrome.tabs.query({ groupId: g.id })`. There is no database, no SQL
and no string literal anywhere in the file. The taint rule accepted any `.query(`
as a database read and then matched the same line again as a SQL sink.

Fixing that, and the bugs it uncovered, brought the same scan down to 1,524
findings and 2 criticals. Every fabricated finding was removed by fixing the
rule that produced it, never by filtering the output. Eleven defects in total,
in four rounds:

| Round | Root cause | What it matched | Fix |
| --- | --- | --- | --- |
| 1 | `\.\s*query\s*(` | `chrome.tabs.query(…)` — a browser API reported as a database read, then matched again as a SQL sink | database calls now need a database receiver; a source and a sink on one line no longer count as a flow |
| 1 | `\b(?:INSERT\|UPDATE\|DELETE)\b`, case-insensitive | `this._groupTabIds.delete(tabId)` — a `Map` removal reported as an untransacted write | requires `INSERT INTO` / `UPDATE … SET` / `DELETE FROM` |
| 2 | `\.\s*findOne?\s*(` | `Array.prototype.find` | removed; `.findOne(` needs a database receiver |
| 2 | `\b(?:…\|repo\|…)\w*\.` | the `repo` inside `report.find(…)` | added a trailing `\b` |
| 2 | `QueryContext` | Playwright's DOM query context type | removed |
| 2 | `\beval\s*(` | Playwright's `page.$eval(selector, fn)` | added `(?<![$\w.])`, because `$` is a non-word character |
| 3 | `_find_source` returned the first source-shaped line anywhere in a function | a file with one `process.env.X` and 40 `path.join(` calls produced 40 findings claiming the env var reached each one | a source is attributed only when the tainted name is assigned on a line that actually reads a source; otherwise it is reported as `parameter` or `unknown-origin` and the finding is downgraded a severity level with `confidence: low` and `verification_status: inconclusive` |
| 3 | evidence snippets taken from sanitised text | `path.join(appFolder, '          ')` — the literal a reader needs in order to check the finding had been blanked | snippets come from the original line; detection still runs on sanitised text |
| 4 | `exec\s*\(\s*["']` | Node's `child_process.exec('tar', '-xzf', file)` argv form, which passes no string to a shell | now requires a template literal or a concatenation |

Two of those eleven I introduced myself while fixing the first one. That is the
honest shape of it: tightening one pattern revealed more underneath it, and each
was only visible by re-running against the real repository and reading the
source.

| | First run | After the pattern fixes | Also today |
| --- | --- | --- | --- |
| Findings | 2,823 | 1,524 | **930** |
| Critical | 68 | 2 | **2** |
| High | 316 | 216 | **211** |
| Medium | 180 | 307 | **277** |
| Low | 1,892 | 632 | **46** |

The last column removes one more class of noise: the repository vendors a
browserified copy of React 15 under `tests/assets/`, and that build was
producing hundreds of findings about code this repository does not contain.
Excluding shipped bundles took 5,854 symbols and 35,160 edges out of the
analysis and cut findings by 42% while critical stayed at 2.

Medium rising while high falls is the correct direction: a flow whose origin
could not be tied to untrusted input now moves down a level instead of being
presented as a demonstrated vulnerability.

**The 216 high findings are 8 rules repeated, not 216 separate problems.** The
same `env → path.join` shape accounts for 128 of them across 53 files, and one
file (`packages/playwright/src/reporters/html.ts`) contributes several in which
the path is derived from `require.resolve('playwright-core')` and has nothing to
do with the environment variable the rule named. Read those as one pattern to
review per function, not as 128 independent issues. `BUG-CMP-001` (11) fires
mostly on vendored React, and all 3 `SEC-TLS-001` findings are deliberate
`rejectUnauthorized: false` test fixtures — correct about the text, wrong about
the risk.

This is the honest state of the tool in October 2026:

| | Python | TypeScript / JavaScript |
| --- | --- | --- |
| Parsing | `ast`, exact | `tree-sitter`, exact |
| Symbol resolution | name and scope | name only |
| Usable for triage | yes | syntax yes, call graph after review |
| False positive rate | low | low on syntax, high on unresolved calls |

TypeScript and JavaScript are parsed with the `tree-sitter` grammars from the `ts` extra (`pip install -e ".[ts]"`) and fall back to the lexical parser when those wheels are absent. Call targets are still resolved by name only, so the graph stays approximate. A number that matters more than the finding count: **132,153 call targets could
not be resolved.** That number is printed in the report precisely so you know how
much of the graph is guesswork. If a repository produces a high unresolved count,
its `cross_module_trace` findings are close to meaningless.

Read the report as a list of places to look, not a list of bugs. Sort by
`verification: cross_module_trace` first and you will get the most defensible
results. `--fail-on high` on this repository exits 2, which is the tool telling
you the truth about itself rather than telling you the code is broken.

If you only care about Python, run `understand scan <repo> security --profile
deep` and the numbers become usable. On TypeScript the syntax is now exact, but call targets are resolved by name alone, so treat the output as a
triage queue.

## What it does

Points at a repository, reads it, and reports what it finds with the code that
triggered it: file, line, snippet, and how strong the evidence actually is.

```bash
understand scan ./my-project security --deep --format text
```

The output above came from a real repository. This one is the bundled fixture,
which is small enough to read in full:

```text
UNDERSTAND scan report
  scan id      : scan-20261018-ae8865ae
  repository   : repo_shell_risk
  status       : completed
  duration     : 0.03s
  findings     : 5
      critical 4
      medium   1

critical (4)
------------
  SEC-FLOW-001-5f9747b50c62  HTTP request data reaches shell command execution
      rule        : SEC-FLOW-001  [command-injection]
      location    : app/api.py:11
      confidence  : medium   verification: static_evidence
      summary     : Data from HTTP request data reaches shell command execution at app/api.py:11.
      remediation : Use an argument array with shell disabled and validate each argument.
```

That one is a real scan of `tests/fixtures/repo_shell_risk`, a six-file Python
project with deliberately planted defects. It is the only output here with a
hand-verifiable finding count.

## The five checks

| Check | Finds |
|---|---|
| `security` | Injection, unsafe shell calls, weak crypto, hardcoded secrets, path traversal |
| `bugs` | Bare excepts, ignored returns, dead code, swallowed errors, off-by-one shapes |
| `architecture` | Import cycles, coupling, layer violations, oversized modules |
| `dependencies` | Manifests, declared versions, conflicts. Inventory, not vulnerability lookup |
| `reliability` | Retries without backoff, unbounded sleeps, missing cleanup, unchecked timeouts |

Positional tokens and flags both work, in any order: `security bugs`, or
`--security --bugs`. `--all` runs everything.

## How a finding is described

Every finding carries two independent axes.

`confidence` is how sure the engine is. `verification_status` is how the finding
was reached.

| verification_status | Meaning |
|---|---|
| `static_evidence` | Found in one place, no cross-file trace |
| `cross_module_trace` | Traced through the import and call graph to the sink |
| `test_backed` | A test in the repository exercises it |
| `reproduced` | Reproduced in a local authorised environment |
| `inconclusive` | Could not be settled. Says so |
| `not_verified` | Deliberately not checked |

A low-confidence, inconclusive finding is labelled as one. The report tells you
what it could not analyse, and the Limitations section is always present.

## Install

```bash
pip install understand-mcp
```

From source:

```bash
git clone https://github.com/understand-mcp/Understand.git
cd Understand
pip install .
```

Python 3.11 or newer. `git` is only needed for remote repositories.

## Commands

```text
understand scan SOURCE [FEATURE ...] [OPTIONS]
understand report list | show SCAN_ID
understand finding show FINDING_ID
understand map show SCAN_ID [--view module] [--root PATH] [--output map.html]
understand map views
understand config show
understand capabilities
understand version
```

### Code maps

`understand map show` turns a stored scan into one HTML file you can open from disk.
No server, no CDN, no network call at view time.

```bash
understand scan ./playwright security bugs --deep --cross-module
understand map show scan-20261019-eb775652 --output map.html

# A symbol view rooted at one function.
understand map show scan-20261019-eb775652 --view call --root handlePage --depth 3
understand map show scan-20261019-eb775652 --view test --root tests/e2e/login.spec.ts

# The causal account of one finding, in the terminal.
understand map explain SEC-FLOW-001 --scan-id scan-20261019-eb775652
```

On microsoft/playwright that produces a single 2.7 MB file: 1,321 file nodes and 8,000
edges, laid out in 9 dependency layers with the caller above what it calls. It zooms,
pans, filters and has a minimap. At fit-to-view the whole repository is visible; zoom in
and file names appear. The status bar states how many of the 8,000 edges are drawn at the
current zoom, which edges the budget removed, and how many of the scan's 42,026 unresolved
call targets the map did not draw, because a map that looks complete but is not is worse
than no map.

Click any node and it explains itself. You get the source lines of that symbol, and
every finding attached to it in full: the technical explanation, the impact, the
data-flow path as a numbered chain from source to sink, the evidence with real file and
line and a real snippet, what must be true for it to matter, how to fix it — and, as its
own section, **what this analysis did not prove**. That last block is the reason the rest
is trustworthy; an impact sentence next to a red badge reads as a demonstrated defect,
and the same sentence next to an explicit statement of the gap reads as what it is.

`understand map explain FINDING_ID` is that account as prose, for when you want the
argument rather than the picture. It prints the path from source to sink with each hop,
the evidence under it, the preconditions, the assumptions, and a closing "Read this
before acting" section carrying the scan's own unresolved-call count and truncation
state. It ends by printing the exact `map show` command that draws the path it just
described. A rule id works anywhere a finding id does, and without `--scan-id` it
searches the 25 most recent scans rather than guessing which one you meant.

Ten views ship. Seven walk the code graph outward from a root: `module` (which files
depend on which), `call` (what this symbol calls and what calls it), `inheritance`
(what this class extends or implements), `dependency` (what this module imports),
`test` (what this test exercises), `event` (who raises an event and who listens),
`obligation` (what a function validates, authorises or sends) and `influence` (what
configuration decides its behaviour). The symbol views take `--root` as a full id, a
name, a file path or `file::symbol`.

The last two are built from the findings instead of the graph, because that is where
the evidence is. `data_flow` draws the paths the analyzer actually traced from
untrusted input to a sink — nothing else, since a path that exists but was not traced
would be a guess — and gives the value's origin and the sink their own anchored nodes,
because the graph has no node for `process.env` or for `sql-exec`. Solid edges are
flows traced across modules; dashed ones matched a source and a sink without the value
in between being followed, and the map states the split. `finding` places every symbol
a finding landed on, worst severity first.

Panning and zooming stay smooth on that same 2,000-node map: measured in a browser,
the worst frame is 12 ms while dragging and 59 ms while zooming, with no frame over
33 ms during a drag. While the camera is moving the map draws a coarser picture
rather than a late one — straight edges instead of curves, no arrow heads, a capped
set of edges, no labels, and only the 400 most connected nodes — and the status bar says
so while it is happening. The detail level also adapts to what the machine actually
manages: the renderer measures its own frames and thins or restores accordingly, so it
needs no particular GPU and runs the same on a laptop with no graphics card.
`docs/interactive-map.md` has the measurements and what each fix was. A `--root` accepts
a full id, a `Class.method`, a file path or a bare name; an ambiguous name is refused
with the candidate ids rather than guessed at. `understand map views` lists all ten,
marking the five that are implemented. The rest are specified in
[interactive-map.md](docs/interactive-map.md).

### scan options

| Option | Effect |
|---|---|
| `-d`, `--deep` | Deeper profile: interprocedural tracing, wider path exploration |
| `-x`, `--cross-module` | Follow calls and data across module boundaries |
| `--profile NAME` | `standard` or `deep`, explicit |
| `--format FORMAT` | `text`, `json` or `sarif` |
| `-o`, `--output PATH` | Write to a file. Protected directories are refused |
| `--no-report` | Analyse without emitting a report |
| `--fail-on SEVERITY` | Exit 2 when a finding at or above that severity exists |
| `--no-evidence` | Leave evidence out of the output |
| `--allow-remote` | Permit remote git. Still subject to the host allowlist |
| `--offline` | No network, no cache |
| `--no-cache` | Recompute even when nothing changed |
| `--local-root PATH` | Allow a repository root. Repeatable |
| `--max-files N` | File budget |
| `--max-seconds N` | Time budget |
| `-q`, `-v` | Quiet, or verbose with a traceback |
| `-c`, `--config PATH` | JSON configuration file |

Feature tokens: `security`, `bugs`, `architecture`, `dependencies`, `reliability`,
`all`, `report`. Unknown tokens and conflicting settings are errors, never ignored.

`--help` works without starting a scan. Logs go to stderr, so `--format json` on
stdout stays parseable.

### recipes

```bash
# everything, deep, cross-module, machine readable
understand scan ./my-project security bugs --deep --cross-module report --format json

# gate a pipeline
understand scan ./my-project --security --fail-on high

# GitHub code scanning
understand scan . --all --deep --format sarif --output results.sarif

# remote
UNDERSTAND_ALLOW_REMOTE=true UNDERSTAND_ALLOWED_HOSTS=github.com \
  understand scan https://github.com/owner/repo.git security --deep
```

### exit codes

| | | | |
|---|---|---|---|
| 0 success | 63 bad format | 67 finding not found | 72 network policy |
| 1 internal error | 64 bad usage | 69 not acquired | 74 store failed |
| | 65 bad source | 70 limit exceeded | 77 access denied |
| | 66 scan not found | 71 analysis failed | 78 config error |

`--fail-on` exits 2. SIGINT exits 130.

## MCP server

```bash
python -m understand.mcp_server               # stdio, the default
understand-mcp-server                         # same thing as a console script
python -m understand.mcp_server streamable-http
```

Transports: `stdio`, `streamable-http`, `sse`.

| Variable | Default |
|---|---|
| `UNDERSTAND_MCP_TRANSPORT` | `stdio` |
| `UNDERSTAND_MCP_HOST` | `127.0.0.1` |
| `UNDERSTAND_MCP_PORT` | `8000` |
| `UNDERSTAND_CONFIG` | none |
| `UNDERSTAND_LOG_LEVEL` | `WARNING` |

Everything logs to stderr, so stdout stays a clean protocol stream.

### the nine tools

| Tool | Kind | Purpose |
|---|---|---|
| `scan_repository` | mutating | Analyse a repo. Returns a scan id |
| `get_scan_status` | read-only | Status, current stage, finding counts |
| `cancel_scan` | mutating | Stop a running scan |
| `get_scan_report` | read-only | Findings, filtered and paginated |
| `inspect_finding` | read-only | One finding in full, with a plain-language interpretation |
| `trace_execution` | read-only | Call paths from a symbol, ranked |
| `trace_data_flow` | read-only | Source to sink. "How does input reach this?" |
| `analyze_change_impact` | read-only | What breaks if this file changes |
| `query_codebase` | read-only | Search findings without rescanning |

Plus two resources: `understand://capabilities` and `understand://security-model`.

`scan_repository` example:

```json
{
  "repository": "./my-project",
  "profile": "deep",
  "checks": ["security", "bugs"],
  "cross_module": true,
  "wait": false
}
```

`wait: false` returns immediately with a scan id. Poll `get_scan_status` until
`completed`, then read `get_scan_report`. A deep scan on a real repository takes
minutes and does not fit in one response.

Every response is `{"ok": true, ...}` or `{"ok": false, "error": {...}}`. Failures
carry a code, a message, a detail object, an exit code, and whether retrying is
worth it.

There is no arbitrary filesystem access, no shell tool and no Python execution
tool. Seven of the nine are read-only.

## Connecting a client

The server starts the same way in every MCP client:

```json
{ "mcpServers": { "understand": {
  "command": "python",
  "args": ["-m", "understand.mcp_server"]
} } }
```

Set the working directory to your project, and raise the timeout. Client defaults
run from 5 to 60 seconds, a deep scan takes minutes, and a timeout looks exactly
like a dead server. Raise it before you go looking in the logs.

### OpenCode

`opencode.json`:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "understand": {
      "type": "local",
      "command": ["python", "-m", "understand.mcp_server"],
      "enabled": true,
      "timeout": 600000
    }
  }
}
```

Check it with `opencode mcp list`. Remote servers use `"type": "remote"` with a
`url`.

### Claude Desktop

`claude_desktop_config.json`. macOS:
`~/Library/Application Support/Claude/`. Windows:
`%APPDATA%\Claude\`.

```json
{ "mcpServers": { "understand": {
  "command": "python",
  "args": ["-m", "understand.mcp_server"],
  "cwd": "C:\\path\\to\\your\\project"
} } }
```

Restart Claude after editing.

### Claude Code

```bash
claude mcp add understand -- python -m understand.mcp_server
claude mcp add understand --scope project -- python -m understand.mcp_server
```

### Codex

`~/.codex/config.toml`, shared by the CLI, the IDE extension and the desktop app.

```toml
[mcp_servers.understand]
command = "python"
args = ["-m", "understand.mcp_server"]
startup_timeout_sec = 30
tool_timeout_sec = 600
```

Trim the context cost with `enabled_tools`. Nine tools is a lot of tokens to load
on every request.

### Cursor

`.cursor/mcp.json`:

```json
{ "mcpServers": { "understand": {
  "command": "python", "args": ["-m", "understand.mcp_server"]
} } }
```

### Gemini CLI

`~/.gemini/settings.json`:

```json
{ "mcpServers": { "understand": {
  "command": "python",
  "args": ["-m", "understand.mcp_server"],
  "timeout": 600000,
  "excludeTools": ["cancel_scan"]
} } }
```

`${VAR}` and `%VAR%` expand. Undefined variables become empty strings.

### OpenClaw

```bash
openclaw mcp add understand --command python --arg "-m" --arg "understand.mcp_server"
openclaw mcp doctor understand --probe
```

Note: its stdio environment filter blocks `PYTHONSTARTUP` and `NODE_OPTIONS`. If
a variable you set gets rejected, move it into a JSON config file and point
`UNDERSTAND_CONFIG` at that.

### LM Studio

MCP support arrived in 0.3.17. Program tab, Install, Edit mcp.json. It follows
Cursor's format, so the snippet above works unchanged.

### VS Code

`.vscode/mcp.json`, note the key is `servers`:

```json
{ "servers": { "understand": {
  "command": "python", "args": ["-m", "understand.mcp_server"]
} } }
```

### Providers without an MCP client

Ollama, OpenAI, xAI, DeepSeek and Kimi have no MCP surface of their own. The
model never speaks MCP. Your client does.

```text
Ollama  ──►  MCP bridge  ──►  UNDERSTAND
```

For Ollama, put an MCP-to-OpenAI bridge in front of its `/v1` endpoint. Two
things bite: the model has to support tool calling, which most small local models
do not do reliably, and nine tools is too many for a small context. Expose two or
three and leave the rest off.

For OpenAI and the rest, use an agent framework with an MCP adapter.

Full configs, the bridge setup and remote hosting: [docs/clients.md](docs/clients.md).

## Configuration

Precedence: CLI flag, then `UNDERSTAND_` env var, then config file.

| Setting | Variable | Default |
|---|---|---|
| Scan store | `UNDERSTAND_STORAGE` | `~/.understand/scans.db` |
| Remote scanning | `UNDERSTAND_ALLOW_REMOTE` | `false` |
| Allowed hosts | `UNDERSTAND_ALLOWED_HOSTS` | any |
| Block private networks | `UNDERSTAND_BLOCK_PRIVATE_NETWORKS` | `true` |
| Plain http remotes | `UNDERSTAND_ALLOW_HTTP` | `false` |
| SSH remotes | `UNDERSTAND_ALLOW_SSH` | `false` |
| Clone depth | `UNDERSTAND_CLONE_DEPTH` | `25` |
| Max files | `UNDERSTAND_MAX_FILES` | `20000` |
| Max file bytes | `UNDERSTAND_MAX_FILE_BYTES` | `2000000` |
| Max seconds | `UNDERSTAND_MAX_SECONDS` | `600` |
| Follow symlinks | `UNDERSTAND_FOLLOW_SYMLINKS` | `false` |
| Workers | `UNDERSTAND_WORKERS` | `8` |
| Telemetry | `UNDERSTAND_TELEMETRY` | `false` |

Config file:

```json
{
  "storage_path": "~/.understand/scans.db",
  "security": {
    "allow_remote": false,
    "allowed_hosts": ["github.com"],
    "block_private_networks": true
  },
  "analysis": {
    "max_files": 20000,
    "max_file_bytes": 2000000,
    "follow_symlinks": false
  }
}
```

There is no `--allowed-host` flag, on purpose. Hosts come from configuration, so a
scan cannot widen its own network permissions. Remote scanning needs three
independent agreements: the flag, `allow_remote`, and a host that passes the
allowlist and the private-network block.

Everything: [docs/configuration.md](docs/configuration.md).

## Output

`text` for people, `json` for scripts, `sarif` for GitHub code scanning and Azure
DevOps. An unsupported format is an error, never a silent substitution. Secrets
are redacted on the way out.

The SARIF is validated against the real OASIS 2.1.0 schema, not just against
itself:

```bash
python tools/validate_sarif.py
```

```
result : VALID against the OASIS SARIF 2.1.0 schema
```

## Security

The repository is the adversary, because it usually is.

Paths are resolved before they are compared, so a symlink cannot walk out of the
workspace. Filenames are checked against Windows reserved names, control
characters and alternate data streams. Generated code, vendored trees, hidden
files and sensitive names are excluded, and the exclusion is recorded in the
report.

Remote fetching accepts only https, plus ssh when configured. It rejects
credentials embedded in a URL, cloud metadata endpoints, loopback and private
addresses, IPv4-mapped and Teredo equivalents of the same, and anything starting
with a dash. DNS is resolved again immediately before cloning, which closes the
rebinding window.

`git` runs with hooks disabled, credential helpers cleared, protocols restricted
and no shell. Nothing else is executed. Not the analysed code, not a build script,
not a test.

Findings carry confidence and verification status separately, so a downstream
model has something concrete to not overstate.

Threat model and every control: [docs/security-model.md](docs/security-model.md).

## Architecture

```text
CLI  ─────┐
          ├──►  application/  ──►  engine/  ──►  storage/  (sqlite)
MCP  ─────┘
```

Both front ends are thin. They share one request model, one pipeline, one findings
model and one reporter, so the CLI and an AI model can never disagree about a
finding.

```text
validate → acquire → inventory → detect languages → parse → build graph
        → data flow → verify → run checks → impact → finalize
```

Only the first three stages can fail a scan outright. A failure after that becomes
a partial report with a recorded warning, never a quietly complete one.

Details: [docs/architecture.md](docs/architecture.md).

## Documentation

The long version is in `docs/`.

| Document | Contents |
|---|---|
| [architecture.md](docs/architecture.md) | Pipeline, graph model, storage |
| [security-model.md](docs/security-model.md) | Threat model, every control |
| [mcp-protocol.md](docs/mcp-protocol.md) | Tool schemas, envelope, error codes |
| [cli.md](docs/cli.md) | Every command, flag and exit code |
| [configuration.md](docs/configuration.md) | Every setting |
| [clients.md](docs/clients.md) | Per-client setup, bridges, remote hosting |
| [deployment.md](docs/deployment.md) | Local, container, remote |
| [mcpb.md](docs/mcpb.md) | The distributable MCPB bundle |
| [portability.md](docs/portability.md) | Linux, macOS, Windows |
| [extending.md](docs/extending.md) | Adding a check, a language, a tool |
| [interactive-map.md](docs/interactive-map.md) | Interactive code maps: what ships, what is next |
| [roadmap.md](docs/roadmap.md) | What is next, and what is deliberately not |

## Development

```bash
pip install -e .
python -m pytest -q
python tools/validate_sarif.py
```

```text
533 passed
```

Linux, macOS and Windows, Python 3.11 to 3.13. Adding a check or a language:
[docs/extending.md](docs/extending.md).

## Deploying

```bash
docker build -t understand-mcp .
docker run --rm -p 8000:8000 -v understand-data:/data understand-mcp
```

Runs unprivileged, defaults to streamable HTTP on 0.0.0.0:8000, stores in
`/data`. Put TLS and authentication in front of it before exposing it, and read
[docs/deployment.md](docs/deployment.md) first, because a remote MCP server has no
access to the client's disk.

The distributable bundle: [docs/mcpb.md](docs/mcpb.md). One command builds it,
and every published release attaches it.

## Troubleshooting

**The model says nothing happened.** Raise the tool timeout first. It is almost
always that.

**No findings.** Check Limitations in the report. Generated files, vendored trees
and test files are excluded by default.

**Remote scan refuses.** Remote is off, then the host still has to be in the
allowlist and must not resolve to a private address.

**Repository outside the roots.** Add `--local-root`.

**`git` complains about ownership.** git's `safe.directory`. UNDERSTAND reports it
as an acquisition failure rather than hiding it.

## License

MIT. Free for everyone, commercial use included. See [LICENSE](LICENSE).

Keep the evidence model intact if you redistribute output. Do not present an
inconclusive finding as a proven one, and do not strip the Limitations section.

## Support this project

If UNDERSTAND saved you time, you can support its maintenance.

```text
BTC    1CC4RD7887DZdQWafPeh18cGM39YsMPftS
EVM    0x9C4776a50b861538030c6717Df9fa588c8285091
SOL    88ADQVkvJag7YtUwgzpgp3y7pa5V4vu3r2ix68DEWEGC
```

The EVM address works on every EVM chain. Check an address before you send.

## Acknowledgements

- [Model Context Protocol](https://modelcontextprotocol.io)
- [OASIS SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Pydantic](https://docs.pydantic.dev)
