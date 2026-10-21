# The CLI

The CLI is a thin argument parser over the same application services the MCP
server exposes. It is not a separate implementation: any behaviour you see here
is behaviour the tools also have.

Verified against `understand --help` and `understand scan --help` at version
0.1.0.

---

## 1. Commands

```
understand scan SOURCE [FEATURE ...] [OPTIONS]
understand report show SCAN_ID [--format json] [--share] [--limit N] [--offset N]
understand report list [--limit N] [--offset N] [--status STATUS]
understand finding show FINDING_ID [--scan-id SCAN_ID] [--format json]
understand map show SCAN_ID [--view module] [--root PATH] [--depth N] [--output map.html]
understand map explain FINDING_ID [--scan-id SCAN_ID] [--json]
understand map views
understand config show
understand capabilities
understand version
```

| Command | What it does |
| --- | --- |
| `scan` | Run one analysis and print or write the report. |
| `report show` | Re-print a stored report by id, optionally filtered and paginated. |
| `report list` | List stored scans with their status and finding counts. |
| `finding show` | Print one finding in full, including evidence. |
| `map show` | Build an interactive single-file HTML map of a stored scan. |
| `map explain` | Print the causal account of one finding: the path from source to sink, the evidence, what must be true, and what was not proven. |
| `map views` | List every map view and mark which are implemented. |
| `config show` | Print the effective configuration and where each value came from. |
| `capabilities` | Print the machine-readable capability manifest as JSON. |
| `version` | Print the version. |

### Building a map

```bash
# One HTML file. No server, no CDN, no network call at view time.
understand map show scan-20261018-e9b97d48 --output map.html

# Restrict to one part of the tree, print to stdout, open it afterwards.
understand map show scan-20261018-e9b97d48 --root packages --output packages.html --open

# The model instead of the document, for scripting or for a model to read.
understand map show scan-20261018-e9b97d48 --json > map.json

# Only the relations you care about, within a budget you chose.
understand map show scan-20261018-e9b97d48 --kind imports --kind calls --max-edges 2000
understand map show scan-20261018-e9b97d48 --view call --root handlePage --depth 4
understand map show scan-20261018-e9b97d48 --view inheritance --root BrowserContext --direction in
understand map show scan-20261018-e9b97d48 --view test --root tests/e2e/login.spec.ts
```

### Explaining a finding

```bash
# The path from source to sink, the evidence, the fix, and the gap.
understand map explain SEC-FLOW-001 --scan-id scan-20261019-eb775652

# A rule_id is accepted anywhere a finding_id is. Without --scan-id the command
# searches the 25 most recent scans and reports which one it used.
understand map explain SEC-JS-XSS-001-0df21e2a937d

# Machine-readable, for piping into something else.
understand map explain SEC-FLOW-001-bb8c7e93f9af --scan-id scan-20261019-eb775652 --json

# Keep it next to the map.
understand map explain SEC-FLOW-001 --scan-id scan-20261019-eb775652 --output finding.txt
```

The output is ordered as an argument rather than as a record: what was found and
where, why it matters, the impact, the path from source to sink with each hop,
the evidence under it, what must be true for it to matter, **what this analysis
did not prove**, why that confidence, the fix, the references, and finally a
`Read this before acting` section carrying the scan's unresolved-call count and
snapshot-truncation state. It ends by printing the exact `map show` command that
draws the path it just described, with the root already resolved to an id the map
can open.

| Option | Default | What it does |
| --- | --- | --- |
| `--view NAME` | `module` | Which question to draw: `module`, `call`, `inheritance`, `dependency` or `test`. |
| `--root PATH` | whole repository | A symbol id, a `Class.method`, a file path, or a directory prefix. On the symbol views an ambiguous name is refused with the candidate ids rather than guessed. |
| `--depth N` | `3` | Traversal depth, 1 to 6. The root is depth 0, so `--depth 3` reaches three hops out. |
| `--direction` | `both` | `out`, `in` or `both`, relative to `--root`. |
| `--kind KIND` | all | Restrict to a relation kind. Repeatable. |
| `--no-findings` | off | Omit per-file finding counts. |
| `--max-nodes N` | `2000` | Node ceiling. |
| `--max-edges N` | `8000` | Edge ceiling. |
| `--scan-id SCAN_ID` | newest containing scan, for `explain` only | Which scan to read. A finding id is not unique across scans, so `map explain` searches rather than guessing. |
| `--json` | off | Emit the map model rather than the HTML document. |
| `--open` | off | Best-effort open with the OS handler. Never fails the command. |
| `--output PATH` | stdout | Destination `.html` file. |
| `--storage PATH` | default | Scan store to read. |

When a budget removes edges, the map says so in its own status bar and in its caveats,
naming the kinds and the counts. A truncated map that looks complete is a lie.

The ten views answer ten different questions. They fall into two families, and the
difference matters: the first seven are traversals of the code graph from a root,
while the last two are projections of the findings, because a traced path and a
severity cluster only exist on the finding.

| View | Question | Built from | Draws |
| --- | --- | --- | --- |
| `module` | Which files depend on which files? | the graph, collapsed onto files | every kind |
| `call` | What does this symbol call, and what calls it? | the graph | `calls`, `awaits_task`, `starts_task` |
| `inheritance` | What does this class extend or implement? | the graph | `inherits`, `implements` |
| `dependency` | What does this module import, directly or transitively? | the graph | `imports`, `depends_on` |
| `test` | What does this test actually exercise? | the graph | `tests` |
| `event` | Who raises this event, and who listens for it? | the graph | `registers`, `handles_event` |
| `obligation` | What does this code validate, authorise, or send? | the graph | `validates`, `authorizes`, `sends_data_to`, `opens_resource`, `closes_resource` |
| `influence` | What configuration decides how this behaves? | the graph | `configures`, `influences` |
| `data_flow` | How does untrusted input reach this sink? | the findings' traced flows | the hops between them |
| `finding` | Where are the findings, and how bad are they? | the findings | every kind |

With no `--root` the seven graph views draw the whole snapshot ranked by degree, so
the budget keeps the busiest symbols rather than the alphabetically first 2,000.

`data_flow` is not a traversal, and that is deliberate. The graph contains every
call in the repository; drawing it under the name "data flow" would be a call
graph wearing a label. What makes a path a flow is that the analyzer traced
untrusted input through it, and that evidence lives only on the finding. So the
nodes come from `finding.data_flows`, the origin of the value and the sink it
reaches get their own anchored nodes (the graph has no node for `process.env` or
for `sql-exec`), and edges are solid only where the flow was actually traced across
modules — dashed where a source pattern and a sink pattern merely matched. The
caveats state how many edges are which.

`finding` places every symbol a finding landed on, worst severity first. A finding
that touched five symbols is counted on each of them, and the caveat says so rather
than letting the totals look like five separate problems.

A view that finds nothing says which of two things happened: that no relation of
its kinds connects the requested root, or that the analyzer recorded no such
relation anywhere in the repository. Those send a reader to different next steps.

The design is in [`interactive-map.md`](interactive-map.md).

---

## 2. The five checks

`scan` accepts checks both as positional tokens and as flags. Both spellings are
order-independent and repeatable.

| Check | Token | Flag | What it looks for |
| --- | --- | --- | --- |
| Security | `security` | `--security` | Injection, unsafe execution, hardcoded credentials, weak crypto, path traversal. |
| Bugs | `bugs` | `--bugs` | Unhandled exceptions, silent failures, incorrect conditionals, resource leaks. |
| Architecture | `architecture` | `--architecture` | Import cycles, coupling hotspots, layer violations. |
| Dependencies | `dependencies` | `--dependencies` | Manifest inventory and declared version ranges. |
| Reliability | `reliability` | `--reliability` | Missing retries, unbounded waits, missing cleanup. |

`all` selects every check. Omitting all checks also runs every check.

> **Dependencies ≠ vulnerability scanning.** UNDERSTAND reads manifests and
> reports what a project declares. It has no advisory feed, so dependency
> results describe declared versions, never known CVEs.

---

## 3. Scan options

### Source

| Form | Notes |
| --- | --- |
| `/path/to/project` | Local directory. Must exist and must be a directory. |
| `./relative/path` | Relative paths work; they resolve against the current working directory. |
| `https://github.com/owner/repo.git` | Requires `--allow-remote` **and** `security.allow_remote`. |
| `git@github.com:owner/repo.git` | Requires `--allow-remote`, `security.allow_remote` and `security.allow_ssh`. |

Remote hosts are **not** selected by a flag. There is deliberately no
`--allowed-host` option: the outbound allowlist comes from configuration
(`security.allowed_hosts` / `UNDERSTAND_ALLOWED_HOSTS`) so that a scan cannot
widen its own network permissions from the command line.

```bash
# Remote scanning, opt-in twice on purpose: once to allow remotes at all,
# once to name the hosts you trust.
export UNDERSTAND_ALLOW_REMOTE=1
export UNDERSTAND_ALLOWED_HOSTS=github.com
understand scan https://github.com/owner/repo.git security --deep --format json
```

### Feature and depth

| Option | Effect |
| --- | --- |
| `-d`, `--deep` | Deep profile. Slower and more thorough. |
| `-x`, `--cross-module` | Follow calls and imports across module boundaries. |
| `--profile NAME` | `standard` or `deep`. Overrides `--deep`. |

### Output

| Option | Effect |
| --- | --- |
| `--format FORMAT` | `text` (default), `json`, or `sarif`. |
| `-o`, `--output PATH` | Write to a file instead of stdout. |
| `--no-report` | Do not persist the report to the store. |
| `--fail-on SEVERITY` | Exit **2** if any finding at or above `SEVERITY` exists. For CI. |
| `--no-evidence` | Omit source evidence from findings. Smaller output. |
| `--no-execution-paths` | Omit execution-path data. Smaller output. |

### Resources and safety

| Option | Effect |
| --- | --- |
| `--max-files N` | Maximum files to inventory. |
| `--max-file-bytes N` | Skip files larger than this. |
| `--max-total-bytes N` | Stop after reading this much. |
| `--max-seconds N` | Wall-clock budget for the analysis itself. |
| `--timeout N` | How long the CLI waits before cancelling the scan. |
| `--local-root PATH` | Restrict local sources to these roots. Repeatable. |
| `--mode MODE` | `local` (default) or `hosted`, which hardens the network policy. |
| `--offline` | Skip the cache entirely. |
| `--no-cache` | Reuse cached scans is disabled; the scan always recomputes. |
| `--allow-remote` | Permit a remote source for this invocation. |

### Configuration and output control

| Option | Effect |
| --- | --- |
| `-c`, `--config PATH` | JSON configuration file. Also `UNDERSTAND_CONFIG`. |
| `--storage PATH` | Path to the scan database. |
| `-q`, `--quiet` | Errors only. |
| `-v`, `--verbose` | Tracebacks and debug logging on stderr. |
| `-h`, `--help` | Help. |

---

## 4. Recipes

### Local project, security and bug review, JSON to a file

```bash
understand scan ./my-project security bugs \
    --deep --cross-module --format json --output findings.json
```

### Fail CI on anything high or worse

```bash
understand scan . security --fail-on high --format sarif --output results.sarif
# exit 0  -> nothing at or above `high`
# exit 2  -> at least one finding at or above `high`
# other   -> the scan itself failed; read the message
```

### Re-read a stored report without rescanning

```bash
understand report list
understand report show scan-20260118-a1b2c3d4 --format json --limit 25
understand report show scan-20260118-a1b2c3d4 --limit 25 --offset 25
```

### Share a report

`--share` turns a stored report into a block you can paste into a chat, an
issue or a post. It carries the repository, the number of files, the findings
by severity and the top findings with their file and line.

```bash
understand report show scan-20260118-a1b2c3d4 --share
understand report show scan-20260118-a1b2c3d4 --share --format markdown
understand report show scan-20260118-a1b2c3d4 --share --format json
```

Nothing is uploaded when you use it: the block is printed for you to copy, and
the tool never contacts a server to produce it.

### Inspect one finding

```bash
understand finding show SEC-PY-SHELL-001-f4c30abdca5e --scan-id scan-20260118-a1b2c3d4
```

### Machine-readable capability document

```bash
understand capabilities | jq .
```

---

## 5. Exit codes

Exit codes follow the BSD `sysexits.h` convention, so a shell script can branch
on them without parsing text.

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Unexpected internal error. This is an UNDERSTAND defect. |
| `2` | A finding at or above `--fail-on` exists. **Not an error.** |
| `63` | The requested output format is not supported. |
| `64` | Invalid usage or invalid input. |
| `65` | The scan source could not be interpreted (missing, not a directory, malformed URL). |
| `66` | The requested scan id does not exist. |
| `67` | The requested finding id does not exist. |
| `69` | The repository could not be acquired (clone failed, size limits). |
| `70` | A resource limit was exceeded. |
| `71` | Analysis failed. |
| `72` | The source was blocked by network policy. |
| `74` | The scan store could not be read or written. |
| `77` | Access denied. |
| `78` | Configuration error. |
| `130` | The scan was cancelled (SIGINT). |

The same taxonomy is returned by the MCP tools in `error.code` and
`error.exit_code`, so a client can treat CLI and MCP failures identically.

---

## 6. Global options

Global options may appear **before** the command word:

```bash
understand --storage /var/lib/understand.db report list
```

`--storage`, `--config`/`-c`, `--mode`, `--local-root`, `--format`/`-f`,
`--out`/`--output`/`-o` are recognised globally. `report`, `finding` and
`config` also accept `--storage` / `--config` directly.

---

## 7. What the CLI deliberately does not do

- **It never executes repository code.** No `pip install`, no test runner, no
  build step. Findings come from static reading.
- **It never sends your code anywhere.** Telemetry is off by default and there
  is no analytics endpoint in the codebase.
- **It never guesses.** An unresolved call is reported as unresolved, not
  resolved to a likely name. A missing dependency advisory is reported as
  `not_performed`, not as "no vulnerabilities".