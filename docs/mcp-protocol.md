# The MCP Interface

This document is the contract between UNDERSTAND and any Model Context Protocol
client. It covers transports, the nine tools, the two resources, the response
envelope, and the rules a client is expected to follow.

Everything described here is implemented in
[`src/understand/mcp/`](../src/understand/mcp/) and is exercised by
`tests/integration/test_mcp.py` (27 tests).

---

## 1. Starting the server

The server is the thin module [`src/understand/mcp_server.py`](../src/understand/mcp_server.py),
which exists so the package can be launched by `python -m`, by Docker and by
Smithery without importing anything else first.

Three equivalent entry points:

| Command | When to prefer it |
| --- | --- |
| `python -m understand.mcp_server` | Clients that can run a Python interpreter with the package installed (most of them). |
| `understand-mcp-server` | Clients that want a bare executable name with no interpreter or module arguments. |
| `python -c "from understand.mcp.server import main; raise SystemExit(main())"` | Restricted launchers that allow only a single `-c` expression. |

### Transports

```
python -m understand.mcp_server [stdio|streamable-http|sse]
```

| Transport | Default | Use when |
| --- | --- | --- |
| `stdio` | yes | Desktop clients that spawn the process (Claude Desktop, Cursor, Codex, OpenCode, …). The client talks over stdin/stdout. |
| `streamable-http` | no | You host the server yourself and clients connect to `http://host:port/mcp`. **This is the transport Smithery requires for a hosted listing.** |
| `sse` | no | Legacy clients that predate Streamable HTTP. Kept for compatibility. |

### Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `UNDERSTAND_MCP_TRANSPORT` | `stdio` | Transport chosen when no argument is given. |
| `UNDERSTAND_MCP_HOST` | `127.0.0.1` | Bind address for the HTTP transports. **`0.0.0.0` is required to accept connections from outside a container.** |
| `UNDERSTAND_MCP_PORT` | `8000` | Port for the HTTP transports. |
| `UNDERSTAND_CONFIG` | unset | Path to a JSON configuration file (see [configuration.md](configuration.md)). |
| `UNDERSTAND_LOG_LEVEL` | `WARNING` | Log level **for the server process**. Analysis settings default to `INFO`; the server deliberately starts quieter because stderr is part of the protocol surface on stdio. |

> **stdio hygiene.** On stdio the server speaks JSON-RPC on stdout. UNDERSTAND
> writes all logging to **stderr**, so nothing corrupts the protocol stream. Do
> not add a client wrapper that redirects stdout.

---

## 2. The three resources

Resources are read-only documents a client can fetch without calling a tool.

| URI | Media type | Contents |
| --- | --- | --- |
| `understand://capabilities` | `application/json` | Machine-readable capability manifest: version, available checks, profiles, limits, output formats. Same document as `understand capabilities`. |
| `understand://security-model` | `text/markdown` | The security model in prose: what is read, what is never executed, what the remote policy allows, and the honesty guarantees. |

---

### `understand://map-schema`

The exact shape `get_code_map` returns: every field of `node`, `edge`, `stats`,
`layout` and `honesty`, plus the rules that govern them. Read it once and a
client can render or reason about a map without guessing, and without a second
round trip to ask what a field means.

It is static text and changes only when the model does, so a client may cache it.

## 3. The ten tools

| Tool | Kind | Purpose |
| --- | --- | --- |
| `scan_repository` | mutating | Start a scan. Returns immediately or waits for completion. |
| `get_scan_status` | read-only | Poll a running scan, or inspect a finished one. |
| `cancel_scan` | mutating | Request cancellation of a queued or running scan. |
| `get_scan_report` | read-only | Fetch the report with filtering, pagination and optional stages. |
| `inspect_finding` | read-only | One finding in full: evidence, provenance, and a plain-language interpretation. |
| `trace_execution` | read-only | "What does this call reach?" — walk the call graph up or down. |
| `trace_data_flow` | read-only | "How does this value reach that sink?" — source-to-sink paths recorded by the scan. |
| `analyze_change_impact` | read-only | "What breaks if I change these files?" — reverse reachability plus related findings. |
| `query_codebase` | read-only | Search an existing report without rescanning. |

Only `scan_repository` and `cancel_scan` change server state; the other seven are
pure reads over stored reports. The MCP tool annotations (`readOnlyHint`,
`destructiveHint`, `idempotentHint`, `openWorldHint`) are set accordingly, so a
client can render the correct confirm/skip affordance without guessing.

### 3.1 `scan_repository`

| Argument | Type | Default | Meaning |
| --- | --- | --- | --- |
| `repository` | string, required | — | Local directory or remote git URL. |
| `checks` | array of enum | `[]` (all) | `security`, `bugs`, `architecture`, `dependencies`, `reliability`. |
| `profile` | `standard` \| `deep` | `standard` | Depth of analysis. |
| `cross_module` | boolean | `false` | Follow calls and imports across module boundaries. |
| `report_format` | `text` \| `json` \| `sarif` | `text` | Stored report format. |
| `include_evidence` | boolean | `true` | Attach source evidence to findings. |
| `include_execution_paths` | boolean | `true` | Attach execution paths. |
| `allow_remote` | boolean | `false` | Permit fetching a remote URL. Also requires `security.allow_remote`. |
| `offline` | boolean | `false` | Skip the cache entirely. |
| `use_cache` | boolean | `true` | Reuse a previous identical scan. |
| `max_files`, `max_file_bytes`, `max_seconds` | integer | from limits | Per-request resource budget. |
| `wait` | boolean | `true` | Block until the scan finishes. |
| `timeout_seconds` | number | from limits | How long to wait when `wait` is true. |

**Use `wait: false` on anything large.** A repository that takes ninety seconds
to scan will time out a client-side MCP call long before the scan is interesting
to discuss. The correct pattern for a large repository is:

```jsonc
// 1. start it, do not wait
{"repository": "/path/to/repo", "profile": "deep", "cross_module": true, "wait": false}
// -> {"ok": true, "scan_id": "scan-20260118-a1b2c3d4", "status": "queued", ...}

// 2. poll while you do something else
{"scan_id": "scan-20260118-a1b2c3d4"}
// -> {"ok": true, "status": "running", "current_stage": "parse_and_index", ...}

// 3. when it is terminal, read the report
{"scan_id": "scan-20260118-a1b2c3d4", "severity": ["critical", "high"], "limit": 25}
```

### 3.2 Reading findings

`get_scan_report` and `query_codebase` share the filter vocabulary:

| Argument | Meaning |
| --- | --- |
| `severity` | One or more of `critical`, `high`, `medium`, `low`, `info`. |
| `category` | Finding category, e.g. `security`, `bugs`. |
| `rule_id` | Exact rule identifier, e.g. `SEC-PY-SHELL-001`. |
| `file` | Repository-relative file path. |
| `language` | Source language. |
| `verification_status` | One or more of `static_evidence`, `cross_module_trace`, `test_backed`, `reproduced`, `inconclusive`, `not_verified`. |
| `query` | Free text over finding fields. |
| `include_suppressed` | Include findings the policy suppressed. Off by default. |
| `limit` | Page size, 1–500. Default 50. |
| `offset` | Page offset, ≥ 0. Default 0. |

### 3.3 Answer-size ceilings

Two constants in [`schemas.py`](../src/understand/mcp/schemas.py) bound what a
single response may carry:

| Constant | Value | Applies to | Why |
| --- | --- | --- | --- |
| `MAX_LIMIT` | 500 | `limit` on `get_scan_report` and `query_codebase` | A model, not a human, decides page size. 500 is the most one response should carry; anything larger is paged with `offset`. Every page returns `pagination.next_offset`, so **no result is ever unreachable — only not returned all at once.** |
| `MAX_TEXT_QUERY` | 200 characters | `query` | A real search term is a symbol name, a rule id or a phrase. Something longer is almost certainly a pasted file, which belongs in a scan, not in a filter. |

Exceeding either raises `validation_error`, so the client learns the limit
instead of silently receiving a truncated answer.

---

### 3.5 `get_code_map` -- the tenth tool

`scan_repository` answers questions about code. `get_code_map` answers them
about a shape: which module calls what, what inherits from what, how untrusted
input reaches a sink, where findings landed.

| Argument | Type | Default | Notes |
| --- | --- | --- | --- |
| `scan_id` | string | required | Must already be stored. |
| `view` | enum of ten | `module` | Which question the map answers. |
| `root` | string | `""` | Symbol id, file, directory or `file::symbol`. Empty means the whole repository. |
| `depth` | int 0-6 | 3 | Hops from the root. |
| `direction` | `out` / `in` / `both` | `both` | Which way to walk. |
| `kinds` | list of relation kinds | view's own set | At most 20. |
| `include_findings` | bool | true | Attach findings and source text to every node. |
| `max_nodes` | int 10-20000 | 2000 | Node budget. |
| `max_edges` | int 10-60000 | 8000 | Edge budget. |
| `html` | bool | false | Also return the single-file HTML. |

The result is `{"map": ..., "view": ..., "question": ..., "provenance": ...}`.
`map` is the renderable model: `nodes`, `edges`, `stats`, `layout`, `legend` and
`honesty`. `honesty.caveats` is not decoration -- it is the list of what the
analysis did not do, and it travels with every response.

**`html` is opt-in on purpose.** A client that wants to reason about this map
needs the nodes and edges as data. Forty megabytes of markup helps nobody and
would blow the context window of every model it was handed to. Ask for it only
when the intent is to write a file.

```json
{
  "scan_id": "scan-20261019-9da096c3",
  "view": "data_flow",
  "root": "tests/config/parquetReporter.ts::ParquetReporter.onEnd",
  "depth": 3,
  "html": false
}
```

When a client has a finding in hand, `understand map explain <finding_id>`
prints the same causal chain as prose and ends with the exact `map show` command
that draws it.

## 4. The response envelope

Every tool returns a plain object with the same three top-level keys.

### Success

```jsonc
{
  "ok": true,
  "tool": "get_scan_report",
  "scan_id": "scan-20260118-a1b2c3d4",
  "status": "completed",
  "findings": [ /* ... */ ],
  "pagination": {"total": 37, "offset": 0, "limit": 25, "next_offset": 25},
  "findings_by_severity": {"critical": 3, "medium": 1},
  "provenance": {"tool": "understand", "tool_version": "0.1.0", "note": "..."}
}
```

### Failure

```jsonc
{
  "ok": false,
  "tool": "get_scan_report",
  "error": {
    "code": "scan_not_found",
    "message": "unknown scan id 'scan-nope'",
    "detail": {"scan_id": "scan-nope"},
    "exit_code": 66,
    "recoverable": true,
    "retryable": false
  }
}
```

| Field | Meaning |
| --- | --- |
| `code` | Stable machine-readable identifier. See the error taxonomy below. |
| `message` | Human-readable, safe to show. Never contains secrets — tool output is redacted. |
| `detail` | Optional structured context (ids, limits, validation problems). |
| `exit_code` | The process exit code the CLI would use for the same condition, so a client can map CLI and MCP behaviour onto one vocabulary. |
| `recoverable` | Whether the caller can act and try again. |
| `retryable` | Whether retrying unchanged could plausibly succeed (currently: resource limits and storage failures). |

### Error codes

`invalid_source`, `access_denied`, `network_policy`, `acquisition_failed`,
`resource_limit_exceeded`, `analysis_error`, `scan_cancelled`, `scan_not_found`,
`finding_not_found`, `unsupported_format`, `storage_error`, `configuration_error`,
`validation_error`, `internal_error`, plus `invalid_input` for malformed arguments
that never reach the engine.

A failed **scan** is not a failed **tool call**: if the engine runs and the
repository turns out to be missing, `scan_repository` returns `ok: true` with a
report whose `status` is `failed` and whose `errors` explain why. The tool only
returns `ok: false` when the call itself could not be honoured.

---

## 5. What a client should do

The server ships these instructions to clients verbatim
(`INSTRUCTIONS` in [`server.py`](../src/understand/mcp/server.py)), so a
well-behaved client already knows them:

1. **Scan first, then ask.** Run `scan_repository` before anything else.
2. **Do not rescan to answer a question.** Use `query_codebase` or
   `get_scan_report` on the existing `scan_id`.
3. **Check `verification_status` before claiming a vulnerability.** A finding is
   a *static* result. `confidence: low` with `verification_status: inconclusive`
   means **unproven** — say so.
4. **Never invent a CVE id, CVSS score, file path or line number** that is not in
   tool output.
5. **Dependency vulnerability data is `not_performed`** unless a trusted advisory
   source has been configured. UNDERSTAND reads manifests; it does not have a
   vulnerability feed.
6. **Use `analyze_change_impact` before editing code**, and
   `trace_execution` / `trace_data_flow` when you need to justify *why*.

---

## 6. Safety properties

- **No tool executes repository code.** The only subprocess UNDERSTAND ever runs
  is `git`, with hooks disabled, no shell, credential helpers disabled and
  prompts disabled.
- **No tool accepts an arbitrary filesystem path to read.** Sources go through
  path containment; see [security-model.md](security-model.md).
- **The repository is untrusted data.** Instructions inside analysed files are
  never followed and never enter the model's instruction channel.
- **Findings are redacted on the way out.** Snippets pass through the same
  redaction used for reports, so an evidence snippet cannot leak an AWS key,
  a GitHub token or a private key that happened to be near the finding.