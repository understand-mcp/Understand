# Connecting UNDERSTAND to your AI client

UNDERSTAND speaks the Model Context Protocol, so the only thing a client needs to
know is **how to start one process and talk to it over stdio**. Every client that
implements MCP can host it. The configurations below differ only in file format and
field names.

If your client is not listed, the pattern is universal — see
[Universal pattern](#universal-pattern).

---

## Universal pattern

```bash
pip install understand-mcp
```

The server is then started three equivalent ways. Use whichever your client can express:

| Start command | Best when |
| --- | --- |
| `python -m understand.mcp_server` | any client that accepts an interpreter plus arguments |
| `understand-mcp-server` | the server is pip-installed and on `PATH` |
| `python -c "from understand.mcp.server import main; raise SystemExit(main())"` | the client insists on a single command string |

Whatever you choose, **stdio is the default transport**, so no URL, port or token is
involved. See [Remote (HTTP) deployment](deployment.md#remote-streamable-http-deployment)
for the network case.

### Two settings worth changing

| Setting | Why |
| --- | --- |
| **Working directory** | A scan of `.` resolves against the process's working directory. Point it at the repository you actually want analysed, or always pass an absolute path. |
| **Timeout** | Most clients default to 5–60 seconds. A deep cross-module scan of a large repository legitimately takes minutes. Raising the timeout prevents a mid-scan disconnect that loses the work. |

### Optional environment

| Variable | Default | Effect |
| --- | --- | --- |
| `UNDERSTAND_CONFIG` | unset | Path to a JSON config file. Same mechanism as the CLI's `--config`. |
| `UNDERSTAND_STORAGE` | `~/.understand/scans.db` | SQLite scan store. Put it somewhere writable for the user running the client. |
| `UNDERSTAND_ALLOW_REMOTE` | `false` | Must be `true` before the model may scan a remote git URL. |
| `UNDERSTAND_ALLOWED_HOSTS` | unset | Comma-separated host allowlist, e.g. `github.com,gitlab.com`. |
| `UNDERSTAND_LOG_LEVEL` | `WARNING` | `DEBUG` / `INFO` when diagnosing; logs go to **stderr**, never stdout. |

Full list: [configuration.md](configuration.md).

---

## The clients

### OpenCode

File: `opencode.json` (global `~/.config/opencode/opencode.json`, or per project).
Schema: <https://opencode.ai/config.json>

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

Remote instead of local:

```json
{
  "mcp": {
    "understand": {
      "type": "remote",
      "url": "https://understand.example.com/mcp",
      "enabled": true,
      "timeout": 600000
    }
  }
}
```

CLI: `opencode mcp list`, `opencode mcp auth <name>` (only needed when the server
returns 401 and OAuth is required), `opencode mcp logout <name>`.

> MCP tool definitions are added to the model's context. If you work across many
> projects, leave `enabled: false` globally and turn it on per project.

---

### Claude Desktop

File: `claude_desktop_config.json`.
macOS `~/Library/Application Support/Claude/claude_desktop_config.json` ·
Windows `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "understand": {
      "command": "python",
      "args": ["-m", "understand.mcp_server"],
      "env": {
        "UNDERSTAND_STORAGE": "/absolute/path/to/scans.db"
      }
    }
  }
}
```

Restart Claude Desktop after editing. Confirm the server is connected from the
tools menu (the wrench icon).

---

### Claude Code

```bash
claude mcp add understand -- python -m understand.mcp_server
```

Project-scoped instead of user-scoped:

```bash
claude mcp add understand --scope project -- python -m understand.mcp_server
```

To point at a repository, set the working directory explicitly:

```bash
claude mcp add understand -- python -m understand.mcp_server
# then edit the saved entry to add "cwd": "/path/to/repo"
```

---

### Codex (CLI, IDE extension and ChatGPT desktop)

All three share `~/.codex/config.toml`, so one entry covers every surface.

```toml
[mcp_servers.understand]
command = "python"
args = ["-m", "understand.mcp_server"]
startup_timeout_sec = 30
tool_timeout_sec = 900
enabled = true

[mcp_servers.understand.env]
UNDERSTAND_STORAGE = "/absolute/path/to/scans.db"
```

Remote (streamable HTTP):

```toml
[mcp_servers.understand]
url = "https://understand.example.com/mcp"
bearer_token_env_var = "UNDERSTAND_MCP_TOKEN"
tool_timeout_sec = 900
```

Useful per-server fields: `env_vars` (names to forward), `cwd`, `enabled`,
`required`, `enabled_tools`, `disabled_tools`,
`default_tools_approval_mode` (`auto`, `prompt`, `writes`, `approve`).

**Reduce context usage** with tool filtering — this is the highest-value knob
when the scan tools are not needed on every turn:

```toml
[mcp_servers.understand]
command = "python"
args = ["-m", "understand.mcp_server"]
enabled_tools = ["scan_repository", "get_scan_report", "inspect_finding"]
```

CLI: `codex mcp list`, `codex mcp login <name>`.

---

### Cursor

File: `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` globally.

```json
{
  "mcpServers": {
    "understand": {
      "command": "python",
      "args": ["-m", "understand.mcp_server"],
      "env": { "UNDERSTAND_STORAGE": "/absolute/path/to/scans.db" }
    }
  }
}
```

LM Studio and several other clients deliberately follow Cursor's format, so this
snippet often transfers unchanged.

---

### Gemini CLI

File: `~/.gemini/settings.json` (Windows: `%USERPROFILE%\.gemini\settings.json`).

```json
{
  "mcpServers": {
    "understand": {
      "command": "python",
      "args": ["-m", "understand.mcp_server"],
      "cwd": "/absolute/path/to/your/project",
      "timeout": 600000,
      "trust": true
    }
  }
}
```

Remote: use `url` for SSE, `httpUrl` for streamable HTTP, plus `headers`.

`${VAR}` / `$VAR` are expanded in `env` values on all platforms, `%VAR%` on
Windows. An undefined variable resolves to an empty string rather than an error.
`includeTools` / `excludeTools` restrict the exposed set (`excludeTools` wins).

---

### OpenClaw

CLI is the quickest path:

```bash
openclaw mcp add understand \
  --command python \
  --arg -m \
  --arg understand.mcp_server \
  --cwd /absolute/path/to/your/project
```

Remote:

```bash
openclaw mcp add understand \
  --url https://understand.example.com/mcp \
  --transport streamable-http
```

Verify what actually connected:

```bash
openclaw mcp doctor understand --probe
openclaw mcp status --verbose
openclaw mcp tools
```

Config keys: `command`, `args`, `env`, `cwd`, `url`, `transport`, `enabled`,
`connectionTimeoutMs`, `requestTimeoutMs`, `toolFilter.include`.

> **Known constraint.** OpenClaw filters a server's `env` against an interpreter-
> injection blocklist (`NODE_OPTIONS`, `PYTHONSTARTUP`, `PERL5OPT`, `RUBYOPT`,
> `BASHOPTS`, `KSH_ENV`, `DYLD_*`, `LD_*`, `BASH_FUNC_*`). This is correct
> behaviour — those variables can hijack interpreter start-up. Put settings in a
> JSON config file via `UNDERSTAND_CONFIG` instead of `env` if a value is
> rejected.

---

### LM Studio

LM Studio has hosted MCP since **v0.3.17 (build 10)**. Open the **Program** tab →
**Install** → **Edit mcp.json**, and paste:

```json
{
  "mcpServers": {
    "understand": {
      "command": "python",
      "args": ["-m", "understand.mcp_server"],
      "env": {}
    }
  }
}
```

From **v0.4.0** MCP is also available through the LM Studio API:

```json
{
  "integrations": [
    {
      "type": "ephemeral_mcp",
      "server_label": "understand",
      "server_url": "http://127.0.0.1:8000/mcp",
      "allowed_tools": ["scan_repository", "get_scan_report", "inspect_finding"]
    }
  ]
}
```

Two settings must be enabled: *Allow per-request MCPs* and, for `mcp.json` entries,
*Allow calling servers from mcp.json*.

> Two cautions specific to local models: an untrusted MCP server can run arbitrary
> code, and nine tool definitions consume a meaningful slice of a small local
> model's context window. Use `allowed_tools` to trim.

---

### VS Code (Copilot / MCP support)

File `.vscode/mcp.json` in the workspace, or user settings via
`mcp.json` / `settings.json`:

```json
{
  "servers": {
    "understand": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "understand.mcp_server"],
      "env": {}
    }
  }
}
```

---

## Clients without native MCP support

Not every AI runtime can host an MCP server. Being straight about this is more
useful than a config snippet that cannot work.

### Ollama

**Ollama has no MCP client.** It serves models over its own HTTP API and an
OpenAI-compatible endpoint; it does not read `mcp.json`, and there is no setting
that changes this.

To use UNDERSTAND with Ollama you need a **bridge** that speaks MCP on one side and
an OpenAI-compatible tool-calling interface on the other:

```
┌──────────┐  tool calls   ┌────────────────┐  MCP/stdio   ┌─────────────────┐
│  Ollama  │ ────────────► │  MCP ⇄ OpenAI  │ ───────────► │    UNDERSTAND   │
│ (model)  │ ◄──────────── │     bridge     │               │  (MCP server)   │
└──────────┘   results     └────────────────┘               └─────────────────┘
```

The bridge is generic; UNDERSTAND needs no changes for it. Two practical notes:

- The model must support **tool calling** for this to work at all. Most local
  models below ~7B do not do it reliably, so results get worse as context fills.
- Give the bridge a narrow tool list. UnderSTAND exposes nine tools; forwarding all
  nine to a small local model usually exceeds what it can use.

For a hosted model with MCP support, skip the bridge and use the client's native
configuration above.

### Remote-model providers

| Provider | MCP route |
| --- | --- |
| **OpenAI / ChatGPT** | No user-configured MCP servers in the consumer/desktop apps. Use Codex (above), or expose UNDERSTAND over streamable HTTP and call it from your own agent code. |
| **Anthropic Claude** | Native. Use Claude Desktop or Claude Code above. |
| **Google Gemini** | Native in Gemini CLI and the IDE extensions; see above. |
| **xAI Grok** | No user MCP configuration surface. Use an agent framework (LangChain, OpenAI Agents SDK, …) with an MCP adapter pointed at the stdio server. |
| **DeepSeek, Kimi, ZCode, and similar APIs** | No native MCP client. Same answer: an agent framework or your own MCP client implementation. |

For anything outside that list, the rule is unchanged: **the model never speaks MCP
directly — your client does.** If your client can spawn a process and speak JSON-RPC
over stdio, it can host UNDERSTAND. If it cannot, put an MCP-capable agent between
the model and this server.

---

### What a connected client can actually do

The server exposes **ten tools** and **three resources**. Nine tools analyse a
repository; `get_code_map` projects an already-stored scan into a bounded graph,
and `understand://map-schema` documents the exact shape it returns so a client
can read the result without guessing.

## Verifying the connection

1. **Start the server by hand.** `python -m understand.mcp_server` should sit
   silently — no output on stdout is the correct behaviour. If you see log lines,
   they are on stderr; that is fine, but the client must not merge the streams.
2. **Ask the client to list tools.** You should see all nine:
   `scan_repository`, `get_scan_status`, `cancel_scan`, `get_scan_report`,
   `inspect_finding`, `trace_execution`, `trace_data_flow`,
   `analyze_change_impact`, `query_codebase`.
3. **Run a smoke test** on a small repository:

   > Scan ./examples/small-repo with the security check and tell me the three
   > highest-severity findings, quoting the evidence for each.

4. **If nothing comes back**, raise the client's timeout first, then set
   `UNDERSTAND_LOG_LEVEL=DEBUG` and read the client's MCP log. Timeouts are far
   more common than connection failures.

---

## Related

- [mcp-protocol.md](mcp-protocol.md) — the wire-level contract
- [deployment.md](deployment.md) — running it as a shared HTTP service
- [configuration.md](configuration.md) — every setting
- [security-model.md](security-model.md) — what the server will and will not do