# Publishing to Smithery

Smithery is a registry and hosting platform for MCP servers. Once published, users install your server with one command instead of cloning and configuring it.

Two important things to settle before reading further:

- **Only the maintainer publishes.** Uploading requires `smithery auth login` against the account that owns the namespace you publish to. Nobody else — not a collaborator, not a user, not Smithery — can publish under your name. Anyone can *install* what you published, and anyone can fork it and publish their own build under their own name, but the canonical listing is yours.
- **Two routes exist, and they are not equivalent.** Which one you want is decided by one question: does your server need to be hosted by Smithery, or distributed as a file clients run locally?

| Route | Use when | Transport | What Smithery stores |
|---|---|---|---|
| **A. Public URL** | You will host the server | streamable-http | Nothing but metadata; you host |
| **B. MCPB bundle** | Clients should run it locally | stdio | A `.mcpb` archive |

For UNDERSTAND, **route A is the better fit**, because the server is a pure analysis engine with no per-user state to provision, and `streamable-http` is already implemented. Route B is valid if you want zero server-side cost.

---

## Prerequisites (both routes)

```bash
npm install -g smithery@latest      # Node.js 20+; the old package was @smithery/cli
smithery auth login                  # opens a browser; authenticates the OWNER
```

Check it worked:

```bash
smithery whoami
```

Do this **before** you publish anything, not after. If you are not logged in, every later command fails at the least convenient moment.

---

## Route A — publish a public URL

### Step 1: get the server running over HTTP

The URL must be reachable **from the public internet**, over **HTTPS**, and must speak **streamable HTTP**. It cannot be `127.0.0.1`.

Locally, to confirm the transport works:

```bash
python -m understand.mcp_server streamable-http
# in another shell, confirm the endpoint answers
curl -i -X POST http://127.0.0.1:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}'
```

An unauthenticated deployment should answer **401** with a `WWW-Authenticate` header (not 403) so OAuth discovery can start per RFC 9728. See [deployment.md](deployment.md) for what must sit in front of the server.

### Step 2: host it

Any of these work:

| Option | Notes |
|---|---|
| Docker on a VPS | The included `Dockerfile` already defaults to `streamable-http` on `0.0.0.0:8000`. Put Caddy/nginx in front for TLS. |
| Fly.io / Railway / Render | Use the Dockerfile; bind `0.0.0.0`; attach a volume for `/data`. |
| A company VM | Same, plus the auth and rate-limit layers from [deployment.md](deployment.md). |
| Smithery's own container runtime | Needs `smithery.yaml` + Dockerfile in the repo (below). |

Point `UNDERSTAND_STORAGE` at a **persistent volume**. On a fresh volume every scan is cold, and you lose the report cache.

### Step 3a: publish from the CLI

```bash
smithery mcp publish "https://your-server.example.com/mcp" \
  -n @your-org/understand
```

Add a config schema so users can see what they may configure:

```bash
smithery mcp publish "https://your-server.example.com/mcp" \
  -n @your-org/understand \
  --config-schema '{
    "type": "object",
    "properties": {
      "UNDERSTAND_STORAGE":    {"type": "string"},
      "UNDERSTAND_ALLOWED_HOSTS": {"type": "string"},
      "UNDERSTAND_ALLOW_REMOTE":  {"type": "string"},
      "UNDERSTAND_MAX_FILES":     {"type": "integer"}
    },
    "additionalProperties": false
  }'
```

### Step 3b: or publish from the web

Go to `smithery.ai/new`, enter the public HTTPS URL, and follow the flow. Use this if you would rather not put the URL in a shell history.

### Step 4: the server card fallback

Smithery scans your server to discover tools and resources. That scan can fail behind a WAF, an auth wall, or a flaky TLS chain. When it cannot complete, serve a **static server card** at:

```
https://your-server.example.com/.well-known/mcp/server-card.json
```

```json
{
  "serverInfo": { "name": "UNDERSTAND", "version": "0.1.0" },
  "tools": [
    { "name": "scan_repository",      "description": "Analyse a repository and return a scan id." },
    { "name": "get_scan_status",      "description": "Poll a running scan." },
    { "name": "cancel_scan",          "description": "Cancel a queued or running scan." },
    { "name": "get_scan_report",      "description": "Read a report, filtered and paginated." },
    { "name": "inspect_finding",      "description": "Full evidence and interpretation for one finding." },
    { "name": "trace_execution",      "description": "Call-graph paths from a symbol." },
    { "name": "trace_data_flow",      "description": "Source-to-sink flows for a finding." },
    { "name": "analyze_change_impact","description": "Blast radius of a proposed change." },
    { "name": "query_codebase",       "description": "Filter findings across fields." }
  ],
  "resources": [
    { "uri": "understand://capabilities",  "name": "capabilities", "mimeType": "application/json" },
    { "uri": "understand://security-model","name": "security-model", "mimeType": "text/markdown" }
  ]
}
```

`serverInfo` is required. Everything else is optional but improves discovery. The schema follows the SDK types (SEP-1649).

### Step 5: verify

```bash
npx @smithery/cli playground --port 8081
```

Then open the playground, pick your server, and run `scan_repository` against a small local path. The distribution page is `smithery.ai/server/<your-name>`.

---

## Route B — publish an MCPB bundle

Use this if you want clients to run the server locally and you have no server to host.

### Step 1: `smithery.yaml` in the repo root

```yaml
startCommand:
  type: stdio
  configSchema:
    type: object
    properties:
      UNDERSTAND_CONFIG:
        type: string
        description: Path to a JSON configuration file.
      UNDERSTAND_STORAGE:
        type: string
        description: Where to keep the scan database.
      UNDERSTAND_ALLOW_REMOTE:
        type: string
        description: "true to permit scanning remote git repositories."
      UNDERSTAND_ALLOWED_HOSTS:
        type: string
        description: Comma-separated outbound host allowlist.
      UNDERSTAND_MAX_FILES:
        type: integer
        description: Maximum files to read in one scan.
    additionalProperties: false
  commandFunction: |
    (config) => ({
      command: 'python',
      args: ['-m', 'understand.mcp_server', 'stdio'],
      env: {
        ...(config.UNDERSTAND_CONFIG !== undefined && { UNDERSTAND_CONFIG: String(config.UNDERSTAND_CONFIG) }),
        ...(config.UNDERSTAND_STORAGE !== undefined && { UNDERSTAND_STORAGE: String(config.UNDERSTAND_STORAGE) }),
        ...(config.UNDERSTAND_ALLOW_REMOTE !== undefined && { UNDERSTAND_ALLOW_REMOTE: String(config.UNDERSTAND_ALLOW_REMOTE) }),
        ...(config.UNDERSTAND_ALLOWED_HOSTS !== undefined && { UNDERSTAND_ALLOWED_HOSTS: String(config.UNDERSTAND_ALLOWED_HOSTS) }),
        ...(config.UNDERSTAND_MAX_FILES !== undefined && { UNDERSTAND_MAX_FILES: String(config.UNDERSTAND_MAX_FILES) }),
      },
    })
```

For an HTTP server, change `type` to `http` and add a `build.dockerfile` or `build.dockerBuildPath` pointing at the repo `Dockerfile`.

Two things about that `commandFunction`:

- It is a **JavaScript arrow function evaluated by Smithery**, not a shell command. It must return `{ command, args, env }`.
- The conditional spreads matter. `...(x !== undefined && { X: String(x) })` means an unset value is simply absent, so the server's own defaults still apply. Writing `UNDERSTAND_ALLOW_REMOTE: config.x` unconditionally would set the variable to `"undefined"` and break the default.

### Step 2: build the bundle from source

The bundle is reproducible from the working tree. One command stages it and
packs it:

```bash
npm install -g @anthropic-ai/mcpb
python tools/build_mcpb.py --out-dir dist
```

That writes `dist/understand-mcp-<version>.mcpb`. The builder copies
`pyproject.toml`, `README.md`, `LICENSE` and the `src/` tree into a staging
directory, writes the `manifest.json` and a small `server/main.py` shim, and
then calls `mcpb pack`. The shim imports the bundled source directly and, if
the runtime dependencies are missing, creates a `.venv` next to the bundle and
installs `understand-mcp` from PyPI before starting the server.

The release workflow does the same thing and attaches the result to the GitHub
release, so a published `.mcpb` always matches a published tag.

### Step 3: publish the bundle

```bash
smithery mcp publish ./server.mcpb -n your-org/understand
```

Smithery distributes the bundle; clients download and run it locally.

**Honest warning about route B:** a stdio bundle must be able to reach `python` and install the package. Smithery's model for this is a container image that holds your runtime, not a bare `pip install` on the user's machine. A `.mcpb` that assumes a working Python on the user's laptop will fail for anyone who does not have one. This is the main reason route A is the better fit here.

---

## Scoring your listing

Roughly what moves a listing up:

| Item | Worth |
|---|---|
| A declared config schema | 10 |
| Every schema property **optional** | 15 |
| Actually deployed and reachable | high |
| Tools with real descriptions | high |
| Resources published | moderate |
| Custom icon | small |

"Every property optional" is not vanity: an optional property is one a user is never forced to answer, and required properties are the main reason MCP config screens feel hostile.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403` during the scan | A WAF is blocking Smithery's crawler (Cloudflare Bot Fight Mode blocking `SmitheryBot/1.0`) | Allow-list the bot, or serve a static server card |
| `401` loop | Auth layer returns 401 for the discovery document too | Let `/.well-known/...` and `/mcp` return 401 **with** `WWW-Authenticate`; do not return 403 |
| Scan times out | The tool timeout is shorter than a deep scan | Raise `tool_timeout_sec` / `timeout` on the client; see [clients.md](clients.md) |
| Server not found after publish | Name collision, or namespace typo | `smithery mcp list`, then `smithery mcp update` |
| Tools missing from the listing | Discovery scan failed | Static server card |
| Container will not start | Image lacks `sh`, or does not bind `0.0.0.0` | The included Dockerfile handles both; confirm you did not override `ENV` |

---

## After publishing

```bash
smithery mcp list                 # your servers
smithery mcp get <name>           # inspect the listing
smithery mcp update <name>        # re-push metadata
smithery mcp remove <name>        # unpublish
smithery tool list                # what the CLI can call
```

Add the listing to `README.md` once it exists.

---

## Related

- [deployment.md](deployment.md) — what must sit in front of the server
- [clients.md](clients.md) — per-client configuration
- [security-model.md](security-model.md) — what the server does and does not do