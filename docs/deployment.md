# Deployment

How to run UNDERSTAND outside your own machine. Three shapes, in increasing order of exposure:

| Shape | Transport | Who talks to it | Typical use |
|---|---|---|---|
| Local stdio | stdio | One AI client, one user | Desktop assistants, IDE plugins, CI jobs |
| Local HTTP | streamable-http | Anything on your machine | Your own agent code, shared team server |
| Remote HTTP | streamable-http | Anything on the internet | Hosted deployment, [Smithery](smithery.md) |

The engine is identical in all three. Only the transport changes.

---

## 1. Local stdio (default, recommended)

The client starts the server as a child process and speaks to it over stdin/stdout. Nothing listens on a port, nothing is exposed to the network.

```
AI client  ──spawn──>  python -m understand.mcp_server
     │                              │
     └──── stdio frames ────────────┘
```

```bash
python -m understand.mcp_server              # stdio (default)
python -m understand.mcp_server stdio        # explicit
```

Configuration per client is in [clients.md](clients.md).

**Two things that matter in practice:**

- **stdout must stay clean.** The server logs exclusively to stderr. If you wrap it in a shell script, never `echo` anything.
- **Raise the client's timeout.** Client defaults are usually 5–60 seconds. A `--deep` cross-module scan of a large repository takes minutes. A too-low timeout looks exactly like "the server is broken" — it is the most common false alarm.

---

## 2. Local HTTP

```bash
python -m understand.mcp_server streamable-http
# defaults: 127.0.0.1:8000
```

```bash
UNDERSTAND_MCP_HOST=127.0.0.1 \
UNDERSTAND_MCP_PORT=8000 \
python -m understand.mcp_server streamable-http
```

| Variable | Default | Meaning |
|---|---|---|
| `UNDERSTAND_MCP_TRANSPORT` | `stdio` | `stdio`, `streamable-http`, or `sse` |
| `UNDERSTAND_MCP_HOST` | `127.0.0.1` | Bind address for HTTP transports |
| `UNDERSTAND_MCP_PORT` | `8000` | Bind port |
| `UNDERSTAND_CONFIG` | unset | Path to a JSON config file |
| `UNDERSTAND_LOG_LEVEL` | `WARNING` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

The endpoint is `http://<host>:<port>/mcp`.

`sse` is accepted for older clients and is not recommended for new deployments.

### Authentication for a local HTTP server

**There is none, and that is intentional.** The server has no built-in auth layer; it binds loopback and trusts the local user boundary. Anyone who can reach the socket can run analysis and read the scan store.

Consequences to be explicit about:

- It must not be bound to `0.0.0.0` on a machine you do not control.
- It must not be exposed through a reverse proxy without auth in front.
- The **scan store is readable through the tools**. `get_scan_report` returns whatever the configured `storage_path` holds, so a shared HTTP server on a shared database is a shared read of every scan that database has ever held. Point `UNDERSTAND_STORAGE` at a directory the deploying user owns, and treat the database as sensitive: it contains findings about internal code, including file paths, symbol names and (redacted) source snippets.

For a team, prefer per-developer stdio, or run the remote deployment below behind real auth.

---

## 3. Remote HTTP

### 3.1 Container

The included `Dockerfile` is a two-stage build producing a small `python:3.12-slim` runtime that runs as an unprivileged user and defaults to `streamable-http` on `0.0.0.0:8000`.

```bash
docker build -t understand-mcp .
docker run --rm -p 8000:8000 \
  -v "$PWD/data:/data" \
  understand-mcp
```

The image's defaults:

```
UNDERSTAND_MCP_TRANSPORT=streamable-http
UNDERSTAND_MCP_HOST=0.0.0.0
UNDERSTAND_MCP_PORT=8000
UNDERSTAND_STORAGE=/data/scans.db
UNDERSTAND_LOG_LEVEL=WARNING
```

`/data` is a volume owned by uid 10001 so the scan store survives restarts.

Running the image as a **stdio** server (for clients that start containers themselves):

```bash
docker run --rm -i -v "$PWD:/repo" understand-mcp stdio
```

Notes:

- The base image is `python:3.12-slim`, **not** distroless, because a shell must exist inside the container for hosting platforms that exec into it.
- The HEALTHCHECK reports healthy when no HTTP listener exists, so the same image is usable in stdio mode without being marked unhealthy.

### 3.2 Directly, without a container

```bash
pip install .
UNDERSTAND_MCP_TRANSPORT=streamable-http \
UNDERSTAND_MCP_HOST=0.0.0.0 \
UNDERSTAND_STORAGE=/var/lib/understand/scans.db \
understand-mcp-server
```

### 3.3 What you MUST add before exposing it publicly

The server is honest about analysis; it is not hardened for the public internet. A deployment that is reachable from untrusted networks needs, at minimum:

1. **TLS.** Terminate it at a reverse proxy or load balancer.
2. **Authentication and authorisation.** The server has none. `get_scan_report` and `query_codebase` will return any scan id you can name. This is a read-your-own-database endpoint unless you put auth in front of it.
3. **Multi-tenancy.** There is none. Scans from different users share one store and are mutually readable. Do not present this to mutually-distrusting users without adding isolation.
4. **Per-request source restrictions.** `allowed_roots` / `local_roots` must be pinned. Otherwise any client can ask the server to read any path the process can read.
5. **Resource budgets.** Set `UNDERSTAND_MAX_FILES`, `UNDERSTAND_MAX_FILE_BYTES`, `UNDERSTAND_MAX_TOTAL_BYTES` and `UNDERSTAND_WORKERS` for the machine you actually have. The defaults are generous.
6. **A rate limit** on `scan_repository`. Analysis is CPU- and memory-heavy; an unbounded endpoint is a denial-of-service endpoint.
7. **A secrets-free environment.** Never pass API keys or tokens as `env` in the MCP client config — they are visible to the process and to anything that dumps the environment. Use the config file for settings instead (see [configuration.md](configuration.md)).

`mode: hosted` exists for this situation. It forces `allow_http=false`, `allow_ssh=false` and `block_private_networks=true`, so a hosted deployment cannot be talked into fetching from a private network or an insecure scheme. Set it, and do not weaken it per request.

### 3.4 OAuth and RFC 9728

[Smithery](smithery.md) and other hosts require unauthenticated requests to return **401**, never 403, so that OAuth discovery can begin (RFC 9728 / RFC 9728-protected-resource-metadata). Terminate auth at your proxy and return `401` with a `WWW-Authenticate` header pointing at your authorisation server's metadata document.

---

## 4. CI

The CLI is the CI-friendly interface; the MCP server is not (it is long-lived and client-oriented).

```bash
python -m pip install understand-mcp
understand scan "$CHECKOUT" security bugs architecture --deep --format sarif -o results.sarif
```

Gate the build on findings:

```bash
understand scan "$CHECKOUT" security --fail-on high   # exits 2 when high or critical exists
```

Exit codes are documented in [cli.md](cli.md). In short: `0` clean, `2` the `--fail-on` threshold was met, `1` an internal defect, everything else a specific failure you can branch on.

Upload `results.sarif` to GitHub code scanning — it is valid against the OASIS SARIF 2.1.0 schema (verify with `python tools/validate_sarif.py results.sarif`).

Cache the database between runs to get report reuse:

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.understand
    key: understand-${{ hashFiles('**/*.py', '**/*.js', '**/*.ts') }}
```

---

## 5. Operational checklist

| Check | Why |
|---|---|
| `python -m pytest -q` | The suite must pass on the deploying machine's Python. |
| `python tools/validate_sarif.py` | SARIF stays schema-valid. |
| Scan store on a persistent volume | Otherwise every restart loses the cache. |
| Scan store permissions `0600`/owner-only | It contains internal code facts. |
| Log level `WARNING` or higher in production | `INFO` logs stage names; `DEBUG` logs exception detail. |
| Timeouts raised on the client side | Otherwise long scans look like connection failures. |
| Auth in front of any non-loopback listener | The server ships no auth. |