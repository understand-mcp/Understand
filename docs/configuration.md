# Configuration

Configuration is resolved from three sources, in increasing priority:

1. Built-in defaults.
2. Environment variables (every one prefixed `UNDERSTAND_`).
3. A JSON configuration file.
4. Command-line flags — **for the CLI only**.

`understand config show` prints the effective configuration, which is the
fastest way to answer "why is it behaving like this?".

---

## 1. Top level

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `storage_path` | `UNDERSTAND_STORAGE` | `~/.understand/scans.db` | SQLite database holding scans, findings, stages and cache entries. |
| `mode` | `UNDERSTAND_MODE` | `local` | `local` or `hosted`. `hosted` hardens the network policy (see §5). |
| `local_roots` | `UNDERSTAND_LOCAL_ROOTS` | unset | Directories local sources are restricted to. Comma-separated. |
| `telemetry` | `UNDERSTAND_TELEMETRY` | `false` | Kept at `false`. No analytics endpoint exists in the codebase. |
| `log_level` | `UNDERSTAND_LOG_LEVEL` | `INFO` | Log verbosity for analysis. The MCP server defaults to `WARNING`. |
| `max_workers` | `UNDERSTAND_WORKERS` | `8` | Worker threads for concurrent scans. |
| — | `UNDERSTAND_CONFIG` | unset | Path to the JSON configuration file. |

## 2. `security`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `allow_remote` | `UNDERSTAND_ALLOW_REMOTE` | `false` | Permit fetching remote git URLs. |
| `allow_http` | `UNDERSTAND_ALLOW_HTTP` | `false` | Permit plain `http://` remotes. Almost never what you want. |
| `allow_ssh` | `UNDERSTAND_ALLOW_SSH` | `false` | Permit `ssh://`, `git+ssh://` and `git@host:path`. |
| `allowed_hosts` | `UNDERSTAND_ALLOWED_HOSTS` | unset | Outbound allowlist. Empty means "any host that passes the other checks". |
| `block_private_networks` | `UNDERSTAND_BLOCK_PRIVATE_NETWORKS` | `true` | Refuse loopback, private, link-local, multicast and reserved destinations. |
| `clone_depth` | `UNDERSTAND_CLONE_DEPTH` | `25` | `--depth` for shallow clones. |
| `recurse_submodules` | `UNDERSTAND_SUBMODULES` | `false` | Clone submodules. Off by default: submodules are a common supply-chain path. |
| `allow_private_repo_credentials` | `UNDERSTAND_ALLOW_PRIVATE_CREDS` | `false` | Let a credential helper supply credentials. Only meaningful with SSH. |
| `clone_timeout_seconds` | `UNDERSTAND_CLONE_TIMEOUT` | `180.0` | Wall-clock bound on a single `git` invocation. Floor of 5s is enforced. |
| `max_clone_bytes` | `UNDERSTAND_MAX_CLONE_BYTES` | `536870912` (512 MB) | Refuse to fetch a repository larger than this. |
| `execute_repo_code` | *none — config file only* | `false` | Must stay `false`. UNDERSTAND never executes analysed repository code; this field exists so a hosted deployment can assert the invariant. There is deliberately no environment variable, so a process environment cannot turn it on. |
| `respect_git_hooks` | *removed — not configurable* | `false` | Git hooks from an untrusted repository are never run: `git` is always invoked with `core.hooksPath=<devnull>` and `protocol.*.allow=never`. An earlier version of this field suggested hooks could be re-enabled; they cannot, and the switch was deleted rather than left as a setting that lies. |

> **Remote scanning is opt-in twice.** `--allow-remote` on the command line is
> not sufficient on its own: `security.allow_remote` must also be true, and the
> host must pass validation. Two independent switches mean one stray flag
> cannot open the network.

## 3. `analysis`

| Setting | Environment variable | Default | Meaning |
| --- | --- | --- | --- |
| `max_file_bytes` | `UNDERSTAND_MAX_FILE_BYTES` | `2000000` | Skip files larger than this. |
| `max_files` | `UNDERSTAND_MAX_FILES` | `20000` | Maximum files to inventory. |
| `max_total_bytes` | `UNDERSTAND_MAX_TOTAL_BYTES` | `536870912` | Stop after reading this much (512 MB). |
| `follow_symlinks` | `UNDERSTAND_FOLLOW_SYMLINKS` | `false` | Follow symlinks. Off by default: a symlink can point outside the repository. |

Policy-level exclusions — excluded directories, excluded globs and sensitive
globs — live in `AnalysisPolicy` with curated defaults (`.git`, `node_modules`,
`vendor`, `*.min.js`, `*.lock`, binary formats, and so on). They are applied to
every scan and are recorded, with reasons, in `coverage.exclusions` so a report
can always explain what was left out.

## 4. Per-request budgets

Some limits belong to a single scan rather than to the installation. They are
set per request (CLI flag or MCP argument) and default to the `analysis`
values:

| Limit | CLI flag | MCP argument |
| --- | --- | --- |
| Files | `--max-files` | `max_files` |
| File size | `--max-file-bytes` | `max_file_bytes` |
| Total size | `--max-total-bytes` | — |
| Time | `--max-seconds` | `max_seconds` |
| Symbols | — | `limits.max_symbols` |
| Findings | — | `limits.max_findings` |
| Graph depth | — | `limits.max_call_graph_depth` |

The effective value for a scan is the **smaller** of the request budget and the
configured policy limit. A request can tighten a budget, never widen it.

## 5. `hosted` mode

Setting `mode` to `hosted` is the posture you want when other people's code is
being analysed on your infrastructure:

| Setting | Effect in `hosted` mode |
| --- | --- |
| `security.allow_http` | forced `false` |
| `security.allow_ssh` | forced `false` |
| `security.block_private_networks` | forced `true` |
| repository code execution | never enabled, in any mode |

```bash
understand --mode hosted scan ./untrusted-project security --deep
```

## 6. Configuration file

JSON, pointed at with `--config` or `UNDERSTAND_CONFIG`:

```json
{
  "storage_path": "/var/lib/understand/scans.db",
  "mode": "local",
  "local_roots": ["/srv/repos"],
  "telemetry": false,
  "log_level": "INFO",
  "max_workers": 8,
  "security": {
    "allow_remote": true,
    "allow_http": false,
    "allow_ssh": false,
    "allowed_hosts": ["github.com", "gitlab.com"],
    "block_private_networks": true,
    "clone_depth": 25,
    "recurse_submodules": false,
    "allow_private_repo_credentials": false
  },
  "analysis": {
    "max_file_bytes": 2000000,
    "max_files": 20000,
    "max_total_bytes": 536870912,
    "follow_symlinks": false
  }
}
```

Malformed JSON raises `configuration_error` (exit code 78) naming the file,
rather than silently falling back to defaults. A non-integer numeric
environment variable raises the same error, naming the variable and the value it
could not parse.

---

## 7. Verifying configuration

```bash
# Effective configuration and where each value came from.
understand config show

# Machine-readable capability manifest.
understand capabilities
```

Both are the fastest way to settle a "it behaves differently on my machine"
question before looking anywhere else.