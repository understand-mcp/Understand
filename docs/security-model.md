# Security model

This document states what UNDERSTAND trusts, what it refuses to do, and where the
controls live. It is written to be checkable: each claim names the module that
implements it.

## The threat model

UNDERSTAND is pointed at repositories it did not author. The adversary here is
**the repository**: files whose names are hostile, whose contents are adversarial
(including text engineered to look like instructions), whose build manifests
reference remote locations, and whose git remotes point at internal services.

The adversary is *not* assumed to be a network attacker. The tool does not expose
a network service by default and, when it does, network policy is enforced
separately (see [deployment.md](deployment.md)).

## Invariants

These are the guarantees the code is built around.

1. **UNDERSTAND never executes analysed repository code.** No stage runs, imports,
   builds or evaluates anything from the repository. The only subprocess the tool
   ever starts is `git`, with an explicit argv list, `shell=False`, hooks
   disabled and prompts disabled — and only for remote acquisition.
2. **No tool reads an arbitrary path from the model.** Every filesystem
   operation is derived from a source the operator configured, then re-validated
   to be inside an authorized root.
3. **Repository content is data, never instruction.** File contents are scanned,
   never obeyed. Prompt-injection text inside a source file is treated as text.
4. **Nothing is invented.** See "Honesty" below.
5. **Secrets do not leave the process.** Redaction runs on report bodies, snippets
   and error messages before serialization.

## Trust boundaries

```
 operator / AI client
        │  (configuration, authorized roots, opt-in flags)
        ▼
 ┌────────────────────────────────────────────┐
 │ MCP tool / CLI command  ← validation layer │  security/path_validation.py
 └────────────────────────────────────────────┘  mcp/schemas.py  (strict, extra=forbid)
        │  validated, typed arguments only
        ▼
 ┌────────────────────────────────────────────┐
 │ application/ — no direct filesystem access  │
 └────────────────────────────────────────────┘
        │
        ▼
 ┌────────────────────────────────────────────┐
 │ engine/ — reads only under policy          │  security/repository_policy.py
 └────────────────────────────────────────────┘        security/safe_git.py
        │
        ▼
   untrusted repository content  (treated as data)
```

## Path containment

`security/path_validation.py`:

- `normalize_relpath()` rejects absolute paths, drive letters, UNC paths, `..`
  segments, NUL bytes and control characters, and normalizes to a POSIX-style
  relative form. Repository-relative paths are the only currency inside the
  engine.
- `is_hostile_filename()` rejects Windows-reserved names (`CON`, `NUL`, `COM1`…),
  trailing dots and spaces, over-long names, alternate-data-stream syntax and
  embedded separators. A name that is unportable on Windows is refused
  everywhere, so results do not depend on the host OS.
- `resolve_within()` resolves both the root and the candidate with
  `os.path.realpath` **before** the containment test. Resolving first is what
  defeats the symlink-escape trick; comparing before resolving does not.
- `assert_local_source()` refuses a path that does not exist, is a file rather
  than a directory, is a filesystem root, or falls outside `allowed_roots`.

Symlinks are not followed by default (`analysis.follow_symlinks`).

## Exclusion policy

`security/repository_policy.py` decides what may be read:

- `FORBIDDEN_NAMES` (`.env`, `.netrc`, `id_rsa`, …) are never read, regardless of
  include rules.
- `sensitive_globs` are never read.
- Excluded directories (`.git`, `node_modules`, `vendor`, `dist`, virtualenv
  directories, …) are pruned.
- Generated and vendored files are excluded unless `analysis.allow_generated` is
  set. This is checked by `is_generated_path()`, which recognises path markers
  (`/vendor/`, `/generated/`, `/proto/`, `/migrations/`, …) and file-name markers
  (`*_pb2.py`, `*.pb.go`, `*.g.dart`, …).
- Hidden files are excluded.

Every exclusion carries a **reason**, recorded in `coverage.exclusions`. A tool
that silently skips files makes its coverage percentage meaningless.

## Remote acquisition and SSRF

`security/safe_git.py`. Remote scanning is **off by default**
(`security.allow_remote = False`). When enabled:

| Control | Implementation |
|---|---|
| Scheme allowlist | `https` only, plus `ssh`/`git+ssh` behind `security.allow_ssh`. Plain `http` is refused. |
| Credential stripping | URLs containing `username:password@` are rejected outright. |
| Argument injection | URLs containing whitespace or starting with `-` are rejected, so a URL can never become a `git` flag. |
| Host validation | Fully-qualified names with valid DNS labels; literals are checked directly. |
| Cloud metadata | A denylist of metadata endpoints (`169.254.169.254`, `metadata.google.internal`, …) is refused. |
| Private networks | Loopback, private, link-local, multicast, reserved and unspecified addresses are refused, including IPv4-mapped, 6to4 and Teredo forms. |
| DNS rebinding | Names are resolved and every returned address is validated **immediately before the clone**, not only at validation time. This is the reason resolution happens in `clone_remote()` and not in `parse_git_url()`. |
| Host allowlist | `security.allowed_hosts` restricts outbound destinations to an explicit set. |
| Clone limits | Shallow (`--depth`), `--no-tags`, submodules off by default, `protocol.ext.allow=never`, `protocol.file.allow=never`, `core.hooksPath` neutralised, `credential.helper=` cleared, `http.followRedirects=false`, `fetch.fsckObjects=true`. |
| Environment | `_safe_git_env()` builds a minimal environment: no inherited credentials, prompts disabled (`GIT_TERMINAL_PROMPT=0`), system and global git config disabled (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=os.devnull`). Credentials are only forwarded when explicitly allowed. |
| Size and time | Clone depth, clone timeout, and total repository size are bounded. |

Static URL validation is **deterministic and network-free**. That is
intentional: validation must be testable, reproducible and offline-safe.

## The sandbox

`security/sandbox.py`:

- `run_tool(argv, policy)` runs an external analyzer only if its executable is in
  the policy allowlist. Arguments are passed as an array, `shell=False`.
- The timeout is mandatory; exceeding it raises `ResourceLimitExceeded`.
- Output is size-capped.
- Only environment variables on the allowlist are forwarded.
- `Workspace` is a temporary directory that always cleans up.

## Redaction

`security/redaction.py` masks credential shapes in anything serialized:
AWS keys, GitHub tokens, Slack tokens, Google API keys, PEM private-key blocks
**and bare PEM markers**, JWTs, credentials embedded in URLs, and
assignment-shaped secrets. `redact_obj()` walks nested structures and pydantic
models. `redact_snippet()` bounds length before redaction.

Redaction is applied to report bodies, evidence snippets, notifications and error
messages. It is **not** a substitute for not collecting a secret in the first
place, and it is not guaranteed to catch every credential shape — which is
exactly why the engine never writes raw source bodies to storage by default.

## Honesty

The most important property of this tool is that it does not manufacture
confidence. Concretely:

- `confidence` describes evidence strength. `verification_status` describes how
  the finding was reached (`static_evidence`, `cross_module_trace`, `test_backed`,
  `reproduced`, `inconclusive`, `not_verified`). Neither is a claim about
  exploitability, and the MCP server instructions say so to the model explicitly.
- A finding without file/line evidence is still emitted, as a result **without a
  location**. A fabricated location would be worse than no location.
- Dependency vulnerability lookup is reported as `not_performed` unless a
  trusted advisory source is configured. The tool does not guess CVE ids or CVSS
  scores.
- Every report ends with a **Limitations** section. If the report has no
  limitations recorded, three are still emitted, because "nothing to say" is not
  the same as "nothing to worry about".
- Unresolved calls are counted and named, not hidden.
- Coverage is accounted honestly: analysed + skipped equals total, where skipped
  includes files the policy refused to read.

## Hosted mode

`--mode hosted` (or `mode: "hosted"` in config) hardens the network policy:
`allow_http=False`, `allow_ssh=False`, `block_private_networks=True`,
`execute_repo_code=False`. Use hosted mode whenever more than one person can
submit a repository.

## Reporting a vulnerability

Report security issues privately rather than in a public issue. Include the
version, the reproduction steps, and the impact. Do not include a working
exploit against a third party.