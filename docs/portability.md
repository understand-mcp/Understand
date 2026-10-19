# Portability

UNDERSTAND runs on **Linux, macOS and Windows** with no platform-specific build
step. This document explains what that claim rests on, so it can be checked rather
than believed.

---

## Supported versions

| Platform | Versions | Notes |
| --- | --- | --- |
| Linux | 3.10+ | Primary CI target. The container image is `python:3.12-slim`. |
| macOS | 3.10+ | Intel and Apple Silicon. No native extensions are compiled. |
| Windows | 3.10+ | Where most path-handling subtlety lives; see below. |

Python 3.10 is the floor because the code uses `X \| Y` union syntax at runtime in
annotations and `match`-free control flow only.

There are **no compiled dependencies**. `mcp` and `pydantic` (plus `pydantic-core`,
which ships prebuilt wheels) are the only runtime requirements, so there is no
compiler, no Rust toolchain and no platform wheel to hunt for. `git` is needed
**only** for remote repository scanning; local scans need nothing beyond Python.

---

## How the code stays platform-neutral

Every OS-dependent construct in `src/` was located and reviewed. The complete list
is short, and each entry is deliberate.

### POSIX semantics used on purpose, on every platform

Repository-relative paths are a **contractual format**, not a filesystem path. They
are always `/`-separated, forward-slash-only, relative to the repository root.
`normalize_relpath()` enforces this on the way in, so downstream code is free to use
POSIX semantics regardless of the host OS:

| Location | Construct | Why it is correct |
| --- | --- | --- |
| `application/impact_service.py` | `posixpath.normpath()` | Normalising an already-POSIX relative path must use POSIX rules, or `a/b` and `a\b` would be treated as different files. |
| `engine/dependency_analysis.py:192`, `engine/parsing.py:233`, `engine/symbol_index.py:190,336,446` | `PurePosixPath(relpath).name` | Extracts the basename from a repo-relative path. Using `PureWindowsPath` here would break on any name containing a colon. |
| `security/path_validation.py:33` | `PurePosixPath(text).parts` | Splits a normalised relative path into segments. |
| `storage/cache.py:97` | `rel_dir.as_posix()` | Cache keys must be identical across platforms, or a cache written on Linux would never be read on Windows. |

### Branches that genuinely differ by OS

| Location | Behaviour |
| --- | --- |
| `security/path_validation.py:105` | Drive-root guard. On Windows (`os.name == "nt"`) a scan of `C:\` is refused; on POSIX the equivalent check is inherent in the path model. |
| `security/path_validation.py:130` | `relative_to_root()` returns `PureWindowsPath(...).as_posix()` on Windows so the stored key is still POSIX-form. |
| `security/safe_git.py:259,323` | On Windows, `SYSTEMROOT`, `SystemRoot`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA` and `LOCALAPPDATA` are copied into the hardened git environment. Without these, `git.exe` fails to start at all. |
| `security/safe_git.py:256,286,293,319` | `os.devnull` throughout. Resolves to `nul` on Windows, which git accepts for `core.hooksPath` and `credential.helper`. |

There are **no `sys.platform` checks and no hardcoded `/bin/...` or `/tmp/...`
paths** anywhere in `src/`.

### The one place the platforms genuinely disagree

`reporting/__init__.py::safe_output_path()` refuses to write reports into protected
directories. The list includes POSIX entries such as `/etc` and `/bin`, but on
Windows a candidate like `/etc/report.json` is re-anchored onto the current drive
(`C:\etc\report.json`) before any comparison happens. A naive string prefix check
therefore never matches, and the guard silently does nothing.

The fix is to resolve **both** sides fully and normalise case before comparing:

```python
text = os.path.normcase(str(normalized))
for protected in _PROTECTED:
    if not protected:
        continue
    root = os.path.normcase(os.path.abspath(protected))
    try:
        if os.path.commonpath([text, root]) == root and text != root:
            raise UnsupportedFormatError(f"refusing to write into protected location {root}")
    except ValueError:  # pragma: no cover - different drives
        continue
```

Both normalisation and case-folding are required: `commonpath` returns the
first-seen casing, which would otherwise never equal the lower-cased `root`.
`test_safe_output_path_refuses_protected_locations` covers this.

---

## Installing on each platform

### Linux

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install understand-mcp
git config --global --add safe.directory '*'   # optional, see below
understand-mcp-server
```

### macOS

Identical; substitute `python3.11` (or any 3.10+) if that is what you have.
If `git` is managed by Homebrew or Xcode CLT, it is already present.

### Windows

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install understand-mcp
understand-mcp-server
```

If PowerShell refuses to run the activation script:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Use the **absolute** path to the interpreter in client configs rather than relying
on `python` being on `PATH`:

```json
{ "command": "C:\\Users\\you\\project\\.venv\\Scripts\\python.exe",
  "args": ["-m", "understand.mcp_server"] }
```

`where.exe python` and `Get-Command python` will tell you which interpreter a
client will actually use.

---

## Platform-specific behaviour a user will notice

### Windows drive letters in reports

SARIF and JSON outputs carry repository-relative paths, so a finding on Windows
reads `app/api.py`, not `C:\Users\you\project\app\api.py`. This is intentional:
reports are portable and diffable across machines.

### Symlink handling

Symlinks are **not** followed by default (`analysis.follow_symlinks` is `false`).
`resolve_within()` resolves a path before comparing it to the root, so a symlink
pointing outside the repository is refused even in that mode. The test
`test_resolve_within_blocks_symlink_escape` skips itself on Windows hosts without
developer mode, because creating a symlink there requires elevation.

### Case sensitivity

Windows and macOS are case-insensitive filesystems; Linux is not. UNDERSTAND
compares paths **case-insensitively** for security decisions
(`safe_output_path` uses `os.path.normcase`) and **case-sensitively** for symbol
and finding identity. Two files differing only in case are therefore one file to
the containment check on Windows but two to the index on Linux. This is a property
of the underlying filesystem, not a divergence in the code.

### `git` and `safe.directory`

When scanning a repository owned by another user (common in containers and CI),
git refuses to operate and reports *dubious ownership*. UNDERSTAND reports that
failure honestly as an acquisition error rather than working around it. The fix is
on git's side:

```bash
git config --global --add safe.directory '<path>'
```

### Long paths

Windows caps paths at 260 characters unless the long-path setting is enabled.
Repository-relative paths inside UNDERSTAND stay well under that; only a very
deeply nested absolute working directory could hit the limit, and it does so in
the OS, before UNDERSTAND sees the path.

---

## The container image

A `Dockerfile` is included. It is Linux by definition — a container image has no
Windows or macOS variant — so it is one deployment option, not the portability
story. Native install works everywhere.

The image is built for the streamable-HTTP shape (Smithery and shared
deployments): it runs as an unprivileged user, exposes port 8000, and defaults
`UNDERSTAND_MCP_HOST` to `0.0.0.0` so it accepts connections from outside the
container. For a stdio deployment, override the transport:

```bash
docker run --rm -i -v "$PWD:/repo" understand-mcp
```

A full `python:3.12-slim` base is used rather than distroless specifically because
Smithery's container runtime needs `sh`. See [deployment.md](deployment.md).

---

## Verifying portability yourself

```bash
python -m pytest -q                    # the suite runs on any platform
python tools/validate_sarif.py         # output must be platform-independent
```

The tests use `tmp_path`, so they exercise the real filesystem of whichever host
runs them. `test_resolve_within_blocks_symlink_escape` is the only test that
self-skips, and only when the OS cannot create symlinks.

To confirm the shipped report format is not platform-dependent:

```bash
understand scan . --format sarif -o report.sarif
python tools/validate_sarif.py report.sarif
# must print: result : VALID against the OASIS SARIF 2.1.0 schema
```