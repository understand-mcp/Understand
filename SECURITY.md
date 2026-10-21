# Security policy

## Supported versions

UNDERSTAND is pre-1.0. Security fixes land on the latest released version and
on `main`. Older versions are not patched.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |
| < 0.1   | no        |

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Report it privately through GitHub's security advisory form:
[Report a vulnerability](https://github.com/understand-mcp/Understand/security/advisories/new).

Include:

- what the problem is and what an attacker gains,
- the exact steps to reproduce it, including any input you used,
- the version or commit you tested,
- the impact: local information disclosure, arbitrary file read, code execution
  in the scanning host, denial of service, or something else.

You will get an acknowledgement within a few days. If the report is accepted, a
fix and a release go out, and the advisory is published with credit unless you
prefer otherwise.

## What the tool does with untrusted input

UNDERSTAND is a scanner. It is designed to be pointed at code you did not write,
so the following is treated as attacker-controlled:

- the repository contents, including file names, file sizes and file contents,
- symlinks inside a scanned tree,
- archive-like directory structures,
- the identifiers and messages inside source files.

The controls that follow from that are implemented in
`src/understand/security/`:

- **Path containment.** `assert_local_source()` resolves every path with
  `os.path.realpath` and refuses anything that escapes the allowed roots. A
  filesystem root is refused outright, because scanning one is unbounded.
- **Symlink handling.** Symlinks that point outside the scanned root are not
  followed.
- **Resource budgets.** File count, per-file size, total bytes, worker count and
  wall-clock time are all capped. Exceeding a cap raises a resource limit error
  rather than continuing.
- **Redaction.** Secrets that match the known credential shapes are masked in
  reports and in exported artefacts.
- **Output containment.** Report and map files are written through
  `safe_output_path()`, which refuses destinations that are not inside the
  expected output areas.
- **No network by default.** The scanner does not fetch remote URLs, does not
  phone home and does not send telemetry. The only outbound requests it can make
  are `git clone` of a remote repository when you explicitly allow remote
  sources.

## Running the server publicly

The MCP server has **no authentication of its own**. It will answer any caller
who can reach it. Before exposing it beyond your own machine, put a reverse
proxy in front of it that terminates TLS and enforces authentication, and pin
the directories it is allowed to read. See
[docs/deployment.md](docs/deployment.md), section 3.3, and the recipe in
[deploy/](deploy/).

Do not publish an unauthenticated endpoint. If you find a way to make the server
act outside its configured roots or read a file it should not, that is a
vulnerability in the tool, not a misconfiguration: report it privately.
