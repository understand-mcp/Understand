# UNDERSTAND documentation

This directory is the long-form documentation for UNDERSTAND. The
[README](../README.md) at the repository root is the fast entry point — this
directory holds the material that does not fit in a README: the reasoning behind
design decisions, the exact contracts the tool honours, and the details you need
when you are integrating or operating it.

## Contents

| Document | What it answers |
|---|---|
| [architecture.md](architecture.md) | How a scan is executed, stage by stage, and why the pipeline is shaped that way. |
| [security-model.md](security-model.md) | Every trust boundary, every control, and what the tool explicitly refuses to do. |
| [mcp-protocol.md](mcp-protocol.md) | The wire contract: tools, resources, response envelopes, error codes, transport choices. |
| [cli.md](cli.md) | Complete CLI reference: commands, options, output formats, exit codes. |
| [configuration.md](configuration.md) | Every setting, every environment variable, every default, and how they interact. |
| [clients.md](clients.md) | Verified configuration for each MCP-capable AI client, with per-platform notes. |
| [deployment.md](deployment.md) | Running the server as a hosted HTTP service, containers, and network exposure. |
| [mcpb.md](mcpb.md) | Building the distributable MCPB bundle. |
| [portability.md](portability.md) | Linux, macOS and Windows behaviour, known differences, and how to work around them. |
| [extending.md](extending.md) | How to add a check, a rule, a language, or an MCP tool. |
| [interactive-map.md](interactive-map.md) | Code maps: the shipped views and renderer, the budgets and honesty rules, the adaptive-quality controller, and what a node and a finding explain when you click them. |
| [roadmap.md](roadmap.md) | Known limitations and planned work. |

## Conventions used here

- **MUST / MUST NOT** — a requirement the code actually enforces today.
- **SHOULD / SHOULD NOT** — a strong recommendation that is not enforced.
- **MAY** — genuinely optional.

Where this documentation and the code disagree, the code is the defect. Please
open an issue.

## Verifying claims

The suite is expected to be green:

```bash
python -m pytest -q
```

The SARIF renderer is additionally validated against the official OASIS schema,
which is fetched once and cached:

```bash
python tools/validate_sarif.py
```

A correct run prints `VALID against the OASIS SARIF 2.1.0 schema`.