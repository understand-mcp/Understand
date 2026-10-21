# The distributable bundle

UNDERSTAND ships two ways: as a normal Python package (`pip install understand-mcp`)
and as a single file in the MCPB format. MCPB is a zip with a manifest that
describes the server, its entry point and its runtime. Any host that speaks MCPB
can install that one file and run the server locally over stdio, without a
Python environment of its own.

Published GitHub releases carry the bundle as `understand-mcp-<version>.mcpb`.

## Build it from source

    npm install -g @anthropic-ai/mcpb
    python tools/build_mcpb.py --out-dir dist

The builder prints the path and the size of the archive. It needs the MCPB CLI
on `PATH`; `tools/build_mcpb.py` refuses to run without it and prints the
install command.

## What the builder stages

- `manifest.json` - manifest version 0.4. The server is declared as `python`,
  the entry point is `server/main.py`, and the MCP config runs it over stdio.
  Compatibility is declared for macOS, Windows and Linux on Python 3.11+.
- `src/` - the whole source tree, plus `pyproject.toml`, `README.md` and
  `LICENSE`.
- `server/main.py` - a small bootstrap. It imports `understand.mcp.server`
  directly when the bundled sources are importable. When they are not, it
  creates a virtual environment next to the bundle, installs
  `understand-mcp==<version>` from PyPI into it, and re-executes itself with
  that interpreter. That fallback needs network access the first time it runs.

## Run it

    python server/main.py

The server speaks stdio on that transport. The other transports and the
environment variables are described in [deployment.md](deployment.md).

## Check it

    mcpb validate <staging directory>
    mcpb info dist/understand-mcp-<version>.mcpb

## How it gets released

`.github/workflows/bundle.yml` runs on every published release: it checks the
tag out, installs the MCPB CLI, builds the bundle with `tools/build_mcpb.py`
and uploads it to the GitHub release. The bundle that ships with a release is
built from that release's tag, by the same command you can run locally.

## Where to host it

The bundle is the local, stdio path. To serve the same server over HTTP
instead, use the container and the reverse proxy in [deployment.md](deployment.md)
and the recipe in the repository's `deploy/` directory.
