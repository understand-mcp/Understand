# UNDERSTAND - container image
#
# Two shapes in one file:
#   * default (stdio)      - the MCP client starts the server itself over stdio
#   * streamable-http      - the server runs as an HTTP service, which is what
#                            Smithery and other remote registries require
#
# Smithery's container runtime needs: a Linux image, `sh` available, and a
# process that speaks HTTP. `sh` is why the runtime base is used instead of a
# distroless image: a distroless image cannot host a shell entrypoint.
#
# Build:
#   docker build -t understand-mcp .
#
# Run as a one-shot CLI scan (no server involved):
#   docker run --rm -v "$PWD:/work:ro" understand-mcp scan /work --security --bugs
#
# Run the HTTP MCP server:
#   docker run --rm -p 8000:8000 \
#     -e UNDERSTAND_MCP_TRANSPORT=streamable-http \
#     -e UNDERSTAND_MCP_HOST=0.0.0.0 \
#     -e UNDERSTAND_STORAGE=/data/scans.db \
#     -v understand-data:/data \
#     understand-mcp
#
# Run as an MCP server over stdio (the default):
#   docker run -i --rm understand-mcp

# ---------------------------------------------------------------- build stage
FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Copy only what the build needs first so dependency layers cache across code
# edits. Copying the whole tree first would invalidate the cache on every commit.
COPY pyproject.toml README.md ./
COPY src ./src

# `git` is an optional dependency: without it remote repository scanning is
# refused with a clear error, but every local feature still works. It is
# installed here because a scanner that cannot clone is far less useful.
RUN apt-get update \
    && apt-get install --no-install-recommends -y git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip \
    && python -m pip install .

# --------------------------------------------------------------- runtime stage
FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="UNDERSTAND" \
      org.opencontainers.image.description="Repository-wide code intelligence, security and defect analysis engine with a CLI and MCP server" \
      org.opencontainers.image.source="https://github.com/Understand-Dev/understand-mcp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="0.1.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UNDERSTAND_MCP_TRANSPORT=streamable-http \
    UNDERSTAND_MCP_HOST=0.0.0.0 \
    UNDERSTAND_MCP_PORT=8000 \
    UNDERSTAND_STORAGE=/data/scans.db \
    UNDERSTAND_LOG_LEVEL=WARNING

RUN apt-get update \
    && apt-get install --no-install-recommends -y git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 understand

COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin/understand /usr/local/bin/understand
COPY --from=build /usr/local/bin/understand-mcp-server /usr/local/bin/understand-mcp-server

# The scan store lives on a volume so results survive container replacement.
# A world-writable /data owned by the unprivileged user avoids running as root.
RUN mkdir -p /data && chown understand:understand /data
VOLUME ["/data"]

USER understand
WORKDIR /work

EXPOSE 8000

# The health check asks the HTTP transport for its capabilities resource. It is
# intentionally tolerant: a stdio deployment must not be reported unhealthy just
# because it has no HTTP port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python - <<'PY' || exit 1
import os, sys, urllib.request
host = os.environ.get("UNDERSTAND_MCP_HOST", "0.0.0.0")
port = os.environ.get("UNDERSTAND_MCP_PORT", "8000")
if host in ("0.0.0.0", "::"):
    host = "127.0.0.1"
try:
    with urllib.request.urlopen(f"http://{host}:{port}/mcp", timeout=4) as response:
        sys.exit(0 if response.status < 500 else 1)
except Exception:
    # No HTTP listener (stdio mode) is a valid configuration, not a failure.
    sys.exit(0)
PY

ENTRYPOINT ["understand-mcp-server"]