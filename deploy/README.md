# Self-hosting UNDERSTAND

This directory runs the MCP server as a container behind Caddy. Caddy is the
access boundary: it terminates TLS and enforces HTTP basic authentication,
because the server itself has none.

The server scans any repository a caller names, so nothing about it is safe to
expose without the proxy in front of it.

## 1. A hostname and a certificate

Point an A record at the host that will run this. Caddy obtains a certificate
for it over HTTP, so ports 80 and 443 have to reach the host.

## 2. Configuration

    cp .env.example .env

Fill in:

- `MCP_HOST` - the hostname the certificate is for.
- `ACME_EMAIL` - the address Caddy registers the certificate with.
- `MCP_AUTH_USER` - the user name (default `understand`).
- `MCP_AUTH_HASH` - the hashed password, generated once:

      docker run --rm caddy:2-alpine caddy hash-password --plaintext 'YOUR-TOKEN'

`.env` is ignored by git. Do not commit it.

## 3. Start

    docker compose up -d
    docker compose logs -f caddy

The first start asks Caddy for a certificate; that takes a few seconds.

## 4. Verify

An unauthenticated request must be answered with `401` and a `WWW-Authenticate`
header, so that a client can begin an OAuth discovery flow (RFC 9728):

    curl -i https://$MCP_HOST/mcp

With the credentials:

    curl -u "understand:YOUR-TOKEN" -i https://$MCP_HOST/mcp

## 5. Point a client at it

    {
      "mcpServers": {
        "understand": {
          "type": "http",
          "url": "https://$MCP_HOST/mcp",
          "headers": { "Authorization": "Basic <base64 user:token>" }
        }
      }
    }

## Notes

- The scan database lives in the `scans` volume. Back it up if the scans
  matter.
- The budgets in `docker-compose.yml` (`UNDERSTAND_MAX_FILES`,
  `UNDERSTAND_MAX_FILE_BYTES`, `UNDERSTAND_MAX_TOTAL_BYTES`,
  `UNDERSTAND_WORKERS`) cap what a single scan can do. They are not a rate
  limit: put one in front of the proxy if the endpoint is public.
- The container runs as an unprivileged user and stores nothing outside the
  volumes.
