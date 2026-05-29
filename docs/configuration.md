# Configuration Reference

All configuration is via environment variables. This page documents every
`MCP_WITNESS_*` variable, its default, and its security implications.

> **Secure-by-default (v1.0.0):** the server refuses to start without a
> persistent signing key and fails closed if the chain does not verify at
> startup. Each such default has an opt-out variable noted below.

## Quick start (recommended production baseline)

```bash
export MCP_WITNESS_SIGNING_KEY=$(openssl rand -hex 32)   # non-repudiation
export MCP_WITNESS_HMAC_KEY=$(openssl rand -hex 32)      # tamper-resistance
export MCP_WITNESS_ENCRYPTION_KEY=$(openssl rand -hex 32) # encryption at rest
export MCP_WITNESS_API_KEYS="<32+char-key>:admin"        # authentication
```

## Core & storage

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_DB` | `~/.mcp-witness/witness.db` | SQLite database path. |
| `MCP_WITNESS_BACKEND` | `sqlite` | Storage backend: `sqlite` or `postgresql`. |
| `MCP_WITNESS_PG_URL` | — | PostgreSQL connection URL (required when backend is `postgresql`). |
| `MCP_WITNESS_PG_POOL_MIN` | `2` | Minimum PostgreSQL connection pool size. |
| `MCP_WITNESS_PG_POOL_MAX` | `10` | Maximum PostgreSQL connection pool size. |
| `MCP_WITNESS_ORG_ID` | — | Tenant identifier for multi-tenant deployments. |
| `MCP_WITNESS_CHECKPOINT_INTERVAL` | `1000` | Records per Merkle checkpoint. |
| `MCP_WITNESS_CLEANUP_INTERVAL` | `100` | Inserts between nonce/rate-limit cleanup passes. |
| `MCP_WITNESS_MAX_PAYLOAD_SIZE` | `10485760` (10 MiB) | Maximum accepted payload size in bytes. |

## Cryptography & integrity

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_SIGNING_KEY` | — | Ed25519 private seed (64 hex chars) for record signing / non-repudiation. **Required by default.** |
| `MCP_WITNESS_REQUIRE_PERSISTENT_KEY` | `true` | If `true`, refuse to start without `MCP_WITNESS_SIGNING_KEY`. Set `false` to allow an ephemeral per-process key (development only). |
| `MCP_WITNESS_HMAC_KEY` | — | HMAC key (64 hex chars) protecting the hash chain. When unset, plain SHA-256 is used and a warning is logged. |
| `MCP_WITNESS_REQUIRE_HMAC` | `false` | If `true`, refuse to start without `MCP_WITNESS_HMAC_KEY`. |
| `MCP_WITNESS_ENCRYPTION_KEY` | — | AES-256-GCM key (64 hex chars) for field-level encryption at rest. Alias: `MCP_WITNESS_DEK` (deprecated). Without it, sensitive fields are stored as plaintext. |
| `MCP_WITNESS_TRUST_STORE` | — | Path to the key trust store (signing-key rotation / revocation metadata). |
| `MCP_WITNESS_FAIL_ON_STARTUP_VERIFICATION_FAILURE` | `true` | If `true`, abort startup when the chain fails verification. Set `false` to continue in degraded mode (logs a warning). |

## Authentication & access control

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_API_KEYS` | — | Comma-separated `key:role` pairs. Roles: `admin`, `auditor`, `writer`. Keys must be ≥16 chars. |
| `MCP_WITNESS_API_KEY` | — | Single API key presented by the client (legacy / convenience). |
| `MCP_WITNESS_DEFAULT_ACCESS` | `deny` | Access when no auth is configured: `deny`, `read_only`, or `admin`. Non-`deny` values log a prominent warning. |
| `MCP_WITNESS_REQUIRE_AUTH` | `false` | If `true`, refuse to start unless API keys or a JWT public key are configured. |
| `MCP_WITNESS_ALLOW_ANON_WRITES` | `false` | When auth is configured, allow unauthenticated callers writer access (discouraged). |
| `MCP_WITNESS_READ_ONLY` | `false` | **Deprecated.** Use `MCP_WITNESS_API_KEYS` / `MCP_WITNESS_DEFAULT_ACCESS`. |
| `MCP_WITNESS_JWT_PUBLIC_KEY` | — | Ed25519 public key (hex) used to verify JWT assertions. |
| `MCP_WITNESS_JWT_PRIVATE_KEY` | — | Ed25519 private key (hex) used by `mcp-witness jwt-sign` to mint tokens. |
| `MCP_WITNESS_JWT_ISSUER` | — | Expected JWT `iss` claim (validated when set). |
| `MCP_WITNESS_JWT_AUDIENCE` | — | Expected JWT `aud` claim (validated when set). |
| `MCP_WITNESS_JWT_MAX_AGE` | `3600` | Maximum JWT age in seconds. |

> **Note:** MCP uses stdio transport (no TLS). For network deployments, terminate
> TLS at a reverse proxy and authenticate clients with API keys or JWT assertions.

## Anchoring

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_ANCHOR_STRICT` | `true` | If `true`, any anchor-provider failure raises `AnchorFailureError`. Set `false` for best-effort partial results. |
| `MCP_WITNESS_AUTO_ANCHOR` | `false` | Automatically anchor checkpoints to external providers as they are created. |

## Webhooks & alerting

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_WEBHOOK_URL` | — | URL POSTed on chain-failure detection. Validated against the SSRF guard. |
| `MCP_WITNESS_SLACK_WEBHOOK_URL` | — | Slack incoming-webhook URL for formatted alerts. Validated against the SSRF guard. |
| `MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS` | `false` | If `true`, allow webhook URLs that resolve to loopback/private/link-local addresses (otherwise blocked to prevent SSRF). |

## Dashboard & metrics

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_DASHBOARD_PORT` | `9090` | Port for the web dashboard. |
| `MCP_WITNESS_DASHBOARD_ORIGIN` | — | `Access-Control-Allow-Origin` value. Leave unset (and bind to localhost) unless you front the dashboard with TLS + auth. |
| `MCP_WITNESS_METRICS_PORT` | `0` (disabled) | Prometheus metrics port. Must be `0`–`65535`; invalid values fail fast at startup. |
| `MCP_WITNESS_METRICS_HOST` | `127.0.0.1` | Bind host for the metrics endpoint. Keep on loopback unless intentionally exposed. |

## Operational

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_LOG_FORMAT` | `text` | `json` for structured logs (aggregators), otherwise human-readable text. |
| `MCP_WITNESS_LOG_LEVEL` | `INFO` | Root log level. |
| `MCP_WITNESS_SHUTDOWN_TIMEOUT` | `30` | Seconds to wait for in-flight writes on SIGTERM/SIGINT. |
| `MCP_WITNESS_EXPORT_DIR` | current working dir | Directory exports are confined to (path-traversal protection). |
| `MCP_WITNESS_RATE_LIMIT` | `1000` | Maximum records per second (token bucket). |

See also: [SECURITY.md](../SECURITY.md) for the threat model and
[docs/runbook.md](runbook.md) for incident response.
