# Changelog

All notable changes to mcp-witness.

## [1.0.0] — 2026-05-29

First production-stable release. This release flips several defaults to
**secure-by-default** and completes the ASSURANCE-3 hardening.

### ⚠️ Breaking changes
Each new default can be reverted with the noted environment variable; all log a
clear message at startup.
- **Persistent signing key now required by default.** The server refuses to start
  without `MCP_WITNESS_SIGNING_KEY` (no persistent key = no cross-restart
  non-repudiation). Override: `MCP_WITNESS_REQUIRE_PERSISTENT_KEY=false`.
- **Startup chain verification is fail-closed by default.** A corrupt/invalid
  chain aborts startup instead of continuing in degraded mode. Override:
  `MCP_WITNESS_FAIL_ON_STARTUP_VERIFICATION_FAILURE=false`.
- **Invalid numeric config now fails fast** (e.g. a malformed
  `MCP_WITNESS_METRICS_PORT` raises at startup instead of silently disabling).

### Added
- **SSRF protection** for `MCP_WITNESS_WEBHOOK_URL` and
  `MCP_WITNESS_SLACK_WEBHOOK_URL`: outbound notifications to loopback, private,
  link-local, or cloud-metadata addresses are blocked. Override:
  `MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS=true`.
- **`MCP_WITNESS_REQUIRE_HMAC`** opt-in to refuse startup without an HMAC key; a
  warning is logged whenever the chain runs in plain-SHA256 mode.
- **Domain-specific anchoring exceptions** (`AnchorError`, `AnchorProviderError`,
  `TSAError`, `OpenTimestampsError`, `IPFSError`) replacing bare `Exception`.
- **`docs/configuration.md`** — complete reference for all environment variables.
- One-time loud warning when running with unauthenticated `admin`/`read_only`
  default access.

### Fixed
- **Encryption-at-rest env var mismatch.** The documented
  `MCP_WITNESS_ENCRYPTION_KEY` is now the canonical name the code reads (with
  `MCP_WITNESS_DEK` kept as a backward-compatible alias). Previously the code
  only read `MCP_WITNESS_DEK`, so users following the docs stored PII in plaintext.
- **RBAC authorization gap.** `witness_health`, `witness_delete`, and
  `witness_search` were registered tools but absent from every role, making them
  uncallable via `call_tool` (even for admin). They are now mapped (delete is a
  write tool).
- **Unknown-tool reporting.** `call_tool` now returns "Unknown tool" for
  unregistered names instead of a misleading permission error.
- Authentication default-access mode is resolved at call time so it honors the
  environment in embedded/test contexts.
- Fire-and-forget webhook notifications are now tracked tasks with exception
  logging (no more orphaned task exceptions at shutdown).
- Restored a green CI baseline (lint, format, types, tests).

### Changed
- `__version__` is now sourced from installed package metadata (single source of
  truth in `pyproject.toml`).
- Test suite expanded to 570+ tests; coverage gate raised from 65% to 80%.
- Classifier promoted to `Development Status :: 5 - Production/Stable`.

### Upgrading from 0.9.x
1. Generate and set a signing key: `export MCP_WITNESS_SIGNING_KEY=$(openssl rand -hex 32)`
   (or set `MCP_WITNESS_REQUIRE_PERSISTENT_KEY=false` to keep ephemeral keys).
2. If you relied on `MCP_WITNESS_DEK`, it still works, but prefer
   `MCP_WITNESS_ENCRYPTION_KEY`.
3. If a webhook targets an internal collector, set
   `MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS=true`.
4. Ensure your existing chain verifies (`mcp-witness verify`) before upgrading, or
   set `MCP_WITNESS_FAIL_ON_STARTUP_VERIFICATION_FAILURE=false`.

## [0.9.0] — 2026-05-18

### Adversarial Hardening (v1.0 P0 items — 13 of 14 complete)
- **P0: TSA strict anchoring** — fail-closed on real TSA providers; no silent fallback
- **P0: Canonicalized signing payload** — `canonicalize_record_fields()` signs full record view
- **P0: Algorithm versioning** — `versioned_sign()` / `versioned_verify()` for Ed25519 → Ed448 → PQC migration
- **P0: Strict Merkle proof validation** — depth, index, tree_size bounds checks
- **P0: Key lifecycle management** — `KeyTrustStore` with rotation, revocation, trust store persistence
- **P0: Envelope encryption at rest** — AES-256-GCM field-level encryption via `MCP_WITNESS_ENCRYPTION_KEY`
- **P0: Sensitive data scrubbing in logs** — `SensitiveDataFilter` registered on log handlers
- **P0: PostgreSQL full backend parity** — `search()`, `redact_record()`, `org_id` column all present
- **P0: Hard pagination ceiling** — `MAX_QUERY_LIMIT=10000`, `MAX_OFFSET=100000` in all handlers
- **P0: CI security gates** — SAST (bandit) + typecheck (mypy) + SBOM jobs
- **P0: Structured metrics** — `Counter`/`Histogram`, `witness_metrics` MCP tool, metrics server

### Added (since v0.6.0)
- **Graceful shutdown** — signal handlers for SIGTERM/SIGINT
- **Slack webhook notifier** — chain failure alerts to Slack
- **Migration CLI** — `mcp-witness migrate` for schema upgrades
- **Incident response runbook** — `docs/runbook.md` (413 lines)
- **Backup/restore documentation** — `docs/backup.md` (373 lines)
- **Metrics server** — Prometheus-compatible metrics endpoint

### Fixed
- Proper host binding (0.0.0.0 for dashboard)
- Safe environment variable parsing (no stack trace leaks)
- Full test coverage for new modules (330 tests passing)
- `__init__.py` exports updated for all public modules

## [0.6.0] — 2026-05-11

### Security Hardening (Codex Audit — 20 fixes)
- **P0: TSA silent fallback fixed** — errors now logged, receipt metadata marked `status: local_fallback`
- **P0: OTS verify() structural-only warning** — docstring + runtime warning that Bitcoin confirmation is not checked
- **P0: IPFS verify() HEAD fallback removed** — no longer returns True on HEAD 200; returns False with explicit CID mismatch logging
- **P0: Hash delimiter `|` → `\x00`** — prevents collision attacks via pipe injection in field names
- **P0: Ed25519 auto-key generation** — signing key now auto-generated on startup; records always signed
- **P1: Nonce cleanup respects per-row TTL** — SQLite datetime arithmetic replaces hardcoded 24h cutoff
- **P1: `cleanup_expired()` auto-called** — runs at startup + every N inserts (configurable via `MCP_WITNESS_CLEANUP_INTERVAL`)
- **P1: `verify_chain_fast()` auto-backfills** — no manual backfill needed for fresh databases
- **P1: Schema versioning** — `witness_schema_version` table + incremental migration framework

### New Features
- **`witness_health` MCP tool** — DB connectivity, chain validity, signing status, anchor stats, version
- **`witness_delete` MCP tool** — GDPR right to erasure via data redaction (preserves chain integrity)
- **`witness_search` MCP tool** — LIKE-based full-text search across reasoning/input/output data
- **Tenant namespacing** — `org_id` column + `MCP_WITNESS_ORG_ID` env var for multi-team deployments
- **Webhook on chain failure** — `MCP_WITNESS_WEBHOOK_URL` + non-blocking notification on verify issues
- **Structured logging** — `MCP_WITNESS_LOG_FORMAT=json` for production JSON log output
- **HTML/PDF compliance reports** — `mcp-witness report` CLI + `generate_html_report()` / `generate_pdf_report()`
- **Dashboard server** — `mcp-witness dashboard` serves index.html + `/api/dashboard` JSON endpoint
- **Quickstart** — `mcp-witness quickstart` one-command init + serve with next-steps instructions
- **CLI search** — `mcp-witness search <query>` for terminal-based full-text audit search

### CI/CD
- **PostgreSQL integration tests** — 12 tests with GitHub Actions service container (Postgres 16)
- **Multi-Python matrix** — 3.10, 3.11, 3.12
- **Security audit job** — pip-audit vulnerability scanning
- **Build verification** — package build + smoke test in CI
- **Weekly health check** — scheduled Monday morning CI run

### Added
- **CLI interface** — `mcp-witness serve|init|verify|stats|export|proof|checkpoints|anchors`
- **Compliance presets** — HIPAA, GDPR, SOX, FedRAMP, SOC2, PCI DSS
- **Security module** — rate limiting, RBAC (read-only mode), error sanitization, idempotency
- **Path traversal protection** — validated export paths
- **Web dashboard** — standalone HTML viewer
- `witness_configure_compliance` MCP tool
- `witness_export` now supports file output with path validation

### Changed
- **Version bump: Alpha → Beta** — production-ready classification
- CLI entry point changed from `mcp_witness.server:main` to `mcp_witness.cli:main`

### Fixed
- **Atomic transactions** — `BEGIN IMMEDIATE` prevents race conditions on concurrent writes
- **Domain-separated Merkle tree** — 0x00 leaf / 0x01 node prefixes prevent second-preimage attacks
- **Proper genesis hash** — deterministic instead of all-zeros placeholder
- **Input validation** — session_id length/char limits, payload size limits (10MB default)
- **SQLITE_BUSY retry** — exponential backoff (3 attempts, 50ms base)
- **Error sanitization** — stack traces never leak to clients
- Merkle proof verification uses domain-separated leaf hashes

## [0.2.0] — 2026-05-05

### Added
- **Merkle checkpoints** — O(log n) verification via Merkle trees
- **External anchoring** — RFC 3161 TSA, OpenTimestamps (Bitcoin), IPFS
- **Proper DER-encoded TSA requests** — RFC 3161 compliant
- **IPFS CIDv0/v1 computation** — authentic content addressing
- `witness_verify_fast`, `witness_anchor`, `witness_verify_anchors`, `witness_proof`, `witness_backfill` tools
- 13 MCP tools (up from 7)

### Changed
- WAL mode enabled on database
- Busy timeout set to 5000ms

## [0.1.0] — 2026-03-02

### Added
- Initial release
- Hash chain integrity with SHA-256
- 7 MCP tools: record, verify, query, chain, stats, attest, export
- PII redaction support
- SQLite backend
- RFC 3161 TSA integration (basic)
