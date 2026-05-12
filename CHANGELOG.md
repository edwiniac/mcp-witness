# Changelog

All notable changes to mcp-witness.

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
