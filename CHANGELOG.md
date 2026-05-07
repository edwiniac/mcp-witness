# Changelog

All notable changes to mcp-witness.

## [0.3.0] — 2026-05-07

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
