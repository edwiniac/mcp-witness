# 🔐 MCP Witness

[![CI](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml/badge.svg)](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)
[![Version](https://img.shields.io/badge/version-0.6.0-orange.svg)](https://pypi.org/project/mcp-witness/)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Cryptographic proof of every AI decision.** An immutable, verifiable audit trail MCP server — because "trust me bro" isn't SOC2 compliant.

```bash
pip install mcp-witness
mcp-witness quickstart
```

## ✨ Why mcp-witness?

AI agents make decisions. Regulators ask questions. mcp-witness provides **cryptographic proof** of what happened, when, and why — with hash chain integrity, Merkle tree verification, Ed25519 signatures, external trust anchoring (RFC 3161 TSA strict mode with optional local attestation, OpenTimestamps for structural verification, IPFS), and compliance presets for HIPAA, GDPR, SOC2, and more.

| Feature | mcp-witness | Standard Logging |
|---------|-------------|-----------------|
| Tamper detection | ✅ SHA-256 hash chain + Merkle trees | ❌ Text files, easy to edit |
| O(log n) verification | ✅ Merkle checkpoints with auto-backfill | ❌ Linear scan only |
| Non-repudiation | ✅ Ed25519 record signing | ❌ None |
| External anchoring | ✅ TSA, Bitcoin (OTS), IPFS | ❌ None |
| Compliance presets | ✅ HIPAA, GDPR, SOX, PCI DSS, FedRAMP, SOC2 | ❌ Manual configuration |
| PII/PHI redaction | ✅ Cryptographic hashing | ❌ Plaintext or manual |
| GDPR right to erasure | ✅ `witness_delete` with chain preservation | ❌ Destructive deletion |
| Legal-grade proof | ⚠️ RFC 3161 timestamps (strict mode default; local attestation in degraded mode) | ❌ None |
| Chain failure alerts | ✅ Webhook notifications | ❌ Silent failure |
| Multi-tenancy | ✅ org_id isolation | ❌ None |
| Reports | ✅ HTML + PDF compliance reports | ❌ Manual |
| Dashboard | ✅ Web dashboard with live API | ❌ None |
| Structured logging | ✅ JSON log format option | ❌ Unstructured |

### 🔒 Assurance Levels

| Level | Description | Current |
|-------|-------------|---------|
| ASSURANCE-1 | Best-effort logging, no cryptographic guarantees | — |
| ASSURANCE-2 | Hash chain + Merkle trees, tamper-EVIDENT, configurable anchoring | **v0.6.0** |
| ASSURANCE-3 | Non-repudiation (Ed25519), strict anchoring, encryption at rest, formal threat model | **Target: v1.0** |

See [SECURITY.md](SECURITY.md) for the full threat model.

## 🚀 30-Second Quickstart

```bash
# Install
pip install mcp-witness

# One command: init + serve
mcp-witness quickstart
# ✅ Database ready: ~/.mcp-witness/witness.db
# 📋 Next Steps:
#    1. Configure signing:  export MCP_WITNESS_SIGNING_KEY=$(openssl rand -hex 32)
#    2. Configure HMAC:     export MCP_WITNESS_HMAC_KEY=$(openssl rand -hex 32)
#    3. Start dashboard:    mcp-witness dashboard
#    4. Add to Claude:      claude mcp add witness -- mcp-witness serve

# Or go step-by-step:
mcp-witness init        # Initialize database
mcp-witness serve       # Start MCP server

# Check system health
mcp-witness stats       # Chain statistics
mcp-witness verify      # Chain integrity check
mcp-witness dashboard   # Web dashboard on :9090
mcp-witness report      # Generate compliance report
```

### Claude Desktop Integration

```json
{
  "mcpServers": {
    "witness": {
      "command": "mcp-witness",
      "args": ["serve"],
      "env": {
        "MCP_WITNESS_DB": "~/.mcp-witness/witness.db",
        "MCP_WITNESS_HMAC_KEY": "<32-byte hex key>",
        "MCP_WITNESS_SIGNING_KEY": "<32-byte hex seed for Ed25519>",
        "MCP_WITNESS_CHECKPOINT_INTERVAL": "1000",
        "MCP_WITNESS_AUTO_ANCHOR": "false",
        "MCP_WITNESS_WEBHOOK_URL": "https://alerts.example.com/witness",
        "MCP_WITNESS_LOG_FORMAT": "json"
      }
    }
  }
}
```

## 🛠️ CLI Reference

```
mcp-witness quickstart           One-command init + serve with next steps
mcp-witness serve                Start the MCP server
mcp-witness init                 Initialize database
mcp-witness verify [--fast]      Verify hash chain integrity
mcp-witness stats                Chain health dashboard
mcp-witness export [--output]    Export audit report
mcp-witness report [--format]    Generate HTML/PDF compliance report
mcp-witness proof SEQUENCE       Merkle proof for a record
mcp-witness search QUERY         Full-text search across audit records
mcp-witness checkpoints          List Merkle checkpoints
mcp-witness dashboard            Start web dashboard (default :9090)
mcp-witness anchors create ID    Anchor to TSA/Bitcoin/IPFS
mcp-witness anchors verify ID    Verify external anchor receipts
```

## 🛠️ MCP Tools (17 Total)

| Tool | Description |
|------|-------------|
| `witness_record` | Log an AI action to the immutable audit trail |
| `witness_verify` | Verify hash chain integrity (detect tampering) |
| `witness_verify_fast` | O(log n) verification using Merkle checkpoints |
| `witness_query` | Search records by session, actor, tool, time |
| `witness_chain` | Get full decision chain for a session |
| `witness_stats` | Get audit trail statistics and health |
| `witness_health` | Check DB connectivity, signing status, anchors, version |
| `witness_attest` | RFC 3161 timestamp from external authority |
| `witness_export` | Export records for compliance reporting |
| `witness_delete` | GDPR right to erasure (data redaction, chain preserved) |
| `witness_search` | Full-text search across reasoning/input/output data |
| `witness_checkpoints` | List Merkle checkpoints |
| `witness_anchor` | Anchor checkpoint to TSA/Bitcoin/IPFS |
| `witness_verify_anchors` | Verify external anchor receipts |
| `witness_proof` | Get Merkle proof for a single record |
| `witness_backfill` | Create checkpoints for existing records |
| `witness_configure_compliance` | Apply HIPAA/GDPR/SOX/FedRAMP/SOC2/PCI DSS preset |

## 🏛️ Compliance Presets

One command. Full compliance baseline.

```python
# Via MCP tool:
witness_configure_compliance(preset="hipaa")
# → 6-year retention, auto-redacts 12 PHI fields, requires attestation

witness_configure_compliance(preset="gdpr")
# → Right-to-erasure support, consent records, 12 PII fields redacted

witness_configure_compliance(preset="soc2")
# → 1-year retention, API key redaction, quarterly audit schedule
```

| Preset | Retention | Auto-Redact | Attestation | Immutable |
|--------|-----------|-------------|-------------|-----------|
| HIPAA | 6 years | 12 PHI fields | ✅ Required | — |
| GDPR | Per-purpose | 12 PII fields | ✅ Required | Right to erasure |
| SOX | 7 years | 7 financial fields | ✅ Required | ✅ Yes |
| FedRAMP | 3 years | 6 CUI fields | ✅ Required | — |
| SOC 2 | 1 year | 7 fields | ✅ Required | — |
| PCI DSS | 1 year | 7 card fields | ✅ Required | — |

## 📊 How It Works

### Hash Chain + Merkle Trees + Ed25519 Signatures

```
Records:    [R0] → [R1] → [R2] → ... → [R999] → [R1000] → ...
           ✍️🔑    ✍️🔑    ✍️🔑              ✍️🔑       ✍️🔑
           Ed25519 Ed25519 Ed25519          Ed25519     Ed25519
                                                   ↓
                                           [Checkpoint #1]
                                           Merkle Root: abc123
                                           Covers: records 0-999
                                                   ↓
                                           [External Anchors]
                                           🕐 TSA (RFC 3161)
                                           ₿  OpenTimestamps
                                           🌐 IPFS

Merkle Tree:         root_hash
                    /         \
               hash_01        hash_23
               /    \         /    \
            h_0    h_1      h_2    h_3
             ↓      ↓        ↓      ↓
          R0:R0h  R1:R1h  R2:R2h  R3:R3h
```

**Every record** is signed with Ed25519 for non-repudiation (signing key auto-generated if not configured).

**Tamper Detection:** Change any record → its hash changes → signature invalid → Merkle root changes → checkpoint invalidated → external anchors prove when the real root existed.

**GDPR Right to Erasure:** `witness_delete` nulls data fields but preserves the hash chain — records can be redacted without breaking integrity verification.

### Verification Performance

| Records | Full Chain | With Checkpoints |
|---------|-----------|-----------------|
| 1,000 | ~100ms | ~100ms |
| 10,000 | ~1s | ~100ms |
| 100,000 | ~10s | ~1s |
| 1,000,000 | ~100s | ~10s |

Single record: **O(log n)** with Merkle proof (vs O(n) linear scan).

## 🔒 Security

- **SHA-256 hash chain** with null-byte delimiters to prevent collision attacks
- **Ed25519 record signing** — auto-generated ephemeral keys, configurable via env var
- **HMAC key protection** — optional server-side secret makes hashes un-recomputable
- **RFC 3161 TSA anchoring** — legal-grade timestamps (strict mode; local attestation in degraded mode)
- **OpenTimestamps** — structural verification (full Bitcoin confirmation requires external OTS client)
- **IPFS content addressing** — CIDv0/CIDv1 computation with gateway verification
- **Domain-separated Merkle trees** — prevents second-preimage attacks
- **Atomic transactions** — `BEGIN IMMEDIATE` prevents race conditions and chain forks
- **Rate limiting** — configurable token bucket (DB-backed)
- **RBAC** — role-based access control for read-only audit deployments
- **Error sanitization** — stack traces never leak to clients
- **Path traversal protection** — exports confined to allowed directories
- **Idempotency** — nonce-based replay attack prevention with per-row TTL cleanup
- **Webhook alerts** — POST to configurable URL on chain integrity failure
- **Structured logging** — optional JSON log format for production monitoring

See [CONTRIBUTING.md](CONTRIBUTING.md) for the security disclosure policy.

## 🧪 Development

```bash
git clone https://github.com/edwiniac/mcp-witness.git
cd mcp-witness
pip install -e ".[dev]"
pytest -v                    # 251 unit tests
pytest --ignore=tests/test_storage_pg.py  # Skip PG (needs PostgreSQL)
```

### CI/CD Pipeline

| Job | Description |
|-----|-------------|
| **lint** | ruff + black formatting checks |
| **test** | 251 tests across Python 3.10, 3.11, 3.12 with ≥65% coverage |
| **test-postgres** | 12 PostgreSQL integration tests on Postgres 16 |
| **security** | pip-audit vulnerability scanning |
| **build** | Package build + smoke test |

## 🗺️ Roadmap

- [x] Core hash chain (v0.1.0)
- [x] Merkle checkpoints + external anchoring (v0.2.0)
- [x] CLI + compliance presets + security hardening (v0.3.0)
- [x] PostgreSQL backend (v0.5.0)
- [x] Ed25519 record signing + non-repudiation (v0.6.0)
- [x] GDPR right to erasure + schema migrations (v0.6.0)
- [x] Web dashboard with live API (v0.6.0)
- [x] HTML + PDF compliance reports (v0.6.0)
- [x] Structured JSON logging (v0.6.0)
- [x] Multi-tenancy (v0.6.0)
- [x] Webhook alerts on chain failure (v0.6.0)
- [x] Full-text search (v0.6.0)
- [ ] Streaming architecture (Kafka/NATS)
- [ ] AWS KMS / cloud HSM signing
- [ ] Grafana/Prometheus metrics endpoint
- [ ] Plugin system for custom anchor providers

## 📄 License

MIT — see [LICENSE](LICENSE)

## 👤 Author

**Edwin Isac** — AI Engineer  
[GitHub](https://github.com/edwiniac) · [Email](mailto:edwinisac007@gmail.com)
