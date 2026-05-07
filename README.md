# 🔐 MCP Witness

[![CI](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml/badge.svg)](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)
[![Version](https://img.shields.io/badge/version-0.3.0-orange.svg)](https://pypi.org/project/mcp-witness/)

**Cryptographic proof of every AI decision.** An immutable, verifiable audit trail MCP server — because "trust me bro" isn't SOC2 compliant.

```bash
pip install mcp-witness
mcp-witness init
mcp-witness serve
```

## ✨ Why mcp-witness?

AI agents make decisions. Regulators ask questions. mcp-witness provides **cryptographic proof** of what happened, when, and why — with Merkle tree verification, external trust anchoring, and compliance presets for HIPAA, GDPR, SOC2, and more.

| Feature | mcp-witness | Standard Logging |
|---------|-------------|-----------------|
| Tamper detection | ✅ Hash chain + Merkle trees | ❌ Text files, easy to edit |
| O(log n) verification | ✅ Merkle checkpoints | ❌ Linear scan only |
| External anchoring | ✅ TSA, Bitcoin, IPFS | ❌ None |
| Compliance presets | ✅ HIPAA, GDPR, SOX, PCI | ❌ Manual configuration |
| PII redaction | ✅ Cryptographic hashing | ❌ Plaintext or manual |
| CLI dashboard | ✅ `mcp-witness stats` | ❌ `tail -f` |
| Legal-grade proof | ✅ RFC 3161 timestamps | ❌ None |

## 🚀 30-Second Quickstart

```bash
# Install
pip install mcp-witness

# Initialize
mcp-witness init
# ✅ Witness database initialized: ~/.mcp-witness/witness.db

# Start recording (via MCP client like Claude Desktop)
# Or use the CLI to verify:
mcp-witness stats
# 📊 MCP Witness — Chain Statistics
#    Total Records:      42
#    Chain Valid:        ✅
#    Checkpoints:        0 (next at 1000 records)

# Apply a compliance preset
# (via MCP tool: witness_configure_compliance preset=hipaa)
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
        "MCP_WITNESS_CHECKPOINT_INTERVAL": "1000",
        "MCP_WITNESS_AUTO_ANCHOR": "false"
      }
    }
  }
}
```

## 🛠️ CLI Reference

```
mcp-witness serve              Start the MCP server
mcp-witness init               Initialize database
mcp-witness verify [--fast]    Verify chain integrity
mcp-witness stats              Chain health dashboard
mcp-witness export [--output]  Export audit report
mcp-witness proof SEQUENCE     Merkle proof for a record
mcp-witness checkpoints        List Merkle checkpoints
mcp-witness anchors create ID  Anchor to TSA/Bitcoin/IPFS
mcp-witness anchors verify ID  Verify external anchors
```

## 🛠️ MCP Tools (14 Total)

| Tool | Description |
|------|-------------|
| `witness_record` | Log an AI action to the immutable audit trail |
| `witness_verify` | Verify hash chain integrity (detect tampering) |
| `witness_verify_fast` | O(log n) verification using Merkle checkpoints |
| `witness_query` | Search records by session, actor, tool, time |
| `witness_chain` | Get full decision chain for a session |
| `witness_stats` | Get audit trail statistics and health |
| `witness_attest` | RFC 3161 timestamp from external authority |
| `witness_export` | Export records for compliance reporting |
| `witness_checkpoints` | List Merkle checkpoints |
| `witness_anchor` | Anchor checkpoint to TSA/Bitcoin/IPFS |
| `witness_verify_anchors` | Verify external anchor receipts |
| `witness_proof` | Get Merkle proof for a single record |
| `witness_backfill` | Create checkpoints for existing records |
| `witness_configure_compliance` | Apply HIPAA/GDPR/SOX preset |

## 🏛️ Compliance Presets

One command. Full compliance baseline.

```python
# Via MCP tool:
witness_configure_compliance(preset="hipaa")
# → 6-year retention, auto-redacts PHI fields, requires attestation

witness_configure_compliance(preset="gdpr")
# → Right-to-erasure support, consent records, PII redaction

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

### Hash Chain + Merkle Trees

```
Records:    [R0] → [R1] → [R2] → ... → [R999] → [R1000] → ...
                                                   ↓
                                           [Checkpoint #1]
                                           Merkle Root: abc123
                                           Covers: records 0-999

Merkle Tree:         root_hash
                    /         \
               hash_01        hash_23
               /    \         /    \
            h_0    h_1      h_2    h_3
             ↓      ↓        ↓      ↓
          R0:R0h  R1:R1h  R2:R2h  R3:R3h
```

**Tamper Detection:** Change any record → its hash changes → Merkle root changes → checkpoint invalidated → external anchors prove when the real root existed.

### Verification Performance

| Records | Full Chain | With Checkpoints |
|---------|-----------|-----------------|
| 1,000 | ~100ms | ~100ms |
| 10,000 | ~1s | ~100ms |
| 100,000 | ~10s | ~1s |
| 1,000,000 | ~100s | ~10s |

Single record: **O(log n)** with Merkle proof (vs O(n) linear scan).

## 🔒 Security

- **Domain-separated Merkle trees** — prevents second-preimage attacks
- **Atomic transactions** — `BEGIN IMMEDIATE` prevents race conditions
- **Rate limiting** — configurable token bucket
- **RBAC** — read-only mode for audit-only deployments
- **Error sanitization** — stack traces never leak to clients
- **Path traversal protection** — exports confined to allowed directories
- **Idempotency** — replay attack prevention

See [CONTRIBUTING.md](CONTRIBUTING.md) for the security disclosure policy.

## 🧪 Development

```bash
git clone https://github.com/edwiniac/mcp-witness.git
cd mcp-witness
pip install -e ".[dev]"
pytest -v  # 107 tests
```

## 🗺️ Roadmap

- [x] Core hash chain (v0.1.0)
- [x] Merkle checkpoints + external anchoring (v0.2.0)
- [x] CLI + compliance presets + security hardening (v0.3.0)
- [ ] PostgreSQL backend
- [ ] Ed25519 record signing
- [ ] PDF report generation
- [ ] Web dashboard with live API
- [ ] Streaming architecture (Kafka/NATS)
- [ ] Multi-tenancy

## 📄 License

MIT — see [LICENSE](LICENSE)

## 👤 Author

**Edwin Isac** — AI Engineer  
[GitHub](https://github.com/edwiniac) · [Email](mailto:edwinisac007@gmail.com)
