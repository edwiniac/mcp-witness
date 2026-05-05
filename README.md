# 🔐 MCP Witness

[![CI](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml/badge.svg)](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)

**Immutable audit trail for AI decisions** — cryptographic proof of what your AI did, when, and why.

Designed for **SOC2**, **HIPAA**, and **GDPR** compliance in regulated industries.

---

## ✨ Features

- **🔗 Hash Chain Integrity** — Every record cryptographically links to the previous one. Tampering is detectable and tested.
- **🌳 Merkle Checkpoints** — O(log n) verification instead of O(n). Verify millions of records in seconds.
- **⚓ External Anchoring** — Anchor proofs to RFC 3161 TSA (proper DER-encoded TimeStampReq), OpenTimestamps (Bitcoin), and IPFS (spec-compliant CIDv0/CIDv1 multihash).
- **📝 Complete Audit Trail** — Log tool calls, decisions, outputs, and errors with full context.
- **🔒 PII Redaction** — Store hashes instead of sensitive data while preserving verifiability.
- **📊 Compliance Reports** — Export audit trails for SOC2/HIPAA auditors.
- **🔍 Queryable History** — Search by session, actor, tool, time range, sensitivity level.
- **📜 Proof Packages** — Generate complete verification packages for third-party auditors.

## 🚀 Quick Start

### Installation

```bash
pip install mcp-witness
```

Or install from source:

```bash
git clone https://github.com/edwiniac/mcp-witness.git
cd mcp-witness
pip install -e .
```

### Usage with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "witness": {
      "command": "mcp-witness",
      "env": {
        "MCP_WITNESS_DB": "~/.mcp-witness/witness.db"
      }
    }
  }
}
```

### Example Prompts

Once configured, ask Claude:

> "Record that I just called the search_tool with query 'stock prices'"

> "Verify the integrity of the audit chain"

> "Show me all decisions made in session abc123"

> "Export an audit report for compliance review"

> "What's the current status of the audit trail?"

## 🛠️ Available Tools

### Core Tools

| Tool | Description |
|------|-------------|
| `witness_record` | Log an AI action/decision to the audit trail |
| `witness_verify` | Verify hash chain integrity (detect tampering) |
| `witness_query` | Search records by session, actor, tool, time |
| `witness_chain` | Get full decision chain for a session |
| `witness_stats` | Get audit trail statistics and health |
| `witness_export` | Export records for compliance reporting |

### Checkpoint & Anchoring Tools (v0.2.0+)

| Tool | Description |
|------|-------------|
| `witness_checkpoints` | List Merkle checkpoints |
| `witness_verify_fast` | Fast O(log n) verification using checkpoints |
| `witness_anchor` | Anchor checkpoint to TSA/Bitcoin/IPFS |
| `witness_verify_anchors` | Verify external anchor receipts |
| `witness_proof` | Get complete proof package for a record |
| `witness_backfill` | Create checkpoints for existing records |

## 📊 How It Works

### Hash Chain

Every record includes:
- **prev_hash**: SHA-256 of the previous record
- **record_hash**: SHA-256 of this record's key fields

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Record #0   │     │  Record #1   │     │  Record #2   │
│              │     │              │     │              │
│ prev: 000... │────▶│ prev: abc... │────▶│ prev: def... │
│ hash: abc... │     │ hash: def... │     │ hash: 123... │
└──────────────┘     └──────────────┘     └──────────────┘
```

**Tamper Detection**: If anyone modifies a record, the hash changes, breaking the chain. All subsequent records become invalid.

### Merkle Checkpoints

Every 1000 records, a Merkle tree checkpoint is created:

```
Records 0-999          Merkle Tree              Checkpoint
─────────────          ───────────              ──────────
   rec_0  ────┐              root ──────────▶  checkpoint_0
   rec_1  ────┤             /    \              merkle_root: abc...
   rec_2  ────┼───▶    hash_01  hash_23         records: 0-999
    ...       │         / \      / \
   rec_999────┘       h0  h1   h2  h3
```

**Benefits:**
- **O(log n) verification** — Verify any record in ~10 steps instead of walking entire chain
- **Proof packages** — Generate portable proofs for third-party verification
- **Checkpoint anchoring** — Anchor roots to external trust sources

### External Anchoring

Anchor checkpoint Merkle roots to external trust sources:

| Provider | Cost | Latency | Trust Level |
|----------|------|---------|-------------|
| **RFC 3161 TSA** | Free | ~1s | Legal-grade |
| **OpenTimestamps** | Free | ~hours | Bitcoin-backed |
| **IPFS** | Free | ~2s | Content-addressed |

```
Your Database              External Anchors
────────────              ────────────────
checkpoint_0  ──────────▶  TSA timestamp
merkle_root: abc...        OpenTimestamps receipt
                           IPFS CID
```

**Third-party verification**: Auditors can verify records using only:
1. The record hash
2. Merkle proof path
3. External anchor receipt

No database access required.

### Data Model

```python
WitnessRecord:
  # Identity
  id, timestamp, sequence, prev_hash, record_hash
  
  # Who
  actor_type, actor_id, session_id
  
  # What
  action_type, tool_name, input_data, output_data
  input_hash, output_hash  # Privacy: store hash, not raw data
  
  # Why
  context, reasoning, confidence
  
  # Compliance
  sensitivity, retention_days, tsa_receipt, anchored_at
```

## 🔒 Privacy Features

### Field Redaction

Store SHA-256 hash instead of sensitive data:

```python
witness_record(
    action_type="tool_call",
    input_data={"patient_ssn": "123-45-6789", "query": "lookup"},
    redact_fields=["patient_ssn"]
)
# Stores: {"patient_ssn": "[REDACTED:sha256:a1b2c3...]", "query": "lookup"}
```

### Retention Policies

GDPR-compliant auto-deletion:

```python
witness_record(
    action_type="tool_call",
    sensitivity="pii",
    retention_days=90  # Auto-delete after 90 days
)
```

## 📋 Compliance Use Cases

### SOC2

- **CC6.1**: Access logging with immutable audit trails
- **CC7.2**: Change tracking with cryptographic verification
- **CC6.6**: Logical access controls logged

### HIPAA

- **164.312(b)**: Audit controls for PHI access
- **164.312(c)**: Integrity controls via hash chain
- **164.312(e)**: Transmission security with attestation

### GDPR

- **Article 30**: Records of processing activities
- **Article 17**: Right to erasure via retention policies
- **Article 32**: Security measures with cryptographic proof

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          AI Client                               │
│                    (Claude, ChatGPT, etc.)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │ MCP Protocol
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        mcp-witness                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Recorder   │  │  Verifier   │  │   Report Generator      │  │
│  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘  │
│         │                │                      │                │
│         ▼                ▼                      ▼                │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    SQLite + WAL                              ││
│  └─────────────────────────────────────────────────────────────┘│
└───────────────────────────┬─────────────────────────────────────┘
                            │ Optional
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│              External Trust Anchors (Optional)                   │
│         RFC 3161 TSA  ·  Blockchain  ·  S3 Object Lock          │
└─────────────────────────────────────────────────────────────────┘
```

## 🧪 Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# With coverage
pytest --cov=mcp_witness --cov-report=term-missing
```

## 📁 Project Structure

```
src/mcp_witness/
├── __init__.py       # Package exports
├── server.py         # MCP server + 13 tool handlers
├── models.py         # Pydantic models (ConfigDict)
├── storage.py        # SQLite + WAL + hash chain + checkpoints
├── hasher.py         # SHA-256 chain integrity + PII redaction
├── merkle.py         # Merkle tree + proof generation/verification
└── anchoring.py      # RFC 3161 TSA (DER), IPFS (CIDv0/v1), OpenTimestamps

tests/
├── test_server.py
├── test_storage.py
├── test_hasher.py
├── test_merkle.py
├── test_checkpoints.py
├── test_anchoring.py
└── conftest.py
```

## ⚙️ Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_WITNESS_DB` | `~/.mcp-witness/witness.db` | Database path |
| `MCP_WITNESS_CHECKPOINT_INTERVAL` | `1000` | Records per checkpoint |
| `MCP_WITNESS_AUTO_ANCHOR` | `false` | Auto-anchor checkpoints |
| `PINATA_API_KEY` | - | For IPFS pinning (optional) |
| `PINATA_API_SECRET` | - | For IPFS pinning (optional) |

## 🗺️ Roadmap

- [x] Core hash chain storage
- [x] MCP server with 13 tools
- [x] PII redaction
- [x] Query and export
- [x] Merkle tree checkpoints
- [x] O(log n) fast verification
- [x] External anchoring — RFC 3161 TSA (proper DER-encoded), IPFS (spec-compliant CIDv0/CIDv1)
- [x] Proof packages for third-party verification
- [x] Tamper-detection integration tests
- [x] SQLite WAL mode for concurrent access
- [ ] PostgreSQL backend option
- [ ] Full Certificate-chain TSA verification (pyasn1 + cryptography)
- [ ] PDF report generation
- [ ] Web dashboard
- [ ] Decision graph (non-linear workflows)

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 👤 Author

**Edwin Isac** — AI Engineer  
[GitHub](https://github.com/edwiniac) · [Email](mailto:edwinisac007@gmail.com)

---

*Part of the MCP ecosystem: [mcp-finance](https://github.com/edwiniac/mcp-finance) · [mcp-security](https://github.com/edwiniac/mcp-security)*
