# 🔐 MCP Witness

[![CI](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml/badge.svg)](https://github.com/edwiniac/mcp-witness/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io)
[![Status: Alpha](https://img.shields.io/badge/status-alpha-orange.svg)](CHANGELOG.md)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**A tamper-evident log of agent-reported actions.** An MCP server that hash-chains,
signs and (optionally) externally anchors the actions an AI agent reports to it, so
that later edits to the log are detectable.

> [!WARNING]
> **Do not `pip install mcp-witness`.** The `mcp-witness` name on PyPI belongs to an
> unrelated project (a security toolkit by another author). That command installs
> *different software*. Install this project from source:
>
> ```bash
> pip install git+https://github.com/edwiniac/mcp-witness
> mcp-witness quickstart
> ```

> **Status: alpha.** APIs, storage schema and defaults may still change.

## 🧭 Trust model

Read this before relying on mcp-witness for anything:

- **The agent self-reports.** Records exist only because the agent (or its host)
  calls `witness_record`. mcp-witness does not intercept tool calls or observe
  what the agent actually did; an agent that omits or misdescribes an action
  produces an accurate log of a false report.
- **The operator holds the keys.** Signing, HMAC and encryption keys live with
  whoever runs the server. Whoever holds them can rewrite and re-sign history;
  external anchors (TSA/OTS/IPFS) only bound *when* a Merkle root existed.
- **What it protects against:** after-the-fact modification, insertion,
  reordering or deletion of records by parties who do *not* hold the keys
  (e.g. someone with read/write access to the database file alone).
- **What it does not protect against:** a misbehaving or compromised agent, a
  malicious operator, or a host compromise that exposes the keys.
- **Signatures** prove a record was produced by a holder of the server's signing
  key — not by a particular agent or human. Any "non-repudiation" claim is in that
  limited sense only.
- **`org_id`** is a tag stored on each record (from the call or
  `MCP_WITNESS_ORG_ID`). It is *not* access isolation: any caller with a read role
  can read every org's records in the same database.

## ✨ Why mcp-witness?

AI agents take actions; auditors ask what happened. mcp-witness keeps a
tamper-evident record of what the agent *reported* — with a hash chain, Merkle
checkpoints, Ed25519 signatures, optional external anchoring (RFC 3161 TSA,
OpenTimestamps structural verification, IPFS) and compliance presets that enforce
field redaction and default retention. It is a building block for compliance, not
compliance by itself.

| Feature | mcp-witness | Standard Logging |
|---------|-------------|-----------------|
| Tamper detection | ✅ SHA-256 hash chain + Merkle trees | ❌ Text files, easy to edit |
| O(log n) verification | ✅ Merkle checkpoints with auto-backfill | ❌ Linear scan only |
| Origin signatures | ⚠️ Ed25519 signing by the server key (proves key holder, not agent identity) | ❌ None |
| External anchoring | ✅ TSA, Bitcoin (OTS), IPFS | ❌ None |
| Compliance presets | ⚠️ Enforce redaction field list + default retention; rest advisory | ❌ Manual configuration |
| PII/PHI redaction | ✅ Named fields replaced by hashes before storage | ❌ Plaintext or manual |
| GDPR right to erasure | ✅ `witness_delete` with chain preservation | ❌ Destructive deletion |
| Trusted timestamps | ⚠️ RFC 3161 TSA (strict mode default; local attestation in degraded mode) | ❌ None |
| Chain failure alerts | ✅ Webhook notifications | ❌ Silent failure |
| Org tagging | ⚠️ `org_id` tag per record (not access isolation) | ❌ None |
| Reports | ✅ HTML + PDF compliance reports | ❌ Manual |
| Dashboard | ✅ Web dashboard with live API | ❌ None |
| Structured logging | ✅ JSON log format option | ❌ Unstructured |

### 🔒 Defaults

mcp-witness refuses to start without a persistent signing key and fails closed if
the chain does not verify at startup. Each default has an opt-out — see
[docs/configuration.md](docs/configuration.md).

### ⚠️ Known Limitations

**Anchoring is asynchronous.** Records are created first, then anchored later when a
checkpoint triggers `AnchorService`. Between record creation and checkpoint anchoring,
records exist without external trust proof. Use `witness_attest` to anchor individual
records immediately.

**Single-node storage.** SQLite (default) and PostgreSQL backends are single-instance.
No built-in replication, clustering, or HA. Back up your database regularly.
See [docs/backup.md](docs/backup.md).

**Encryption at rest is opt-in.** Set `MCP_WITNESS_ENCRYPTION_KEY` (32-byte hex) to
enable AES-256-GCM field-level envelope encryption. Without it, sensitive fields are
stored as plaintext JSON.

### ⬆️ Upgrading from 0.9.x

v1.0.0 changes several defaults. To upgrade smoothly:

1. Set a signing key: `export MCP_WITNESS_SIGNING_KEY=$(openssl rand -hex 32)`
   (or `MCP_WITNESS_REQUIRE_PERSISTENT_KEY=false` to keep ephemeral keys).
2. Verify your chain first: `mcp-witness verify` (or set
   `MCP_WITNESS_FAIL_ON_STARTUP_VERIFICATION_FAILURE=false`).
3. If a webhook targets an internal collector, set
   `MCP_WITNESS_ALLOW_INTERNAL_WEBHOOKS=true`.

See the [full configuration reference](docs/configuration.md) and
[SECURITY.md](SECURITY.md) for the threat model.

## 🚀 30-Second Quickstart

```bash
# Install (from source -- the PyPI name is a different project, see above)
pip install git+https://github.com/edwiniac/mcp-witness

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

## 🛠️ MCP Tools (18 Total)

| Tool | Description |
|------|-------------|
| `witness_record` | Append an agent-reported action to the tamper-evident log |
| `witness_verify` | Verify hash chain integrity (detect tampering) |
| `witness_verify_fast` | O(log n) verification using Merkle checkpoints |
| `witness_query` | Search records by session, actor, tool, time |
| `witness_chain` | Get full decision chain for a session |
| `witness_stats` | Get audit trail statistics and health |
| `witness_health` | Check DB connectivity, signing status, anchors, version |
| `witness_attest` | RFC 3161 timestamp from external authority |
| `witness_export` | Export records for compliance reporting |
| `witness_delete` | GDPR erasure: redacts data, chain preserved, appends an erasure record (admin only) |
| `witness_search` | Full-text search across reasoning/input/output data |
| `witness_checkpoints` | List Merkle checkpoints |
| `witness_anchor` | Anchor checkpoint to TSA/Bitcoin/IPFS |
| `witness_verify_anchors` | Verify external anchor receipts |
| `witness_proof` | Get Merkle proof for a single record |
| `witness_backfill` | Create checkpoints for existing records (admin only) |
| `witness_configure_compliance` | Activate a HIPAA/GDPR/SOX/FedRAMP/SOC2/PCI DSS preset (admin only) |
| `witness_metrics` | In-process operational metrics |

Roles: **writer** = `witness_record`, `witness_attest`, `witness_anchor` (append-only);
**auditor** = read tools; **admin** = everything, including `witness_delete`,
`witness_configure_compliance` and `witness_backfill`.

## 🏛️ Compliance Presets

A preset activated with `witness_configure_compliance` (or at startup with
`MCP_WITNESS_COMPLIANCE_PRESET`) is **enforced** for: the auto-redact field list
(merged into every `witness_record`), the default retention (when the caller omits
`retention_days`), and refusing `witness_delete` for immutable presets. The change
itself is written to the chain. Attestation, anchoring frequency, encryption and
audit cadence are **advisory**. The active preset is process-local.

```python
witness_configure_compliance(preset="hipaa")
# → PHI field names redacted on every record, 6-year default retention
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

**Every record** is signed with the server's Ed25519 key (`MCP_WITNESS_SIGNING_KEY`;
required by default). A signature shows the record came from a holder of that key.

**Tamper Detection:** Change any record without the keys → its hash changes → signature invalid → Merkle root changes → checkpoint invalidated → external anchors show when the original root existed.

**GDPR Right to Erasure:** `witness_delete` (admin only) nulls data fields but preserves the hash chain, and appends an erasure record (ids, reason, count — no content) so the erasure itself is auditable.

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
- **Ed25519 JWT assertions** — signed JSON Web Tokens as alternative to shared API keys
- **Ed25519 record signing** — persistent server signing key required by default (`MCP_WITNESS_SIGNING_KEY`); proves origin from the key holder
- **SSRF-guarded webhooks** — alert URLs are blocked from reaching internal/metadata addresses
- **HMAC key protection** — optional server-side secret makes hashes un-recomputable
- **RFC 3161 TSA anchoring** — third-party timestamps (strict mode; local attestation in degraded mode)
- **OpenTimestamps** — structural verification (full Bitcoin confirmation requires external OTS client)
- **IPFS content addressing** — CIDv0/CIDv1 computation with gateway verification
- **Domain-separated Merkle trees** — prevents second-preimage attacks
- **Atomic transactions** — `BEGIN IMMEDIATE` prevents race conditions and chain forks
- **Rate limiting** — configurable token bucket (DB-backed)
- **RBAC** — admin / auditor / writer; writers are append-only and cannot erase or reconfigure
- **Encryption at rest (opt-in)** — AES-256-GCM field encryption only when `MCP_WITNESS_ENCRYPTION_KEY` is set; otherwise data is stored in plaintext
- **Dashboard auth (opt-in)** — set `MCP_WITNESS_DASHBOARD_TOKEN` to require a bearer token on the API; a warning is logged when binding to a non-loopback address without one
- **Error sanitization** — stack traces never leak to clients
- **Path traversal protection** — exports confined to allowed directories
- **Idempotency** — nonce-based replay attack prevention with per-row TTL cleanup
- **Webhook alerts** — POST to configurable URL on chain integrity failure
- **Structured logging** — optional JSON log format for production monitoring

See [CONTRIBUTING.md](CONTRIBUTING.md) for the security disclosure policy.

## 🐳 Docker

```bash
# Build
docker build -t mcp-witness .

# Run MCP server (stdio)
docker run -v witness-data:/data mcp-witness serve

# Run web dashboard
docker run -v witness-data:/data -p 9090:9090 mcp-witness dashboard

# With PostgreSQL
docker run -v witness-data:/data \
  -e MCP_WITNESS_BACKEND=postgresql \
  -e MCP_WITNESS_PG_URL=postgresql://user:pass@host:5432/db \
  mcp-witness serve
```

## 🧪 Development

```bash
git clone https://github.com/edwiniac/mcp-witness.git
cd mcp-witness
pip install -e ".[dev]"
pytest -v                    # unit tests
pytest --ignore=tests/test_storage_pg.py  # Skip PG (needs PostgreSQL)
```

### CI/CD Pipeline

| Job | Description |
|-----|-------------|
| **lint** | ruff + black formatting checks |
| **test** | Unit tests across Python 3.10, 3.11, 3.12 with coverage gate |
| **test-postgres** | 12 PostgreSQL integration tests on Postgres 16 |
| **security** | pip-audit vulnerability scanning |
| **build** | Package build + smoke test |

## 🗺️ Roadmap

- [x] Core hash chain (v0.1.0)
- [x] Merkle checkpoints + external anchoring (v0.2.0)
- [x] CLI + compliance presets + security hardening (v0.3.0)
- [x] PostgreSQL backend (v0.5.0)
- [x] Ed25519 record signing (v0.6.0)
- [x] GDPR right to erasure + schema migrations (v0.6.0)
- [x] Web dashboard with live API (v0.6.0)
- [x] HTML + PDF compliance reports (v0.6.0)
- [x] Structured JSON logging (v0.6.0)
- [x] `org_id` record tagging (v0.6.0)
- [x] Webhook alerts on chain failure (v0.6.0)
- [x] Full-text search (v0.6.0)
- [x] Adversarial hardening — TSA strict mode, canonical signing, crypto agility, key lifecycle (v0.9.0)
- [x] Merkle proof strict validation + envelope encryption + metrics (v0.9.0)
- [x] PostgreSQL full backend parity + sensitive data log scrubbing (v0.9.0)
- [x] Secure-by-default hardening — required signing key, fail-closed startup, SSRF guard (v1.0.0)
- [ ] Streaming architecture (Kafka/NATS)
- [ ] AWS KMS / cloud HSM signing
- [ ] Grafana/Prometheus metrics endpoint
- [ ] Plugin system for custom anchor providers
- [ ] Post-quantum cryptographic algorithm support (tracking NIST PQC)

## 📄 License

MIT — see [LICENSE](LICENSE)

## 👤 Author

**Edwin Isac** — AI Engineer  
[GitHub](https://github.com/edwiniac) · [Email](mailto:edwinisac007@gmail.com)
