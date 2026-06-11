# Security Threat Model — mcp-witness v1.0.0

**Status:** Current  
**Last updated:** 2026-06-10  
**Version:** Applicable to v1.0.0 codebase

---

## 1. Assets

| Asset | Value | Compromise Impact |
|-------|-------|-------------------|
| **Audit trail integrity** (hash chain + signatures) | HIGH | Undetectable tampering, loss of regulatory compliance |
| **Record data** (inputs, outputs, reasoning) | HIGH | Exposure of PII/PHI, GDPR violation, IP theft |
| **Ed25519 signing key** | CRITICAL | Attacker can forge records with valid signatures |
| **HMAC key** | HIGH | Attacker with DB access can recompute valid hash chain |
| **API keys** | MEDIUM | Unauthorized record access or insertion |
| **External anchor receipts** | MEDIUM | Loss of independent verification capability |
| **Merkle checkpoints** | MEDIUM | Degraded verification performance |
| **Anchor provider credentials** (Pinata API key, etc.) | LOW | Loss of IPFS pinning, not data integrity |

## 2. Attacker Capabilities (Adversarial Model)

### Threat Actors

| Actor | Capabilities | Motivation |
|-------|-------------|------------|
| **Malicious MCP client** | Can call any exposed MCP tool, replay requests, flood with data, craft malicious payloads | Cover tracks, inject false records, DoS |
| **Malicious insider** (compromised operator/agent) | Has valid API key, knows DB path, may have env access | Tamper with audit trail, exfiltrate data |
| **Compromised host** | Root/shell access to server, can read DB files, env vars, process memory, tamper with filesystem | Full compromise of all local secrets |
| **Network adversary** (MITM) | Can intercept MCP stdio transport, anchor provider HTTP, webhook POSTs | Replay, tamper with in-flight data, forge anchor responses |
| **Malicious anchor provider** | Can return bogus receipts, fail silently, or collude | Weaken external trust, provide fake attestations |

### Assumptions
1. **MCP transport (stdio) is trusted** — the local process boundary protects stdio from network interception.
2. **Python runtime integrity** — we assume the Python interpreter and loaded modules are not compromised at runtime.
3. **Ed25519 implementation is correct** — we trust the `cryptography` library's Ed25519 implementation.
4. **SQLite/Postgres provides ACID** — we trust the database engine for atomicity and durability.
5. **Clock is reasonably accurate** — we assume monotonic clock drift < 5 seconds for token bucket refill (not for cryptographic operations).

### Non-Goals (Out of Scope for v1.0)
- Hardware Security Module (HSM) or TPM-based key protection
- Memory-hardened key storage (secrets are in process memory)
- Full TSA certificate-chain verification (RFC 3161 PKIStatusInfo chain)
- Post-quantum cryptographic algorithms
- Formal verification of Merkle tree implementation
- Network-layer DDoS mitigation at the MCP server level

## 3. Trust Boundaries

```
┌──────────────────────────────────────────────────────────┐
│                    MCP CLIENT (untrusted)                 │
│  • Can call any exposed tool                              │
│  • Can provide arbitrary arguments                        │
│  • Can replay requests                                    │
└──────────────────────┬───────────────────────────────────┘
                       │  stdio (MCP protocol)
           ┌───────────▼────────────┐
           │   TRUST BOUNDARY 1     │  ← Authentication + Authorization
           │   server.py dispatch    │
           └───────────┬────────────┘
                       │
           ┌───────────▼────────────┐
           │   TRUST BOUNDARY 2     │  ← Input validation + rate limiting
           │   security.py guards   │
           └───────────┬────────────┘
                       │
┌──────────────────────▼────────────────────────────────────┐
│               TRUSTED SERVER PROCESS                       │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │ hasher.py │  │merkle.py │  │security.py│  │ auth.py  │ │
│  │ (crypto)  │  │ (proofs) │  │  (keys)   │  │ (RBAC)   │ │
│  └──────────┘  └──────────┘  └───────────┘  └──────────┘ │
│                                                            │
│  ┌──────────────────────────────────────────────────┐     │
│  │              storage.py / storage_pg.py           │     │
│  └──────────────────────────────────────────────────┘     │
└──────────────────────┬────────────────────────────────────┘
                       │  SQL / file I/O
           ┌───────────▼────────────┐
           │   TRUST BOUNDARY 3     │  ← OS file permissions
           │   SQLite file / PG DB  │
           └────────────────────────┘
                       │
           ┌───────────▼────────────┐
           │   TRUST BOUNDARY 4     │  ← Network (HTTPS)
           │   Anchor providers     │
           │   (TSA, OTS, IPFS)     │
           └────────────────────────┘
```

## 4. Security Invariants

### Invariant 1: Append-Only Chain
> Every record in the chain has a `prev_hash` that cryptographically references its predecessor. Records cannot be inserted, deleted, or reordered without detection.

**Enforced by:** `compute_record_hash()` in `hasher.py` includes `prev_hash` in the hash payload. `verify_chain()` in `storage.py` checks `record.prev_hash == expected_prev_hash` for each record. `BEGIN IMMEDIATE` ensures no concurrent writers create sequence gaps.

**Current gap:** Auto-generated ephemeral signing keys (when `MCP_WITNESS_SIGNING_KEY` not set) weaken this invariant across process restarts — different keys sign different records, making it impossible to verify a consistent signer identity over time.

### Invariant 2: Signer Authenticity
> Every signed record can be cryptographically verified against a known public key that is associated with an authorized signer.

**Enforced by:** `sign_record_hash()` + `verify_record_signature()` in `hasher.py`. Public key stored per-record in `signer_public_key`.

**Current gap:** No key rotation metadata (no key IDs, validity windows, or next-key pointers). No revocation list or trust-store. An attacker who compromises a key can forge records with no way to distinguish pre-compromise from post-compromise signatures.

### Invariant 3: Checkpoint Immutability
> Once a Merkle checkpoint is created and anchored, the records it covers cannot be tampered with without detection.

**Enforced by:** `build_merkle_tree()` in `merkle.py` with domain-separated hashes. `verify_chain_fast()` in `storage.py` rebuilds trees and compares roots. External anchors provide timestamps for the root.

**Current gap:** No periodic re-verification of checkpoints. A compromise after checkpoint creation but before anchoring could go undetected until explicit verification is run.

### Invariant 4: Verifiable Anchor Provenance
> External anchor receipts cryptographically prove a Merkle root existed at a specific time with a specific provider.

**Enforced by:** `TSAProvider.verify()`, `OpenTimestampsProvider.verify()`, `IPFSProvider.verify()` in `anchoring.py`.

**Current gap (CRITICAL):** `TSAProvider.anchor()` falls back to `local_attestation` when the TSA is unreachable. This local attestation is NOT an RFC 3161 timestamp — it's a locally-generated JSON blob. It silently degrades the trust guarantee from "legal-grade" to "self-asserted." Similarly, `OpenTimestampsProvider.verify()` is "structural-only" — it does NOT check the Bitcoin blockchain.

## 5. Specific Threat Scenarios

### T1: Replay Attack
**Attacker:** Malicious MCP client.  
**Mechanism:** Resend a valid `witness_record` call.  
**Current defense:** Idempotency check via `compute_action_fingerprint()` + `check_idempotency()` with nonce store.  
**Gap:** No timestamp window enforcement on idempotency. A replay after nonce TTL expires (default 3600s) would succeed.

### T2: Chain Forgery via Key Compromise
**Attacker:** Malicious insider with HMAC key access.  
**Mechanism:** Directly INSERT into witness_records table with computed hashes.  
**Current defense:** HMAC-SHA256 chain makes hashes un-recomputable without the key.  
**Gap:** HMAC key lives in process memory as plain bytes. A compromised host can read `/proc/<pid>/mem` or `/proc/<pid>/environ` to extract it.

### T3: Silent Trust Degradation (Anchor Fallback)
**Attacker:** Network adversary blocking TSA access.  
**Mechanism:** Block network to TSA, trigger local attestation fallback.  
**Current defense:** None — `TSAProvider.anchor()` silently falls back to `local_attestation`.  
**Gap:** The resulting receipt is stored with `anchor_type=TSA` but is NOT a real TSA timestamp. This violates the "no silent degradation" requirement.

### T4: Data Exfiltration via Export
**Attacker:** Malicious MCP client with auditor role.  
**Mechanism:** Call `witness_export` with crafted output path to write outside allowed directory.  
**Current defense:** `validate_export_path()` in security.py with `relative_to()` check.  
**Gap:** TOCTOU race between path validation and file open. Symlink substitution window exists.

### T5: PII/PHI Exposure at Rest
**Attacker:** Malicious insider with filesystem access to SQLite DB.  
**Mechanism:** Directly read witness_records.input_data and output_data columns (stored as JSON text).  
**Current defense:** Field-level redaction via `redact_fields()` replaces values with `[REDACTED:sha256:abc123...]`.  
**Gap:** Non-redacted fields stored in plaintext. No envelope encryption for sensitive columns.

### T6: Flood DoS via Unbounded Payload
**Attacker:** Malicious MCP client.  
**Mechanism:** Send records with 10MB payloads at max rate.  
**Current defense:** MAX_PAYLOAD_SIZE=10MB, token bucket rate limiter at 1000/s.  
**Gap:** At 1000 req/s × 10MB = 10GB/s write throughput, DB fills quickly. No backpressure mechanism. No per-actor quota beyond rate limiting.

### T7: Key Rotation Gap
**Attacker:** Malicious insider who obtained old signing key.  
**Mechanism:** Use old key to sign forged records with backdated timestamps.  
**Current defense:** None — all records are signed with the current key.  
**Gap:** No key rotation metadata means verifiers cannot distinguish records signed with old (potentially compromised) keys from current keys. No signature timestamp in signed payload prevents detection of backdated signatures.

---

## 6. Assurance Level Statement

**Current assurance level (v1.0.0): ASSURANCE-3 (Adversary-Resistant) when configured with persistent keys (signing + HMAC + encryption) and external anchoring**

- Cryptographic hash chain provides tamper evidence
- Ed25519 signatures provide non-repudiation within a single key lifetime
- Merkle checkpoints enable efficient verification
- External anchoring is available but not guaranteed (silent fallback)

**Target assurance level (v1.0): ASSURANCE-3 (Adversary-Resistant)**

- All cryptographic guarantees hold against active adversaries
- No silent degradation of trust guarantees
- Key lifecycle management with rotation and revocation
- Encrypted sensitive data at rest
- Comprehensive monitoring and alerting
