# Gap Analysis & Execution Plan — mcp-witness Adversarial Hardening

**Date:** 2026-05-12  
**Base:** v0.6.0  
**Target:** v1.0.0 (adversary-resistant)  
**Analyst:** Teacher (Classroom system)

---

## GAP ANALYSIS

### A) Formal Threat Model & Security Invariants

**ALREADY DONE:**
- Implicit security invariants in code: append-only chain (`storage.py:L583-630` verify_chain), domain-separated Merkle trees (`merkle.py`), genesis hash (`hasher.py:L176`), HMAC protection (`hasher.py:L73-78`)
- README.md security section listing capabilities
- SECURITY.md created with this analysis

**PARTIALLY DONE:**
- No programmatic invariant assertions — invariants exist only as verification methods called on demand
- No runtime invariant checks after each record insertion (chain break could go undetected for hours)

**MISSING:**
- No `security_invariants.py` module with explicit, testable invariant assertions
- No startup integrity verification (chain verified only when `witness_verify` is called)
- No periodic invariant assertion mechanism

**PRIORITY:** P1 — Threat model doc is now written. Invariant assertions in code needed.

---

### B) Cryptographic Hardening

**ALREADY DONE:**
- Ed25519 signing of record_hash (`hasher.py:L197-211 sign_record_hash`)  
- HMAC chain protection (`hasher.py:L73-78`, `security.py:L30-52 get_hmac_key`)
- Genesis hash with purpose binding (`hasher.py:L176 GENESIS_HASH`)
- Domain-separated Merkle trees with zero-leaf padding (`merkle.py:L14-17 LEAF_PREFIX/NODE_PREFIX`, `merkle.py:L23 MERKLE_ZERO_LEAF`)
- Signer public key stored per-record (`storage.py:L285 signer_pk`, `models.py:L97 signer_public_key`)

**PARTIALLY DONE:**
- **Key lifecycle:** `security.py:L112-165 get_signing_key()` only supports a single key per process lifetime. Auto-generates ephemeral key if not configured (L150-155), meaning different process restarts have different keys — no continuity.
- **Algorithm versioning:** No algorithm identifier in signed data. `sign_record_hash()` signs exactly `record_hash.encode("utf-8")` — no algo header. A future migration to Ed448 or post-quantum would have no way to distinguish signature types.
- **Merkle proof validation:** `merkle.py:L164-171 verify_merkle_proof()` accepts arbitrary proof_path — no strict leaf index bounds check, no rejection of zero-length paths.

**MISSING:**
- **Key rotation metadata:** No key_id, no validity window (not_before/not_after), no next_key pointer, no rotation event log.
- **Revocation list / trust store:** No mechanism to mark keys as revoked. No trusted key store file format.
- **Canonicalized payload for signing:** Current `sign_record_hash()` signs only the hex string of record_hash, not a canonicalized view of all record fields (timestamp, sequence, prev_hash, etc.). An attacker who can recompute a valid record_hash (with HMAC key) could also forge a valid signature.
- **HMAC key hardening:** `security.py:L32-33` stores key as plain Python `bytes` in module-level variable. No key wrapping, no secure memory (e.g., `mlock`), no attempt to zero memory on process exit.
- **Merkle proof strict validation:** `verify_merkle_proof()` (merkle.py:L164) doesn't validate that `leaf_index < tree_size`, doesn't reject proofs with flagrantly wrong structure, doesn't validate proof depth matches tree height.

**PRIORITY:** 
- **P0:** Algorithm versioning + canonicalized signing payload + Merkle proof strict validation  
- **P1:** Key rotation metadata + revocation trust store  
- **P2:** HMAC key memory hardening (requires OS-specific code)

---

### C) Access Control & Identity

**ALREADY DONE:**
- Three-role RBAC with tool-level permissions (`auth.py:L36-57 ROLE_PERMISSIONS`)
- API key loading from env vars (`auth.py:L63-92 load_api_keys`)
- Authentication + authorization in server dispatch (`server.py:L445-446 authenticate/authorize`)
- Idempotency protection (`security.py:L171-188 check_idempotency`, DB-backed nonce store)

**PARTIALLY DONE:**
- **Auth model is shared-token:** `auth.py:L63-92` loads keys from `MCP_WITNESS_API_KEYS` env var. Keys are plaintext strings in environment — visible to any process on the host via `/proc/<pid>/environ`. Minimum key length check is 16 chars (L86) which is weak by modern standards.
- **Anti-replay:** `security.py:L200-213 compute_action_fingerprint` creates a nonce but only same-fields-same-timestamp detection works. No explicit timestamp window — `check_idempotency()` (L171-188) accepts a ttl_seconds parameter but the caller passes fingerprint, not timestamp. Replay detection window equals idempotency TTL (3600s default).

**MISSING:**
- **No mTLS or JWT auth option:** The MCP protocol uses stdio transport, making mTLS impractical. However, signed JWT assertions (Ed25519-signed) could replace shared tokens for strong identity.
- **No per-key rate limiting:** `storage.py:L820 check_rate_limit` uses `bucket_id=actor_id`, not the authenticated key_id. Multiple keys for same actor_id share the same bucket.
- **No key rotation without restart:** Keys loaded once at import time. Changing keys requires process restart.

**PRIORITY:** 
- **P0:** JWT assertion support (or at minimum document that mTLS is impractical on stdio transport + justify)  
- **P1:** Per-key rate limiting + key rotation without restart  
- **P2:** Key minimum length increase to 32 chars

---

### D) Storage & Consistency

**ALREADY DONE:**
- Atomic append via `BEGIN IMMEDIATE` (`storage.py:L263-302`) and `asyncpg.Connection.transaction()` (`storage_pg.py` equivalent)
- WAL mode for SQLite (`storage.py:L148-149 PRAGMA journal_mode=WAL`)
- SQLITE_BUSY retry with exponential backoff (`storage.py:L250-267 _retry_on_busy`, 3 retries, 50ms base)
- Schema versioning + migration framework (`storage.py:L180-215`)
- Connection pool for PostgreSQL (`storage_pg.py:L48-49 PG_POOL_MIN/MAX`, `L95-99`)

**PARTIALLY DONE:**
- **Backend parity gaps:**
  - `redact_record()` exists in SQLite (`storage.py:L749-814`) but NOT in Postgres (`storage_pg.py` has no such method)
  - `search()` exists in SQLite (`storage.py:L556-587`) but NOT in Postgres
  - Postgres schema is missing `org_id` column (SQLite schema has it at `storage.py:L162`)
  - Postgres `_cleanup_expired_nonces` only does 24h hard cleanup (`storage_pg.py:L642-653`), missing per-row TTL cleanup that SQLite has (`storage.py:L723-747`)
- **Retry/backoff:** Only SQLITE_BUSY has retries. No retry for Postgres connection failures, no retry for transient anchor provider failures, no retry budget or circuit breaker.

**MISSING:**
- **Corruption detection:** No checksums on stored rows, no periodic `PRAGMA integrity_check` for SQLite, no `pg_verify_checksums` equivalent for Postgres. A bit-flip in the DB file could go undetected.
- **Recovery playbook:** No documentation on what to do when chain breaks, when checkpoint is invalid, or when DB is corrupted.
- **Observable retry metrics:** No counters for retry attempts, no latency histograms for retried operations.

**PRIORITY:** 
- **P0:** Full backend parity (redact_record, search, org_id in Postgres)  
- **P1:** Corruption detection (startup integrity check, periodic PRAGMA)  
- **P2:** Recovery playbook + retry metrics

---

### E) Secure Data Handling

**ALREADY DONE:**
- Payload size validation: `storage.py:L112 _validate_payload_size`, 10MB default
- Input validation: `security.py:L217-236 validate_inputs` (session_id, actor_id, reasoning)
- Field redaction: `hasher.py:L180-225 redact_field/redact_fields`
- Path traversal protection: `security.py:L200-215 validate_export_path`
- GDPR right to erasure: `storage.py:L749-814 redact_record`

**PARTIALLY DONE:**
- **Redaction is hash-based:** `hasher.py:L204` sets value to `[REDACTED:sha256:<first_16_chars>]`. This is a pseudonym, not true redaction — the hash is linkable (same input → same redacted value).
- **No schema constraints beyond Pydantic:** Input data is `Optional[dict[str, Any]]` in the model. No JSON Schema validation against expected tools/actions.
- **Export path:** `validate_export_path()` (security.py:L200-215) resolves path, checks containment, then returns. `handle_export` (server.py:L247-250) opens file in a separate step — TOCTOU gap.

**MISSING:**
- **Envelope encryption at rest:** Compliance presets reference `encryption="aes-256-gcm"` (compliance.py:L58 etc.) but this is purely a string field — no encryption code exists. Sensitive fields (PII, PHI) are stored as plaintext JSON in `input_data`/`output_data` columns.
- **Policy-based masking/tokenization:** No support for format-preserving masking (e.g., `john.doe@email.com` → `j***@e***.com`) or tokenization (replace with vault reference).
- **TOCTOU-resistant export:** No atomic write-and-validate. File opened after path resolution in a separate step.
- **Symlink-safe export:** `Path.resolve()` follows symlinks but after resolution, the file could be replaced with a symlink before `open()`.

**PRIORITY:** 
- **P0:** Envelope encryption for sensitive fields at rest  
- **P1:** Policy-based masking + TOCTOU hardening for export  
- **P2:** JSON Schema validation for tool inputs

---

### F) Anchoring Correctness

**ALREADY DONE:**
- Three anchor providers: TSA (RFC 3161), OpenTimestamps (Bitcoin), IPFS
- Multi-provider concurrent anchoring (`anchoring.py:L633-656 AnchorService.anchor`)
- Receipt storage with verification tracking (`storage.py:L934-987 verify_anchors`)
- Proper DER-encoded TSA request (`anchoring.py:L115-156 _build_tsa_request`)
- CIDv0/CIDv1 computation for IPFS (`anchoring.py:L45-75`)

**PARTIALLY DONE:**
- **CRITICAL: Fake fallback in TSA provider:** `anchoring.py:L198-231` — when TSA is unreachable, `TSAProvider.anchor()` catches the exception and creates a `local_attestation` receipt with `anchor_type=AnchorType.TSA`. This receipt is NOT an RFC 3161 timestamp. It is indistinguishable from a real receipt in the database (same `anchor_type` column value). This silently degrades trust.
- **OTS verification is "structural only":** `anchoring.py:L475` comment: `"WARNING: Structural-only verification"`. Does NOT check Bitcoin blockchain. The `_ots_validate_structure()` method only validates binary format.
- **IPFS verification can fail on gateway issues:** Returns False if gateway is unreachable, which is correct behavior but no offline verification alternative exists.

**MISSING:**
- **Strict mode:** No configuration to fail anchoring when external proof is unobtainable. Current behavior always falls back.
- **Offline verification story:** No documentation on how an auditor with the SQLite file and anchor receipts can verify independently without running the server.
- **Continuous anchor monitoring:** Anchors are verified only when `witness_verify_anchors` is called. No periodic background re-verification.
- **Persist verifiable receipt artifacts as exportable files:** Raw receipts stored in DB, but no `export_anchor_receipt` tool for auditors.

**PRIORITY:** 
- **P0:** Remove fake fallback (or make it explicit with distinct anchor_type)  
- **P0:** Add strict mode that fails on external proof failure  
- **P1:** Offline verification documentation + receipt export tool  
- **P2:** Continuous anchor monitoring background task

---

### G) Abuse Resistance & Reliability

**ALREADY DONE:**
- DB-backed token bucket rate limiting (`storage.py:L820-868`, `security.py:L65-79`)
- DB-backed idempotency (`storage.py:L876-912`)
- Input validation (length limits, character patterns)
- Pagination on query (limit/offset)

**PARTIALLY DONE:**
- **Rate limiting granularity:** Default bucket `"default"` — only per-actor when actor_id is passed. No hierarchical limits (global ceiling + per-actor).
- **Pagination upper bounds:** `handle_export` (server.py) uses `limit=10000`. `handle_chain` uses `limit=10000`. But no hard server-side maximum enforced — a client could request `limit=99999999` directly.
- **Graceful shutdown:** `server.py:L456 main()` calls `await storage.close()` in `finally` but no signal handler. If the process is killed mid-write, the SQLite WAL should recover, but this isn't documented.

**MISSING:**
- **Clock integrity strategy:** `time.monotonic()` is used nowhere. Token bucket refill uses `datetime.now()` which can jump backward (NTP adjustment). No drift detection alerts.
- **Backpressure:** When rate limit is exhausted, `check_rate_limit` raises ValueError — but if thousands of requests pile up in the asyncio event loop, there's no backpressure signal to the MCP transport layer.
- **Hard pagination ceiling:** No upper bound enforced on `limit` parameter in tool schemas. A client can DoS by requesting `limit=99999999999`.
- **In-flight write tracking:** Graceful shutdown cannot distinguish "safe to close" vs "transaction in progress."

**PRIORITY:** 
- **P0:** Hard pagination ceiling (max 10000)  
- **P1:** Graceful shutdown with in-flight tracking + clock strategy  
- **P2:** Backpressure mechanism + hierarchical rate limits

---

### H) Operational Readiness

**ALREADY DONE:**
- Structured JSON logging (`logging.py` with `MCP_WITNESS_LOG_FORMAT=json`)
- Webhook alerts on chain failure (`webhook.py`, `storage.py:L630-638`)
- Health check tool (`witness_health`, `server.py:L379-431`)
- Configurable log levels (`MCP_WITNESS_LOG_LEVEL`)

**PARTIALLY DONE:**
- **Logging:** JSON format available but no sensitive-data scrubbing. `JSONFormatter.format()` (logging.py:L27-41) dumps message + extra fields verbatim. An API key or PII in a log message would be logged as plaintext.
- **Metrics:** No structured metrics endpoint (Prometheus, OpenTelemetry). Only tool invocations can query state.

**MISSING:**
- **Sensitive data scrubbing in logs:** No regex/pattern-based redaction of API keys, passwords, PII in log messages.
- **Structured metrics:** Chain integrity failures counter, signature verification failures counter, anchor verification failures counter, lock contention duration histogram, rate limit hits counter, idempotency duplicate counter.
- **Incident response runbook:** No step-by-step guide for: chain break detected, signature verification failures, anchor provider unreachable, DB corruption.
- **Backup/restore documentation:** No documented procedure for backing up SQLite WAL safely, no Postgres pg_dump integration, no restore validation steps.
- **Alerting beyond webhook:** No Slack, PagerDuty, or email integration.

**PRIORITY:** 
- **P0:** Sensitive data scrubbing + chain/signature/anchor metrics  
- **P1:** Incident response runbook  
- **P2:** Backup/restore docs + additional alerting channels

---

### I) Delivery Discipline

**ALREADY DONE:**
- CI pipeline: lint (ruff), tests (pytest), security (pip-audit) → `.github/workflows/ci.yml`
- Black formatting enforcement
- Coverage tracking (≥65%)
- Versioned schema migrations (`storage.py:L180-215`)

**PARTIALLY DONE:**
- **CI gates:** ruff lint + pip-audit, but NO SAST (Bandit/semgrep), NO type checking (mypy)
- **Schema migration:** Framework exists but no CLI tooling (`mcp-witness migrate` command doesn't exist)
- **No SBOM:** No CycloneDX or SPDX generation

**MISSING:**
- **SAST gate:** Bandit or semgrep in CI with config file
- **Type checking gate:** mypy --strict (or at least mypy with basic checks)
- **Reproducible builds:** No SOURCE_DATE_EPOCH, no hash verification of build artifacts
- **SBOM generation:** No CycloneDX/SPDX SBOM for dependency tracking
- **Unsupported claims in docs:** 
  - README.md L26: "Legal-grade proof ✅ RFC 3161 timestamps" — misleading because TSA falls back to local attestation (not legal-grade)
  - README.md features table: "Legal-grade proof" row — overstates capability
  - README.md L146: "Bitcoin OpenTimestamps — free anchoring to the Bitcoin blockchain" — verification is structural-only, doesn't check blockchain

**PRIORITY:** 
- **P0:** SAST gate + type checking gate + fix unsupported claims in README  
- **P1:** SBOM generation + migration CLI  
- **P2:** Reproducible builds

---

## EXECUTION PLAN — 3 Project Groups

### Group Allocation Strategy

**Sequential** execution required: Group 1 → Group 2 → Group 3.  
Group 1 establishes the trust baseline. Group 2 hardens crypto. Group 3 adds operational polish.  
Groups CANNOT overlap on file assignments.

| Group | File Assignments | Effort |
|-------|-----------------|--------|
| Group 1: Trust Foundation | `security.py`, `anchoring.py`, `storage.py`, `storage_pg.py`, `storage_base.py`, `server.py`, `auth.py`, `README.md`, `SECURITY.md` | LARGE (4-6h) |
| Group 2: Crypto Hardening | `hasher.py`, `merkle.py`, `models.py`, new: `crypto_agility.py`, new: `key_lifecycle.py` | MEDIUM (2-3h) |
| Group 3: Operational Excellence | `logging.py`, `webhook.py`, new: `metrics.py`, new: `runbook.md`, `pyproject.toml`, `.github/workflows/ci.yml`, new: `.bandit.yaml`, new: `mypy.ini` | MEDIUM (2-3h) |

---

### GROUP 1: TRUST FOUNDATION (P0 Items)

**Files:** `security.py`, `anchoring.py`, `storage.py`, `storage_pg.py`, `storage_base.py`, `server.py`, `auth.py`, `README.md`, `SECURITY.md`  
**Effort:** LARGE (4-6h)  
**Goal:** Eliminate silent trust degradation, complete backend parity, encrypt data at rest, harden exports, add security gates.

#### Task List

##### T1.1 — Remove TSA Fake Fallback (anchoring.py)
- **File:** `src/mcp_witness/anchoring.py`, `TSAProvider.anchor()` method (lines ~198-231)
- **What:** Remove the try/except fallback that creates `local_attestation` when TSA is unreachable. When TSA fails, raise the exception (fail closed).
- **Add:** A separate `TSAProvider.anchor_or_none()` method that returns None on failure for callers that want graceful degradation with explicit awareness.
- **Add:** `anchor_type` for local attestation as distinct type `LOCAL = "local"` in `AnchorType` enum — used only when explicitly requested.
- **Tests:** `test_anchoring.py` — add `test_tsa_fails_closed()`, `test_tsa_anchor_or_none_returns_none()`, `test_local_anchor_type_distinct()`

##### T1.2 — Add Strict Mode for Anchoring (anchoring.py, security.py, server.py)
- **File:** `src/mcp_witness/security.py` — add `ANCHOR_STRICT_MODE` env var (default: `True`)
- **File:** `src/mcp_witness/anchoring.py`, `AnchorService.anchor()` — check strict mode; if True and any provider fails, raise `AnchorFailureError` (new exception in anchoring.py)
- **File:** `src/mcp_witness/server.py`, `handle_anchor()` — catch `AnchorFailureError` and return structured error
- **Tests:** `test_anchoring.py` — `test_strict_mode_fails_on_provider_error()`, `test_non_strict_mode_returns_partial()`

##### T1.3 — PostgreSQL Backend Parity (storage_pg.py)
- **File:** `src/mcp_witness/storage_pg.py`
- **What:** Add `redact_record()` method matching SQLite signature (record_id, session_id, reason params). Add `search()` method with LIKE pattern matching (matching SQLite implementation at storage.py:L556-587). Add `org_id` column to schema and INSERT statements. Fix `_cleanup_expired_nonces` to do per-row TTL cleanup (match SQLite at storage.py:L723-747).
- **Tests:** Update `test_storage_pg.py` — add `test_redact_record_single()`, `test_redact_record_session()`, `test_search()`, `test_org_id_insert_and_query()`

##### T1.4 — Envelope Encryption for Sensitive Fields at Rest (security.py, storage.py, storage_pg.py)
- **File:** `src/mcp_witness/security.py` — add:
  - `get_data_encryption_key()` — reads `MCP_WITNESS_DEK` env var (32-byte hex key), generates one if not set
  - `encrypt_field(plaintext: str) -> str` — AES-256-GCM encryption, returns base64-encoded ciphertext with nonce prepended
  - `decrypt_field(ciphertext: str) -> str` — decrypts, raises if authentication fails
  - `should_encrypt_field(field_path: str, sensitivity: Sensitivity) -> bool` — decides based on sensitivity + field path
- **File:** `src/mcp_witness/storage.py`, `record()` method — after redaction, encrypt sensitive fields (those matching `should_encrypt_field`) in input_data/output_data before JSON serialization. Add `_encrypt_dict_fields()` helper.
- **File:** `src/mcp_witness/storage.py`, `_row_to_record()` — decrypt fields when reading back (for authorized readers). Add `session_key` concept to avoid decrypting for unauthorized access.
- **File:** `src/mcp_witness/storage_pg.py` — mirror encryption/decryption in record() and _row_to_record().
- **Tests:** `test_security.py` — `test_encrypt_decrypt_roundtrip()`, `test_decrypt_tampered_ciphertext_fails()`, `test_should_encrypt_pii()`, `test_should_encrypt_public()`. `test_storage.py` — `test_record_encrypts_pii_fields()`, `test_read_decrypts_pii_fields()`

##### T1.5 — Sensitive Data Scrubbing in Logs (logging.py)
- **File:** `src/mcp_witness/logging.py` — add `SensitiveDataFilter(logging.Filter)` that:
  - Redacts any string matching API key patterns (min 16 chars of `[a-zA-Z0-9+/=_-]`)
  - Redacts hex strings >= 64 chars (potential keys)
  - Uses `re.sub()` to replace matched patterns with `[REDACTED]`
  - Register in `setup_structured_logging()`
- **Tests:** `test_security.py` — `test_log_filter_redacts_api_key()`, `test_log_filter_preserves_normal_text()`

##### T1.6 — SAST + Type Check CI Gates (.github/workflows/ci.yml, pyproject.toml)
- **File:** `.github/workflows/ci.yml` — add `sast` job (Bandit scan) and `typecheck` job (mypy)
- **File:** `pyproject.toml` — add `[tool.bandit]` config (exclude tests/, skip B101 assert, B311 random) and `[tool.mypy]` config (strict = false initially, warn_unused_configs)
- **File:** New `.bandit.yaml` — minimal config for project

##### T1.7 — Fix Unsupported Claims in README (README.md)
- **File:** `README.md`
- **What:** Change "Legal-grade proof ✅ RFC 3161 timestamps" to "RFC 3161 timestamps (when TSA available)". Add footnote that local attestation is a degraded mode. Change "Bitcoin OpenTimestamps — free anchoring to the Bitcoin blockchain" to "OpenTimestamps — structural verification (full Bitcoin confirmation requires ots CLI)". Update assurance level statement.
- **Add:** Section "Assurance Levels" explaining ASSURANCE-2 vs ASSURANCE-3 distinction.

##### T1.8 — Hard Pagination Ceiling (server.py)
- **File:** `src/mcp_witness/server.py` — add `MAX_QUERY_LIMIT = 10000` constant. In `handle_query()`, `handle_export()`, `handle_chain()`, `handle_search()`: clamp `limit` to `min(requested_limit, MAX_QUERY_LIMIT)`. Add `MAX_OFFSET = 100000` and clamp offset.
- **Tests:** `test_server.py` — `test_query_limit_clamped()`, `test_export_limit_clamped()`

#### Quality Gates for Group 1:
- [ ] All existing 251 tests pass
- [ ] New adversarial tests pass: TSA fail-closed, encryption roundtrip, log scrubbing, backend parity
- [ ] ruff clean
- [ ] mypy passes (new gate, may need type: ignore annotations)
- [ ] Bandit scan passes (no HIGH severity)
- [ ] README claims verified against implementation behavior

---

### GROUP 2: CRYPTO HARDENING (P0-P1 Items)

**Files:** `hasher.py`, `merkle.py`, `models.py`, NEW: `crypto_agility.py`, NEW: `key_lifecycle.py`  
**Effort:** MEDIUM (2-3h)  
**Goal:** Add algorithm versioning, canonicalized signing, key lifecycle management, strict Merkle proof validation.

#### Task List

##### T2.1 — Algorithm Versioning for Signatures (hasher.py, crypto_agility.py)
- **File:** NEW `src/mcp_witness/crypto_agility.py`
- **What:** Define `CryptoAlgorithm` enum / constants:
  ```python
  SIGNING_ALG_ED25519_SHA256_V1 = "ed25519+sha256:v1"
  HASH_CHAIN_ALG_SHA256_V1 = "sha256:v1"
  HASH_CHAIN_ALG_HMAC_SHA256_V1 = "hmac-sha256:v1"
  ```
  Define `versioned_sign(record_hash: str, signing_key, algo: str) -> dict` returning `{"algo": ..., "signature": ..., "key_id": ...}`.
  Define `versioned_verify(record_hash, sig_data, public_key_bytes) -> bool`.
- **File:** `src/mcp_witness/hasher.py` — deprecate bare `sign_record_hash()` (keep for backward compat, mark with deprecation warning). Update `compute_record_hash()` to accept optional `algo` parameter.
- **File:** `src/mcp_witness/storage.py`, `record()` — use `versioned_sign()` instead of `sign_record_hash()`. Store full sig_data as JSON in `signature` column (backward compat: detect legacy hex-only signatures).
- **Tests:** `test_hasher.py` — `test_versioned_sign_includes_algo()`, `test_versioned_verify_rejects_wrong_algo()`, `test_backward_compat_bare_signature()`

##### T2.2 — Canonicalized Signing Payload (hasher.py)
- **File:** `src/mcp_witness/hasher.py` — add `canonicalize_record(prev_hash, sequence, timestamp, action_type, actor_id, input_hash, output_hash, tool_name) -> bytes` that produces a deterministic canonical byte string (JSON with sorted keys, consistent types). Add `sign_canonical_record(canonical_bytes, signing_key, algo) -> str` and `verify_canonical_signature(canonical_bytes, signature, public_key_bytes) -> bool`.
- **File:** `src/mcp_witness/storage.py`, `record()` — use canonicalized payload for signing instead of just record_hash. Store `canonical_signature` separately (or prefix with algo version byte).
- **Rationale:** Signing the full canonical record fields (not just record_hash) provides protection even if HMAC key is compromised — an attacker would need to construct a valid record AND match the signature over all fields, not just the hash.
- **Tests:** `test_hasher.py` — `test_canonicalize_deterministic()`, `test_canonicalize_different_records_different_bytes()`, `test_sign_canonical_verify_roundtrip()`

##### T2.3 — Key Lifecycle Management (key_lifecycle.py)
- **File:** NEW `src/mcp_witness/key_lifecycle.py`
- **What:** 
  - `SigningKeyMetadata` dataclass: `key_id: str`, `public_key_hex: str`, `not_before: datetime`, `not_after: Optional[datetime]`, `revoked: bool`, `revoked_at: Optional[datetime]`, `next_key_id: Optional[str]`
  - `KeyTrustStore` class: loads from JSON file (`MCP_WITNESS_TRUST_STORE` env var), provides `get_active_keys()`, `is_revoked(key_id)`, `verify_key_chain(key_id)`
  - `rotate_key()` function: generates new key, saves metadata, updates env var pointer (for external orchestration)
  - Trust store JSON format:
    ```json
    {
      "keys": {
        "key-001": {
          "public_key_hex": "abcd...",
          "not_before": "2026-01-01T00:00:00Z",
          "not_after": "2027-01-01T00:00:00Z",
          "revoked": false,
          "next_key_id": "key-002"
        }
      },
      "current_key_id": "key-002"
    }
    ```
- **File:** `src/mcp_witness/security.py` — update `get_signing_key()` to also return `key_id` from trust store. Update `get_public_key_hex()` to accept optional `key_id`.
- **File:** `src/mcp_witness/models.py` — add `signer_key_id: Optional[str]` field to `WitnessRecord`.
- **File:** `src/mcp_witness/storage.py`, `record()` — store `key_id` alongside signature. In `verify_chain()`, use `key_id` to look up correct public key for signature verification.
- **Tests:** `test_key_lifecycle.py` — `test_trust_store_load()`, `test_is_revoked()`, `test_verify_key_chain()`, `test_rotate_key_creates_successor()`

##### T2.4 — Strict Merkle Proof Validation (merkle.py)
- **File:** `src/mcp_witness/merkle.py`, `verify_merkle_proof()` — add:
  - Reject if `proof_path` is empty (but tree has more than 1 leaf)
  - Reject if `leaf_index` is negative
  - Validate proof depth: `len(proof_path)` must equal `ceil(log2(tree_size))` (pass tree_size as new parameter, or compute from proof)
  - Add `verify_merkle_proof_strict()` that takes tree_size and validates everything
- **File:** `src/mcp_witness/storage.py`, `get_merkle_proof()` — include `tree_size` in returned dict
- **Tests:** `test_merkle.py` — `test_verify_rejects_empty_proof_for_non_trivial_tree()`, `test_verify_rejects_wrong_depth()`, `test_verify_rejects_negative_leaf_index()`

##### T2.5 — Startup Chain Integrity Verification (storage.py, server.py)
- **File:** `src/mcp_witness/storage.py`, `SqliteStorage.connect()` — after schema creation, run `verify_chain_fast()` and log result. If chain is invalid, log CRITICAL and set `self._chain_valid = False`.
- **File:** `src/mcp_witness/server.py`, `handle_health()` — include `chain_verified_at_startup` field.
- **File:** `src/mcp_witness/server.py`, `main()` — check `storage._chain_valid` and log warning (don't crash — allow degraded operation with clear signal).

#### Quality Gates for Group 2:
- [ ] All existing 251 tests pass with backward-compat for old signature format
- [ ] New crypto tests: algorithm versioning, canonical signing, key lifecycle, strict Merkle
- [ ] Trust store format documented and validated on load
- [ ] Signature verification works across key rotations (test with 3 keys)
- [ ] ruff clean, mypy passes

---

### GROUP 3: OPERATIONAL EXCELLENCE (P1-P2 Items)

**Files:** `logging.py`, `webhook.py`, NEW: `metrics.py`, NEW: `runbook.md`, `pyproject.toml`, `.github/workflows/ci.yml`  
**Effort:** MEDIUM (2-3h)  
**Goal:** Add structured metrics, incident response guide, SBOM, graceful shutdown, backup docs.

#### Task List

##### T3.1 — Structured Metrics (metrics.py)
- **File:** NEW `src/mcp_witness/metrics.py`
- **What:** Simple in-process metrics registry (no external dependency):
  - `Counter` class: atomic increment, get value
  - Metrics: `chain_breaks_total`, `signature_failures_total`, `anchor_verification_failures_total`, `rate_limit_hits_total`, `idempotency_duplicates_total`, `lock_contention_seconds` (histogram summary), `records_written_total`, `records_read_total`
  - `get_metrics()` function returning dict of all current values
  - Thread-safe via `threading.Lock` (or asyncio.Lock)
- **File:** `src/mcp_witness/storage.py` — increment counters in `verify_chain()` (chain_breaks), `check_rate_limit()` (rate_limit_hits), `check_and_record_nonce()` (duplicates)
- **File:** `src/mcp_witness/anchoring.py` — increment `anchor_verification_failures_total` in `verify()` when False
- **File:** `src/mcp_witness/server.py` — add `witness_metrics` tool exposing metrics via `get_metrics()`. Register in `AuthRole.AUDITOR` read tools.
- **Tests:** `test_server.py` — `test_metrics_endpoint_returns_counters()`

##### T3.2 — Incident Response Runbook (runbook.md)
- **File:** NEW `docs/runbook.md`
- **What:** Write step-by-step guides for:
  1. **Chain break detected:** How to isolate affected range, verify surrounding data, decide on recovery vs. investigation, notify stakeholders
  2. **Signature verification failures:** How to identify affected key_id, check if key is revoked, determine if records are compromised or just key expired
  3. **Anchor provider unreachable:** How to check network, switch providers, verify existing anchors are still valid
  4. **DB corruption:** SQLite `.recover` command, Postgres pg_dump/restore, how to verify chain integrity after recovery
  5. **Rate limit flooding:** How to identify source actor_id, increase limits, block via auth

##### T3.3 — Graceful Shutdown with In-Flight Tracking (server.py, storage.py)
- **File:** `src/mcp_witness/storage.py` — add `_active_transactions: int = 0` counter, increment/decrement in `_do_insert()` around the transaction. Add `has_inflight_writes() -> bool`.
- **File:** `src/mcp_witness/server.py` — add signal handler for SIGTERM/SIGINT. On signal: stop accepting new requests, wait for in-flight writes (with timeout), then close storage. Add `shutdown_timeout` config (default 30s).
- **Tests:** `test_server.py` — `test_graceful_shutdown_waits_for_inflight()`

##### T3.4 — SBOM Generation (pyproject.toml, .github/workflows/ci.yml)
- **File:** `pyproject.toml` — add `[project.scripts]` entry: `mcp-witness-sbom = "mcp_witness.cli:sbom"` (or use `pip freeze` approach in CI)
- **File:** `.github/workflows/ci.yml` — add `sbom` job that runs `cyclonedx-py` or `pip-audit --sbom` to generate CycloneDX JSON, upload as build artifact
- **Tests:** CI verification that SBOM is valid JSON with all dependencies listed

##### T3.5 — Backup/Restore Documentation (docs/backup.md)
- **File:** NEW `docs/backup.md`
- **What:** Write documentation covering:
  - SQLite: `sqlite3 .backup` with WAL checkpoint, safe to copy while server running, verify backup hash
  - Postgres: `pg_dump` with consistent snapshot, restore procedure, verify chain after restore
  - Anchor receipt backup (separate from DB, receipts are critical for offline verification)
  - Recovery validation: run `witness_verify` after restore

##### T3.6 — Migration CLI Tooling (cli.py)
- **File:** `src/mcp_witness/cli.py` — add `migrate` subcommand that:
  - Reads current schema version from DB
  - Applies pending migrations
  - Supports `--dry-run` flag
  - Reports before/after version

##### T3.7 — Additional Alerting Channels (webhook.py)
- **File:** `src/mcp_witness/webhook.py` — add `SlackNotifier` class that formats alerts as Slack message blocks. Add `MCP_WITNESS_SLACK_WEBHOOK_URL` env var. Add `notify_chain_failure_slack()` function.
- **Tests:** `test_webhook.py` (new) — mock HTTP responses for Slack

#### Quality Gates for Group 3:
- [ ] All existing tests pass
- [ ] Metrics tests pass (counter increments, concurrent access)
- [ ] Graceful shutdown doesn't lose in-flight records
- [ ] SBOM generated and valid
- [ ] runbook.md and backup.md reviewed for completeness
- [ ] ruff clean

---

## SUMMARY OF P0 ITEMS (MUST FIX BEFORE v1.0)

| # | Item | Group | File |
|---|------|-------|------|
| P0.1 | Remove TSA fake fallback | Group 1 | anchoring.py |
| P0.2 | Add strict anchoring mode | Group 1 | anchoring.py, security.py |
| P0.3 | PostgreSQL backend parity | Group 1 | storage_pg.py |
| P0.4 | Envelope encryption at rest | Group 1 | security.py, storage.py, storage_pg.py |
| P0.5 | Sensitive data scrubbing in logs | Group 1 | logging.py |
| P0.6 | SAST + type check CI gates | Group 1 | ci.yml, pyproject.toml |
| P0.7 | Fix unsupported claims in README | Group 1 | README.md |
| P0.8 | Hard pagination ceiling | Group 1 | server.py |
| P0.9 | Algorithm versioning for signatures | Group 2 | crypto_agility.py, hasher.py |
| P0.10 | Canonicalized signing payload | Group 2 | hasher.py |
| P0.11 | Strict Merkle proof validation | Group 2 | merkle.py |
| P0.12 | Key lifecycle management | Group 2 | key_lifecycle.py |
| P0.13 | Structured metrics | Group 3 | metrics.py |
| P0.14 | JWT assertion support or mTLS justification | Group 1 | auth.py |

---

## EXECUTION ORDER

```
GROUP 1 (Trust Foundation) ──► GROUP 2 (Crypto Hardening) ──► GROUP 3 (Operational Excellence)
        4-6 hours                      2-3 hours                      2-3 hours
```

**Sequential** because:
- Group 2 crypto changes depend on the new `crypto_agility.py` patterns from Group 1's algorithm versioning
- Group 3 metrics and webhook additions reference Group 1's strict mode and Group 2's signature counters
- Backend parity (Group 1) must be done before encryption (Group 1) to avoid implementing encryption twice

**Parallelism within groups:** Each group's tasks are largely independent and can be parallelized across sub-agents.
