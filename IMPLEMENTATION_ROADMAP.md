# Implementation Roadmap — mcp-witness v1.0.0

**Date:** 2026-05-13  
**Base:** v0.6.0 → **Target:** v1.0.0  
**Author:** Planner (Chaos vs Order analysis)  
**Status:** Codebase is ~95% complete. Only 1 of 14 P0 items remains unaddressed.

---

## ⚠️ Critical Discovery

The GAP_ANALYSIS.md (2026-05-12) was written against an **earlier state** of the codebase. Since then, **13 of 14 P0 items have already been implemented**, along with most P1 and several P2 items. The gap analysis remains valuable as a conceptual framework but **overstates remaining work by ~80%**.

### Already Implemented (✅)

| # | P0 Item | Status | Files |
|---|---------|--------|-------|
| P0.1 | Remove TSA fake fallback | ✅ DONE | `anchoring.py:L310-370` — TSA raises exceptions (fail-closed), `anchor_or_none()` separate |
| P0.2 | Strict anchoring mode | ✅ DONE | `anchoring.py:L791-877` — `AnchorFailureError`, `is_anchor_strict_mode()`, strict check |
| P0.3 | PostgreSQL backend parity | ✅ DONE | `storage_pg.py:L937` — `search()`, `redact_record()` (L1335), `org_id` column |
| P0.4 | Envelope encryption at rest | ✅ DONE | `security.py:L51-114` — `encrypt_field()`, `decrypt_field()`, `should_encrypt_field()` |
| P0.5 | Sensitive data scrubbing in logs | ✅ DONE | `logging.py:L50-117` — `SensitiveDataFilter` registered on handler |
| P0.6 | SAST + type check CI gates | ✅ DONE | `ci.yml` — `sast` (bandit) + `typecheck` (mypy) + `sbom` jobs all present |
| P0.7 | Fix unsupported README claims | ✅ DONE | `README.md:L19-30` — Uses "⚠️" indicators, describes strict mode + degraded mode |
| P0.8 | Hard pagination ceiling | ✅ DONE | `server.py:L46-47` — `MAX_QUERY_LIMIT=10000`, `MAX_OFFSET=100000`, clamp in all handlers |
| P0.9 | Algorithm versioning for signatures | ✅ DONE | `crypto_agility.py` — Full implementation with `versioned_sign()`, `versioned_verify()` |
| P0.10 | Canonicalized signing payload | ✅ DONE | `hasher.py:L277-363` — `canonicalize_record_fields()`, `sign_canonical_payload()` |
| P0.11 | Strict Merkle proof validation | ✅ DONE | `merkle.py:L202-265` — `verify_merkle_proof_strict()` with depth, index, tree_size checks |
| P0.12 | Key lifecycle management | ✅ DONE | `key_lifecycle.py` — `KeyTrustStore` with rotation, revocation, trust store JSON |
| P0.13 | Structured metrics | ✅ DONE | `metrics.py` — `Counter`/`Histogram`, `witness_metrics` MCP tool |
| **P0.14** | JWT assertion support / mTLS justification | ❌ **TRULY MISSING** | `auth.py` — No JWT support, no mTLS justification documentation |

### Additional Items Already Done (beyond P0 scope)
- ✅ **Graceful shutdown** (`server.py:L1182-1212`, `storage.py:L136-174`)
- ✅ **Slack webhook notifier** (`webhook.py:L101-168`)
- ✅ **Migration CLI** (`cli.py:L454 — `cmd_migrate`)
- ✅ **Incident response runbook** (`docs/runbook.md`, 413 lines)
- ✅ **Backup/restore documentation** (`docs/backup.md`, 373 lines)
- ✅ **SBOM generation in CI** (cyclonedx-py in CI pipeline)

---

## PHASE 1 — Trust Foundation (Estimated: 0.5-1 day)

**Goal:** Ship the missing P0 item + final polish on existing work. This is the only phase with remaining code changes.

### T1.0 — JWT Assertion Support + mTLS Justification (P0.14)

**Priority:** MUST SHIP. This is the **only remaining P0 gap**.

**Files:** `src/mcp_witness/auth.py` (+ docs/justification.md)

**What to build:**

#### Option A (Recommended — JWT Support):
Add an Ed25519-signed JWT alternative alongside shared tokens.

**File: `src/mcp_witness/auth.py`**
Lines to add/edit:
- Add `_JWT_SECRET_KEY: Optional[Ed25519PrivateKey] = None` module-level variable (L16)
- Add `_JWT_PUBLIC_KEY: Optional[Ed25519PublicKey] = None` 
- Add `load_jwt_keys()` function (~L70, alongside `load_api_keys()`) — reads `MCP_WITNESS_JWT_PRIVATE_KEY` and `MCP_WITNESS_JWT_PUBLIC_KEY` env vars (Ed25519 PEM-encoded)
- Add `create_jwt_token(actor_id: str, role: AuthRole, ttl_seconds: int = 3600)` — returns signed JWT string
- Add `verify_jwt_token(token: str) -> tuple[str, AuthRole]` — returns (actor_id, role) or raises
- Modify `authenticate()` (L108) — if `MCP_WITNESS_JWT_PRIVATE_KEY` is set, check for JWT in `MCP_WITNESS_JWT_TOKEN` env var (for testing) or accept both shared keys and JWT
- Add docstring explaining why mTLS is impractical on stdio transport (no TLS layer available)

**Test file: `tests/test_auth.py`** (new file or add to `tests/test_security.py`)
- `test_jwt_create_and_verify_roundtrip()`
- `test_jwt_tampered_token_rejected()`
- `test_jwt_expired_token_rejected()`
- `test_jwt_wrong_issuer_rejected()`

#### Fallback (Minimum viable — documentation only):
If JWT is deemed scope creep, at minimum add a `docs/auth_model.md` that:
- Justifies shared-token model (MCP uses stdio → no TLS → mTLS not feasible)
- Documents that tokens should be treated as secrets (env var, not file)
- Recommends external TLS proxy (nginx/caddy) for network deployments
- States minimum key length of 32 chars (align with existing practice)

**Time estimate:** 2-3 hours (JWT option) | 30 minutes (documentation-only)

### T1.1 — `sign_record_hash()` Deprecation Warning

**File:** `src/mcp_witness/hasher.py`, line ~223

Change the legacy `sign_record_hash()` function to emit a deprecation warning pointing callers to `sign_canonical_payload()`.

```python
def sign_record_hash(record_hash: str, signing_key) -> str:
    import warnings
    warnings.warn(
        "sign_record_hash() is deprecated. Use sign_canonical_payload() "
        "via canonicalize_record_fields() + versioned_sign() for algorithm-aware signing.",
        DeprecationWarning,
        stacklevel=2,
    )
    # ... existing body ...
```

**Time estimate:** 5 minutes

### T1.2 — Version Bump + Changelog

**File:** `src/mcp_witness/__init__.py`, line 3
Change `__version__ = "0.6.0"` → `__version__ = "1.0.0"`

**File:** `CHANGELOG.md`
Add `[1.0.0]` section capturing:
- Crypto hardening (crypto_agility, key_lifecycle, canonical signing)
- Trust foundation (TSA strict mode, envelope encryption, log scrubbing)
- Operational readiness (metrics, graceful shutdown, CI gates, SBOM, runbooks)
- Breaking changes: algorithm-versioned signatures require v1.0+ verifier, canonical payload signing format

**Time estimate:** 20 minutes

### T1.3 — Documentation Audit

**Files:** `README.md`, `docs/runbook.md`, `docs/backup.md`, `SECURITY.md`
- Verify README claims match implementation (they look correct, do a final sweep)
- Add `docs/auth_model.md` if going documentation-only path
- Verify runbook references exist for all implemented features

**Time estimate:** 30 minutes

### T1.4 — Final Test Coverage Sweep

Run full test suite, check coverage. Add tests for:
- `test_auth.py` — JWT tests (if implemented)
- `test_anchoring.py` — TSA strict mode, local_anchor_type distinct, anchor_or_none
- Verify existing test count passes (31 merkle, 48 hasher, 47 security, 54 anchoring, 30 server, 11 key_lifecycle)

**Time estimate:** 1 hour

---

## PHASE 2 — Crypto Hardening Audit (Estimated: 0.5 day)

**Goal:** Verify that all crypto hardening is complete and correct. No new code — pure verification.

### T2.1 — Audit: Algorithm Versioning Integration

Check that `storage.py:record()` (L512-531) actually uses `versioned_sign()` from `crypto_agility.py`. Verify:
- Store contains `algo`, `signature`, `key_id` fields
- `versioned_verify()` handles both versioned and legacy signatures
- `detect_signature_format()` works for both formats

**Files:** `crypto_agility.py`, `hasher.py`, `storage.py`
**Time estimate:** 30 minutes

### T2.2 — Audit: Key Lifecycle Integration

Check `security.py:get_signing_key()` (L112-165) returns `key_id` alongside key. Verify:
- `storage.py:record()` stores `signer_key_id` in DB
- `storage.py:verify_chain()` uses `key_id` to look up public key
- Trust store JSON file is documented format
- Test `verify_key_chain()` with 3-key rotation

**Files:** `key_lifecycle.py`, `security.py`, `storage.py`
**Time estimate:** 30 minutes

### T2.3 — Audit: Merkle Proof Validation

Run strict Merkle proof validation tests. Verify:
- `verify_merkle_proof_strict()` rejects empty proofs for >1 leaf
- Rejects negative leaf_index
- Validates proof depth matches `ceil(log2(tree_size))`
- `get_merkle_proof()` includes `tree_size` in returned dict

**File:** `merkle.py`
**Time estimate:** 15 minutes

---

## PHASE 3 — Operational Excellence (Estimated: 0.5 day)

**Goal:** Ensure all operational features are wired up correctly.

### T3.1 — Verify Metrics Wired Through

Check each metric counter is incremented in the right places:
- `chain_breaks` → `storage.py:verify_chain()` (L1227)
- `signature_failures` → `storage.py:verify_chain()` (L1143-1211)
- `anchor_verification_failures` → `anchoring.py:verify()`
- `rate_limit_hits` → `storage.py:check_rate_limit()`
- `idempotency_duplicates` → `storage.py:check_and_record_nonce()`
- `witness_metrics` tool registered in server.py (L442-497)

**Time estimate:** 15 minutes

### T3.2 — Verify CI Pipeline End-to-End

- `lint` (ruff + black) ✅
- `test` (pytest + coverage, 3 Python versions) ✅
- `test-postgres` (12 tests) ✅
- `sast` (bandit) ✅
- `typecheck` (mypy) ✅
- `security` (pip-audit) ✅
- `sbom` (cyclonedx-py) ✅
- `build` (package build + smoke test) ✅

**Note:** The CI file has a hardcoded `MCP_WITNESS_BACKEND: postgresql` env var with password `witness_test` in cleartext. Ensure this is only in the CI yaml (not production config). Add a note to rotate this as a best practice.

**Time estimate:** 15 minutes

### T3.3 — Verify Graceful Shutdown

- Signal handlers registered for SIGTERM/SIGINT (server.py:L1209-1212)
- `_active_transactions` counter incremented/decremented in `_do_insert()` (storage.py:L596-609)
- `has_inflight_writes()` returns correct value
- `SHUTDOWN_TIMEOUT` configured (server.py:L57, default 30s)

**Time estimate:** 10 minutes

---

## RESOURCE ALLOCATION (2 Developers × 1 Week)

### Developer A: Backend + Security (4 days)

| Day | Tasks |
|-----|-------|
| **Day 1** | **T1.0 — JWT support** in `auth.py`. Add JWT token creation/verification, modify `authenticate()`, write `test_auth.py`. |
| **Day 2** | **T1.0 continued** — integration testing with JWT tokens in MCP tool dispatch. Add `docs/auth_model.md` with mTLS justification. |
| **Day 3** | **T1.1 + T1.2** — Deprecation warning in `hasher.py`, version bump to 1.0.0, CHANGELOG update. **Phase 2 audit** — verify crypto integration end-to-end. |
| **Day 4** | **T1.3 + T1.4** — Documentation audit, SECURITY.md update, final test sweep, edge-case coverage. |

### Developer B: Infrastructure + Verification (4 days)

| Day | Tasks |
|-----|-------|
| **Day 1** | **Phase 3 audit** — metrics wiring, CI pipeline E2E, graceful shutdown verification. Fix any CI config issues. |
| **Day 2** | **Integration testing** — write integration tests for JWT auth + existing anchor/storage flows. Run full test matrix. |
| **Day 3** | **Fuzz testing** — fuzz `verify_merkle_proof_strict()`, `versioned_verify()`, `decrypt_field()`, `validate_export_path()`. |
| **Day 4** | **Chaos testing** — kill process mid-write, verify WAL recovery. Test TSA timeout scenarios. Test key rotation with history. |

### Combined (Day 5)

| Both | **Release prep** — tag v1.0.0, build package, run full CI matrix, sign off on release. |
|------|----------|

---

## RISK ASSESSMENT

### Implementation Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| JWT implementation breaks existing shared-token auth | Low | High | Keep `authenticate()` fallthrough — JWT or shared token, never break existing path |
| Canonical signing format breaks backward compat with v0.6.0 records | Medium | High | `versioned_verify()` detects legacy hex sigs + `detect_signature_format()` handles both; verify this path with test fixture |
| Dependency mismatch (cryptography library version) | Low | Medium | Pin `cryptography>=42.0.0` in pyproject.toml, verify in CI lock file |
| Postgres integration tests fail on different PG versions | Low | Medium | CI uses Postgres 16; document PG 14+ requirement |
| Key trust store file path doesn't exist in production | Medium | Low | `KeyTrustStore.__init__()` handles missing file gracefully (no-op mode + warning) |

### Rollback Plan Per Phase

| Phase | Rollback Action | Signal to Roll Back |
|-------|----------------|---------------------|
| **Phase 1** (JWT + docs) | Revert `auth.py` changes. Pin version at 0.6.0. No migration needed — JWT is additive. | JWT auth breaks existing clients |
| **Phase 2** (crypto audit) | No code changes — this is verification only. Rollback not applicable. | N/A |
| **Phase 3** (ops audit) | Revert `__init__.py` version change. Keep CI improvements. | CI pipeline fails unexpectedly |

**Safe rollback commit strategy:**
```
commit A — Current state (0.6.0 with all hardening)
commit B — T1.0 JWT support (additive, safe to revert)
commit C — Version bump to 1.0.0
```
Each commit is independently revertible. `git revert B` drops JWT without losing version bump.

---

## TESTING STRATEGY

### Minimum Tests Before v1.0.0 Ship

#### MUST PASS (Existing)
- All existing 251+ tests pass across Python 3.10, 3.11, 3.12
- PostgreSQL integration tests (12 tests) pass

#### MUST ADD (Before Ship)

| Test | Why It Matters | File |
|------|---------------|------|
| JWT create/verify roundtrip | Core identity feature | `tests/test_auth.py` |
| JWT tampered token rejection | Security invariant | `tests/test_auth.py` |
| JWT expired token rejection | Security invariant | `tests/test_auth.py` |
| TSA fail-closed behavior | Silent degradation prevention | `tests/test_anchoring.py` |
| TSA anchor_or_none returns None on failure | Graceful path works | `tests/test_anchoring.py` |
| Encryption roundtrip (encrypt→decrypt) | Data at rest protection | `tests/test_security.py` |
| Tampered ciphertext rejection | Integrity check | `tests/test_security.py` |
| Sensitive data log filter (API key redacted) | Log leak prevention | `tests/test_security.py` |
| Log filter preserves normal text | No false positives | `tests/test_security.py` |
| Graceful shutdown waits for inflight writes | Data loss prevention | `tests/test_server.py` |
| Metrics counter increments correctly | Operational visibility | `tests/test_server.py` |

#### Desirable (Not blocking, add post-v1.0)

| Test | Type | File |
|------|------|------|
| Fuzz `verify_merkle_proof_strict()` with random proof paths | Fuzz | `tests/test_merkle.py` |
| Fuzz `decrypt_field()` with random ciphertexts | Fuzz | `tests/test_security.py` |
| Fuzz `validate_export_path()` with path traversal attempts | Fuzz | `tests/test_security.py` |
| Chaos: kill server mid-write, verify WAL recovery | Chaos | `tests/test_storage.py` |
| Chaos: concurrent writes from 10 connections | Chaos | `tests/test_storage.py` |
| Key rotation across 5 keys with chain verification | Integration | `tests/test_key_lifecycle.py` |

### Test Execution Matrix

```
pytest tests/                       # Core suite
pytest tests/ -k "pg"              # PostgreSQL (requires PG running)
pytest tests/ --hypothesis-show-statistics  # Property-based tests
```

---

## RELEASE PLAN — v1.0.0

### Versioning

`0.6.0` → `1.0.0`

**Rationale:** Breaking change in internal signature format (algorithm-versioned signatures). Semantic version rules apply: major bump for breaking API changes.

### Changelog Template

```markdown
## [1.0.0] — 2026-05-13

### Security Hardening
- **P0.14: JWT assertion support** — Ed25519-signed JWT authentication alongside shared tokens
- **P0: Crypto agility** — Algorithm-versioned signatures (ed25519+sha256:v1), graceful backward compat
- **P0: Canonicalized signing payload** — Deterministic canonical byte string includes all record fields
- **P0: Envelope encryption at rest** — AES-256-GCM encryption for sensitive fields (PII, PHI)
- **P0: Sensitive data scrubbing in logs** — Regex-based redaction of API keys and secrets
- **P0: SAST + type checking CI gates** — Bandit SAST, mypy type checking in CI pipeline
- **P0: Hard pagination ceiling** — MAX_QUERY_LIMIT=10000 enforced for all query/export/search tools

### Trust Foundation
- **P0: TSA strict mode** — AnchorFailureError when TSA unreachable (fail-closed); anchor_or_none() for graceful opt-in
- **P0: Local attestation distinct type** — AnchorType.LOCAL separate from TSA for degraded mode receipts
- **P0: PostgreSQL backend parity** — search(), redact_record(), org_id column in Postgres
- **P0: README claims corrected** — Accuracy marks for assurance levels, TSA behaviour documented

### Crypto Hardening
- **Algorithm versioning** — crypto_agility.py with SigningAlgorithm/HashChainAlgorithm enums
- **Key lifecycle management** — KeyTrustStore with rotation, revocation window, trust store JSON
- **Strict Merkle proof validation** — verify_merkle_proof_strict() with depth/index/tree_size checks

### Operational Excellence
- **Structured metrics** — 7 counters + 1 histogram, witness_metrics MCP tool
- **Graceful shutdown** — Signal handlers (SIGTERM/SIGINT), in-flight write tracking, 30s timeout
- **Incident response runbook** — docs/runbook.md (413 lines, 6 scenarios)
- **Backup/restore documentation** — docs/backup.md (373 lines, SQLite/Postgres/Anchor receipts)
- **Slack webhook notifier** — SlackNotifier class with formatted message blocks
- **SBOM in CI** — CycloneDX SBOM generation as build artifact
- **Migration CLI** — mcp-witness migrate --dry-run support

### Breaking Changes
- **Signature format changed to versioned** — v0.6.0 records with legacy hex-only signatures remain verifiable
  (backward compat in versioned_verify()). New records use versioned JSON signature format.
- **TSA anchoring now fail-closed by default** — use MCP_WITNESS_ANCHOR_STRICT_MODE=false for legacy behaviour

### Deprecations
- `sign_record_hash()` → use `sign_canonical_payload()` + `canonicalize_record_fields()`
- `verify_record_signature()` → use `versioned_verify()` from crypto_agility module
```

### Migration Guide for Existing Users

**For v0.6.0 → v1.0.0 users:**

1. **No DB migration needed** (backward compatible) — v0.6.0 records remain readable and verifiable
2. **New records** will use algorithm-versioned signatures (JSON format) — ensure any external verifiers are updated to `versioned_verify()` which handles both formats
3. **TSA anchoring** will now fail by default if TSA is unreachable. Set `MCP_WITNESS_ANCHOR_STRICT_MODE=false` if you want the old graceful-degradation behaviour
4. **New env vars:**
   - `MCP_WITNESS_DEK` — 32-byte hex key for field-level encryption (auto-generated if absent)
   - `MCP_WITNESS_TRUST_STORE` — path to key trust store JSON (optional, no-op if absent)
   - `MCP_WITNESS_JWT_PRIVATE_KEY` / `MCP_WITNESS_JWT_PUBLIC_KEY` — Ed25519 PEM keys for JWT auth
   - `MCP_WITNESS_SLACK_WEBHOOK_URL` — Slack webhook for chain failure alerts
5. **Upgrade steps:**
   ```bash
   pip install --upgrade mcp-witness
   mcp-witness migrate --dry-run   # Check for pending migrations
   mcp-witness migrate             # Apply any pending migrations
   mcp-witness serve               # Start v1.0.0
   ```

### Release Checklist

- [ ] All P0 items implemented and verified
- [ ] Test suite passes across all Python versions (3.10, 3.11, 3.12)
- [ ] PostgreSQL integration tests pass
- [ ] Bandit SAST scan: no HIGH severity findings
- [ ] mypy type check: no errors
- [ ] SBOM generated and valid
- [ ] CHANGELOG.md updated
- [ ] `__version__` bumped to 1.0.0
- [ ] README.md reviewed for accuracy
- [ ] Migration guide written
- [ ] Git tag `v1.0.0` created and signed
- [ ] Package built and verified (`python -m build` + `pip install dist/*.whl` + `mcp-witness --version`)

---

## SUMMARY

| Metric | Value |
|--------|-------|
| P0 items total | 14 |
| P0 already done | 13 (93%) |
| P0 remaining | 1 (JWT auth — T1.0) |
| Total estimated effort | 2.5-3.5 days (2 devs, not 1 week) |
| Actual remaining code changes | ~100-150 lines in `auth.py` + test file |
| Risk level | Low — all changes are additive, no rewrites needed |
| Can ship v1.0.0 | **YES** — after T1.0 is complete |

**Bottom line:** This codebase is production-ready. The gap analysis identified high-quality targets, and the implementation team delivered. The only remaining item is JWT authentication support (or formal documentation of the shared-token model with mTLS justification). Ship it.
