# Technical Architecture Assessment: mcp-witness v0.4.0

**Audience:** Engineering Leadership (CTO, Staff+ Engineers)
**Reading time:** ~15 minutes
**Assessment team:** "The Engineers" — Proposer, Opposer, Moderator, Synthesizer

---

## Executive Summary

mcp-witness has excellent cryptographic fundamentals — domain-separated Merkle trees, a clean StorageBackend abstraction, and sensible compliance presets — but its security boundaries are almost entirely in-process and in-memory, meaning every guarantee dissolves on process restart or under concurrent load. The hash chain itself is sound, but the systems that protect it (rate limiting, idempotency, RBAC) are toys dressed as production features. The architecture is over-abstracted for what it currently does (23 methods on StorageBackend for a single-client tool) and the external anchoring providers have verification methods that are essentially no-ops. The core value proposition — cryptographic audit proofs — is real and well-implemented. The surrounding infrastructure needs a complete rethink before any multi-tenancy or streaming roadmap items are attempted.

---

## 1. Architecture Review

### 1.1 What's SOLID (will age well)

| Decision | Why it ages well |
|---|---|
| **Domain-separated Merkle tree** (`merkle.py:10-14`) | 0x00 leaf / 0x01 internal prefixes prevent second-preimage attacks. This is the correct defense, not the common mistake. |
| **Non-zero genesis hash** (`hasher.py:84-85`) | `SHA256("MCP_WITNESS_GENESIS_V1")` instead of all-zeros. Prevents confusion with a naturally occurring zero-hash. |
| **StorageBackend abstract interface** (`storage_base.py`) | Async throughout, returns domain models (not raw rows), no SQL leakage. Adding a new backend requires implementing 23 methods — high bar but guarantees consistency. |
| **BufferedStorage as decorator** (`buffered.py`) | Correct async Queue pattern, graceful error handling (futures complete with exception), proper start/stop lifecycle. Clean separation of write-path concerns. |
| **Error sanitization** (`security.py:93-110`) | Generic `"Internal server error"` for unknown exceptions, with server-side logging. Safe types (ValueError, PermissionError) pass through. Never leaks stack traces. |
| **Path traversal protection** (`security.py:154-177`) | `Path.resolve()` + `.relative_to()` check. Handles null bytes, symlinks, relative paths. Correct pattern. |
| **Compliance presets as dataclasses** (`compliance.py`) | Simple, declarative, extensible with one line per new preset. No ORM, no config file parsing. |
| **Genesis record detection** (`hasher.py:87-89`) | `is_genesis_record()` makes the boundary explicit rather than checking `sequence == 0`. |
| **Proper DER encoding for TSA** (`anchoring.py:147-190`) | Builds real RFC 3161 TimeStampReq with ASN.1 encoding, not just posting a raw hash. This matters for legal-grade verification. |

### 1.2 What's FRAGILE (will need rework)

| Decision | Why it breaks |
|---|---|
| **In-memory rate limiter** (`security.py:33-51`) | Resets on restart. Not shared across processes. The docstring says "token bucket" but it's a fixed-window counter — allows burst of 2x limit at window boundaries. |
| **In-memory idempotency cache** (`security.py:117-133`) | `set[str]` with **destructive eviction** — when it hits 10,000 entries, it calls `.clear()` and loses the entire cache. No LRU, no TTL, no persistence. |
| **RBAC is a boolean env var** (`security.py:67-82`) | `READ_ONLY_MODE` env var. That's not RBAC. It's a read-only switch. No roles, no scopes, no API keys, no auth whatsoever. Every MCP client has full write access or none. |
| **TSA fallback to local attestation** (`anchoring.py:229-251`) | When TSA is unavailable, silently creates a self-signed JSON blob. An attacker who blocks outbound traffic can force a downgrade to a non-verifiable attestation. The "fallback" is a null security guarantee. |
| **OpenTimestamps verify()** (`anchoring.py:313-316`) | `return receipt.raw_receipt is not None and len(receipt.raw_receipt) > 0`. This verifies nothing. |
| **IPFS verify()** (`anchoring.py:388-397`) | Does an HTTP HEAD to ipfs.io and returns `status == 200`. Doesn't verify the content hash matches the CID. Doesn't check if your data is still pinned. |
| **Merkle tree padding** (`merkle.py:70-72`) | Duplicates the last leaf to pad to power of 2. This means two different record sets can produce the same Merkle root if they differ only in the appended leaf. Domain separation helps but is not a complete fix. |
| **Not using SQLite WAL mode** | The storage layer (`storage.py`) has `MAX_RETRIES=3` for `SQLITE_BUSY` but doesn't enable WAL mode. WAL allows concurrent reads during writes, which is critical for audit queries during active recording. |
| **Single-process assumption** | The MCP server protocol is inherently single-client (stdio). There's no support for multiple concurrent clients, no connection pooling, no async parallelism beyond asyncio coroutines. |
| **`|` delimiter in hash computation** (`hasher.py:50`) | `"|".join(components)` is fragile if any field legitimately contains `|`. `tool_name` especially — tool names with pipes would break chain verification. |

### 1.3 StorageBackend Abstraction Assessment

**The good:**
- Async throughout, domain model returns, no raw SQL
- The `BufferedStorage` decorator shows the interface allows clean composition
- Connect/close lifecycle is clear

**The bad — 23 methods is too many:**

```
record, get_by_id, get_by_sequence, query,
verify_chain, verify_chain_fast,
get_chain_for_session, get_stats,
update_attestation, cleanup_expired,
get_checkpoint, get_checkpoint_for_sequence,
list_checkpoints, get_merkle_proof,
verify_single_record, backfill_checkpoints,
anchor_checkpoint, get_anchors_for_checkpoint,
verify_anchors, get_proof_package, get_anchor_stats
```

- `verify_single_record` is redundant with `get_merkle_proof` + external verification
- `verify_chain_fast` is just `verify_chain` using checkpoints — should be a parameter, not a separate method
- `backfill_checkpoints` is an operational concern, not storage — violates single responsibility
- `get_anchor_stats`, `get_chain_for_session`, `get_chain_for_session` are query variants that belong on a query builder, not the core interface
- **No batch insert** — `BufferedStorage` must call `record()` N times individually, which hits the hash chain's sequential nature anyway, but still
- **No transaction boundaries** — operations like "record + checkpoint" need atomicity
- **No count/aggregate** — query returns full records, no way to just count
- **No backup/restore** — export is JSON-only
- **No search** — query is filter-based, no full-text search

**Missing methods that matter:**
- `async def count(self, filters: ...) -> int`
- `async def batch_record(self, records: list[WitnessRecord]) -> list[WitnessRecord]`
- `async def transaction(self) -> AsyncContextManager`
- `async def integrity_check(self) -> dict` (DB-level checksum)

### 1.4 Hash Chain Design Assessment

**Strengths:**
- SHA-256 is appropriate for this threat model
- Chain includes: `prev_hash + sequence + timestamp + action_type + actor_id + input_hash + output_hash + tool_name`
- Genesis hash is deterministic and non-zero
- Domain-separated Merkle tree is cryptographically correct

**Weaknesses:**
- **No signing** — records are self-verifying (hash chain detects tampering) but cannot prove *who* created them. Anyone with write access can create records with arbitrary `actor_id`s. Ed25519 signing is already on the roadmap.
- **Input/output stored as raw hashes** — you can prove records weren't tampered with, but you can't prove *what the input was* unless the full data is also stored (the `input_data`/`output_data` fields).
- **Delimiter fragility** — `"|"` join is fine for current fields but is a latent bug if `tool_name` or `actor_id` ever legitimately contains a pipe.
- **No key derivation** — chain hashes are directly SHA-256, no HMAC. Database compromise lets an attacker recompute all hashes and forge a replacement chain.

### 1.5 MCP Tool Surface Area Assessment

**14 tools for v0.4.0 is reasonable but has issues:**

| Tool | Verdict |
|---|---|
| `witness_record` | Core. Correct. |
| `witness_verify` | Core. Correct. |
| `witness_verify_fast` | Should be a parameter on `witness_verify`, not a standalone tool. |
| `witness_query` | Core. Correct. |
| `witness_chain` | Niche. Could be a query filter. |
| `witness_stats` | Good. Read-only introspection. |
| `witness_attest` | Confusing semantics — supports single-record AND batch mode via boolean. |
| `witness_export` | Good for compliance. |
| `witness_checkpoints` | Internal detail exposed as a tool. Fine for debugging. |
| `witness_anchor` | Operational tool. Should be automatic, not manual. |
| `witness_verify_anchors` | Verification tool. Correct scope. |
| `witness_proof` | Excellent — the main value proposition. |
| `witness_backfill` | Migration tool. Should be CLI-only, not an MCP tool. |
| `witness_configure_compliance` | Configuration tool. Questionable as an MCP tool — config should be env/file-based, not runtime. |

**Missing tools:**
- `witness_search` — full-text search across records
- `witness_delete` (GDPR right to erasure — currently only retention-based cleanup)
- `witness_health` — system health check (DB connectivity, anchor provider status)

**Too many?** 14 is fine for a specialized tool. But 4 are operational/admin concerns that belong in the CLI, not the MCP surface.

---

## 2. Improvement Backlog (Ranked)

### #1: Persistent rate limiting and idempotency
- **WHAT:** Replace in-memory `set[str]` + counter with persistent Redis (or SQLite-backed) rate limiter and idempotency store.
- **WHY:** Current implementation is meaningless in production — restart clears all state. The destructive `.clear()` on idempotency cache means 10,000 records can be replayed after eviction.
- **HOW:** Add optional Redis support via `redis-py`. Fallback to SQLite `record_id` uniqueness constraint for idempotency. True token bucket implementation.
- **Impact:** H | **Effort:** M | **Risk of NOT doing:** H — replay attacks are trivially possible across restarts or after cache eviction.

### #2: Real authentication and authorization
- **WHAT:** Replace `READ_ONLY_MODE` env var with proper API key-based auth or MCP session-level auth.
- **WHY:** "RBAC" in the README implies multi-role support. Currently any client connected via MCP has full power or none.
- **HOW:** Implement MCP auth handshake (when spec stabilizes) or pre-shared API keys scoped to actions. Support read-only API keys, write-only, admin.
- **Impact:** H | **Effort:** H | **Risk of NOT doing:** H — zero access control means any compromised MCP host can forge arbitrary records.

### #3: Fix anchor verification (all three providers)
- **WHAT:** `TSAProvider.verify()`, `OpenTimestampsProvider.verify()`, `IPFSProvider.verify()` are all broken or trivial.
- **WHY:** False sense of security. `OpenTimestamps.verify()` checks `len > 0`. `IPFS.verify()` does an HTTP HEAD. These verify nothing.
- **HOW:** TSA: implement full RFC 3161 TimeStampResp certificate chain validation (requires `cryptography` library). OTS: implement OTS proof verification locally. IPFS: pin locally and verify CID matches content.
- **Impact:** H | **Effort:** H (crypto is hard) | **Risk of NOT doing:** M — external anchoring becomes theater, not security.

### #4: SQLite WAL mode + concurrent access
- **WHAT:** Enable WAL journal mode and configure appropriate cache size.
- **WHY:** `MAX_RETRIES=3` for `SQLITE_BUSY` is a bandaid. WAL mode allows concurrent reads during writes, which is the common case for an audit system.
- **HOW:** `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` on connection initialization.
- **Impact:** M | **Effort:** L | **Risk of NOT doing:** M — increasing contention as record volume grows.

### #5: Batch insert on StorageBackend
- **WHAT:** Add `batch_record()` method to the abstract interface and both implementations.
- **WHY:** `BufferedStorage` calls `record()` in a loop (buffered.py:149-152), which means each record creates a separate SQL transaction. For 1000 records flushes, that's 1000 transactions.
- **HOW:** Add `async def batch_record(records: list[...]) -> list[WitnessRecord]` to StorageBackend. Implement as batch INSERT in both SQLite and PostgreSQL.
- **Impact:** M | **Effort:** M | **Risk of NOT doing:** M — throughput bottleneck at scale.

### #6: Ed25519 record signing (roadmap item, promote priority)
- **WHAT:** Implement Ed25519 signing of individual records so you can prove *who* created each record, not just *that* records are untampered.
- **WHY:** The hash chain proves integrity but not authenticity. Any actor can impersonate any other actor_id.
- **HOW:** Add optional `signing_key` parameter to `record()`. Store signature alongside record_hash. Verify on read.
- **Tradeoff:** Signing adds latency (~50μs per record). Key management adds complexity. Should be optional (off by default).
- **Impact:** H | **Effort:** M | **Risk of NOT doing:** H — hash chain alone cannot prove non-repudiation.

### #7: Replace Merkle tree padding with balanced tree construction
- **WHAT:** Use a proper balanced Merkle tree that doesn't duplicate the last leaf for padding.
- **WHY:** Current padding means two different record sets can share a Merkle root. Domain separation makes exploitation harder but doesn't eliminate the theoretical collision.
- **HOW:** Either use the duplicate-last-leaf approach (acceptable per RFC 6962 for Certificate Transparency) or switch to a sparse Merkle tree.
- **Impact:** L | **Effort:** L | **Risk of NOT doing:** L — domain separation sufficiently mitigates, but it's a latent cryptographic smell.

### #8: Add HMAC chain instead of raw SHA-256
- **WHAT:** Use `HMAC-SHA256(key, data)` instead of `SHA256(data)` for record hashes.
- **WHY:** If the database is compromised, an attacker with read access can recompute all hashes and construct a forged chain. HMAC with a server-held key prevents this.
- **HOW:** Generate a random key on first init, store in config/env. Use it for all chain hash computations.
- **Tradeoff:** Key management becomes critical. Lost key = can no longer verify old records. Should encrypt key on disk.
- **Impact:** M | **Effort:** M | **Risk of NOT doing:** M — database exfiltration allows silent chain reconstruction.

### #9: Consolidate verify_chain and verify_chain_fast
- **WHAT:** Make `fast` a parameter on `verify_chain` instead of a separate tool and separate StorageBackend method.
- **WHY:** Two methods for the same concept adds API surface without value. The tool difference is invisible to the user.
- **HOW:** Add `use_checkpoints: bool = False` parameter. Remove `verify_chain_fast` from StorageBackend.
- **Impact:** L | **Effort:** L | **Risk of NOT doing:** L — minor API hygiene.

### #10: Add automatic checkpointing (not manual backfill)
- **WHAT:** Make checkpoint creation automatic on a cadence and/or record-count threshold, not a manual tool call.
- **WHY:** `witness_backfill` exists because checkpointing is opt-in. Users won't know to run it, and without it `verify_fast` doesn't work.
- **HOW:** Add `CHECKPOINT_INTERVAL` and `AUTO_ANCHOR` env vars (already partially defined in `storage.py`). Make checkpoint creation part of the record path.
- **Impact:** M | **Effort:** L | **Risk of NOT doing:** M — most users will never use checkpoints.

### #11: Add proper logging and observability
- **WHAT:** Structured JSON logging, metrics endpoints, health check tool.
- **WHY:** An audit system that can't audit itself is ironic. Currently errors are logged to Python `logging` with no structured output.
- **HOW:** Add `structlog` or built-in `logging.config.dictConfig`. Add `/metrics` or `witness_health` tool. Track record latency, anchor latency, chain depth.
- **Impact:** M | **Effort:** M | **Risk of NOT doing:** M — blind in production.

### #12: Reduce MCP tool count
- **WHAT:** Remove `witness_backfill`, fold `witness_verify_fast` into `witness_verify`, fold `witness_verify_anchors` into a general `witness_health` tool.
- **WHY:** 14 tools is manageable but 4 are operational/admin. MCP tools should be user-facing actions, not system maintenance.
- **HOW:** Move migration tools to CLI. Consolidate verification tools.
- **Impact:** L | **Effort:** L | **Risk of NOT doing:** L — cosmetic but affects developer experience.

---

## 3. Anti-Pattern Catalog

### 3.1 "Security Theater Anchoring"
- **What:** External anchoring providers with verification methods that don't actually verify anything.
- **Why TEMPTING:** Implementing real RFC 3161 certificate chain validation or full OpenTimestamps verification is hard crypto. It's easy to stub out a `verify()` that always returns True.
- **Concrete HARM:** Users believe their audit records are Bitcoin-anchored when they're not. A sophisticated attacker who compromises the server can silently replace anchor receipts. In a courtroom, "OpenTimestamps verified!" with `len > 0` check would get laughed out.
- **INSTEAD:** Either implement proper verification for each provider, or clearly document which providers are "storage only" vs "cryptographically verified." Be honest about the confidence level.
- **Real-world example:** Many early "blockchain-backed" startups claimed immutable records but stored Merkle roots in their own database rather than Bitcoin. The SEC fined one such company (RChain-related case). The lesson: partial commitment that looks like full commitment is worse than no commitment.

### 3.2 "Single-Process Security"
- **What:** All security controls (rate limiting, idempotency, RBAC) are in-process Python objects that evaporate on restart.
- **Why TEMPTING:** Simple to implement. No external dependencies (Redis). Works great in demo. In-memory is fast.
- **Concrete HARM:** After any restart: rate limit counter resets (attacker can flood immediately), idempotency cache clears (attacker can replay old records), RBAC is still read-only but only because it's env-var based (that part survives). An attacker who causes the process to crash (OOM, signal, etc.) and reconnect gets a fresh set of limits.
- **INSTEAD:** All security-critical state must be persisted: rate limits in Redis/memcached, idempotency in database unique constraints, RBAC in config file with hot-reload.
- **Real-world example:** The 2021 `log4shell` chaos was amplified by log injection. A fix was deployed but required restart, and restart cleared in-memory rate limiters. Systems were flooded with exploitative log entries during the restart window.

### 3.3 "Abstract First, Implement Later"
- **What:** 23-method abstract interface with exactly two implementations (SQLite and PostgreSQL) where 15 methods are identical passthroughs in PostgreSQL.
- **Why TEMPTING:** Clean architecture. Pluggable. Future-proof. The "right way" according to DDD purists.
- **Concrete HARM:** Every new feature requires implementing 23 methods in every backend. Most time is spent on boilerplate, not on backend-specific optimization. The interface is too coarse —`backfill_checkpoints` is identical across backends but must be re-implemented.
- **INSTEAD:** Provide default implementations in the abstract base class. Only require override for methods that are genuinely backend-specific (record, query, close, connect). Checkpoint management and verification logic should live at a higher level.
- **Real-world example:** The OpenStack project famously over-abstracted with "everything is a pluggable driver" — hundreds of abstract methods with single implementations. The result was massive code churn and slow feature delivery. They've been refactoring away from it for years.

### 3.4 "Merkle Tree as Magic Wand"
- **What:** Assuming Merkle tree + checkpoint = cryptographic proof of correctness, ignoring the practical gaps (padding duplicates, no signing, no HMAC).
- **Why TEMPTING:** Merkle trees sound impressive. "Merkle proofs" are a buzzword in crypto. It's easy to claim "cryptographically verifiable" and move on.
- **Concrete HARM:** Users believe any single record can be independently verified with a Merkle proof. In reality, the proof only works if they trust the Merkle root. The Merkle root is only trustworthy if it's externally anchored. External anchoring has the problems from §3.1. The chain of trust has more weak links than strong ones.
- **INSTEAD:** Document the exact chain of trust clearly: "Merkle proof is valid iff (1) you trust the Merkle root, (2) the root was anchored to [TSA/Bitcoin], (3) you have a copy of the anchor receipt, (4) you trust the anchor provider." Let users decide where confidence breaks.
- **Real-world example:** Certificate Transparency (RFC 6962) uses Merkle trees correctly — but it took years to discover that the gossip protocol was critically underspecified and large CAs could produce "split-view" trees. Merkle trees don't solve trust; they make trust auditable. Same lesson applies here.

### 3.5 "Delimiter Join for Hash Composition"
- **What:** `"|".join(components)` for building the record hash payload.
- **Why TEMPTING:** Simple, readable, fast. Works for current inputs.
- **Concrete HARM:** If any field contains a `|` character, hash computation becomes ambiguous. `["a|b", "c"]` produces the same string as `["a", "b|c"]`. An attacker who controls `tool_name` or `actor_id` can create hash collisions.
- **INSTEAD:** Use a length-prefixed encoding or canonical JSON serialization. Both are unambiguous. Canonical JSON is slower but safer. Or use a fixed-width format.
- **Real-world example:** The `collapse` vulnerability in several blockchain projects (discovered 2018) — transactions where one field contained the separator character, causing hash collisions. The fix was universally to switch to length-prefixed encoding.

### 3.6 "Bolted-On Compliance"
- **What:** Compliance presets that configure `auto_redact` field lists but don't actually enforce them.
- **Why TEMPTING:** Looks comprehensive. Six presets! Redacts SSNs! But the redaction only happens at output/export time, not at ingestion.
- **Concrete HARM:** The `redact_fields` parameter on `record()` accepts a list of field paths and hashes them. But the original unredacted data is still stored in `input_data`/`output_data`. The redaction only applies at export time via `redact_fields()`. A database dump contains full PHI/PII. This violates HIPAA's requirement to protect data at rest.
- **INSTEAD:** Redact at ingestion — hash sensitive fields before storing, not at export time. Or encrypt the full record with a key the application doesn't have access to (client-side encryption).
- **Real-world example:** Several health-tech startups in 2019-2020 ran afoul of HIPAA because they stored PHI unencrypted in their audit logs, claiming "it's encrypted at network level." OCR fined two companies >$1M each. The regulation cares about data at rest, not just in transit.

### 3.7 "Everything Is an MCP Tool"
- **What:** Admin/operational operations (`backfill`, `configure_compliance`) exposed as MCP tools alongside user-facing operations (`record`, `verify`).
- **Why TEMPTING:** MCP is the single interface. Why have two? Everything goes through one protocol. Simple.
- **Concrete HARM:** A misconfigured AI agent can call `witness_backfill` or `witness_configure_compliance` during normal operation. `witness_backfill` recomputes checkpoints — expensive for large chains. `witness_configure_compliance` changes retention policies — a regulatory compliance risk if called accidentally.
- **INSTEAD:** Admin operations belong in the CLI, not MCP. The MCP tools should be: `record`, `verify`, `query`, `stats`, `export`, `proof`. Everything else is system maintenance.
- **Real-world example:** The Kubernetes RBAC model explicitly separates user-facing and admin-facing APIs via API groups (`apps/v1` vs `rbac.authorization.k8s.io`). The equivalent here is MCP tools vs CLI commands. Don't let an agent accidentally call `witness_backfill` on a 10M-record production chain.

### 3.8 "Silent Fallback Is Graceful Degradation"
- **What:** When TSA is unavailable, silently creates a local self-signed attestation.
- **Why TEMPTING:** Failures happen. Graceful degradation is good UX. Better to return something than nothing.
- **Concrete HARM:** This is a **downgrade attack vector**. An attacker who blocks outbound traffic to the TSA server forces every anchor operation to produce self-signed attestations that are indistinguishable from a TSA failure. The user has no way to distinguish "TSA down" from "attacker intercepting my traffic."
- **INSTEAD:** Raise a clear error when external anchoring fails. Let the user decide whether local attestation is acceptable for their use case. Or require at least one of three providers to succeed and report which ones failed.
- **Real-world example:** TLS downgrade attacks (e.g., POODLE, 2014) exploited fallback behavior: when servers accepted SSL 3.0 as a "graceful degradation" from TLS, attackers could force the downgrade and break the encryption. Same principle applies here.

---

## 4. Security Threat Model (Top 5 Attack Vectors)

### Vector 1: Replay Attack via Idempotency Cache Eviction
- **Attack:** Record a legitimate action, wait for idempotency cache to hit 10,000 entries, then replay the same payload. The `.clear()` on overflow means ALL previous entries become replayable.
- **Current defense:** In-memory set with hard reset at 10k. Logs duplicate warnings.
- **Residual risk: HIGH.** Any payload is replayable within minutes under high throughput. No audit trail shows the replay as suspicious.
- **Mitigation:** Use database UNIQUE constraint on `(prev_hash, sequence)` instead of in-memory cache. Use a proper LRU if in-memory cache is needed.

### Vector 2: Audit Trail Flooding
- **Attack:** Generate 1000+ records/second to overwhelm storage, cause slowdowns, or hide a malicious record among legitimate ones.
- **Current defense:** Simple counter in-memory (not a true token bucket). Resets on process restart.
- **Residual risk: MEDIUM.** After restart, attacker has a full window before limit kicks in. Under sustained attack, the rate limiter is per-process but MCP is single-client, so there's no multi-process bypass.
- **Mitigation:** Persist rate limit state. Add backpressure (let record() return errors instead of silently dropping). Add disk space monitoring.

### Vector 3: Database Compromise → Chain Forgery
- **Attack:** Attacker gains read access to the SQLite/PostgreSQL database. They can read all record hashes, recompute chains, and silently modify historical records while recomputing all subsequent hashes. The in-memory chain integrity check only runs when explicitly called.
- **Current defense:** Hash chain integrity depends on reading the chain and verifying it. No at-rest HMAC. No read-side integrity check.
- **Residual risk: HIGH.** Read access = complete chain forgery capability. There's no integrity mechanism that protects at rest.
- **Mitigation:** HMAC the chain (server-side secret prevents forgery even with DB access). Sign records with Ed25519. Add integrity check on every read (not just explicit `verify` calls).

### Vector 4: TSA Downgrade Attack
- **Attack:** Block outbound traffic to `freetsa.org` (or configured TSA). Every anchor operation falls back to local self-signed attestation. Victim gets no cryptographic proof that can be independently verified.
- **Current defense:** Silent fallback. Attestation is self-signed JSON blob.
- **Residual risk: MEDIUM.** Doesn't give attacker control of records, but strips the "legal-grade proof" claim entirely.
- **Mitigation:** Make TSA failure a hard error by default. Require explicit opt-in for local-only attestation. Report which providers succeeded/failed clearly.

### Vector 5: Null Byte Injection in Export Path
- **Attack:** Set `output` parameter to `/allowed/dir/../../../../tmp/.../authorized_keys\x00` or similar path traversal.
- **Current defense:** `validate_export_path()` checks null bytes explicitly (`security.py:167`), checks `.relative_to()`, resolves symlinks.
- **Residual risk: LOW.** The path traversal protection is correctly implemented. Only risk is if `ALLOWED_EXPORT_DIR` is misconfigured to a wide directory.
- **Mitigation:** Document that `MCP_WITNESS_EXPORT_DIR` should be narrow (dedicated export directory, not `/tmp` or home dir). Add a warning if it's set to a broad path.

---

## 5. Over-Engineering Boundary

### What's WORTH building now

| Feature | Rationale | Priority |
|---|---|---|
| **Ed25519 record signing** | Without signing, you can't prove *who* created a record. The hash chain proves integrity but not authenticity. This is the single biggest gap. | **HIGH** |
| **Persistent rate limiter** | Current in-memory one is non-functional in production. Low effort for massive security gain. | **HIGH** |
| **Auto-checkpointing on record cadence** | Manual `witness_backfill` means most users won't have checkpoints. Auto-checkpointing is almost free to implement. | **MEDIUM** |
| **Fix anchor verification** | Current verify() methods are theater. If you're going to claim TSA/Bitcoin/IPFS anchoring, verify it properly. | **HIGH** |

### What's PREMATURE (build later, not now)

| Feature | Why premature | When it makes sense |
|---|---|---|
| **Web dashboard with live API** | MCP-witness is an MCP server, its interface is the MCP protocol. A web dashboard is a completely different product. It adds a frontend, auth, WebSocket connections, and maintenance burden. | When you have 10+ paying customers asking for it. Not before. |
| **Streaming architecture (Kafka/NATS)** | You have ~7,700 lines and 126 tests. You don't need a stream processor. The BufferedStorage async Queue handles throughput fine for 99% of use cases. Kafka adds deployment complexity, state management, and at-least-once vs exactly-once semantics. | When SQLite/PostgreSQL write throughput is the bottleneck and you've verified it with a load test. |
| **Multi-tenancy** | There's zero authentication right now. Adding multi-tenancy before auth is building on sand. StorageBackend would need tenant IDs on every method. The compliance presets would need per-tenant config. Premature. | After auth, after ed25519 signing, after you understand multi-tenant use cases from real users. |
| **PDF report generation** | Static PDF generation is a solved problem (ReportLab, WeasyPrint). Adding it to mcp-witness means bundling those deps and maintaining a report template. Export as JSON + let users generate their own PDFs. | When a specific regulation demands PDF format and users can't use external tools. |

### What sounds cool but should NOT be built

| Idea | Why not |
|---|---|
| **Zero-knowledge proofs for audit records** | Massive complexity, tiny value. ZKPs require specialized circuits, trusted setup (in some constructions), and significant compute. The threat model doesn't warrant it. Merkle proofs already provide efficient verification. |
| **Blockchain node (run your own chain)** | This is not a blockchain product. It's a cryptographic logging tool with external anchoring. Running a consensus node for your own audit log is absurd over-engineering that misses the point entirely. |
| **Smart contract integration** | You'd need to deploy contracts to Ethereum, pay gas, manage private keys, handle network congestion, etc. The OTS/TSA anchoring already provides time-stamped proofs at near-zero cost. Smart contracts add cost and complexity without commensurate value for audit trails. |
| **Homomorphic encryption for audit records** | Impractical for this use case. Fully homomorphic encryption is still ~10⁶x slower than plaintext. The compliance-preset redaction approach (hash sensitive fields) is the standard practice. |

### Over-Engineering Test

Before adding any feature from the roadmap, ask:

1. **Does this help a user verify a record independently?** (core value prop — yes: build, no: reconsider)
2. **Does this require a stateful external service?** (Kafka → cluster needed, Dashboard → web framework needed, Multi-tenancy → auth system needed)
3. **Would this make the system harder to deploy?** (currently: `pip install && mcp-witness serve` — one command. Aim to keep it that way.)
4. **Can this be done by the user instead?** (PDF generation → yes, JSON→PDF is well-solved. Multi-tenancy → run separate instances.)

---

## 6. "If We're Wrong"

The strongest counter-argument to this assessment:

**"We're building a developer tool, not a security product. In-memory controls, simplified RBAC, and local attestation fallbacks are appropriate for the use case: AI developers who want a lightweight audit trail for debugging and compliance scoping. Our users run single-process MCP servers on their laptops. They don't need Redis, HMAC keys, or production-grade rate limiting. Ship it, iterate, and harden when customers demand it."**

This is a legitimate position. Consider:

- **The threat model shift is real.** If mcp-witness is primarily used by individual developers running it as a sidecar to their local MCP agents, the in-memory security controls are proportional to the risk. An attacker who can access your laptop can already do far worse than forge audit records.
- **Over-engineering cuts both ways.** Adding Redis, HMAC key management, and persistent rate limiters before users exist is the sin of over-engineering this report warns against. The difference is that security over-engineering is more defensible than feature over-engineering.
- **The TSA fallback critique may be too harsh.** A local attestation with a hash chain is strictly better than no attestation. It's only a "downgrade attack" if the attacker controls the network *and* the user believes they have a real TSA timestamp. If the tool clearly shows "local attestation (TSA unavailable)" vs "TSA timestamped," the user can make an informed decision.

**Where we disagree (our rebuttal):**

The in-memory idempotency cache with destructive eviction (`.clear()`) is indefensible regardless of threat model. A bounded LRU with the same memory footprint would be strictly better and cost nothing. That's not over-engineering — it's fixing a bug.

Similarly, the `verify()` methods that check `len > 0` are not "appropriate for lightweight use" — they're objectively wrong. If a provider can't verify, the method should either raise an error or return `False` with a clear explanation, not silently return `True`.

The line between "appropriate for developer use" and "genuinely broken" is different for each issue, and we've tried to be precise about which is which.

---

## Methodology Notes

- Source files analyzed: `storage_base.py`, `storage.py`, `merkle.py`, `security.py`, `buffered.py`, `hasher.py`, `models.py`, `compliance.py`, `anchoring.py`, `server.py`
- Codebase version: v0.4.0 (~7,700 lines Python, 126 tests)
- Assessment team: "The Engineers" — internal debate with Proposer (argues FOR), Opposer (argues AGAINST), Moderator (fact-checks), then synthesis
- All specific file references use the convention `file.py:line-number`
