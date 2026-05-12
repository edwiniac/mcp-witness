# MCP Witness — Incident Response Runbook

> **Purpose:** Step-by-step procedures for responding to common mcp-witness incidents.
> **Severity Levels:** critical, warning, info
> **Contact:** #oncall channel (Slack) or [email]

---

## Table of Contents

1. [Chain Break Detected](#1-chain-break-detected)
2. [Signature Verification Failures](#2-signature-verification-failures)
3. [Anchor Provider Unreachable](#3-anchor-provider-unreachable)
4. [Database Corruption](#4-database-corruption)
5. [Rate Limit Flooding](#5-rate-limit-flooding)

---

## 1. Chain Break Detected

### Symptoms
- `verify_chain()` returns `valid=False`
- `metrics.chain_breaks_total` > 0
- Log entries containing `CHAIN INVARIANT BROKEN` or `Chain break at sequence`
- Webhook/Slack alert from `notify_chain_failure`

### Severity
**critical** — Integrity of the audit trail is compromised.

### Immediate Actions

1. **Isolate the affected range**
   ```bash
   mcp-witness verify --from <first_invalid_sequence> --to <last_sequence>
   ```
   Identify the exact range where the chain break occurred.

2. **Check surrounding records**
   ```bash
   mcp-witness proof <first_invalid_sequence - 1>
   mcp-witness proof <first_invalid_sequence>
   mcp-witness proof <first_invalid_sequence + 1>
   ```
   Verify the records before and after the break point.

3. **Record metrics snapshot**
   ```bash
   mcp-witness metrics
   ```
   Save this output for post-mortem analysis.

### Investigation

1. **Identify the first invalid record**
   - The `first_invalid_sequence` field in the verification result tells you where the chain breaks.
   - Verify its `prev_hash` against the previous record's `record_hash`.

2. **Check database access logs**
   - Review who or what accessed the database around the timestamp of the first invalid record.
   - Look for concurrent writers or unauthorized access.

3. **Verify HMAC key integrity**
   - If `MCP_WITNESS_HMAC_KEY` changed between the valid and invalid record, the hash chain would break.
   - Check if the HMAC key was rotated or reset recently.
   - The hash is computed as `HMAC-SHA256(key, record_fields)`. A different key produces a different hash.

4. **Check for concurrent write forks**
   - If two processes wrote records simultaneously, the chain could fork.
   - Look for sequence numbers that don't follow the expected pattern.

### Recovery

1. **Option A: Restore from backup** (preferred)
   ```bash
   # Shut down the server
   # Restore database from backup
   cp /backups/witness-$(date -d "yesterday" +%Y%m%d).db ~/.mcp-witness/witness.db
   # Verify restored chain
   mcp-witness verify
   # Restart server
   ```

2. **Option B: Isolate and document** (when backup isn't available)
   - Records before the break point are still valid and usable.
   - The chain from the first invalid record onward must be treated as untrusted.
   - Export the valid portion for auditors.
   - Document the incident including: affected sequence range, timestamp, root cause.

3. **After recovery**
   - Run full chain verification: `mcp-witness verify`
   - Check all checkpoints: `mcp-witness checkpoints`
   - Verify external anchors: run `witness_verify_anchors` via MCP

### Stakeholder Notification

**Template for Slack/Email:**

```
🚨 CHAIN BREAK DETECTED — mcp-witness

Severity: CRITICAL
Detected at: <timestamp>
First invalid sequence: <sequence>
Records affected: <count>

Impact: Integrity of audit trail <range> is compromised.
Records before the break are valid.

Action taken: <isolated range / restored from backup / documented>
Recovery status: <in progress / completed>

Next steps: <root cause analysis / key rotation / backup restoration>
```

---

## 2. Signature Verification Failures

### Symptoms
- `metrics.signature_failures_total` > 0
- `verify_chain()` reports "signature verification failed" issues
- Log entries with "signature verification failed at sequence"

### Severity
**warning** — Individual records have invalid signatures, but chain integrity may still be intact.

### Investigation

1. **Identify affected records**
   ```bash
   mcp-witness verify | grep -i signature
   ```
   Note the sequence numbers where signature verification fails.

2. **Check the signing key**
   ```bash
   # Get the key_id from affected records
   mcp-witness export --format json | jq '.records[] | select(.signature != null) | {sequence, signer_key_id}'
   ```

3. **Is the key revoked in the trust store?**
   - If `signer_key_id` is present, check if it's in the trust store's revocation list.
   - Rotated keys will cause signature failures for records signed with the old key.

### Root Causes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Expired key | Key was rotated, old key no longer valid | Re-sign records with new key |
| Compromised key | Key appears in revocation list | Revoke old key, rotate, re-sign |
| Clock skew | Timestamp on signature is in the future | Fix system clock NTP sync |
| Data tampering | Hash mismatch + signature failure | Investigate chain integrity |

### Actions

1. **Rotate the signing key**
   ```bash
   export MCP_WITNESS_SIGNING_KEY=$(openssl rand -hex 32)
   ```

2. **Re-sign affected records** (requires tooling support)
   - Export the affected records
   - Re-compute signatures with the new key
   - Update the records in the database

3. **Revoke the old key**
   - Add the old key_id to the trust store's revocation list
   - This prevents the old key from being used again

4. **Verify after fix**
   ```bash
   mcp-witness verify
   ```

---

## 3. Anchor Provider Unreachable

### Symptoms
- `verify_anchors()` fails or returns `valid=False`
- Anchor operations timeout or return HTTP errors
- Log entries with "TSA returned HTTP" or "All OpenTimestamps servers failed"
- Metrics `anchor_verification_failures_total` increasing

### Severity
**warning** — Existing anchors are still valid, but new anchoring is unavailable.

### Immediate Actions

1. **Verify existing anchors are still valid**
   - Use the `witness_verify_anchors` MCP tool to check existing anchors.
   - Anchor receipts are stored locally; they remain verifiable even if the provider is down.

2. **Check network connectivity**
   ```bash
   curl -I https://freetsa.org/tsr
   curl -I https://a.pool.opentimestamps.org
   curl -I https://api.pinata.cloud
   ```

3. **Check provider status pages**
   - FreeTSA: https://freetsa.org/
   - OpenTimestamps: https://opentimestamps.org/
   - Pinata: https://pinata.statuspage.io/

4. **Check API rate limits**
   - Have you exceeded the provider's rate limit?
   - Check HTTP response status codes for 429 (Too Many Requests).

### Actions

1. **Switch providers temporarily**
   - If TSA is down, switch to OpenTimestamps or IPFS-only mode.
   - Set `MCP_WITNESS_ANCHOR_PROVIDERS=ots,ipfs` environment variable.

2. **Degraded operation**
   ```bash
   export MCP_WITNESS_ANCHOR_STRICT=false
   # Restart the MCP server for changes to take effect
   ```
   This allows the server to continue operating without external anchors.
   Anchor receipts will be recorded as "local" and can be upgraded later.

3. **Backfill anchors when provider recovers**
   - Once the provider is back online, run the backfill procedure.
   - Use `witness_backfill` MCP tool to re-anchor unanchored checkpoints.

---

## 4. Database Corruption

### Symptoms
- `SQLITE_OPERATIONAL_ERROR` or `SQLITE_CORRUPT` errors
- PostgreSQL connection failures
- Chain verification reports unexpected hash mismatches across many records
- Queries return nonsensical or truncated data

### Severity
**critical** — Potential data loss; immediate recovery needed.

### SQLite Recovery

1. **Stop the server**
   ```bash
   # Send SIGTERM for graceful shutdown
   kill -TERM <pid>
   ```

2. **Create a WAL checkpoint**
   ```sql
   -- Run against the database
   PRAGMA wal_checkpoint(TRUNCATE);
   ```

3. **Run integrity check**
   ```bash
   sqlite3 ~/.mcp-witness/witness.db "PRAGMA integrity_check;"
   ```
   If this reports "ok", the database is structurally sound but may still have logical corruption.

4. **Recover if corruption is found**
   ```bash
   # Use .recover command (SQLite >= 3.32.0)
   sqlite3 ~/.mcp-witness/witness.db ".recover" | sqlite3 ~/.mcp-witness/witness-recovered.db
   
   # Verify the recovered database
   sqlite3 ~/.mcp-witness/witness-recovered.db "PRAGMA integrity_check;"
   
   # Run chain verification
   mcp-witness --db ~/.mcp-witness/witness-recovered.db verify
   ```

5. **Restore from backup** (if recovery fails)
   ```bash
   cp /backups/witness-$(date -d "yesterday" +%Y%m%d).db ~/.mcp-witness/witness.db
   ```

### PostgreSQL Recovery

1. **Verify checksums**
   ```bash
   pg_verify_checksums -D $PGDATA
   ```

2. **Dump and restore**
   ```bash
   pg_dump -Fc witness_test > witness_dump.dump
   pg_restore --list witness_dump.dump  # Verify structure
   
   # Create a new database and restore
   createdb witness_recovered
   pg_restore -d witness_recovered witness_dump.dump
   ```

3. **Run chain verification after restore**
   ```bash
   mcp-witness --db <recovered> verify
   ```

### Recovery Validation

1. **Run chain verification**
   ```bash
   mcp-witness verify
   ```
2. **Check all external anchors**
   ```bash
   mcp-witness anchors verify <checkpoint_id>
   ```
3. **Spot-check records from before the corruption**
   ```bash
   mcp-witness proof <sequence>
   ```

---

## 5. Rate Limit Flooding

### Symptoms
- `metrics.rate_limit_hits_total` increasing rapidly
- Error responses: "Rate limit exceeded" for many requests
- Legitimate writes are being rejected

### Severity
**warning** — System is operational but legitimate requests may be blocked.

### Investigation

1. **Identify the source**
   - Check `actor_id` values in recent API key authentications.
   - Look for a single actor making excessive write requests.

2. **Check auth logs**
   ```bash
   # If JSON logging is enabled
   grep "rate_limit_hits_total" /var/log/mcp-witness/metrics.log
   ```

3. **Determine if it's an attack or misconfiguration**
   - A single actor sending thousands of writes per second → likely an attack.
   - Multiple actors all hitting limits → likely misconfiguration (limit too low).

### Actions

1. **Temporarily increase limits**
   ```bash
   export MCP_WITNESS_RATE_LIMIT=5000  # Increase from default 1000
   # Restart the MCP server
   ```

2. **Block abusive keys**
   - Rotate API keys for the affected actors.
   - Remove or revoke the abusive key from `MCP_WITNESS_API_KEYS`.

3. **Monitor after action**
   ```bash
   mcp-witness metrics
   # Check that rate_limit_hits_total stabilizes
   ```

### Long-term Solutions

- **Implement per-key quotas** instead of a single global limit.
- **Add burst protection** — allow short bursts above the limit.
- **Use IP-based rate limiting** if the attack is from a single origin.
- **Configure webhook alerts** — get notified when rate limit hits exceed a threshold.

---

## Appendix: Metrics Reference

| Metric | Type | Description |
|--------|------|-------------|
| `chain_breaks_total` | Counter | Total chain breaks detected |
| `signature_failures_total` | Counter | Total signature verification failures |
| `anchor_verification_failures_total` | Counter | Total anchor verification failures |
| `rate_limit_hits_total` | Counter | Total rate limit exceeded events |
| `idempotency_duplicates_total` | Counter | Total duplicate nonce rejections |
| `records_written_total` | Counter | Total records written |
| `records_read_total` | Counter | Total records read |
| `lock_contention` | Histogram | Transaction lock contention times (p95) |

View metrics via: `mcp-witness metrics` or the `witness_metrics` MCP tool.

---

## Appendix: Quick Commands

```bash
# Check chain integrity
mcp-witness verify

# Check fast verification
mcp-witness verify --fast

# Show metrics
mcp-witness metrics

# Show stats
mcp-witness stats

# List checkpoints
mcp-witness checkpoints

# Get proof for a record
mcp-witness proof <sequence>

# Run migration (dry run)
mcp-witness migrate --dry-run

# List schema versions
mcp-witness migrations
```
