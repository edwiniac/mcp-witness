# MCP Witness — Backup & Restore Guide

> **Purpose:** Procedures for backing up and restoring mcp-witness data, including the database and anchor receipts.
> **Last updated:** 2026-05-12

---

## Table of Contents

1. [Backup Strategy Overview](#1-backup-strategy-overview)
2. [SQLite Backup](#2-sqlite-backup)
3. [PostgreSQL Backup](#3-postgresql-backup)
4. [Anchor Receipt Backup](#4-anchor-receipt-backup)
5. [Recovery Procedure](#5-recovery-procedure)
6. [Automated Backup](#6-automated-backup)

---

## 1. Backup Strategy Overview

The mcp-witness system has two critical data components:

| Component | Location | Criticality | Notes |
|-----------|----------|-------------|-------|
| **Database** | `~/.mcp-witness/witness.db` (SQLite) or PostgreSQL | High | Contains all witness records, hash chain, checkpoints |
| **Anchor Receipts** | Stored in database + external providers | Critical | Required for offline verification of chain integrity |

**Backup frequency recommendations:**

| Environment | Frequency | Retention |
|-------------|-----------|-----------|
| Production | Every 6 hours | 30 days |
| Staging | Daily | 7 days |
| Development | Weekly | 1 month |

---

## 2. SQLite Backup

### Prerequisites
- Server should be idle or in read-only mode during backup
- SQLite >= 3.8.0 (for WAL mode support)

### Step 1: Create a WAL Checkpoint

Before backing up, flush the Write-Ahead Log to ensure all data is in the main database file:

```bash
sqlite3 ~/.mcp-witness/witness.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

This ensures the backup captures the complete database state.

### Step 2: Use `.backup` Command

The safest method uses SQLite's built-in backup API which creates a consistent snapshot:

```bash
sqlite3 ~/.mcp-witness/witness.db ".backup /backups/witness-$(date +%Y%m%d-%H%M%S).db"
```

This acquires a shared lock on the source database, allowing reads to continue during backup.

### Step 3: Verify the Backup

```bash
# Check database integrity
sqlite3 /backups/witness-$(date +%Y%m%d-%H%M%S).db "PRAGMA integrity_check;"

# Compute hash for verification
sha256sum /backups/witness-$(date +%Y%m%d-%H%M%S).db > /backups/witness-$(date +%Y%m%d-%H%M%S).db.sha256

# Verify hash later with:
# sha256sum -c /backups/witness-*.db.sha256
```

### Alternative: Using SqliteStorage API

```python
import aiosqlite
import asyncio

async def backup_db(source_path: str, backup_path: str):
    """Create a consistent backup using SQLite's backup API."""
    source = await aiosqlite.connect(source_path)
    dest = await aiosqlite.connect(backup_path)

    with source, dest:
        await source.backup(dest, pages=1000)  # 1000 pages per iteration

    print(f"Backup created: {backup_path}")

asyncio.run(backup_db("~/.mcp-witness/witness.db", "/backups/witness-backup.db"))
```

---

## 3. PostgreSQL Backup

### Step 1: Dump the Database

Use `pg_dump` with the custom format for compressed, parallel-capable backups:

```bash
PGPASSWORD=witness_test pg_dump -h localhost -U witness \
  -Fc --compress=9 --no-owner \
  -f /backups/witness-$(date +%Y%m%d-%H%M%S).dump \
  witness_test
```

Options explained:
- `-Fc`: Custom format (compressed, supports parallel restore)
- `--compress=9`: Maximum compression level
- `--no-owner`: Skip ownership commands (safer for cross-environment restore)

### Step 2: Verify the Dump

```bash
# List contents without restoring
pg_restore --list /backups/witness-*.dump | head -20

# Verify structure is intact
pg_restore -l /backups/witness-*.dump | grep -E "TABLE|INDEX|SEQUENCE" | wc -l
```

### Step 3: Compute Backup Hash

```bash
sha256sum /backups/witness-*.dump > /backups/witness-$(date +%Y%m%d).dump.sha256
```

### Alternative: Consistent Snapshot

For production PostgreSQL, use a consistent snapshot with replication slots:

```bash
# Create a replication slot
psql -h localhost -U witness -d witness_test -c \
  "SELECT pg_create_physical_replication_slot('witness_backup');"

# Use pg_basebackup for full cluster backup
pg_basebackup -h localhost -U witness -D /backups/pg_base \
  --slot=witness_backup --progress --verbose

# Verify checksums
pg_verify_checksums -D /backups/pg_base
```

---

## 4. Anchor Receipt Backup

Anchor receipts are stored in the database but should be backed up **separately** because they are critical for **offline verification** of chain integrity.

### What to Backup

Anchor receipts include:
- RFC 3161 TSA timestamps (binary DER-encoded)
- OpenTimestamps receipts (binary)
- IPFS CIDs (text)
- Verification URLs

### Method 1: Export from Database

```bash
# Export anchor receipts as JSON
mcp-witness export --format json --output /backups/anchors-$(date +%Y%m%d).json

# Also export raw receipt data
sqlite3 ~/.mcp-witness/witness.db -json \
  "SELECT * FROM witness_anchors;" \
  > /backups/anchor-receipts-$(date +%Y%m%d).json
```

### Method 2: Backup Referenced Files

If anchor receipts reference external files (e.g., raw TSR files):

```bash
ls -la ~/.mcp-witness/anchors/
tar -czf /backups/anchor-files-$(date +%Y%m%d).tar.gz ~/.mcp-witness/anchors/
```

### Why Backup Separately?

Anchor receipts from external providers (TSA, Bitcoin, IPFS) are the **only way to prove** that records existed at a specific point in time. If the database is lost but you have the anchor receipt, you can still prove the chain was intact up to the checkpoint that was anchored.

**Store anchor backups off-site** or in a different region from the database backup.

---

## 5. Recovery Procedure

### Full Recovery Steps

1. **Stop the MCP Witness server**
   ```bash
   # Graceful shutdown
   kill -TERM <mcp-witness-pid>
   ```

2. **Restore the database**

   **SQLite:**
   ```bash
   # Restore from backup
   cp /backups/witness-20260511.db ~/.mcp-witness/witness.db

   # Verify integrity
   sqlite3 ~/.mcp-witness/witness.db "PRAGMA integrity_check;"
   ```

   **PostgreSQL:**
   ```bash
   # Drop and recreate the database
   createdb witness_recovered
   pg_restore -d witness_recovered --clean --if-exists \
     /backups/witness-20260511.dump

   # Verify
   psql -d witness_recovered -c "SELECT COUNT(*) FROM witness_records;"
   ```

3. **Restore anchor receipts** (if stored separately)
   ```bash
   tar -xzf /backups/anchor-files-20260511.tar.gz -C ~/.mcp-witness/
   ```

4. **Verify chain integrity**
   ```bash
   mcp-witness --db ~/.mcp-witness/witness.db verify
   ```

5. **Confirm chain valid**
   ```bash
   mcp-witness --db ~/.mcp-witness/witness.db stats
   # Look for: Chain Valid: ✅
   ```

6. **Run anchor verification**
   Run the `witness_verify_anchors` MCP tool to verify all external anchors
   for the latest checkpoints.

7. **Start the server**
   ```bash
   mcp-witness serve
   ```

### Partial Recovery

If only a subset of records need recovery, use the `witness_export` tool
to export the affected range and re-insert them:

```bash
# From the backup database
mcp-witness --db /backups/witness-20260511.db export --format json \
  --from_time 2026-05-10T00:00:00 --to_time 2026-05-11T00:00:00

# Replay records through the MCP server
```

---

## 6. Automated Backup

### Cron Job Example (SQLite)

Create `/etc/cron.d/mcp-witness-backup`:

```cron
# MCP Witness backup — every 6 hours
0 */6 * * * witness-user /opt/mcp-witness/scripts/backup.sh
```

Backup script `/opt/mcp-witness/scripts/backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backups/witness"
DB_PATH="$HOME/.mcp-witness/witness.db"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

# Timestamp
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/witness-$TS.db"
HASH_FILE="$BACKUP_DIR/witness-$TS.db.sha256"

# Create WAL checkpoint
sqlite3 "$DB_PATH" "PRAGMA wal_checkpoint(TRUNCATE);"

# Create backup
sqlite3 "$DB_PATH" ".backup $BACKUP_FILE"

# Verify integrity
INTEGRITY=$(sqlite3 "$BACKUP_FILE" "PRAGMA integrity_check;")
if [ "$INTEGRITY" != "ok" ]; then
    echo "ERROR: Backup integrity check failed: $INTEGRITY"
    rm -f "$BACKUP_FILE"
    exit 1
fi

# Compute hash
sha256sum "$BACKUP_FILE" > "$HASH_FILE"

# Clean old backups (retain 30 days)
find "$BACKUP_DIR" -name "witness-*.db" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "witness-*.db.sha256" -mtime +$RETENTION_DAYS -delete

# Also backup anchor receipts
sqlite3 "$DB_PATH" -json \
  "SELECT * FROM witness_anchors;" \
  > "$BACKUP_DIR/anchors-$TS.json"

echo "Backup complete: $BACKUP_FILE"
echo "Anchor receipts: $BACKUP_DIR/anchors-$TS.json"
```

### Cron Job Example (PostgreSQL)

Backup script `/opt/mcp-witness/scripts/pg-backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/backups/witness"
DB_NAME="witness_test"
DB_USER="witness"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"
TS=$(date +%Y%m%d-%H%M%S)

# Dump with compression
PGPASSWORD="${PGPASSWORD:-}" pg_dump -h localhost -U "$DB_USER" \
  -Fc --compress=9 \
  -f "$BACKUP_DIR/witness-pg-$TS.dump" \
  "$DB_NAME"

# Verify
pg_restore -l "$BACKUP_DIR/witness-pg-$TS.dump" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: pg_restore verification failed"
    exit 1
fi

# Hash
sha256sum "$BACKUP_DIR/witness-pg-$TS.dump" > "$BACKUP_DIR/witness-pg-$TS.dump.sha256"

# Clean old
find "$BACKUP_DIR" -name "witness-pg-*.dump" -mtime +$RETENTION_DAYS -delete
find "$BACKUP_DIR" -name "witness-pg-*.dump.sha256" -mtime +$RETENTION_DAYS -delete

echo "PostgreSQL backup complete: $BACKUP_DIR/witness-pg-$TS.dump"
```

---

## Appendix: Verification Checklist

After any restore, verify:

- [ ] Database integrity check passes
- [ ] Chain verification succeeds (`mcp-witness verify`)
- [ ] No records were lost (compare record count with pre-backup stats)
- [ ] Checkpoints are intact (`mcp-witness checkpoints`)
- [ ] External anchors are valid (`witness_verify_anchors`)
- [ ] Server starts without errors (`mcp-witness serve --check-only`)
- [ ] Webhook notification was sent (if configured)
