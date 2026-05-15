# Production Audit Report — mcp-witness (Deep-Dive Revision)

## Executive Summary
This second-pass audit performs a niche-level review of operational security, cryptographic hygiene, concurrency, resilience, and production ergonomics. The project demonstrates strong cryptographic direction (hash chaining, signing, Merkle checkpointing, anchoring), but **critical default-access behavior and transport/application hardening gaps remain**. The most material risks are:

1. **Implicit open-admin mode when auth is not configured** (broken access control).
2. **Non-strict JWT claim validation**, which weakens trust assumptions.
3. **Dashboard runtime defects and permissive response behavior** (error/metadata leakage).
4. **Scalability issues in query/search/export paths** under high-volume retention.
5. **Insufficient defensive validation + edge-case tests for malformed inputs and timing boundaries**.

Current readiness assessment for regulated, high-scale production: **Not yet acceptable without remediation of Critical/High findings below**.

---

## 1) Architecture & Design Patterns

- **[Severity]** Critical
- **[Location]**: `src/mcp_witness/auth.py` (`authenticate`, `authorize` flow)
- **[The Flaw]**: Authentication and authorization semantics are coupled through a special `None` role that means “admin/open mode.” This is an architectural anti-pattern because “absence of identity” doubles as “highest privilege.”
- **[The Fix]**:
```python
class AuthRole(str, Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    WRITER = "writer"
    ANONYMOUS = "anonymous"

# authenticate() should always return a concrete role
if not api_keys:
    return AuthRole.ANONYMOUS

def authorize(role: AuthRole, tool_name: str) -> None:
    if role == AuthRole.ANONYMOUS:
        raise PermissionError("Anonymous access denied; configure authentication")
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/server.py` (`call_tool` giant dispatcher)
- **[The Flaw]**: Large `if/elif` tool dispatch violates Open/Closed principle and increases defect probability when adding/removing handlers.
- **[The Fix]**:
```python
TOOL_HANDLERS: dict[str, Callable[[StorageBackend, dict], Awaitable[dict]]] = {
    "witness_record": handle_record,
    "witness_verify": handle_verify,
    "witness_query": handle_query,
    # ... all tools
}

handler = TOOL_HANDLERS.get(name)
if not handler:
    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
result = await handler(store, arguments)
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/server.py` (`get_storage`)
- **[The Flaw]**: Singleton initialization can race in concurrent startup windows; no lock protects first-connect initialization.
- **[The Fix]**:
```python
_storage_lock = asyncio.Lock()

async def get_storage() -> StorageBackend:
    global storage
    if storage is not None:
        return storage
    async with _storage_lock:
        if storage is None:
            s = _create_storage()
            await s.connect()
            storage = s
    return storage
```

- **[Severity]** Low
- **[Location]**: `src/mcp_witness/dashboard/server.py`
- **[The Flaw]**: Dashboard module blends HTTP concerns, async orchestration, storage lifecycle, and serialization in one handler class (low cohesion).
- **[The Fix]**:
```python
class DashboardService:
    async def fetch_snapshot(self) -> dict: ...

class DashboardHandler(SimpleHTTPRequestHandler):
    service: DashboardService
    def handle_api(self):
        data = self.service.fetch_snapshot_sync()
        self._send_json(data)
```

---

## 2) Security & Vulnerabilities

- **[Severity]** Critical
- **[Location]**: `src/mcp_witness/auth.py` (`authenticate`, lines around open mode behavior)
- **[The Flaw]**: If no key configuration exists, requests effectively get admin behavior (`role=None` and `authorize` bypass). This is a Broken Access Control issue (OWASP A01).
- **[The Fix]**:
```python
DEFAULT_ACCESS_MODE = os.getenv("MCP_WITNESS_DEFAULT_ACCESS", "deny").lower()

if not api_keys:
    if DEFAULT_ACCESS_MODE == "deny":
        raise PermissionError("Authentication not configured")
    if DEFAULT_ACCESS_MODE == "read_only":
        return AuthRole.AUDITOR
    raise ValueError("Invalid MCP_WITNESS_DEFAULT_ACCESS")
```

- **[Severity]** High
- **[Location]**: `src/mcp_witness/auth.py` (`verify_jwt_assertion`)
- **[The Flaw]**: Missing strict header/payload claim checks (`alg`, `typ`, required `sub`, bounded future `iat`, issuer/audience checks). Signature validity alone is not sufficient.
- **[The Fix]**:
```python
header = json.loads(b64url_decode(header_b64))
if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
    return None

payload = json.loads(payload_bytes)
required = ("sub", "iat", "exp", "role")
if any(k not in payload for k in required):
    return None

if payload.get("iss") != os.getenv("MCP_WITNESS_JWT_ISSUER"):
    return None
if payload.get("aud") != os.getenv("MCP_WITNESS_JWT_AUDIENCE"):
    return None
```

- **[Severity]** High
- **[Location]**: `src/mcp_witness/dashboard/server.py` (`_send_json`, `handle_api`)
- **[The Flaw]**: `Access-Control-Allow-Origin: *` and raw exception reflection enable broad-origin metadata/error harvesting.
- **[The Fix]**:
```python
origin = os.getenv("MCP_WITNESS_DASHBOARD_ORIGIN", "")
if origin:
    self.send_header("Access-Control-Allow-Origin", origin)
self.send_header("X-Content-Type-Options", "nosniff")
self.send_header("Cache-Control", "no-store")

except Exception:
    logger.exception("Dashboard API error")
    self._send_json({"error": "internal_error"}, status=500)
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/server.py` (`call_tool` argument typing)
- **[The Flaw]**: `arguments` is assumed to be dict-like and trusted. Absent strict schema validation at runtime, malformed payloads can trigger inconsistent error paths.
- **[The Fix]**:
```python
if not isinstance(arguments, dict):
    raise ValueError("Tool arguments must be an object")
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/security.py` (`decrypt_field`)
- **[The Flaw]**: Broad exception suppression can hide tampering/wrong-key events. Silent fallback may reduce forensic signal.
- **[The Fix]**:
```python
except Exception as exc:
    logger.warning("decrypt_field failure", extra={"error": str(exc)})
    return encrypted
```

---

## 3) Performance & Scalability

- **[Severity]** High
- **[Location]**: `src/mcp_witness/storage.py` (`search` LIKE queries)
- **[The Flaw]**: `%query%` pattern on multiple JSON/text fields causes full scans and poor latency at high record counts.
- **[The Fix]**:
```python
await self._db.execute(
    "CREATE VIRTUAL TABLE IF NOT EXISTS witness_records_fts "
    "USING fts5(reasoning, input_data, output_data, content='witness_records', content_rowid='rowid')"
)

cursor = await self._db.execute(
    """
    SELECT wr.*
    FROM witness_records_fts fts
    JOIN witness_records wr ON wr.rowid = fts.rowid
    WHERE witness_records_fts MATCH ?
    ORDER BY wr.sequence DESC
    LIMIT ? OFFSET ?
    """,
    (query, limit, offset),
)
```

- **[Severity]** High
- **[Location]**: `src/mcp_witness/server.py` (`handle_export`)
- **[The Flaw]**: Full materialization of export payload into memory before write is non-linear risk for large datasets.
- **[The Fix]**:
```python
with open(safe_path, "w", encoding="utf-8") as f:
    f.write('{"records":[\n')
    first = True
    offset, page = 0, 1000
    while True:
        rows = await store.query(limit=page, offset=offset, ...)
        if not rows:
            break
        for r in rows:
            if not first:
                f.write(',\n')
            first = False
            f.write(json.dumps(record_to_dict(r), default=str))
        offset += page
    f.write('\n]}')
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/server.py` (`handle_export` summary actions)
- **[The Flaw]**: `actions_by_type` recomputes `any(...)` and `sum(...)` per enum variant; avoidable repeated scans.
- **[The Fix]**:
```python
from collections import Counter
counts = Counter(r.action_type.value for r in records)
actions_by_type = dict(counts)
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/storage.py` (`query` with large offsets)
- **[The Flaw]**: Offset pagination degrades with deep offsets; high-cardinality tables suffer increasing latency.
- **[The Fix]**:
```python
# keyset pagination
WHERE sequence > ?
ORDER BY sequence ASC
LIMIT ?
```

---

## 4) Concurrency & State Management

- **[Severity]** High
- **[Location]**: `src/mcp_witness/dashboard/server.py` (`handle_api`, `_get_dashboard_data`)
- **[The Flaw]**: Nested lifecycle misuse: connect/close happens both in outer and inner coroutines; also uses `asyncio.run()` per request. This is fragile and wasteful.
- **[The Fix]**:
```python
async def _load_dashboard(store):
    stats = await store.get_stats()
    anchor_stats = await store.get_anchor_stats()
    checkpoints = await store.list_checkpoints(limit=5)
    records = await store.query(limit=20)
    verification = await store.verify_chain_fast()
    return build_payload(stats, anchor_stats, checkpoints, records, verification)

# single connect/close boundary
await store.connect()
try:
    data = await _load_dashboard(store)
finally:
    await store.close()
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/storage.py` (`has_inflight_writes`, `_active_transactions`)
- **[The Flaw]**: Shared mutable counter read/write lacks explicit lock discipline for all paths, risking stale read under future threading/multi-loop adaptation.
- **[The Fix]**:
```python
async with self._transaction_lock:
    self._active_transactions += 1
try:
    ...
finally:
    async with self._transaction_lock:
        self._active_transactions -= 1
```

---

## 5) Code Quality & Maintainability

- **[Severity]** High
- **[Location]**: `src/mcp_witness/dashboard/server.py` (`from ..storage import WitnessStorage`)
- **[The Flaw]**: Import references a non-existent class; runtime failure path on dashboard API call.
- **[The Fix]**:
```python
from ..storage import SqliteStorage
store = SqliteStorage(Path(db_path).expanduser())
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/server.py` (tool schemas vs handlers)
- **[The Flaw]**: Some schema-level defaults/constraints are not mirrored by defensive handler-level validation, increasing drift risk.
- **[The Fix]**:
```python
def require_int(value: object, field: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or value < minimum:
        raise ValueError(f"{field} must be integer >= {minimum}")
    return value
```

- **[Severity]** Low
- **[Location]**: `src/mcp_witness/storage.py` docstring of `search`
- **[The Flaw]**: Docstring claims fallback “on reasoning field” but query actually searches reasoning/input_data/output_data.
- **[The Fix]**:
```python
"""Search across reasoning, input_data, and output_data using LIKE.
Consider FTS5 for production-scale usage.
"""
```

---

## 6) Testing & Edge Cases

- **[Severity]** High
- **[Location]**: `src/mcp_witness/dashboard/server.py` (dashboard API execution path)
- **[The Flaw]**: The `WitnessStorage` symbol defect implies missing integration coverage for dashboard endpoint startup + fetch.
- **[The Fix]**:
```python
def test_dashboard_api_returns_200(tmp_path):
    # start server with temp db and assert /api/dashboard returns JSON snapshot
    ...
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/server.py` (`handle_query` time parsing)
- **[The Flaw]**: Invalid ISO-8601 values rely on generic exception sanitizer; no precise contract tests for malformed timestamps/timezone boundaries.
- **[The Fix]**:
```python
def parse_iso8601(s: str, field: str) -> datetime:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid {field}; expected ISO-8601") from exc
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/auth.py` (JWT verification logic)
- **[The Flaw]**: No explicit tests for boundary claims (`iat` in future, expired `exp`, invalid `aud`/`iss`, unknown role downgrade).
- **[The Fix]**:
```python
@pytest.mark.parametrize(...)
def test_verify_jwt_rejects_invalid_claims(...):
    assert verify_jwt_assertion(token) is None
```

- **[Severity]** Medium
- **[Location]**: `src/mcp_witness/storage.py` (`search`, `query`, `verify_chain_fast`)
- **[The Flaw]**: Missing performance regression tests (latency budgets / query plans) for large-scale datasets.
- **[The Fix]**:
```python
def test_search_plan_uses_fts(sqlite_conn):
    plan = sqlite_conn.execute("EXPLAIN QUERY PLAN ...").fetchall()
    assert "VIRTUAL TABLE" in str(plan)
```

---

## Prioritized Remediation Plan

1. **Immediate (P0):** eliminate implicit open-admin mode; enforce deny-by-default authentication.
2. **Immediate (P0):** harden JWT claims and issuer/audience semantics.
3. **Immediate (P1):** fix dashboard import/runtime path and remove wildcard CORS + raw error reflection.
4. **Short-term (P1):** replace large dispatcher with registry and add strict runtime argument validators.
5. **Short-term (P1):** implement FTS5 migration and streaming exports.
6. **Short-term (P2):** add integration/performance tests for dashboard and search at scale.

## Final Assessment
The codebase is promising and already includes several mature primitives, but current defaults and edge-path behavior are not production-safe for high-assurance environments. Addressing the P0/P1 items above will significantly improve trustworthiness and operational resilience.
