# ── mcp-witness Dockerfile ───────────────────────────────────────────────────
# Cryptographic audit trail for AI decisions.
#
# Usage:
#   docker build -t mcp-witness .
#   docker run -v witness-data:/data -p 9090:9090 mcp-witness serve
#
# Multi-stage: builder stage keeps the image small (~180MB final).

FROM python:3.12-slim AS builder

WORKDIR /build

# Install build deps
RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
COPY src/ ./src/

# Build wheel
RUN uv pip install --system build && \
    python -m build --wheel && \
    ls dist/

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim

# Metadata
LABEL org.opencontainers.image.title="mcp-witness"
LABEL org.opencontainers.image.description="Immutable audit trail MCP server for AI decisions"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/edwiniac/mcp-witness"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN groupadd -r witness && useradd -r -g witness -d /data witness

# Install runtime deps
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Create data directory
RUN mkdir -p /data && chown witness:witness /data

# Switch to non-root
USER witness
WORKDIR /data

# ── Configuration ────────────────────────────────────────────────────────────
ENV MCP_WITNESS_DB=/data/witness.db
ENV MCP_WITNESS_CHECKPOINT_INTERVAL=1000
ENV MCP_WITNESS_DASHBOARD_PORT=9090
ENV MCP_WITNESS_LOG_FORMAT=json

# Secrets (set at runtime, not baked into image)
# MCP_WITNESS_SIGNING_KEY  — 64-char hex Ed25519 seed
# MCP_WITNESS_HMAC_KEY     — 64-char hex HMAC secret
# MCP_WITNESS_ENCRYPTION_KEY — 64-char hex AES-256 key
# MCP_WITNESS_API_KEYS     — key:role,key:role
# MCP_WITNESS_JWT_PUBLIC_KEY — 64-char hex Ed25519 public key
# MCP_WITNESS_JWT_PRIVATE_KEY — 64-char hex Ed25519 private key

# Health check verifies the server is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD mcp-witness stats || exit 1

# Default: MCP server over stdio (for Claude Desktop / MCP clients)
ENTRYPOINT ["mcp-witness"]
CMD ["serve"]

# ── Alternative run modes ────────────────────────────────────────────────────
# Dashboard:
#   docker run -p 9090:9090 mcp-witness dashboard
#
# With PostgreSQL:
#   docker run -e MCP_WITNESS_BACKEND=postgresql \
#              -e MCP_WITNESS_PG_URL=postgresql://user:pass@host:5432/db \
#              mcp-witness serve
#
# Init-only (setup DB, then exit):
#   docker run -v witness-data:/data mcp-witness init
