# Contributing to mcp-witness

First off — thanks for caring about AI audit trails. This project exists because AI decisions need cryptographic proof, and every contribution makes that proof stronger.

## Quick Start

```bash
git clone https://github.com/edwiniac/mcp-witness.git
cd mcp-witness
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python3 -m pytest tests/ -v
```

## Project Structure

```
src/mcp_witness/
├── __init__.py       # Public API exports
├── server.py         # MCP server + 14 tool definitions
├── models.py         # Pydantic data models
├── storage.py        # SQLite backend with hash chain
├── hasher.py         # Cryptographic hashing
├── merkle.py         # Merkle tree with domain separation
├── anchoring.py      # TSA, OpenTimestamps, IPFS anchoring
├── security.py       # Rate limiting, RBAC, validation
├── compliance.py     # HIPAA, GDPR, SOX presets
├── cli.py           # Command-line interface
└── dashboard/       # Web dashboard
```

## Development Guidelines

### Before Submitting

1. Run the test suite: `python3 -m pytest tests/ -v`
2. Run the linter: `ruff check src/`
3. Format: `black src/ tests/`
4. Make sure all 107+ tests pass

### Commit Style

- `fix:` — bug fixes
- `feat:` — new features
- `security:` — security-related changes
- `docs:` — documentation
- `test:` — test additions/changes

### Design Principles

- **Immutability is sacred.** Any change that could compromise the hash chain is unacceptable.
- **Domain separation.** Cryptographic operations use distinct prefixes to prevent confusion.
- **Fail secure.** Errors must never leak sensitive information.
- **Zero trust.** Input is validated at every boundary.

## Areas Needing Help

- PostgreSQL backend (`[project.optional-dependencies].postgres`)
- Web dashboard API server (FastAPI)
- Ed25519 record signing
- Streaming architecture (Kafka/NATS)
- Multi-tenancy with row-level security
- Schema migration tools (Alembic)
- PDF report generation
- Threat model documentation

## Security

Found a security issue? Please email edwinisac007@gmail.com directly.
Do NOT open a public issue for security vulnerabilities.
