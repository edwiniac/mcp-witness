"""
Structured JSON logging for mcp-witness.

When MCP_WITNESS_LOG_FORMAT=json, all log output is formatted as newline-delimited
JSON objects for consumption by log aggregators (Datadog, ELK, etc.).

Default (format=text) stays human-readable for local development.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Format log records as JSON objects.

    Each log line is a JSON object with:
        timestamp (ISO 8601), level, logger, message, and extra fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
            }

        # Include any extra fields passed via extra={}
        for key, value in getattr(record, "extra_fields", {}).items():
            log_entry[key] = value

        return json.dumps(log_entry, default=str)


# ---------------------------------------------------------------------------
# Sensitive data scrubbing in logs
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS = [
    (
        re.compile(
            r"(?:api[_-]?key|apikey|secret|password|token|auth)[=:]\s*[\"']?"
            r"([a-zA-Z0-9+/=_-]{16,})[\"']?",
            re.IGNORECASE,
        ),
        "[CREDENTIAL]",
    ),
    (re.compile(r"[a-fA-F0-9]{64,}"), "[HEX_KEY]"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "[API_KEY]"),
]


class SensitiveDataFilter(logging.Filter):
    """Filter that redacts sensitive data from log messages.

    Patterns matched are replaced with safe placeholders:
    - API keys / secrets / passwords → [CREDENTIAL]
    - Long hex strings → [HEX_KEY]
    - OpenAI-style API keys (sk-...) → [API_KEY]
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, replacement in _SENSITIVE_PATTERNS:
                record.msg = pattern.sub(replacement, record.msg)
        return True


def setup_structured_logging():
    """Configure logging based on MCP_WITNESS_LOG_FORMAT env var.

    - "json": JSON-formatted log lines (for production / log aggregators)
    - anything else or unset: human-readable text (for local dev)

    Also registers SensitiveDataFilter on the handler to redact sensitive
    information (API keys, secrets, tokens) from log output.

    This configures the root logger and can be called at application startup.
    """
    log_format = os.getenv("MCP_WITNESS_LOG_FORMAT", "text").lower()
    log_level = os.getenv("MCP_WITNESS_LOG_LEVEL", "INFO").upper()

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(getattr(logging, log_level, logging.INFO))

    if log_format == "json":
        handler.setFormatter(JSONFormatter())
    else:
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
        handler.setFormatter(formatter)

    # Register sensitive data filter on the handler
    handler.addFilter(SensitiveDataFilter())

    root_logger.addHandler(handler)

    # Log the configuration
    root_logger.info(
        "Logging configured: format=%s, level=%s",
        log_format,
        log_level,
    )
