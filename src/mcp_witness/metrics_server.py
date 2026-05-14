"""Minimal Prometheus-format metrics HTTP server for mcp-witness.

Exposes counters on a configurable port so external monitoring systems
(Grafana, Alertmanager, Datadog agent) can scrape them.

Enable via: MCP_WITNESS_METRICS_PORT=9091
"""

import asyncio
import logging
from typing import Optional

from . import metrics as _metrics

logger = logging.getLogger(__name__)

_METRIC_DEFS = [
    ("chain_breaks_total", "counter", "Total chain integrity failures detected"),
    ("signature_failures_total", "counter", "Total Ed25519 signature verification failures"),
    (
        "anchor_verification_failures_total",
        "counter",
        "Total external anchor verification failures",
    ),
    ("rate_limit_hits_total", "counter", "Total rate-limit rejections"),
    ("idempotency_duplicates_total", "counter", "Total duplicate-action rejections"),
    ("records_written_total", "counter", "Total audit records written"),
    ("records_read_total", "counter", "Total audit records read"),
]

_PREFIX = "mcp_witness_"

# Guard against a slow client holding the connection open by sending
# one header line every ~5 seconds indefinitely.
_MAX_REQUEST_HEADERS = 100


def _render_prometheus() -> str:
    """Render all counters in Prometheus text exposition format (v0.0.4)."""
    m = _metrics.get_metrics()
    lines: list[str] = []
    for key, metric_type, help_text in _METRIC_DEFS:
        full_name = _PREFIX + key
        lines.append(f"# HELP {full_name} {help_text}")
        lines.append(f"# TYPE {full_name} {metric_type}")
        lines.append(f"{full_name} {m.get(key, 0)}")
    return "\n".join(lines) + "\n"


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle a single HTTP request, return metrics, close connection."""
    try:
        # Read and discard the entire HTTP request (headers only; no body expected).
        # The line limit guards against a slow-sender keeping the socket open.
        for _ in range(_MAX_REQUEST_HEADERS):
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if line in (b"\r\n", b"\n", b""):
                break

        body = _render_prometheus().encode()
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        writer.write(response)
        await writer.drain()
    except Exception as exc:
        logger.debug("metrics_server: request handling error: %s", exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def start_metrics_server(
    host: str = "0.0.0.0",
    port: int = 9091,
) -> Optional[asyncio.AbstractServer]:
    """Start the Prometheus metrics HTTP server as a background asyncio task.

    Returns the Server object so the caller can close it on shutdown.
    Returns None if the port is 0 (disabled).
    """
    if not port:
        return None

    try:
        server = await asyncio.start_server(_handle, host, port)
        logger.info(
            "Prometheus metrics endpoint started on http://%s:%d/metrics — "
            "scrape with Prometheus or curl",
            host,
            port,
        )
        return server
    except OSError as exc:
        logger.warning(
            "Could not start metrics server on %s:%d — %s. "
            "Metrics will only be available via witness_metrics tool.",
            host,
            port,
            exc,
        )
        return None
