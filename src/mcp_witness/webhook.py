"""
Webhook notification for mcp-witness chain failures.

When chain verification finds issues, optionally POST the verification result
to a configured webhook URL (e.g., Slack, Discord, or custom endpoint).

Configure via MCP_WITNESS_WEBHOOK_URL env var.
"""

import logging
import os
from typing import Optional

import httpx

from .models import VerificationResult

logger = logging.getLogger(__name__)

# Webhook URL from environment
WEBHOOK_URL = os.getenv("MCP_WITNESS_WEBHOOK_URL", "").strip()


def is_webhook_configured() -> bool:
    """Check if a webhook URL is configured."""
    return bool(WEBHOOK_URL)


async def notify_chain_failure(
    result: VerificationResult,
    context: Optional[dict] = None,
) -> bool:
    """
    Send chain failure notification to configured webhook.

    If MCP_WITNESS_WEBHOOK_URL is not set, this is a no-op.
    Failures are logged as warnings but don't crash the caller.

    Args:
        result: The VerificationResult from verify_chain() or verify_chain_fast()
        context: Optional additional context dict (e.g., db_path, hostname)

    Returns:
        True if webhook was successfully notified, False otherwise.
        Returns True (no-op) if webhook URL is not configured.
    """
    if not WEBHOOK_URL:
        logger.debug("Webhook URL not configured. Skipping notification.")
        return True

    payload = {
        "event": "chain_failure",
        "severity": "warning",
        "records_checked": result.records_checked,
        "issues": result.issues,
        "verified_at": result.verified_at.isoformat(),
        "context": context or {},
    }

    logger.info(
        "Sending chain failure notification to webhook (%d issues)",
        len(result.issues),
    )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                WEBHOOK_URL,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "mcp-witness-webhook/1.0",
                },
            )

        if response.is_success:
            logger.info("Webhook notification sent successfully (status=%d)", response.status_code)
            return True
        else:
            logger.warning(
                "Webhook returned non-success status: %d %s",
                response.status_code,
                response.text[:200],
            )
            return False

    except httpx.TimeoutException:
        logger.warning("Webhook request timed out after 30s")
        return False
    except httpx.RequestError as e:
        logger.warning("Webhook request failed: %s", e)
        return False
    except Exception as e:
        logger.warning("Webhook notification error: %s", e, exc_info=True)
        return False
