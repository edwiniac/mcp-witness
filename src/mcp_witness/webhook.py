"""
Webhook notification for mcp-witness chain failures.

When chain verification finds issues, optionally POST the verification result
to a configured webhook URL (e.g., Slack, Discord, or custom endpoint).

Configure via MCP_WITNESS_WEBHOOK_URL env var.

Slack alerts can be configured separately via MCP_WITNESS_SLACK_WEBHOOK_URL.
"""

import logging
import os
from datetime import datetime
from typing import Optional

import httpx

from .models import VerificationResult
from .security import validate_external_url

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

    try:
        validate_external_url(WEBHOOK_URL)
    except ValueError as exc:
        logger.warning("Refusing to send webhook (SSRF guard): %s", exc)
        return False

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


class SlackNotifier:
    """Send formatted alerts to a Slack webhook.

    Configure via MCP_WITNESS_SLACK_WEBHOOK_URL env var.
    Supports severity levels: critical, warning, info.

    Usage:
        notifier = SlackNotifier()
        await notifier.send_alert("Chain break", "Details...", severity="critical")
    """

    def __init__(self, webhook_url: Optional[str] = None):
        self._url = webhook_url or os.getenv("MCP_WITNESS_SLACK_WEBHOOK_URL", "").strip()

    def is_configured(self) -> bool:
        """Check if a Slack webhook URL is configured."""
        return bool(self._url)

    async def send_alert(
        self,
        title: str,
        text: str,
        severity: str = "warning",
    ) -> bool:
        """Send a formatted alert to Slack.

        Args:
            title: Alert title (bold header)
            text: Alert body text
            severity: One of "critical", "warning", "info"

        Returns:
            True if the alert was sent successfully.
        """
        if not self._url:
            logger.debug("Slack webhook URL not configured. Skipping alert.")
            return False

        try:
            validate_external_url(self._url)
        except ValueError as exc:
            logger.warning("Refusing to send Slack alert (SSRF guard): %s", exc)
            return False

        color = {
            "critical": "#FF0000",
            "warning": "#FFA500",
            "info": "#0000FF",
        }.get(severity, "#808080")

        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": title,
                    "text": text,
                    "footer": "mcp-witness",
                    "ts": int(datetime.now().timestamp()),
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    self._url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "mcp-witness-slack/1.0",
                    },
                )
            if resp.is_success:
                logger.info("Slack alert sent successfully (status=%d)", resp.status_code)
                return True
            else:
                logger.warning(
                    "Slack alert returned status %d: %s",
                    resp.status_code,
                    resp.text[:200],
                )
                return False
        except httpx.TimeoutException:
            logger.warning("Slack alert request timed out after 30s")
            return False
        except httpx.RequestError as e:
            logger.warning("Slack alert request failed: %s", e)
            return False
        except Exception as e:
            logger.warning("Slack alert error: %s", e, exc_info=True)
            return False

    async def send_chain_failure_alert(
        self,
        result: VerificationResult,
        context: Optional[dict] = None,
    ) -> bool:
        """Send a formatted chain failure alert to Slack.

        Builds a human-readable alert from a VerificationResult.

        Args:
            result: The chain verification result
            context: Optional context dict (e.g., db_path, hostname)

        Returns:
            True if the alert was sent successfully.
        """
        ctx_str = f"\nContext: {context}" if context else ""
        issues_summary = "\n".join(result.issues[:5])  # Top 5 issues
        if len(result.issues) > 5:
            issues_summary += f"\n... and {len(result.issues) - 5} more issues"

        text = (
            f"*Records checked:* {result.records_checked}\n"
            f"*Issues found:* {len(result.issues)}\n"
            f"*First invalid sequence:* {result.first_invalid_sequence}\n"
            f"*Verified at:* {result.verified_at.isoformat()}{ctx_str}\n\n"
            f"*Issues:*\n{issues_summary}"
        )

        return await self.send_alert(
            title="🚨 Chain Break Detected — mcp-witness",
            text=text,
            severity="critical",
        )


async def notify_chain_failure_slack(
    result: VerificationResult,
    context: Optional[dict] = None,
) -> bool:
    """Convenience function to send a chain failure alert to Slack.

    Creates a SlackNotifier from the environment and sends
    the formatted alert.

    Args:
        result: The chain verification result
        context: Optional context dict

    Returns:
        True if the alert was sent successfully.
    """
    notifier = SlackNotifier()
    if not notifier.is_configured():
        logger.debug("Slack webhook not configured, skipping chain failure alert")
        return False
    return await notifier.send_chain_failure_alert(result, context)
