"""Notification service for pipeline completion webhooks.

Sends POST webhook notifications to Slack, MS Teams, Discord, or generic
endpoints when a pipeline run completes. Notifications are fire-and-forget
and will never break the pipeline on failure.
"""

import json
import time
from typing import Any
from urllib.parse import urlparse

import requests  # type: ignore

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)

_WEBHOOK_TIMEOUT = 15
_MAX_RETRIES = 2


def send_webhook(url: str, payload: dict[str, Any]) -> bool:
    """Send a POST request to the webhook URL with JSON payload.

    Args:
        url: The webhook endpoint URL.
        payload: The JSON-serialisable payload to send.

    Returns:
        True if the request succeeded, False otherwise.
    """
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "security-pipeline/1.0"}

    for attempt in range(1, _MAX_RETRIES + 1):
        # Validate webhook URL to avoid unexpected schemes (file:, data:, etc.)
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            logger.warning("Webhook URL has unsupported scheme or missing host: %s", url)
            return False

        try:
            resp = requests.post(url, data=data, headers=headers, timeout=_WEBHOOK_TIMEOUT)
            if resp.status_code in (200, 201, 204):
                logger.info("Webhook sent successfully to %s", url)
                return True
            logger.warning("Webhook returned unexpected status %d from %s", resp.status_code, url)
        except requests.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", "N/A")
            logger.warning(
                "Webhook HTTP error %s on attempt %d/%d for %s: %s",
                status,
                attempt,
                _MAX_RETRIES,
                url,
                exc,
            )
        except (requests.RequestException, OSError, TimeoutError) as exc:
            logger.warning(
                "Webhook network error on attempt %d/%d for %s: %s",
                attempt,
                _MAX_RETRIES,
                url,
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Webhook unexpected error on attempt %d/%d for %s: %s",
                attempt,
                _MAX_RETRIES,
                url,
                exc,
            )

        if attempt < _MAX_RETRIES:
            time.sleep(1.0)

    logger.error("Webhook failed after %d attempts for %s", _MAX_RETRIES, url)
    return False


def _format_slack_payload(notification: dict[str, Any]) -> dict[str, Any]:
    """Format the notification payload for Slack incoming webhook."""
    severity = notification.get("severity", "unknown")
    color = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffcc00",
        "low": "#00ccff",
        "info": "#00cc00",
    }.get(severity, "#888888")

    status_emoji = ":white_check_mark:" if notification.get("status") == "success" else ":x:"
    fields = [
        {"title": "Duration", "value": notification.get("duration", "N/A"), "short": True},
        {
            "title": "Findings",
            "value": notification.get("total_findings", 0),
            "short": True,
        },
    ]

    finding_summary = notification.get("finding_summary")
    if finding_summary:
        for sev in ("critical", "high", "medium", "low", "info"):
            count = finding_summary.get(sev, 0)
            if count > 0:
                fields.append({"title": sev.capitalize(), "value": count, "short": True})

    report_link = notification.get("report_link")
    if report_link:
        fields.append({"title": "Report", "value": f"<{report_link}|View Report>", "short": False})

    return {
        "attachments": [
            {
                "color": color,
                "title": f"{status_emoji} Pipeline Run: {notification.get('target', 'Unknown')}",
                "fields": fields,
                "footer": "Security Test Pipeline",
                "ts": int(time.time()),
            }
        ]
    }


def _format_msteams_payload(notification: dict[str, Any]) -> dict[str, Any]:
    """Format the notification payload for MS Teams incoming webhook."""
    severity = notification.get("severity", "unknown")
    theme_color = {
        "critical": "FF0000",
        "high": "FF6600",
        "medium": "FFCC00",
        "low": "00CCFF",
        "info": "00CC00",
    }.get(severity, "888888")

    status_text = "Succeeded" if notification.get("status") == "success" else "Failed"
    facts = [
        {"name": "Duration", "value": notification.get("duration", "N/A")},
        {"name": "Total Findings", "value": str(notification.get("total_findings", 0))},
    ]

    finding_summary = notification.get("finding_summary")
    if finding_summary:
        for sev in ("critical", "high", "medium", "low", "info"):
            count = finding_summary.get(sev, 0)
            if count > 0:
                facts.append({"name": sev.capitalize(), "value": str(count)})

    report_link = notification.get("report_link")
    if report_link:
        facts.append({"name": "Report", "value": f"[View Report]({report_link})"})

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Pipeline {status_text}: {notification.get('target', 'Unknown')}",
        "sections": [
            {
                "activityTitle": f"Pipeline {status_text}: {notification.get('target', 'Unknown')}",
                "facts": facts,
            }
        ],
    }


def _format_discord_payload(notification: dict[str, Any]) -> dict[str, Any]:
    """Format the notification payload for Discord incoming webhook."""
    severity = notification.get("severity", "unknown")
    color = {
        "critical": 0xFF0000,
        "high": 0xFF6600,
        "medium": 0xFFCC00,
        "low": 0x00CCFF,
        "info": 0x00CC00,
    }.get(severity, 0x888888)

    status_emoji = "\u2705" if notification.get("status") == "success" else "\u274c"
    fields = [
        {"name": "Duration", "value": notification.get("duration", "N/A"), "inline": True},
        {
            "name": "Total Findings",
            "value": str(notification.get("total_findings", 0)),
            "inline": True,
        },
    ]

    finding_summary = notification.get("finding_summary")
    if finding_summary:
        for sev in ("critical", "high", "medium", "low", "info"):
            count = finding_summary.get(sev, 0)
            if count > 0:
                fields.append({"name": sev.capitalize(), "value": str(count), "inline": True})

    embed = {
        "title": f"{status_emoji} Pipeline Run: {notification.get('target', 'Unknown')}",
        "color": color,
        "fields": fields,
        "footer": {"text": "Security Test Pipeline"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    report_link = notification.get("report_link")
    if report_link:
        embed["url"] = report_link

    return {"embeds": [embed]}


def _detect_webhook_type(url: str, config_type: str) -> str:
    """Detect the webhook type from URL pattern or config flag.

    Args:
        url: The webhook URL.
        config_type: The type specified in config.

    Returns:
        One of 'slack', 'msteams', 'discord', or 'generic'.
    """
    if config_type and config_type != "generic":
        return config_type.lower()

    url_lower = url.lower()
    if "hooks.slack.com" in url_lower or "slack.com/services" in url_lower:
        return "slack"
    if "discord.com/api/webhooks" in url_lower or "discordapp.com/api/webhooks" in url_lower:
        return "discord"
    if "webhook.office.com" in url_lower or "outlook.office.com/webhook" in url_lower:
        return "msteams"
    return "generic"


def build_notification_payload(summary: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Build a compact notification payload from a pipeline summary.

    Args:
        summary: The pipeline summary dict produced by build_summary().
        config: The full pipeline configuration dict.

    Returns:
        A dict with target, status, severity, duration, finding counts,
        and optional report link.
    """
    target = summary.get("target_name", config.get("target_name", "Unknown"))
    findings = summary.get("findings", [])

    severity_counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = len(findings)
    if severity_counts.get("critical", 0) > 0:
        overall_severity = "critical"
    elif severity_counts.get("high", 0) > 0:
        overall_severity = "high"
    elif severity_counts.get("medium", 0) > 0:
        overall_severity = "medium"
    elif severity_counts.get("low", 0) > 0:
        overall_severity = "low"
    else:
        overall_severity = "info"

    metrics = summary.get("metrics", {})
    duration_seconds = metrics.get("duration_seconds", 0)
    hours = int(duration_seconds // 3600)
    minutes = int((duration_seconds % 3600) // 60)
    seconds = int(duration_seconds % 60)
    if hours > 0:
        duration_str = f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        duration_str = f"{minutes}m {seconds}s"
    else:
        duration_str = f"{seconds}s"

    run_dir = summary.get("run_dir", "")
    report_link = ""
    if run_dir:
        report_link = str(run_dir)
        if not report_link.startswith(("http://", "https://")):
            report_link = f"file://{report_link}/report.html"

    payload: dict[str, Any] = {
        "target": target,
        "status": summary.get("status", "success"),
        "severity": overall_severity,
        "total_findings": total,
        "duration": duration_str,
        "duration_seconds": duration_seconds,
    }

    include_summary = config.get("notifications", {}).get("include_finding_summary", True)
    if include_summary and severity_counts:
        payload["finding_summary"] = severity_counts

    if report_link:
        payload["report_link"] = report_link

    return payload


def notify_on_completion(summary: dict[str, Any], config: dict[str, Any]) -> bool:
    """Send webhook notification on pipeline completion.

    Reads webhook URLs from config, builds the notification payload,
    and sends it to each configured endpoint. Failures are logged but
    never raised.

    Args:
        summary: The pipeline summary dict.
        config: The full pipeline configuration dict.

    Returns:
        True if at least one webhook was sent successfully, False otherwise.
    """
    notifications = config.get("notifications", {})
    if not notifications:
        return False

    webhook_urls = notifications.get("webhook_urls", [])
    webhook_url = notifications.get("webhook_url", "")
    if webhook_url and isinstance(webhook_url, str):
        webhook_urls = [webhook_url] if not webhook_urls else webhook_urls
    if not webhook_urls:
        return False

    pipeline_status = summary.get("status", "success")
    notify_on_success = notifications.get("notify_on_success", True)
    notify_on_failure = notifications.get("notify_on_failure", True)

    if pipeline_status == "success" and not notify_on_success:
        return False
    if pipeline_status != "success" and not notify_on_failure:
        return False

    notification_payload = build_notification_payload(summary, config)
    any_sent = False

    for url in webhook_urls:
        webhook_type = _detect_webhook_type(url, notifications.get("webhook_type", "generic"))
        if webhook_type == "slack":
            formatted = _format_slack_payload(notification_payload)
        elif webhook_type == "msteams":
            formatted = _format_msteams_payload(notification_payload)
        elif webhook_type == "discord":
            formatted = _format_discord_payload(notification_payload)
        else:
            formatted = notification_payload
        if send_webhook(url, formatted):
            any_sent = True
    return any_sent
