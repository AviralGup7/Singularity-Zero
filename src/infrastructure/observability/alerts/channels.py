"""Alert notification channel implementations.

Provides channel send logic for webhook, email, and Slack.
"""

from __future__ import annotations

from src.infrastructure.observability.alerts.models import Alert, AlertChannel, ChannelType


async def send_alert(channel: AlertChannel, alert: Alert) -> bool:
    """Send an alert through a channel.

    Args:
        channel: The channel to send through.
        alert: The alert to send.

    Returns:
        True if the alert was sent successfully.
    """
    if not channel.enabled:
        return False

    match channel.channel_type:
        case ChannelType.WEBHOOK:
            return await _send_webhook(channel, alert)
        case ChannelType.EMAIL:
            return await _send_channel(channel, alert)  # email helper
        case ChannelType.SLACK:
            return await _send_slack(channel, alert)
        case _:
            return False


async def _send_webhook(channel: AlertChannel, alert: Alert) -> bool:
    """Send alert via HTTP webhook."""
    url = channel.config.get("url", "")
    if not url:
        return False
    try:
        import httpx

        payload = alert.to_dict()
        headers = {}
        auth = channel.config.get("auth_header")
        if auth:
            headers["Authorization"] = auth
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            return response.status_code < 400
    except Exception:
        return False


async def _send_channel(channel: AlertChannel, alert: Alert) -> bool:
    """Send alert via email."""
    recipients = channel.config.get("recipients", "")
    if not recipients:
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText

        smtp_host = channel.config.get("smtp_host", "localhost")
        smtp_port = int(channel.config.get("smtp_port", "587"))
        sender = channel.config.get("sender", "alerts@pipeline.local")
        password = channel.config.get("password", "")

        msg = MIMEText(
            f"Alert: {alert.name}\nSeverity: {alert.severity.value}\n"
            f"Message: {alert.message}\nValue: {alert.value}\n"
            f"Threshold: {alert.threshold}",
        )
        msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.name}"
        msg["From"] = sender
        msg["To"] = recipients

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if password:
                server.starttls()
                server.login(sender, password)
            server.sendmail(sender, recipients.split(","), msg.as_string())
        return True
    except Exception:
        return False


async def _send_slack(channel: AlertChannel, alert: Alert) -> bool:
    """Send alert via Slack webhook."""
    url = channel.config.get("webhook_url", "")
    if not url:
        return False
    try:
        import httpx

        color = {"critical": "#ff0000", "warning": "#ffaa00", "info": "#00aa00"}.get(
            alert.severity.value, "#888888"
        )
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"{alert.severity.value.upper()}: {alert.name}",
                    "text": alert.message,
                    "fields": [
                        {"title": "Value", "value": str(alert.value), "short": True},
                        {"title": "Threshold", "value": str(alert.threshold), "short": True},
                    ],
                    "footer": "Cyber Security Pipeline",
                    "ts": int(alert.last_fired),
                }
            ]
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            return response.status_code < 400
    except Exception:
        return False
