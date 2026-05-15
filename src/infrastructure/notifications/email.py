import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from pydantic import EmailStr, Field

from src.infrastructure.notifications.base import (
    BaseNotifier,
    NotificationConfig,
    NotificationPayload,
    NotificationResult,
)

logger = logging.getLogger(__name__)


class EmailConfig(NotificationConfig):
    smtp_host: str = Field(default="localhost")
    smtp_port: int = Field(default=587, gt=0)
    smtp_user: str = Field(default="")
    smtp_password: str = Field(default="")
    use_tls: bool = Field(default=True)
    from_address: EmailStr
    to_addresses: list[EmailStr] = Field(min_length=1)
    cc_addresses: list[EmailStr] = Field(default_factory=list)
    subject_prefix: str = Field(default="[Cyber Security Pipeline]")


class EmailNotifier(BaseNotifier):
    def __init__(self, config: EmailConfig) -> None:
        super().__init__(config, channel_name="email")
        self._email_config = config

    async def _do_send(self, payload: NotificationPayload) -> NotificationResult:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = self._build_subject(payload)
        msg["From"] = self._email_config.from_address
        msg["To"] = ", ".join(self._email_config.to_addresses)

        if self._email_config.cc_addresses:
            msg["Cc"] = ", ".join(self._email_config.cc_addresses)

        if payload.correlation_id:
            msg["X-Correlation-ID"] = payload.correlation_id

        msg["X-Priority"] = self._build_priority_header(payload)

        plain_text = self._build_plain_text(payload)
        html_body = self._build_html(payload)

        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        all_recipients = self._email_config.to_addresses + self._email_config.cc_addresses

        def _send() -> None:
            if self._email_config.use_tls:
                server = smtplib.SMTP(
                    self._email_config.smtp_host,
                    self._email_config.smtp_port,
                )
                server.starttls()
            else:
                server = smtplib.SMTP(
                    self._email_config.smtp_host,
                    self._email_config.smtp_port,
                )

            if self._email_config.smtp_user and self._email_config.smtp_password:
                server.login(
                    self._email_config.smtp_user,
                    self._email_config.smtp_password,
                )

            try:
                server.sendmail(
                    self._email_config.from_address,
                    all_recipients,
                    msg.as_string(),
                )
            finally:
                server.quit()

        import asyncio

        await asyncio.get_running_loop().run_in_executor(None, _send)

        return NotificationResult(
            success=True,
            channel=self._channel_name,
            event=payload.event.value,
            priority=payload.priority.value,
            response_data={"recipients": all_recipients},
        )

    def _build_subject(self, payload: NotificationPayload) -> str:
        priority_tag = {
            "low": "[INFO]",
            "medium": "[WARN]",
            "high": "[HIGH]",
            "critical": "[CRITICAL]",
        }.get(payload.priority.value, "")
        return f"{self._email_config.subject_prefix} {priority_tag} {payload.title}"

    def _build_plain_text(self, payload: NotificationPayload) -> str:
        lines = [
            payload.title,
            "=" * len(payload.title),
            "",
            f"Event: {payload.event.value}",
            f"Priority: {payload.priority.value.upper()}",
            f"Source: {payload.source}",
            f"Time: {payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "Message:",
            payload.message,
        ]

        if payload.correlation_id:
            lines.append("")
            lines.append(f"Correlation ID: {payload.correlation_id}")

        if self._email_config.include_metadata and payload.metadata:
            lines.append("")
            lines.append("Metadata:")
            for key, value in payload.metadata.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)

    def _build_html(self, payload: NotificationPayload) -> str:
        priority_colors = {
            "low": "#36a64f",
            "medium": "#ffcc00",
            "high": "#ff6600",
            "critical": "#ff0000",
        }
        color = priority_colors.get(payload.priority.value, "#666666")

        metadata_html = ""
        if self._email_config.include_metadata and payload.metadata:
            rows = "".join(
                f"<tr><td><code>{k}</code></td><td><code>{v}</code></td></tr>"
                for k, v in payload.metadata.items()
            )
            metadata_html = f"""
            <h3>Metadata</h3>
            <table style="border-collapse: collapse; width: 100%;">
                <tbody>{rows}</tbody>
            </table>
            """

        correlation_html = ""
        if payload.correlation_id:
            correlation_html = (
                f"<p><strong>Correlation ID:</strong> <code>{payload.correlation_id}</code></p>"
            )

        return f"""
        <html>
        <body style="font-family: Arial, sans-serif; max-width: 600px;">
            <div style="border-left: 4px solid {color}; padding: 12px; background: #f9f9f9;">
                <h2 style="margin-top: 0; color: {color};">{payload.title}</h2>
                <table style="border-collapse: collapse;">
                    <tr>
                        <td><strong>Event:</strong></td>
                        <td>{payload.event.value}</td>
                    </tr>
                    <tr>
                        <td><strong>Priority:</strong></td>
                        <td><span style="color: {color}; font-weight: bold;">
                            {payload.priority.value.upper()}
                        </span></td>
                    </tr>
                    <tr>
                        <td><strong>Source:</strong></td>
                        <td>{payload.source}</td>
                    </tr>
                    <tr>
                        <td><strong>Time:</strong></td>
                        <td>{payload.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}</td>
                    </tr>
                </table>
                <h3>Message</h3>
                <p>{payload.message}</p>
                {correlation_html}
                {metadata_html}
            </div>
            <p style="color: #999; font-size: 12px; margin-top: 20px;">
                {payload.source} | {payload.timestamp.isoformat()}
            </p>
        </body>
        </html>
        """

    def _build_priority_header(self, payload: NotificationPayload) -> str:
        return {
            "low": "5",
            "medium": "3",
            "high": "1",
            "critical": "1",
        }.get(payload.priority.value, "3")

    async def close(self) -> None:
        pass
