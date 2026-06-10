import asyncio
import logging
import mimetypes
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

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
    smtp_timeout_seconds: float = Field(default=30.0, gt=0)
    max_attachment_bytes: int = Field(default=25 * 1024 * 1024, gt=0)


class EmailNotifier(BaseNotifier):
    def __init__(self, config: EmailConfig) -> None:
        super().__init__(config, channel_name="email")
        self._email_config = config

    async def _do_send(self, payload: NotificationPayload) -> NotificationResult:
        attachment_paths = self._resolve_attachments(payload)
        msg: MIMEMultipart
        if attachment_paths:
            msg = MIMEMultipart("mixed")
        else:
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

        if attachment_paths:
            body = MIMEMultipart("alternative")
            body.attach(MIMEText(plain_text, "plain", "utf-8"))
            body.attach(MIMEText(html_body, "html", "utf-8"))
            msg.attach(body)
        else:
            msg.attach(MIMEText(plain_text, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        for attachment_path in attachment_paths:
            attachment = self._build_attachment(attachment_path)
            if attachment is not None:
                msg.attach(attachment)

        all_recipients = self._email_config.to_addresses + self._email_config.cc_addresses

        response_data: dict[str, Any] = {"recipients": all_recipients}
        if attachment_paths:
            response_data["attachments"] = [str(p) for p in attachment_paths]

        def _send() -> None:
            server: smtplib.SMTP | None = None
            try:
                server = smtplib.SMTP(
                    self._email_config.smtp_host,
                    self._email_config.smtp_port,
                    timeout=self._email_config.smtp_timeout_seconds,
                )
                if self._email_config.use_tls:
                    server.starttls()
                    if self._email_config.smtp_user and self._email_config.smtp_password:
                        server.ehlo()
                else:
                    server.ehlo()

                if self._email_config.smtp_user and self._email_config.smtp_password:
                    server.login(
                        self._email_config.smtp_user,
                        self._email_config.smtp_password,
                    )

                server.sendmail(
                    self._email_config.from_address,
                    all_recipients,
                    msg.as_string(),
                )
            finally:
                if server is not None:
                    try:
                        server.quit()
                    except (smtplib.SMTPException, OSError) as exc:
                        logger.warning("Operation failed in email.py: %s", exc, exc_info=True)  # noqa: BLE001

        await asyncio.get_running_loop().run_in_executor(None, _send)

        return NotificationResult(
            success=True,
            channel=self._channel_name,
            event=payload.event.value,
            priority=payload.priority.value,
            response_data=response_data,
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

    def _resolve_attachments(self, payload: NotificationPayload) -> list[Path]:
        """Return the attachment paths declared in ``payload.metadata``.

        Supported keys (in priority order):

        * ``attachments`` — list of string paths
        * ``attachment``   — single string path

        Paths that do not exist or exceed :attr:`max_attachment_bytes`
        are silently dropped and logged — the email still goes out with
        whatever attachments did pass validation.
        """
        metadata = payload.metadata or {}
        candidates: list[Any] = []
        if isinstance(metadata, dict):
            if isinstance(metadata.get("attachments"), (list, tuple)):
                candidates.extend(metadata["attachments"])
            elif isinstance(metadata.get("attachment"), str):
                candidates.append(metadata["attachment"])
        paths: list[Path] = []
        for raw in candidates:
            if not raw:
                continue
            path = Path(str(raw))
            if not path.is_file():
                logger.debug("Attachment dropped (missing): %s", path)
                continue
            try:
                size = path.stat().st_size
            except OSError as exc:
                logger.debug("Attachment dropped (stat failed): %s (%s)", path, exc)
                continue
            if size > self._email_config.max_attachment_bytes:
                logger.warning(
                    "Attachment dropped (exceeds %d bytes): %s",
                    self._email_config.max_attachment_bytes,
                    path,
                )
                continue
            paths.append(path)
        return paths

    def _build_attachment(self, path: Path) -> MIMEApplication | None:
        try:
            data = path.read_bytes()
        except OSError as exc:
            logger.warning("Attachment read failed for %s: %s", path, exc)
            return None
        mime_type, _ = mimetypes.guess_type(path.name)
        if mime_type:
            maintype, subtype = mime_type.split("/", 1)
        else:
            _maintype, subtype = "application", "octet-stream"
        attachment = MIMEApplication(data, _subtype=subtype)
        attachment.add_header(
            "Content-Disposition",
            "attachment",
            filename=path.name,
        )
        return attachment

    async def close(self) -> None:
        """Close the email notifier (no persistent resources to clean up)."""
        logger.debug("Email notifier closed")
