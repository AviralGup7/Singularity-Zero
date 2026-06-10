"""Report distribution stage.

Sends the generated ``report.html`` (and an optional ``attestation.pdf``
when present) to a configured distribution list once the pipeline
reaches ``PIPELINE_COMPLETE``.  Gated by ``[distribution] enabled =
true`` in the pipeline config; default off so existing deployments
keep their plain-text :class:`NotificationManager` behaviour.

The stage is deliberately tiny and idempotent: a re-run on the same
artefacts emits the same emails.  No state is mutated outside the
report run directory.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline_runtime import StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress

logger = get_pipeline_logger(__name__)


@dataclass(frozen=True, slots=True)
class DistributionRecord:
    """Per-recipient distribution outcome."""

    recipient: str
    ok: bool
    error: str = ""
    attachments: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "recipient": self.recipient,
            "ok": self.ok,
            "error": self.error,
            "attachments": list(self.attachments),
        }


@dataclass(slots=True)
class ReportDistributor:
    """Sends the run report to a configured list of recipients.

    Attributes:
        enabled: Master switch.  When ``False`` the stage SKIPs
            without sending.
        smtp_host: SMTP server hostname.
        smtp_port: SMTP server port.
        smtp_user: Optional SMTP username.
        smtp_password: Optional SMTP password.
        use_tls: Whether to start TLS.
        from_address: Sender email address.
        to_addresses: Recipients (to).
        cc_addresses: Recipients (cc).
        subject_prefix: Prepended to the email subject line.
        attachment_filenames: Report artefact filenames to attach.
            Resolved relative to ``run_dir`` when an entry is not
            absolute.  Files that do not exist are silently skipped.
    """

    enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    use_tls: bool = True
    from_address: str = ""
    to_addresses: tuple[str, ...] = ()
    cc_addresses: tuple[str, ...] = ()
    subject_prefix: str = "[Cyber Security Pipeline] Run report"
    attachment_filenames: tuple[str, ...] = (
        "report.html",
        "report.json",
        "attestation.pdf",
    )
    smtp_timeout_seconds: float = 30.0
    max_attachment_bytes: int = 25 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.smtp_port <= 0:
            raise ValueError("smtp_port must be > 0")
        if self.smtp_timeout_seconds <= 0:
            raise ValueError("smtp_timeout_seconds must be > 0")
        if self.max_attachment_bytes <= 0:
            raise ValueError("max_attachment_bytes must be > 0")
        if self.enabled and not self.from_address:
            raise ValueError("from_address is required when distribution is enabled")
        if self.enabled and not self.to_addresses:
            raise ValueError("to_addresses must not be empty when distribution is enabled")

    @classmethod
    def from_config(cls, config: Any) -> ReportDistributor:
        section: Any = None
        if config is None:
            section = None
        elif isinstance(config, Mapping):
            section = config.get("distribution")
        else:
            section = getattr(config, "distribution", None)

        if not section:
            return cls(enabled=False)

        if isinstance(section, Mapping):
            block = dict(section)
        else:
            try:
                block = {
                    "enabled": bool(getattr(section, "enabled", False)),
                    "smtp_host": str(getattr(section, "smtp_host", "localhost")),
                    "smtp_port": int(getattr(section, "smtp_port", 587)),
                    "smtp_user": str(getattr(section, "smtp_user", "")),
                    "smtp_password": str(getattr(section, "smtp_password", "")),
                    "use_tls": bool(getattr(section, "use_tls", True)),
                    "from_address": str(getattr(section, "from_address", "")),
                    "to_addresses": tuple(getattr(section, "to_addresses", ()) or ()),
                    "cc_addresses": tuple(getattr(section, "cc_addresses", ()) or ()),
                    "subject_prefix": str(
                        getattr(section, "subject_prefix", "[Cyber Security Pipeline] Run report")
                    ),
                    "attachment_filenames": tuple(
                        getattr(section, "attachment_filenames", ())
                        or ("report.html", "report.json", "attestation.pdf")
                    ),
                    "smtp_timeout_seconds": float(getattr(section, "smtp_timeout_seconds", 30.0)),
                    "max_attachment_bytes": int(
                        getattr(section, "max_attachment_bytes", 25 * 1024 * 1024)
                    ),
                }
            except AttributeError:
                return cls(enabled=False)

        try:
            return cls(
                enabled=bool(block.get("enabled", False)),
                smtp_host=str(block.get("smtp_host", "localhost")),
                smtp_port=int(block.get("smtp_port", 587)),
                smtp_user=str(block.get("smtp_user", "")),
                smtp_password=str(
                    block.get("smtp_password") or os.environ.get("DISTRIBUTION_SMTP_PASSWORD", "")
                ),
                use_tls=bool(block.get("use_tls", True)),
                from_address=str(
                    block.get("from_address") or os.environ.get("DISTRIBUTION_FROM", "")
                ),
                to_addresses=tuple(block.get("to_addresses", ()) or ()),
                cc_addresses=tuple(block.get("cc_addresses", ()) or ()),
                subject_prefix=str(
                    block.get(
                        "subject_prefix",
                        "[Cyber Security Pipeline] Run report",
                    )
                ),
                attachment_filenames=tuple(
                    block.get(
                        "attachment_filenames",
                        ("report.html", "report.json", "attestation.pdf"),
                    )
                ),
                smtp_timeout_seconds=float(block.get("smtp_timeout_seconds", 30.0)),
                max_attachment_bytes=int(block.get("max_attachment_bytes", 25 * 1024 * 1024)),
            )
        except (TypeError, ValueError) as exc:
            logger.warning("Invalid distribution config, defaulting to disabled: %s", exc)
            return cls(enabled=False)

    def resolve_attachments(self, run_dir: Path | None) -> list[Path]:
        if run_dir is None:
            return []
        resolved: list[Path] = []
        for name in self.attachment_filenames:
            if not name:
                continue
            path = Path(name)
            if not path.is_absolute():
                path = run_dir / name
            try:
                if path.is_file() and path.stat().st_size <= self.max_attachment_bytes:
                    resolved.append(path)
            except OSError:
                continue
        return resolved

    async def send(
        self, run_dir: Path | None, *, target_name: str, run_name: str
    ) -> list[DistributionRecord]:
        if not self.enabled:
            return []
        attachments = self.resolve_attachments(run_dir)
        try:
            from src.infrastructure.notifications.base import (
                EventType,
                NotificationPayload,
                Priority,
            )
            from src.infrastructure.notifications.email import EmailConfig, EmailNotifier
        except Exception as exc:  # noqa: BLE001
            logger.warning("Email infrastructure unavailable: %s", exc)
            return [
                DistributionRecord(
                    recipient=addr,
                    ok=False,
                    error=f"email infrastructure unavailable: {exc}",
                )
                for addr in self.to_addresses
            ]

        config = EmailConfig(
            smtp_host=self.smtp_host,
            smtp_port=self.smtp_port,
            smtp_user=self.smtp_user,
            smtp_password=self.smtp_password,
            use_tls=self.use_tls,
            from_address=self.from_address,
            to_addresses=list(self.to_addresses),
            cc_addresses=list(self.cc_addresses),
            subject_prefix=self.subject_prefix,
            smtp_timeout_seconds=self.smtp_timeout_seconds,
            max_attachment_bytes=self.max_attachment_bytes,
        )
        notifier = EmailNotifier(config)
        try:
            payload = NotificationPayload(
                event=EventType.PIPELINE_COMPLETE,
                priority=Priority.MEDIUM,
                title=f"Run report: {target_name} / {run_name}",
                message=(
                    f"Pipeline run completed for target '{target_name}' (run '{run_name}'). "
                    "The run artefacts are attached."
                ),
                source="report_distributor",
                correlation_id=run_name,
                metadata={
                    "attachments": [str(p) for p in attachments],
                    "target": target_name,
                    "run": run_name,
                },
            )
            result = await notifier.send(payload)
        finally:
            try:
                await notifier.close()
            except Exception:  # noqa: BLE001
                pass

        return [
            DistributionRecord(
                recipient=addr,
                ok=bool(result.success) if result is not None else False,
                error=str(getattr(result, "error", "")),
                attachments=tuple(str(p) for p in attachments),
            )
            for addr in self.to_addresses
        ]


def _summary_block(records: Iterable[DistributionRecord]) -> dict[str, Any]:
    rows = [r.to_dict() for r in records]
    return {
        "total": len(rows),
        "delivered": sum(1 for r in rows if r["ok"]),
        "failed": sum(1 for r in rows if not r["ok"]),
        "records": rows,
    }


async def run_report_distribution(
    args: Any,
    config: Any,
    ctx: PipelineContext,
) -> StageOutput:
    """Stage: distribute the run report to the configured recipient list."""
    stage_started = time.monotonic()
    state_delta: dict[str, Any] = {
        "module_metrics": {},
        "distribution_summary": {},
    }

    try:
        emit_progress("report_distribution", "Distributing run report", 98)

        distributor = ReportDistributor.from_config(config)
        if not distributor.enabled:
            logger.info("Report distribution disabled by config")
            state_delta["module_metrics"]["report_distribution"] = {
                "status": "skipped",
                "reason": "disabled_in_config",
                "duration_seconds": round(time.monotonic() - stage_started, 2),
            }
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="report_distribution",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics=state_delta["module_metrics"]["report_distribution"],
                state_delta=state_delta,
            )

        try:
            run_dir = Path(ctx.output_store.run_dir)
        except (AttributeError, TypeError):
            run_dir = None

        try:
            target_name = str(getattr(config, "target_name", ""))
        except (AttributeError, TypeError):
            target_name = ""

        run_name = (
            run_dir.name if run_dir is not None else datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        )
        records = await distributor.send(run_dir, target_name=target_name, run_name=run_name)
        summary = _summary_block(records)
        state_delta["distribution_summary"] = summary

        if run_dir is not None:
            try:
                (run_dir / "distribution_report.json").write_text(
                    _json_dumps(summary),
                    encoding="utf-8",
                )
            except OSError as exc:
                logger.warning("Failed to write distribution_report.json: %s", exc)

        metrics = {
            "status": "ok" if summary["delivered"] == summary["total"] else "degraded",
            "duration_seconds": round(time.monotonic() - stage_started, 2),
            **summary,
        }
        state_delta["module_metrics"]["report_distribution"] = metrics

        if metrics["status"] == "degraded":
            logger.warning(
                "Report distribution: %d/%d deliveries failed",
                summary["failed"],
                summary["total"],
            )

        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="report_distribution",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics=metrics,
            state_delta=state_delta,
        )

    except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
        logger.error("Stage 'report_distribution' failed: %s", exc)
        ctx.mark_stage_failed("report_distribution", str(exc))
        return StageOutput(
            stage_name="report_distribution",
            outcome=StageOutcome.FAILED,
            duration_seconds=round(time.monotonic() - stage_started, 2),
            error=str(exc),
            reason="report_distribution_exception",
            metrics={"status": "error", "error": str(exc)},
            state_delta={
                "module_metrics": {
                    "report_distribution": {
                        "status": "error",
                        "error": str(exc),
                    }
                },
                "distribution_summary": {},
            },
        )


def _json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, indent=2, default=str)


__all__ = [
    "DistributionRecord",
    "ReportDistributor",
    "run_report_distribution",
]
