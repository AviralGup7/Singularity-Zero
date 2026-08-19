"""Container image scanning stage."""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context
from src.pipeline.services.pipeline_orchestrator.stages._tool_runner import (
    is_scanner_crash,
    run_scanner,
)

logger = get_pipeline_logger(__name__)


def _which(tool: str) -> bool:
    return shutil.which(tool) is not None


async def run_container_scan_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: Container image scanning using Trivy."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("container_scan", config, ctx)

    stage_started = time.monotonic()
    container_images = getattr(ctx.result, "container_images", None) or []
    dockerfiles = getattr(ctx.result, "dockerfiles", None) or []

    if not container_images and not dockerfiles:
        ctx.mark_stage_skipped("container_scan", reason="no_container_images_or_dockerfiles")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="container_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "no_container_images_or_dockerfiles"},
            state_delta={},
        )

    if not _which("trivy"):
        ctx.mark_stage_skipped("container_scan", reason="trivy_not_available")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="container_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "trivy_not_available"},
            state_delta={},
        )

    emit_progress("container_scan", "Running Trivy container scan", 50)

    container_findings: list[dict[str, Any]] = []
    image_vulns: list[dict[str, Any]] = []
    sbom_fragment: dict[str, Any] = {}

    def _ingest(data: Any) -> None:
        items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
        for result_item in items:
            if not isinstance(result_item, dict):
                continue
            image_name = result_item.get("Target", "") or result_item.get("ImageName", "")
            for vuln in result_item.get("Vulnerabilities", []) or []:
                image_vulns.append({"image": image_name, "vulnerability": vuln})
                container_findings.append(
                    {
                        "type": "container_vulnerability",
                        "image": image_name,
                        "vulnerability": vuln,
                    }
                )
            sbom_fragment[str(image_name)] = {
                "target": image_name,
                "vulnerabilities": result_item.get("Vulnerabilities", []),
            }

    try:
        crashed = False
        last_error = ""
        for image in container_images:
            output_file = ctx.output_store.run_dir / f"trivy_image_{abs(hash(str(image)))}.json"
            result = await run_scanner(
                [
                    "trivy",
                    "image",
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                    "--scanners",
                    "vuln,secret",
                    str(image),
                ],
                timeout=900,
            )
            if is_scanner_crash(result.returncode):
                crashed = True
                last_error = result.stderr or f"trivy image exit {result.returncode}"
                logger.warning("Trivy image scan failed for %s: %s", image, last_error)
                continue
            if output_file.exists():
                try:
                    _ingest(json.loads(output_file.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError) as exc:
                    crashed = True
                    last_error = str(exc)

        for dockerfile in dockerfiles:
            output_file = (
                ctx.output_store.run_dir / f"trivy_config_{abs(hash(str(dockerfile)))}.json"
            )
            config_target = str(Path(str(dockerfile)).parent or dockerfile)
            result = await run_scanner(
                [
                    "trivy",
                    "config",
                    "--format",
                    "json",
                    "--output",
                    str(output_file),
                    config_target,
                ],
                timeout=600,
            )
            if is_scanner_crash(result.returncode):
                crashed = True
                last_error = result.stderr or f"trivy config exit {result.returncode}"
                logger.warning("Trivy config scan failed for %s: %s", dockerfile, last_error)
                continue
            if output_file.exists():
                try:
                    _ingest(json.loads(output_file.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError) as exc:
                    crashed = True
                    last_error = str(exc)

        if crashed and not container_findings:
            ctx.mark_stage_failed("container_scan", last_error or "trivy failed")
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="container_scan",
                outcome=StageOutcome.FAILED,
                duration_seconds=duration,
                error=last_error or "trivy failed",
                metrics={"status": "error", "error": last_error},
                state_delta={},
            )

        ctx.mark_stage_complete("container_scan")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="container_scan",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "degraded" if crashed else "ok",
                "targets": len(container_images) + len(dockerfiles),
                "vulnerabilities": len(image_vulns),
            },
            state_delta={
                "container_findings": container_findings,
                "image_vulns": image_vulns,
                "sbom_fragment": sbom_fragment,
            },
        )

    except Exception as exc:
        logger.error("Container scan failed: %s", exc)
        ctx.mark_stage_failed("container_scan", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="container_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
