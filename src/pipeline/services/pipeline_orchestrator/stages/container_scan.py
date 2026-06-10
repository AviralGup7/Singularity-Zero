"""Container image scanning stage."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

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

    try:
        targets: list[str] = []
        for image in container_images:
            targets.append(str(image))
        for dockerfile in dockerfiles:
            targets.append(str(dockerfile))

        output_file = ctx.output_store.run_dir / "container_scan.json"
        cmd = [
            "trivy",
            "image",
            "--format",
            "json",
            "--output",
            str(output_file),
            "--scanners",
            "vuln,secret,config",
        ]
        for target in targets:
            cmd.append(target)

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("Trivy exited with code %d: %s", result.returncode, result.stderr)

        if output_file.exists():
            try:
                data = json.loads(output_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for result_item in data:
                        if not isinstance(result_item, dict):
                            continue
                        image_name = result_item.get("Target", "") or result_item.get(
                            "ImageName", ""
                        )
                        for vuln in result_item.get("Vulnerabilities", []) or []:
                            image_vulns.append(
                                {
                                    "image": image_name,
                                    "vulnerability": vuln,
                                }
                            )
                            container_findings.append(
                                {
                                    "type": "container_vulnerability",
                                    "image": image_name,
                                    "vulnerability": vuln,
                                }
                            )
                        sbom_fragment[image_name] = {
                            "target": image_name,
                            "vulnerabilities": result_item.get("Vulnerabilities", []),
                        }
                elif isinstance(data, dict):
                    image_name = data.get("Target", "") or data.get("ImageName", "")
                    for vuln in data.get("Vulnerabilities", []) or []:
                        image_vulns.append(
                            {
                                "image": image_name,
                                "vulnerability": vuln,
                            }
                        )
                        container_findings.append(
                            {
                                "type": "container_vulnerability",
                                "image": image_name,
                                "vulnerability": vuln,
                            }
                        )
                    sbom_fragment[image_name] = {
                        "target": image_name,
                        "vulnerabilities": data.get("Vulnerabilities", []),
                    }
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to parse container scan output: %s", exc)

        ctx.mark_stage_complete("container_scan")
        duration = round(time.monotonic() - stage_started, 2)
        state_delta = {
            "container_findings": container_findings,
            "image_vulns": image_vulns,
            "sbom_fragment": sbom_fragment,
        }
        return StageOutput(
            stage_name="container_scan",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "targets": len(targets),
                "vulnerabilities": len(image_vulns),
            },
            state_delta=state_delta,
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
