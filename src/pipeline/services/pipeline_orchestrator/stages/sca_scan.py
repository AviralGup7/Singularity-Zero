"""SCA (Software Composition Analysis) scanning stage."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.runner_support import emit_progress
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

logger = get_pipeline_logger(__name__)


def _which(tool: str) -> bool:
    return shutil.which(tool) is not None


async def run_sca_scan_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: SCA scan using Grype or Trivy on dependency manifests."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("sca_scan", config, ctx)

    stage_started = time.monotonic()
    source_code_paths = getattr(ctx.result, "source_code_paths", None) or []
    if not source_code_paths:
        ctx.mark_stage_skipped("sca_scan", reason="no_source_code_paths")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sca_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "no_source_code_paths"},
            state_delta={},
        )

    tool = None
    if _which("grype"):
        tool = "grype"
    elif _which("trivy"):
        tool = "trivy"

    sca_findings: list[dict[str, Any]] = []
    dependency_tree: dict[str, Any] = {}
    sbom_fragment: dict[str, Any] = {}

    if tool is None:
        ctx.mark_stage_skipped("sca_scan", reason="sca_tool_not_available")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sca_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "sca_tool_not_available"},
            state_delta={},
        )

    emit_progress("sca_scan", f"Running {tool} on source paths", 50)

    try:
        manifest_files = []
        for path in source_code_paths:
            p = Path(path)
            if not p.exists():
                continue
            if p.is_file():
                manifest_files.append(str(p))
            else:
                for name in ("package.json", "requirements.txt", "pom.xml", "go.mod", "Cargo.toml"):
                    candidate = p / name
                    if candidate.exists():
                        manifest_files.append(str(candidate))

        if not manifest_files:
            ctx.mark_stage_skipped("sca_scan", reason="no_dependency_manifests_found")
            duration = round(time.monotonic() - stage_started, 2)
            return StageOutput(
                stage_name="sca_scan",
                outcome=StageOutcome.SKIPPED,
                duration_seconds=duration,
                metrics={"status": "skipped", "reason": "no_dependency_manifests_found"},
                state_delta={},
            )

        output_file = ctx.output_store.run_dir / "sca_findings.json"
        cmd = [tool, "sbom", "--output", str(output_file), "--format", "cyclonedx-json"]
        for mf in manifest_files:
            cmd.extend(["-f", mf])

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("SCA tool exited with code %d: %s", result.returncode, result.stderr)

        if output_file.exists():
            try:
                sbom_data = json.loads(output_file.read_text(encoding="utf-8"))
                sbom_fragment = sbom_data
                components = sbom_data.get("components", [])
                dependency_tree = {"components": components}
                for comp in components:
                    purl = comp.get("purl", "")
                    if purl:
                        sca_findings.append(
                            {
                                "type": "sca_component",
                                "purl": purl,
                                "name": comp.get("name", ""),
                                "version": comp.get("version", ""),
                                "evidence": {"source": tool},
                            }
                        )
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to parse SCA output: %s", exc)

        ctx.mark_stage_complete("sca_scan")
        duration = round(time.monotonic() - stage_started, 2)
        state_delta = {
            "sca_findings": sca_findings,
            "dependency_tree": dependency_tree,
            "sbom_fragment": sbom_fragment,
        }
        return StageOutput(
            stage_name="sca_scan",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "tool": tool,
                "manifests_scanned": len(manifest_files),
                "findings_count": len(sca_findings),
            },
            state_delta=state_delta,
        )

    except Exception as exc:
        logger.error("SCA scan failed: %s", exc)
        ctx.mark_stage_failed("sca_scan", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="sca_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
