"""IaC (Infrastructure as Code) security scanning stage."""

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


async def run_iac_scan_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: IaC scanning using Checkov or Semgrep."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("iac_scan", config, ctx)

    stage_started = time.monotonic()
    iac_paths = getattr(ctx.result, "iac_paths", None) or []
    if not iac_paths:
        ctx.mark_stage_skipped("iac_scan", reason="no_iac_paths")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="iac_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "no_iac_paths"},
            state_delta={},
        )

    tool = None
    if _which("checkov"):
        tool = "checkov"
    elif _which("semgrep"):
        tool = "semgrep"

    iac_findings: list[dict[str, Any]] = []
    misconfigurations: list[dict[str, Any]] = []

    if tool is None:
        ctx.mark_stage_skipped("iac_scan", reason="iac_tool_not_available")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="iac_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "iac_tool_not_available"},
            state_delta={},
        )

    emit_progress("iac_scan", f"Running {tool} on IaC paths", 50)

    try:
        output_file = ctx.output_store.run_dir / "iac_scan.json"

        if tool == "checkov":
            cmd = [
                "checkov",
                "--directory",
                *iac_paths,
                "--framework",
                "terraform,cloudformation,kubernetes",
                "--output",
                "json",
                "--output-file-path",
                str(output_file),
                "--compact",
            ]
        else:
            cmd = [
                "semgrep",
                "--config",
                "p/security-audit",
                "--json",
                "-o",
                str(output_file),
                *iac_paths,
            ]

        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if result.returncode != 0:
            logger.warning("IaC tool exited with code %d: %s", result.returncode, result.stderr)

        if output_file.exists():
            try:
                data = json.loads(output_file.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    parsed_findings = data
                elif isinstance(data, dict):
                    parsed_findings = data.get("results", data.get("findings", [data]))
                else:
                    parsed_findings = []

                for finding in parsed_findings:
                    if not isinstance(finding, dict):
                        continue
                    finding_type = finding.get("check_type", finding.get("check_id", "unknown"))
                    misconfigurations.append(
                        {
                            "type": finding_type,
                            "severity": finding.get("severity", "unknown"),
                            "description": finding.get("check_name", finding.get("description", "")),
                            "file": finding.get("file_path", finding.get("file", "")),
                            "line": finding.get("line_number", finding.get("line", "")),
                            "evidence": finding,
                        }
                    )
                    iac_findings.append(
                        {
                            "type": "iac_misconfiguration",
                            "tool": tool,
                            "check": finding_type,
                            "severity": finding.get("severity", "unknown"),
                            "file": finding.get("file_path", finding.get("file", "")),
                            "line": finding.get("line_number", finding.get("line", "")),
                        }
                    )
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to parse IaC scan output: %s", exc)

        ctx.mark_stage_complete("iac_scan")
        duration = round(time.monotonic() - stage_started, 2)
        state_delta = {
            "iac_findings": iac_findings,
            "misconfigurations": misconfigurations,
        }
        return StageOutput(
            stage_name="iac_scan",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "tool": tool,
                "paths_scanned": len(iac_paths),
                "misconfigurations": len(misconfigurations),
            },
            state_delta=state_delta,
        )

    except Exception as exc:
        logger.error("IaC scan failed: %s", exc)
        ctx.mark_stage_failed("iac_scan", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="iac_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
