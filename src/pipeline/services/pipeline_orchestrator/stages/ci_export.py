"""CI export stage: JUnit XML, GitHub Actions summary, SARIF reference, exit code recommendation."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context

logger = get_pipeline_logger(__name__)


def _classify_severity(severity: str | None) -> str:
    normalized = (severity or "info").strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mapping.get(normalized, "info")


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _severity_exceeds_threshold(finding: Any, threshold: str) -> bool:
    finding_severity = _classify_severity(getattr(finding, "severity", None) or getattr(finding, "risk", None))
    try:
        return SEVERITY_ORDER.index(finding_severity) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def _junit_xml(findings: list[Any], threshold: str) -> str:
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<testsuites>',
        f'  <testsuite name="security-scan" tests="{len(findings)}" timestamp="{timestamp}">',
    ]
    for i, finding in enumerate(findings, start=1):
        severity = _classify_severity(getattr(finding, "severity", None) or getattr(finding, "risk", None))
        name = getattr(finding, "title", None) or getattr(finding, "name", None) or getattr(finding, "vuln_type", "unknown")
        target = getattr(finding, "target_url", None) or getattr(finding, "affected_url", None) or getattr(finding, "url", "unknown")
        message = getattr(finding, "description", None) or getattr(finding, "summary", "") or ""
        tool = getattr(finding, "tool", "unknown")
        lines.append(f'    <testcase name="{i}. {name}" classname="{tool}">')
        if _severity_exceeds_threshold(finding, threshold):
            lines.append(f'      <failure message="{target}: {message}" type="{severity}">')
            lines.append(f"        Severity: {severity}")
            lines.append(f"        Target: {target}")
            lines.append(f"        Tool: {tool}")
            lines.append("      </failure>")
        else:
            lines.append(f'      <skipped message="Below threshold ({severity})" type="{severity}"/>')
        lines.append("    </testcase>")
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines)


def _github_summary(findings: list[Any], threshold: str, failed_stages: dict[str, Any]) -> str:
    lines = [
        "## Security Scan Report",
        "",
        f"**Findings:** {len(findings)}",
        "",
        "### Findings",
        "",
    ]
    if not findings:
        lines.append("No findings detected.")
    else:
        for finding in findings:
            severity = _classify_severity(getattr(finding, "severity", None) or getattr(finding, "risk", None))
            name = getattr(finding, "title", None) or getattr(finding, "name", None) or getattr(finding, "vuln_type", "unknown")
            target = getattr(finding, "target_url", None) or getattr(finding, "affected_url", None) or getattr(finding, "url", "unknown")
            status = "❌ FAIL" if _severity_exceeds_threshold(finding, threshold) else "⚠️ BELOW THRESHOLD"
            lines.append(f"- **{severity.upper()}** | {status} | {name}")
            lines.append(f"  - Target: `{target}`")
            tool = getattr(finding, "tool", "unknown")
            lines.append(f"  - Tool: `{tool}`")

    if failed_stages:
        lines.append("")
        lines.append("### Failed Stages")
        lines.append("")
        for stage_name, metrics in failed_stages.items():
            reason = ""
            if isinstance(metrics, dict):
                reason = metrics.get("failure_reason") or metrics.get("error") or metrics.get("status", "unknown")
            lines.append(f"- **{stage_name}**: {reason}")

    failed_count = sum(1 for f in findings if _severity_exceeds_threshold(f, threshold))
    lines.append("")
    lines.append(f"### Threshold: `{threshold}` | Findings exceeding threshold: {failed_count}")
    return "\n".join(lines)


async def run_ci_export(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    started = time.monotonic()
    if stage_input is None:
        stage_input = build_stage_input_from_context("ci_export", config, ctx)

    try:
        findings = list(getattr(ctx.result, "reportable_findings", []) or [])
        failed_stages: dict[str, Any] = {}

        threshold = "medium"
        if hasattr(args, "ci_fail_on_severity") and args.ci_fail_on_severity:
            threshold = str(args.ci_fail_on_severity).strip().lower()
            if threshold not in SEVERITY_ORDER:
                logger.warning("Invalid --ci-fail-on-severity value %r; defaulting to 'medium'.", threshold)
                threshold = "medium"

        run_dir = getattr(getattr(ctx, "output_store", None), "run_dir", None) or Path(".")
        artifacts_dir = run_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        junit_path = artifacts_dir / "junit.xml"
        junit_path.write_text(_junit_xml(findings, threshold), encoding="utf-8")

        summary_md = _github_summary(findings, threshold, failed_stages)
        github_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if github_summary_path:
            try:
                Path(github_summary_path).write_text(summary_md, encoding="utf-8")
            except OSError as exc:
                logger.debug("Failed to write GITHUB_STEP_SUMMARY: %s", exc)

        sarif_ref = "sarif_export"
        ci_artifacts: dict[str, Any] = {
            "junit_xml": str(junit_path),
            "github_summary": github_summary_path or str(artifacts_dir / "github_summary.md"),
            "sarif_reference": {
                "stage": sarif_ref,
                "path": str(run_dir / "report.sarif"),
            },
            "findings_total": len(findings),
            "threshold": threshold,
        }
        (artifacts_dir / "ci_artifacts.json").write_text(
            json.dumps(ci_artifacts, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        return StageOutput(
            stage_name="ci_export",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=round(time.monotonic() - started, 2),
            metrics={
                "findings_total": len(findings),
                "junit_path": str(junit_path),
            },
            state_delta={
                "junit_xml": str(junit_path),
                "github_summary": ci_artifacts["github_summary"],
                "ci_artifacts": ci_artifacts,
                "exit_code_recommendation": 1 if any(_severity_exceeds_threshold(f, threshold) for f in findings) else 0,
            },
        )
    except Exception as exc:
        logger.exception("CI export stage failed: %s", exc)
        return StageOutput(
            stage_name="ci_export",
            outcome=StageOutcome.FAILED,
            duration_seconds=round(time.monotonic() - started, 2),
            error=str(exc),
            metrics={},
            state_delta={
                "junit_xml": None,
                "github_summary": None,
                "ci_artifacts": {},
                "exit_code_recommendation": 2,
            },
        )
