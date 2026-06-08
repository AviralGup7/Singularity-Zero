"""Git secret scanning stage."""

from __future__ import annotations

import json
import os
import re
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

_AWS_KEY_RE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
_GENERIC_API_KEY_RE = re.compile(r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{20,})[\"']", re.IGNORECASE)


def _which(tool: str) -> bool:
    return shutil.which(tool) is not None


def _regex_scan_path(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not path.is_file():
        return findings
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for match in _AWS_KEY_RE.finditer(text):
        findings.append(
            {
                "type": "hardcoded_aws_key",
                "file": str(path),
                "line": text[: match.start()].count("\n") + 1,
                "match": match.group(0)[:4] + "****",
                "scanner": "regex",
            }
        )
    for match in _GENERIC_API_KEY_RE.finditer(text):
        findings.append(
            {
                "type": "hardcoded_api_key",
                "file": str(path),
                "line": text[: match.start()].count("\n") + 1,
                "match": "****",
                "scanner": "regex",
            }
        )
    return findings


def _scan_repo_fallback(repo_path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for name in files:
            file_path = Path(root) / name
            findings.extend(_regex_scan_path(file_path))
    return findings


async def run_git_secret_scan_stage(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    scope_interceptor: Any = None,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: Git secret scanning using Gitleaks with regex fallback."""
    if stage_input is None:
        stage_input = build_stage_input_from_context("git_secret_scan", config, ctx)

    stage_started = time.monotonic()
    repo_path = getattr(ctx.result, "source_repo_path", None)
    if not repo_path:
        repo_path = Path.cwd()
    repo_path = Path(repo_path)

    if not repo_path.exists():
        ctx.mark_stage_skipped("git_secret_scan", reason="repo_path_missing")
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="git_secret_scan",
            outcome=StageOutcome.SKIPPED,
            duration_seconds=duration,
            metrics={"status": "skipped", "reason": "repo_path_missing"},
            state_delta={},
        )

    emit_progress("git_secret_scan", "Scanning repository for secrets", 50)

    secret_findings: list[dict[str, Any]] = []

    try:
        gitleaks_config = repo_path / ".gitleaks.toml"
        if not gitleaks_config.exists():
            gitleaks_config = Path(".gitleaks.toml")

        if _which("gitleaks"):
            output_file = ctx.output_store.run_dir / "gitleaks.json"
            cmd = [
                "gitleaks",
                "detect",
                "--source",
                str(repo_path),
                "--report-path",
                str(output_file),
                "--report-format",
                "json",
                "--no-git",
            ]
            if gitleaks_config.exists():
                cmd.extend(["--config", str(gitleaks_config)])

            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            if result.returncode not in (0, 1):
                logger.warning("Gitleaks exited with code %d: %s", result.returncode, result.stderr)

            if output_file.exists():
                try:
                    data = json.loads(output_file.read_text(encoding="utf-8"))
                    for finding in data if isinstance(data, list) else [data]:
                        if not isinstance(finding, dict):
                            continue
                        secret_findings.append(
                            {
                                "type": finding.get("rule", "gitleaks_finding"),
                                "file": finding.get("file", ""),
                                "line": finding.get("line", 0),
                                "secret": finding.get("secret", "****"),
                                "scanner": "gitleaks",
                                "description": finding.get("description", ""),
                            }
                        )
                except (OSError, json.JSONDecodeError) as exc:
                    logger.warning("Failed to parse gitleaks output: %s", exc)

        regex_findings = _scan_repo_fallback(repo_path)
        secret_findings.extend(regex_findings)

        ctx.mark_stage_complete("git_secret_scan")
        duration = round(time.monotonic() - stage_started, 2)
        state_delta = {
            "secret_findings": secret_findings,
            "exposed_credentials_count": len(secret_findings),
        }
        return StageOutput(
            stage_name="git_secret_scan",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=duration,
            metrics={
                "status": "ok",
                "gitleaks_used": _which("gitleaks"),
                "secret_findings": len(secret_findings),
                "exposed_credentials_count": len(secret_findings),
            },
            state_delta=state_delta,
            findings=tuple(secret_findings),
        )

    except Exception as exc:
        logger.error("Git secret scan failed: %s", exc)
        ctx.mark_stage_failed("git_secret_scan", str(exc))
        duration = round(time.monotonic() - stage_started, 2)
        return StageOutput(
            stage_name="git_secret_scan",
            outcome=StageOutcome.FAILED,
            duration_seconds=duration,
            error=str(exc),
            metrics={"status": "error", "error": str(exc)},
            state_delta={},
        )
