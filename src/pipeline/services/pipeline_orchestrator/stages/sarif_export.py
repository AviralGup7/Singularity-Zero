"""SARIF 2.1 export stage.

Emits ``report.sarif`` alongside the existing report artifacts so CI
providers (GitHub Code Scanning, GitLab, Azure DevOps) can ingest
findings as native code-scan alerts.  Runs as the terminal stage of
the pipeline so it always operates on the final ``reportable_findings``
set (after FP reduction).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.core.contracts.pipeline_runtime import StageInput, StageOutcome, StageOutput
from src.core.logging.pipeline_logging import emit_info
from src.core.logging.trace_logging import get_pipeline_logger
from src.core.models.stage_result import PipelineContext
from src.pipeline.services.pipeline_helpers import build_stage_input_from_context
from src.reporting.sarif_exporter import export_findings_to_sarif

logger = get_pipeline_logger(__name__)


async def run_sarif_export(
    args: Any,
    config: Any,
    ctx: PipelineContext,
    *,
    stage_input: StageInput | None = None,
) -> StageOutput:
    """Stage: emit ``report.sarif`` from the final reportable_findings set."""
    started = time.monotonic()
    if stage_input is None:
        stage_input = build_stage_input_from_context("sarif_export", config, ctx)

    try:
        findings = list(getattr(ctx.result, "reportable_findings", []) or [])
        include_fps = bool(
            (getattr(config, "ci", None) or {}).get("include_false_positives_in_sarif", False)
            if hasattr(config, "ci")
            else False
        )
        result = export_findings_to_sarif(
            findings,
            include_false_positives=include_fps,
        )

        run_dir: Path | None = None
        if getattr(ctx, "output_store", None) is not None:
            run_dir = ctx.output_store.run_dir

        if run_dir is not None:
            sarif_path = run_dir / "report.sarif"
            sarif_path.write_text(
                json.dumps(result.document, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            emit_info(f"SARIF 2.1 report written: {sarif_path}")
            if getattr(ctx.output_store, "upload_file", None):
                try:
                    ctx.output_store.upload_file(sarif_path, "report.sarif")
                except Exception as exc:  # noqa: BLE001
                    logger.debug("SARIF artifact upload failed: %s", exc)

        return StageOutput(
            stage_name="sarif_export",
            outcome=StageOutcome.COMPLETED,
            duration_seconds=round(time.monotonic() - started, 2),
            metrics={
                "findings_exported": len(result.document["runs"][0]["results"]),
                "findings_dropped": result.dropped,
                "findings_total": result.total,
            },
            state_delta={"sarif_document": result.document},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("SARIF export failed (non-fatal): %s", exc)
        return StageOutput(
            stage_name="sarif_export",
            outcome=StageOutcome.FAILED,
            duration_seconds=round(time.monotonic() - started, 2),
            error=str(exc),
            metrics={},
            state_delta={},
        )
