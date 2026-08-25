"""Centralized progress constants for stage execution and job tracking."""

from src.pipeline.services.stage_registry import PIPELINE_STAGES

STAGE_BASELINE_PERCENT = {stage.key: stage.percent_start for stage in PIPELINE_STAGES}
STAGE_BASELINE_PERCENT["completed"] = 100
# Aliases for backward compatibility
STAGE_BASELINE_PERCENT["analysis"] = STAGE_BASELINE_PERCENT.get("passive_scan", 86)

# Sibling mapping for orchestrator stage baseline lookups
_STAGE_BASELINE_PROGRESS = {
    k: v for k, v in STAGE_BASELINE_PERCENT.items() if k not in {"startup", "completed", "analysis"}
}
