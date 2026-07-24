import warnings

from src.core.models.config import DEFAULT_USER_AGENT, DIFF_TARGETS, TOOL_NAMES
from src.core.models.entities import Finding, Request, Response, ValidationResult
from src.core.models.stage_result import (
    PipelineContext,
    StageMetric,
    StageName,
    StageResult,
    StageStatus,
)

# Re-export legacy Config for backward compatibility during migration.
# Suppress the deprecation warning at the re-export site to avoid noise
# on every `import src.core.models` — the warning is emitted at the
# definition site in src.core.models.config instead.
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from src.core.models.config import Config  # noqa: F401

__all__ = [
    "Config",
    "DEFAULT_USER_AGENT",
    "DIFF_TARGETS",
    "TOOL_NAMES",
    "Finding",
    "PipelineContext",
    "Request",
    "Response",
    "StageMetric",
    "StageName",
    "StageResult",
    "StageStatus",
    "ValidationResult",
]
