"""Learning integration hooks for pipeline adaptation and feedback."""

from typing import Any

from src.learning.integration import LearningIntegration

from src.core.logging.trace_logging import get_pipeline_logger

logger = get_pipeline_logger(__name__)


def apply_learning_adaptations(ctx_dict: dict[str, Any]) -> bool:
    """Hook 1: Apply learning adaptations from previous runs.

    Called before pipeline execution begins.
    Returns True if adaptations were applied.
    """
    try:
        learning = LearningIntegration.get_or_create(ctx_dict)
        adaptations = learning.compute_adaptations(ctx_dict)
        if adaptations:
            learning.apply_adaptations(ctx_dict, adaptations)
            logger.info("Applied %d learning adaptations from previous runs", len(adaptations))
            return True
        return False
    except Exception as exc:
        logger.warning("Learning adaptation failed: %s", exc)
        return False


def emit_feedback_events(ctx_dict: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Hook 2: Emit feedback events for findings.

    Called after analysis enrichments complete.
    Feeds finding outcomes back into the learning system.
    """
    try:
        learning = LearningIntegration.get_or_create(ctx_dict)
        learning.emit_feedback_events(ctx_dict, findings)
    except Exception as exc:
        logger.debug("Feedback event emission failed: %s", exc)


async def run_learning_update(ctx_dict: dict[str, Any]) -> dict[str, Any]:
    """Hook 3: Run post-scan learning update.

    Called after pipeline completion.
    Updates learning models with run results for future adaptation.
    Returns a status dict for metrics collection.
    """
    try:
        learning = LearningIntegration.get_or_create(ctx_dict)
        result = await learning.run_learning_update(ctx_dict)
        logger.info("Learning update completed: %s", result.get("status"))
        return result
    except Exception as exc:
        logger.debug("Learning update failed: %s", exc)
        return {"status": "error", "error": str(exc)}
