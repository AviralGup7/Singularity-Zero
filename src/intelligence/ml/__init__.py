"""ML model lifecycle and active learning helpers."""

from functools import lru_cache

from src.intelligence.ml.active_learning import ActiveLearningController
from src.intelligence.ml.context import truncate_context
from src.intelligence.ml.feature_vector import FeatureVector
from src.intelligence.ml.gnn_predict import GNNPredictor, ProbeSelectionRLAgent
from src.intelligence.ml.prompts import (
    EXPLAIN_FINDING_SYSTEM,
    GENERATE_EXECUTIVE_SUMMARY_SYSTEM,
    GENERATE_PATCH_SYSTEM,
    TRIAGE_FALSE_POSITIVE_SYSTEM,
)
from src.intelligence.ml.registry import ModelVersion, ModelVersionRegistry
from src.intelligence.ml.scoring import (
    GRC_MAPPINGS,
    fallback_explain,
    fallback_patch,
    fallback_summary,
    fallback_triage,
)
from src.intelligence.ml.xgboost_pipeline import XGBoostSeverityPipeline


@lru_cache(maxsize=1)
def get_default_model_registry() -> ModelVersionRegistry:
    """Return a process-wide singleton ``ModelVersionRegistry``.

    Previously each ``CalibratedSeverityModel`` and ``ActiveLearningController``
    constructed their own registry, so retrains were invisible to serving
    predictors. This factory ensures a single shared instance.
    """
    return ModelVersionRegistry()


__all__ = [
    "EXPLAIN_FINDING_SYSTEM",
    "GENERATE_EXECUTIVE_SUMMARY_SYSTEM",
    "GENERATE_PATCH_SYSTEM",
    "TRIAGE_FALSE_POSITIVE_SYSTEM",
    "GRC_MAPPINGS",
    "ModelVersion",
    "ModelVersionRegistry",
    "FeatureVector",
    "XGBoostSeverityPipeline",
    "ActiveLearningController",
    "GNNPredictor",
    "ProbeSelectionRLAgent",
    "fallback_explain",
    "fallback_patch",
    "fallback_summary",
    "fallback_triage",
    "get_default_model_registry",
    "truncate_context",
]
