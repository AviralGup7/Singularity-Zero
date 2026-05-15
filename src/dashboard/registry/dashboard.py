from typing import Any

from src.dashboard.constants.analysis import (
    ANALYSIS_CHECK_OPTIONS,
    ANALYSIS_CONTROL_GROUPS,
    ANALYSIS_FOCUS_PRESETS,
)
from src.dashboard.constants.modules import MODE_PRESETS, MODULE_GROUPS, MODULE_OPTIONS
from src.dashboard.constants.pipeline import PROGRESS_PREFIX, STAGE_LABELS

DASHBOARD_REGISTRY: dict[str, dict[str, Any]] = {
    "analysis": {
        "check_options": ANALYSIS_CHECK_OPTIONS,
        "control_groups": ANALYSIS_CONTROL_GROUPS,
        "focus_presets": ANALYSIS_FOCUS_PRESETS,
    },
    "modules": {
        "options": MODULE_OPTIONS,
        "groups": MODULE_GROUPS,
        "mode_presets": MODE_PRESETS,
    },
    "pipeline": {
        "progress_prefix": PROGRESS_PREFIX,
        "stage_labels": STAGE_LABELS,
    },
}
